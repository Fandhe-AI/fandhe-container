//! `mounts[].destination` の正規化とトラバーサル拒否（TASK-29.1.2・CORE-2・OCI-4）。
//!
//! # 役割と呼び出し元
//!
//! `config::convert_mount` が config.json の destination を [`MountDestination`] に変換する
//! （段 A: パース時の字句正規化）。TASK-29.2（create）は rootfs の絶対パスを渡して
//! [`MountDestination::resolve_in`] を呼ぶ想定（段 B: rootfs への結合。呼び出し側は後続 TASK で未実装）。
//! 素朴な `rootfs.join(destination)` は、絶対パスの destination で基点が置き換わりホスト側を指すため使ってはならない。
//!
//! # 段 A の規則（ホスト OS 非依存）
//!
//! JSON 由来の `String` を `/` で自前分割し、ホストの `Path::components()` を使わない
//! （Windows と Linux で `\` や `C:` の解釈が変わるため。CLI-1・IO-5）。
//!
//! - 空文字・NUL・`\` を含む値は拒否する。
//! - `..` 要素は位置を問わず拒否する（rootfs 内へ丸めず fail-closed にする）。
//! - 連続する `/`・`.` 要素・末尾の `/` は除き、`/a/b` 形式に正規化する。
//! - 正規化後に要素が 0 個（`/` 等）は rootfs 全体を覆うため拒否する。
//! - 相対パスは OCI Runtime Spec が `/` 起点として解釈することを許すため、`/` 起点に正規化して受理する。
//!   先頭の `/` 付与で増えた正規化後の長さも `CONFIG_MAX_PATH_BYTES` 以下であることを検証する。
//!
//! # 監査記録（SEC-4・TASK-41.4・#195）
//!
//! 拒否を `Mount` 監査レコードにする [`MountDestination::resolve_in_audited`]・[`audit_mount_config_error`]
//! を持つ。ファイル永続化（TASK-41.5.1・#839）は実装済みで、本番経路への sink の配線は未実装。
//!
//! # スコープ外（REPAIR-3）
//!
//! 字句的な正規化のみで、rootfs 内の symlink は解決しない。[`MountDestination::resolve_in`] の返り値は
//! 「字句上 rootfs 配下」の保証であり、symlink 経由の脱出や検証からマウントまでの TOCTOU は防げない。
//! 実マウントは rootfs の fd を起点に `O_NOFOLLOW` で 1 要素ずつ辿る方式（`exec` の `open_dir_beneath` と同じ）で
//! 行う必要があり、TASK-29.2・TASK-127 の担当とする。文字列パスで直接 `mount(2)` してはならない。

use std::path::{Component, Path, PathBuf};

use super::config::{CONFIG_MAX_PATH_BYTES, OciConfigError, OciConfigErrorKind};
use crate::audit_log::{AuditSink, AuditedRejection, record_mount_rejection};

const DEST_FIELD: &str = "mounts[].destination";
const ROOT_FIELD: &str = "root.path";

/// 検証済みのコンテナ内マウント先（Linux 表記の `/a/b` 正規形）。
///
/// 生成経路は config パーサ（`pub(super) parse`）のみで、`..` や rootfs 全体を指す値は表現できない
/// （REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountDestination(String);

impl MountDestination {
    /// destination 文字列を検証・正規化する（段 A）。
    pub(crate) fn parse(value: &str) -> Result<Self, OciConfigError> {
        if value.is_empty() || value.contains('\0') || value.contains('\\') {
            return Err(OciConfigError::invalid(DEST_FIELD));
        }
        let mut parts: Vec<&str> = Vec::new();
        for part in value.split('/') {
            match part {
                "" | "." => {}
                ".." => return Err(OciConfigError::invalid(DEST_FIELD)),
                other => parts.push(other),
            }
        }
        if parts.is_empty() {
            return Err(OciConfigError::invalid(DEST_FIELD));
        }
        let normalized = format!("/{}", parts.join("/"));
        // 相対パスは先頭に `/` が付き 1 バイト増えるため、正規化後にも上限を再検証する。
        if normalized.len() > CONFIG_MAX_PATH_BYTES {
            return Err(OciConfigError::invalid(DEST_FIELD));
        }
        Ok(Self(normalized))
    }

    /// 正規化済みのコンテナ内パス（`/` 始まり）。
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// 正規化済みのコンテナ内パス文字列（`/` 始まり）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// rootfs の絶対パス配下のマウント先を組み立てる（段 B。CORE-2・OCI-4）。
    ///
    /// `rootfs` はホスト基準の絶対パスで、bundle 相対の `root.path` は呼び出し側が解決してから渡す。
    /// 字句上の保証のみで、symlink は解決しない（モジュール doc 参照）。
    pub fn resolve_in(&self, rootfs: &Path) -> Result<PathBuf, OciConfigError> {
        let rootfs_ok = rootfs.is_absolute()
            && !rootfs.as_os_str().to_string_lossy().contains('\0')
            && !rootfs
                .components()
                .any(|c| matches!(c, Component::ParentDir));
        if !rootfs_ok {
            return Err(OciConfigError::invalid(ROOT_FIELD));
        }
        let mut out = PathBuf::from(rootfs);
        for elem in self.0.split('/').filter(|e| !e.is_empty()) {
            // Windows の `C:` 等の prefix は `Normal` 単独にならないためここで捕まえる。
            let mut comps = Path::new(elem).components();
            match (comps.next(), comps.next()) {
                (Some(Component::Normal(_)), None) => out.push(elem),
                _ => return Err(OciConfigError::invalid(DEST_FIELD)),
            }
        }
        if !out.starts_with(rootfs) {
            return Err(OciConfigError::invalid(DEST_FIELD));
        }
        Ok(out)
    }

    /// [`Self::resolve_in`] の拒否を監査記録する版（SEC-4・TASK-41.4・#195）。
    ///
    /// 成功時は `resolve_in` と同じ値。`mounts[].destination` 起因の拒否時は正規化済みのコンテナ内パス（ホスト側 rootfs の実パスは
    /// 載せない）を `Mount` レコードとして `sink` へ 1 件渡し、エラーはそのまま返す（fail-closed）。
    /// 本番経路への配線は未実装（TASK-29.2）。
    pub fn resolve_in_audited(
        &self,
        rootfs: &Path,
        sink: &dyn AuditSink,
    ) -> Result<PathBuf, Box<AuditedRejection<OciConfigError>>> {
        self.resolve_in(rootfs).map_err(|e| {
            // `root.path`（rootfs 引数）起因の拒否はマウント先の違反ではないため記録しない。
            let is_dest = matches!(
                e.kind(),
                OciConfigErrorKind::Invalid { field } if *field == DEST_FIELD
            );
            Box::new(if is_dest {
                record_mount_rejection(e, Some(self.as_path()), sink)
            } else {
                AuditedRejection::not_applicable(e)
            })
        })
    }
}

/// config.json のパース拒否が `mounts[].destination` の検証によるものなら `Mount` レコードを
/// 記録する（SEC-4・OCI-4・TASK-41.4・#195）。
///
/// エラーは入力値を保持しないため `path` なしで記録する（計画段階の拒否）。他フィールドの拒否は
/// 記録せず `NotApplicable`。エラーは常にそのまま返る。
pub fn audit_mount_config_error(
    err: OciConfigError,
    sink: &dyn AuditSink,
) -> AuditedRejection<OciConfigError> {
    let is_dest = match err.kind() {
        OciConfigErrorKind::Invalid { field } => *field == DEST_FIELD,
        OciConfigErrorKind::LimitExceeded { field, .. } => field == DEST_FIELD,
        _ => false,
    };
    if is_dest {
        record_mount_rejection(err, None, sink)
    } else {
        AuditedRejection::not_applicable(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::OciConfigErrorKind;
    use crate::traits::ErrorCode;

    fn rootfs(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fandhe-mnt-ut-{name}-{}", std::process::id()))
    }

    fn assert_dest_err(e: &OciConfigError) {
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            *e.kind(),
            OciConfigErrorKind::Invalid {
                field: "mounts[].destination"
            }
        );
    }

    /// CORE-2・OCI-4: 正規化の具体値。
    #[test]
    fn core2_parse_normalizes() {
        for (input, want) in [
            ("/proc", "/proc"),
            ("/a/./b//", "/a/b"),
            ("//a///b/", "/a/b"),
            ("proc", "/proc"),
            ("a/b", "/a/b"),
            ("/...", "/..."),
            ("/a..b", "/a..b"),
            ("/.hidden", "/.hidden"),
        ] {
            let d = MountDestination::parse(input).expect(input);
            assert_eq!(d.as_str(), want, "input={input}");
            assert_eq!(d.as_path(), Path::new(want));
        }
    }

    /// CORE-2・OCI-4: トラバーサル・区切り違い・rootfs 全体・空は拒否し、入力値をメッセージに含めない。
    #[test]
    fn oci4_parse_rejects_traversal() {
        for input in [
            "/../etc",
            "../x",
            "/a/../../x",
            "/a/../b",
            "..",
            "/a/..",
            "a\\..\\..\\x",
            "\\\\server\\share",
            "C:\\Windows",
            "/",
            "/.",
            "//",
            ".",
            "",
            "/a\0b",
        ] {
            let e = MountDestination::parse(input).expect_err(input);
            assert_dest_err(&e);
            assert_eq!(
                e.message(),
                "config.json has an invalid value for `mounts[].destination`"
            );
        }
    }

    /// CORE-2: 正規化で `/` が付与されて上限を超える 4096 バイトの相対パスは拒否し、絶対 4096 バイトは受理する。
    #[test]
    fn core2_parse_rejects_over_limit_after_normalization() {
        let rel = "a".repeat(CONFIG_MAX_PATH_BYTES);
        let e = MountDestination::parse(&rel).expect_err("relative 4096 bytes");
        assert_dest_err(&e);
        let abs = format!("/{}", "a".repeat(CONFIG_MAX_PATH_BYTES - 1));
        let d = MountDestination::parse(&abs).expect("absolute 4096 bytes");
        assert_eq!(d.as_str().len(), CONFIG_MAX_PATH_BYTES);
    }

    /// CORE-2・OCI-4: 絶対パス destination でも rootfs 配下に解決され、ホストの `/etc` にならない。
    #[test]
    fn core2_resolve_in_stays_under_rootfs() {
        let r = rootfs("abs");
        let got = MountDestination::parse("/etc")
            .unwrap()
            .resolve_in(&r)
            .unwrap();
        assert_eq!(got, r.join("etc"));
        assert!(got.starts_with(&r));
        assert_ne!(got, PathBuf::from("/etc"));
        let got = MountDestination::parse("/a/./b//")
            .unwrap()
            .resolve_in(&r)
            .unwrap();
        assert_eq!(got, r.join("a").join("b"));
    }

    /// CORE-2: rootfs 自体が相対・`..` 入りなら拒否する。
    #[test]
    fn core2_resolve_in_rejects_bad_rootfs() {
        let d = MountDestination::parse("/a").unwrap();
        let bad = rootfs("dd").join("..").join("x");
        for r in [PathBuf::from("rootfs"), bad] {
            let e = d.resolve_in(&r).expect_err("bad rootfs");
            assert_eq!(
                *e.kind(),
                OciConfigErrorKind::Invalid { field: "root.path" }
            );
        }
    }

    /// CORE-2: `C:` 要素は Windows では prefix として拒否される。
    #[cfg(windows)]
    #[test]
    fn core2_drive_prefix_element_rejected_on_windows() {
        let e = MountDestination::parse("/C:/x")
            .unwrap()
            .resolve_in(&rootfs("win"))
            .expect_err("prefix");
        assert_dest_err(&e);
    }

    /// CORE-2: `C:` 要素は Windows 以外では通常名として受理される。
    #[cfg(not(windows))]
    #[test]
    fn core2_drive_like_element_is_plain_name_on_unix() {
        let r = rootfs("unix");
        let got = MountDestination::parse("/C:/x")
            .unwrap()
            .resolve_in(&r)
            .unwrap();
        assert_eq!(got, r.join("C:").join("x"));
    }
    /// SEC-4・TASK-41.4: resolve_in の成功時は記録しない（destination 起因の拒否は
    /// 字句正規化後は Linux では到達しないため、記録経路は `audit_mount_config_error` 側で検証する）。
    #[test]
    fn sec4_task41_4_resolve_in_audited_success_records_nothing() {
        use crate::audit_log::mount::tests::VecSink;

        let dest = MountDestination::parse("/etc").expect("parse");
        let ok_sink = VecSink::new(false);
        let root = std::env::temp_dir();
        let out = dest.resolve_in_audited(&root, &ok_sink).expect("ok");
        assert_eq!(out, root.join("etc"));
        assert_eq!(ok_sink.snapshot().len(), 0);
    }

    /// SEC-4・TASK-41.4: root.path 起因の拒否は Mount レコードにしない。
    #[test]
    fn sec4_task41_4_resolve_in_audited_skips_root_path_rejection() {
        use crate::audit_log::AuditDelivery;
        use crate::audit_log::mount::tests::VecSink;

        let dest = MountDestination::parse("/etc").expect("parse");
        let sink = VecSink::new(false);
        let r = dest
            .resolve_in_audited(Path::new("relative-rootfs"), &sink)
            .expect_err("relative rootfs rejected");
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(sink.snapshot().len(), 0);
    }
}
