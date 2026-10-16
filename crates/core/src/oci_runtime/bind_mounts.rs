//! `mounts[]` の bind mount の指定を検証済みの型へ変換する（TASK-29 追補・#1911・CORE-2・OCI-4・CORE-5・SEC-1）。
//!
//! # 役割と呼び出し元
//!
//! Linux の fandhe のコンテナは、利用者指定の bind mount（`config.json` の `mounts[]`）を適用する（#1907 の
//! オーナー判断）。本モジュールは「何を受けて何を拒否するか」を 1 か所の純粋関数 [`BindMountSet::from_mounts`] と
//! 検証済みの型 [`BindMountSpec`] に固定する。適用側は #1912（sys ラッパー）・#1913（適用の段）・#1914（pivot 前段）・
//! #1915（`start` への結線）が本型だけを入力にする。`OciMount` は「未検証の指定」、[`BindMountSet`] は
//! 「検証済みの bind」の分担で、`OciMount` 側は変更しない。
//!
//! 受け入れ範囲は #1910 のオーナー決定（2026-10-12）による。`cfg` を付けず 3 OS でビルドし、syscall・
//! ファイルシステムへのアクセスをしない（CLI-1）。パスはホスト OS の `Path` 解釈に依存せず `/` で自前分割する。
//!
//! # 受け入れ規則
//!
//! - 種類: bind のみ（`type == "bind"`、または options に `bind` / `rbind`）。それ以外は `UNIMPLEMENTED`
//! - 受けるオプション: `bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・`rprivate`
//! - 拒否: `suid`・`dev`（制限を外す側。SEC-1）、`shared`・`rshared`・`slave`・`rslave`・`unbindable`・
//!   `runbindable`（伝播）、上記以外すべて（未知は fail-closed）
//! - 常に付ける: `nosuid`・`nodev`（型が常に真を返し、外した値を表現できない。REPAIR-2）。伝播は常に private
//!   （適用側は private で付ける契約）。`noexec` は指定時のみ
//! - 再帰: 既定は非再帰。`rbind` 指定時のみ再帰（属性を再帰で付けるのは適用側）
//! - マウント元: 字句検証（絶対・`..`/`.`/空要素/NUL/`\` なし・`/` 不可）。rootfs・bundle・状態ルートの
//!   同一・祖先は [`BindMountSet::check_against_host_paths`]
//! - マウント先: `/proc`・`/sys`・`/dev` とその配下を拒否。先行 bind との同一・入れ子を拒否。tmpfs・注入・
//!   保護パスとの重なりは各 `check_against_*`
//!
//! # OCI Runtime Spec との差
//!
//! 一次情報は opencontainers/runtime-spec v1.2.1 の `config.md`（Mounts 節と Linux mount options 表）。
//!
//! | 項目 | 仕様の読み | 本実装 |
//! | -- | -- | -- |
//! | bind の判定 | options に `bind` / `rbind`。type は dummy | 同じ＋`type == "bind"` も bind |
//! | 非 bind の種類 | kernel の fs 種別 | `UNIMPLEMENTED` |
//! | `source` | 絶対、または bundle 相対 | 絶対のみ |
//! | `nosuid`・`nodev` | 指定時のみ | 常に付与・外せない |
//! | `suid`・`dev` | 受ける | 拒否 |
//! | 伝播系・`unbindable` | 受ける | 拒否（常に private） |
//! | `defaults` | no-op | 拒否（許可集合外） |
//! | 再帰版 `rro` 等・`idmap` | 受ける | 拒否 |
//! | 宛先 `/proc`・`/sys`・`/dev` 配下 | 制限なし | 拒否 |
//! | bind 同士の入れ子 | Linux は列挙順に適用 | 拒否 |
//!
//! # 暫定の判断（#1910 の決定外。オーナー確認待ち）
//!
//! `bind` と `rbind` の併記は拒否、マウント元の `.` 要素と `\` は拒否、bind 同士の入れ子は拒否（子の宛先が
//! ホストのディレクトリになり、無いディレクトリの作成がホストへ書き込む経路になるため）、
//! `check_against_host_paths` は子孫（bundle 配下など）を拒否しない。いずれも fail-closed 側または仕様どおりで、
//! 決定が出たらここを更新する。
//!
//! # Landlock との解釈の共有
//!
//! `ro`/`rw`・`noexec`/`exec` の「後の指定が勝つ」畳み込みは `landlock::rules::mount_rights` と同じ読みで、
//! `landlock/rules.rs` の照合試験が両者の結果を突き合わせる。解釈を変えるときはもう一方と照合試験を更新する。
//! `crate::landlock` は Linux 限定のため intra-doc リンクは張らない。
//!
//! # スコープ外（REPAIR-3）
//!
//! 本型は字句検証のみで、検証から適用までの TOCTOU を防がない。symlink を含む実体の照合・fd 起点 `O_NOFOLLOW` の
//! 走査・種別と存在の確認・宛先ディレクトリの作成・利用者権限での到達性・rootfs 自身とその祖先の実体照合（`dev`/`ino`）は、
//! 適用の段 `crate::exec::mount_binds`（#1913。実装済み。Linux 限定のため intra-doc リンクは張らない）が担う。
//! 実体照合の残余（REPAIR-3）は bundle・状態ルートと、ホスト側の別の bind mount による別名で、字句検証（`check_against_host_paths`）
//! だけが効く。`run_pre_pivot` への組み込みは #1914、`ro` と Landlock の `WriteRestrictionShadowed` の衝突解消は #1917、
//! `start` の結線は #1915。監査 sink の本番配線も #1915 で未実装。`MountDestination::resolve_in` の文字列結合で直接 mount してはならない。

use std::fmt;
use std::path::Path;

use super::config::{CONFIG_MAX_MOUNTS, CONFIG_MAX_PATH_BYTES, OciMount};
use super::mount_destination::MountDestination;
use crate::audit_log::{AuditSink, AuditedRejection, record_mount_rejection};
use crate::injected_files::{InjectedFileSet, overlaps};
use crate::path_masks::ProtectedPath;
use crate::tmpfs::TmpfsMountSet;
use crate::traits::{ContainerId, ErrorCode};

/// 暗黙・固定のマウントがある、bind を置けないコンテナ内の最上位（`/dev` 系は `crate::dev_mounts` の暗黙分と
/// `crate::path_masks` の固定集合をすべて覆う）。
const RESERVED_DESTINATIONS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// 検証済みの bind mount 1 件（フィールドは非公開。REPAIR-2）。
///
/// `nosuid` / `nodev` は常に付与され外せない（#1910）。伝播は常に private で、適用側は private で付ける。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountSpec {
    index: usize,
    destination: MountDestination,
    source: String,
    read_only: bool,
    noexec: bool,
    recursive: bool,
}

impl BindMountSpec {
    /// `mounts[]` 内の位置（監査・エラーの対応づけ用）。
    pub fn index(&self) -> usize {
        self.index
    }

    /// 正規化済みのコンテナ内マウント先。
    pub fn destination(&self) -> &MountDestination {
        &self.destination
    }

    /// 字句検証済みのホスト絶対パス（`/a/b` 形式）。
    pub fn source(&self) -> &str {
        &self.source
    }

    /// [`Self::source`] を `Path` として返す。
    pub fn source_path(&self) -> &Path {
        Path::new(&self.source)
    }

    /// 読み取り専用で付けるか。
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// `nosuid` を付ける（常に真。外せない）。
    pub fn nosuid(&self) -> bool {
        true
    }

    /// `nodev` を付ける（常に真。外せない）。
    pub fn nodev(&self) -> bool {
        true
    }

    /// `noexec` を付けるか（指定時のみ）。
    pub fn noexec(&self) -> bool {
        self.noexec
    }

    /// 再帰 bind（`rbind`）か。
    pub fn recursive(&self) -> bool {
        self.recursive
    }
}

/// bind mount 変換・検証の失敗分類。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindMountErrorKind {
    /// bind ではない種類（`UNIMPLEMENTED`）。
    NotBind,
    /// 件数が上限超過（位置なし）。
    TooMany {
        /// 指定された件数。
        count: usize,
        /// 上限。
        max: usize,
    },
    /// `source` が無い。
    MissingSource,
    /// `source` が字句規則に反する。
    InvalidSource,
    /// `source` が rootfs・bundle・状態ルートと同一または祖先。
    ForbiddenSource,
    /// `suid` / `dev`（制限を外す指定）。
    RestrictionLifting,
    /// 伝播系（`shared` / `slave` / `unbindable` 等）。
    Propagation,
    /// 許可集合外のオプション。
    UnsupportedOption,
    /// `bind` と `rbind` の併記（暫定）。
    ConflictingBindKind,
    /// `/proc`・`/sys`・`/dev` とその配下への bind。
    ReservedDestination,
    /// 先行の bind と同一の宛先。
    DuplicateDestination {
        /// 重複先の位置。
        other: usize,
    },
    /// 先行の bind と親子の宛先（暫定）。
    NestedDestination {
        /// 親子関係の相手の位置。
        other: usize,
    },
    /// tmpfs のマウント先と重なる。
    OverlapsTmpfs,
    /// 注入ファイルの親ディレクトリ・宛先と重なる。
    OverlapsInjected,
    /// `readonlyPaths` / `maskedPaths` と重なる。
    OverlapsProtectedPath,
}

/// bind mount 変換・検証のエラー（ERR-1）。メッセージは位置と固定英文のみで、パス・オプション値を含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMountError {
    index: Option<usize>,
    kind: BindMountErrorKind,
}

impl BindMountError {
    fn at(index: usize, kind: BindMountErrorKind) -> Self {
        Self {
            index: Some(index),
            kind,
        }
    }

    /// 構造化エラーコード。`NotBind` は `Unimplemented`、他は `InvalidArgument`。
    pub fn code(&self) -> ErrorCode {
        match self.kind {
            BindMountErrorKind::NotBind => ErrorCode::Unimplemented,
            _ => ErrorCode::InvalidArgument,
        }
    }

    /// 対象の `mounts[]` 内の位置（件数超過など集合全体の失敗は `None`）。
    pub fn index(&self) -> Option<usize> {
        self.index
    }

    /// 分類。
    pub fn kind(&self) -> &BindMountErrorKind {
        &self.kind
    }

    /// 位置と固定英文のみのメッセージ（入力値を含めない）。
    pub fn message(&self) -> String {
        let text = match &self.kind {
            BindMountErrorKind::NotBind => "mount type is not supported (only bind mounts)",
            BindMountErrorKind::TooMany { count, max } => {
                return format!("too many mounts: {count} exceeds limit {max}");
            }
            BindMountErrorKind::MissingSource => "bind mount has no source",
            BindMountErrorKind::InvalidSource => "bind mount source is not a valid absolute path",
            BindMountErrorKind::ForbiddenSource => "bind mount source is a forbidden host path",
            BindMountErrorKind::RestrictionLifting => "mount option lifts a mandatory restriction",
            BindMountErrorKind::Propagation => "mount propagation options are not supported",
            BindMountErrorKind::UnsupportedOption => "unsupported mount option",
            BindMountErrorKind::ConflictingBindKind => "both bind and rbind are specified",
            BindMountErrorKind::ReservedDestination => {
                "bind mount destination is reserved (/proc, /sys or /dev)"
            }
            BindMountErrorKind::DuplicateDestination { .. } => "duplicate bind mount destination",
            BindMountErrorKind::NestedDestination { .. } => "nested bind mount destinations",
            BindMountErrorKind::OverlapsTmpfs => "bind mount destination overlaps a tmpfs mount",
            BindMountErrorKind::OverlapsInjected => {
                "bind mount destination overlaps an injected file"
            }
            BindMountErrorKind::OverlapsProtectedPath => {
                "bind mount destination overlaps a readonly or masked path"
            }
        };
        match self.index {
            Some(i) => format!("mounts[{i}]: {text}"),
            None => text.to_owned(),
        }
    }
}

impl fmt::Display for BindMountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for BindMountError {}

/// 検証済みの bind mount 集合（`mounts[]` の指定順）。生成口は [`Self::from_mounts`] のみ。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindMountSet {
    mounts: Vec<BindMountSpec>,
}

impl BindMountSet {
    /// `mounts[]` を検証して bind の集合へ変換する。1 件でも拒否されれば全体を拒否する（fail-closed）。
    ///
    /// 件数は確保前に検証する。処理順は種類 → オプション → マウント元 → マウント先 → 先行 bind との関係。
    pub fn from_mounts(mounts: &[OciMount]) -> Result<Self, BindMountError> {
        if mounts.len() > CONFIG_MAX_MOUNTS {
            return Err(BindMountError {
                index: None,
                kind: BindMountErrorKind::TooMany {
                    count: mounts.len(),
                    max: CONFIG_MAX_MOUNTS,
                },
            });
        }
        let mut out: Vec<BindMountSpec> = Vec::with_capacity(mounts.len());
        for (index, m) in mounts.iter().enumerate() {
            let opts = parse_options(index, m)?;
            let source = validate_source(index, m)?;
            let dest = m.mount_destination();
            if RESERVED_DESTINATIONS
                .iter()
                .any(|r| overlaps(dest.as_str(), r) && dest.as_str().len() >= r.len())
            {
                return Err(BindMountError::at(
                    index,
                    BindMountErrorKind::ReservedDestination,
                ));
            }
            for prev in &out {
                if prev.destination.as_str() == dest.as_str() {
                    return Err(BindMountError::at(
                        index,
                        BindMountErrorKind::DuplicateDestination { other: prev.index },
                    ));
                }
                if overlaps(prev.destination.as_str(), dest.as_str()) {
                    return Err(BindMountError::at(
                        index,
                        BindMountErrorKind::NestedDestination { other: prev.index },
                    ));
                }
            }
            out.push(BindMountSpec {
                index,
                destination: dest.clone(),
                source,
                read_only: opts.read_only,
                noexec: opts.noexec,
                recursive: opts.recursive,
            });
        }
        Ok(Self { mounts: out })
    }

    /// 指定順の bind 一覧。
    pub fn mounts(&self) -> &[BindMountSpec] {
        &self.mounts
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// 利用者指定の tmpfs のマウント先と同一・祖先・子孫なら拒否する。
    pub fn check_against_tmpfs(&self, tmpfs: &TmpfsMountSet) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if tmpfs
                .mounts()
                .iter()
                .any(|t| overlaps(b.destination.as_str(), t.destination.as_str()))
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsTmpfs,
                ));
            }
        }
        Ok(())
    }

    /// 注入ファイルの親ディレクトリ・宛先と同一・祖先・子孫なら拒否する。
    pub fn check_against_injected(&self, injected: &InjectedFileSet) -> Result<(), BindMountError> {
        for b in &self.mounts {
            let hit = injected.files().iter().any(|f| {
                overlaps(b.destination.as_str(), f.parent())
                    || overlaps(b.destination.as_str(), f.destination().as_str())
            });
            if hit {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsInjected,
                ));
            }
        }
        Ok(())
    }

    /// `linux.readonlyPaths` / `linux.maskedPaths` と同一・祖先・子孫なら拒否する。
    ///
    /// `/proc`・`/sys` 配下の固定集合は [`Self::from_mounts`] の予約先拒否が覆う。
    pub fn check_against_protected_paths(
        &self,
        readonly: &[ProtectedPath],
        masked: &[ProtectedPath],
    ) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if readonly
                .iter()
                .chain(masked.iter())
                .any(|p| overlaps(b.destination.as_str(), p.as_str()))
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::OverlapsProtectedPath,
                ));
            }
        }
        Ok(())
    }

    /// マウント元が `forbidden`（rootfs・bundle・状態ルートのホスト絶対パス。呼び出し側が渡す）と
    /// 同一または祖先なら拒否する。
    ///
    /// 字句比較のみ。rootfs 自身とその祖先の実体照合は適用の段（#1913）が `dev`/`ino` で行う。bundle・状態ルートの実体照合は未対応。子孫は拒否しない（暫定）。
    pub fn check_against_host_paths(&self, forbidden: &[&str]) -> Result<(), BindMountError> {
        for b in &self.mounts {
            if forbidden
                .iter()
                .any(|f| overlaps(f, &b.source) && f.len() >= b.source.len())
            {
                return Err(BindMountError::at(
                    b.index,
                    BindMountErrorKind::ForbiddenSource,
                ));
            }
        }
        Ok(())
    }
}

/// options を畳み込んだ結果。
struct ParsedOptions {
    read_only: bool,
    noexec: bool,
    recursive: bool,
}

fn parse_options(index: usize, m: &OciMount) -> Result<ParsedOptions, BindMountError> {
    let err = |kind| BindMountError::at(index, kind);
    let (mut has_bind, mut has_rbind) = (false, false);
    let (mut read_only, mut noexec) = (false, false);
    // 種類判定を先に行う（処理順は種類 → オプション）。bind 以外は他オプションの内容に依らず NotBind。
    let opts_have = |name: &str| m.options().iter().any(|o| o.as_str() == name);
    if !(m.fs_type() == Some("bind") || opts_have("bind") || opts_have("rbind")) {
        return Err(err(BindMountErrorKind::NotBind));
    }
    for opt in m.options() {
        match opt.as_str() {
            "bind" => has_bind = true,
            "rbind" => has_rbind = true,
            "ro" => read_only = true,
            "rw" => read_only = false,
            "noexec" => noexec = true,
            "exec" => noexec = false,
            // 効果は常時付与済み（nosuid / nodev）または既定（private）。
            "nosuid" | "nodev" | "private" | "rprivate" => {}
            "suid" | "dev" => return Err(err(BindMountErrorKind::RestrictionLifting)),
            "shared" | "rshared" | "slave" | "rslave" | "unbindable" | "runbindable" => {
                return Err(err(BindMountErrorKind::Propagation));
            }
            _ => return Err(err(BindMountErrorKind::UnsupportedOption)),
        }
    }
    if has_bind && has_rbind {
        return Err(err(BindMountErrorKind::ConflictingBindKind));
    }
    Ok(ParsedOptions {
        read_only,
        noexec,
        recursive: has_rbind,
    })
}

fn validate_source(index: usize, m: &OciMount) -> Result<String, BindMountError> {
    let invalid = || BindMountError::at(index, BindMountErrorKind::InvalidSource);
    let path = m
        .source()
        .ok_or_else(|| BindMountError::at(index, BindMountErrorKind::MissingSource))?;
    let s = path.to_str().ok_or_else(invalid)?;
    if s.len() > CONFIG_MAX_PATH_BYTES || s.contains('\0') || s.contains('\\') {
        return Err(invalid());
    }
    let rest = s.strip_prefix('/').ok_or_else(invalid)?;
    // `/` のみ（rest が空）はホスト全体を覆うため拒否する。空要素・`.`・`..` も正規形以外として拒否する。
    if rest.is_empty() || rest.split('/').any(|e| matches!(e, "" | "." | "..")) {
        return Err(invalid());
    }
    Ok(s.to_owned())
}

/// bind mount の変換拒否を `Mount` 監査レコードにする（SEC-4）。
///
/// `path` は位置が `mounts` で解決できるときだけコンテナ内の宛先を載せる。マウント元（ホスト側パス）は載せない。
/// エラーは常にそのまま返る。sink の本番配線は #1915 で未実装（REPAIR-3）。
pub fn audit_bind_mount_error(
    err: BindMountError,
    mounts: &[OciMount],
    container: Option<&ContainerId>,
    sink: &dyn AuditSink,
) -> AuditedRejection<BindMountError> {
    let path = err
        .index()
        .and_then(|i| mounts.get(i))
        .map(|m| m.mount_destination().as_path());
    record_mount_rejection(err, path, container, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::AuditDelivery;
    use crate::audit_log::mount::tests::VecSink;
    use crate::dev_mounts::ImplicitDevMount;
    use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSpec};
    use crate::oci_runtime::{OciConfig, parse_config_bytes};
    use crate::tmpfs::TmpfsMountSpec;
    use serde_json::{Value, json};

    fn cfg_with(mounts: Value, extra: Value) -> OciConfig {
        let mut v = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "mounts": mounts,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in e {
                o.insert(k.clone(), val.clone());
            }
        }
        parse_config_bytes(v.to_string().as_bytes()).expect("valid config")
    }

    fn cfg(mounts: Value) -> OciConfig {
        cfg_with(mounts, json!({}))
    }

    fn one(ty: Option<&str>, dest: &str, src: Option<&str>, opts: &[&str]) -> Value {
        let mut m = json!({"destination": dest, "options": opts});
        if let (Some(o), Some(t)) = (m.as_object_mut(), ty) {
            o.insert("type".into(), json!(t));
        }
        if let (Some(o), Some(s)) = (m.as_object_mut(), src) {
            o.insert("source".into(), json!(s));
        }
        m
    }

    fn bind(opts: &[&str]) -> Value {
        one(Some("bind"), "/mnt/d", Some("/data"), opts)
    }

    fn set(mounts: Value) -> Result<BindMountSet, BindMountError> {
        BindMountSet::from_mounts(cfg(mounts).mounts())
    }

    fn kind_of(mounts: Value) -> (BindMountErrorKind, Option<usize>, ErrorCode) {
        let e = set(mounts).expect_err("must be rejected");
        (e.kind().clone(), e.index(), e.code())
    }

    /// OCI-4・CORE-2: 受ける bind の各フィールドを具体値で照合する。
    #[test]
    fn core2_oci4_bind_accepts_forms() {
        let s = set(json!([
            one(Some("bind"), "/a", Some("/data/a"), &[]),
            one(Some("none"), "/b", Some("/data/b"), &["rbind", "rprivate"]),
            one(None, "/c", Some("/data/c"), &["bind", "ro"]),
            one(
                Some("none"),
                "/d",
                Some("/data/d"),
                &["rbind", "nosuid", "nodev", "noexec", "private"]
            ),
        ]))
        .expect("accepted");
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        let m = s.mounts();
        assert_eq!(m[0].index(), 0);
        assert_eq!(m[0].destination().as_str(), "/a");
        assert_eq!(m[0].source(), "/data/a");
        assert_eq!(m[0].source_path(), Path::new("/data/a"));
        assert_eq!(
            (m[0].read_only(), m[0].noexec(), m[0].recursive()),
            (false, false, false)
        );
        assert_eq!(
            (m[1].read_only(), m[1].noexec(), m[1].recursive()),
            (false, false, true)
        );
        assert_eq!(
            (m[2].read_only(), m[2].noexec(), m[2].recursive()),
            (true, false, false)
        );
        assert_eq!(
            (m[3].read_only(), m[3].noexec(), m[3].recursive()),
            (false, true, true)
        );
        assert_eq!(m[3].index(), 3);
        for x in m {
            assert!(x.nosuid());
            assert!(x.nodev());
        }
    }

    /// CORE-5: ro/rw・noexec/exec は後の指定が勝つ。
    #[test]
    fn core5_bind_option_last_wins() {
        for (opts, ro, nx) in [
            (vec!["bind", "ro", "rw"], false, false),
            (vec!["bind", "rw", "ro"], true, false),
            (vec!["bind", "noexec", "exec"], false, false),
            (vec!["bind", "exec", "noexec"], false, true),
            (vec!["bind", "ro", "ro"], true, false),
        ] {
            let s = set(json!([bind(&opts)])).expect("accepted");
            let m = &s.mounts()[0];
            assert_eq!((m.read_only(), m.noexec()), (ro, nx), "opts={opts:?}");
        }
    }

    /// OCI-4: bind 以外の種類は UNIMPLEMENTED。位置を照合する。
    #[test]
    fn oci4_bind_rejects_non_bind_types() {
        for ty in ["proc", "tmpfs", "sysfs", "devpts", "mqueue", "cgroup"] {
            let (k, i, c) = kind_of(json!([
                bind(&[]),
                one(Some(ty), "/x", Some("/data/x"), &["nosuid"])
            ]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::NotBind,
                    Some(1),
                    ErrorCode::Unimplemented
                )
            );
        }
        let (k, _, c) = kind_of(json!([one(None, "/x", None, &[])]));
        assert_eq!(
            (k, c),
            (BindMountErrorKind::NotBind, ErrorCode::Unimplemented)
        );
        // 許可集合外のオプションがあっても種類判定が先（UNIMPLEMENTED）。
        for opts in [
            &["size=64m"][..],
            &["mode=755", "strictatime"],
            &["newinstance"],
        ] {
            let (k, i, c) = kind_of(json!([one(Some("tmpfs"), "/x", Some("/data/x"), opts)]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::NotBind,
                    Some(0),
                    ErrorCode::Unimplemented
                ),
                "opts={opts:?}"
            );
        }
    }

    /// SEC-1: 制限を外すオプションは拒否する。
    #[test]
    fn sec1_bind_rejects_lifting_options() {
        for o in ["suid", "dev"] {
            let (k, i, c) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(
                (k, i, c),
                (
                    BindMountErrorKind::RestrictionLifting,
                    Some(0),
                    ErrorCode::InvalidArgument
                )
            );
        }
    }

    /// SEC-1: 伝播系は拒否する。
    #[test]
    fn sec1_bind_rejects_propagation() {
        for o in [
            "shared",
            "rshared",
            "slave",
            "rslave",
            "unbindable",
            "runbindable",
        ] {
            let (k, _, _) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(k, BindMountErrorKind::Propagation, "opt={o}");
        }
    }

    /// SEC-1: 許可集合外は拒否する（fail-closed）。
    #[test]
    fn sec1_bind_rejects_unknown_options() {
        for o in [
            "defaults", "rro", "rnosuid", "rdev", "idmap", "remount", "", "RO",
        ] {
            let (k, _, _) = kind_of(json!([bind(&["bind", o])]));
            assert_eq!(k, BindMountErrorKind::UnsupportedOption, "opt={o:?}");
        }
    }

    /// CORE-2: bind と rbind の併記は拒否する（暫定）。
    #[test]
    fn core2_bind_rejects_bind_and_rbind() {
        let (k, i, _) = kind_of(json!([bind(&["bind", "rbind"])]));
        assert_eq!((k, i), (BindMountErrorKind::ConflictingBindKind, Some(0)));
    }

    /// CORE-2: マウント元の字句規則。
    #[test]
    fn core2_bind_source_lexical() {
        for ok in ["/data", "/a/b"] {
            assert!(
                set(json!([one(Some("bind"), "/x", Some(ok), &[])])).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "data", "./a", "/", "//", "/a//b", "/a/", "/a/./b", "/a/../b", "/a\\b",
        ] {
            let (k, i, _) = kind_of(json!([one(Some("bind"), "/x", Some(bad), &[])]));
            assert_eq!(
                (k, i),
                (BindMountErrorKind::InvalidSource, Some(0)),
                "src={bad}"
            );
        }
        let (k, _, _) = kind_of(json!([one(Some("bind"), "/x", None, &[])]));
        assert_eq!(k, BindMountErrorKind::MissingSource);
    }

    /// CORE-2・SEC-1: /proc・/sys・/dev とその配下は拒否する。
    #[test]
    fn core2_bind_rejects_reserved_destinations() {
        for d in [
            "/proc",
            "/proc/sys",
            "/sys",
            "/sys/fs",
            "/dev",
            "/dev/shm",
            "/dev/pts",
            "/dev/x",
        ] {
            let (k, _, _) = kind_of(json!([one(Some("bind"), d, Some("/data"), &[])]));
            assert_eq!(k, BindMountErrorKind::ReservedDestination, "dest={d}");
        }
        for d in ["/devx", "/procfs", "/system"] {
            assert!(
                set(json!([one(Some("bind"), d, Some("/data"), &[])])).is_ok(),
                "{d}"
            );
        }
        for m in ImplicitDevMount::ALL {
            let (k, _, _) = kind_of(json!([one(
                Some("bind"),
                m.destination(),
                Some("/data"),
                &[]
            )]));
            assert_eq!(k, BindMountErrorKind::ReservedDestination);
        }
    }

    /// CORE-2: 同一宛先・入れ子は拒否し、相手の位置を返す。
    #[test]
    fn core2_bind_rejects_duplicate_and_nested() {
        let m = |d: &str| one(Some("bind"), d, Some("/data"), &[]);
        let (k, i, _) = kind_of(json!([m("/a"), m("/a")]));
        assert_eq!(
            (k, i),
            (
                BindMountErrorKind::DuplicateDestination { other: 0 },
                Some(1)
            )
        );
        let (k, i, _) = kind_of(json!([m("/a"), m("/a/b")]));
        assert_eq!(
            (k, i),
            (BindMountErrorKind::NestedDestination { other: 0 }, Some(1))
        );
        let (k, i, _) = kind_of(json!([m("/a/b"), m("/a")]));
        assert_eq!(
            (k, i),
            (BindMountErrorKind::NestedDestination { other: 0 }, Some(1))
        );
        assert!(set(json!([m("/a"), m("/ab")])).is_ok());
    }

    /// CORE-2: 件数超過は確保前に拒否する。
    #[test]
    fn core2_bind_rejects_too_many() {
        let c = cfg(json!([bind(&[])]));
        let one_mount = c.mounts()[0].clone();
        let many = vec![one_mount; CONFIG_MAX_MOUNTS + 1];
        let e = BindMountSet::from_mounts(&many).expect_err("too many");
        assert_eq!(
            *e.kind(),
            BindMountErrorKind::TooMany {
                count: CONFIG_MAX_MOUNTS + 1,
                max: CONFIG_MAX_MOUNTS
            }
        );
        assert_eq!(e.index(), None);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// ERR-1: メッセージは位置と固定英文のみで入力値を含めない。
    #[test]
    fn err1_bind_error_message_has_no_values() {
        let c = cfg(json!([
            bind(&[]),
            one(
                Some("bind"),
                "/x",
                Some("/secret-host-dir"),
                &["bind", "x-token"]
            )
        ]));
        let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
        let (m, d) = (e.message(), e.to_string());
        assert_eq!(m, d);
        assert_eq!(m, "mounts[1]: unsupported mount option");
        assert!(!m.contains("x-token") && !m.contains("secret-host-dir"));
    }

    /// CORE-2: tmpfs・注入・保護パス・ホストパスとの交差検査。
    #[test]
    fn core2_bind_cross_checks() {
        let b = |d: &str| set(json!([one(Some("bind"), d, Some("/var/lib/y"), &[])])).expect("set");
        // tmpfs
        for d in ["/scratch", "/scratch/x", "/scratch/x/y"] {
            let mut t = TmpfsMountSet::new();
            t.push(TmpfsMountSpec::new("/scratch/x", None).expect("tmpfs"))
                .expect("push");
            let e = b(d).check_against_tmpfs(&t).expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsTmpfs);
        }
        let mut t = TmpfsMountSet::new();
        t.push(TmpfsMountSpec::new("/scratch", None).expect("tmpfs"))
            .expect("push");
        assert!(b("/other").check_against_tmpfs(&t).is_ok());
        // 注入
        let inj = |dest: &str| {
            let mut set = InjectedFileSet::new();
            set.push(
                InjectedFileSpec::new(
                    dest,
                    InjectedContent::from_bytes(b"x".to_vec()).expect("content"),
                    InjectedFileMode::DEFAULT,
                )
                .expect("spec"),
            )
            .expect("push");
            set
        };
        for d in ["/run/secrets", "/run", "/run/secrets/a"] {
            let e = b(d)
                .check_against_injected(&inj("/run/secrets/a"))
                .expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsInjected);
        }
        assert!(
            b("/other")
                .check_against_injected(&inj("/run/secrets/a"))
                .is_ok()
        );
        // 保護パス
        let c = cfg_with(
            json!([]),
            json!({"linux": {"readonlyPaths": ["/data/x"], "maskedPaths": ["/m/y"]}}),
        );
        for d in ["/data", "/data/x", "/m"] {
            let e = b(d)
                .check_against_protected_paths(c.readonly_paths(), c.masked_paths())
                .expect_err(d);
            assert_eq!(*e.kind(), BindMountErrorKind::OverlapsProtectedPath);
        }
        assert!(
            b("/datax")
                .check_against_protected_paths(c.readonly_paths(), c.masked_paths())
                .is_ok()
        );
        // ホストパス
        let host = ["/var/lib/x/rootfs"];
        for src in ["/var/lib", "/var/lib/x/rootfs"] {
            let one_b = set(json!([one(Some("bind"), "/d", Some(src), &[])])).expect("set");
            let e = one_b.check_against_host_paths(&host).expect_err(src);
            assert_eq!(*e.kind(), BindMountErrorKind::ForbiddenSource);
        }
        let ok = set(json!([one(Some("bind"), "/d", Some("/var/lib/y"), &[])])).expect("set");
        assert!(ok.check_against_host_paths(&host).is_ok());
    }

    /// SEC-4: 監査はコンテナ内の宛先のみを載せ、マウント元を載せない。
    #[test]
    fn sec4_bind_audit_records_destination_only() {
        let c = cfg(json!([
            bind(&[]),
            one(
                Some("bind"),
                "/mnt/two",
                Some("/secret-host-dir"),
                &["bind", "suid"]
            )
        ]));
        let e = BindMountSet::from_mounts(c.mounts()).expect_err("rejected");
        let sink = VecSink::new(false);
        let r = audit_bind_mount_error(e, c.mounts(), None, &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(r.error.code(), ErrorCode::InvalidArgument);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        let line = format!("{:?}", recs[0]);
        assert!(line.contains("/mnt/two"), "{line}");
        assert!(!line.contains("secret-host-dir"), "{line}");

        // 位置なし（件数超過）は path なしで記録し、sink 失敗でもエラーは返る。
        let many = vec![c.mounts()[0].clone(); CONFIG_MAX_MOUNTS + 1];
        let e = BindMountSet::from_mounts(&many).expect_err("too many");
        let bad = VecSink::new(true);
        let r = audit_bind_mount_error(e, &many, None, &bad);
        assert!(matches!(r.error.kind(), BindMountErrorKind::TooMany { .. }));
        assert_ne!(r.delivery, AuditDelivery::Recorded);
    }
}
