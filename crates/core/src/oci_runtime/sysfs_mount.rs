//! `mounts[]` の sysfs の指定を検証済みの型へ変換する（TASK-29 追補・#2020・SEC-2・OCI-4・CORE-5）。
//!
//! # 役割と呼び出し元
//!
//! OCI の既定 config は `{"destination":"/sys","type":"sysfs"}` を含む。実行層は #2020 のオーナー判断
//! （#2018 の 3。2026-10-15）により、これを**読み取り専用の sysfs**として `/sys` に供給する。本モジュールは
//! 「何を受けて何を拒否するか」を純粋関数 [`SysfsMountSpec::from_mounts`] と検証済みの型 [`SysfsMountSpec`] に
//! 固定する。`start` が呼び、結果は `LaunchSpec` → 本番 launcher → pivot 前段（Linux 限定の
//! `exec::mount_sysfs`）へ渡る。適用側は本型だけを入力にし、`OciMount` の文字列を再解釈しない。
//!
//! `cfg` を付けず 3 OS でビルドし、syscall・ファイルシステムへのアクセスをしない（CLI-1）。
//!
//! # 種類の判定の共有
//!
//! `OciMountKind::of` が `mounts[]` の 1 件を bind／sysfs／その他に分類する。bind の判定（`type == "bind"`、
//! または options に `bind` / `rbind`）を優先し、それ以外で `type == "sysfs"` のものを sysfs とする。
//! `BindMountSet` は sysfs を飛ばし（位置は保つ）、Landlock のルール生成も同じ分類で `/sys` の sysfs を
//! 扱う。分類を変えるときは両者と照合試験を更新する。
//!
//! # 受け入れ規則
//!
//! - 宛先: 正規化後に `/sys` と完全一致のみ。それ以外は [`SysfsMountErrorKind::UnsupportedDestination`]
//! - `source`: 無指定または `"sysfs"` のみ（カーネルは使わない値。ホストのパスとして扱わない）
//! - options: `ro`・`nosuid`・`nodev`・`noexec` のみ（いずれも常に付くため no-op）。
//!   `rw`・`suid`・`dev`・`exec` は [`SysfsMountErrorKind::RestrictionLifting`]、伝播系は
//!   [`SysfsMountErrorKind::Propagation`]、それ以外（`defaults`・`rro` 等の未知）は
//!   [`SysfsMountErrorKind::UnsupportedOption`]
//! - 件数: sysfs は 1 件まで（2 件目は [`SysfsMountErrorKind::DuplicateDestination`]）
//! - 常に付ける: `ro`・`nosuid`・`nodev`・`noexec`（型が常に真を返し、外した値を表現できない。REPAIR-2）
//!
//! # OCI Runtime Spec・runc との差
//!
//! | 項目 | 仕様・runc の読み | 本実装 |
//! | -- | -- | -- |
//! | 宛先 | 任意 | `/sys` のみ |
//! | `rw`・`suid`・`dev`・`exec` | 受ける | 拒否（黙って ro に丸めない。SEC-1） |
//! | 供給方式 | 新しい sysfs を載せる。rootless は rbind へ差し替える（runc。条件は未確認） | 事前に方式を決め、失敗しても縮退しない（`exec::mount_sysfs`） |
//!
//! runc・moby の扱いは一次資料で確かめきれていない部分がある（未確認の項目は上表に明記）。差が確定したら
//! 本表を更新する（REPAIR-3）。

use std::fmt;

use super::config::OciMount;
use crate::audit_log::{AuditSink, AuditedRejection, record_mount_rejection};
use crate::traits::{ContainerId, ErrorCode};

/// sysfs を置ける唯一の宛先。
const SYSFS_DESTINATION: &str = "/sys";

/// `mounts[]` の 1 件の種類（bind 側・sysfs 側・Landlock 側が同じ分類を使う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OciMountKind {
    /// bind mount（`type == "bind"`、または options に `bind` / `rbind`）。
    Bind,
    /// sysfs（bind ではなく `type == "sysfs"`）。
    Sysfs,
    /// 上記以外（実行層は未対応）。
    Other,
}

impl OciMountKind {
    /// 1 件の種類を判定する。bind の判定を優先する。
    pub(crate) fn of(m: &OciMount) -> Self {
        let opts_have = |name: &str| m.options().iter().any(|o| o.as_str() == name);
        if m.fs_type() == Some("bind") || opts_have("bind") || opts_have("rbind") {
            Self::Bind
        } else if m.fs_type() == Some("sysfs") {
            Self::Sysfs
        } else {
            Self::Other
        }
    }
}

/// 検証済みの sysfs mount 1 件（フィールドは非公開。REPAIR-2）。
///
/// 宛先は常に `/sys`。`ro`・`nosuid`・`nodev`・`noexec` は常に付与され外せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsMountSpec {
    index: usize,
}

impl SysfsMountSpec {
    /// `mounts[]` 内の位置（監査・エラーの対応づけ用）。
    pub fn index(&self) -> usize {
        self.index
    }

    /// コンテナ内のマウント先（常に `/sys`）。
    pub fn destination(&self) -> &'static str {
        SYSFS_DESTINATION
    }

    /// 読み取り専用で付ける（常に真。外せない）。
    pub fn read_only(&self) -> bool {
        true
    }

    /// `nosuid` を付ける（常に真。外せない）。
    pub fn nosuid(&self) -> bool {
        true
    }

    /// `nodev` を付ける（常に真。外せない）。
    pub fn nodev(&self) -> bool {
        true
    }

    /// `noexec` を付ける（常に真。外せない）。
    pub fn noexec(&self) -> bool {
        true
    }

    /// `mounts[]` から sysfs の指定を取り出して検証する。sysfs が無ければ `Ok(None)`。
    ///
    /// 1 件でも拒否されれば全体を拒否する（fail-closed）。`mounts[]` の件数上限の検証は
    /// `BindMountSet::from_mounts` が先に行う。
    pub fn from_mounts(mounts: &[OciMount]) -> Result<Option<Self>, SysfsMountError> {
        let mut found: Option<Self> = None;
        for (index, m) in mounts.iter().enumerate() {
            if OciMountKind::of(m) != OciMountKind::Sysfs {
                continue;
            }
            let err = |kind| SysfsMountError { index, kind };
            if m.mount_destination().as_str() != SYSFS_DESTINATION {
                return Err(err(SysfsMountErrorKind::UnsupportedDestination));
            }
            match m.source() {
                None => {}
                Some(p) if p.to_str() == Some("sysfs") => {}
                Some(_) => return Err(err(SysfsMountErrorKind::InvalidSource)),
            }
            for opt in m.options() {
                match opt.as_str() {
                    // 効果は常時付与済み。
                    "ro" | "nosuid" | "nodev" | "noexec" => {}
                    "rw" | "suid" | "dev" | "exec" => {
                        return Err(err(SysfsMountErrorKind::RestrictionLifting));
                    }
                    "shared" | "rshared" | "slave" | "rslave" | "private" | "rprivate"
                    | "unbindable" | "runbindable" => {
                        return Err(err(SysfsMountErrorKind::Propagation));
                    }
                    _ => return Err(err(SysfsMountErrorKind::UnsupportedOption)),
                }
            }
            if let Some(prev) = &found {
                return Err(err(SysfsMountErrorKind::DuplicateDestination {
                    other: prev.index,
                }));
            }
            found = Some(Self { index });
        }
        Ok(found)
    }
}

/// sysfs mount 変換・検証の失敗分類。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SysfsMountErrorKind {
    /// 宛先が `/sys` ではない。
    UnsupportedDestination,
    /// `source` が無指定・`"sysfs"` 以外。
    InvalidSource,
    /// `rw`・`suid`・`dev`・`exec`（常時の制限を外す指定）。
    RestrictionLifting,
    /// 伝播系（`shared` / `private` 等）。
    Propagation,
    /// 許可集合外のオプション。
    UnsupportedOption,
    /// sysfs の指定が 2 件以上ある。
    DuplicateDestination {
        /// 先行する sysfs の位置。
        other: usize,
    },
}

/// sysfs mount 変換・検証のエラー（ERR-1）。メッセージは位置と固定英文のみで、入力値を含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsMountError {
    index: usize,
    kind: SysfsMountErrorKind,
}

impl SysfsMountError {
    /// 構造化エラーコード（常に `InvalidArgument`）。
    pub fn code(&self) -> ErrorCode {
        ErrorCode::InvalidArgument
    }

    /// 対象の `mounts[]` 内の位置。
    pub fn index(&self) -> usize {
        self.index
    }

    /// 分類。
    pub fn kind(&self) -> &SysfsMountErrorKind {
        &self.kind
    }

    /// 位置と固定英文のみのメッセージ。
    pub fn message(&self) -> String {
        let text = match &self.kind {
            SysfsMountErrorKind::UnsupportedDestination => "sysfs mount destination must be /sys",
            SysfsMountErrorKind::InvalidSource => "sysfs mount source must be absent or sysfs",
            SysfsMountErrorKind::RestrictionLifting => {
                "sysfs mount option lifts a mandatory restriction"
            }
            SysfsMountErrorKind::Propagation => "mount propagation options are not supported",
            SysfsMountErrorKind::UnsupportedOption => "unsupported sysfs mount option",
            SysfsMountErrorKind::DuplicateDestination { .. } => "duplicate sysfs mount",
        };
        format!("mounts[{}]: {text}", self.index)
    }
}

impl fmt::Display for SysfsMountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SysfsMountError {}

/// sysfs mount の変換拒否を `Mount` 監査記録にする（SEC-4）。エラーは常にそのまま返る。
///
/// `path` は位置が `mounts` で解決できるときだけコンテナ内の宛先を載せる（ホスト側パスは載せない）。
pub fn audit_sysfs_mount_error(
    err: SysfsMountError,
    mounts: &[OciMount],
    container: Option<&ContainerId>,
    sink: &dyn AuditSink,
) -> AuditedRejection<SysfsMountError> {
    let path = mounts
        .get(err.index())
        .map(|m| m.mount_destination().as_path());
    record_mount_rejection(err, path, container, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::{OciConfig, parse_config_bytes};
    use serde_json::{Value, json};

    fn cfg(mounts: Value) -> OciConfig {
        let v = json!({"ociVersion": "1.2.0", "root": {"path": "rootfs"}, "mounts": mounts});
        parse_config_bytes(v.to_string().as_bytes()).expect("valid config")
    }

    fn sysfs(dest: &str, src: Option<&str>, opts: &[&str]) -> Value {
        let mut m = json!({"destination": dest, "type": "sysfs", "options": opts});
        if let (Some(o), Some(s)) = (m.as_object_mut(), src) {
            o.insert("source".into(), json!(s));
        }
        m
    }

    fn parse(mounts: Value) -> Result<Option<SysfsMountSpec>, SysfsMountError> {
        SysfsMountSpec::from_mounts(cfg(mounts).mounts())
    }

    fn reject(mounts: Value) -> (SysfsMountErrorKind, usize, ErrorCode) {
        let e = parse(mounts).expect_err("must be rejected");
        (e.kind().clone(), e.index(), e.code())
    }

    /// SEC-2・OCI-4: OCI 既定の sysfs を受け、ro・nosuid・nodev・noexec が常に真になる。
    #[test]
    fn sec2_oci4_sysfs_accepts_oci_default() {
        let spec = parse(json!([
            {"destination": "/proc", "type": "proc", "source": "proc"},
            sysfs("/sys", Some("sysfs"), &["nosuid", "noexec", "nodev", "ro"]),
        ]))
        .expect("accepted")
        .expect("present");
        assert_eq!(spec.index(), 1);
        assert_eq!(spec.destination(), "/sys");
        assert!(spec.read_only() && spec.nosuid() && spec.nodev() && spec.noexec());
    }

    /// OCI-4: options 無し・source 無し・末尾スラッシュの宛先（正規化で `/sys`）も受ける。
    #[test]
    fn oci4_sysfs_accepts_minimal_and_normalized_destination() {
        let idx = |v: Value| parse(v).expect("ok").map(|s| s.index());
        assert_eq!(idx(json!([sysfs("/sys", None, &[])])), Some(0));
        assert_eq!(idx(json!([sysfs("/sys/", None, &["ro"])])), Some(0));
        assert_eq!(idx(json!([])), None);
    }

    /// SEC-2: 宛先が `/sys` 以外の sysfs は拒否する。
    #[test]
    fn sec2_sysfs_rejects_other_destinations() {
        for dest in ["/x", "/sys/fs", "/mnt/sys", "/proc"] {
            assert_eq!(
                reject(json!([sysfs(dest, None, &[])])),
                (
                    SysfsMountErrorKind::UnsupportedDestination,
                    0,
                    ErrorCode::InvalidArgument
                ),
                "dest={dest}"
            );
        }
    }

    /// SEC-1: 制限を外す・伝播・未知のオプションは種類ごとに拒否する。
    #[test]
    fn sec1_sysfs_rejects_options() {
        for opt in ["rw", "suid", "dev", "exec"] {
            assert_eq!(
                reject(json!([sysfs("/sys", None, &[opt])])).0,
                SysfsMountErrorKind::RestrictionLifting,
                "opt={opt}"
            );
        }
        for opt in [
            "shared",
            "rshared",
            "slave",
            "rslave",
            "private",
            "rprivate",
            "unbindable",
        ] {
            assert_eq!(
                reject(json!([sysfs("/sys", None, &[opt])])).0,
                SysfsMountErrorKind::Propagation,
                "opt={opt}"
            );
        }
        for opt in ["defaults", "rro", "size=1m", "relatime"] {
            assert_eq!(
                reject(json!([sysfs("/sys", None, &["ro", opt])])).0,
                SysfsMountErrorKind::UnsupportedOption,
                "opt={opt}"
            );
        }
    }

    /// SEC-1: source は無指定か `sysfs` のみ。2 件目の sysfs は重複として拒否する。
    #[test]
    fn sec1_sysfs_rejects_source_and_duplicates() {
        for src in ["/sys", "/proc", "bogus"] {
            assert_eq!(
                reject(json!([sysfs("/sys", Some(src), &[])])).0,
                SysfsMountErrorKind::InvalidSource,
                "src={src}"
            );
        }
        assert_eq!(
            reject(json!([
                sysfs("/sys", None, &[]),
                sysfs("/sys", None, &["ro"])
            ])),
            (
                SysfsMountErrorKind::DuplicateDestination { other: 0 },
                1,
                ErrorCode::InvalidArgument
            )
        );
    }

    /// 種類の判定: bind が優先され、`type: sysfs` に `bind` を足した指定は sysfs として扱わない。
    #[test]
    fn oci4_mount_kind_prefers_bind() {
        let c = cfg(json!([
            sysfs("/sys", None, &["ro"]),
            sysfs("/x", None, &["bind"]),
            {"destination": "/y", "type": "bind", "source": "/d"},
            {"destination": "/t", "type": "tmpfs"},
        ]));
        let kinds: Vec<_> = c.mounts().iter().map(OciMountKind::of).collect();
        assert_eq!(
            kinds,
            [
                OciMountKind::Sysfs,
                OciMountKind::Bind,
                OciMountKind::Bind,
                OciMountKind::Other
            ]
        );
        assert_eq!(
            SysfsMountSpec::from_mounts(c.mounts())
                .expect("ok")
                .map(|s| s.index()),
            Some(0)
        );
    }

    /// ERR-1: メッセージは位置と固定英文のみで、入力値を含まない。
    #[test]
    fn err1_sysfs_message_has_no_input_values() {
        let e = parse(json!([sysfs(
            "/secret/dest",
            Some("/secret/src"),
            &["secret-opt"]
        )]))
        .expect_err("rejected");
        assert_eq!(
            e.message(),
            "mounts[0]: sysfs mount destination must be /sys"
        );
        let e = parse(json!([sysfs("/sys", Some("/secret/src"), &[])])).expect_err("rejected");
        assert_eq!(
            e.message(),
            "mounts[0]: sysfs mount source must be absent or sysfs"
        );
    }
}
