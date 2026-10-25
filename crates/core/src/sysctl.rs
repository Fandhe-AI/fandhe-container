//! `linux.sysctl` のキー・値の検証と名前空間の分類（CRI-2・CORE-3・SEC-1・REPAIR-2。#2670）。
//!
//! # 役割と呼び出し元
//!
//! OS 非依存の純関数と検証済みの型だけを置く。`oci_runtime::config` が `config.json` の `linux.sysctl` を
//! [`SysctlSet`] へ変換し、`oci_runtime::start` / `launcher` が実効の名前空間との整合を確かめ、`exec` の pivot 前段
//! （`apply_sysctls`）が `/proc/sys` 配下へ書く。`fandhe-container-cri` も pod の `sysctls` の受け入れ判定に
//! [`SysctlKey::parse`] を再利用し、規則を二重に持たない。
//!
//! # 受けるキー（namespaced のみ。fail-closed）
//!
//! | 分類 | キー | 要る名前空間 |
//! | ---- | ---- | ------------ |
//! | [`SysctlNamespace::Ipc`] | `kernel.msgmax`・`kernel.msgmnb`・`kernel.msgmni`・`kernel.sem`・`kernel.shmall`・`kernel.shmmax`・`kernel.shmmni`・`kernel.shm_rmid_forced`・`fs.mqueue.` 以下 | IPC namespace |
//! | [`SysctlNamespace::Net`] | `net.` 以下 | network namespace |
//!
//! `kernel.hostname`・`kernel.domainname` は UTS namespace に属するが、前者は `hostname` 欄と競合し、後者は未適用の
//! 項目のため [`SysctlError::Uts`] で拒否する（「まだ」受けない側。`Unimplemented` に写る）。それ以外は名前空間を持たず
//! ホスト全体に効くため [`SysctlError::NotNamespaced`]（設計上受けない側。`InvalidArgument` に写る）。
//!
//! 出典: runc `libcontainer/configs/validate/validator.go` の `sysctl`（tag v1.3.0、commit
//! `4ca628d1d4c974f92d24daccb901aa078aad748e`、Apache-2.0）の許可集合と同じ分類。写したのはキー名と接頭辞だけで、
//! ロジックは写していない。runc の NOTICE の内容（帰属行と輸出規制の注記）はルート `NOTICE` に記載済み（#2670）。
//!
//! # 文法（`/proc/sys` 配下のパスへ変換するため、すり抜けを文法の段で閉じる）
//!
//! - 区切りは `.` のみ。runc と違い `/` 区切りは受けない（`kernel/shmmax` の形で許可リストをすり抜けさせない。既知の差）
//! - 各要素は 1 文字以上の `[A-Za-z0-9_-]`。先頭・末尾・連続の `.` は拒否。キーは [`SYSCTL_MAX_KEY_BYTES`] バイト以下、
//!   要素数は [`SYSCTL_MAX_KEY_SEGMENTS`] 以下
//! - 値は 1 以上 [`SYSCTL_MAX_VALUE_BYTES`] バイト以下の印字可能 ASCII・空白・タブ（NUL・改行・制御文字・非 ASCII は拒否）
//! - エラーの文言にキー・値を含めない（内容の漏えいとログ汚染を避ける）

use std::collections::BTreeMap;
use std::fmt;

/// `linux.sysctl` の最大件数（CRI の `MAX_CONFIG_COLLECTION_ENTRIES` と同値。cri 側が一致を試験で照合する）。
pub const SYSCTL_MAX_ENTRIES: usize = 1024;
/// キーの最大バイト数。
pub const SYSCTL_MAX_KEY_BYTES: usize = 256;
/// キーの最大要素数（`.` 区切り）。
pub const SYSCTL_MAX_KEY_SEGMENTS: usize = 16;
/// 値の最大バイト数。
pub const SYSCTL_MAX_VALUE_BYTES: usize = 4096;

/// IPC namespace に属する個別キー（接頭辞 `fs.mqueue.` は別に判定する）。
const IPC_KEYS: [&str; 8] = [
    "kernel.msgmax",
    "kernel.msgmnb",
    "kernel.msgmni",
    "kernel.sem",
    "kernel.shmall",
    "kernel.shmmax",
    "kernel.shmmni",
    "kernel.shm_rmid_forced",
];

/// キーが属する名前空間（これが無いと書き込みはホストの値を変える）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SysctlNamespace {
    /// IPC namespace。
    Ipc,
    /// network namespace。
    Net,
}

/// sysctl のキーまたは値の拒否理由（機械可読。キー・値の内容は含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SysctlError {
    /// 文法違反（空・不正文字・区切りの誤り・上限超過など）。
    Malformed,
    /// 名前空間を持たない（ホスト全体に効く）。設計上受けない。
    NotNamespaced,
    /// UTS namespace に属するキー（`kernel.hostname`・`kernel.domainname`）。まだ受けない。
    Uts,
}

impl fmt::Display for SysctlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed sysctl key or value",
            Self::NotNamespaced => "sysctl is not in a separate kernel namespace",
            Self::Uts => "sysctl in the UTS namespace is not supported",
        })
    }
}

impl std::error::Error for SysctlError {}

/// 検証済みの sysctl キー（`.` 区切り・分類済み）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SysctlKey {
    name: String,
    namespace: SysctlNamespace,
}

impl SysctlKey {
    /// 文法を検証して分類する。許可リスト外・UTS 系は理由別のエラーで拒否する。
    pub fn parse(raw: &str) -> Result<Self, SysctlError> {
        check_grammar(raw)?;
        let namespace = if IPC_KEYS.contains(&raw) || raw.starts_with("fs.mqueue.") {
            SysctlNamespace::Ipc
        } else if raw.starts_with("net.") {
            SysctlNamespace::Net
        } else if raw == "kernel.hostname" || raw == "kernel.domainname" {
            return Err(SysctlError::Uts);
        } else {
            return Err(SysctlError::NotNamespaced);
        };
        Ok(Self {
            name: raw.to_owned(),
            namespace,
        })
    }

    /// `.` 区切りのキー名。
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// 属する名前空間。
    pub fn namespace(&self) -> SysctlNamespace {
        self.namespace
    }

    /// `/proc/sys` からの相対パスの各要素（`.` で分けたもの）。文法検証済みのため `/`・`..`・空要素を含まない。
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.name.split('.')
    }
}

fn check_grammar(raw: &str) -> Result<(), SysctlError> {
    if raw.is_empty() || raw.len() > SYSCTL_MAX_KEY_BYTES {
        return Err(SysctlError::Malformed);
    }
    let mut segments = 0usize;
    for seg in raw.split('.') {
        segments += 1;
        if segments > SYSCTL_MAX_KEY_SEGMENTS
            || seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(SysctlError::Malformed);
        }
    }
    Ok(())
}

/// 検証済みの sysctl 値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlValue(String);

impl SysctlValue {
    /// 値の文法を検証する。
    pub fn parse(raw: &str) -> Result<Self, SysctlError> {
        let ok = !raw.is_empty()
            && raw.len() <= SYSCTL_MAX_VALUE_BYTES
            && raw
                .bytes()
                .all(|b| b == b'\t' || b == b' ' || b.is_ascii_graphic());
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(SysctlError::Malformed)
        }
    }

    /// 値の文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 検証済みの sysctl の集合（キーの昇順・重複なし・[`SYSCTL_MAX_ENTRIES`] 件以下）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysctlSet {
    entries: BTreeMap<String, (SysctlKey, SysctlValue)>,
}

impl SysctlSet {
    /// 空集合（何も適用しない）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 件足す。キーの重複・件数超過は [`SysctlError::Malformed`]。
    pub fn insert(&mut self, key: SysctlKey, value: SysctlValue) -> Result<(), SysctlError> {
        if self.entries.len() >= SYSCTL_MAX_ENTRIES || self.entries.contains_key(key.as_str()) {
            return Err(SysctlError::Malformed);
        }
        self.entries.insert(key.as_str().to_owned(), (key, value));
        Ok(())
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// キー昇順の `(キー, 値)`。
    pub fn iter(&self) -> impl Iterator<Item = (&SysctlKey, &SysctlValue)> {
        self.entries.values().map(|(k, v)| (k, v))
    }

    /// 指定の名前空間に属するキーを含むか。
    pub fn has_namespace(&self, namespace: SysctlNamespace) -> bool {
        self.iter().any(|(k, _)| k.namespace() == namespace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-2・CORE-3: namespaced のキーは分類され、他は理由別に拒否される。
    #[test]
    fn classifies_keys_with_concrete_values() {
        let ns = |k: &str| SysctlKey::parse(k).map(|k| k.namespace());
        assert_eq!(ns("kernel.shmmax"), Ok(SysctlNamespace::Ipc));
        assert_eq!(ns("kernel.sem"), Ok(SysctlNamespace::Ipc));
        assert_eq!(ns("kernel.shm_rmid_forced"), Ok(SysctlNamespace::Ipc));
        assert_eq!(ns("fs.mqueue.msg_max"), Ok(SysctlNamespace::Ipc));
        assert_eq!(
            ns("net.ipv4.ip_unprivileged_port_start"),
            Ok(SysctlNamespace::Net)
        );
        assert_eq!(ns("kernel.hostname"), Err(SysctlError::Uts));
        assert_eq!(ns("kernel.domainname"), Err(SysctlError::Uts));
        for k in ["kernel.panic", "vm.swappiness", "fs.file-max", "kernel.shm"] {
            assert_eq!(ns(k), Err(SysctlError::NotNamespaced), "{k}");
        }
    }

    /// 文法違反（許可リストのすり抜けを含む）は `Malformed`。
    #[test]
    fn rejects_malformed_keys() {
        let long = format!("net.{}", "a".repeat(SYSCTL_MAX_KEY_BYTES));
        let many = format!("net.{}", vec!["a"; SYSCTL_MAX_KEY_SEGMENTS].join("."));
        for k in [
            "",
            "kernel/shmmax",
            "kernel..shmmax",
            ".kernel.shmmax",
            "net.ipv4.",
            "net.ipv4/conf",
            "net.a\0b",
            "net.ipv4.é",
            "net.a b",
            "net.../x",
            long.as_str(),
            many.as_str(),
        ] {
            assert_eq!(
                SysctlKey::parse(k).map(|_| ()),
                Err(SysctlError::Malformed),
                "{k:?}"
            );
        }
        // 16 要素ちょうどは受ける。
        let ok = format!("net.{}", vec!["a"; SYSCTL_MAX_KEY_SEGMENTS - 1].join("."));
        assert!(SysctlKey::parse(&ok).is_ok());
    }

    /// 値の文法。
    #[test]
    fn value_grammar() {
        assert_eq!(
            SysctlValue::parse("250 32000 32 128").unwrap().as_str(),
            "250 32000 32 128"
        );
        assert!(SysctlValue::parse("0\t0").is_ok());
        assert!(SysctlValue::parse(&"1".repeat(SYSCTL_MAX_VALUE_BYTES)).is_ok());
        for v in ["", "1\n", "1\0", "é", "a\x7f", "a\r"] {
            assert_eq!(SysctlValue::parse(v), Err(SysctlError::Malformed), "{v:?}");
        }
        assert_eq!(
            SysctlValue::parse(&"1".repeat(SYSCTL_MAX_VALUE_BYTES + 1)),
            Err(SysctlError::Malformed)
        );
    }

    /// 集合は昇順・重複拒否・名前空間の問い合わせができる。
    #[test]
    fn set_is_ordered_and_rejects_duplicates() {
        let mut set = SysctlSet::new();
        let k = |s: &str| SysctlKey::parse(s).unwrap();
        let v = |s: &str| SysctlValue::parse(s).unwrap();
        set.insert(k("kernel.shmmax"), v("1")).unwrap();
        set.insert(k("kernel.msgmax"), v("2")).unwrap();
        assert_eq!(
            set.insert(k("kernel.shmmax"), v("3")),
            Err(SysctlError::Malformed)
        );
        let keys: Vec<&str> = set.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["kernel.msgmax", "kernel.shmmax"]);
        assert!(set.has_namespace(SysctlNamespace::Ipc));
        assert!(!set.has_namespace(SysctlNamespace::Net));
        assert_eq!(
            k("fs.mqueue.msg_max").segments().collect::<Vec<_>>(),
            ["fs", "mqueue", "msg_max"]
        );
    }

    /// 件数の上限。
    #[test]
    fn set_entry_limit() {
        let mut set = SysctlSet::new();
        for i in 0..SYSCTL_MAX_ENTRIES {
            set.insert(
                SysctlKey::parse(&format!("net.k{i}")).unwrap(),
                SysctlValue::parse("1").unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            set.insert(
                SysctlKey::parse("net.over").unwrap(),
                SysctlValue::parse("1").unwrap()
            ),
            Err(SysctlError::Malformed)
        );
    }
}
