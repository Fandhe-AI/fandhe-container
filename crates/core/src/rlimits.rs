//! rlimit（`process.rlimits`・Docker の `--ulimit`）の検証済み型（SUP-12・TASK-169.1・#526・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! コンテナプロセスへ適用するリソース制限を「壊れた値を表現できない」型で持つ（REPAIR-2）。
//! 数値の検証（`soft <= hard`・種別の重複禁止・件数上限）をここで済ませ、syscall 層
//! （`sys.rs` の `prlimit(2)` ラッパー）へは検証済みの値だけを渡す。OS 非依存で syscall を持たない。
//!
//! - 構築側: `fandhe-container-supervisor` の `container_options`（`--ulimit` 形式の解釈）
//! - 適用側: `exec::StagePipeline::with_rlimits`（fork 後・capability 削減の前に `prlimit(2)` で適用。Linux 限定）
//!
//! # 未結線の箇所（REPAIR-3）
//!
//! OCI `config.json` の `process.rlimits` はパーサがまだ型付きで解釈せず、`create` / `start` は
//! `Unimplemented` で拒否する（fail-closed）。config → `LaunchSpec` → `with_rlimits` の結線は後続作業。
//! `--ulimit` の指定は起動オプション（`LaunchOptions::with_rlimits`。#2713）経由で本番 launcher が 16 種へ補完して適用する。

use crate::traits::types::{ErrorCode, TraitError};

/// 無制限（`RLIM_INFINITY`）。OCI の uint64 表現（`u64::MAX`）をそのまま通す。
pub const RLIMIT_INFINITY: u64 = u64::MAX;

/// rlimit の種別（Linux の 16 種）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RlimitKind {
    /// `RLIMIT_CPU`
    Cpu,
    /// `RLIMIT_FSIZE`
    Fsize,
    /// `RLIMIT_DATA`
    Data,
    /// `RLIMIT_STACK`
    Stack,
    /// `RLIMIT_CORE`
    Core,
    /// `RLIMIT_RSS`
    Rss,
    /// `RLIMIT_NPROC`
    Nproc,
    /// `RLIMIT_NOFILE`
    Nofile,
    /// `RLIMIT_MEMLOCK`
    Memlock,
    /// `RLIMIT_AS`
    As,
    /// `RLIMIT_LOCKS`
    Locks,
    /// `RLIMIT_SIGPENDING`
    Sigpending,
    /// `RLIMIT_MSGQUEUE`
    Msgqueue,
    /// `RLIMIT_NICE`
    Nice,
    /// `RLIMIT_RTPRIO`
    Rtprio,
    /// `RLIMIT_RTTIME`
    Rttime,
}

impl RlimitKind {
    /// 全種別（件数上限の根拠）。
    pub const ALL: [RlimitKind; 16] = [
        RlimitKind::Cpu,
        RlimitKind::Fsize,
        RlimitKind::Data,
        RlimitKind::Stack,
        RlimitKind::Core,
        RlimitKind::Rss,
        RlimitKind::Nproc,
        RlimitKind::Nofile,
        RlimitKind::Memlock,
        RlimitKind::As,
        RlimitKind::Locks,
        RlimitKind::Sigpending,
        RlimitKind::Msgqueue,
        RlimitKind::Nice,
        RlimitKind::Rtprio,
        RlimitKind::Rttime,
    ];

    /// OCI 名（`RLIMIT_NOFILE` 等）。
    pub fn as_oci_name(self) -> &'static str {
        match self {
            RlimitKind::Cpu => "RLIMIT_CPU",
            RlimitKind::Fsize => "RLIMIT_FSIZE",
            RlimitKind::Data => "RLIMIT_DATA",
            RlimitKind::Stack => "RLIMIT_STACK",
            RlimitKind::Core => "RLIMIT_CORE",
            RlimitKind::Rss => "RLIMIT_RSS",
            RlimitKind::Nproc => "RLIMIT_NPROC",
            RlimitKind::Nofile => "RLIMIT_NOFILE",
            RlimitKind::Memlock => "RLIMIT_MEMLOCK",
            RlimitKind::As => "RLIMIT_AS",
            RlimitKind::Locks => "RLIMIT_LOCKS",
            RlimitKind::Sigpending => "RLIMIT_SIGPENDING",
            RlimitKind::Msgqueue => "RLIMIT_MSGQUEUE",
            RlimitKind::Nice => "RLIMIT_NICE",
            RlimitKind::Rtprio => "RLIMIT_RTPRIO",
            RlimitKind::Rttime => "RLIMIT_RTTIME",
        }
    }

    /// OCI 名から種別を引く。未知の名前は `InvalidArgument`（入力値はメッセージに含めない）。
    pub fn from_oci_name(name: &str) -> Result<Self, TraitError> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_oci_name() == name)
            .ok_or_else(|| invalid("unknown rlimit name"))
    }
}

/// 1 種別ぶんの制限（`soft <= hard` を構築時に保証する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    kind: RlimitKind,
    soft: u64,
    hard: u64,
}

impl Rlimit {
    /// `soft > hard` は `InvalidArgument`。無制限は [`RLIMIT_INFINITY`]。
    pub fn new(kind: RlimitKind, soft: u64, hard: u64) -> Result<Self, TraitError> {
        if soft > hard {
            return Err(invalid("rlimit soft exceeds hard"));
        }
        Ok(Self { kind, soft, hard })
    }

    /// 種別。
    pub fn kind(&self) -> RlimitKind {
        self.kind
    }

    /// soft limit。
    pub fn soft(&self) -> u64 {
        self.soft
    }

    /// hard limit。
    pub fn hard(&self) -> u64 {
        self.hard
    }
}

/// 種別の重複を持たない rlimit の集合（件数は最大 [`Rlimits::MAX_LEN`]）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rlimits {
    items: Vec<Rlimit>,
}

impl Rlimits {
    /// 件数の上限（種別は 16 種で、重複禁止からも導かれる）。
    pub const MAX_LEN: usize = RlimitKind::ALL.len();

    /// 重複種別・件数超過は `InvalidArgument`。空集合は受理する（何も適用しない）。
    pub fn new(items: Vec<Rlimit>) -> Result<Self, TraitError> {
        if items.len() > Self::MAX_LEN {
            return Err(invalid("too many rlimits"));
        }
        for (i, a) in items.iter().enumerate() {
            if items.iter().skip(i + 1).any(|b| b.kind == a.kind) {
                return Err(invalid("duplicate rlimit kind"));
            }
        }
        Ok(Self { items })
    }

    /// 指定順の要素。
    pub fn iter(&self) -> impl Iterator<Item = &Rlimit> {
        self.items.iter()
    }

    /// 要素数。
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 空か。
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 全 16 種をちょうど 1 回ずつ持つか（launch 時の記録の完全性。TASK-169 追補・#1467）。
    ///
    /// 種別の重複は構築時に禁止されているため、件数が [`Rlimits::MAX_LEN`] に一致することと同値。
    pub fn is_complete(&self) -> bool {
        self.items.len() == Self::MAX_LEN
    }

    /// 指定のある種別は指定値、無い種別は `inherited` が返す値で埋めた全 16 種の集合を返す（#1467）。
    ///
    /// launch 時の記録（`state.json`）を作る純関数。`inherited` は呼び出しプロセスが launch の子へ
    /// 継承させる実効値の読み取り（Linux では `prlimit(2)`）で、syscall はここでは持たない。並びは
    /// 指定済みの要素を指定順に、続けて指定の無い種別を [`RlimitKind::ALL`] の順に並べる。
    /// `soft <= hard` の検証は [`Rlimit::new`] を通す。読み取りの失敗はそのまま伝える。
    pub fn complete_with<E>(
        &self,
        mut inherited: impl FnMut(RlimitKind) -> Result<(u64, u64), E>,
        invalid_value: impl Fn(TraitError) -> E,
    ) -> Result<Rlimits, E> {
        let mut items = self.items.clone();
        for kind in RlimitKind::ALL {
            if items.iter().any(|r| r.kind == kind) {
                continue;
            }
            let (soft, hard) = inherited(kind)?;
            items.push(Rlimit::new(kind, soft, hard).map_err(&invalid_value)?);
        }
        Rlimits::new(items).map_err(invalid_value)
    }
}

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-12・TASK-169.1: 16 種の OCI 名が往復する。
    #[test]
    fn sup12_oci_names_round_trip() {
        assert_eq!(RlimitKind::ALL.len(), 16);
        for k in RlimitKind::ALL {
            assert_eq!(RlimitKind::from_oci_name(k.as_oci_name()).unwrap(), k);
        }
        assert_eq!(RlimitKind::Nofile.as_oci_name(), "RLIMIT_NOFILE");
        assert_eq!(RlimitKind::As.as_oci_name(), "RLIMIT_AS");
    }

    /// SUP-12・TASK-169.1: 未知名は InvalidArgument。
    #[test]
    fn sup12_unknown_name_rejected() {
        for n in ["", "RLIMIT_BOGUS", "nofile", "RLIMIT_NOFILE "] {
            let e = RlimitKind::from_oci_name(n).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{n:?}");
        }
    }

    /// SUP-12・TASK-169.1: soft > hard は拒否、soft == hard と無制限は受理。
    #[test]
    fn sup12_soft_hard_validation() {
        let e = Rlimit::new(RlimitKind::Nofile, 2, 1).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let r = Rlimit::new(RlimitKind::Nofile, 5, 5).unwrap();
        assert_eq!((r.soft(), r.hard()), (5, 5));
        let r = Rlimit::new(RlimitKind::Core, RLIMIT_INFINITY, RLIMIT_INFINITY).unwrap();
        assert_eq!((r.soft(), r.hard()), (u64::MAX, u64::MAX));
        assert_eq!(r.kind(), RlimitKind::Core);
        assert!(Rlimit::new(RlimitKind::Core, RLIMIT_INFINITY, 1).is_err());
    }

    /// TASK-169 追補・#1467: 補完は指定値を保ち、無い種別を継承値で埋めて 16 種にする。
    #[test]
    fn sup12_complete_with_fills_unspecified_kinds() {
        let spec = Rlimits::new(vec![Rlimit::new(RlimitKind::Nofile, 700, 1500).unwrap()]).unwrap();
        assert!(!spec.is_complete());
        let full = spec
            .complete_with::<TraitError>(|k| Ok((k as u64, 100 + k as u64)), |e| e)
            .unwrap();
        assert!(full.is_complete());
        assert_eq!(full.len(), 16);
        let get = |k: RlimitKind| {
            let r = full.iter().find(|r| r.kind() == k).unwrap();
            (r.soft(), r.hard())
        };
        assert_eq!(get(RlimitKind::Nofile), (700, 1500));
        assert_eq!(get(RlimitKind::Cpu), (0, 100));
        assert_eq!(get(RlimitKind::Core), (4, 104));
        // 読み取りの失敗は伝わり、soft > hard の継承値は拒否される。
        let e = spec
            .complete_with::<TraitError>(
                |_| Err(TraitError::new(ErrorCode::Internal, "read")),
                |e| e,
            )
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        let e = spec
            .complete_with::<TraitError>(|_| Ok((9, 1)), |e| e)
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// SUP-12・TASK-169.1: 重複種別は拒否、空集合と全種別は受理。
    #[test]
    fn sup12_set_rejects_duplicates() {
        let a = Rlimit::new(RlimitKind::Nofile, 1, 2).unwrap();
        let b = Rlimit::new(RlimitKind::Nofile, 3, 4).unwrap();
        let e = Rlimits::new(vec![a, b]).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(Rlimits::new(Vec::new()).unwrap().is_empty());
        let all: Vec<_> = RlimitKind::ALL
            .into_iter()
            .map(|k| Rlimit::new(k, 1, 1).unwrap())
            .collect();
        let set = Rlimits::new(all).unwrap();
        assert_eq!(set.len(), 16);
        assert_eq!(set.iter().count(), 16);
        assert!(Rlimits::new(vec![a; 17]).is_err());
    }
}
