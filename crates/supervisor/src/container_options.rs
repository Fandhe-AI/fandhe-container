//! コンテナ起動オプションの指定モデル（SUP-12・TASK-169・#526・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! Docker の `docker run` 相当のオプション群（ulimit・後続の #527〜#530 が同じ型を拡張する）を、
//! 検証済みの型として保持する入口。本 issue（TASK-169.1）は ulimit（`--ulimit <name>=<soft>[:<hard>]`）だけを扱い、
//! core の [`Rlimits`] へ変換して保持する。
//!
//! 変換先の [`Rlimits`] は `fandhe_container_core::exec::StagePipeline::with_rlimits`（fork 後・capability
//! 削減の前に `prlimit(2)` で適用。Linux 限定）が消費する。
//!
//! # サブモジュール
//!
//! [`mounts`]（TASK-169.2・#527）が `--shm-size` / `--tmpfs` を解析し、core の tmpfs 仕様型へ変換する
//! （適用は core の `exec::mount_tmpfs`。supervisor → core の一方向依存）。
//!
//! # 未結線の箇所（REPAIR-3）
//!
//! 本番の `ProcessLauncher` が未提供のため、現時点で [`ContainerOptions`] の消費者は無い
//! （CLI・launcher からの結線は後続作業）。OS 非依存で、3 OS でビルド・テストする。
//!
//! # 外部入力の扱い
//!
//! `--ulimit` 文字列は外部入力として、長さ上限・形式・数値・種別名を検証してから型へ写す。
//! エラーメッセージは固定の英語文言で、入力値は含めない。

pub mod mounts;

pub use mounts::{DEFAULT_SHM_SIZE_BYTES, MountOptions, ShmSize, TmpfsOption};

use fandhe_container_core::rlimits::{RLIMIT_INFINITY, Rlimit, RlimitKind, Rlimits};
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

/// `--ulimit` 1 件の最大バイト数（最長の名前 `sigpending` と u64 の 2 値に十分な余裕を持たせた上限）。
const ULIMIT_MAX_LEN: usize = 64;

/// `--ulimit <name>=<soft>[:<hard>]` の解釈結果（検証済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ulimit {
    rlimit: Rlimit,
}

impl Ulimit {
    /// Docker 形式の指定を解釈する。
    ///
    /// - name は Docker の小文字名（`nofile`・`nproc`・`core`・`as` 等の 16 種）
    /// - hard を省略すると soft と同値、`-1` は無制限
    /// - 形式不正・未知名・数値不正・`soft > hard` は `InvalidArgument`
    pub fn parse(input: &str) -> Result<Self, TraitError> {
        if input.len() > ULIMIT_MAX_LEN {
            return Err(invalid("ulimit value is too long"));
        }
        let (name, limits) = input
            .split_once('=')
            .ok_or_else(|| invalid("ulimit must be <name>=<soft>[:<hard>]"))?;
        let kind = kind_from_docker_name(name)?;
        let (soft, hard) = match limits.split_once(':') {
            Some((s, h)) => (parse_value(s)?, parse_value(h)?),
            None => {
                let v = parse_value(limits)?;
                (v, v)
            }
        };
        Ok(Self {
            rlimit: Rlimit::new(kind, soft, hard)?,
        })
    }

    /// 解釈済みの rlimit。
    pub fn rlimit(&self) -> Rlimit {
        self.rlimit
    }
}

/// コンテナ起動オプション（現状は ulimit のみ。後続 issue が拡張する）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerOptions {
    rlimits: Rlimits,
}

impl ContainerOptions {
    /// 何も指定しない既定のオプション。
    pub fn new() -> Self {
        Self::default()
    }

    /// ulimit の一覧を設定する。同じ種別の重複は `InvalidArgument`。
    pub fn with_ulimits(mut self, ulimits: Vec<Ulimit>) -> Result<Self, TraitError> {
        self.rlimits = Rlimits::new(ulimits.into_iter().map(|u| u.rlimit()).collect())?;
        Ok(self)
    }

    /// core の `StagePipeline::with_rlimits` へ渡す集合。
    pub fn rlimits(&self) -> &Rlimits {
        &self.rlimits
    }
}

fn kind_from_docker_name(name: &str) -> Result<RlimitKind, TraitError> {
    let kind = match name {
        "core" => RlimitKind::Core,
        "cpu" => RlimitKind::Cpu,
        "data" => RlimitKind::Data,
        "fsize" => RlimitKind::Fsize,
        "locks" => RlimitKind::Locks,
        "memlock" => RlimitKind::Memlock,
        "msgqueue" => RlimitKind::Msgqueue,
        "nice" => RlimitKind::Nice,
        "nofile" => RlimitKind::Nofile,
        "nproc" => RlimitKind::Nproc,
        "rss" => RlimitKind::Rss,
        "rtprio" => RlimitKind::Rtprio,
        "rttime" => RlimitKind::Rttime,
        "sigpending" => RlimitKind::Sigpending,
        "stack" => RlimitKind::Stack,
        "as" => RlimitKind::As,
        _ => return Err(invalid("unknown ulimit name")),
    };
    Ok(kind)
}

/// 10 進の非負整数、または `-1`（無制限）。
fn parse_value(s: &str) -> Result<u64, TraitError> {
    if s == "-1" {
        return Ok(RLIMIT_INFINITY);
    }
    // `u64::from_str` は先頭の `+` を許すため、数字だけで構成されることを先に確認する。
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("ulimit value must be a non-negative integer or -1"));
    }
    s.parse::<u64>()
        .map_err(|_| invalid("ulimit value is out of range"))
}

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(s: &str) -> (RlimitKind, u64, u64) {
        let r = Ulimit::parse(s).unwrap().rlimit();
        (r.kind(), r.soft(), r.hard())
    }

    /// SUP-12・TASK-169.1: soft:hard 指定・hard 省略・無制限を具体値で照合する。
    #[test]
    fn sup12_parse_valid_forms() {
        assert_eq!(parsed("nofile=1024:2048"), (RlimitKind::Nofile, 1024, 2048));
        assert_eq!(parsed("nproc=512"), (RlimitKind::Nproc, 512, 512));
        assert_eq!(parsed("core=-1"), (RlimitKind::Core, u64::MAX, u64::MAX));
        assert_eq!(parsed("as=0:-1"), (RlimitKind::As, 0, u64::MAX));
        assert_eq!(parsed("nofile=5:5"), (RlimitKind::Nofile, 5, 5));
    }

    /// SUP-12・TASK-169.1: Docker の 16 種の名前がすべて解釈できる。
    #[test]
    fn sup12_parse_all_docker_names() {
        let names = [
            ("core", RlimitKind::Core),
            ("cpu", RlimitKind::Cpu),
            ("data", RlimitKind::Data),
            ("fsize", RlimitKind::Fsize),
            ("locks", RlimitKind::Locks),
            ("memlock", RlimitKind::Memlock),
            ("msgqueue", RlimitKind::Msgqueue),
            ("nice", RlimitKind::Nice),
            ("nofile", RlimitKind::Nofile),
            ("nproc", RlimitKind::Nproc),
            ("rss", RlimitKind::Rss),
            ("rtprio", RlimitKind::Rtprio),
            ("rttime", RlimitKind::Rttime),
            ("sigpending", RlimitKind::Sigpending),
            ("stack", RlimitKind::Stack),
            ("as", RlimitKind::As),
        ];
        for (n, k) in names {
            assert_eq!(parsed(&format!("{n}=1")), (k, 1, 1), "{n}");
        }
    }

    /// SUP-12・TASK-169.1: 不正な指定は InvalidArgument で拒否する。
    #[test]
    fn sup12_parse_rejects_invalid() {
        let long = format!("nofile={}", "1".repeat(100));
        for bad in [
            "nofile=2048:1024",
            "bogus=1",
            "nofile=",
            "nofile=1:2:3",
            "=1",
            "nofile=abc",
            "nofile",
            "nofile=+1",
            "nofile=-2",
            "nofile=1:",
            "nofile=:1",
            "nofile=99999999999999999999",
            "NOFILE=1",
            "",
            long.as_str(),
        ] {
            let e = Ulimit::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad:?}");
        }
    }

    /// SUP-12・TASK-169.1: ContainerOptions は指定順に rlimits を持ち、重複種別を拒否する。
    #[test]
    fn sup12_options_collects_ulimits_and_rejects_duplicates() {
        let opts = ContainerOptions::new()
            .with_ulimits(vec![
                Ulimit::parse("nofile=1024:2048").unwrap(),
                Ulimit::parse("core=0").unwrap(),
            ])
            .unwrap();
        let got: Vec<_> = opts
            .rlimits()
            .iter()
            .map(|r| (r.kind(), r.soft(), r.hard()))
            .collect();
        assert_eq!(
            got,
            [(RlimitKind::Nofile, 1024, 2048), (RlimitKind::Core, 0, 0)]
        );
        assert!(ContainerOptions::new().rlimits().is_empty());
        let e = ContainerOptions::new()
            .with_ulimits(vec![
                Ulimit::parse("nofile=1").unwrap(),
                Ulimit::parse("nofile=2").unwrap(),
            ])
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }
}
