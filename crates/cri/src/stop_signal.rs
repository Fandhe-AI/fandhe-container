//! CRI の `ContainerConfig.stop_signal`（proto の enum `Signal`）を Linux のシグナル番号へ写す（CRI-2・CRI-7・PLUG-1。#2668）。
//!
//! CRI の enum の値は Linux のシグナル番号ではない（例: `SIGNAL_SIGTERM = 23`、`SIGNAL_SIGKILL = 13`）。
//! 値をそのまま番号として使うと誤ったシグナルを送るため、必ずこの表を通す。呼び出し元は `bundle::spec`
//! （CreateContainer の検証）と `runtime_service`（StopContainer / StopPodSandbox が `RuntimeAdapter::stop_with_signal`
//! へ渡す番号を求める）。結果は core の `StopRequest::with_signal` で運ばれる（core は CRI の型を知らない）。
//!
//! 番号体系は x86_64 と aarch64 で 1..=31 が一致する Linux のもの。実時間シグナルは glibc / moby の
//! 慣習（`SIGRTMIN` = 34、`SIGRTMAX` = 64。カーネルの 32・33 は glibc が予約する）に合わせる。

use crate::error::CriError;
use crate::runtime::v1::Signal;

/// CRI の `Signal` の i32 を Linux のシグナル番号（1..=64）へ写す。
///
/// `SIGNAL_RUNTIME_DEFAULT`（0）は SIGTERM（15）。未知の値は `INVALID_ARGUMENT`（固定文言。値は含めない。ERR-2）。
/// `match` は網羅で、cri-api の更新で variant が増えたらコンパイルエラーになる（REPAIR-12）。
pub fn linux_stop_signal(value: i32) -> Result<u8, CriError> {
    let sig = Signal::try_from(value)
        .map_err(|_| CriError::invalid_argument("stop_signal is invalid"))?;
    Ok(match sig {
        Signal::RuntimeDefault => 15,
        Signal::Sigabrt | Signal::Sigiot => 6,
        Signal::Sigalrm => 14,
        Signal::Sigbus => 7,
        Signal::Sigchld | Signal::Sigcld => 17,
        Signal::Sigcont => 18,
        Signal::Sigfpe => 8,
        Signal::Sighup => 1,
        Signal::Sigill => 4,
        Signal::Sigint => 2,
        Signal::Sigio | Signal::Sigpoll => 29,
        Signal::Sigkill => 9,
        Signal::Sigpipe => 13,
        Signal::Sigprof => 27,
        Signal::Sigpwr => 30,
        Signal::Sigquit => 3,
        Signal::Sigsegv => 11,
        Signal::Sigstkflt => 16,
        Signal::Sigstop => 19,
        Signal::Sigsys => 31,
        Signal::Sigterm => 15,
        Signal::Sigtrap => 5,
        Signal::Sigtstp => 20,
        Signal::Sigttin => 21,
        Signal::Sigttou => 22,
        Signal::Sigurg => 23,
        Signal::Sigusr1 => 10,
        Signal::Sigusr2 => 12,
        Signal::Sigvtalrm => 26,
        Signal::Sigwinch => 28,
        Signal::Sigxcpu => 24,
        Signal::Sigxfsz => 25,
        Signal::Sigrtmin => 34,
        Signal::Sigrtminplus1 => 35,
        Signal::Sigrtminplus2 => 36,
        Signal::Sigrtminplus3 => 37,
        Signal::Sigrtminplus4 => 38,
        Signal::Sigrtminplus5 => 39,
        Signal::Sigrtminplus6 => 40,
        Signal::Sigrtminplus7 => 41,
        Signal::Sigrtminplus8 => 42,
        Signal::Sigrtminplus9 => 43,
        Signal::Sigrtminplus10 => 44,
        Signal::Sigrtminplus11 => 45,
        Signal::Sigrtminplus12 => 46,
        Signal::Sigrtminplus13 => 47,
        Signal::Sigrtminplus14 => 48,
        Signal::Sigrtminplus15 => 49,
        Signal::Sigrtmaxminus14 => 50,
        Signal::Sigrtmaxminus13 => 51,
        Signal::Sigrtmaxminus12 => 52,
        Signal::Sigrtmaxminus11 => 53,
        Signal::Sigrtmaxminus10 => 54,
        Signal::Sigrtmaxminus9 => 55,
        Signal::Sigrtmaxminus8 => 56,
        Signal::Sigrtmaxminus7 => 57,
        Signal::Sigrtmaxminus6 => 58,
        Signal::Sigrtmaxminus5 => 59,
        Signal::Sigrtmaxminus4 => 60,
        Signal::Sigrtmaxminus3 => 61,
        Signal::Sigrtmaxminus2 => 62,
        Signal::Sigrtmaxminus1 => 63,
        Signal::Sigrtmax => 64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::Signal as CoreSignal;

    /// CRI-2: 代表的な値が Linux の番号へ写る（CRI の値そのものではない）。
    #[test]
    fn cri2_stop_signal_maps_to_linux_numbers() {
        let cases: [(i32, u8); 20] = [
            (0, 15),
            (23, 15),
            (13, 9),
            (10, 2),
            (8, 1),
            (29, 10),
            (30, 12),
            (21, 19),
            (65, 64),
            (35, 34),
            (36, 35),
            (50, 49),
            (51, 50),
            (64, 63),
            (1, 6),
            (12, 6),
            (4, 17),
            (5, 17),
            (11, 29),
            (15, 29),
        ];
        for (cri, linux) in cases {
            assert_eq!(linux_stop_signal(cri).expect("known value"), linux, "{cri}");
        }
    }

    /// CRI-2: 既知の全値（0..=65）が受理され、core の `Signal::new`（1..=64）を通る。
    #[test]
    fn cri2_stop_signal_all_known_values_are_valid_core_signals() {
        for v in 0..=65 {
            let n = linux_stop_signal(v).expect("known value");
            assert!(CoreSignal::new(n).is_ok(), "{v} -> {n}");
        }
    }

    /// CRI-2・ERR-2: 未知の値は `INVALID_ARGUMENT` で、message に値を含めない。
    #[test]
    fn cri2_stop_signal_unknown_value_is_invalid_argument() {
        for v in [66, 999, -1, i32::MIN] {
            let err = linux_stop_signal(v).expect_err("unknown value");
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
            assert!(!err.message().contains(&v.to_string()), "{v}");
        }
    }
}
