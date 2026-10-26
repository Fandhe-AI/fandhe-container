//! CRI の `ContainerConfig.stop_signal`（proto の enum `Signal`）を Linux のシグナル番号へ写す（CRI-2・CRI-7・PLUG-1。#2668）。
//!
//! CRI の enum の値は Linux のシグナル番号ではない（例: `SIGNAL_SIGTERM = 23`、`SIGNAL_SIGKILL = 13`）。
//! 値をそのまま番号として使うと誤ったシグナルを送るため、必ずこの表を通す。呼び出し元は `bundle::spec`
//! （CreateContainer の検証）と `runtime_service`（StopContainer / StopPodSandbox が `RuntimeAdapter::stop_with_signal`
//! へ渡す番号を求める）。結果は core の `StopRequest::with_signal` で運ばれる（core は CRI の型を知らない）。
//!
//! イメージ config の `StopSignal` は、語彙の解釈を core の `Signal::parse_notation`（CLI の `stop --signal` と共有）へ
//! 委ね、本モジュールは空・長さ・`RUNTIME_DEFAULT` 除外・`CriError` 写像と CRI enum への写像、および CRI の値との
//! 解決（`RUNTIME_DEFAULT` のときだけイメージの値）を持つ（#2771・#2832・OCI-1。受ける形式は
//! `docs/design/cri-config-acceptance.md`）。
//!
//! 番号体系は x86_64 と aarch64 で 1..=31 が一致する Linux のもの。実時間シグナルは glibc / moby の
//! 慣習（`SIGRTMIN` = 34、`SIGRTMAX` = 64。カーネルの 32・33 は glibc が予約する）に合わせる。

use crate::error::CriError;
use crate::runtime::v1::Signal;
use fandhe_container_core::traits::Signal as CoreSignal;

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

/// Linux のシグナル番号（1..=64。32・33 を除く）を CRI の `Signal` へ戻す（`linux_stop_signal` の逆向き。#2771・CRI-2）。
///
/// 別名のある番号は正規の名前に寄せる（6 は `Sigabrt`、17 は `Sigchld`、29 は `Sigio`）。32・33 は glibc が予約する
/// ため `None`。`match` は網羅（cri-api の更新で variant が増えても `linux_stop_signal` 側が検出する）。
pub fn linux_to_cri_signal(n: u8) -> Option<Signal> {
    Some(match n {
        1 => Signal::Sighup,
        2 => Signal::Sigint,
        3 => Signal::Sigquit,
        4 => Signal::Sigill,
        5 => Signal::Sigtrap,
        6 => Signal::Sigabrt,
        7 => Signal::Sigbus,
        8 => Signal::Sigfpe,
        9 => Signal::Sigkill,
        10 => Signal::Sigusr1,
        11 => Signal::Sigsegv,
        12 => Signal::Sigusr2,
        13 => Signal::Sigpipe,
        14 => Signal::Sigalrm,
        15 => Signal::Sigterm,
        16 => Signal::Sigstkflt,
        17 => Signal::Sigchld,
        18 => Signal::Sigcont,
        19 => Signal::Sigstop,
        20 => Signal::Sigtstp,
        21 => Signal::Sigttin,
        22 => Signal::Sigttou,
        23 => Signal::Sigurg,
        24 => Signal::Sigxcpu,
        25 => Signal::Sigxfsz,
        26 => Signal::Sigvtalrm,
        27 => Signal::Sigprof,
        28 => Signal::Sigwinch,
        29 => Signal::Sigio,
        30 => Signal::Sigpwr,
        31 => Signal::Sigsys,
        34 => Signal::Sigrtmin,
        35 => Signal::Sigrtminplus1,
        36 => Signal::Sigrtminplus2,
        37 => Signal::Sigrtminplus3,
        38 => Signal::Sigrtminplus4,
        39 => Signal::Sigrtminplus5,
        40 => Signal::Sigrtminplus6,
        41 => Signal::Sigrtminplus7,
        42 => Signal::Sigrtminplus8,
        43 => Signal::Sigrtminplus9,
        44 => Signal::Sigrtminplus10,
        45 => Signal::Sigrtminplus11,
        46 => Signal::Sigrtminplus12,
        47 => Signal::Sigrtminplus13,
        48 => Signal::Sigrtminplus14,
        49 => Signal::Sigrtminplus15,
        50 => Signal::Sigrtmaxminus14,
        51 => Signal::Sigrtmaxminus13,
        52 => Signal::Sigrtmaxminus12,
        53 => Signal::Sigrtmaxminus11,
        54 => Signal::Sigrtmaxminus10,
        55 => Signal::Sigrtmaxminus9,
        56 => Signal::Sigrtmaxminus8,
        57 => Signal::Sigrtmaxminus7,
        58 => Signal::Sigrtmaxminus6,
        59 => Signal::Sigrtmaxminus5,
        60 => Signal::Sigrtmaxminus4,
        61 => Signal::Sigrtmaxminus3,
        62 => Signal::Sigrtmaxminus2,
        63 => Signal::Sigrtmaxminus1,
        64 => Signal::Sigrtmax,
        _ => return None,
    })
}

/// イメージ config の `StopSignal` 文字列の長さ上限（oci 側の `MAX_PROCESS_STOP_SIGNAL_BYTES` と同値）。
const MAX_IMAGE_STOP_SIGNAL_BYTES: usize = 64;

fn image_stop_signal_invalid() -> CriError {
    CriError::invalid_argument("image stop signal is invalid")
}

/// イメージ config の `StopSignal`（OCI image-spec。`SIGTERM`・`TERM`・`sigint`・`9`・`SIGRTMIN+3` 等）を CRI の
/// `Signal` へ解釈する（OCI-1・CRI-2。#2771・#2832）。空は `Ok(None)`（未指定）。
///
/// 語彙の解釈は core の `Signal::parse_notation`（CLI の `stop --signal` と共有。CLI-1）へ委ね、本関数は
/// 空の扱い・長さ上限・`RUNTIME_DEFAULT` の除外・`CriError`（固定文言。値は含めない。ERR-2）への写像だけを持つ。
/// 受ける名前の集合は moby の `ParseSignal` と同じで、数字の扱いは moby より厳しい
/// （差は `docs/design/cri-config-acceptance.md`）。別名（`IOT`・`CLD`・`POLL`）は番号経由で正規の名前
/// （`Sigabrt`・`Sigchld`・`Sigio`）に寄る。
pub fn parse_image_stop_signal(raw: &str) -> Result<Option<Signal>, CriError> {
    if raw.is_empty() {
        return Ok(None);
    }
    // core も同じ上限を検査するが、イメージ由来の信頼できない入力を他 crate へ渡す前に cri 側でも検査する。
    if raw.len() > MAX_IMAGE_STOP_SIGNAL_BYTES {
        return Err(image_stop_signal_invalid());
    }
    // core のエラー文言は使わず、cri の固定文言へ写す（`?` の From 変換を使わない）。
    let n = CoreSignal::parse_notation(raw).map_err(|_| image_stop_signal_invalid())?;
    linux_to_cri_signal(n.as_u8())
        // 番号の写像は 0（RUNTIME_DEFAULT）を返さないが、イメージの値としては受けない防御として残す。
        .filter(|s| *s != Signal::RuntimeDefault)
        .map(Some)
        .ok_or_else(image_stop_signal_invalid)
}

/// 実際に stop で使う CRI の `Signal` を決める（#2771・CRI-2・OCI-1）。
///
/// CRI の `stop_signal`（`cri`）が `RUNTIME_DEFAULT` のときはイメージの値（`image`）、それも無ければ `Sigterm`。
/// 明示の値はそのまま使う（別名も保つ）。未知の値は `INVALID_ARGUMENT`。
pub fn resolve_stop_signal(cri: i32, image: Option<Signal>) -> Result<Signal, CriError> {
    let sig =
        Signal::try_from(cri).map_err(|_| CriError::invalid_argument("stop_signal is invalid"))?;
    Ok(match sig {
        Signal::RuntimeDefault => image.unwrap_or(Signal::Sigterm),
        explicit => explicit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// CRI-2: 逆向きの表。1..=64 から 32・33 を除く全番号で往復が一致し、別名は正規の名前になる（#2771）。
    #[test]
    fn cri2_linux_to_cri_signal_round_trips() {
        for n in (1u8..=64).filter(|n| !matches!(n, 32 | 33)) {
            let sig = linux_to_cri_signal(n).expect("mapped");
            assert_eq!(linux_stop_signal(sig as i32).expect("known"), n, "{n}");
        }
        assert_eq!(linux_to_cri_signal(6), Some(Signal::Sigabrt));
        assert_eq!(linux_to_cri_signal(17), Some(Signal::Sigchld));
        assert_eq!(linux_to_cri_signal(29), Some(Signal::Sigio));
        for n in [0u8, 32, 33, 65, 255] {
            assert_eq!(linux_to_cri_signal(n), None, "{n}");
        }
    }

    /// OCI-1・CRI-2: イメージの StopSignal の受理形式（名前・接頭辞なし・小文字・番号・実時間）。
    #[test]
    fn oci1_parse_image_stop_signal_accepts() {
        let cases = [
            ("SIGTERM", Signal::Sigterm),
            ("TERM", Signal::Sigterm),
            ("sigint", Signal::Sigint),
            ("9", Signal::Sigkill),
            ("SIGRTMIN+3", Signal::Sigrtminplus3),
            ("rtmin+15", Signal::Sigrtminplus15),
            ("SIGRTMAX-1", Signal::Sigrtmaxminus1),
            ("SIGRTMAX", Signal::Sigrtmax),
            ("SIGRTMIN", Signal::Sigrtmin),
            ("34", Signal::Sigrtmin),
            ("SIGIOT", Signal::Sigabrt),
            ("CLD", Signal::Sigchld),
            ("poll", Signal::Sigio),
            ("rtmax-14", Signal::Sigrtmaxminus14),
            ("1", Signal::Sighup),
            ("64", Signal::Sigrtmax),
            ("kill", Signal::Sigkill),
        ];
        for (raw, want) in cases {
            assert_eq!(parse_image_stop_signal(raw).unwrap(), Some(want), "{raw}");
        }
        assert_eq!(parse_image_stop_signal("").unwrap(), None);
    }

    /// OCI-1・CRI-2・ERR-2: 解釈できない StopSignal は INVALID_ARGUMENT で、文言に値を含めない。
    #[test]
    fn oci1_parse_image_stop_signal_rejects() {
        let long = "S".repeat(MAX_IMAGE_STOP_SIGNAL_BYTES + 1);
        for raw in [
            "32",
            "0",
            "65",
            "256",
            "SIGFOO",
            " SIGTERM",
            "SIGTERM ",
            "SIGRTMIN+16",
            "SIGRTMIN+0",
            "SIGRTMAX-15",
            "SIGNAL_SIGTERM",
            "RUNTIME_DEFAULT",
            "SIGTÉRM",
            "SIG",
            "RTMINPLUS3",
            "SIGRTMAXMINUS1",
            "RTMIN+01",
            "RTMAX-01",
            "33",
            "+15",
            "-1",
            "99999999999",
            "RTMIN+",
            "RTMAX-0",
            "ＳＩＧＫＩＬＬ",
            long.as_str(),
        ] {
            let err = parse_image_stop_signal(raw).expect_err(raw);
            assert_eq!(
                err.code(),
                crate::error::CriErrorCode::InvalidArgument,
                "{raw}"
            );
            assert_eq!(err.message(), "image stop signal is invalid");
        }
    }

    /// CRI-2・CLI-1・OCI-1: core の `parse_notation` と受ける語彙・拒否する語彙が同じ（#2832）。
    #[test]
    fn cri2_parse_image_stop_signal_matches_core_notation() {
        for (text, want) in [
            ("SIGKILL", 9u8),
            ("kill", 9),
            ("TERM", 15),
            ("sigusr1", 10),
            ("SIGRTMIN", 34),
            ("rtmin+1", 35),
            ("RTMIN+15", 49),
            ("SIGRTMAX-1", 63),
            ("RTMAX-14", 50),
            ("SIGRTMAX", 64),
            ("IOT", 6),
            ("CLD", 17),
            ("POLL", 29),
            ("10", 10),
            ("1", 1),
            ("64", 64),
        ] {
            let got = parse_image_stop_signal(text).unwrap().expect(text);
            assert_eq!(linux_stop_signal(got as i32).unwrap(), want, "{text}");
            assert_eq!(CoreSignal::parse_notation(text).unwrap().as_u8(), want);
        }
        assert_eq!(parse_image_stop_signal("").unwrap(), None);
        assert!(CoreSignal::parse_notation("").is_err());
        for text in [
            "0",
            "32",
            "33",
            "65",
            "256",
            "99999999999",
            "+15",
            "-1",
            " SIGTERM",
            "SIGTERM ",
            "SIGFOO",
            "SIG",
            "RTMIN+0",
            "RTMIN+16",
            "RTMAX-15",
            "RTMAX-0",
            "RTMIN+01",
            "RTMAX-01",
            "RTMIN+",
            "SIGNAL_SIGTERM",
            "ＳＩＧＫＩＬＬ",
        ] {
            assert!(CoreSignal::parse_notation(text).is_err(), "{text}");
            let err = parse_image_stop_signal(text).expect_err(text);
            assert_eq!(err.message(), "image stop signal is invalid", "{text}");
        }
    }

    /// CRI-2・REPAIR-12: CRI enum の全名（containerd の写し方）が受理され、同じ Linux 番号になる。
    #[test]
    fn cri2_parse_image_stop_signal_covers_cri_enum_names() {
        for v in 1..=65 {
            let sig = Signal::try_from(v).expect("known");
            let name = sig
                .as_str_name()
                .trim_start_matches("SIGNAL_")
                .replace("PLUS", "+")
                .replace("MINUS", "-");
            let got = parse_image_stop_signal(&name).unwrap().expect(&name);
            assert_eq!(
                linux_stop_signal(got as i32).unwrap(),
                linux_stop_signal(v).unwrap(),
                "{name}"
            );
        }
    }

    /// CRI-2・OCI-1: RUNTIME_DEFAULT のときだけイメージの値を使い、明示値は別名も含めて保つ。
    #[test]
    fn cri2_resolve_stop_signal() {
        assert_eq!(
            resolve_stop_signal(0, Some(Signal::Sigint)).unwrap(),
            Signal::Sigint
        );
        assert_eq!(resolve_stop_signal(0, None).unwrap(), Signal::Sigterm);
        assert_eq!(
            resolve_stop_signal(15, Some(Signal::Sigint)).unwrap(),
            Signal::Sigpoll
        );
        assert_eq!(
            resolve_stop_signal(13, Some(Signal::Sigint)).unwrap(),
            Signal::Sigkill
        );
        let err = resolve_stop_signal(66, None).expect_err("unknown");
        assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
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
