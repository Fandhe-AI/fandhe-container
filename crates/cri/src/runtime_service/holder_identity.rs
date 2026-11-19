//! 記録ファイルに残す保持役の素性と、再採用時の終了済みの分類（R11・#2940・CRI-2・SEC-5・SEC-1。設計は
//! `docs/design/cri-record-readoption.md`）。
//!
//! 役割: `record`（sandbox 記録 v2 の `holder=` 行の符号化・復号）・`pod_holder`（spawn 成功時の記録）・
//! `readopt`（再採用時の観測と分類）が共有する、cri 内部だけの型を持つ。起動中の保持役の素性は公開の
//! `crate::adapter::HolderIdentity`（provider が集める）で、本モジュールの [`RecordedHolderIdentity`] はその
//! 記録上の写しである。
//!
//! 契約（SEC-5・SEC-1）: [`RecordedHolderIdentity`] から `PodHolder`・`PodNamespacePaths`・pidfd・シグナルへ
//! 変換する口は意図して作らない。再採用した記録の pid は診断と「終了済み」の確認にだけ使う。bundle への
//! namespace のパスは `CriRuntimeService` が起動中の `SandboxRecord::pod_holder` からだけ作る。
//! 値は untrusted（記録ファイル）として厳密に復号し、パスの組み立てには使わない。

use super::record::canonical_u64;
use crate::adapter::{
    HolderIdentity, NamespaceIdentity, ProcessStartObservation, holder_fields_consistent,
};

/// `holder=` 行の内容の上限: キー 7（`holder=`）+ pid(10) + ',' + starttime(20) + 4 × (',' + dev(20) + ':' + ino(20))
/// （4 つ目は pid を共有する sandbox の pid ns。#4816）。
pub(super) const LINE_MAX_HOLDER: usize = 7 + 10 + 1 + 20 + 4 * (1 + 20 + 1 + 20);

/// 記録ファイルに残した保持役の素性（診断用。パス・シグナルの根拠にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordedHolderIdentity {
    pid: u32,
    start_time_ticks: u64,
    user: NamespaceIdentity,
    ipc: NamespaceIdentity,
    net: NamespaceIdentity,
    /// pod の pid ns（pid を共有する sandbox だけ。#4816）。
    pid_ns: Option<NamespaceIdentity>,
}

impl From<&HolderIdentity> for RecordedHolderIdentity {
    /// 起動中から記録への一方向の変換（逆向きは作らない）。
    fn from(id: &HolderIdentity) -> Self {
        Self {
            pid: id.pid().get(),
            start_time_ticks: id.start_time_ticks(),
            user: id.user(),
            ipc: id.ipc(),
            net: id.net(),
            pid_ns: id.pid_ns(),
        }
    }
}

impl RecordedHolderIdentity {
    /// 記録した pid（診断・`observe_process_start` の入力にだけ使う）。
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    /// 記録した starttime。
    pub(super) fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    /// `holder=` の値（`-` または `<pid>,<starttime>,<user>,<ipc>,<net>[,<pid_ns>]`。各 ns は `<dev>:<ino>`。pid ns は
    /// pid を共有する sandbox だけで、無い記録〔#4816 より前のもの〕も同じ形で読める）。
    pub(super) fn encode_value(value: Option<&Self>) -> String {
        match value {
            None => "-".to_owned(),
            Some(v) => {
                let mut out = format!(
                    "{},{},{}:{},{}:{},{}:{}",
                    v.pid,
                    v.start_time_ticks,
                    v.user.dev,
                    v.user.ino,
                    v.ipc.dev,
                    v.ipc.ino,
                    v.net.dev,
                    v.net.ino
                );
                if let Some(p) = v.pid_ns {
                    out.push_str(&format!(",{}:{}", p.dev, p.ino));
                }
                out
            }
        }
    }

    /// `holder=` の値を厳密に復号する。整数は正準形、要素数は 5（pid ns なし）か 6（pid ns あり。#4816）、不変条件は
    /// `HolderIdentity::new`・`with_pid_ns` と同じ。違反は `Err(())`（呼び出し側が固定文言の拒否に写す）。
    pub(super) fn parse_value(s: &str) -> Result<Option<Self>, ()> {
        if s == "-" {
            return Ok(None);
        }
        // 要素数は 5 か 6（行の長さは呼び出し側が `LINE_MAX_HOLDER` で上限つき）。
        let fields: Vec<&str> = s.splitn(8, ',').collect();
        let (head, ns_fields) = match fields.as_slice() {
            [pid, start, rest @ ..] if (3..=4).contains(&rest.len()) => ((*pid, *start), rest),
            _ => return Err(()),
        };
        let pid = u32::try_from(canonical_u64(head.0).ok_or(())?).map_err(|_| ())?;
        let start_time_ticks = canonical_u64(head.1).ok_or(())?;
        let ns = |field: &str| -> Result<NamespaceIdentity, ()> {
            let (dev, ino) = field.split_once(':').ok_or(())?;
            Ok(NamespaceIdentity {
                dev: canonical_u64(dev).ok_or(())?,
                ino: canonical_u64(ino).ok_or(())?,
            })
        };
        let parsed = ns_fields
            .iter()
            .map(|f| ns(f))
            .collect::<Result<Vec<_>, ()>>()?;
        let (user, ipc, net, pid_ns) = match parsed.as_slice() {
            [u, i, n] => (*u, *i, *n, None),
            [u, i, n, p] => (*u, *i, *n, Some(*p)),
            _ => return Err(()),
        };
        if !holder_fields_consistent(pid, user, ipc, net) {
            return Err(());
        }
        if let Some(p) = pid_ns
            && (p.ino == 0 || p.dev != user.dev || [user, ipc, net].iter().any(|o| o.ino == p.ino))
        {
            return Err(());
        }
        Ok(Some(Self {
            pid,
            start_time_ticks,
            user,
            ipc,
            net,
            pid_ns,
        }))
    }
}

/// 再採用時に記録の保持役を観測した結果の分類。どの分類でも、登録する値（NotReady・保持役なし）は変えない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordedHolderStatus {
    /// `/proc/<pid>` が無い。記録の保持役は終了済み。
    Gone,
    /// 同じ pid に別の starttime のプロセスが居る。記録の保持役は終了済みで、pid が再利用された。
    PidReused,
    /// starttime が一致する。終了を確認できない（boot id を記録しないため、再起動をまたぐ偶然の一致を否定できない）。
    /// Ready・パス・シグナルの根拠にしない。
    StartTimeMatches,
    /// 観測できなかった（provider 未注入・観測の失敗）。
    Unobserved,
}

/// 記録の starttime と観測結果から分類する（純粋関数）。`observation` が `None` は観測できなかったこと。
pub(super) fn classify_recorded_holder(
    recorded_start_time_ticks: u64,
    observation: Option<ProcessStartObservation>,
) -> RecordedHolderStatus {
    match observation {
        None => RecordedHolderStatus::Unobserved,
        Some(ProcessStartObservation::Absent) => RecordedHolderStatus::Gone,
        Some(ProcessStartObservation::Present { start_time_ticks }) => {
            if start_time_ticks == recorded_start_time_ticks {
                RecordedHolderStatus::StartTimeMatches
            } else {
                RecordedHolderStatus::PidReused
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "4242,123456,4:4026531837,4:4026531839,4:4026531840";

    fn ns(dev: u64, ino: u64) -> NamespaceIdentity {
        NamespaceIdentity { dev, ino }
    }

    fn sample() -> RecordedHolderIdentity {
        RecordedHolderIdentity {
            pid: 4242,
            start_time_ticks: 123456,
            user: ns(4, 4026531837),
            ipc: ns(4, 4026531839),
            net: ns(4, 4026531840),
            pid_ns: None,
        }
    }

    /// #2940: starttime の不一致は pid の再利用（記録の保持役は終了済み）。
    #[test]
    fn cri2_sec5_2940_classify_start_time_mismatch_is_pid_reused() {
        let got = classify_recorded_holder(
            123456,
            Some(ProcessStartObservation::Present {
                start_time_ticks: 987654,
            }),
        );
        assert_eq!(got, RecordedHolderStatus::PidReused);
    }

    /// #2940: 不在は Gone、一致は終了を確認できない、観測の失敗は Unobserved。
    #[test]
    fn cri2_sec5_2940_classify_other_cases() {
        assert_eq!(
            classify_recorded_holder(123456, Some(ProcessStartObservation::Absent)),
            RecordedHolderStatus::Gone
        );
        assert_eq!(
            classify_recorded_holder(
                123456,
                Some(ProcessStartObservation::Present {
                    start_time_ticks: 123456
                })
            ),
            RecordedHolderStatus::StartTimeMatches
        );
        assert_eq!(
            classify_recorded_holder(123456, None),
            RecordedHolderStatus::Unobserved
        );
    }

    /// #2940: `holder=` の値の往復（具体値）。
    #[test]
    fn cri2_sec5_2940_holder_value_roundtrips() {
        assert_eq!(RecordedHolderIdentity::encode_value(Some(&sample())), VALUE);
        assert_eq!(
            RecordedHolderIdentity::parse_value(VALUE),
            Ok(Some(sample()))
        );
        assert_eq!(RecordedHolderIdentity::encode_value(None), "-");
        assert_eq!(RecordedHolderIdentity::parse_value("-"), Ok(None));
    }

    /// CRI-2・SEC-5・#4816: pid を共有する sandbox の pid ns の素性が 6 つ目の要素で往復し、無い記録（5 要素）も読める。
    #[test]
    fn cri2_sec5_4816_holder_value_with_pid_ns_roundtrips() {
        let with = RecordedHolderIdentity {
            pid_ns: Some(ns(4, 4026531841)),
            ..sample()
        };
        let text = format!("{VALUE},4:4026531841");
        assert_eq!(RecordedHolderIdentity::encode_value(Some(&with)), text);
        assert_eq!(RecordedHolderIdentity::parse_value(&text), Ok(Some(with)));
        assert!(format!("holder={text}").len() <= LINE_MAX_HOLDER);
        let id = HolderIdentity::new(
            4242,
            123456,
            ns(4, 4026531837),
            ns(4, 4026531839),
            ns(4, 4026531840),
            ns(48, 2),
        )
        .unwrap()
        .with_pid_ns(ns(4, 4026531841))
        .unwrap();
        assert_eq!(RecordedHolderIdentity::from(&id), with);
        let base = HolderIdentity::new(4242, 1, ns(4, 1), ns(4, 2), ns(4, 3), ns(48, 2)).unwrap();
        for bad in [ns(4, 0), ns(4, 2), ns(5, 4)] {
            assert!(base.with_pid_ns(bad).is_err(), "{bad:?}");
        }
    }

    /// #2940: 範囲外・非正準・重複・不一致・要素数・区切りの誤りはすべて拒否する。
    #[test]
    fn cri2_sec5_2940_holder_value_rejects_malformed() {
        let cases = [
            "0,1,4:1,4:2,4:3",
            "2147483648,1,4:1,4:2,4:3",
            "04242,1,4:1,4:2,4:3",
            "4242,01,4:1,4:2,4:3",
            "4242,1,4:0,4:2,4:3",
            "4242,1,4:1,4:1,4:3",
            "4242,1,4:1,5:2,4:3",
            "4242,1,4:1,4:2",
            "4242,1,4:1,4:2,4:3,4:4,4:5",
            "4242,1,4:1,4:2,4:3,4:0",
            "4242,1,4:1,4:2,4:3,4:3",
            "4242,1,4:1,4:2,4:3,5:4",
            "4242;1;4:1;4:2;4:3",
            "4242,1,4-1,4:2,4:3",
            "4242,1,4:1,4:2,4:3,",
            "4242,-1,4:1,4:2,4:3",
            "",
            " ",
        ];
        for c in cases {
            assert_eq!(RecordedHolderIdentity::parse_value(c), Err(()), "{c:?}");
        }
    }

    /// #2940: 公開の `HolderIdentity::new` も同じ不変条件で拒否し、記録の型へ写せる。
    #[test]
    fn cri2_sec5_2940_holder_identity_invariants() {
        let same = ns(4, 7);
        assert!(HolderIdentity::new(4242, 1, same, same, same, ns(48, 2)).is_err());
        assert!(HolderIdentity::new(0, 1, ns(4, 1), ns(4, 2), ns(4, 3), ns(48, 2)).is_err());
        let id = HolderIdentity::new(
            4242,
            123456,
            ns(4, 4026531837),
            ns(4, 4026531839),
            ns(4, 4026531840),
            ns(48, 2),
        )
        .unwrap();
        assert_eq!(RecordedHolderIdentity::from(&id), sample());
        // #4823: shm は dev・ino が非 0 で、dev が nsfs と違うときだけ受ける。
        let (u, i, n) = (ns(4, 1), ns(4, 2), ns(4, 3));
        for bad in [ns(0, 2), ns(48, 0), ns(4, 9)] {
            assert!(
                HolderIdentity::new(4242, 1, u, i, n, bad).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(
            HolderIdentity::new(4242, 1, u, i, n, ns(48, 2))
                .unwrap()
                .shm(),
            ns(48, 2)
        );
    }
}
