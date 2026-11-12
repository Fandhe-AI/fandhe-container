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

/// `holder=` 行の内容の上限: キー 7（`holder=`）+ pid(10) + ',' + starttime(20) + 3 × (',' + dev(20) + ':' + ino(20))。
pub(super) const LINE_MAX_HOLDER: usize = 7 + 10 + 1 + 20 + 3 * (1 + 20 + 1 + 20);

/// 記録ファイルに残した保持役の素性（診断用。パス・シグナルの根拠にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordedHolderIdentity {
    pid: u32,
    start_time_ticks: u64,
    user: NamespaceIdentity,
    ipc: NamespaceIdentity,
    net: NamespaceIdentity,
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

    /// `holder=` の値（`-` または `<pid>,<starttime>,<user>,<ipc>,<net>`。各 ns は `<dev>:<ino>`）。
    pub(super) fn encode_value(value: Option<&Self>) -> String {
        match value {
            None => "-".to_owned(),
            Some(v) => format!(
                "{},{},{}:{},{}:{},{}:{}",
                v.pid,
                v.start_time_ticks,
                v.user.dev,
                v.user.ino,
                v.ipc.dev,
                v.ipc.ino,
                v.net.dev,
                v.net.ino
            ),
        }
    }

    /// `holder=` の値を厳密に復号する。整数は正準形、要素数はちょうど 6、不変条件は
    /// `HolderIdentity::new` と同じ。違反は `Err(())`（呼び出し側が固定文言の拒否に写す）。
    pub(super) fn parse_value(s: &str) -> Result<Option<Self>, ()> {
        if s == "-" {
            return Ok(None);
        }
        let mut parts = s.split(',');
        let pid =
            u32::try_from(canonical_u64(parts.next().ok_or(())?).ok_or(())?).map_err(|_| ())?;
        let start_time_ticks = canonical_u64(parts.next().ok_or(())?).ok_or(())?;
        let mut ns = || -> Result<NamespaceIdentity, ()> {
            let (dev, ino) = parts.next().ok_or(())?.split_once(':').ok_or(())?;
            Ok(NamespaceIdentity {
                dev: canonical_u64(dev).ok_or(())?,
                ino: canonical_u64(ino).ok_or(())?,
            })
        };
        let user = ns()?;
        let ipc = ns()?;
        let net = ns()?;
        if parts.next().is_some() || !holder_fields_consistent(pid, user, ipc, net) {
            return Err(());
        }
        Ok(Some(Self {
            pid,
            start_time_ticks,
            user,
            ipc,
            net,
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
            "4242,1,4:1,4:2,4:3,4:4",
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
        assert!(HolderIdentity::new(4242, 1, same, same, same).is_err());
        assert!(HolderIdentity::new(0, 1, ns(4, 1), ns(4, 2), ns(4, 3)).is_err());
        let id = HolderIdentity::new(
            4242,
            123456,
            ns(4, 4026531837),
            ns(4, 4026531839),
            ns(4, 4026531840),
        )
        .unwrap();
        assert_eq!(RecordedHolderIdentity::from(&id), sample());
    }
}
