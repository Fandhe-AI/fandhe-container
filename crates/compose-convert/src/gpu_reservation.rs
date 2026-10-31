//! GPU 予約の検出（TASK-156.1・STACK-9）。
//!
//! compose の `services.*.deploy.resources.reservations.devices` の各要素のうち、
//! `driver: nvidia` かつ `capabilities` に `gpu` を含むものを「変換の対象」として見分け、
//! それ以外は理由つきで [`GpuReservationDrop`] に記録する（黙って捨てない）。
//!
//! - 呼び出し元: TASK-151（#595・#598）の変換器が `devices` のノードを [`detect_gpu_reservations`] へ渡す。
//!   [`GpuReservationDetection::drops`] の件数は、#599 が `value_drops` の [`DEVICES_KEY_PATH`] へ
//!   加算する統合点になる。
//! - 範囲外: CDI 完全修飾名の組み立て・`count: N` の扱い・device_id の文字種検証は #625（TASK-156.2）、
//!   合成フィクスチャでの往復検証は #626（TASK-156.3）。`deploy` / `resources` / `reservations` が
//!   マッピングでない場合の記録は変換器本体（#598・#599）が担う。
//! - パーサーに依存しない: YAML 値への [`ComposeNode`] の実装は #595 の結線で行う（依存を増やさない）。
//! - 入力の大きさ: 再帰しない一段の走査で、確保は要素数に比例するだけ。要素数・深さの上限は
//!   パーサーの `Budget`（#595）が担う。
//! - PoC-16 との差: PoC は不正な device_id を飛ばして残りを変換し、`capabilities` の文字列でない要素を
//!   無視するが、本実装は GPU の数が黙って減らないよう予約ごと対象外にして記録する（fail-closed）。

/// `value_drops` に使うキーパス。識別子を含まない。
pub const DEVICES_KEY_PATH: &str = "services.*.deploy.resources.reservations.devices";

/// 検出が入力の YAML ノードに求める最小の読み取り口。
pub trait ComposeNode: Sized {
    /// 文字列スカラーのとき `Some`。
    fn as_str(&self) -> Option<&str>;
    /// 非負の整数スカラーのとき `Some`。
    fn as_u64(&self) -> Option<u64>;
    /// シーケンスのとき要素列を返す。
    fn as_sequence(&self) -> Option<&[Self]>;
    /// マッピングのとき `true`。
    fn is_mapping(&self) -> bool;
    /// マッピングのキー参照。マッピングでない・キーが無いときは `None`。
    fn get(&self, key: &str) -> Option<&Self>;
}

/// 検出結果。変換の対象と、記録すべき対象外の両方を持つ。
#[derive(Debug)]
pub struct GpuReservationDetection<'a, N> {
    /// 変換の対象になる予約（入力の順）。
    pub reservations: Vec<DetectedGpuReservation<'a, N>>,
    /// 対象外にした予約の記録（入力の順。1 要素につき理由は 1 つ）。
    pub drops: Vec<GpuReservationDrop>,
}

impl<N> GpuReservationDetection<'_, N> {
    /// `value_drops[DEVICES_KEY_PATH]` へ加算する件数。
    pub fn drop_count(&self) -> u64 {
        u64::try_from(self.drops.len()).unwrap_or(u64::MAX)
    }
}

/// 変換の対象になる 1 件の GPU 予約。
#[derive(Debug)]
pub struct DetectedGpuReservation<'a, N> {
    /// `devices` 内での添字。
    pub index: usize,
    /// 要求の指定形（解釈は #625）。
    pub request: GpuRequest<'a, N>,
}

/// GPU 要求の指定形。`count` の値は解釈しない（`"all"` か表現できない値かの判定は #625）。
#[derive(Debug)]
pub enum GpuRequest<'a, N> {
    /// `count`・`device_ids` のどちらも無い。
    Unspecified,
    /// `count` だけがある。値は未解釈のノード。
    Count(&'a N),
    /// 空でない `device_ids`。各要素は文字列へ正規化済み。
    DeviceIds(Vec<String>),
}

/// 対象外にした予約の記録。値そのものは持たない（識別子が入りうるため）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuReservationDrop {
    /// `devices` 内の添字。`devices` 自体の問題なら `None`。
    pub index: Option<usize>,
    /// 対象外にした理由。
    pub reason: GpuDropReason,
}

/// 対象外の理由。#625 が variant を足せるよう `non_exhaustive`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GpuDropReason {
    /// `devices` がシーケンスでない。
    DevicesNotSequence,
    /// 要素がマッピングでない。
    NotMapping,
    /// `driver` が無い。
    DriverMissing,
    /// `driver` が `nvidia`（完全一致）でない。文字列でない場合も含む。
    DriverNotNvidia,
    /// `capabilities` が無い。
    CapabilitiesMissing,
    /// `capabilities` がシーケンスでない、または文字列でない要素がある。
    CapabilitiesInvalid,
    /// `capabilities` に `gpu` が無い。
    GpuCapabilityMissing,
    /// `count` と `device_ids` の同時指定。
    CountAndDeviceIds,
    /// `device_ids` がシーケンスでない。
    DeviceIdsNotSequence,
    /// `device_ids` が空。
    DeviceIdsEmpty,
    /// `device_ids` に文字列でも非負整数でもない要素がある。
    DeviceIdInvalid,
}

/// `devices` ノードから GPU 予約を検出する（STACK-9）。
pub fn detect_gpu_reservations<N: ComposeNode>(devices: &N) -> GpuReservationDetection<'_, N> {
    let mut out = GpuReservationDetection {
        reservations: Vec::new(),
        drops: Vec::new(),
    };
    let Some(items) = devices.as_sequence() else {
        out.drops.push(GpuReservationDrop {
            index: None,
            reason: GpuDropReason::DevicesNotSequence,
        });
        return out;
    };
    for (index, item) in items.iter().enumerate() {
        match classify(item) {
            Ok(request) => out
                .reservations
                .push(DetectedGpuReservation { index, request }),
            Err(reason) => out.drops.push(GpuReservationDrop {
                index: Some(index),
                reason,
            }),
        }
    }
    out
}

fn classify<N: ComposeNode>(item: &N) -> Result<GpuRequest<'_, N>, GpuDropReason> {
    if !item.is_mapping() {
        return Err(GpuDropReason::NotMapping);
    }
    let driver = item.get("driver").ok_or(GpuDropReason::DriverMissing)?;
    if driver.as_str() != Some("nvidia") {
        return Err(GpuDropReason::DriverNotNvidia);
    }
    let caps = item
        .get("capabilities")
        .ok_or(GpuDropReason::CapabilitiesMissing)?;
    let caps = caps
        .as_sequence()
        .ok_or(GpuDropReason::CapabilitiesInvalid)?;
    let mut has_gpu = false;
    for cap in caps {
        match cap.as_str() {
            Some("gpu") => has_gpu = true,
            Some(_) => {}
            None => return Err(GpuDropReason::CapabilitiesInvalid),
        }
    }
    if !has_gpu {
        return Err(GpuDropReason::GpuCapabilityMissing);
    }
    match (item.get("count"), item.get("device_ids")) {
        (Some(_), Some(_)) => Err(GpuDropReason::CountAndDeviceIds),
        (Some(count), None) => Ok(GpuRequest::Count(count)),
        (None, None) => Ok(GpuRequest::Unspecified),
        (None, Some(ids)) => {
            let ids = ids
                .as_sequence()
                .ok_or(GpuDropReason::DeviceIdsNotSequence)?;
            if ids.is_empty() {
                return Err(GpuDropReason::DeviceIdsEmpty);
            }
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(s) = id.as_str() {
                    out.push(s.to_owned());
                } else if let Some(n) = id.as_u64() {
                    out.push(n.to_string());
                } else {
                    return Err(GpuDropReason::DeviceIdInvalid);
                }
            }
            Ok(GpuRequest::DeviceIds(out))
        }
    }
}

#[cfg(test)]
mod tests {
    //! STACK-9 の検出規則の単体テスト。

    use super::*;

    enum T {
        Null,
        Bool,
        Int(i64),
        Float,
        Str(String),
        Seq(Vec<T>),
        Map(Vec<(String, T)>),
    }

    impl ComposeNode for T {
        fn as_str(&self) -> Option<&str> {
            match self {
                T::Str(s) => Some(s),
                _ => None,
            }
        }
        fn as_u64(&self) -> Option<u64> {
            match self {
                T::Int(i) => u64::try_from(*i).ok(),
                _ => None,
            }
        }
        fn as_sequence(&self) -> Option<&[T]> {
            match self {
                T::Seq(v) => Some(v),
                _ => None,
            }
        }
        fn is_mapping(&self) -> bool {
            matches!(self, T::Map(_))
        }
        fn get(&self, key: &str) -> Option<&T> {
            match self {
                T::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
    }

    fn s(v: &str) -> T {
        T::Str(v.to_owned())
    }
    fn seq(v: Vec<T>) -> T {
        T::Seq(v)
    }
    fn map(v: Vec<(&str, T)>) -> T {
        T::Map(v.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
    fn gpu(extra: Vec<(&str, T)>) -> T {
        let mut v = vec![
            ("driver", s("nvidia")),
            ("capabilities", seq(vec![s("gpu")])),
        ];
        v.extend(extra);
        map(v)
    }
    fn drop_of(devices: T) -> Vec<(Option<usize>, GpuDropReason)> {
        let d = detect_gpu_reservations(&devices);
        assert!(d.reservations.is_empty());
        d.drops.iter().map(|x| (x.index, x.reason)).collect()
    }

    #[test]
    fn detects_unspecified_count_and_device_ids() {
        let devices = seq(vec![
            gpu(vec![]),
            gpu(vec![("count", s("all"))]),
            gpu(vec![("device_ids", seq(vec![T::Int(0), s("GPU-xxxx")]))]),
        ]);
        let d = detect_gpu_reservations(&devices);
        assert!(d.drops.is_empty());
        assert_eq!(d.drop_count(), 0);
        assert_eq!(d.reservations.len(), 3);
        assert!(matches!(d.reservations[0].request, GpuRequest::Unspecified));
        assert!(matches!(d.reservations[1].request, GpuRequest::Count(_)));
        match &d.reservations[2].request {
            GpuRequest::DeviceIds(ids) => assert_eq!(ids, &["0", "GPU-xxxx"]),
            _ => panic!("expected DeviceIds"),
        }
        assert_eq!(d.reservations[2].index, 2);
    }

    #[test]
    fn driver_missing_is_dropped() {
        let e = map(vec![("capabilities", seq(vec![s("gpu")]))]);
        assert_eq!(
            drop_of(seq(vec![e])),
            vec![(Some(0), GpuDropReason::DriverMissing)]
        );
    }

    #[test]
    fn non_nvidia_driver_and_capabilities_are_dropped() {
        let amd = map(vec![
            ("driver", s("amd")),
            ("capabilities", seq(vec![s("gpu")])),
        ]);
        let upper = map(vec![
            ("driver", s("NVIDIA")),
            ("capabilities", seq(vec![s("gpu")])),
        ]);
        let compute = map(vec![
            ("driver", s("nvidia")),
            ("capabilities", seq(vec![s("compute")])),
        ]);
        let nocap = map(vec![("driver", s("nvidia"))]);
        let badcap = map(vec![
            ("driver", s("nvidia")),
            ("capabilities", seq(vec![s("gpu"), T::Int(1)])),
        ]);
        let capstr = map(vec![("driver", s("nvidia")), ("capabilities", s("gpu"))]);
        assert_eq!(
            drop_of(seq(vec![amd, upper, compute, nocap, badcap, capstr])),
            vec![
                (Some(0), GpuDropReason::DriverNotNvidia),
                (Some(1), GpuDropReason::DriverNotNvidia),
                (Some(2), GpuDropReason::GpuCapabilityMissing),
                (Some(3), GpuDropReason::CapabilitiesMissing),
                (Some(4), GpuDropReason::CapabilitiesInvalid),
                (Some(5), GpuDropReason::CapabilitiesInvalid),
            ]
        );
    }

    #[test]
    fn count_and_device_ids_conflict_and_bad_device_ids() {
        let both = gpu(vec![
            ("count", T::Int(1)),
            ("device_ids", seq(vec![s("0")])),
        ]);
        let empty = gpu(vec![("device_ids", seq(vec![]))]);
        let not_seq = gpu(vec![("device_ids", s("0"))]);
        let b = gpu(vec![("device_ids", seq(vec![T::Bool]))]);
        let neg = gpu(vec![("device_ids", seq(vec![T::Int(-1)]))]);
        let fl = gpu(vec![("device_ids", seq(vec![T::Float]))]);
        let nul = gpu(vec![("device_ids", seq(vec![T::Null]))]);
        let nested = gpu(vec![("device_ids", seq(vec![seq(vec![])]))]);
        assert_eq!(
            drop_of(seq(vec![both, empty, not_seq, b, neg, fl, nul, nested])),
            vec![
                (Some(0), GpuDropReason::CountAndDeviceIds),
                (Some(1), GpuDropReason::DeviceIdsEmpty),
                (Some(2), GpuDropReason::DeviceIdsNotSequence),
                (Some(3), GpuDropReason::DeviceIdInvalid),
                (Some(4), GpuDropReason::DeviceIdInvalid),
                (Some(5), GpuDropReason::DeviceIdInvalid),
                (Some(6), GpuDropReason::DeviceIdInvalid),
                (Some(7), GpuDropReason::DeviceIdInvalid),
            ]
        );
    }

    #[test]
    fn non_mapping_elements_and_non_sequence_devices() {
        assert_eq!(
            drop_of(seq(vec![s("x"), seq(vec![]), T::Null])),
            vec![
                (Some(0), GpuDropReason::NotMapping),
                (Some(1), GpuDropReason::NotMapping),
                (Some(2), GpuDropReason::NotMapping),
            ]
        );
        assert_eq!(
            drop_of(map(vec![("driver", s("nvidia"))])),
            vec![(None, GpuDropReason::DevicesNotSequence)]
        );
    }

    #[test]
    fn mixed_keeps_order() {
        let devices = seq(vec![
            gpu(vec![]),
            s("x"),
            gpu(vec![("count", s("all"))]),
            map(vec![
                ("driver", s("amd")),
                ("capabilities", seq(vec![s("gpu")])),
            ]),
            gpu(vec![("device_ids", seq(vec![]))]),
        ]);
        let d = detect_gpu_reservations(&devices);
        let idx: Vec<usize> = d.reservations.iter().map(|r| r.index).collect();
        assert_eq!(idx, vec![0, 2]);
        let drops: Vec<_> = d.drops.iter().map(|x| (x.index, x.reason)).collect();
        assert_eq!(
            drops,
            vec![
                (Some(1), GpuDropReason::NotMapping),
                (Some(3), GpuDropReason::DriverNotNvidia),
                (Some(4), GpuDropReason::DeviceIdsEmpty),
            ]
        );
        assert_eq!(d.drop_count(), 3);
    }
}
