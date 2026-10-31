//! GPU 予約の検出と CDI 完全修飾名への変換（TASK-156.1・TASK-156.2・STACK-9）。
//!
//! compose の `services.*.deploy.resources.reservations.devices` の各要素のうち、
//! `driver: nvidia` かつ `capabilities` に `gpu` を含むものを「変換の対象」として見分け、
//! それ以外は理由つきで [`GpuReservationDrop`] に記録する（黙って捨てない）。
//!
//! - 呼び出し元: TASK-151（#595・#598）の変換器が `devices` のノードを [`detect_gpu_reservations`] へ渡す。
//!   [`GpuReservationDetection::drops`] の件数は、#599 が `value_drops` の [`DEVICES_KEY_PATH`] へ
//!   加算する統合点になる。
//! - 変換規則（TASK-156.2）: [`convert_gpu_reservations`] が検出結果を `nvidia.com/gpu=<id>|all` へ変換する。
//!   `count`・`device_ids` が無いか `count: "all"` のときだけ `all` にする。`count: N` は GPU の個数であり
//!   インデックスではなく一意な CDI 名にできないため、変換せず drop に記録する（spec の P1-9 訂正）。
//!   `device_ids` の各要素は CDI デバイス名の規則で検証し、不正・`"all"`・重複が 1 つでもあれば
//!   予約ごと drop にする（GPU の数を黙って減らさない）。
//! - 範囲外: 合成フィクスチャでの往復検証は #626（TASK-156.3）。変換結果の stack への書き込みと
//!   `value_drops` への加算は #598・#599。`deploy` / `resources` / `reservations` が
//!   マッピングでない場合の記録は変換器本体（#598・#599）が担う。
//! - パーサーに依存しない: YAML 値への [`ComposeNode`] の実装は #595 の結線で行う（依存を増やさない）。
//! - 入力の大きさ: 再帰しない一段の走査。確保・複製の前に [`MAX_DEVICES`]・[`MAX_DEVICE_IDS`]・
//!   [`MAX_DEVICE_ID_BYTES`]・[`MAX_DEVICE_IDS_TOTAL_BYTES`] を検証し、超過は構造化された
//!   [`GpuDropReason`] で対象外にする（パーサーの `Budget`〔#595〕に依存しない）。
//! - PoC-16 との差: PoC は不正な device_id を飛ばして残りを変換し、重複と `"all"` もそのまま通すが、`capabilities` の文字列でない要素を
//!   無視するが、本実装は GPU の数が黙って減らないよう予約ごと対象外にして記録する（fail-closed）。

/// `value_drops` に使うキーパス。識別子を含まない。
pub const DEVICES_KEY_PATH: &str = "services.*.deploy.resources.reservations.devices";

/// `devices` の要素数の上限。超えたら全体を対象外にする（STACK-9・REPAIR-5。無制限確保の防止）。
pub const MAX_DEVICES: usize = 256;
/// 1 予約の `device_ids` の件数の上限。
pub const MAX_DEVICE_IDS: usize = 256;
/// `device_ids` の 1 要素の最大バイト数。
pub const MAX_DEVICE_ID_BYTES: usize = 256;
/// 1 予約の `device_ids` の総バイト数の上限。
pub const MAX_DEVICE_IDS_TOTAL_BYTES: usize = 16 * 1024;

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
    /// 要求の指定形（解釈は [`cdi_names_for`]）。
    pub request: GpuRequest<'a, N>,
}

/// GPU 要求の指定形。`count` の値は検出では解釈しない（判定は [`cdi_names_for`]）。
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
    /// `devices` の要素数が [`MAX_DEVICES`] を超える（全体を対象外にする）。
    TooManyDevices,
    /// `device_ids` の件数が [`MAX_DEVICE_IDS`] を超える。
    TooManyDeviceIds,
    /// `device_ids` の要素が [`MAX_DEVICE_ID_BYTES`] を超える、または総バイト数が上限を超える。
    DeviceIdTooLong,
    /// `count` が `"all"`（大文字小文字を区別した完全一致）でない（STACK-9・TASK-156.2）。
    /// 整数・他の文字列・スカラーでない値・null を含む。個数であり一意な CDI 名にできないため変換しない。
    CountNotAll,
    /// `device_ids` の要素が CDI デバイス名の規則に合わない（空文字を含む。TASK-156.2）。
    DeviceIdNotCdiName,
    /// `device_ids` の要素が `"all"`。`all` は未指定または `count: "all"` のときだけ作る（TASK-156.2）。
    DeviceIdReservedAll,
    /// `device_ids` に同じ要素が重なる。同名の二重出力か暗黙の重複除去かで意味が変わるため、
    /// 予約ごと対象外にする安全側の判断（TASK-156.2）。
    DeviceIdDuplicate,
}

/// CDI の kind（vendor/class）。利用者の入力から組み立てず固定する。
pub const NVIDIA_GPU_KIND: &str = "nvidia.com/gpu";
/// 全 GPU を表すデバイス名。
pub const ALL_DEVICE_NAME: &str = "all";

/// CDI デバイス名の規則。先頭と末尾が ASCII 英数字、中は英数字と `_` `-` `.` `:`。
///
/// 規則は `crates/gpu` の `is_valid_device_name`（private）と上流 container-device-interface の
/// `ValidateDeviceName` に合わせた再実装。compose-convert から gpu への依存を足さない
/// （crate-naming.md 決定 5）ため共有しない。`up`（TASK-155）では gpu crate が改めて名前を解析する。
/// 両者の規則がずれる危険は残るため、gpu 側の規則を変えたらここも見直す。
/// `/`・`=`・空白・NUL・制御文字・非 ASCII は通らず、kind や区切りの差し込みを防ぐ。
fn is_valid_cdi_device_name(s: &str) -> bool {
    let b = s.as_bytes();
    let (Some(first), Some(last)) = (b.first(), b.last()) else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':'))
}

/// 1 件の GPU 要求を CDI 完全修飾名へ変換する（STACK-9）。
///
/// `Unspecified` と `count: "all"` は `nvidia.com/gpu=all`。`count` のそれ以外は
/// [`GpuDropReason::CountNotAll`]。`device_ids` は全要素を検証してから入力の順に変換し、
/// 1 件でも不正なら予約ごと `Err`。件数・長さは検出（TASK-156.1）の上限で検証済み。
pub fn cdi_names_for<N: ComposeNode>(
    request: &GpuRequest<'_, N>,
) -> Result<Vec<String>, GpuDropReason> {
    match request {
        GpuRequest::Unspecified => Ok(vec![format!("{NVIDIA_GPU_KIND}={ALL_DEVICE_NAME}")]),
        GpuRequest::Count(node) => {
            if node.as_str() == Some(ALL_DEVICE_NAME) {
                Ok(vec![format!("{NVIDIA_GPU_KIND}={ALL_DEVICE_NAME}")])
            } else {
                Err(GpuDropReason::CountNotAll)
            }
        }
        GpuRequest::DeviceIds(ids) => {
            let mut seen = std::collections::BTreeSet::new();
            for id in ids {
                if id == ALL_DEVICE_NAME {
                    return Err(GpuDropReason::DeviceIdReservedAll);
                }
                if !is_valid_cdi_device_name(id) {
                    return Err(GpuDropReason::DeviceIdNotCdiName);
                }
                if !seen.insert(id.as_str()) {
                    return Err(GpuDropReason::DeviceIdDuplicate);
                }
            }
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                out.push(format!("{NVIDIA_GPU_KIND}={id}"));
            }
            Ok(out)
        }
    }
}

/// 変換できた 1 件の GPU 予約。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedGpuReservation {
    /// `devices` 内での添字。
    pub index: usize,
    /// CDI 完全修飾名（`device_ids` の順）。
    pub devices: Vec<String>,
}

/// 検出と変換をあわせた結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuReservationConversion {
    /// 変換できた予約（入力の順）。
    pub reservations: Vec<ConvertedGpuReservation>,
    /// 検出段・変換段の対象外の記録（添字の順。値は持たない）。
    pub drops: Vec<GpuReservationDrop>,
}

impl GpuReservationConversion {
    /// `value_drops[DEVICES_KEY_PATH]` へ加算する件数（検出段と変換段の合計。#599 の統合点）。
    pub fn drop_count(&self) -> u64 {
        u64::try_from(self.drops.len()).unwrap_or(u64::MAX)
    }

    /// 全予約の名前を入力の順につないだもの（stack の `ResourceReservations.devices` へ渡す形）。
    /// 予約をまたぐ重複は除かない。別々の予約の合成は変換器本体の判断に任せる。
    pub fn devices(&self) -> Vec<String> {
        self.reservations
            .iter()
            .flat_map(|r| r.devices.iter().cloned())
            .collect()
    }
}

/// `devices` ノードを検出し、CDI 完全修飾名へ変換する（STACK-9・TASK-156.2）。
pub fn convert_gpu_reservations<N: ComposeNode>(devices: &N) -> GpuReservationConversion {
    let detection = detect_gpu_reservations(devices);
    let mut drops = detection.drops;
    let mut reservations = Vec::with_capacity(detection.reservations.len());
    for r in &detection.reservations {
        match cdi_names_for(&r.request) {
            Ok(names) => reservations.push(ConvertedGpuReservation {
                index: r.index,
                devices: names,
            }),
            Err(reason) => drops.push(GpuReservationDrop {
                index: Some(r.index),
                reason,
            }),
        }
    }
    // `None`（devices 全体の問題）は先頭、以降は添字順。安定ソートで同一添字の順を保つ。
    drops.sort_by_key(|d| d.index);
    GpuReservationConversion {
        reservations,
        drops,
    }
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
    if items.len() > MAX_DEVICES {
        out.drops.push(GpuReservationDrop {
            index: None,
            reason: GpuDropReason::TooManyDevices,
        });
        return out;
    }
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
            if ids.len() > MAX_DEVICE_IDS {
                return Err(GpuDropReason::TooManyDeviceIds);
            }
            let mut out = Vec::with_capacity(ids.len());
            let mut total = 0usize;
            for id in ids {
                let v = if let Some(s) = id.as_str() {
                    if s.len() > MAX_DEVICE_ID_BYTES {
                        return Err(GpuDropReason::DeviceIdTooLong);
                    }
                    s.to_owned()
                } else if let Some(n) = id.as_u64() {
                    n.to_string()
                } else {
                    return Err(GpuDropReason::DeviceIdInvalid);
                };
                total = total.saturating_add(v.len());
                if total > MAX_DEVICE_IDS_TOTAL_BYTES {
                    return Err(GpuDropReason::DeviceIdTooLong);
                }
                out.push(v);
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

    /// STACK-9・REPAIR-5: 件数・長さの上限超過は確保前に構造化された理由で対象外になる。
    #[test]
    fn size_limits_are_enforced() {
        let many = seq((0..=MAX_DEVICES).map(|_| gpu(vec![])).collect());
        assert_eq!(drop_of(many), vec![(None, GpuDropReason::TooManyDevices)]);
        let at_limit = seq((0..MAX_DEVICES).map(|_| gpu(vec![])).collect());
        assert_eq!(
            detect_gpu_reservations(&at_limit).reservations.len(),
            MAX_DEVICES
        );

        let many_ids = gpu(vec![(
            "device_ids",
            seq((0..=MAX_DEVICE_IDS).map(|_| s("0")).collect()),
        )]);
        let long_id = gpu(vec![(
            "device_ids",
            seq(vec![s(&"a".repeat(MAX_DEVICE_ID_BYTES + 1))]),
        )]);
        let total = gpu(vec![(
            "device_ids",
            seq((0..MAX_DEVICE_IDS)
                .map(|_| s(&"a".repeat(MAX_DEVICE_ID_BYTES)))
                .collect()),
        )]);
        let ok_id = gpu(vec![(
            "device_ids",
            seq(vec![s(&"a".repeat(MAX_DEVICE_ID_BYTES))]),
        )]);
        let devices = seq(vec![many_ids, long_id, total, ok_id]);
        let d = detect_gpu_reservations(&devices);
        let drops: Vec<_> = d.drops.iter().map(|x| (x.index, x.reason)).collect();
        assert_eq!(
            drops,
            vec![
                (Some(0), GpuDropReason::TooManyDeviceIds),
                (Some(1), GpuDropReason::DeviceIdTooLong),
                (Some(2), GpuDropReason::DeviceIdTooLong),
            ]
        );
        assert_eq!(d.reservations.len(), 1);
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

    fn ids(v: Vec<T>) -> T {
        gpu(vec![("device_ids", seq(v))])
    }
    fn names(devices: &T) -> Vec<String> {
        let c = convert_gpu_reservations(devices);
        assert!(c.drops.is_empty(), "{:?}", c.drops);
        c.devices()
    }
    fn conv_drops(devices: T) -> Vec<(Option<usize>, GpuDropReason)> {
        let c = convert_gpu_reservations(&devices);
        assert!(c.reservations.is_empty());
        c.drops.iter().map(|x| (x.index, x.reason)).collect()
    }

    #[test]
    fn stack_9_unspecified_and_count_all_become_all() {
        let d = seq(vec![gpu(vec![]), gpu(vec![("count", s("all"))])]);
        assert_eq!(names(&d), vec!["nvidia.com/gpu=all", "nvidia.com/gpu=all"]);
    }

    #[test]
    fn stack_9_device_ids_become_qualified_names() {
        let d = seq(vec![ids(vec![
            s("GPU-abc"),
            s("1"),
            T::Int(7),
            s("0:1"),
            s("GPU-8f2a1c3e-0000-4b5d-9e11-aaaaaaaaaaaa"),
        ])]);
        assert_eq!(
            names(&d),
            vec![
                "nvidia.com/gpu=GPU-abc",
                "nvidia.com/gpu=1",
                "nvidia.com/gpu=7",
                "nvidia.com/gpu=0:1",
                "nvidia.com/gpu=GPU-8f2a1c3e-0000-4b5d-9e11-aaaaaaaaaaaa",
            ]
        );
    }

    #[test]
    fn stack_9_count_number_is_dropped_not_converted() {
        let cases = vec![
            T::Int(1),
            T::Int(0),
            s("2"),
            s("ALL"),
            T::Bool,
            T::Null,
            seq(vec![]),
            map(vec![]),
        ];
        for c in cases {
            let d = seq(vec![gpu(vec![("count", c)])]);
            assert_eq!(conv_drops(d), vec![(Some(0), GpuDropReason::CountNotAll)]);
        }
    }

    #[test]
    fn stack_9_invalid_device_id_drops_whole_reservation() {
        for bad in ["", "-a", "a-", "a/b", "a=b", "x y", "a\0b", "ＧＰＵ"] {
            let d = seq(vec![ids(vec![s("0"), s(bad)])]);
            assert_eq!(
                conv_drops(d),
                vec![(Some(0), GpuDropReason::DeviceIdNotCdiName)],
                "{bad:?}"
            );
        }
    }

    #[test]
    fn stack_9_device_id_all_and_duplicates_are_dropped() {
        assert_eq!(
            conv_drops(seq(vec![ids(vec![s("all")])])),
            vec![(Some(0), GpuDropReason::DeviceIdReservedAll)]
        );
        assert_eq!(
            conv_drops(seq(vec![ids(vec![s("0"), s("0")])])),
            vec![(Some(0), GpuDropReason::DeviceIdDuplicate)]
        );
        assert_eq!(
            conv_drops(seq(vec![ids(vec![T::Int(0), s("0")])])),
            vec![(Some(0), GpuDropReason::DeviceIdDuplicate)]
        );
    }

    #[test]
    fn stack_9_conversion_merges_detection_and_conversion_drops_in_order() {
        let devices = seq(vec![
            gpu(vec![]),
            gpu(vec![("count", T::Int(2))]),
            T::Null,
            ids(vec![s("a"), s("b")]),
            ids(vec![s("a/b")]),
            map(vec![("driver", s("amd"))]),
        ]);
        let c = convert_gpu_reservations(&devices);
        assert_eq!(
            c.reservations,
            vec![
                ConvertedGpuReservation {
                    index: 0,
                    devices: vec!["nvidia.com/gpu=all".into()]
                },
                ConvertedGpuReservation {
                    index: 3,
                    devices: vec!["nvidia.com/gpu=a".into(), "nvidia.com/gpu=b".into()]
                },
            ]
        );
        let got: Vec<_> = c.drops.iter().map(|d| (d.index, d.reason)).collect();
        assert_eq!(
            got,
            vec![
                (Some(1), GpuDropReason::CountNotAll),
                (Some(2), GpuDropReason::NotMapping),
                (Some(4), GpuDropReason::DeviceIdNotCdiName),
                (Some(5), GpuDropReason::DriverNotNvidia),
            ]
        );
        assert_eq!(c.drop_count(), 4);
        assert_eq!(
            c.devices(),
            vec!["nvidia.com/gpu=all", "nvidia.com/gpu=a", "nvidia.com/gpu=b"]
        );
    }

    #[test]
    fn stack_9_conversion_whole_devices_problems_yield_no_devices() {
        assert_eq!(
            conv_drops(s("x")),
            vec![(None, GpuDropReason::DevicesNotSequence)]
        );
        let many = seq((0..=MAX_DEVICES).map(|_| gpu(vec![])).collect());
        assert_eq!(
            conv_drops(many),
            vec![(None, GpuDropReason::TooManyDevices)]
        );
    }
}
