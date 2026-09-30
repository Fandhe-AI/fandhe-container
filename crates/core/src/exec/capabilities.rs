//! capability の絞り込み（SEC-1・TASK-37.1・#172・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）の第 2 段「capability 削減」の実体。呼び出したスレッドの
//! capability を OCI 既定集合（[`CapabilitySet::oci_default`]。SEC-1）へ絞り込み、結果を読み戻して
//! 検証する。ステージ列（`StagePipeline`）への組み込みと制限適用の証跡化は #173（TASK-37.2）、
//! 実プロセスでの `/proc/<pid>/status` 検証は #174（TASK-37.3）が担う。
//! **現時点ではどの経路からも呼ばれない**（REPAIR-3）。`process.rs::require_restriction_evidence` も
//! 変えておらず、本関数の成否によらず exec は引き続き拒否される。
//!
//! # 契約
//!
//! - `fork_single_threaded` による単一スレッドの子で、pivot 後・`NO_NEW_PRIVS` の前に呼ぶ。
//!   bounding set・`capset(2)` はスレッド単位で、呼んだスレッドにしか効かない
//! - 許可集合は OCI 既定集合に固定し、任意の集合を渡せる公開経路は持たない（設定から危険な
//!   capability を足せない）
//! - bounding set は `execve` 後の uid 0 プロセスの permitted の上限を決めるため、最初に縮める。
//!   カーネルが知る全番号を `PR_CAPBSET_READ` で調べ、許可集合に無いものはすべて drop する。
//!   本 crate の `Capability` が知らない新しい capability も drop される（fail-closed）
//! - inheritable は空にする（CVE-2022-29162 の教訓。ambient は inheritable ⊆ で空に保たれる）
//! - 途中で失敗したら打ち切ってエラーを返し、部分的に成功した状態のまま `Ok` を返さない。
//!   設定後に capget と bounding set を読み戻し、不一致なら `Internal` で失敗する
//!
//! 本物の syscall は [`RealKernel`]（`sys` のラッパー）だけが呼ぶ。テストは偽の `CapKernel` を差し込んで
//! 呼び出し順・エラー写像・読み戻し不一致を再現し、本物の syscall は `sys.rs` のテストと、使い捨て
//! スレッドを使う `sec1_apply_default_capabilities_real_thread` で確認する。

use super::{ExecError, IsolationStage};
use crate::capabilities::CapabilitySet;
use crate::sys::{self, EINVAL, SysError, ThreadCaps};
use crate::traits::types::ErrorCode;

/// カーネルへの capability 操作の境界。本番は [`RealKernel`]（`sys` の薄いラッパー）、
/// テストは偽物を差し込んで呼び出し順・エラー写像・読み戻し不一致を再現する。
trait CapKernel {
    fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError>;
    fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError>;
    fn ambient_clear_all(&mut self) -> Result<(), SysError>;
    fn get(&mut self) -> Result<ThreadCaps, SysError>;
    fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError>;
}

/// 本物の syscall を呼ぶ実装。
struct RealKernel;

impl CapKernel for RealKernel {
    fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError> {
        sys::cap_bounding_contains(cap)
    }
    fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError> {
        sys::cap_bounding_drop(cap)
    }
    fn ambient_clear_all(&mut self) -> Result<(), SysError> {
        sys::cap_ambient_clear_all()
    }
    fn get(&mut self) -> Result<ThreadCaps, SysError> {
        sys::cap_get_thread()
    }
    fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError> {
        sys::cap_set_thread(caps)
    }
}

/// capability の適用結果。将来の拡張（証跡化。#173）に備えて `non_exhaustive` にする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapabilityReport {
    /// bounding set から drop した capability 番号（本 crate が知らない番号も表せるよう番号で持つ）。
    pub bounding_dropped: Vec<u8>,
    /// 最終的な effective / permitted の集合。
    pub granted: CapabilitySet,
    /// 許可集合に含まれるが、適用前の permitted に無く付与できなかったもの。
    pub unavailable: CapabilitySet,
    /// 調べて分かったカーネルの最後の capability 番号。
    pub last_cap: u8,
}

/// 呼び出したスレッドの capability を OCI 既定集合（SEC-1）へ絞り込む。
///
/// 単一スレッドの子で pivot 後・`NO_NEW_PRIVS` の前に呼ぶ前提（ステージ列への組み込みは #173）。
/// bounding set・capset はスレッド単位のため、マルチスレッドのプロセスで呼んでも他スレッドには
/// 効かない。
pub fn apply_default_capabilities() -> Result<CapabilityReport, ExecError> {
    apply_capabilities(CapabilitySet::oci_default(), &mut RealKernel)
}

/// カーネルの capability 番号の上限（2 語 = 64 bit）。
const CAP_INDEX_LIMIT: u8 = 64;

fn apply_capabilities(
    allowed: CapabilitySet,
    kernel: &mut impl CapKernel,
) -> Result<CapabilityReport, ExecError> {
    let stage = IsolationStage::CapabilityDrop;
    let fail = |e: SysError, what: &str| ExecError::from_sys(e, stage, what);

    // 1. bounding set の削減（許可集合に無い番号を、カーネルが知る最後の番号まですべて drop する）。
    let mut dropped = Vec::new();
    let mut last_cap = None;
    for n in 0..CAP_INDEX_LIMIT {
        match kernel.bounding_contains(n) {
            Ok(true) if !allowed.contains_index(n) => {
                kernel
                    .bounding_drop(n)
                    .map_err(|e| fail(e, "prctl(PR_CAPBSET_DROP)"))?;
                dropped.push(n);
            }
            Ok(_) => {}
            // カーネルの最後の capability を超えると EINVAL になる。
            Err(SysError::Os(e)) if e == EINVAL && n > 0 => {
                last_cap = Some(n - 1);
                break;
            }
            // 番号 0 で EINVAL は「capability を 1 つも知らない」ことになり、カーネルの応答として異常。
            Err(SysError::Os(e)) if e == EINVAL => {
                return Err(ExecError::new(
                    ErrorCode::Internal,
                    stage,
                    "prctl(PR_CAPBSET_READ) rejected capability 0",
                ));
            }
            Err(e) => return Err(fail(e, "prctl(PR_CAPBSET_READ)")),
        }
    }
    let last_cap = match last_cap {
        Some(n) => n,
        // 0..64 がすべて既知だった場合、番号 64 が EINVAL であること（= 63 が最後）を確認する。
        // 認識されるなら本実装の 2 語 ABI では扱えない未知 capability が残り得るため、
        // 対応 ABI を実装するまで fail-closed で拒否する（SEC-1）。
        None => match kernel.bounding_contains(CAP_INDEX_LIMIT) {
            Err(SysError::Os(e)) if e == EINVAL => CAP_INDEX_LIMIT - 1,
            Ok(_) => {
                return Err(ExecError::new(
                    ErrorCode::Unimplemented,
                    stage,
                    "kernel recognises capability numbers beyond 63, which this implementation cannot drop",
                ));
            }
            Err(e) => return Err(fail(e, "prctl(PR_CAPBSET_READ)")),
        },
    };

    // 2. ambient のクリア。
    kernel
        .ambient_clear_all()
        .map_err(|e| fail(e, "prctl(PR_CAP_AMBIENT_CLEAR_ALL)"))?;

    // 3. effective = permitted = 許可集合 ∩ 現在の permitted、inheritable = 空。
    let current = kernel.get().map_err(|e| fail(e, "capget"))?;
    let granted = allowed.intersect(CapabilitySet::from_cap_words(current.permitted));
    let unavailable = without(allowed, granted);
    let target = ThreadCaps {
        effective: granted.to_cap_words(),
        permitted: granted.to_cap_words(),
        inheritable: [0, 0],
    };
    kernel.set(target).map_err(|e| fail(e, "capset"))?;

    // 4. 読み戻し検証（fail-closed）。
    let after = kernel.get().map_err(|e| fail(e, "capget"))?;
    if after != target {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "capabilities differ from the target after capset",
        ));
    }
    for n in 0..=last_cap {
        let present = kernel
            .bounding_contains(n)
            .map_err(|e| fail(e, "prctl(PR_CAPBSET_READ)"))?;
        if present && !allowed.contains_index(n) {
            return Err(ExecError::new(
                ErrorCode::Internal,
                stage,
                "bounding set still holds a capability outside the allowed set",
            ));
        }
    }

    Ok(CapabilityReport {
        bounding_dropped: dropped,
        granted,
        unavailable,
        last_cap,
    })
}

/// `set` から `minus` の要素を除いた集合。
fn without(set: CapabilitySet, minus: CapabilitySet) -> CapabilitySet {
    set.iter()
        .filter(|c| !minus.contains(*c))
        .fold(CapabilitySet::empty(), |acc, c| acc.with(c))
}

/// テスト用の偽 syscall。
#[cfg(test)]
pub(super) mod testing {
    use crate::sys::{EINVAL, SysError, ThreadCaps};

    /// 偽カーネルの状態と、呼び出し記録・注入するエラー。
    pub(super) struct Fake {
        pub(super) bounding: u64,
        pub(super) last_cap: u8,
        pub(super) caps: ThreadCaps,
        pub(super) calls: Vec<&'static str>,
        pub(super) drop_err: Option<SysError>,
        pub(super) read_err: Option<SysError>,
        pub(super) capset_err: Option<SysError>,
        /// capset が成功を返すが値を反映しない（読み戻し検証の不一致を作る）。
        pub(super) capset_noop: bool,
        pub(super) capset_arg: Option<ThreadCaps>,
    }

    impl Fake {
        pub(super) fn new() -> Self {
            Self {
                bounding: (1u64 << 41) - 1,
                last_cap: 40,
                caps: ThreadCaps {
                    effective: [u32::MAX, 0x1FF],
                    permitted: [u32::MAX, 0x1FF],
                    inheritable: [0x10, 0],
                },
                calls: Vec::new(),
                drop_err: None,
                read_err: None,
                capset_err: None,
                capset_noop: false,
                capset_arg: None,
            }
        }
    }

    impl super::CapKernel for Fake {
        fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError> {
            if cap == 0
                && let Some(e) = self.read_err
            {
                return Err(e);
            }
            if cap > self.last_cap {
                return Err(SysError::Os(EINVAL));
            }
            // 64 以上は bounding（u64）の範囲外。認識されるが保持していない扱いにする。
            Ok(cap < 64 && self.bounding & (1u64 << cap) != 0)
        }

        fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError> {
            self.calls.push("drop");
            if let Some(e) = self.drop_err {
                return Err(e);
            }
            self.bounding &= !(1u64 << cap);
            Ok(())
        }

        fn ambient_clear_all(&mut self) -> Result<(), SysError> {
            self.calls.push("ambient");
            Ok(())
        }

        fn get(&mut self) -> Result<ThreadCaps, SysError> {
            self.calls.push("capget");
            Ok(self.caps)
        }

        fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError> {
            self.calls.push("capset");
            self.capset_arg = Some(caps);
            if let Some(e) = self.capset_err {
                return Err(e);
            }
            if !self.capset_noop {
                self.caps = caps;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Fake;
    use super::*;
    use crate::capabilities::Capability;

    const DEFAULT_MASK: u64 = 0xA804_25FB;

    /// 偽カーネルへ既定集合を適用する。
    fn run(fake: &mut Fake) -> Result<CapabilityReport, ExecError> {
        apply_capabilities(CapabilitySet::oci_default(), fake)
    }

    /// SEC-1: 既定集合以外（41 - 14 = 27 個）をすべて drop し、bounding が既定集合になる。
    #[test]
    fn sec1_drops_all_non_default_caps_from_bounding() {
        let mut k = Fake::new();
        let report = run(&mut k).unwrap();
        let expected: Vec<u8> = (0..41u8)
            .filter(|n| DEFAULT_MASK & (1u64 << n) == 0)
            .collect();
        assert_eq!(expected.len(), 27);
        assert_eq!(report.bounding_dropped, expected);
        assert_eq!(report.last_cap, 40);
        assert_eq!(k.bounding, DEFAULT_MASK);
        assert_eq!(report.granted, CapabilitySet::oci_default());
        assert!(report.unavailable.is_empty());
    }

    /// SEC-1: 本 crate が知らない新しい capability（41〜45）も drop される。
    #[test]
    fn sec1_unknown_newer_cap_is_dropped() {
        let mut k = Fake::new();
        k.last_cap = 45;
        k.bounding = (1u64 << 46) - 1;
        let report = run(&mut k).unwrap();
        for n in 41..=45u8 {
            assert!(report.bounding_dropped.contains(&n), "{n}");
        }
        assert_eq!(report.last_cap, 45);
        assert_eq!(k.bounding, DEFAULT_MASK);
    }

    /// SEC-1: カーネルが番号 64 以上を認識する場合は fail-closed で拒否する。
    #[test]
    fn sec1_cap_number_64_recognised_is_rejected() {
        let mut k = Fake::new();
        k.last_cap = 64;
        k.bounding = u64::MAX;
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unimplemented);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        // 拒否は ambient・capset より前（以降の呼び出しは行わない）。
        assert!(!k.calls.contains(&"capset"));
    }

    /// SEC-1: 番号 63 まで既知で 64 が EINVAL なら last_cap = 63 で成功する。
    #[test]
    fn sec1_cap_number_63_is_last_succeeds() {
        let mut k = Fake::new();
        k.last_cap = 63;
        k.bounding = u64::MAX;
        let report = run(&mut k).unwrap();
        assert_eq!(report.last_cap, 63);
        assert_eq!(k.bounding, DEFAULT_MASK);
    }

    /// SEC-1: 呼び出し順は bounding drop → ambient → capget → capset → capget（検証）。
    #[test]
    fn sec1_call_order_is_bounding_ambient_capset_verify() {
        let mut k = Fake::new();
        k.bounding = 0xFF; // 既定外の番号 2 が drop 対象になる
        run(&mut k).unwrap();
        assert_eq!(k.calls, ["drop", "ambient", "capget", "capset", "capget"]);
    }

    /// SEC-1: capset に渡る値は effective = permitted = 既定集合、inheritable = 空。
    #[test]
    fn sec1_inheritable_is_cleared_and_effective_equals_permitted() {
        let mut k = Fake::new();
        run(&mut k).unwrap();
        let arg = k.capset_arg.unwrap();
        assert_eq!(arg.effective, [0xA804_25FB, 0]);
        assert_eq!(arg.permitted, [0xA804_25FB, 0]);
        assert_eq!(arg.inheritable, [0, 0]);
    }

    /// SEC-1: 適用前の permitted に無い capability は付与せず、`unavailable` に報告する。
    #[test]
    fn sec1_unavailable_caps_are_reported() {
        let mut k = Fake::new();
        // CAP_MKNOD（27）を permitted から外す。
        k.caps.permitted = [!(1u32 << 27), 0x1FF];
        let report = run(&mut k).unwrap();
        assert_eq!(
            report.unavailable,
            CapabilitySet::empty().with(Capability::Mknod)
        );
        assert!(!report.granted.contains(Capability::Mknod));
        assert_eq!(report.granted.len(), 13);
        let arg = k.capset_arg.unwrap();
        assert_eq!(arg.effective, [0xA804_25FB & !(1 << 27), 0]);
    }

    /// SEC-1: drop の EPERM は PermissionDenied・段は CapabilityDrop・後続を呼ばない。
    #[test]
    fn sec1_drop_eperm_maps_permission_denied_and_stops() {
        let mut k = Fake::new();
        k.drop_err = Some(SysError::Os(sys::EPERM));
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        assert_eq!(e.violation, None);
        assert_eq!(k.calls, ["drop"]);
    }

    /// SEC-1: capset が成功を返しても読み戻しが違えば Internal（fail-closed）。
    #[test]
    fn sec1_verify_mismatch_is_internal() {
        let mut k = Fake::new();
        k.capset_noop = true;
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
    }

    /// SEC-1: capset の EPERM は PermissionDenied。
    #[test]
    fn sec1_capset_eperm_maps_permission_denied() {
        let mut k = Fake::new();
        k.capset_err = Some(SysError::Os(sys::EPERM));
        assert_eq!(run(&mut k).unwrap_err().code, ErrorCode::PermissionDenied);
    }

    /// SEC-1: 番号 0 で EINVAL なら Internal、Unsupported は Unimplemented。
    #[test]
    fn sec1_bounding_read_errors_are_mapped() {
        let mut k = Fake::new();
        k.read_err = Some(SysError::Os(EINVAL));
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        let mut k = Fake::new();
        k.read_err = Some(SysError::Unsupported);
        assert_eq!(run(&mut k).unwrap_err().code, ErrorCode::Unimplemented);
    }

    /// `/proc/thread-self/status` の `field:` 行（16 進 64 bit）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn status_value(field: &str) -> u64 {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let v = status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .unwrap_or_else(|| panic!("{field} missing"));
        u64::from_str_radix(v.trim(), 16).unwrap()
    }

    /// SEC-1: 本物の syscall（使い捨てスレッド。スレッド単位なので libtest の他スレッドに影響しない）。
    /// `CAP_SETPCAP` が effective にあれば適用が成功して /proc の値が既定集合に絞られ、無ければ
    /// `PR_CAPBSET_DROP` が EPERM で PermissionDenied になる（root 権限は要求しない）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec1_apply_default_capabilities_real_thread() {
        std::thread::spawn(|| {
            let bnd = status_value("CapBnd:");
            let prm = status_value("CapPrm:");
            let eff = status_value("CapEff:");
            let bnd_has_extra = bnd & !DEFAULT_MASK & ((1u64 << 41) - 1) != 0;
            if eff & (1 << 8) == 0 {
                if bnd_has_extra {
                    let e = apply_default_capabilities().unwrap_err();
                    assert_eq!(e.code, ErrorCode::PermissionDenied);
                    assert_eq!(e.stage, IsolationStage::CapabilityDrop);
                }
            } else {
                let report = apply_default_capabilities().unwrap();
                assert_eq!(status_value("CapBnd:"), bnd & DEFAULT_MASK);
                assert_eq!(status_value("CapEff:"), prm & DEFAULT_MASK);
                assert_eq!(status_value("CapPrm:"), prm & DEFAULT_MASK);
                assert_eq!(status_value("CapInh:"), 0);
                assert_eq!(status_value("CapAmb:"), 0);
                assert_eq!(
                    report.granted.len() as u32,
                    (prm & DEFAULT_MASK).count_ones()
                );
            }
        })
        .join()
        .unwrap();
    }
}
