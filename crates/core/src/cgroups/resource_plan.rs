//! OCI `linux.resources` の検証済みの値（`oci_runtime::LinuxResourceLimits`）を、cgroup v2 の setter が受ける型へ
//! 変換した「資源制限の計画」（TASK-29 追補・#2019。setter は TASK-32・TASK-170。CORE-3・CORE-4・SEC-1・SUP-13）。
//!
//! # 役割と呼び出し元
//!
//! - `create` の `validate_bundle` が [`ResourceLimitPlan::try_from`] を試し、cgroup v2 の範囲外の値（`cpu.period`
//!   の範囲・pids の上限・blkio の重み・デバイス番号の幅）を create の時点で `InvalidArgument` にする
//! - supervisor の start 経路（`ProductionStartDeps::prepare_cgroup`）が同じ変換で plan を組み、
//!   [`super::CgroupLimitPlan::with_resources`] 経由で [`super::CgroupPrepared::apply_limits`] に渡す。そこで
//!   [`ResourceLimitPlan::required_controllers`] を `enable_controllers` で有効化してから setter を呼ぶ
//!
//! # 契約
//!
//! 変換は OCI の意味の正規化を済ませた値を受け取り、cgroup v2 の型の検証（`CpuMax`・`PidsMax`・`BlkioWeight`・
//! `BlockDevice`・`IoMax`）だけを行う。`CgroupError` のメッセージは値を含まない固定文言に置き換える（ERR-1）。

use super::{
    BlkioWeight, BlockDevice, CgroupError, CgroupStep, Controller, ControllerSet, CpuMax, CpuQuota,
    IoLimit, IoMax, MemoryLimit, MemoryLimits, PidsMax,
};
use crate::oci_runtime::{ByteLimit, LinuxResourceLimits};
use crate::traits::ErrorCode;

/// 範囲外の値を表す共通のエラー。値・キー名以外は載せない（ERR-1）。
fn out_of_range(field: &'static str) -> CgroupError {
    CgroupError::new(
        ErrorCode::InvalidArgument,
        CgroupStep::SetCpuMax,
        format!("{field} is outside the cgroup v2 range"),
    )
}

/// cgroup v2 の型へ変換済みの資源制限の計画。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ResourceLimitPlan {
    /// `memory.max` と `memory.swap.max`。
    pub memory: Option<MemoryLimits>,
    /// `cpu.max`。
    pub cpu: Option<CpuMax>,
    /// `pids.max`。
    pub pids: Option<PidsMax>,
    /// `blockIO.weight`（`io.bfq.weight` か `io.weight`）。
    pub blkio_weight: Option<BlkioWeight>,
    /// デバイスごとの `io.max`（`(major, minor)` の昇順）。
    pub io_max: Vec<IoMax>,
}

fn memory_limit(l: ByteLimit) -> Result<MemoryLimit, CgroupError> {
    match l {
        ByteLimit::Max => Ok(MemoryLimit::Max),
        ByteLimit::Bytes(n) => MemoryLimit::bytes(n),
    }
}

fn io_limit(rate: Option<u64>) -> IoLimit {
    rate.map_or(IoLimit::Unlimited, IoLimit::Value)
}

impl TryFrom<&LinuxResourceLimits> for ResourceLimitPlan {
    type Error = CgroupError;

    /// 範囲外は `InvalidArgument`（メッセージはキー名だけ）。
    fn try_from(limits: &LinuxResourceLimits) -> Result<Self, Self::Error> {
        let memory = match (limits.memory_max(), limits.memory_swap_max()) {
            (None, None) => None,
            (Some(max), swap) => Some(MemoryLimits {
                memory_max: memory_limit(max)
                    .map_err(|_| out_of_range("linux.resources.memory.limit"))?,
                swap_max: swap
                    .map(memory_limit)
                    .transpose()
                    .map_err(|_| out_of_range("linux.resources.memory.swap"))?,
            }),
            // `memory.limit` なしの `swap = -1`（無制限）はパーサが受理する。メモリも無制限として扱う（CORE-3）。
            (None, Some(ByteLimit::Max)) => Some(MemoryLimits {
                memory_max: MemoryLimit::Max,
                swap_max: Some(MemoryLimit::Max),
            }),
            // 有限の swap だけの指定は、パーサが拒否済み（合計表現にはメモリ上限が要る）。到達したら不整合として拒否する。
            (None, Some(ByteLimit::Bytes(_))) => {
                return Err(out_of_range("linux.resources.memory.swap"));
            }
        };
        let cpu = match (limits.cpu_quota(), limits.cpu_period()) {
            (None, None) => None,
            (Some(q), p) => Some(
                CpuMax::from_signed_quota(q, p.unwrap_or(CpuMax::DEFAULT_PERIOD_US))
                    .map_err(|_| out_of_range("linux.resources.cpu"))?,
            ),
            (None, Some(p)) => Some(
                CpuMax::new(CpuQuota::Unlimited, p)
                    .map_err(|_| out_of_range("linux.resources.cpu.period"))?,
            ),
        };
        let pids = limits
            .pids_limit()
            .map(PidsMax::from_pids_limit)
            .transpose()
            .map_err(|_| out_of_range("linux.resources.pids.limit"))?;
        let blkio_weight = limits
            .blkio_weight()
            .map(BlkioWeight::new)
            .transpose()
            .map_err(|_| out_of_range("linux.resources.blockIO.weight"))?;
        let io_max = limits
            .io_throttles()
            .iter()
            .map(|t| {
                IoMax::new(
                    BlockDevice::new(t.major(), t.minor())?,
                    io_limit(t.rbps()),
                    io_limit(t.wbps()),
                    io_limit(t.riops()),
                    io_limit(t.wiops()),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| out_of_range("linux.resources.blockIO.throttle"))?;
        Ok(Self {
            memory,
            cpu,
            pids,
            blkio_weight,
            io_max,
        })
    }
}

impl ResourceLimitPlan {
    /// この計画の setter が要る controller の集合（`memory`・`cpu`・`pids`・`io`）。空なら有効化は要らない。
    pub fn required_controllers(&self) -> ControllerSet {
        let mut want = Vec::new();
        if self.memory.is_some() {
            want.push(Controller::Memory);
        }
        if self.cpu.is_some() {
            want.push(Controller::Cpu);
        }
        if self.pids.is_some() {
            want.push(Controller::Pids);
        }
        if self.blkio_weight.is_some() || !self.io_max.is_empty() {
            want.push(Controller::Io);
        }
        ControllerSet::of(&want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_runtime::parse_config_bytes;
    use serde_json::json;

    fn limits(resources: serde_json::Value) -> LinuxResourceLimits {
        let v = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["/bin/true"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "linux": {"resources": resources}
        });
        parse_config_bytes(&serde_json::to_vec(&v).expect("serialize"))
            .expect("valid config")
            .linux_resources()
            .cloned()
            .expect("resources")
    }

    /// CORE-3・SUP-13: 受理項目が cgroup v2 の型へ具体値で変換される。
    #[test]
    fn core3_plan_maps_concrete_values() {
        let plan = ResourceLimitPlan::try_from(&limits(json!({
            "memory": {"limit": 67108864, "swap": 134217728},
            "cpu": {"quota": 50000},
            "pids": {"limit": 64},
            "blockIO": {
                "weight": 500,
                "throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1048576}],
                "throttleWriteIOPSDevice": [{"major": 8, "minor": 0, "rate": 100}]
            }
        })))
        .expect("plan");
        let memory = plan.memory.expect("memory");
        assert_eq!(memory.memory_max, MemoryLimit::Bytes(67_108_864));
        assert_eq!(memory.swap_max, Some(MemoryLimit::Bytes(67_108_864)));
        let cpu = plan.cpu.expect("cpu");
        assert_eq!(cpu.quota(), CpuQuota::Micros(50_000));
        assert_eq!(cpu.period_us(), 100_000);
        assert_eq!(plan.pids.expect("pids").limit(), Some(64));
        assert_eq!(plan.blkio_weight.expect("weight").weight(), 500);
        assert_eq!(plan.io_max.len(), 1);
        let io = plan.io_max[0];
        assert_eq!((io.device().major(), io.device().minor()), (8, 0));
        assert_eq!(io.rbps(), IoLimit::Value(1_048_576));
        assert_eq!(io.wbps(), IoLimit::Unlimited);
        assert_eq!(io.riops(), IoLimit::Unlimited);
        assert_eq!(io.wiops(), IoLimit::Value(100));
    }

    /// CORE-3: 必要な controller の集合は指定した項目だけ。`{}` は空。
    #[test]
    fn core3_required_controllers_follow_the_specified_items() {
        let empty = ResourceLimitPlan::try_from(&limits(json!({}))).expect("plan");
        assert!(empty.required_controllers().is_empty());
        let plan = ResourceLimitPlan::try_from(&limits(json!({
            "memory": {"limit": -1}, "pids": {"limit": -1}
        })))
        .expect("plan");
        assert_eq!(
            plan.required_controllers(),
            ControllerSet::of(&[Controller::Memory, Controller::Pids])
        );
        assert_eq!(plan.memory.expect("memory").memory_max, MemoryLimit::Max);
        assert_eq!(plan.pids.expect("pids").limit(), None);
        let io =
            ResourceLimitPlan::try_from(&limits(json!({"blockIO": {"weight": 10}}))).expect("plan");
        assert_eq!(
            io.required_controllers(),
            ControllerSet::of(&[Controller::Io])
        );
    }

    /// CORE-3: `memory.limit` なしの `swap = -1` は `memory.max` も `max` にして swap も `max` にする。
    #[test]
    fn core3_plan_maps_swap_unlimited_without_memory_limit() {
        let plan =
            ResourceLimitPlan::try_from(&limits(json!({"memory": {"swap": -1}}))).expect("plan");
        let memory = plan.memory.expect("memory");
        assert_eq!(memory.memory_max, MemoryLimit::Max);
        assert_eq!(memory.swap_max, Some(MemoryLimit::Max));
        assert_eq!(
            plan.required_controllers(),
            ControllerSet::of(&[Controller::Memory])
        );
    }

    /// CORE-3: period だけの指定は quota 無制限、範囲外の値は InvalidArgument でキー名だけを返す。
    #[test]
    fn core3_plan_rejects_out_of_range_values() {
        let plan =
            ResourceLimitPlan::try_from(&limits(json!({"cpu": {"period": 200000}}))).expect("plan");
        let cpu = plan.cpu.expect("cpu");
        assert_eq!(
            (cpu.quota(), cpu.period_us()),
            (CpuQuota::Unlimited, 200_000)
        );
        for (resources, field) in [
            (json!({"cpu": {"period": 0}}), "linux.resources.cpu.period"),
            (
                json!({"cpu": {"quota": 1, "period": 100000}}),
                "linux.resources.cpu",
            ),
            (
                json!({"pids": {"limit": 4194305}}),
                "linux.resources.pids.limit",
            ),
            (
                json!({"blockIO": {"weight": 5}}),
                "linux.resources.blockIO.weight",
            ),
            (
                json!({"blockIO": {"weight": 0}}),
                "linux.resources.blockIO.weight",
            ),
            (
                json!({"blockIO": {"throttleReadBpsDevice": [{"major": 4096, "minor": 0, "rate": 1}]}}),
                "linux.resources.blockIO.throttle",
            ),
        ] {
            let err = ResourceLimitPlan::try_from(&limits(resources)).expect_err("out of range");
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{field}");
            assert_eq!(
                err.message,
                format!("{field} is outside the cgroup v2 range")
            );
        }
    }
}
