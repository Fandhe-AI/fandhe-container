//! child subreaper の設定と、再親付けされた孫プロセス（コンテナの PID 1）の pid 指定回収（CORE-1・CORE-2・TASK-29 追補・#1813）。
//!
//! 本番 launcher は fork した中間プロセスの中でコンテナの PID 1 を起動する。中間プロセスが先に終わると
//! PID 1 は呼び出し側（supervisor）から見て孫になり、subreaper が無ければ init へ再親付けされて
//! `waitpid` で回収できない。呼び出し側を child subreaper（`prctl(PR_SET_CHILD_SUBREAPER)`）にして、
//! 再親付けされた孫を pid 指定で回収できるようにするのが本モジュールの責務である。
//!
//! # 呼び出し文脈と契約
//!
//! - 設定する側は launcher を呼ぶプロセス（supervisor）。時機は launcher の fork の**前**。フラグは fork した
//!   子へ継承されず、設定前に既に init へ再親付けされた孫は回収できない
//! - [`ChildSubreaper::enable`] は設定後に読み戻して確認し、設定できなければ `Err` を返す。呼び出し側は
//!   launch へ進まない（fail-closed）。冪等で、複数回呼んでもよい
//! - 証跡 [`ChildSubreaper`] はこのモジュール外から構築できない。[`ContainerChild::adopt_reparented`] は
//!   証跡を引数に取るので、subreaper 未設定のまま adopt 経路を使うコードはコンパイルできない
//! - 解除（`disable`）は提供しない（YAGNI）。`Drop` で暗黙に解除すると、回収前の孫が再び init へ流れるため、
//!   プロセスの生存期間にわたって設定したままにする
//! - 回収は既存の [`ContainerChild::wait_timeout`] が `waitpid(<その pid>, WNOHANG)` だけで行う。
//!   `waitpid(-1)` は使わないので他の子を巻き込まない（期限つき。REPAIR-5）
//! - 再親付けの前（中間プロセスの生存中）は孫は自分の子ではなく、`waitpid` は `ECHILD` になる。
//!   このとき `wait_timeout` は `Internal`（段 `Wait`）で `Err` を返し、他プロセスを回収せず状態も変えない。
//!   呼び出し側は中間プロセスの終了を回収してから adopt して待つ
//! - 再親付けされたゾンビは自分が回収するまで pid が解放されないため、pid の再利用による取り違えは起きない
//!   （adopt 時に `pidfd` も取得し、シグナル送信は `ContainerChild` の pidfd 経路を使う）
//! - 対象は PID 1 のみ。コンテナ内でさらに孤児になった PID 1 以外の子孫は subreaper ではなく PID 1 が
//!   再親付けの受け皿になるため本モジュールの対象外
//!
//! # 配線（#1816）と未実装（REPAIR-3）
//!
//! 本番 launcher（`oci_runtime::ProductionLauncher`）が構築時に [`ChildSubreaper::enable`] を呼んで証跡を保持し、
//! `exec/launch_intermediate.rs` が報告 pipe で受け取った PID 1 の pid を [`ContainerChild::adopt_reparented`] へ渡す。
//! 中間プロセスが報告前に殺された場合の PID 1 は、起動識別子による `/proc` 探索で特定して回収する（`launch_intermediate.rs` の
//! `rescan_unreported_init`。launch 失敗時と `confirm_no_process` で使う。#1817）。

use std::num::NonZeroU32;

use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

use super::{ContainerChild, ExecError, IsolationStage};

const SET_WHAT: &str = "prctl(PR_SET_CHILD_SUBREAPER)";
const GET_WHAT: &str = "prctl(PR_GET_CHILD_SUBREAPER)";

/// 呼び出しプロセスが child subreaper であることの証跡。[`ChildSubreaper::enable`] だけが作る。
#[derive(Debug)]
pub struct ChildSubreaper {
    _priv: (),
}

impl ChildSubreaper {
    /// 呼び出しプロセスを child subreaper にして、設定を読み戻して確認する。
    ///
    /// launcher を呼ぶ前（fork の前）に supervisor が呼ぶ。設定または読み戻しに失敗したら `Err` で、
    /// 呼び出し側は launch に進まない。非対応環境は `Unimplemented`。
    pub fn enable() -> Result<ChildSubreaper, ExecError> {
        Self::enable_with(sys::set_child_subreaper, sys::get_child_subreaper)
    }

    /// [`ChildSubreaper::enable`] の本体。設定・読み戻しを注入して失敗写像を単体で照合する。
    fn enable_with(
        set: impl FnOnce(bool) -> Result<(), SysError>,
        get: impl FnOnce() -> Result<bool, SysError>,
    ) -> Result<ChildSubreaper, ExecError> {
        const STAGE: IsolationStage = IsolationStage::Spawn;
        set(true).map_err(|e| ExecError::from_sys(e, STAGE, SET_WHAT))?;
        let on = get().map_err(|e| ExecError::from_sys(e, STAGE, GET_WHAT))?;
        if !on {
            return Err(ExecError::new(
                ErrorCode::Internal,
                STAGE,
                format!("{GET_WHAT} reported the flag is not set after enabling it"),
            ));
        }
        Ok(ChildSubreaper { _priv: () })
    }
}

impl ContainerChild {
    /// subreaper のもとで再親付けされた孫（コンテナの PID 1）を pid 指定で回収するハンドルを作る。
    ///
    /// `pid` は launcher の状態 pipe など信頼できる経路で受け取った値に限る（外部入力を直接渡さない）。
    /// 回収・シグナル送信は [`ContainerChild::wait_timeout`] など既存の入口をそのまま使い、その pid
    /// だけを対象にする。呼び出し順の契約はモジュール doc の「呼び出し文脈と契約」を参照。
    pub fn adopt_reparented(pid: NonZeroU32, _proof: &ChildSubreaper) -> ContainerChild {
        ContainerChild::spawned(pid.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORE-1・#1813: 設定の失敗は段 `Spawn` の `Err` になり、読み戻しは呼ばれず証跡は作られない。
    #[test]
    fn enable_fails_closed_when_set_fails() {
        let err = ChildSubreaper::enable_with(
            |_| Err(SysError::Os(sys::EINVAL)),
            || panic!("get must not be called after a failed set"),
        )
        .unwrap_err();
        assert_eq!(err.stage, IsolationStage::Spawn);
        assert!(err.message.contains(SET_WHAT), "{}", err.message);
    }

    /// 非対応環境は `Unimplemented`。
    #[test]
    fn enable_maps_unsupported_to_unimplemented() {
        let err =
            ChildSubreaper::enable_with(|_| Err(SysError::Unsupported), || Ok(true)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unimplemented);
    }

    /// 読み戻しが偽なら成功扱いにしない。
    #[test]
    fn enable_rejects_flag_not_set_on_readback() {
        let err = ChildSubreaper::enable_with(|_| Ok(()), || Ok(false)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.stage, IsolationStage::Spawn);
        assert!(err.message.contains(GET_WHAT), "{}", err.message);
    }

    /// 読み戻し自体の失敗も `Err`。
    #[test]
    fn enable_fails_when_readback_fails() {
        let err =
            ChildSubreaper::enable_with(|_| Ok(()), || Err(SysError::Os(sys::EINVAL))).unwrap_err();
        assert!(err.message.contains(GET_WHAT), "{}", err.message);
    }

    /// 設定・読み戻しがともに成功すれば証跡を得る。
    #[test]
    fn enable_succeeds_when_both_succeed() {
        assert!(
            ChildSubreaper::enable_with(
                |on| {
                    assert!(on);
                    Ok(())
                },
                || Ok(true)
            )
            .is_ok()
        );
    }
}
