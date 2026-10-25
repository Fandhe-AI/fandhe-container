//! 稼働中コンテナの pid1 の特定と、その namespace への `setns(2)` 参加（SUP-6・TASK-163.1・#500・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! `fandhe-container-supervisor` の `exec` モジュール（`identify_pid1` / `enter_namespaces`）が、
//! `state.json` の記録 pid を **候補** として、記録のコンテナ ID・cgroup 配置とともに [`Pid1Target::open`] へ
//! 渡し、検証を通った対象に対して [`join_namespaces`] を呼ぶ。`unsafe` はここへは置かず、
//! `crate::sys::setns_pidfd` に閉じ込める。
//!
//! # 契約
//!
//! - **公開する入口**: 既定のビルドで公開するのは、記録の型（`ContainerId`・`CgroupPlacement`）から期待
//!   cgroup パスを core 側で組み立てる [`Pid1Target::open`] と、SUP-6 の 5 種へ固定で参加する
//!   [`join_namespaces`] だけである。期待 cgroup パスを文字列で受ける入口
//!   （`Pid1Target::open_with_cgroup_path`）は `exec-test-support` feature を付けたビルドにだけ存在し
//!   （実機結合試験用）、参加する namespace の部分集合を呼び出し側が選ぶ入口は持たない
//! - **対象の固定（TOCTOU）**: pidfd を **先に** 開いてから `/proc/<pid>` を検証し、読み取りをすべて終えた後に
//!   pidfd の未終了を確認する。未終了なら pid は再利用されていないので、読んだ内容は pidfd の指すプロセスの
//!   ものである。検証後・参加前に対象が終了しても、pidfd は元のプロセスを指し続けるため、再利用された
//!   別プロセスの namespace へは入らない（SEC-1）。[`join_namespaces`] は `setns` の直前にも終了状態と所属
//!   cgroup を再確認し、終了済み・別 cgroup へ移動済みなら拒否する（カーネルが終了済みの対象を `ESRCH` で
//!   拒否する挙動には依存しない。fail-closed）。再確認から `setns` までの窓（syscall 数回分）は残るが、
//!   その間も pidfd の指すプロセスは変わらない
//! - **記録したコンテナとの同一性**: pidfd は「呼び出した時点でその pid にいたプロセス」を固定するだけで、
//!   `state.json` に記録された元のコンテナのプロセスであることまでは証明しない（元のコンテナが終了し、
//!   その pid が別コンテナの PID 1 に再利用されると、NSpid や namespace 差異の検査は通ってしまう）。そこで
//!   期待 cgroup パス（`<委譲スコープ>/fc-<id>@<instance>`。instance はストア全体で再利用されず、コンテナごとに
//!   一意。OCI-6）と、対象の `/proc/<pid>/cgroup` の cgroup v2 行のパスが **全体で完全一致** することを必須に
//!   する。別コンテナの cgroup とは一致しないため、再利用された別コンテナの PID 1 は拒否される（SEC-1）。
//!   パス要素のどこかに名前が現れるだけ・末尾要素が同名なだけでは認めない（別の場所にある同名の cgroup を
//!   取り違えない）。読み取りが上限に達した場合と、改行で終わらない内容（途中で切れた行）は不一致として
//!   拒否する。照合は文字列で行うため、記録した側と同じ cgroup 名前空間から読むことが前提で、食い違えば
//!   不一致として拒否する（`CgroupScope` と同じ前提）
//! - **同一性照合の前提（変更時は見直すこと）**: この照合は「コンテナの中から cgroupfs に書けない」ことに
//!   依存している。rootless ではコンテナ内 root が委譲スコープの所有者と同じ euid に写るため、コンテナから
//!   cgroupfs に書ける構成では、コンテナ内のプロセスが兄弟の `fc-*` cgroup の `cgroup.procs` へ自分を移し、
//!   別コンテナの期待パスに一致させ得る。現在これが成り立つのは、書き込み可能な cgroupfs をコンテナへマウント
//!   しておらず、cgroup namespace も導入していないからである。`mounts[]` の sysfs を供給する構成（`exec::mount_sysfs`。
//!   #2020）でも、`/sys` とその配下（rbind が持ち込むホストの `/sys/fs/cgroup` の cgroup2 を含む）は再帰の読み取り専用で、
//!   載せた直後に mountinfo で全件の `ro,nosuid,nodev,noexec` を事後検証しており（満たさなければ起動しない）、コンテナの
//!   `CAP_SYS_ADMIN` の削減と seccomp の mount 系の拒否が ro の外し直しを塞ぐ。書き込み可能な cgroupfs のマウント・
//!   `CLONE_NEWCGROUP`・`/sys/fs/cgroup` の rw の bind mount を導入する変更では、本照合に同一性を依存させず、[`Pid1Target::open`]
//!   （記録 pid から開く縮退経路）を拒否へ切り替えること。恒久策は、supervisor がコンテナの起動時（fork 直後・
//!   回収前）から保持する pidfd で対象を固定する [`Pid1Target::open_with_launch_pidfd`]（#1461）で、pidfd の
//!   `Pid:`（`/proc/self/fdinfo`）と記録 pid の一致を同一性の根拠にする。この入口でも期待 cgroup の照合は
//!   多層防御として残るが、同一性の根拠ではない。pidfd を得られない場合は縮退せず拒否する。supervisor 不在
//!   （孤児化・再起動後で起動時の pidfd を失った）の場合の明示された縮退経路が [`Pid1Target::open`] で、
//!   上記の前提が成り立つ間だけ使う（本番の通しの入口はこの縮退経路を使わず拒否する。supervisor 不在時の方式は `docs/design/exec-without-supervisor.md`〔#2688。承認待ち〕）。supervisor から別プロセスの exec 専用プロセスへ pidfd を渡す 1 段目
//!   （execve 越しの継承・`SCM_RIGHTS`）は未実装（下記）
//! - **対象の限定**: 対象は、呼び出し側の PID namespace に **直接** 入れ子になった PID namespace の PID 1
//!   （`NSpid:` がちょうど 2 要素で末尾が 1）に限り、呼び出し側と同じ pid / mnt namespace へは参加しない。
//!   任意プロセスの namespace へ入る汎用手段にしない。入れ子の PID namespace の取り違え（コンテナの中で
//!   さらに作られた PID namespace の PID 1 を pid1 とみなすこと）は、この `NSpid` の深さの検査と、PID
//!   namespace の終了処理（コンテナの init が終了すると配下のプロセスは入れ子の namespace を含めて回収される
//!   ため、記録 pid が再利用される時点でコンテナ内のプロセスは残っていない）で防いでいる。`NSpid` は
//!   読み取りに使う procfs が属する PID namespace を起点に並ぶので、supervisor 自身が入れ子の PID namespace
//!   で動く構成（自分の `/proc` をマウントしている場合）でも、コンテナの pid1 はちょうど 2 要素になる
//! - **user namespace は別のときだけ参加する（SEC-5・SEC-1・TASK-163.4・TASK-163.h2・#1462）**: 対象が呼び出し側と
//!   **別の** user namespace にいるとき（既定の rootless。コンテナが user namespace を持つ）だけ、pid / mnt /
//!   uts / ipc / net より **先に** user namespace へ参加する（1 回の `setns(pidfd, CLONE_NEWUSER | 5 種)`。カーネルは
//!   user namespace を先に取り付けて残りの権限を参加先の全 capability で検証し、全体を all-or-nothing で反映する
//!   ため、途中まで参加した状態を作らない）。**同じ** user namespace（rootful 相当）なら参加しない（同じ
//!   namespace への再参加は `EINVAL`）。この関係は [`Pid1Target::open`] が副作用の前に判定して対象に記録し
//!   （`UserNsRelation`）、[`join_namespaces`] が `setns` の直前に再照合する。再照合は「対象の `ns/user` が
//!   `open` 時と同じ」「呼び出し側の `ns/user` が `open` 時と同じ」を確かめ、ずれていれば違反記録
//!   `exec_target_in_other_user_namespace` つきで拒否する。参加後の資格情報（補助グループ → gid・uid → capability
//!   削減）は `exec/reapply.rs` が launch と同じ関数で処理する。参加で全 capability を得るため、削減を省く経路は
//!   作らない（SEC-5）。カーネルの `mntns_install` / `pidns_install` は「参加先 namespace を所有する user namespace
//!   での `CAP_SYS_ADMIN`」を要求するだけで、初期 user namespace の root はすべての子孫 user namespace でその権限を
//!   持つ。user namespace に **入らず** に参加させると、exec したコマンドは初期 user namespace の uid 0 と（削減後も
//!   初期 user namespace に対して有効な）capability を持ったままコンテナの中で動き、launch より強い権限になる。
//!   そのため rootful でも rootless でも、参加後の自プロセスの `ns/user` が準備時に記録した対象の `ns/user` と
//!   一致することを `exec/reapply.rs` が照合する。**「同じ user namespace か」の基準は pid1 の資格情報の user
//!   namespace（`/proc/<pid>/ns/user`）** である。pidfd 経由の `setns(CLONE_NEWUSER)` が参加するのも pid1 の
//!   資格情報の user namespace なので、比較の基準と参加先が一致する。mount namespace を所有する user namespace
//!   （`ioctl(NS_GET_USERNS)`）を基準にすると参加先とずれ、両者を一致させるには `setns` を 2 段に分けて
//!   all-or-nothing が崩れるため採らない（REPAIR-3）。pid1 の資格情報と mount namespace の所有者がずれる対象
//!   （起動後に入れ子の user namespace へ移った pid1 等）は、カーネルが参加先での `CAP_SYS_ADMIN` を検証して
//!   `EPERM` で拒否する（fail-closed。コンテナ内では seccomp が `unshare` / `setns` を禁じており、pid1 が後から
//!   入れ子へ移る経路も塞がれている）
//! - **参加の性質**: 参加は **不可逆** で、呼び出しスレッドに作用する。単一スレッドのプロセスからのみ呼べる
//!   （`CLONE_NEWNS` はスレッドが複数あると拒否され、他 namespace もスレッドごとに食い違うため fail-closed で
//!   拒否する）。呼び出すのは exec 専用の単一スレッドプロセスで、logs 捕捉スレッドを持つ supervisor 本体から
//!   直接呼ばない（#503）。pid namespace への参加は **以後に fork した子** にだけ効く（2 段目の fork は #503）
//! - **参加後の root と cwd**: `setns(CLONE_NEWNS)` は呼び出しプロセスの root と cwd を、参加先 mount namespace の
//!   ルート（`mnt_ns->root` に積まれた最上位のマウント）へ付け替える（カーネルの `mntns_install`。pidfd で複数
//!   namespace を一括指定した場合も `commit_nsset` が同じ結果を反映する）。これは対象（pid1）自身の root では
//!   なく、両者が一致するのは launcher が `pivot_root` 済みで、以後 `/` にマウントが重ねられていない場合に
//!   限る。本関数はこの一致を検証しない。参加後の `/` が記録したコンテナの rootfs であることの照合は、制限の
//!   再適用（`exec/reapply.rs`。#502）が何も適用する前に行い、不一致なら拒否する
//! - **違反記録（SEC-4）**: 対象が分離の前提を満たさない拒否（入れ子の PID 1 でない・cgroup 不一致・呼び出し側と
//!   同じ pid / mnt namespace）には `IsolationViolation`（種別 `exec_target`）を付ける。cgroup 不一致の対象
//!   には期待 cgroup パスを、既存のエスケープ・切り詰め（`ViolationSubject`）を通して載せる。対象の終了・
//!   `/proc` の読み取り失敗・syscall 失敗・呼び出し側がマルチスレッドであることはシステムエラー / 呼び出し
//!   文脈の誤りで、違反記録を付けない
//!
//! # 参加の前後で必要な処理（#501〜#503 で実装済み）
//!
//! - 順序: ホスト側 fd の確保（cgroup.procs。#501 の `exec::cgroup_join`）は [`join_namespaces`] の **前**、制限の
//!   再適用（#502・#503 の `exec/reapply.rs`）は **後**（`setns` は seccomp の禁止 syscall に含まれ、適用後は
//!   参加できない）
//! - `setns` は uid / gid・capability・補助グループ・`no_new_privs` を **変えない**（user namespace へ参加した場合も、
//!   uid / gid の数値は変わらず参加先の namespace での見え方が変わるだけで、capability は参加先の全部を得る）。
//!   rootful で user namespace へ参加しない場合は参加後も全 capability を持つホスト root のままである。`execve` の前に、再適用が rlimit・capability 削減・
//!   `no_new_privs`・Landlock・seccomp を載せる（SEC-1）
//! - 継承した fd は参加後も開いたままである。ホスト側の fd（cgroup.procs・state・ログ等）をコンテナ内の
//!   プロセスへ渡さないよう、子が `execve` の前に `close_range` で閉じる。fork から `close_range` までの間に
//!   子がコンテナ側から見える窓は、exec 専用 worker を non-dumpable にして閉じる（`exec/exec_command.rs`。#503）
//!
//! # 未実装（REPAIR-3）
//!
//! - `NS_GET_USERNS` による「mount namespace の所有者 user namespace」と参加先の整合検査（上記の判断の注記。
//!   カーネルの `EPERM` で塞がれているため必要になるまで足さない）
//! - 違反記録の監査ログ（SEC-4）への保存のうち、本番の sink の実体の生成と CLI からの受け渡し。記録の層
//!   `AuditLayer::ExecTarget` と、通しの入口 supervisor `run_command` が親プロセス側で 1 拒否 1 件を記録する
//!   経路は実装済み（#1465）。この段関数単体は記録せず、`ExecError::violation` に載せて返すところまで
//! - supervisor が起動時から保持する pidfd の、別プロセスの exec 専用プロセスへの受け渡し（execve 越しの継承・
//!   `SCM_RIGHTS`。fork 継承は supervisor `exec::run_command_with_pidfd` で実装済み。#1461）
//! - 本番 launcher（`ProductionLauncher`）が起動した PID 1 の pidfd は `LaunchedProcess::launch_pidfd` で呼び出し側へ返す
//!   （実装済み。#1816）。別プロセスの supervisor へ渡す手段（`SCM_RIGHTS` 等）と subreaper のもとで回収前に
//!   `pidfd_open` する経路の結線は未実装。subreaper による pid 指定の回収経路自体は `ChildSubreaper`
//!   （`exec/subreaper.rs`。#1813）で追加済み。記録 pid の契約は下記のとおり固定した（#1463）
//!
//! # 記録 pid の契約と pid1 の特定（#1463・TASK-163 追補）
//!
//! - **記録 pid は PID 1 そのもの**: `LaunchedProcess::pid` / `launch_pidfd` はコンテナの PID 1（launcher の
//!   PID namespace から見て `NSpid` が 2 要素で末尾 1）を指す契約とする。中間プロセス（fork 親・mapper・
//!   rootless の代役 init）を記録する launcher は契約違反で、exec は `exec_target_not_nested_pid1` で拒否する
//!   （fail-closed）。pid1 を後から探す走査は採らない
//! - **`/proc/<pid>/task/*/children` の走査を採らない理由**: `CONFIG_PROC_CHILDREN` に依存しスレッドごとの
//!   一覧なので取りこぼす。一覧の pid は読んでから `pidfd_open` するまでに再利用される窓を新たに作る（起動時の
//!   pidfd〔#1461〕が閉じている窓）。使い捨ての中間プロセスが終了済みの設計では親子関係をたどれない
//! - **procfs の PID namespace の前提**: `/proc` の属する PID namespace が呼び出し側と一致する（自分の
//!   `NSpid` が 1 要素）ことを `/proc` を読む最初の段で確かめ、祖先の procfs を共有する構成は違反記録なしの
//!   `FailedPrecondition` で拒否する（サポートには pid の換算が要り、未実装）
//! - 特定した pid1 には cgroup 所属・`NSpid`・namespace 差異の検証が同じ強度で掛かる（新しい特定経路は無い）

use std::fs;
use std::io::Read;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use super::{ExecError, IsolationStage, ViolationReason, errno_to_code, status_threads};
use crate::cgroups::CgroupName;
use crate::sys::{self, NsFlag, SysError};
use crate::traits::types::ErrorCode;
use crate::traits::{CgroupPlacement, CgroupScope, ContainerId};

/// `/proc/<pid>/status`・`/proc/<pid>/cgroup` の読み取り上限（バイト）。通常は 2 KiB 前後で、無制限確保を
/// 避ける。上限を超える内容は切り詰めずにエラーにする（途中で切れた行を照合に使わない）。
const PROC_READ_LIMIT: u64 = 64 * 1024;

/// 期待 cgroup パスの最大バイト数（Linux の `PATH_MAX`）。
const CGROUP_PATH_MAX: usize = 4096;

/// 参加する namespace 種別（SUP-6 の 5 種に、別の user namespace にいる対象への exec でだけ先頭に付く
/// [`User`](Self::User) を加える。#1462）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinNamespace {
    /// user namespace（対象が呼び出し側と別の user namespace にいるときだけ参加し、他の namespace より先に
    /// 取り付けられる。rootful の同じ user namespace では参加しない。[`JoinNamespace::SUP6_SET`] には含まない）。
    User,
    /// PID namespace（以後に fork した子にだけ効く）。
    Pid,
    /// mount namespace。
    Mount,
    /// UTS namespace。
    Uts,
    /// IPC namespace。
    Ipc,
    /// network namespace。
    Net,
}

impl JoinNamespace {
    /// SUP-6 が固定する参加対象 5 種（user namespace は含まない。別の user namespace にいる対象でだけ
    /// [`JoinNamespace::User`] が条件つきで先頭に付く）。
    pub const SUP6_SET: [JoinNamespace; 5] = [
        JoinNamespace::Pid,
        JoinNamespace::Mount,
        JoinNamespace::Uts,
        JoinNamespace::Ipc,
        JoinNamespace::Net,
    ];

    fn flag(self) -> NsFlag {
        match self {
            Self::User => NsFlag::User,
            Self::Pid => NsFlag::Pid,
            Self::Mount => NsFlag::Mount,
            Self::Uts => NsFlag::Uts,
            Self::Ipc => NsFlag::Ipc,
            Self::Net => NsFlag::Net,
        }
    }

    /// `/proc/<pid>/ns/` 配下のエントリ名。
    fn proc_name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Pid => "pid",
            Self::Mount => "mnt",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Net => "net",
        }
    }
}

/// 対象と呼び出し側の user namespace の関係（SUP-6・SEC-5・TASK-163.h2・#1462）。`open` が副作用の前に判定して
/// 対象に記録し、[`join_namespaces`] が参加する集合を決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UserNsRelation {
    /// 同じ user namespace にいる（rootful 相当）。user namespace へは参加しない。
    Shared {
        /// 両者の識別子。
        identity: NsIdentity,
    },
    /// 別の user namespace にいる（既定の rootless）。他の namespace より先に user namespace へ参加する。
    Distinct {
        /// 対象の識別子。
        target: NsIdentity,
        /// 呼び出し側の識別子。
        own: NsIdentity,
        /// 対象の実効 uid（呼び出し側の user namespace から見た値。`/proc/<pid>/status` の `Uid:`）。参加前の
        /// 補助グループの消去を参加後へ回してよいか（呼び出し側がコンテナの所有者と同じ uid か）の判定に使う。
        target_euid: u32,
    },
}

impl UserNsRelation {
    /// 対象の user namespace の識別子（`Shared` なら両者共通の値）。
    pub(super) fn target_identity(&self) -> NsIdentity {
        match *self {
            Self::Shared { identity } => identity,
            Self::Distinct { target, .. } => target,
        }
    }

    /// 別の user namespace か（参加するか）。
    pub(super) fn is_distinct(&self) -> bool {
        matches!(self, Self::Distinct { .. })
    }
}

/// 対象と呼び出し側の識別子から関係を決める（副作用の前に判定するテスト可能な純関数）。同じ識別子なら
/// `Shared`、異なれば `Distinct`（`target_euid` は呼び出し側が先に読む）。inode 番号が同じでも dev が違えば別の
/// namespace として扱う。
fn classify_user_namespace(
    target: NsIdentity,
    own: NsIdentity,
    target_euid: Option<u32>,
) -> Result<UserNsRelation, ExecError> {
    if target == own {
        return Ok(UserNsRelation::Shared { identity: own });
    }
    // 別の user namespace に参加するのに、補助グループの扱いの判断材料（対象の実効 uid）を読めないなら
    // 判断できない。fail-closed で拒否する。
    let target_euid = target_euid.ok_or_else(|| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::SetNs,
            "failed to read the effective uid of the exec target",
        )
    })?;
    Ok(UserNsRelation::Distinct {
        target,
        own,
        target_euid,
    })
}

/// `/proc/<pid>/status` のテキストから実効 uid（`Uid:` の 2 番目の値）を取り出す。行なし・値不足・数値でない
/// 場合は `None`（行が複数あっても最初の行を使う。カーネルは 1 行しか出さない）。
pub(super) fn status_effective_uid(status: &str) -> Option<u32> {
    let rest = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// 関係から、参加する namespace を **参加する順** に返す（副作用の前に判定するテスト可能な純関数）。
/// `Distinct` なら user namespace が先頭、`Shared` なら SUP-6 の 5 種だけ。
fn join_order(relation: &UserNsRelation) -> Vec<JoinNamespace> {
    let mut order = Vec::with_capacity(JoinNamespace::SUP6_SET.len() + 1);
    if relation.is_distinct() {
        order.push(JoinNamespace::User);
    }
    order.extend(JoinNamespace::SUP6_SET);
    order
}

/// 検証済みの参加対象（pid1）。pidfd でプロセス同一性を固定している。
#[derive(Debug)]
pub struct Pid1Target {
    pid: NonZeroU32,
    pidfd: OwnedFd,
    /// `open` で照合した期待 cgroup パス。[`join_namespaces`] が参加の直前に再照合する。
    expected_cgroup_path: String,
    /// `open` で判定した user namespace の関係。[`join_namespaces`] が参加の直前に再照合し、参加する集合を決める。
    user_ns: UserNsRelation,
}

impl Pid1Target {
    /// 対象の pid（呼び出し側の PID namespace から見た値）。
    pub fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// `open` で照合した期待 cgroup 絶対パス（`exec::cgroup_join` が cgroup を開くために使う）。
    pub(super) fn expected_cgroup_path(&self) -> &str {
        &self.expected_cgroup_path
    }

    /// 対象の mount namespace の識別子（nsfs の `st_dev`・`st_ino`）。制限を exec の対象へ束縛するために
    /// `exec::reapply` が参加の前に記録し、参加後の自プロセスの識別子と照合する（SUP-6・SEC-1・TASK-163.4）。
    ///
    /// 読み取りの後に pidfd の未終了を確認し、読んだ識別子が pidfd の指すプロセスのものであることを保証する。
    pub(super) fn mnt_ns_identity(&self) -> Result<NsIdentity, ExecError> {
        let id = ns_identity(&format!("/proc/{}/ns/mnt", self.pid))
            .map_err(|e| target_proc_error(&e, "read target mount namespace"))?;
        ensure_not_exited(self, "refusing to bind restrictions to it")?;
        Ok(id)
    }

    /// 対象と呼び出し側の user namespace の関係（`open` で判定済み）。
    pub(super) fn user_ns_relation(&self) -> UserNsRelation {
        self.user_ns
    }

    /// 対象の PID namespace の識別子（nsfs の `st_dev`・`st_ino`）。参加後に子が入る PID namespace
    /// （`ns/pid_for_children`）との照合に使う（SUP-6・SEC-1・TASK-163.4）。読み取りの後に pidfd の未終了を確認する。
    pub(super) fn pid_ns_identity(&self) -> Result<NsIdentity, ExecError> {
        let id = ns_identity(&format!("/proc/{}/ns/pid", self.pid))
            .map_err(|e| target_proc_error(&e, "read target PID namespace"))?;
        ensure_not_exited(self, "refusing to bind restrictions to it")?;
        Ok(id)
    }

    /// `pid` を候補として pid1 を特定し、検証を通ったものだけを対象にする。
    ///
    /// 期待 cgroup パスは、記録のコンテナ ID と cgroup 配置から `<scope>/fc-<id>@<instance>` として
    /// ここで組み立てる（呼び出し側から文字列では受け取らない）。対象の所属 cgroup がこれと完全一致
    /// しなければ、pid が別コンテナに再利用されたものとして拒否する（SEC-1）。
    ///
    /// 手順は順序固定: pidfd で固定 → `NSpid` が直接入れ子の PID 1 → 期待 cgroup に属する →
    /// 自分と同じ pid / mnt namespace でない → user namespace の関係を記録（別なら参加する対象にする）→ pidfd が未終了。対象が前提を満たさなければ
    /// `FailedPrecondition`（違反記録つき）、存在しない pid・検証中に消えた対象は `NotFound`、cgroup 名を
    /// 作れない ID は `InvalidArgument`。
    pub fn open(
        pid: NonZeroU32,
        id: &ContainerId,
        placement: &CgroupPlacement,
    ) -> Result<Self, ExecError> {
        let name = CgroupName::for_instance(id, placement.instance()).map_err(|_| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::SetNs,
                "container id and instance do not form a valid cgroup name",
            )
        })?;
        Self::open_at(pid, container_cgroup_path(placement.scope(), &name))
    }

    /// 実機結合試験専用の入口: 期待 cgroup 絶対パスを呼び出し側から文字列で受け取る。
    ///
    /// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開
    /// API には含まれない。コンテナ用 cgroup を作れない試験環境で成功経路を通すためのもので、期待値を
    /// 記録から導かないため「記録したコンテナのプロセスであること」（SEC-1）の照合にはならない。
    #[cfg(feature = "exec-test-support")]
    pub fn open_with_cgroup_path(
        pid: NonZeroU32,
        expected_cgroup_path: &str,
    ) -> Result<Self, ExecError> {
        Self::open_at(pid, expected_cgroup_path.to_owned())
    }

    /// [`Self::open`] の本体。期待 cgroup パスの出所を呼び出し側に委ねるため非公開にしている。
    fn open_at(pid: NonZeroU32, expected_cgroup_path: String) -> Result<Self, ExecError> {
        let stage = IsolationStage::SetNs;
        if !is_valid_cgroup_path(&expected_cgroup_path) {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                stage,
                "expected cgroup path must be an absolute, normalized, non-root cgroup path",
            ));
        }
        verify_procfs_pid_ns()?;
        let pidfd = sys::pidfd_open(pid.get()).map_err(|e| setns_error(e, "pidfd_open"))?;
        Self::verify_pinned(pid, pidfd, expected_cgroup_path)
    }

    /// supervisor が起動時（fork 直後・回収前）から保持する pidfd で対象を固定して検証する（SUP-6・SEC-1・
    /// CORE-1・TASK-163 追補・#1461）。
    ///
    /// [`Self::open`] が記録 pid から `pidfd_open` し cgroup の所属で「記録したコンテナのプロセスか」を
    /// 照合するのに対し、こちらは起動時に開いた pidfd が指すプロセスの pid（`/proc/self/fdinfo/<fd>` の
    /// `Pid:`）を記録 pid（`recorded_pid`）と照合する。pidfd は回収前に開いたため pid 再利用の影響を受けず、
    /// 同一性が cgroup の所属（コンテナ内から cgroupfs に書ける構成では偽装され得る）に依存しない。
    /// 不一致は `FailedPrecondition`（違反記録 `ExecTargetPidfdMismatch`）、pidfd でない fd は
    /// `InvalidArgument`、終了済みは `FailedPrecondition`（違反記録なし）。照合後の検証は [`Self::open`] と
    /// 同じ順序で行い、期待 cgroup の照合は同一性の根拠ではなく多層防御として残す。
    ///
    /// `pidfd` の所有権を受け取る（呼び出し側が保持する pidfd は複製して渡す）。
    pub fn open_with_launch_pidfd(
        pidfd: OwnedFd,
        recorded_pid: NonZeroU32,
        id: &ContainerId,
        placement: &CgroupPlacement,
    ) -> Result<Self, ExecError> {
        let name = CgroupName::for_instance(id, placement.instance()).map_err(|_| {
            ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::SetNs,
                "container id and instance do not form a valid cgroup name",
            )
        })?;
        let expected_cgroup_path = container_cgroup_path(placement.scope(), &name);
        if !is_valid_cgroup_path(&expected_cgroup_path) {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::SetNs,
                "expected cgroup path must be an absolute, normalized, non-root cgroup path",
            ));
        }
        // fdinfo の `Pid:` 照合より前に置く（祖先の procfs を共有する構成で誤った違反を記録しない。SEC-4）。
        verify_procfs_pid_ns()?;
        use std::os::fd::AsRawFd as _;
        let info = read_bounded(&format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
            .map_err(|e| target_proc_error(&e, "read pidfd info"))?;
        match parse_fdinfo_pid(&info) {
            FdinfoPid::NotPidfd => {
                return Err(ExecError::new(
                    ErrorCode::InvalidArgument,
                    IsolationStage::SetNs,
                    "the given descriptor is not a pidfd",
                ));
            }
            FdinfoPid::Exited => {
                return Err(ExecError::new(
                    ErrorCode::FailedPrecondition,
                    IsolationStage::SetNs,
                    "the process held by the launch pidfd has already exited",
                ));
            }
            // 呼び出し側の PID namespace から見えない（0）。同一性を示せないため拒否する。
            FdinfoPid::Pid(None) => {
                return Err(ExecError::from_violation(
                    ViolationReason::ExecTargetPidfdMismatch,
                    None,
                ));
            }
            FdinfoPid::Pid(Some(pid)) if pid != recorded_pid => {
                return Err(ExecError::from_violation(
                    ViolationReason::ExecTargetPidfdMismatch,
                    None,
                ));
            }
            FdinfoPid::Pid(Some(_)) => {}
        }
        // pidfd を保持している間 fdinfo の `Pid:` は終了後も元の pid を示し続け（`-1` にならない）、終了を
        // 検出できない。終了済み（zombie 含む）の pidfd は poll で readable になるため、pidfd と確認できた
        // 後にここで終了を拒否する（非 pidfd の fd は poll が常に readable になるため、判定は後段に置く）。
        let exited = sys::poll_readable(pidfd.as_fd(), 0)
            .map_err(|e| setns_error(e, "poll launch pidfd"))?;
        if exited {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                IsolationStage::SetNs,
                "the process held by the launch pidfd has already exited",
            ));
        }
        Self::verify_pinned(recorded_pid, pidfd, expected_cgroup_path)
    }

    /// pidfd で固定済みの `pid` を検証して対象にする共通の後段（[`Self::open`]・
    /// [`Self::open_with_launch_pidfd`] の両方が通る）。
    fn verify_pinned(
        pid: NonZeroU32,
        pidfd: OwnedFd,
        expected_cgroup_path: String,
    ) -> Result<Self, ExecError> {
        let stage = IsolationStage::SetNs;
        let status = read_bounded(&format!("/proc/{pid}/status"))
            .map_err(|e| target_proc_error(&e, "read target status"))?;
        if !nspid_is_nested_pid1(&status) {
            return Err(ExecError::from_violation(
                ViolationReason::ExecTargetNotNestedPid1,
                None,
            ));
        }
        verify_cgroup_membership(pid, &expected_cgroup_path)?;
        let mut identities = Vec::with_capacity(CALLER_DISTINCT.len());
        for ns in CALLER_DISTINCT {
            let target = ns_identity(&format!("/proc/{pid}/ns/{}", ns.proc_name()))
                .map_err(|e| target_proc_error(&e, "read target namespace"))?;
            let own = ns_identity(&format!("/proc/self/ns/{}", ns.proc_name()))
                .map_err(|e| ExecError::from_io(&e, stage, "read own namespace"))?;
            identities.push((ns, target, own));
        }
        if let Some(reason) = shared_namespace_violation(&identities) {
            return Err(ExecError::from_violation(reason, None));
        }
        let user_ns = read_user_ns_relation(pid, &status)?;
        let target = Self {
            pid,
            pidfd,
            expected_cgroup_path,
            user_ns,
        };
        // 終了後は pid が再利用され得るため、`/proc` の検証結果が pidfd の指すプロセスのものである
        // ことを、未終了の確認で保証する。
        ensure_not_exited(&target, "refusing to use it as the exec target")?;
        Ok(target)
    }
}

/// 呼び出し側と同じであってはならない namespace（対象の限定。モジュール doc「対象の限定」）。
const CALLER_DISTINCT: [JoinNamespace; 2] = [JoinNamespace::Pid, JoinNamespace::Mount];

/// namespace の識別子（nsfs の dev, ino）。
pub(super) type NsIdentity = (u64, u64);

/// `(種別, 対象の識別子, 呼び出し側の識別子)` の並びから、呼び出し側と同じ namespace があれば最初の 1 件の
/// 違反理由を返す（副作用の前に判定するテスト可能な純関数）。pid / mnt 以外の種別は判定対象にしない。
fn shared_namespace_violation(
    identities: &[(JoinNamespace, NsIdentity, NsIdentity)],
) -> Option<ViolationReason> {
    identities
        .iter()
        .find_map(|(ns, target, own)| match (target == own, ns) {
            (true, JoinNamespace::Pid) => Some(ViolationReason::ExecTargetSharesPidNamespace),
            (true, JoinNamespace::Mount) => Some(ViolationReason::ExecTargetSharesMountNamespace),
            _ => None,
        })
}

/// 対象 `pid` と呼び出し側の user namespace の関係を読んで決める（SUP-6・SEC-5・SEC-1・TASK-163.h2・#1462）。
///
/// `status` は同じ対象の `/proc/<pid>/status`（`open` が `NSpid:` の検査に読んだもの）。`ns/user` を読めない場合
/// （user namespace 無効のカーネルを含む）は関係を決められないためエラーにする（fail-closed）。読んだ内容が
/// pidfd の指すプロセスのものであることは、呼び出し側がこの後に pidfd の未終了を確認することで保証する。
fn read_user_ns_relation(pid: NonZeroU32, status: &str) -> Result<UserNsRelation, ExecError> {
    let target = ns_identity(&format!("/proc/{pid}/ns/user"))
        .map_err(|e| target_proc_error(&e, "read target user namespace"))?;
    let own = ns_identity("/proc/self/ns/user")
        .map_err(|e| ExecError::from_io(&e, IsolationStage::SetNs, "read own user namespace"))?;
    classify_user_namespace(target, own, status_effective_uid(status))
}

/// 委譲スコープ（`"/"` または `"/a/b"`）とコンテナ用 cgroup 名から、cgroup v2 ルート起点の絶対パスを作る。
/// cgroup のパスはカーネルが `/` 区切りで返す文字列で、OS のパス区切りとは無関係（Linux 専用モジュール）。
fn container_cgroup_path(scope: &CgroupScope, name: &CgroupName) -> String {
    let scope = scope.as_str();
    if scope == "/" {
        format!("/{}", name.as_str())
    } else {
        format!("{scope}/{}", name.as_str())
    }
}

/// 記録（ID と cgroup 配置）から、コンテナ固有の cgroup 絶対パスを導く（[`Pid1Target::open`] と同じ導出）。
///
/// exec 用の子 cgroup の後始末（`exec::cgroup_join`）が、呼び出しプロセスで記録だけからコンテナ cgroup を
/// 開き直すために使う。名前を作れない ID は `InvalidArgument`。
pub(super) fn container_cgroup_path_for(
    id: &ContainerId,
    placement: &CgroupPlacement,
) -> Result<String, ExecError> {
    let name = CgroupName::for_instance(id, placement.instance()).map_err(|_| {
        ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::SetNs,
            "container id and instance do not form a valid cgroup name",
        )
    })?;
    let path = container_cgroup_path(placement.scope(), &name);
    if !is_valid_cgroup_path(&path) {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::SetNs,
            "expected cgroup path must be an absolute, normalized, non-root cgroup path",
        ));
    }
    Ok(path)
}

/// 対象 `pid` の所属 cgroup（`/proc/<pid>/cgroup` の v2 行）が `expected` と完全一致することを確かめる。
///
/// 不一致は `FailedPrecondition`（違反記録 `ExecTargetCgroupMismatch`。対象に期待パスを載せる）。読み取りの
/// 結果が pidfd の指すプロセスのものであることは、呼び出し側がこの後に pidfd の未終了を確認することで
/// 保証する（終了していなければ pid は再利用されていない）。
fn verify_cgroup_membership(pid: NonZeroU32, expected: &str) -> Result<(), ExecError> {
    let cgroup = read_bounded(&format!("/proc/{pid}/cgroup"))
        .map_err(|e| target_proc_error(&e, "read target cgroup"))?;
    if !cgroup_path_matches(&cgroup, expected) {
        return Err(ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new(expected)),
        ));
    }
    Ok(())
}

/// pidfd の指すプロセスが終了済みなら `FailedPrecondition`（`what` はメッセージの末尾に付ける）。
/// 対象の終了は分離違反の試行ではないため、違反記録は付けない。
pub(super) fn ensure_not_exited(target: &Pid1Target, what: &str) -> Result<(), ExecError> {
    let exited = sys::poll_readable(target.pidfd.as_fd(), 0)
        .map_err(|e| setns_error(e, "poll target pidfd"))?;
    if exited {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            format!("process {} has already exited; {what}", target.pid),
        ));
    }
    Ok(())
}

/// 参加の直前に、対象が `open` のときと同じ期待 cgroup に属していることを再照合する（SEC-1）。
///
/// `open` から参加までの間に対象が別の cgroup へ移されていれば `FailedPrecondition`。cgroup の読み取りの後に
/// pidfd の未終了を確認し、読んだ内容が pidfd の指すプロセスのものであることを保証する。
fn recheck_cgroup_membership(target: &Pid1Target) -> Result<(), ExecError> {
    verify_cgroup_membership(target.pid, &target.expected_cgroup_path)?;
    ensure_not_exited(target, "refusing to setns")
}

/// 参加の直前に、対象と呼び出し側の user namespace が `open` のときと同じであることを再照合する
/// （SUP-6・SEC-5・SEC-1・TASK-163.h2・#1462）。
///
/// 対象の `ns/user` が `open` 時の記録（`Shared` なら両者共通、`Distinct` なら対象側）と違えば、検証から参加までの
/// 間に対象が別の user namespace へ移ったとして `FailedPrecondition`（違反記録 `exec_target_in_other_user_namespace`
/// つき）。呼び出し側の `ns/user` が `open` 時から変わっていても同様に拒否する（参加する集合の前提が崩れるため）。
/// 読み取りの後に pidfd の未終了を確認する（[`recheck_cgroup_membership`] と同じ手順）。
fn recheck_user_namespace(target: &Pid1Target) -> Result<(), ExecError> {
    let now_target = ns_identity(&format!("/proc/{}/ns/user", target.pid))
        .map_err(|e| target_proc_error(&e, "read target user namespace"))?;
    let now_own = ns_identity("/proc/self/ns/user")
        .map_err(|e| ExecError::from_io(&e, IsolationStage::SetNs, "read own user namespace"))?;
    if !user_namespace_unchanged(&target.user_ns, now_target, now_own) {
        return Err(ExecError::from_violation(
            ViolationReason::ExecTargetInOtherUserNamespace,
            None,
        ));
    }
    ensure_not_exited(target, "refusing to setns")
}

/// `open` 時の関係 `recorded` が、いまの対象 `target`・呼び出し側 `own` の識別子と矛盾しないか
/// （副作用の前に判定するテスト可能な純関数）。
fn user_namespace_unchanged(
    recorded: &UserNsRelation,
    target: NsIdentity,
    own: NsIdentity,
) -> bool {
    match *recorded {
        UserNsRelation::Shared { identity } => target == identity && own == identity,
        UserNsRelation::Distinct {
            target: t, own: o, ..
        } => target == t && own == o,
    }
}

/// [`join_namespaces`] の成功結果（将来拡張できる構造）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamespaceJoinReport {
    /// 参加した対象の pid（呼び出し側の PID namespace から見た値）。
    pub target_pid: NonZeroU32,
    /// 参加した namespace を **参加した順** に並べたもの（user namespace に参加したときは [`JoinNamespace::User`] が
    /// 先頭、続いて [`JoinNamespace::SUP6_SET`] の順）。
    pub joined: Vec<JoinNamespace>,
    /// 別の user namespace へ参加したか（`joined` に [`JoinNamespace::User`] を含むことと同じ）。`false` は対象が
    /// 呼び出し側と同じ user namespace にいて参加しなかったこと（rootful 相当）。
    pub user_namespace_joined: bool,
}

/// 検証済みの対象 `target` の SUP-6 の 5 種（pid / mnt / uts / ipc / net）の namespace へ、1 回の
/// `setns(2)` で参加する。対象が呼び出し側と **別の** user namespace にいるときは、5 種より先に user namespace にも
/// 参加する（同じ 1 回の syscall。rootless の exec。#1462）。参加する集合は `open` で判定した関係から決まり、
/// 呼び出し側は部分集合を選べない。
///
/// 参加の直前に対象の終了と所属 cgroup（`open` で照合した期待パスとの完全一致）、user namespace（対象と呼び出し側の
/// 識別子が `open` 時と同じであること）を再確認し、終了済み・別 cgroup へ移動済み・user namespace が変化して
/// いれば `FailedPrecondition`。
/// 呼び出しスレッドの namespace を不可逆に変える。単一スレッドでなければ `FailedPrecondition`。
/// 契約全体はモジュール doc を参照（SUP-6・TASK-163.1）。
pub fn join_namespaces(target: &Pid1Target) -> Result<NamespaceJoinReport, ExecError> {
    let stage = IsolationStage::SetNs;
    // 検証（`open`）から参加までの間に対象が終了していないか、参加の直前に再確認する。
    ensure_not_exited(target, "refusing to setns")?;
    let own = read_bounded("/proc/self/status")
        .map_err(|e| ExecError::from_io(&e, stage, "read own status"))?;
    if status_threads(&own) != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns",
        ));
    }
    procfs_matches_caller_pid_ns(&own)?;
    // 所属 cgroup・user namespace の再照合は `setns` の直前に置く（残る窓を最小にする）。
    recheck_cgroup_membership(target)?;
    recheck_user_namespace(target)?;
    let joined = join_order(&target.user_ns);
    let flags: Vec<NsFlag> = joined.iter().map(|n| n.flag()).collect();
    sys::setns_pidfd(target.pidfd.as_fd(), &flags).map_err(|e| setns_error(e, "setns"))?;
    Ok(NamespaceJoinReport {
        target_pid: target.pid,
        user_namespace_joined: target.user_ns.is_distinct(),
        joined,
    })
}

/// syscall 失敗を `SetNs` 段の `ExecError` にする。`ESRCH`（対象の終了）は `NotFound`。
fn setns_error(err: SysError, what: &str) -> ExecError {
    let mut e = ExecError::from_sys(err, IsolationStage::SetNs, what);
    e.code = if err == SysError::Os(sys::ESRCH) {
        ErrorCode::NotFound
    } else {
        errno_to_code(err)
    };
    e
}

/// 対象の `/proc/<pid>` 配下の読み取り失敗を `SetNs` 段の `ExecError` にする。
///
/// pidfd を開いた後に対象が終了・回収されると、`/proc/<pid>` のエントリが消えて `ENOENT`（開いた後の
/// 読み取りでは `ESRCH`）になる。これは内部障害ではなく対象の終了なので、`pidfd_open` / `setns` の
/// `ESRCH` と同じ `NotFound` に揃える。それ以外の errno は通常の分類に従う。
fn target_proc_error(err: &std::io::Error, what: &str) -> ExecError {
    let mut e = ExecError::from_io(err, IsolationStage::SetNs, what);
    if matches!(err.raw_os_error(), Some(n) if n == sys::ENOENT || n == sys::ESRCH) {
        e.code = ErrorCode::NotFound;
    }
    e
}

/// `/proc/self/fdinfo/<fd>` の `Pid:` 行の解釈結果。
///
/// `pidfd_open(2)` によれば `Pid:` は pidfd の指すプロセスの pid（読み手の PID namespace での値）で、
/// プロセスが終了していれば `-1`、読み手の PID namespace から見えなければ `0`。pidfd でない fd の
/// fdinfo には `Pid:` 行が無い（あっても複数・非数値なら pidfd と見なさない）。
#[derive(Debug, PartialEq, Eq)]
enum FdinfoPid {
    /// `Pid:` 行が 1 つだけで、正の pid（`Some`）または 0（`None`。名前空間外）。
    Pid(Option<NonZeroU32>),
    /// `Pid: -1`（終了済み。pidfd 保持中は通常現れないため、終了の主たる検出は poll）。
    Exited,
    /// pidfd の fdinfo として解釈できない。
    NotPidfd,
}

/// fdinfo のテキストから `Pid:` を取り出す。`NSpid:` 等の別行は読まない。
fn parse_fdinfo_pid(info: &str) -> FdinfoPid {
    let mut found = None;
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("Pid:") {
            if found.is_some() {
                return FdinfoPid::NotPidfd;
            }
            found = Some(rest.trim());
        }
    }
    match found {
        Some("-1") => FdinfoPid::Exited,
        Some(v) => match v.parse::<u32>() {
            Ok(n) => FdinfoPid::Pid(NonZeroU32::new(n)),
            Err(_) => FdinfoPid::NotPidfd,
        },
        None => FdinfoPid::NotPidfd,
    }
}

/// `/proc` のテキストを上限つきで読む（[`read_bounded_from`]）。
fn read_bounded(path: &str) -> std::io::Result<String> {
    read_bounded_from(fs::File::open(path)?, PROC_READ_LIMIT)
}

/// `limit` バイトまでのテキストを読む。`limit` を超える内容は切り詰めずに `InvalidData` で失敗させる
/// （途中で切れた行が照合に使われることを防ぐ。無制限確保もしない）。
pub(super) fn read_bounded_from(reader: impl Read, limit: u64) -> std::io::Result<String> {
    let mut buf = String::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_string(&mut buf)?;
    if u64::try_from(buf.len()).map_or(true, |n| n > limit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proc file exceeds the read limit",
        ));
    }
    Ok(buf)
}

/// namespace の識別子（nsfs の dev, ino）。
fn ns_identity(path: &str) -> std::io::Result<NsIdentity> {
    let m = fs::metadata(path)?;
    Ok((m.dev(), m.ino()))
}

/// `NSpid:` の要素がちょうど 2 で、末尾（最も内側の PID namespace での PID）が 1 か。
///
/// 2 要素は「読み取りに使う procfs の PID namespace に直接入れ子になった namespace」を意味する。3 要素以上
/// （コンテナの中でさらに作られた PID namespace の PID 1）は対象にしない。行なし・非数値は fail-closed で
/// `false`。
fn nspid_is_nested_pid1(status: &str) -> bool {
    matches!(parse_nspid(status).as_deref(), Some([_, 1]))
}

/// `NSpid:` 行の各要素（外側の PID namespace から内側の順）を返す。行なし・空・非数値は `None`
/// （fail-closed。`CONFIG_PID_NS` が無効なカーネルでは行自体が無い）。
fn parse_nspid(status: &str) -> Option<Vec<u32>> {
    let rest = status.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
    let mut parsed = Vec::new();
    for tok in rest.split_whitespace() {
        parsed.push(tok.parse::<u32>().ok()?);
    }
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

/// 自プロセスの `/proc/self/status` の内容から、`/proc` の属する PID namespace が呼び出し側の PID namespace と
/// 一致する（自分の `NSpid` がちょうど 1 要素）ことを確かめる純関数（SUP-6・SEC-1・SEC-4・#1463）。
///
/// 祖先の procfs を共有する入れ子の構成では `/proc/<pid>` の番号の空間と `pidfd_open(pid)` の空間が食い違い、
/// 別のプロセスを読む・正当な対象を `exec_target_pidfd_mismatch` と誤記録する恐れがあるため、サポートせず
/// 違反記録なしの前提エラーで拒否する（呼び出し文脈の誤り）。
fn procfs_matches_caller_pid_ns(own_status: &str) -> Result<(), ExecError> {
    match parse_nspid(own_status) {
        Some(v) if v.len() == 1 => Ok(()),
        Some(_) => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            "procfs at /proc does not belong to the caller's PID namespace; cannot identify pid1",
        )),
        None => Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::SetNs,
            "NSpid is missing or malformed in /proc/self/status; cannot identify pid1",
        )),
    }
}

/// [`procfs_matches_caller_pid_ns`] を実プロセスの `/proc/self/status` で行う。`/proc` を読む最初の段で呼ぶ。
fn verify_procfs_pid_ns() -> Result<(), ExecError> {
    let own = read_bounded("/proc/self/status")
        .map_err(|e| ExecError::from_io(&e, IsolationStage::SetNs, "read own status"))?;
    procfs_matches_caller_pid_ns(&own)
}

/// 期待 cgroup パスの形式検証: `/` 始まりの絶対パスで、ルート（`/`）でなく、各要素が空 / `.` / `..` で
/// なく、NUL・改行を含まず、[`CGROUP_PATH_MAX`] 以下。ルートを認めないのは、コンテナ用 cgroup が必ず
/// 委譲スコープの子であり、ルート所属の任意プロセスを対象にさせないため。
fn is_valid_cgroup_path(path: &str) -> bool {
    if path.len() > CGROUP_PATH_MAX || path.contains(['\0', '\n']) {
        return false;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// `/proc/<pid>/cgroup` の cgroup v2 行（`0::<path>`）のパスが `expected` と全体で完全一致するか。
///
/// 内容が改行で終わらない（最終行が途中で切れている可能性がある）・v2 行なし・v2 行が複数・不一致は
/// fail-closed で `false`。部分一致（接頭辞・接尾辞・途中の要素）は認めない。削除済み cgroup に残る
/// プロセスはカーネルが ` (deleted)` を付けるため一致しない。
pub(super) fn cgroup_path_matches(cgroup: &str, expected: &str) -> bool {
    if !cgroup.ends_with('\n') {
        return false;
    }
    let mut v2 = cgroup.lines().filter_map(|l| l.strip_prefix("0::"));
    match (v2.next(), v2.next()) {
        (Some(path), None) => path == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ViolationKind;
    use crate::traits::StateRevision;

    /// #1463: `NSpid` の解析は行なし・空・非数値を `None` にする。
    #[test]
    fn sup6_1463_parse_nspid_concrete_values() {
        assert_eq!(parse_nspid("NSpid:\t4242\t1\n"), Some(vec![4242, 1]));
        assert_eq!(parse_nspid("NSpid:\t4242\n"), Some(vec![4242]));
        assert_eq!(parse_nspid("Name:\tx\n"), None);
        assert_eq!(parse_nspid("NSpid:\t\n"), None);
        assert_eq!(parse_nspid("NSpid:\t4242\tabc\n"), None);
    }

    /// #1463: procfs の PID namespace 前提検査（違反記録なしの FailedPrecondition）。
    #[test]
    fn sup6_1463_procfs_pid_ns_check_concrete_values() {
        assert!(procfs_matches_caller_pid_ns("NSpid:\t4242\n").is_ok());
        let e = procfs_matches_caller_pid_ns("NSpid:\t9000\t42\n").unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert!(e.violation.is_none());
        assert_eq!(
            e.message,
            "procfs at /proc does not belong to the caller's PID namespace; cannot identify pid1"
        );
        let e = procfs_matches_caller_pid_ns("Name:\tx\n").unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message,
            "NSpid is missing or malformed in /proc/self/status; cannot identify pid1"
        );
        let e = procfs_matches_caller_pid_ns("NSpid:\tx\n").unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
    }

    /// #1463: 通常環境（自前の procfs）では前提検査が通る。
    #[test]
    fn sup6_1463_procfs_pid_ns_check_passes_on_host() {
        assert!(verify_procfs_pid_ns().is_ok());
    }

    fn me() -> NonZeroU32 {
        NonZeroU32::new(std::process::id()).unwrap()
    }

    fn placement(scope: &str, instance: u64) -> CgroupPlacement {
        CgroupPlacement::new(
            CgroupScope::new(scope).unwrap(),
            StateRevision::from_raw(instance),
        )
    }

    /// 自プロセス自身を対象にしたときの user namespace の関係（同じ namespace なので `Shared`）。
    fn own_shared() -> UserNsRelation {
        let id = ns_identity("/proc/self/ns/user").unwrap();
        UserNsRelation::Shared { identity: id }
    }

    /// 自プロセスの所属 cgroup（v2 行のパス）。
    fn own_cgroup_path() -> String {
        read_bounded("/proc/self/cgroup")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .expect("cgroup v2 line")
            .to_owned()
    }

    /// SUP-6・SEC-1: cgroup は v2 行のパス全体が完全一致したときだけ一致する。別コンテナ（別 instance・
    /// 別 ID・別スコープ）、配下の子 cgroup、他コンテナ配下に作られた同名の子 cgroup、削除済み、v1 行は
    /// すべて不一致（pid 再利用と偽装の拒否）。
    #[test]
    fn sup6_cgroup_path_exact_match() {
        let want = "/user.slice/x.scope/fc-c1@7";
        assert!(cgroup_path_matches(
            "0::/user.slice/x.scope/fc-c1@7\n",
            want
        ));
        for other in [
            "0::/user.slice/x.scope/fc-c1@8\n",
            "0::/user.slice/x.scope/fc-c2@7\n",
            "0::/user.slice/y.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7/nested\n",
            "0::/user.slice/x.scope/fc-c2@9/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c2@9/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope\n",
            "0::/user.slice/x.scope/fc-c1@7 (deleted)\n",
            "0::/user.slice/x.scope/fc-c1@7/\n",
            "1:name=x:/user.slice/x.scope/fc-c1@7\n",
            "0::/a\n0::/user.slice/x.scope/fc-c1@7\n",
            "0::/user.slice/x.scope/fc-c1@7\n0::/user.slice/x.scope/fc-c1@7\n",
            "",
        ] {
            assert!(!cgroup_path_matches(other, want), "{other:?}");
        }
    }

    /// SUP-6・SEC-1: 改行で終わらない内容（最終行が途中で切れた可能性）は、切れた位置までが期待パスと
    /// 一致していても不一致にする。本来の所属は `/user.slice/x.scope/fc-c1@77` かもしれない。
    #[test]
    fn sup6_cgroup_path_rejects_unterminated_last_line() {
        let want = "/user.slice/x.scope/fc-c1@7";
        assert!(!cgroup_path_matches("0::/user.slice/x.scope/fc-c1@7", want));
        assert!(!cgroup_path_matches(
            "1:name=x:/a\n0::/user.slice/x.scope/fc-c1@7",
            want
        ));
        assert!(cgroup_path_matches(
            "1:name=x:/a\n0::/user.slice/x.scope/fc-c1@7\n",
            want
        ));
    }

    /// SUP-6・SEC-1: 上限ちょうどまでは読み、上限を 1 バイトでも超える内容は切り詰めずに InvalidData で
    /// 失敗させる（切り詰めた末尾行を照合に使わない）。
    #[test]
    fn sup6_read_bounded_rejects_content_over_limit() {
        assert_eq!(PROC_READ_LIMIT, 64 * 1024);
        assert_eq!(read_bounded_from(&b"0::/a\n"[..], 6).unwrap(), "0::/a\n");
        let err = read_bounded_from(&b"0::/a\n"[..], 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proc file exceeds the read limit");
        // 上限で切ると期待パスと一致してしまう内容（本来は `fc-c1@77`）も、照合に進まず失敗する。
        let content = b"0::/s/fc-c1@77\n";
        let cut = "0::/s/fc-c1@7".len() as u64;
        let err = read_bounded_from(&content[..], cut).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let err = target_proc_error(&err, "read target cgroup");
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.violation, None);
    }

    /// SUP-6: 期待 cgroup パスの形式検証（絶対・正規形・ルート以外）。
    #[test]
    fn sup6_cgroup_path_validation() {
        for ok in ["/fc-c1@7", "/user.slice/x.scope/fc-c1@7"] {
            assert!(is_valid_cgroup_path(ok), "{ok}");
        }
        let too_long = format!("/{}", "a".repeat(CGROUP_PATH_MAX));
        for bad in [
            "",
            "/",
            "fc-c1@7",
            "a/b",
            "/a//b",
            "/a/",
            "/a/./b",
            "/a/../b",
            "/..",
            "/a\0b",
            "/a\n0::/b",
            too_long.as_str(),
        ] {
            assert!(!is_valid_cgroup_path(bad), "{bad:?}");
        }
    }

    /// SUP-6・SEC-1: 期待 cgroup パスは記録の委譲スコープと `fc-<id>@<instance>` の連結（ルートは `/` を
    /// 重ねない）。
    #[test]
    fn sup6_container_cgroup_path_concrete_values() {
        let id = ContainerId::new("c1").unwrap();
        let name = CgroupName::for_instance(&id, StateRevision::from_raw(7)).unwrap();
        assert_eq!(
            container_cgroup_path(&CgroupScope::new("/user.slice/x.scope").unwrap(), &name),
            "/user.slice/x.scope/fc-c1@7"
        );
        assert_eq!(
            container_cgroup_path(&CgroupScope::new("/").unwrap(), &name),
            "/fc-c1@7"
        );
    }

    /// SUP-6: 期待 cgroup パスが不正なら、対象へ触れる前に InvalidArgument（違反記録なし）。
    #[test]
    fn sup6_open_rejects_invalid_cgroup_path() {
        for bad in ["", "/", "fc-c1@7", "/a/../b", "/a//b"] {
            let err = Pid1Target::open_at(me(), bad.to_owned()).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad}");
            assert_eq!(err.stage, IsolationStage::SetNs);
            assert_eq!(err.violation, None);
        }
    }

    /// SUP-6: 検証中に対象が消えた（`/proc/<pid>` の ENOENT / ESRCH）場合は Internal ではなく NotFound。
    /// それ以外の errno は通常の分類（EACCES は PermissionDenied）。システムエラーなので違反記録は付かない。
    #[test]
    fn sup6_target_proc_error_maps_vanished_target_to_not_found() {
        for errno in [sys::ENOENT, sys::ESRCH] {
            let io = std::io::Error::from_raw_os_error(errno);
            let err = target_proc_error(&io, "read target status");
            assert_eq!(err.code, ErrorCode::NotFound, "{errno}");
            assert_eq!(err.stage, IsolationStage::SetNs);
            assert_eq!(err.violation, None);
            assert!(
                err.message.starts_with("read target status failed: "),
                "{}",
                err.message
            );
        }
        let io = std::io::Error::from_raw_os_error(sys::EACCES);
        let err = target_proc_error(&io, "read target cgroup");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    /// SUP-6: NSpid の解析。直接入れ子の PID 1（ちょうど 2 要素・末尾 1）のみ許可し、コンテナの中で
    /// さらに作られた PID namespace の PID 1（3 要素以上）は拒否する。
    #[test]
    fn sup6_nspid_parse() {
        assert!(nspid_is_nested_pid1("Name:\tx\nNSpid:\t4242\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\t3\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t1\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\t7\n"));
        assert!(!nspid_is_nested_pid1("Name:\tx\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t4242\tabc\n"));
        assert!(!nspid_is_nested_pid1("NSpid:\t\n"));
    }

    /// SUP-6・SEC-4: 自プロセスは入れ子の PID 1 でないため、違反記録つきで拒否される（記録の型から入る
    /// 公開の入口）。
    #[test]
    fn sup6_open_rejects_self_with_violation() {
        let id = ContainerId::new("x").unwrap();
        let err = Pid1Target::open(me(), &id, &placement("/", 1)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target is not PID 1 of a directly nested PID namespace"
        );
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason, ViolationReason::ExecTargetNotNestedPid1);
        assert_eq!(v.reason.as_str(), "exec_target_not_nested_pid1");
        assert_eq!(v.behavior_id, "SUP-6");
        assert_eq!(v.subject, None);
    }

    /// SUP-6（#1461）: fdinfo の `Pid:` の解釈（具体値）。
    #[test]
    fn sup6_parse_fdinfo_pid_concrete_values() {
        let n = |v: u32| FdinfoPid::Pid(NonZeroU32::new(v));
        assert_eq!(
            parse_fdinfo_pid("pos:\t0\nPid:\t1234\nNSpid:\t1234\n"),
            n(1234)
        );
        assert_eq!(
            parse_fdinfo_pid("Pid:\t-1\nNSpid:\t-1\n"),
            FdinfoPid::Exited
        );
        assert_eq!(parse_fdinfo_pid("Pid:\t0\n"), FdinfoPid::Pid(None));
        assert_eq!(
            parse_fdinfo_pid("pos:\t0\nflags:\t02\n"),
            FdinfoPid::NotPidfd
        );
        assert_eq!(parse_fdinfo_pid("Pid:\tabc\n"), FdinfoPid::NotPidfd);
        assert_eq!(parse_fdinfo_pid("Pid:\t-5\n"), FdinfoPid::NotPidfd);
        assert_eq!(parse_fdinfo_pid("Pid:\t1\nPid:\t2\n"), FdinfoPid::NotPidfd);
        assert_eq!(parse_fdinfo_pid("NSpid:\t7\n"), FdinfoPid::NotPidfd);
    }

    fn spawn_sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep")
    }

    /// SUP-6・SEC-4（#1461）: 記録 pid と pidfd の指すプロセスが違えば `exec_target_pidfd_mismatch`。
    #[test]
    fn sup6_launch_pidfd_rejects_recorded_pid_mismatch() {
        let mut child = spawn_sleeper();
        let pidfd = sys::pidfd_open(child.id())
            .expect("pidfd_open は Linux 5.3 以降が前提（pidfd 非対応環境では失敗させる）");
        let id = ContainerId::new("x").unwrap();
        let other = NonZeroU32::new(child.id() + 1).unwrap();
        let err =
            Pid1Target::open_with_launch_pidfd(pidfd, other, &id, &placement("/", 1)).unwrap_err();
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason, ViolationReason::ExecTargetPidfdMismatch);
        assert_eq!(v.reason.as_str(), "exec_target_pidfd_mismatch");
        assert_eq!(v.behavior_id, "SUP-6");
    }

    /// SUP-6（#1461）: pidfd 照合を通ると次段（入れ子の PID 1 の検査）へ進む（順序の証明）。
    #[test]
    fn sup6_launch_pidfd_match_proceeds_to_nested_pid1_check() {
        let mut child = spawn_sleeper();
        let pidfd = sys::pidfd_open(child.id())
            .expect("pidfd_open は Linux 5.3 以降が前提（pidfd 非対応環境では失敗させる）");
        let id = ContainerId::new("x").unwrap();
        let pid = NonZeroU32::new(child.id()).unwrap();
        let err =
            Pid1Target::open_with_launch_pidfd(pidfd, pid, &id, &placement("/", 1)).unwrap_err();
        let _ = child.kill();
        let _ = child.wait();
        let v = err.violation.expect("violation");
        assert_eq!(v.reason, ViolationReason::ExecTargetNotNestedPid1);
        assert_eq!(v.reason.as_str(), "exec_target_not_nested_pid1");
    }

    /// SUP-6（#1461）: pidfd でない fd は `InvalidArgument`（違反記録なし）。
    #[test]
    fn sup6_launch_pidfd_rejects_non_pidfd() {
        let file = std::fs::File::open("/proc/self/status").unwrap();
        let id = ContainerId::new("x").unwrap();
        let err =
            Pid1Target::open_with_launch_pidfd(OwnedFd::from(file), me(), &id, &placement("/", 1))
                .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.message, "the given descriptor is not a pidfd");
        assert!(err.violation.is_none());
    }

    /// SUP-6（#1461）: 終了・回収済みの子の pidfd は `FailedPrecondition`（違反記録なし）。
    #[test]
    fn sup6_launch_pidfd_rejects_exited_process() {
        let mut child = spawn_sleeper();
        let pidfd = sys::pidfd_open(child.id())
            .expect("pidfd_open は Linux 5.3 以降が前提（pidfd 非対応環境では失敗させる）");
        let pid = NonZeroU32::new(child.id()).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let id = ContainerId::new("x").unwrap();
        let err =
            Pid1Target::open_with_launch_pidfd(pidfd, pid, &id, &placement("/", 1)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the process held by the launch pidfd has already exited"
        );
        assert!(err.violation.is_none());
    }

    /// SUP-6: PID_MAX_LIMIT 超の pid は存在しない（NotFound。違反記録なし）。
    #[test]
    fn sup6_open_missing_pid_is_not_found() {
        let id = ContainerId::new("x").unwrap();
        let err = Pid1Target::open(NonZeroU32::new(4_194_305).unwrap(), &id, &placement("/", 1))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(err.violation, None);
    }

    /// SUP-6・SEC-4: 呼び出し側と同じ pid / mnt namespace の対象は、種別ごとの違反理由で拒否する
    /// （pid を先に判定）。別の namespace なら違反なし。uts 等は判定対象にしない。
    #[test]
    fn sup6_shared_namespace_violation_concrete_values() {
        let a: NsIdentity = (4, 4_026_531_836);
        let b: NsIdentity = (4, 4_026_532_500);
        use JoinNamespace::{Mount, Pid, Uts};
        assert_eq!(
            shared_namespace_violation(&[(Pid, b, a), (Mount, b, a)]),
            None
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, a, a), (Mount, b, a)]),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, b, a), (Mount, a, a)]),
            Some(ViolationReason::ExecTargetSharesMountNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&[(Pid, a, a), (Mount, a, a)]),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        // 同じ inode 番号でも dev が違えば別の namespace。
        assert_eq!(
            shared_namespace_violation(&[(Pid, (5, a.1), a), (Mount, b, a)]),
            None
        );
        assert_eq!(shared_namespace_violation(&[(Uts, a, a)]), None);
        assert_eq!(shared_namespace_violation(&[]), None);
        let err = ExecError::from_violation(ViolationReason::ExecTargetSharesMountNamespace, None);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target shares the mount namespace with the caller; refusing to join"
        );
    }

    /// SUP-6・SEC-4: 自プロセス同士の識別子は pid / mnt とも一致し、同一 namespace の拒否に届く
    /// （実際の `/proc/self/ns` の値での照合）。
    #[test]
    fn sup6_shared_namespace_violation_with_real_identities() {
        let mut identities = Vec::new();
        for ns in CALLER_DISTINCT {
            let own = ns_identity(&format!("/proc/self/ns/{}", ns.proc_name())).unwrap();
            let target = ns_identity(&format!("/proc/{}/ns/{}", me(), ns.proc_name())).unwrap();
            identities.push((ns, target, own));
        }
        assert_eq!(
            shared_namespace_violation(&identities),
            Some(ViolationReason::ExecTargetSharesPidNamespace)
        );
        assert_eq!(
            shared_namespace_violation(&identities[1..]),
            Some(ViolationReason::ExecTargetSharesMountNamespace)
        );
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: 識別子が同じなら `Shared`（参加しない）、違えば `Distinct`（参加する）。
    /// inode 番号が同じでも dev が違えば別の namespace として扱う。別の namespace で対象の実効 uid を読めない
    /// ときは判断できないため拒否する（fail-closed）。
    #[test]
    fn sup6_task163_h2_classify_user_namespace_concrete_values() {
        let own: NsIdentity = (4, 4_026_531_837);
        let other: NsIdentity = (4, 4_026_532_600);
        assert_eq!(
            classify_user_namespace(own, own, Some(1000)).unwrap(),
            UserNsRelation::Shared { identity: own }
        );
        // 同じ namespace では実効 uid を使わない（読めなくても良い）。
        assert_eq!(
            classify_user_namespace(own, own, None).unwrap(),
            UserNsRelation::Shared { identity: own }
        );
        assert_eq!(
            classify_user_namespace(other, own, Some(1000)).unwrap(),
            UserNsRelation::Distinct {
                target: other,
                own,
                target_euid: 1000
            }
        );
        assert_eq!(
            classify_user_namespace((5, own.1), own, Some(0)).unwrap(),
            UserNsRelation::Distinct {
                target: (5, own.1),
                own,
                target_euid: 0
            }
        );
        let err = classify_user_namespace(other, own, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(err.violation, None);
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: `/proc/<pid>/status` の `Uid:` から実効 uid（2 番目）を取る。行なし・
    /// 値不足・数値でない場合は `None`。
    #[test]
    fn sup6_task163_h2_status_effective_uid_parsing() {
        assert_eq!(
            status_effective_uid("Name:\tx\nUid:\t1000\t1001\t1002\t1003\nGid:\t1\t2\t3\t4\n"),
            Some(1001)
        );
        assert_eq!(status_effective_uid("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert_eq!(status_effective_uid("Uid:\t65534\n"), None);
        assert_eq!(status_effective_uid("Uid:\t1\tx\t3\t4\n"), None);
        assert_eq!(status_effective_uid("Uid:\t1\t-1\t3\t4\n"), None);
        assert_eq!(status_effective_uid("Name:\tx\n"), None);
        assert_eq!(status_effective_uid(""), None);
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: 参加する集合は、別の user namespace なら user が先頭の 6 種、同じ
    /// user namespace（rootful 相当）なら 5 種だけで user を含まない。フラグのビット和も具体値で固定する
    /// （mnt 0x00020000 | uts 0x04000000 | ipc 0x08000000 | user 0x10000000 | pid 0x20000000 | net 0x40000000）。
    #[test]
    fn sup6_task163_h2_join_order_adds_user_first_only_when_distinct() {
        use JoinNamespace::{Ipc, Mount, Net, Pid, Uts};
        let own: NsIdentity = (4, 10);
        let shared = UserNsRelation::Shared { identity: own };
        let distinct = UserNsRelation::Distinct {
            target: (4, 11),
            own,
            target_euid: 1000,
        };
        assert_eq!(join_order(&shared), vec![Pid, Mount, Uts, Ipc, Net]);
        assert_eq!(
            join_order(&distinct),
            vec![JoinNamespace::User, Pid, Mount, Uts, Ipc, Net]
        );
        let bits = |r: &UserNsRelation| {
            join_order(r)
                .iter()
                .fold(0i32, |acc, n| acc | n.flag().bits())
        };
        assert_eq!(bits(&shared), 0x6C02_0000);
        assert_eq!(bits(&distinct), 0x7C02_0000);
        assert!(!shared.is_distinct());
        assert!(distinct.is_distinct());
    }

    /// SUP-6・SEC-5・SEC-4・TASK-163.h2・#1462: 再照合は、対象・呼び出し側の識別子が `open` 時の記録と同じときだけ
    /// 通る。どちらかが変われば違反 `exec_target_in_other_user_namespace` で拒否する。
    #[test]
    fn sup6_task163_h2_user_namespace_unchanged_concrete_values() {
        let own: NsIdentity = (4, 10);
        let t: NsIdentity = (4, 11);
        let other: NsIdentity = (4, 12);
        let shared = UserNsRelation::Shared { identity: own };
        let distinct = UserNsRelation::Distinct {
            target: t,
            own,
            target_euid: 1,
        };
        assert!(user_namespace_unchanged(&shared, own, own));
        assert!(!user_namespace_unchanged(&shared, t, own));
        assert!(!user_namespace_unchanged(&shared, own, other));
        assert!(user_namespace_unchanged(&distinct, t, own));
        assert!(!user_namespace_unchanged(&distinct, other, own));
        assert!(!user_namespace_unchanged(&distinct, t, other));
        // 別の user namespace だった対象が呼び出し側と同じになった場合も拒否する。
        assert!(!user_namespace_unchanged(&distinct, own, own));
        let err = ExecError::from_violation(ViolationReason::ExecTargetInOtherUserNamespace, None);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason.as_str(), "exec_target_in_other_user_namespace");
        assert_eq!(v.behavior_id, "SUP-6");
        assert_eq!(v.subject, None);
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: 実際の `/proc` の値での照合。自プロセスは自分と同じ user namespace に
    /// いるため `Shared` になり、存在しない pid は読み取り失敗（`NotFound`。関係を決められない）。参加直前の
    /// 再照合も通る。
    #[test]
    fn sup6_task163_h2_read_user_ns_relation_with_real_identities() {
        let status = read_bounded(&format!("/proc/{}/status", me())).unwrap();
        let own = ns_identity("/proc/self/ns/user").unwrap();
        assert_eq!(
            read_user_ns_relation(me(), &status).unwrap(),
            UserNsRelation::Shared { identity: own }
        );
        let err = read_user_ns_relation(NonZeroU32::new(4_194_305).unwrap(), &status).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(err.violation, None);
        let target = Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: "/fc-x@1".to_owned(),
            user_ns: own_shared(),
        };
        recheck_user_namespace(&target).expect("recheck passes for the caller's own namespace");
        // 記録が実態と違えば（別の namespace だったと記録していれば）拒否する。
        let stale = Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: "/fc-x@1".to_owned(),
            user_ns: UserNsRelation::Distinct {
                target: (1, 1),
                own,
                target_euid: 0,
            },
        };
        let err = recheck_user_namespace(&stale).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.violation.map(|v| v.reason),
            Some(ViolationReason::ExecTargetInOtherUserNamespace)
        );
    }

    /// SUP-6: マルチスレッドの呼び出し側は FailedPrecondition（呼び出し文脈の誤りで、違反記録なし）。
    #[test]
    fn sup6_join_rejects_multi_threaded_caller() {
        let target = Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: "/fc-x@1".to_owned(),
            user_ns: own_shared(),
        };
        // 別スレッドを生かしたまま呼び、Threads が 2 以上になる状態を作る。
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let err = join_namespaces(&target).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the caller is multi-threaded or its thread count is unknown; refusing to setns"
        );
        assert_eq!(err.violation, None);
        let _ = tx.send(());
        let _ = helper.join();
    }

    /// SUP-6・SEC-1・SEC-4: 参加直前の再照合は、対象の現在の所属 cgroup が `open` 時の期待パスと完全一致する
    /// ときだけ通る。別の cgroup（移動後を想定）なら違反記録つきの FailedPrecondition で、対象には期待パスが
    /// 載る。
    #[test]
    fn sup6_recheck_cgroup_membership_rejects_moved_target() {
        let own_path = own_cgroup_path();
        let target = |path: &str| Pid1Target {
            pid: me(),
            pidfd: sys::pidfd_open(me().get()).unwrap(),
            expected_cgroup_path: path.to_owned(),
            user_ns: own_shared(),
        };
        assert_eq!(
            recheck_cgroup_membership(&target(&own_path)).map_err(|e| e.code),
            Ok(())
        );
        let moved = format!("{}/fc-x@1", own_path.trim_end_matches('/'));
        let err = recheck_cgroup_membership(&target(&moved)).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::SetNs);
        assert_eq!(
            err.message,
            "the exec target does not belong to the recorded container cgroup"
        );
        let v = err.violation.expect("violation");
        assert_eq!(v.kind, ViolationKind::ExecTarget);
        assert_eq!(v.reason, ViolationReason::ExecTargetCgroupMismatch);
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(v.subject.as_ref().map(|s| s.as_str()), Some(moved.as_str()));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4: cgroup 不一致の違反記録に載せる期待パスは、既存のエスケープ（制御文字・`\\`）と切り詰め
    /// （256 文字）を通る。
    #[test]
    fn sec4_cgroup_mismatch_subject_is_escaped_and_bounded() {
        let err = ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new("/s/fc-a\u{1b}[31m\\b@1")),
        );
        let v = err.violation.expect("violation");
        let s = v.subject.expect("subject");
        assert_eq!(s.as_str(), "/s/fc-a\\u{1b}[31m\\\\b@1");
        assert!(!s.is_truncated());
        let long = format!("/{}", "a".repeat(1000));
        let err = ExecError::from_violation(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new(&long)),
        );
        let s = err.violation.expect("violation").subject.expect("subject");
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(s.is_truncated());
    }

    /// SUP-6: 検証後に終了した対象への参加は、setns の前に FailedPrecondition で拒否される（違反記録なし）。
    #[test]
    fn sup6_join_rejects_exited_target() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let pidfd = sys::pidfd_open(pid).unwrap();
        child.wait().unwrap();
        let target = Pid1Target {
            pid: NonZeroU32::new(pid).unwrap(),
            pidfd,
            expected_cgroup_path: "/fc-x@1".to_owned(),
            user_ns: own_shared(),
        };
        let err = join_namespaces(&target).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            format!("process {pid} has already exited; refusing to setns")
        );
        assert_eq!(err.violation, None);
    }
}
