//! コンテナ起動時の `/dev` 用 tmpfs のマウントと、基本デバイスノード 6 種・default symlink 4 本・`/dev/pts` の devpts・`/dev/ptmx` の作成
//! （CORE-1・CORE-6・SEC-1・SEC-5・TASK-27.6・TASK-29 追補・#834・#1297・#1653・#1656・#1660・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `docker export` 由来の rootfs には `/dev/null` 等が入っておらず、これらが無いとプログラムが
//! 異常終了する（PoC-15 で `iperf3 -s` が SIGSEGV する事象を確認）。OCI Runtime Spec の
//! default devices に相当する 6 種（`null`・`zero`・`full`・`random`・`urandom`・`tty`）を、
//! CDI の deviceNodes（GPU 系・TASK-127）とは独立した常設の責務として作る。
//!
//! 作成先はホスト上の rootfs ディレクトリの `dev` ではなく、本モジュールが `dev` に載せる専用の tmpfs
//! （runc 方式。設計ドラフト `docs/design/dev-default-mounts.md` 3.1・オーナー判断 2026-10-10）である。
//! これによりノードがホスト側の rootfs に残らず、イメージ同梱の `dev` 配下（偽ノード等）は tmpfs に
//! 覆い隠されてコンテナから見えない。覆い隠す効果は `dev` 配下に限る（#1667 の事後監査 P2）: rootfs の残りの
//! 部分にイメージが同梱したデバイスノードは、`prepare_rootfs` が rootful・rootless を問わず自己 bind に付ける `nodev`
//! （#1676。オーナー判断 2026-10-10）で開けない。`nodev` は rootfs の mount top 1 枚だけに掛かり、本モジュールが
//! 後から載せる `/dev` の tmpfs・devpts・rootless の bind（#1660）には及ばない。汎用のデバイス cgroup は #1677 で扱う（SEC-1）。
//! tmpfs の作成は `sys::mount_dev_tmpfs_on`（#1652。mode 0755・64 MiB・`nosuid|strictatime`・`nodev`/`noexec`
//! なし）を使う。
//!
//! あわせて OCI Runtime Spec の default symlink 4 本（`dev/fd` → `/proc/self/fd`、`dev/stdin`・
//! `dev/stdout`・`dev/stderr` → `/proc/self/fd/{0,1,2}`。#1297）も同じマウントのルート fd 起点で作る。これが
//! 無いと `exec` 前検査（`process.rs` の `verify_script_fd_path`）が新 root の `/dev/fd/N` を解決できず、
//! シェバン付きスクリプトを拒否する。参照先は pivot 後のコンテナ内で解決され、作成時にホスト側では辿らない。
//!
//! 続けて、OCI Runtime Spec の Default Filesystems の `/dev/pts`（devpts）を暗黙の固定集合として常に載せ
//! （#1656。設計ドラフト `dev-default-mounts.md` 3.3・オーナー判断 2026-10-10 の判断 2）、`/dev/ptmx` を
//! `pts/ptmx` への相対 symlink にする（runc の `setupPtmx` と同じ。ただし既存エントリの unlink はしない）。
//! devpts は毎回新しい独立 instance で、ホストの pty は見えない。
//!
//! `crate::exec` の最小実行フロー第 3 段。呼び出し元は TASK-29 の `oci_runtime` と fork 段（#831）を
//! 想定し、次の順で通す。
//!
//! ```text
//! prepare_rootfs(&isolation, rootfs) -> PreparedRootfs
//!   -> create_default_devices(&isolation, &prepared) -> DeviceReport   // 本モジュール
//!        （dev に tmpfs → ノード 6 種 → symlink 4 本 → pts に devpts → ptmx の symlink）
//!   -> [/dev/shm は `mount_tmpfs` が集合（既定 64 MiB を含む。#1654）から載せる。`/dev` 配下の宛先には
//!       `DeviceReport` を順序の証跡として渡す（#1669 事後監査 P2）]
//!   -> mount_tmpfs(.., Some(&report), ..) / inject_files
//!   -> pivot_root(&isolation, prepared)
//! ```
//!
//! `prepare_rootfs` の `check_no_submounts` は準備時点の検査であり、本モジュールが載せた tmpfs は
//! `pivot_root` を越えて新 root の `/dev` になる。ノード作成は「準備の後・切替の前」に置く。
//!
//! # 契約
//!
//! - **fd 起点**: [`PreparedRootfs`] の新しい mount top の fd から `dev` を `O_PATH|O_NOFOLLOW|O_DIRECTORY`
//!   で開き（無ければ作る）、その fd へ tmpfs を載せる。以後の作成（`mknodat`・`symlink`）の起点は
//!   **載せたマウントのルート fd** で、パス文字列を連結せず、マウント後に名前で `dev` を開き直した fd を
//!   作成の起点にしない（開き直しは事後検証専用）。`dev` が symlink・非ディレクトリなら
//!   `path_symlink_or_not_directory` の違反記録付きで、何もマウントせず拒否する（rootfs の外へ作らない）
//! - **ホストへ伝播させない・移動検査**: マウント直前に `dev` が shared propagation でないこと、fd 固定後に
//!   改名・移動・削除されていないことを確かめ、違反は `target_on_shared_mount`・`target_moved` の記録付きで
//!   拒否する（`mount_tmpfs` と同じ）
//! - **事後条件**: マウント後に `dev` を開き直し（作成はしない）、tmpfs であること、マウント前の fd とは別の
//!   マウントであること、自分のマウントそのものであることを確かめる（fail-closed。`mount_tmpfs` と同じ判定）
//! - **対応カーネル**: Linux 5.2 以降の新マウント API。未対応（`ENOSYS`）は `mount(2)` へ縮退せず
//!   `Unimplemented`（段 `CreateDevices`）で拒否する
//! - **tmpfs 上の `EEXIST` は検証を残す**: 新しい tmpfs は空で、マウント namespace は呼び出しスレッド専用の
//!   ため通常は起きず、結果はすべて `Created` になる。それでも `EEXIST` が起きた場合（`/proc/<pid>/root`
//!   経由で第三者が書き込んだ等）は、既存エントリが文字デバイス・`rdev`・モード（0666）まで完全一致のとき
//!   だけ [`DeviceNodeStatus::AlreadyPresent`] とし、それ以外は `FailedPrecondition`（段 `CreateDevices`）で
//!   拒否する（拒否へ一律に倒さず、従来の検証を弱めない）
//! - **モード補正**: `mknodat` のモードは umask で削られるため、作成に成功したノードだけを
//!   `O_PATH|O_NOFOLLOW` で開き直し、文字デバイス・`rdev` の一致を検証した fd に対して magic link
//!   経由で 0666 に補正する（作成直後の差し替えで別 inode の権限を変えない）
//! - **default symlink は完全一致のみ受け入れる**: ノード 6 種の作成後に symlink 4 本をマウントのルート fd
//!   の magic link 起点で `symlink(2)` する（最終要素は辿らない）。`EEXIST` は `readlink(2)` の結果が
//!   期待する参照先と 1 バイトも違わず一致するときだけ [`DeviceLinkStatus::AlreadyPresent`] とし、別の
//!   参照先・通常ファイル・ディレクトリは上書きせず `FailedPrecondition`（段 `CreateDevices`）で拒否する
//! - **供給方式は申告で決める（#1660）**: [`DevptsGidSource`] が `Rootful` なら `mknodat(2)`、`Rootless` なら
//!   ホストのノードの bind で基本デバイスを供給する。`mknod` の `EPERM` を見て経路を切り替えない。rootful の
//!   `EPERM` は `PermissionDenied`（段 `CreateDevices`）のまま拒否し、rootless の bind へ縮退しない
//! - **rootless は bind で供給する（#1660。オーナー判断 2026-10-10 の判断 4・方式 (a)。CORE-6・SEC-5）**:
//!   非特権 user namespace では `mknod(2)` が `EPERM` になる。そこで 6 種それぞれについて、(1) `pivot_root` の前に
//!   開いたホストの `/dev` の fd 起点で `<名前>` を `O_PATH|O_NOFOLLOW` で開き、(2) その fd の `fstat` で文字
//!   デバイスと `rdev`（固定表の major/minor）を確かめ（不一致は `host_device_node_unexpected` の違反記録付きで
//!   bind せず拒否する。種別 `mount_target`・層 Mount にホスト側の `/dev/<名前>` を記録）、(3) tmpfs のルート fd
//!   起点でモード 0 の空ファイルを `O_CREAT|O_EXCL|O_NOFOLLOW` で作って（`EEXIST` は受け入れず拒否し、既存の
//!   エントリは消さない）`O_PATH` で固定し、作成時の fd との同一 inode を照合し、(4) 検証した fd を
//!   `open_tree(2)` で複製して `move_mount(2)` で空ファイルの上へ載せ、(5) 載せた後に名前を `O_PATH|O_NOFOLLOW` で
//!   開き直して文字デバイス・`rdev`・自分のマウントであることを再確認する（不一致は違反なしの
//!   `FailedPrecondition`。rootful の作成直後の検証と同じ扱い）。結果は [`DeviceNodeStatus::BoundFromHost`]。
//!   bind 元は固定表の名前だけで、任意のパス・major/minor を受け付ける経路は作らない（CDI の deviceNodes は
//!   TASK-127）。`AT_RECURSIVE` は付けずホスト側の子マウントを持ち込まない。`nosuid`・`noexec`・`nodev` は付与しない
//!   （ルートが文字デバイス 1 個で守る対象が無く、`nodev` はノードを使えなくする。`sys::open_tree_clone` の doc）。
//!   ホストの `/dev` は `unshare(CLONE_NEWNS)` の後・`pivot_root` の前に開く（`open_tree` の `check_mnt` が、
//!   fd のマウントが呼び出しスレッドの mount namespace に属することを要求するため）。`open_tree`・`move_mount` は
//!   seccomp の適用前に呼ぶ（既定の拒否集合に含まれるため）。user namespace が載せた tmpfs 上の `mknod` は仮に
//!   できても `nodev` 相当で開けないと考えられる一方、bind はホストの devtmpfs の superblock を保つため開ける
//!   はずだが、カーネルのソース（`may_open_dev`・`alloc_super`）での確認は本実装では行っておらず、実機での
//!   `/dev/null` への書き込みと `/dev/zero` の読み出しの結合試験（`default_devices`）が裏付ける（未確認）
//! - **新マウント API が無いカーネルは fail-closed（#1660）**: `open_tree`・`move_mount` の `ENOSYS` は `mount(2)` の
//!   `MS_BIND` へ縮退せず `Unimplemented`（段 `CreateDevices`。Linux 5.2 以降が必要）で拒否する
//! - **失敗時の後始末**: どこかで失敗したら、この呼び出しが載せたマウントを fd 経由で `umount2(MNT_DETACH)` で
//!   外し（名前から開き直した先は外さない）、この呼び出しが作った `ptmx`（参照先が一致するときだけ）・`pts`
//!   （同じ inode のときだけ）・`dev` を消す（`unlinkat(AT_REMOVEDIR)` は空ディレクトリしか消えないため既存の
//!   内容は壊さない）。順序は devpts → `ptmx` → `pts` → rootless の bind（作成の逆順に外し、外した後に名前が
//!   作った空ファイルと同じ inode のときだけ空ファイルを消す。#1660）→ `/dev` の tmpfs → `dev`。tmpfs ごと外すので
//!   ノードは残らない。後始末は最善努力で、失敗しても元のエラーを返す。呼び出し後もプロセスは
//!   破棄する（`crate::exec` のモジュール doc の契約）
//! - **`/dev/pts` は `/dev` のマウントのルート fd 起点**: `pts` を 0755 で作り、`O_PATH|O_NOFOLLOW|O_DIRECTORY` で
//!   固定した fd にだけ devpts を載せる（`sys::mount_devpts_on`。`mode=620`・`ptmxmode=666`・`nosuid|noexec` は
//!   固定）。`nodev` は付けない（pty のスレーブと `ptmx` は文字デバイスで、`nodev` では開けない。devpts の中に
//!   置けるのはカーネルが作る pty ノードだけで、利用者が任意のデバイスを作る経路は無い）。`pts` が symlink・
//!   非ディレクトリなら違反記録付きで何もマウントせず拒否する。マウント後は tmpfs と同じ 3 点（devpts であること・
//!   別マウントであること・自分のマウントそのものであること）で事後検証する
//! - **`gid=` の決定**: [`DevptsGidSource`] で呼び出し元が申告する（基本デバイスの供給方式と同じ入力）。rootful は常に 5、rootless は検証済みの gid の
//!   写像でコンテナ内 gid 5 が写像されているときだけ 5、いなければ `gid=` を渡さない（判断 3）。省いたときは
//!   固定語彙の構造化ログを標準エラーへ 1 行出し、[`DevptsOutcome::gid`] も `None` になる。申告がずれても
//!   緩む方向には働かない（rootless で `Rootful` を渡せばカーネルが `EINVAL` で拒否し、rootful で `Rootless` を
//!   渡せば `gid=` が付かないだけ）
//! - **`ptmx` は完全一致のみ受け入れる**: devpts のマウント後に `ptmx` → `pts/ptmx` を default symlink と同じ
//!   fd 起点の magic link 方式で作る。`EEXIST` は参照先が完全一致のときだけ受け入れ、別の参照先・通常ファイル・
//!   デバイスノードは上書きも unlink もせず `FailedPrecondition` で拒否する
//! - **1 プロセス 1 回**: 同じ [`PreparedRootfs`] に 2 回呼ぶと tmpfs が重なる（2 回目は新しい tmpfs 上で
//!   再び `Created` になり、rootfs の外へは書かない）。重ね掛けの検出（拒否）は行わない
//! - **同一スレッド**: `MountIsolation::establish` と同じスレッドで呼ぶ
//!
//! # 未対応（REPAIR-3: 実装済みを装わない）
//!
//! - rootless の bind を実機で通した記録。本モジュールの rootless 経路は dry-run の単体テストで呼び出し列・
//!   拒否・後始末を照合しており、実マウントでの確認（非特権 user namespace・Linux 5.2 以降）は結合試験
//!   `tests/default_devices.rs`（人間担当・`-- --ignored`）が担う
//! - `/dev/console` は端末機能の親 issue で別途設計する（設計ドラフト 3.5）。`process.terminal: true` も
//!   従来どおり拒否のまま
//! - `spawn_container` の最小フローへの本関数の配線（#1314）
//!
//! # 単体テストの安全策
//!
//! `mknodat(2)`・tmpfs のマウント・解除・マウント観測は `cfg(test)` では dry-run に差し替わる
//! （`mknod_syscall`・`mount_dev_tmpfs_syscall`・`mount_devpts_syscall`・`umount_dev_syscall`・
//! `observe_dev_mount`・`observe_pts_mount`）。rootless の bind も同様に、`open_tree`・`move_mount`・bind 後の
//! 再確認（`open_tree_syscall`・`move_mount_syscall`・`observe_bound_node`）が dry-run になり、ホストの `/dev` は
//! 一時ディレクトリへ差し替えられる（`open_host_dev_syscall`）。ホストのノードの検証（`sys::verify_device_node_fd`）と
//! 空ファイルの作成・削除は実ファイルシステムで行う。root で
//! `cargo test` を実行してもホストへ実ノードやマウントを作らない。symlink は特権不要で一時ディレクトリ内
//! にしか作られないため dry-run にせず実ファイルシステムで照合する。実機での挙動は結合試験
//! `tests/default_devices.rs`（`-- --ignored`）で確認する。

use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::dev_mounts::ImplicitDevMount;
use crate::rootless::IdMapSet;
use crate::sys::{self, SysError};
use crate::traits::types::ErrorCode;

use super::tmpfs::{MountObservation, check_new_mount, check_new_tmpfs};
use super::{
    ExecError, IsolationStage, MountIsolation, PreparedRootfs, ViolationReason, fd_still_at,
    mount_is_shared, open_error,
};

const STAGE: IsolationStage = IsolationStage::CreateDevices;

/// 作成する 1 種のデバイスノードの定義。
struct DefaultDevice {
    /// `dev` 直下の名前（`/` を含まない静的な 1 要素）。
    name: &'static CStr,
    major: u32,
    minor: u32,
    mode: u32,
    /// rootless の bind で照合に使う `sys` の固定表の対応する列挙子（`major`/`minor` と一致する。試験で照合）。
    node: sys::HostDeviceNode,
}

/// OCI Runtime Spec の default devices（文字デバイス・モード 0666）。CDI の deviceNodes は
/// 別責務（TASK-127）で、ここへ任意の major/minor を受け付ける経路は作らない。
const DEFAULT_DEVICES: [DefaultDevice; 6] = [
    DefaultDevice {
        name: c"null",
        major: 1,
        minor: 3,
        mode: 0o666,
        node: sys::HostDeviceNode::Null,
    },
    DefaultDevice {
        name: c"zero",
        major: 1,
        minor: 5,
        mode: 0o666,
        node: sys::HostDeviceNode::Zero,
    },
    DefaultDevice {
        name: c"full",
        major: 1,
        minor: 7,
        mode: 0o666,
        node: sys::HostDeviceNode::Full,
    },
    DefaultDevice {
        name: c"random",
        major: 1,
        minor: 8,
        mode: 0o666,
        node: sys::HostDeviceNode::Random,
    },
    DefaultDevice {
        name: c"urandom",
        major: 1,
        minor: 9,
        mode: 0o666,
        node: sys::HostDeviceNode::Urandom,
    },
    DefaultDevice {
        name: c"tty",
        major: 5,
        minor: 0,
        mode: 0o666,
        node: sys::HostDeviceNode::Tty,
    },
];

/// 作成する 1 本の default symlink の定義。
struct DefaultLink {
    /// `dev` 直下の名前（`/` を含まない静的な 1 要素）。
    name: &'static CStr,
    /// 期待する参照先（pivot 後のコンテナ内で解決される絶対パス）。
    target: &'static str,
}

/// OCI Runtime Spec の default symlink。任意の名前・参照先を受け付ける経路は作らない。
const DEFAULT_LINKS: [DefaultLink; 4] = [
    DefaultLink {
        name: c"fd",
        target: "/proc/self/fd",
    },
    DefaultLink {
        name: c"stdin",
        target: "/proc/self/fd/0",
    },
    DefaultLink {
        name: c"stdout",
        target: "/proc/self/fd/1",
    },
    DefaultLink {
        name: c"stderr",
        target: "/proc/self/fd/2",
    },
];

/// `/dev/ptmx` → `pts/ptmx` の symlink（OCI Runtime Spec の Default Filesystems。#1656）。`DEFAULT_LINKS` に
/// 入れないのは、参照先の `pts/ptmx` が devpts のマウント後でないと意味を持たず、作成順が後になるため。
/// 参照先は相対パスで、pivot 後のコンテナ内で解決される（作成時にホスト側では辿らない）。
const PTMX_LINK: DefaultLink = DefaultLink {
    name: c"ptmx",
    target: "pts/ptmx",
};

/// devpts の `gid=` に渡す tty グループ（runc の既定と同じ。設計ドラフト `dev-default-mounts.md` 3.3）。
const DEVPTS_GID: u32 = sys::DevptsGid::TTY_GID;

/// devpts の `gid=` と基本デバイスノードの供給方式を決めるための権限モデルの入力（オーナー判断 2026-10-10 の
/// 判断 3・4。CORE-6・SEC-5）。
///
/// `Rootful` は基本デバイスを `mknodat(2)` で作り、`Rootless` はホストのノードを bind で供給する
/// （`DeviceSupply`。#1660）。`mknod` の `EPERM` を見て経路を切り替える方式にはせず、この申告で明示的に決める。
///
/// 呼び出し元（#1314 で配線する `oci_runtime` / fork 段）が、すでに検証済みの写像を渡す。子（PID 1）側で
/// `/proc/self/gid_map` を独自に解析し直さない。申告が実態とずれた場合も緩む方向には働かない:
/// rootless で `Rootful` を渡すと `gid=5` が写像されずカーネルが `EINVAL` で拒否し（fail-closed）、
/// rootful で `Rootless` を渡すと `gid=` が付かないだけで権限は広がらない。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DevptsGidSource<'a> {
    /// rootful（`isolate_rootful_host_root`）。常に gid 5 を渡す。
    Rootful,
    /// rootless。検証済みの gid の写像（単一 ID 経路は `rootless::single_id_mapping(egid)`、範囲写像の経路は
    /// その gid の集合）。コンテナ内 gid 5 が写像されているときだけ gid 5 を渡し、いなければ `gid=` を渡さない。
    Rootless(&'a IdMapSet),
}

/// devpts の `gid=` の決定（純粋関数）。rootful は `Tty`（5）、rootless は gid 5 が写像されていれば
/// `Tty`、されていなければ `Omitted`（`gid=` のキー自体を渡さない）。結果は [`sys::DevptsGid`] の 2 通りに
/// 限られ、任意の gid を作る経路は無い（#1663 事後監査 P3）。
fn devpts_gid(source: DevptsGidSource<'_>) -> sys::DevptsGid {
    let mapped = match source {
        DevptsGidSource::Rootful => true,
        DevptsGidSource::Rootless(gid_map) => gid_map.host_id_of(DEVPTS_GID).is_some(),
    };
    if mapped {
        sys::DevptsGid::Tty
    } else {
        sys::DevptsGid::Omitted
    }
}

/// `gid=` を省いたときに出す構造化ログの 1 行（固定の語彙と数値だけ。利用者の値・パスは含めない）。
fn devpts_gid_omitted_log_line() -> &'static str {
    r#"{"event":"devpts_gid_omitted","container_gid":5,"reason":"rootless_gid_unmapped"}"#
}

#[cfg(not(test))]
fn emit_devpts_gid_omitted() {
    use std::io::Write as _;
    // 書き込みの失敗でコンテナの起動を止めない（診断用のログのため結果は捨てる）。
    let _ = writeln!(std::io::stderr(), "{}", devpts_gid_omitted_log_line());
}

/// dry-run: 標準エラーへは出さず、出力した事実を記録する。
#[cfg(test)]
fn emit_devpts_gid_omitted() {
    tests::EVENTS.with(|e| e.borrow_mut().push(tests::Event::GidOmittedLog));
}

/// 1 symlink の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceLinkStatus {
    /// 今回作成した。
    Created,
    /// 既に存在し、参照先が期待と完全一致すると検証済みのため何も変更していない。
    AlreadyPresent,
}

/// [`create_default_devices`] が処理した 1 本の symlink の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceLinkOutcome {
    /// `dev` 直下の名前。
    pub name: &'static str,
    /// 期待する参照先。
    pub target: &'static str,
    /// 作成したか、既存だったか。
    pub status: DeviceLinkStatus,
}

/// 1 ノードの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceNodeStatus {
    /// 今回作成した。
    Created,
    /// 既に存在し、文字デバイス・`rdev`・モードが期待どおりと検証済みのため何も変更していない。
    AlreadyPresent,
    /// rootless 経路で、ホストの `/dev/<名前>` を `open_tree(2)` + `move_mount(2)` で bind して供給した
    /// （#1660。CORE-6・SEC-5）。ホストのノードの所有者ではないためモードの補正はせず、
    /// [`DeviceNodeOutcome::mode`] は固定表の期待値で強制していない。
    BoundFromHost,
}

/// [`create_default_devices`] が処理した 1 ノードの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceNodeOutcome {
    /// `dev` 直下の名前。
    pub name: &'static str,
    /// 主デバイス番号。
    pub major: u32,
    /// 副デバイス番号。
    pub minor: u32,
    /// 期待するモード（下位 12 ビット）。
    pub mode: u32,
    /// 作成したか、既存だったか。
    pub status: DeviceNodeStatus,
}

/// `/dev/pts` ディレクトリの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevptsDirStatus {
    /// 今回作成した（新しい tmpfs 上では通常これ）。
    Created,
    /// 既に存在していた（種別はディレクトリと検証済みで、その上に devpts を載せた）。
    AlreadyPresent,
}

/// `/dev/pts`（devpts の独立 instance）と `/dev/ptmx` の結果（#1656。CORE-1・SEC-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DevptsOutcome {
    /// devpts の `gid=` に渡した値。`None` は `gid=` を渡さなかった（rootless で gid 5 が未写像）ことを表す。
    pub gid: Option<u32>,
    /// `/dev/pts` ディレクトリを作成したか、既存だったか。
    pub pts_dir: DevptsDirStatus,
    /// `/dev/ptmx` → `pts/ptmx` の symlink の結果。
    pub ptmx: DeviceLinkOutcome,
}

/// [`create_default_devices`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceReport {
    /// 6 種の結果（定義順: null・zero・full・random・urandom・tty）。
    pub nodes: Vec<DeviceNodeOutcome>,
    /// default symlink 4 本の結果（定義順: fd・stdin・stdout・stderr。#1297）。
    pub links: Vec<DeviceLinkOutcome>,
    /// `/dev/pts` の devpts と `/dev/ptmx` の結果（#1656）。
    pub devpts: DevptsOutcome,
    /// 載せた `/dev` の tmpfs のルートの識別情報。`mount_tmpfs` が `/dev` 配下の宛先（`/dev/shm` 等）を載せる前に、
    /// rootfs の `dev` が今もこのマウントであることを確かめる証跡に使う（#1669 事後監査 P2。SUP-12・CORE-1）。
    /// crate の外からは読めず、`DeviceReport` 自体も `non_exhaustive` のため crate の外では作れない。
    pub(super) dev_mount: DevMountIdentity,
}

/// マウントのルートを指す fd の識別情報（`st_dev`・`st_ino`）。tmpfs は instance ごとに別の `st_dev` を持つため、
/// 同じ値の `dev` は同じ tmpfs のルートを指す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DevMountIdentity {
    pub(super) dev: u64,
    pub(super) ino: u64,
}

impl DevMountIdentity {
    /// `fd` の `fstat` から作る（`O_PATH` fd でも取れる。fd は消費しない）。
    pub(super) fn of(fd: &OwnedFd, stage: IsolationStage) -> Result<Self, ExecError> {
        let dup = fd
            .try_clone()
            .map_err(|e| ExecError::from_io(&e, stage, "dup"))?;
        let meta = std::fs::File::from(dup)
            .metadata()
            .map_err(|e| ExecError::from_io(&e, stage, "fstat(/dev mount)"))?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

/// rootfs の `dev` に専用の tmpfs を載せ、その上へ基本デバイスノード 6 種・default symlink 4 本・
/// `/dev/pts` の devpts（独立 instance）・`/dev/ptmx` の symlink を作る。
///
/// [`prepare_rootfs`](super::prepare_rootfs) の後、[`pivot_root`](super::pivot_root) の前に呼ぶ。
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。
/// `gid_source` は devpts の `gid=` の決定に使う（[`DevptsGidSource`]）。
/// 詳細な契約はモジュール doc を参照。
pub fn create_default_devices(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    gid_source: DevptsGidSource<'_>,
) -> Result<DeviceReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    create_default_devices_at(
        prepared.new_root(),
        &|dir| mount_is_shared(dir, STAGE),
        gid_source,
    )
}

/// この呼び出しが rootfs・mount namespace に加えた変更の記録（失敗時の [`roll_back_dev`] が使う）。
struct DevState {
    /// この呼び出しの `mkdirat` が成功して作った `dev` を指す fd（既存・競合で先に作られた `dev` は `None`）。
    /// 後始末で名前 `dev` が今も同じ inode を指すか（dev・ino）を確かめる識別情報として使う（差し替え対策）。
    created_dev: Option<OwnedFd>,
    /// 載せた「自分のマウントのルート」を指す fd（付け替え直後に保持し、事後検証に通らなくても外せる）。
    mounted: Option<OwnedFd>,
    /// `/dev/pts` と `/dev/ptmx` の変更記録（`mounted` を借りたまま更新できるよう別の構造体に分ける）。
    pts: PtsState,
    /// rootless 経路でこの呼び出しが加えたデバイスノードの bind の記録（作成順。後始末は逆順に外す。#1660）。
    binds: Vec<BoundNode>,
}

/// rootless 経路の 1 ノードの bind でこの呼び出しが加えた変更の記録（失敗時の [`roll_back_dev`] が使う。#1660）。
struct BoundNode {
    device: &'static DefaultDevice,
    /// この呼び出しの `O_EXCL` 作成が成功して得た空ファイルを指す fd（作成直後に保持する）。後始末で名前が今も
    /// 同じ inode を指すか（dev・ino）を確かめる識別情報として使う（差し替え対策）。
    target: Option<OwnedFd>,
    /// `move_mount` が成功した後の、載せたマウントを指す fd。未接続の複製は drop でカーネルが破棄するため、
    /// 成功してから記録する。
    mounted: Option<OwnedFd>,
}

/// 基本デバイスノードの供給方式（[`DevptsGidSource`] の申告から [`device_supply`] が決める。#1660）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceSupply {
    /// `mknodat(2)` で作る（rootful）。
    Mknod,
    /// ホストの `/dev/<名前>` を fd 起点で bind する（rootless。オーナー判断 2026-10-10 の判断 4）。
    BindFromHost,
}

/// 供給方式の決定（純粋関数）。申告が実態とずれても権限は広がらない: rootless なのに `Rootful` なら
/// `mknodat` が `EPERM` で拒否され、rootful なのに `Rootless` なら固定表と `rdev` を検証したホストの
/// 同じ 6 ノードを bind するだけ。
fn device_supply(source: DevptsGidSource<'_>) -> DeviceSupply {
    match source {
        DevptsGidSource::Rootful => DeviceSupply::Mknod,
        DevptsGidSource::Rootless(_) => DeviceSupply::BindFromHost,
    }
}

/// [`mount_pts`] がこの呼び出しで加えた変更の記録（失敗時の [`roll_back_dev`] が使う）。
#[derive(Default)]
struct PtsState {
    /// この呼び出しの `mkdirat` が成功して作った `pts` を指す fd（既存の `pts` は `None`）。後始末で名前 `pts` が
    /// 今も同じ inode かを確かめる識別情報（差し替え対策）。
    created: Option<OwnedFd>,
    /// 載せた devpts のマウントのルートを指す fd（付け替え直後に保持し、事後検証に通らなくても外せる）。
    mounted: Option<OwnedFd>,
    /// この呼び出しが `ptmx` の symlink を作ったか（`EEXIST` の既存を受け入れた場合は偽。消さない）。
    ptmx_created: bool,
}

/// [`create_default_devices`] の証跡検証後の本体。`root` は rootfs（新しい mount top）の fd、`is_shared` は
/// `dev` が shared propagation かの判定（単体テストはホストの mountinfo に依存しないよう差し替える）。
/// 単体テストは証跡を偽造せず一時ディレクトリの fd を直接渡す。失敗時は後始末をしてから元のエラーを返す。
fn create_default_devices_at(
    root: BorrowedFd<'_>,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    gid_source: DevptsGidSource<'_>,
) -> Result<DeviceReport, ExecError> {
    let rootfs = root_display(root);
    let mut state = DevState {
        created_dev: None,
        mounted: None,
        pts: PtsState::default(),
        binds: Vec::new(),
    };
    let gid = devpts_gid(gid_source);
    let supply = device_supply(gid_source);
    let result = populate_dev(root, &rootfs, is_shared, gid, supply, &mut state);
    if result.is_err() {
        roll_back_dev(root, &state);
    }
    result
}

/// `dev` の固定・tmpfs のマウント・事後検証・ノードと symlink の作成。変更は `state` に記録する。
fn populate_dev(
    root: BorrowedFd<'_>,
    rootfs: &Path,
    is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    gid: sys::DevptsGid,
    supply: DeviceSupply,
    state: &mut DevState,
) -> Result<DeviceReport, ExecError> {
    let (opened, created) = open_dev_dir(root, rootfs)?;
    // 作成した `dev` の fd は複製せず所有権ごと `state` へ移す（複製の失敗で記録漏れが起きないように）。
    // 以降の処理はこの fd を借りて使い、どの失敗経路でも後始末が識別情報を参照できる。
    let local;
    let dev: &OwnedFd = if created {
        &*state.created_dev.insert(opened)
    } else {
        local = opened;
        &local
    };
    // shared propagation でないこと・移動していないことを確かめた fd だけが付け替え先の型になる。
    let target = target::DevMountTarget::check(dev, &rootfs.join("dev"), is_shared)?;
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    let mount_fd =
        mount_dev_tmpfs_syscall(target, sys::DevTmpfsCreate::new()).map_err(dev_mount_error)?;
    let mount_fd = &*state.mounted.insert(mount_fd);
    // 事後検証専用の開き直し（作成の起点にはしない）。
    let after = sys::open_dir_path_nofollow(Some(root), c"dev")
        .map_err(|e| open_error(e, true, rootfs, &[OsStr::new("dev")]).at_stage(STAGE))?;
    let observed = observe_dev_mount(dev, &after, mount_fd)?;
    check_new_tmpfs(observed, ImplicitDevMount::Dev.destination(), STAGE)?;
    let dev_mount = DevMountIdentity::of(mount_fd, STAGE)?;

    let mount = mount_fd.as_fd();
    let mut nodes = Vec::with_capacity(DEFAULT_DEVICES.len());
    match supply {
        DeviceSupply::Mknod => {
            for d in &DEFAULT_DEVICES {
                let status = match mknod_syscall(mount, d) {
                    Ok(()) => {
                        finalize_node(mount, d)?;
                        DeviceNodeStatus::Created
                    }
                    Err(SysError::Os(sys::EEXIST)) => {
                        verify_existing_node(mount, d)?;
                        DeviceNodeStatus::AlreadyPresent
                    }
                    Err(e) => {
                        return Err(ExecError::from_sys(
                            e,
                            STAGE,
                            &format!("mknodat({})", d.name.to_string_lossy()),
                        ));
                    }
                };
                nodes.push(node_outcome(d, status));
            }
        }
        DeviceSupply::BindFromHost => {
            bind_host_devices(mount, &mut state.binds)?;
            for d in &DEFAULT_DEVICES {
                nodes.push(node_outcome(d, DeviceNodeStatus::BoundFromHost));
            }
        }
    }
    let mut links = Vec::with_capacity(DEFAULT_LINKS.len());
    for l in &DEFAULT_LINKS {
        let status = create_link(mount, l)?;
        links.push(DeviceLinkOutcome {
            name: l.name.to_str().unwrap_or("?"),
            target: l.target,
            status,
        });
    }
    let devpts = mount_pts(mount, rootfs, gid, &mut state.pts)?;
    Ok(DeviceReport {
        nodes,
        links,
        devpts,
        dev_mount,
    })
}

/// 1 ノードの結果の組み立て。
fn node_outcome(d: &DefaultDevice, status: DeviceNodeStatus) -> DeviceNodeOutcome {
    DeviceNodeOutcome {
        name: d.name.to_str().unwrap_or("?"),
        major: d.major,
        minor: d.minor,
        mode: d.mode,
        status,
    }
}

/// bind 元（ホストの `/dev/<名前>`）の表示パス。違反記録の対象に使う（固定表の名前だけ）。
fn host_node_path(d: &DefaultDevice) -> PathBuf {
    Path::new("/dev").join(d.name.to_string_lossy().as_ref())
}

/// rootless 経路: ホストの基本デバイス 6 種を、`/dev` の tmpfs 上の空ファイルへ fd 起点で bind する
/// （方式 (a)。`docs/design/dev-default-mounts.md` 3.6・オーナー判断 2026-10-10 の判断 4。CORE-6・SEC-5・#1660）。
///
/// ホストの `/dev` は `MountIsolation::establish` の `unshare(CLONE_NEWNS)` の後・`pivot_root` の前に開く
/// （`open_tree` の `check_mnt` が、fd のマウントが呼び出しスレッドの mount namespace に属することを要求するため。
/// `sys::open_tree_clone` の doc）。bind 元は固定表の名前だけで、任意のパス・major/minor を受け付ける経路は
/// 作らない（CDI の deviceNodes は TASK-127 の別経路）。`open_tree`・`move_mount` は seccomp の適用前に呼ぶ。
fn bind_host_devices(mount: BorrowedFd<'_>, binds: &mut Vec<BoundNode>) -> Result<(), ExecError> {
    let host_dev =
        open_host_dev_syscall().map_err(|e| ExecError::from_sys(e, STAGE, "open(host /dev)"))?;
    for d in &DEFAULT_DEVICES {
        bind_one(host_dev.as_fd(), mount, d, binds)?;
    }
    Ok(())
}

/// 1 ノードの bind: ホストのノードを開いて検証 → 空ファイルを作って固定 → 複製 → 接続 → 再確認。
/// 変更は作成の直後から `binds` に記録し、どこで失敗しても [`roll_back_dev`] が外せる。
fn bind_one(
    host_dev: BorrowedFd<'_>,
    mount: BorrowedFd<'_>,
    d: &'static DefaultDevice,
    binds: &mut Vec<BoundNode>,
) -> Result<(), ExecError> {
    let name = d.name.to_string_lossy();
    // 検証した fd そのものを複製する（開き直さない）。不一致は bind せずに拒否する。
    let host_fd = open_host_node_syscall(host_dev, d)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat(host /dev/{name})")))?;
    let verified = verify_host_node(host_fd, d).map_err(|e| host_node_error(e, d))?;

    // 空ファイルを `O_EXCL` で作り、作成の fd を識別情報として直ちに記録する。
    let created = match create_bind_target(mount, d) {
        Ok(fd) => fd,
        Err(SysError::Os(sys::EEXIST)) => {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                format!("the bind target dev/{name} already exists"),
            ));
        }
        Err(e) => {
            return Err(ExecError::from_sys(
                e,
                STAGE,
                &format!("openat(create dev/{name})"),
            ));
        }
    };
    binds.push(BoundNode {
        device: d,
        target: Some(created),
        mounted: None,
    });
    let target = sys::open_path_nofollow(mount, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat(bind target dev/{name})")))?;
    // 作成と開き直しの間の差し替えを同一 inode の照合で塞ぐ。
    let same = binds
        .last()
        .and_then(|b| b.target.as_ref())
        .and_then(fd_identity)
        .is_some_and(|id| fd_identity(&target) == Some(id));
    if !same {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the bind target dev/{name} was replaced right after creation"),
        ));
    }

    // 複製して空ファイルの上へ載せる。接続に成功してから fd を記録する。
    let tree =
        open_tree_syscall(&verified, d).map_err(|e| bind_api_error(e, "open_tree", &name))?;
    move_mount_syscall(tree.as_fd(), target.as_fd(), d)
        .map_err(|e| bind_api_error(e, "move_mount", &name))?;
    let Some(record) = binds.last_mut() else {
        return Ok(());
    };
    let own = &*record.mounted.insert(tree);

    // 載せた後に名前を開き直し、文字デバイス・`rdev`・自分のマウントであることを再確認する。
    let observed = observe_bound_node(mount, d, own)?;
    check_bound_node(observed, d)
}

/// ホストのノードの種別と `rdev` の照合は `sys::verify_device_node_fd`（fd の `fstat`）で行う。
#[cfg(not(test))]
fn verify_host_node(
    fd: OwnedFd,
    d: &DefaultDevice,
) -> Result<sys::VerifiedDeviceNodeFd, sys::DeviceNodeError> {
    sys::verify_device_node_fd(fd, d.node)
}

/// dry-run: 照合の事実を記録し、`VERIFY_SCRIPT` に積んだ拒否を先頭から返せる（非特権では `null` の位置に
/// 別 `rdev` のデバイスを置けないため）。積んでいなければ実際の照合を行う。
#[cfg(test)]
fn verify_host_node(
    fd: OwnedFd,
    d: &DefaultDevice,
) -> Result<sys::VerifiedDeviceNodeFd, sys::DeviceNodeError> {
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::VerifyHostNode {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    let scripted = tests::VERIFY_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() {
            None
        } else {
            Some(s.remove(0))
        }
    });
    if let Some(e) = scripted {
        return Err(e);
    }
    sys::verify_device_node_fd(fd, d.node)
}

/// ホスト側ノードの検証失敗をエラーにする。文字デバイスでない・`rdev` 違いは bind 元の不正として違反記録つきで
/// 拒否し（種別 `mount_target`。層 Mount にホスト側のパスを記録）、その他は `fstat` の失敗として写す。
fn host_node_error(e: sys::DeviceNodeError, d: &DefaultDevice) -> ExecError {
    match e {
        sys::DeviceNodeError::NotCharDevice { .. }
        | sys::DeviceNodeError::UnexpectedRdev { .. } => ExecError::from_violation_at(
            ViolationReason::HostDeviceNodeUnexpected,
            Some(&host_node_path(d)),
            STAGE,
        ),
        sys::DeviceNodeError::Sys(SysError::Unsupported) => ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "the rootless device bind is not supported on this platform",
        ),
        sys::DeviceNodeError::Sys(e) => ExecError::from_sys(
            e,
            STAGE,
            &format!("fstat(host /dev/{})", d.name.to_string_lossy()),
        ),
    }
}

/// `open_tree`・`move_mount` の失敗をエラーにする。`Unsupported`（`ENOSYS`）は `mount(2)` の `MS_BIND` へ
/// 縮退せず `Unimplemented`（Linux 5.2 以降が必要）で拒否する。
fn bind_api_error(e: SysError, op: &str, name: &str) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "the rootless device bind requires the new mount API (open_tree, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(e, STAGE, &format!("{op}(dev/{name})"))
}

/// bind 後に名前を開き直して観測した値（[`check_bound_node`] の入力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundObservation {
    /// 開き直した fd が文字デバイスか。
    is_char: bool,
    /// 開き直した fd の `rdev`。
    rdev: u64,
    /// 自分のマウント（`open_tree` の fd）のマウント ID。
    own_mnt_id: u64,
    /// 開き直した fd が属するマウントの ID。
    after_mnt_id: u64,
}

/// bind 後の再確認（純粋関数）。文字デバイス・`rdev` 一致・自分のマウントのときだけ通る。違反記録なしの
/// `FailedPrecondition` で拒否する（rootful の [`check_created_node`] と同じ扱い。名前の差し替えの兆候）。
fn check_bound_node(o: BoundObservation, d: &DefaultDevice) -> Result<(), ExecError> {
    let name = d.name.to_string_lossy();
    if !o.is_char || o.rdev != sys::makedev(d.major, d.minor) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!(
                "the bound device node {name} does not match {}:{} after bind",
                d.major, d.minor
            ),
        ));
    }
    if o.after_mnt_id != o.own_mnt_id {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            format!("the bound device node {name} is not the mount created by this call"),
        ));
    }
    Ok(())
}

/// `fd` の識別情報（`st_dev`・`st_ino`）。取得できなければ `None`。
fn fd_identity(fd: &OwnedFd) -> Option<(u64, u64)> {
    let meta = std::fs::File::from(fd.try_clone().ok()?).metadata().ok()?;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(test))]
fn observe_bound_node(
    mount: BorrowedFd<'_>,
    d: &DefaultDevice,
    own: &OwnedFd,
) -> Result<BoundObservation, ExecError> {
    let name = d.name.to_string_lossy();
    let after = sys::open_path_nofollow(mount, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, &format!("openat(bound dev/{name})")))?;
    let meta = std::fs::File::from(
        after
            .try_clone()
            .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?,
    )
    .metadata()
    .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(bound device node)"))?;
    Ok(BoundObservation {
        is_char: meta.file_type().is_char_device(),
        rdev: meta.rdev(),
        own_mnt_id: super::fd_mount_id(own, STAGE)?,
        after_mnt_id: super::fd_mount_id(&after, STAGE)?,
    })
}

/// dry-run: 実際の開き直しは省き（何も載っていないため）、再確認の事実を記録する。既定は「文字デバイスで
/// `rdev` 一致・自分のマウント」を観測したことにし、`OBSERVE_BOUND_SCRIPT` で異常値を差し込める。
#[cfg(test)]
fn observe_bound_node(
    _mount: BorrowedFd<'_>,
    d: &DefaultDevice,
    _own: &OwnedFd,
) -> Result<BoundObservation, ExecError> {
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::RecheckBound {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    let scripted = tests::OBSERVE_BOUND_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() {
            None
        } else {
            Some(s.remove(0))
        }
    });
    Ok(scripted.unwrap_or(BoundObservation {
        is_char: true,
        rdev: sys::makedev(d.major, d.minor),
        own_mnt_id: 2,
        after_mnt_id: 2,
    }))
}

#[cfg(not(test))]
fn open_host_dev_syscall() -> Result<OwnedFd, SysError> {
    sys::open_dir_path_nofollow(None, c"/dev")
}

/// dry-run: `HOST_DEV_SCRIPT` に積んだ一時ディレクトリを「ホストの `/dev`」として開く（無ければ実 `/dev` を
/// `O_PATH` で開くだけで副作用はない）。
#[cfg(test)]
fn open_host_dev_syscall() -> Result<OwnedFd, SysError> {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = tests::HOST_DEV_SCRIPT.with(|s| s.borrow().clone());
    match dir {
        Some(p) => {
            let c =
                CString::new(p.as_os_str().as_bytes()).map_err(|_| SysError::Os(sys::EINVAL))?;
            sys::open_dir_path_nofollow(None, &c)
        }
        None => sys::open_dir_path_nofollow(None, c"/dev"),
    }
}

/// ホストの `/dev` 直下の名前を `O_PATH|O_NOFOLLOW` で開く（種別は問わない。検証は [`verify_host_node`]）。
fn open_host_node_syscall(
    host_dev: BorrowedFd<'_>,
    d: &DefaultDevice,
) -> Result<OwnedFd, SysError> {
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::OpenHostNode {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    sys::open_path_nofollow(host_dev, d.name)
}

/// bind 先の空ファイルをモード 0・`O_EXCL|O_NOFOLLOW` で作る。`cfg(test)` でも実ファイルシステム
/// （一時ディレクトリ）に作り、順序の照合のため作成の事実を記録する。
fn create_bind_target(mount: BorrowedFd<'_>, d: &DefaultDevice) -> Result<OwnedFd, SysError> {
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::CreateBindTarget {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    sys::create_file_excl_at(mount, d.name, 0)
}

#[cfg(not(test))]
fn open_tree_syscall(
    node: &sys::VerifiedDeviceNodeFd,
    _d: &DefaultDevice,
) -> Result<OwnedFd, SysError> {
    sys::open_tree_clone(node)
}

/// dry-run: 新マウント API を呼ばず、複製の代わりに検証済みの fd の複製を返す。`OPEN_TREE_SCRIPT` に積んだ失敗を
/// 先頭から返せる。
#[cfg(test)]
fn open_tree_syscall(
    node: &sys::VerifiedDeviceNodeFd,
    d: &DefaultDevice,
) -> Result<OwnedFd, SysError> {
    let scripted = tests::OPEN_TREE_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() {
            None
        } else {
            Some(s.remove(0))
        }
    });
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::OpenTree {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    if let Some(Err(e)) = scripted {
        return Err(e);
    }
    std::os::fd::AsFd::as_fd(node)
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))
}

#[cfg(not(test))]
fn move_mount_syscall(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    _d: &DefaultDevice,
) -> Result<(), SysError> {
    sys::move_mount_empty_path(from, to)
}

/// dry-run: 新マウント API を呼ばず記録する。`MOVE_MOUNT_SCRIPT` に積んだ失敗を先頭から返せる。
#[cfg(test)]
fn move_mount_syscall(
    _from: BorrowedFd<'_>,
    _to: BorrowedFd<'_>,
    d: &DefaultDevice,
) -> Result<(), SysError> {
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::MoveMount {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    let scripted = tests::MOVE_MOUNT_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() {
            None
        } else {
            Some(s.remove(0))
        }
    });
    scripted.unwrap_or(Ok(()))
}

/// `/dev` 用の nodev なし tmpfs の付け替え先（#1664 事後監査 P2。SEC-1・CORE-1）。
///
/// `sys::mount_dev_tmpfs_on` は付け替え先を任意の `BorrowedFd` で受けるため、型で固定しているのは作成
/// パラメータ（[`sys::DevTmpfsCreate`]）だけで、crate 内の別の箇所から利用者の `--tmpfs` の行き先などへ
/// nodev なしの tmpfs を載せる誤配線を防げない。そこで本モジュールの呼び出しを、検証を通った `dev` の fd
/// を表す [`target::DevMountTarget`] でしか渡せないようにする。フィールドは子モジュールに閉じているため、
/// 本モジュールの他の箇所からもリテラルでは作れず、[`target::DevMountTarget::check`] を通すしかない。
/// `sys::mount_dev_tmpfs_on` の呼び出しが本モジュールの 1 か所だけであることは、単体テスト
/// `sec1_core1_dev_tmpfs_mount_has_single_call_site` がソースを走査して機械的に確かめる。
mod target {
    use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
    use std::path::Path;

    use super::{ExecError, STAGE, ViolationReason, fd_still_at};

    /// 検証済みの rootfs 直下の `dev` を指す `O_PATH` fd の借用。
    pub(super) struct DevMountTarget<'a> {
        fd: BorrowedFd<'a>,
    }

    impl<'a> DevMountTarget<'a> {
        /// `dev`（`open_dev_dir` が rootfs の root fd 起点に `O_PATH|O_NOFOLLOW|O_DIRECTORY` で固定した fd）が
        /// shared propagation でなく、固定後に改名・移動・削除されていないことを確かめて包む。違反は
        /// `target_on_shared_mount`・`target_moved` の記録付きで拒否する（`mount_tmpfs` と同じ判定）。
        pub(super) fn check(
            dev: &'a OwnedFd,
            subject: &Path,
            is_shared: &dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
        ) -> Result<Self, ExecError> {
            if is_shared(dev)? {
                return Err(ExecError::from_violation_at(
                    ViolationReason::TargetOnSharedMount,
                    Some(subject),
                    STAGE,
                ));
            }
            // fd 固定後に別プロセスが `dev`（または祖先）を改名・移動・削除していれば拒否する。
            if !fd_still_at(dev, subject) {
                return Err(ExecError::from_violation_at(
                    ViolationReason::TargetMoved,
                    Some(subject),
                    STAGE,
                ));
            }
            Ok(Self { fd: dev.as_fd() })
        }

        /// 付け替え先の fd。
        pub(super) fn fd(&self) -> BorrowedFd<'a> {
            self.fd
        }
    }
}

/// `/dev` の tmpfs のルート fd 起点で `pts` を作り、独立した devpts を載せ、事後検証してから
/// `ptmx` → `pts/ptmx` の symlink を作る（#1656。CORE-1・SEC-1）。変更は `state` に記録する。
///
/// `pts` は `O_PATH|O_NOFOLLOW|O_DIRECTORY` で固定した fd にだけ載せ、パス文字列を連結して mount API へ渡さない。
/// 名前から開き直した fd は事後検証専用。devpts は毎回新しい instance なのでホストの pty は見えない。
fn mount_pts(
    mount: BorrowedFd<'_>,
    rootfs: &Path,
    gid: sys::DevptsGid,
    state: &mut PtsState,
) -> Result<DevptsOutcome, ExecError> {
    let names = [OsStr::new("dev"), OsStr::new("pts")];
    let created = match mkdir_pts(mount) {
        Ok(()) => true,
        // 新しい tmpfs 上では通常起きない。先に作られていても自分が作った扱いにせず、開き直しで種別を検証する。
        Err(SysError::Os(sys::EEXIST)) => false,
        Err(e) => return Err(ExecError::from_sys(e, STAGE, "mkdirat(dev/pts)")),
    };
    let opened = match sys::open_dir_path_nofollow(Some(mount), c"pts") {
        Ok(fd) => fd,
        Err(e) => {
            // 開き直し失敗は識別用の fd が得られないため後始末に渡せない。ここで空ディレクトリだけを消す。
            if created {
                let _ = sys::remove_dir_at(mount, c"pts");
            }
            return Err(open_error(e, true, rootfs, &names).at_stage(STAGE));
        }
    };
    let local;
    let pts: &OwnedFd = if created {
        &*state.created.insert(opened)
    } else {
        local = opened;
        &local
    };
    let pts_mount =
        mount_devpts_syscall(pts.as_fd(), sys::DevptsCreate { gid }).map_err(devpts_mount_error)?;
    let pts_mount = &*state.mounted.insert(pts_mount);
    // 事後検証専用の開き直し（作成の起点にはしない）。
    let after = sys::open_dir_path_nofollow(Some(mount), c"pts")
        .map_err(|e| open_error(e, true, rootfs, &names).at_stage(STAGE))?;
    let observed = observe_pts_mount(pts, &after, pts_mount)?;
    check_new_mount(
        observed,
        sys::DEVPTS_MAGIC,
        ImplicitDevMount::DevPts.fs_type(),
        ImplicitDevMount::DevPts.destination(),
        STAGE,
    )?;

    let ptmx_status = create_link(mount, &PTMX_LINK)?;
    if ptmx_status == DeviceLinkStatus::Created {
        state.ptmx_created = true;
    }
    if gid == sys::DevptsGid::Omitted {
        emit_devpts_gid_omitted();
    }
    Ok(DevptsOutcome {
        gid: gid.value(),
        pts_dir: if created {
            DevptsDirStatus::Created
        } else {
            DevptsDirStatus::AlreadyPresent
        },
        ptmx: DeviceLinkOutcome {
            name: "ptmx",
            target: PTMX_LINK.target,
            status: ptmx_status,
        },
    })
}

/// `pts` ディレクトリを 0755 で作る。`cfg(test)` でも実ファイルシステム（一時ディレクトリ）に作り、
/// 順序の照合のため作成の事実を記録する。
fn mkdir_pts(mount: BorrowedFd<'_>) -> Result<(), SysError> {
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::Mkdir {
            dirfd: mount.as_raw_fd(),
            name: "pts".to_owned(),
        })
    });
    sys::mkdir_at(mount, c"pts", 0o755)
}

/// devpts の新マウント API の失敗をエラーにする。`Unsupported` は `mount(2)` へ縮退せず `Unimplemented`。
fn devpts_mount_error(e: SysError) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "the /dev/pts devpts mount requires the new mount API (fsopen, fsconfig, fsmount, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(e, STAGE, "mount(devpts on /dev/pts)")
}

/// 新マウント API の失敗をエラーにする。`Unsupported`（`ENOSYS`・対応外アーキテクチャ）は縮退せず
/// `Unimplemented` で拒否する（Linux 5.2 以降が必要）。
fn dev_mount_error(e: SysError) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        return ExecError::new(
            ErrorCode::Unimplemented,
            STAGE,
            "the /dev tmpfs mount requires the new mount API (fsopen, fsconfig, fsmount, move_mount; Linux 5.2 or later)",
        );
    }
    ExecError::from_sys(e, STAGE, "mount(tmpfs on /dev)")
}

/// 失敗時の後始末（最善努力）。新しく作ったものから順に、devpts のマウント → `ptmx` → `pts` → `/dev` の
/// tmpfs → `dev` を片付ける。
///
/// 外すのは付け替え時に得た自分のマウントの fd が指すマウントだけで、名前から開き直した先は外さない。
/// `unlinkat(AT_REMOVEDIR)` は空ディレクトリしか消さないため既存の内容は壊さない。`ptmx` は自分が作り、かつ
/// 参照先が今も `pts/ptmx` のときだけ消す（差し替えられていれば残す）。`pts` と `dev` は名前が作成時と同じ
/// inode を指すときだけ消す。
fn roll_back_dev(root: BorrowedFd<'_>, state: &DevState) {
    if let Some(pts_mount) = &state.pts.mounted
        && let Ok(target) = CString::new(format!("/proc/thread-self/fd/{}", pts_mount.as_raw_fd()))
    {
        let _ = umount_dev_syscall(&target);
    }
    if let Some(mount) = &state.mounted {
        if state.pts.ptmx_created {
            let path = fd_magic_path(mount.as_raw_fd()).join("ptmx");
            let is_ours = std::fs::read_link(&path)
                .is_ok_and(|t| t.as_os_str() == OsStr::new(PTMX_LINK.target));
            if is_ours {
                // `remove_file` は最後の要素を辿らず symlink 自身を消す。
                let _ = std::fs::remove_file(&path);
            }
        }
        if let Some(created) = &state.pts.created
            && name_is_same_inode(mount.as_fd(), c"pts", created, |d, n| {
                sys::open_dir_path_nofollow(Some(d), n)
            })
        {
            let _ = sys::remove_dir_at(mount.as_fd(), c"pts");
        }
        // rootless の bind は作成の逆順に外し、外した後に名前が自分の作った空ファイルのままのときだけ消す
        // （外せなかった場合、名前はデバイスを指すため同一 inode にならず消さない）。
        for b in state.binds.iter().rev() {
            if let Some(m) = &b.mounted
                && let Ok(target) = CString::new(format!("/proc/thread-self/fd/{}", m.as_raw_fd()))
            {
                let _ = umount_dev_syscall(&target);
            }
            if let Some(created) = &b.target
                && name_is_same_inode(mount.as_fd(), b.device.name, created, |d, n| {
                    sys::open_path_nofollow(d, n)
                })
            {
                remove_bind_target(mount, b.device);
            }
        }
        if let Ok(target) = CString::new(format!("/proc/thread-self/fd/{}", mount.as_raw_fd())) {
            let _ = umount_dev_syscall(&target);
        }
    }
    // 名前 `dev` が作成時と同じ inode を指すと確認できたときだけ消す。差し替え・移動・確認不能は残す
    // （fail-closed。別プロセスが置いた別ディレクトリを消さない）。
    if let Some(created) = &state.created_dev
        && name_is_same_inode(root, c"dev", created, |d, n| {
            sys::open_dir_path_nofollow(Some(d), n)
        })
    {
        let _ = sys::remove_dir_at(root, c"dev");
    }
}

/// `dir` 直下の名前 `name` を `open` で固定し、`created` と同じ inode（st_dev・st_ino）を指すか。
/// 開けない・取得できない場合は偽。`open` は種別に応じた開き方（ディレクトリは `O_DIRECTORY` 付き、空ファイルは
/// 付けない）を呼び出し側が選ぶ。
fn name_is_same_inode(
    dir: BorrowedFd<'_>,
    name: &CStr,
    created: &OwnedFd,
    open: impl Fn(BorrowedFd<'_>, &CStr) -> Result<OwnedFd, SysError>,
) -> bool {
    let Ok(now) = open(dir, name) else {
        return false;
    };
    matches!((fd_identity(created), fd_identity(&now)), (Some(a), Some(b)) if a == b)
}

/// 後始末で、この呼び出しが作った空ファイルを消す（同一 inode と確認済みの名前だけ。`remove_file` は
/// 最後の要素を辿らない）。`cfg(test)` では順序の照合のため削除の事実を記録する。
fn remove_bind_target(mount: &OwnedFd, d: &DefaultDevice) {
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::RemoveBindTarget {
            name: d.name.to_string_lossy().into_owned(),
        })
    });
    let path = fd_magic_path(mount.as_raw_fd()).join(d.name.to_string_lossy().as_ref());
    let _ = std::fs::remove_file(path);
}

/// マウントのルート fd の magic link を起点に symlink 1 本を作る。`symlink(2)` は最終要素を辿らないため、
/// 既存の悪性 symlink 経由で rootfs の外へ作らない。`EEXIST` は参照先を検証する。
fn create_link(dev: BorrowedFd<'_>, l: &DefaultLink) -> Result<DeviceLinkStatus, ExecError> {
    let name = l.name.to_string_lossy();
    let path = fd_magic_path(dev.as_raw_fd()).join(&*name);
    #[cfg(test)]
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::Symlink {
            dirfd: dev.as_raw_fd(),
            name: name.to_string(),
            target: l.target.to_owned(),
        })
    });
    match std::os::unix::fs::symlink(l.target, &path) {
        Ok(()) => Ok(DeviceLinkStatus::Created),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = match std::fs::read_link(&path) {
                Ok(t) => Some(t),
                // symlink でない（EINVAL）。
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => None,
                Err(e) => {
                    return Err(ExecError::from_io(
                        &e,
                        STAGE,
                        &format!("readlink(dev/{name})"),
                    ));
                }
            };
            check_existing_link(existing.as_deref(), l)?;
            Ok(DeviceLinkStatus::AlreadyPresent)
        }
        Err(e) => Err(ExecError::from_io(
            &e,
            STAGE,
            &format!("symlinkat(dev/{name})"),
        )),
    }
}

/// 既存 symlink の検証本体（純粋関数）。`existing` は `readlink` の結果（symlink でなければ `None`）。
/// 参照先が期待とバイト列で完全一致のときだけ通る（正規化しない）。
fn check_existing_link(existing: Option<&Path>, l: &DefaultLink) -> Result<(), ExecError> {
    if existing.is_some_and(|t| t.as_os_str() == OsStr::new(l.target)) {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the existing entry dev/{} is not a symlink to {}",
            l.name.to_string_lossy(),
            l.target
        ),
    ))
}

/// 違反記録の対象表示用に rootfs の実パスを得る（取れなければ固定文字列）。
fn root_display(root: BorrowedFd<'_>) -> PathBuf {
    std::fs::read_link(fd_magic_path(root.as_raw_fd()))
        .unwrap_or_else(|_| PathBuf::from("<rootfs>"))
}

fn fd_magic_path(fd: i32) -> PathBuf {
    PathBuf::from(format!("/proc/thread-self/fd/{fd}"))
}

/// `root` 直下の `dev` を `O_PATH|O_NOFOLLOW|O_DIRECTORY` で開く。無ければ rootfs 配下に作って開き直し、
/// 自分で作ったときだけ戻り値の第 2 要素を真にする。symlink・非ディレクトリは違反記録付きで拒否する
/// （rootfs の外へ作らない）。
fn open_dev_dir(root: BorrowedFd<'_>, rootfs: &Path) -> Result<(OwnedFd, bool), ExecError> {
    let names = [OsStr::new("dev")];
    let open = || sys::open_dir_path_nofollow(Some(root), c"dev");
    match open() {
        Ok(fd) => Ok((fd, false)),
        Err(SysError::Os(sys::ENOENT)) => {
            // `mkdirat` は最終要素の symlink を辿らない。競合で先に作られた（EEXIST）場合は自分が作った
            // 扱いにせず、開き直しで種別を検証する。
            let created = match sys::mkdir_at(root, c"dev", 0o755) {
                Ok(()) => true,
                Err(SysError::Os(sys::EEXIST)) => false,
                Err(e) => return Err(ExecError::from_sys(e, STAGE, "mkdirat(dev)")),
            };
            match open() {
                Ok(fd) => Ok((fd, created)),
                Err(e) => {
                    // 作成直後の開き直し失敗は識別用の fd が得られないため、呼び出し元の後始末に
                    // 渡せない。ここで空ディレクトリだけを消す（`AT_REMOVEDIR` は空でない dev・symlink を
                    // 消さない）。ホスト側 rootfs に作成物を残さない。
                    if created {
                        let _ = sys::remove_dir_at(root, c"dev");
                    }
                    Err(open_error(e, true, rootfs, &names).at_stage(STAGE))
                }
            }
        }
        Err(e) => Err(open_error(e, true, rootfs, &names).at_stage(STAGE)),
    }
}

/// 作成に成功したノードを検証し、モードを補正する。`cfg(test)` の dry-run ではノードが実在しない
/// ため呼び出しを省く（検証ロジックは [`check_created_node`] を単体で試験する）。
fn finalize_node(dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), ExecError> {
    if cfg!(test) {
        return Ok(());
    }
    let fd = sys::open_path_nofollow(dev, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(device node)"))?;
    let dup = fd
        .try_clone()
        .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?;
    let meta = std::fs::File::from(dup)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(device node)"))?;
    check_created_node(meta.file_type().is_char_device(), meta.rdev(), d)?;
    // 検証した inode を指す fd の magic link 経由で chmod する（名前は再解決しない）。
    std::fs::set_permissions(
        fd_magic_path(fd.as_raw_fd()),
        std::fs::Permissions::from_mode(d.mode),
    )
    .map_err(|e| ExecError::from_io(&e, STAGE, "chmod(device node)"))
}

/// `EEXIST` で見つかった既存エントリを fd 起点で検証する。種別・`rdev`・モードが期待と一致しなければ
/// 拒否する（変更はしない）。symlink は `O_NOFOLLOW|O_PATH` で開いた fd が symlink 自身を指すため
/// 文字デバイスでないとして拒否される。
fn verify_existing_node(dev: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), ExecError> {
    let fd = sys::open_path_nofollow(dev, d.name)
        .map_err(|e| ExecError::from_sys(e, STAGE, "openat(existing device node)"))?;
    let meta = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| ExecError::from_io(&e, STAGE, "dup"))?,
    )
    .metadata()
    .map_err(|e| ExecError::from_io(&e, STAGE, "fstat(existing device node)"))?;
    check_existing_node(
        meta.file_type().is_char_device(),
        meta.rdev(),
        meta.mode() & 0o7777,
        d,
    )
}

/// 既存ノードの検証本体（純粋関数）。文字デバイスかつ `rdev`・モードが期待と完全一致のときだけ通る。
fn check_existing_node(
    is_char: bool,
    rdev: u64,
    mode: u32,
    d: &DefaultDevice,
) -> Result<(), ExecError> {
    if is_char && rdev == sys::makedev(d.major, d.minor) && mode == d.mode {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the existing entry dev/{} is not the expected character device {}:{} with mode {:o}",
            d.name.to_string_lossy(),
            d.major,
            d.minor,
            d.mode
        ),
    ))
}

/// 作成直後のノードが自分の作った文字デバイス（期待する `rdev`）であることの検証。一致しなければ
/// 作成直後に名前が差し替えられたとみなして拒否する（別 inode のモードを変えない）。
fn check_created_node(is_char: bool, rdev: u64, d: &DefaultDevice) -> Result<(), ExecError> {
    if is_char && rdev == sys::makedev(d.major, d.minor) {
        return Ok(());
    }
    Err(ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "the device node {} was replaced right after creation",
            d.name.to_string_lossy()
        ),
    ))
}

#[cfg(not(test))]
fn mknod_syscall(dir: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    sys::make_char_device(dir, d.name, d.mode, d.major, d.minor)
}

/// dry-run: 呼び出しを記録し、`MKNOD_SCRIPT` に積んだ結果を先頭から返す（空なら `Ok`）。
#[cfg(test)]
fn mknod_syscall(dir: BorrowedFd<'_>, d: &DefaultDevice) -> Result<(), SysError> {
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::Mknod {
            dirfd: dir.as_raw_fd(),
            name: d.name.to_string_lossy().into_owned(),
            major: d.major,
            minor: d.minor,
            mode: d.mode,
        })
    });
    tests::MKNOD_SCRIPT.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_empty() { Ok(()) } else { s.remove(0) }
    })
}

#[cfg(not(test))]
fn mount_dev_tmpfs_syscall(
    target: target::DevMountTarget<'_>,
    create: sys::DevTmpfsCreate,
) -> Result<OwnedFd, SysError> {
    sys::mount_dev_tmpfs_on(target.fd(), create)
}

/// dry-run: 新マウント API を呼ばず、(付け替え先の実体・固定パラメータ・返す fd) を記録し、付け替え先の
/// fd の複製を「自分のマウント」として返す。`MOUNT_SCRIPT` に積んだ失敗を先に返せる。
#[cfg(test)]
fn mount_dev_tmpfs_syscall(
    target: target::DevMountTarget<'_>,
    create: sys::DevTmpfsCreate,
) -> Result<OwnedFd, SysError> {
    let target_dir = target.fd();
    let scripted = tests::MOUNT_SCRIPT.with(|s| s.borrow_mut().take());
    if let Some(e) = scripted {
        return Err(e);
    }
    let resolved = std::fs::read_link(fd_magic_path(target_dir.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fd = target_dir
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))?;
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::MountDev {
            target: resolved,
            attr_bits: create.attr_bits(),
            mode: create.mode(),
            size_bytes: create.size_bytes(),
            fd: fd.as_raw_fd(),
        })
    });
    Ok(fd)
}

#[cfg(not(test))]
fn umount_dev_syscall(target: &CStr) -> Result<(), SysError> {
    sys::umount_detach_at(target)
}

/// dry-run: `umount2(2)` を呼ばず、解決した対象を記録する。
#[cfg(test)]
fn umount_dev_syscall(target: &CStr) -> Result<(), SysError> {
    let resolved = std::fs::read_link(target.to_string_lossy().as_ref())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    tests::EVENTS.with(|e| e.borrow_mut().push(tests::Event::Umount(resolved)));
    Ok(())
}

#[cfg(not(test))]
fn observe_dev_mount(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::fs_type(after.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(/dev)"))?,
        before_mnt_id: super::fd_mount_id(before, STAGE)?,
        after_mnt_id: super::fd_mount_id(after, STAGE)?,
        own_mnt_id: super::fd_mount_id(own, STAGE)?,
    })
}

/// dry-run: 既定は「別マウントの tmpfs で自分のマウント」を観測したことにする。`OBSERVE_SCRIPT` で異常値を
/// 差し込める（実機の検証は結合試験で行う）。
#[cfg(test)]
fn observe_dev_mount(
    _before: &OwnedFd,
    _after: &OwnedFd,
    _own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(tests::OBSERVE_SCRIPT
        .with(|s| s.borrow_mut().take())
        .unwrap_or(MountObservation {
            magic: sys::TMPFS_MAGIC,
            before_mnt_id: 1,
            after_mnt_id: 2,
            own_mnt_id: 2,
        }))
}

#[cfg(not(test))]
fn mount_devpts_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::DevptsCreate,
) -> Result<OwnedFd, SysError> {
    sys::mount_devpts_on(target_dir, create)
}

/// dry-run: 新マウント API を呼ばず、(付け替え先の実体・`gid`・attr フラグ・返す fd) を記録し、付け替え先の
/// fd の複製を「自分のマウント」として返す。`DEVPTS_MOUNT_SCRIPT` に積んだ失敗を先に返せる。
#[cfg(test)]
fn mount_devpts_syscall(
    target_dir: BorrowedFd<'_>,
    create: sys::DevptsCreate,
) -> Result<OwnedFd, SysError> {
    let scripted = tests::DEVPTS_MOUNT_SCRIPT.with(|s| s.borrow_mut().take());
    if let Some(e) = scripted {
        return Err(e);
    }
    let resolved = std::fs::read_link(fd_magic_path(target_dir.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fd = target_dir
        .try_clone_to_owned()
        .map_err(|_| SysError::Os(sys::EBADF))?;
    tests::EVENTS.with(|e| {
        e.borrow_mut().push(tests::Event::MountDevpts {
            target: resolved,
            gid: create.gid.value(),
            attr_bits: create.attr_bits(),
            fd: fd.as_raw_fd(),
        })
    });
    Ok(fd)
}

#[cfg(not(test))]
fn observe_pts_mount(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(MountObservation {
        magic: sys::fs_type(after.as_fd())
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(/dev/pts)"))?,
        before_mnt_id: super::fd_mount_id(before, STAGE)?,
        after_mnt_id: super::fd_mount_id(after, STAGE)?,
        own_mnt_id: super::fd_mount_id(own, STAGE)?,
    })
}

/// dry-run: 既定は「別マウントの devpts で自分のマウント」を観測したことにする。`OBSERVE_PTS_SCRIPT` で異常値を
/// 差し込める（実機の検証は結合試験で行う）。
#[cfg(test)]
fn observe_pts_mount(
    _before: &OwnedFd,
    _after: &OwnedFd,
    _own: &OwnedFd,
) -> Result<MountObservation, ExecError> {
    Ok(tests::OBSERVE_PTS_SCRIPT
        .with(|s| s.borrow_mut().take())
        .unwrap_or(MountObservation {
            magic: sys::DEVPTS_MAGIC,
            before_mnt_id: 1,
            after_mnt_id: 2,
            own_mnt_id: 2,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    type Call = (String, u32, u32, u32);

    /// dry-run が順序つきで記録する 1 件の副作用（テストスレッドごと）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum Event {
        /// tmpfs のマウント（`target` は付け替え先の解決パス、`fd` は返したマウント fd の raw 値）。
        MountDev {
            target: String,
            attr_bits: u32,
            mode: u32,
            size_bytes: u64,
            fd: i32,
        },
        Mknod {
            dirfd: i32,
            name: String,
            major: u32,
            minor: u32,
            mode: u32,
        },
        Symlink {
            dirfd: i32,
            name: String,
            target: String,
        },
        /// `mkdirat`（`pts`。`dev` の作成は記録しない）。
        Mkdir { dirfd: i32, name: String },
        /// devpts のマウント（`target` は付け替え先の解決パス、`fd` は返したマウント fd の raw 値）。
        MountDevpts {
            target: String,
            gid: Option<u32>,
            attr_bits: u32,
            fd: i32,
        },
        /// `gid=` を省いたときの構造化ログの出力。
        GidOmittedLog,
        /// `umount2(MNT_DETACH)`（解決した対象パス）。
        Umount(String),
        /// rootless 経路: ホストの `/dev/<名前>` を `O_PATH|O_NOFOLLOW` で開いた。
        OpenHostNode { name: String },
        /// rootless 経路: 開いたホストのノードを fd の `fstat` で照合した。
        VerifyHostNode { name: String },
        /// rootless 経路: bind 先の空ファイルを `O_EXCL` で作った。
        CreateBindTarget { name: String },
        /// rootless 経路: `open_tree` でホストのノードを複製した。
        OpenTree { name: String },
        /// rootless 経路: `move_mount` で空ファイルの上へ載せた。
        MoveMount { name: String },
        /// rootless 経路: 載せた後に名前を開き直して再確認した。
        RecheckBound { name: String },
        /// 後始末でこの呼び出しが作った空ファイルを消した。
        RemoveBindTarget { name: String },
    }

    thread_local! {
        pub(super) static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
        /// dry-run の mknod が次に返す結果（先頭から消費。空なら `Ok`）。
        pub(super) static MKNOD_SCRIPT: RefCell<Vec<Result<(), SysError>>> =
            const { RefCell::new(Vec::new()) };
        /// dry-run のマウントが次に返す失敗（消費される）。
        pub(super) static MOUNT_SCRIPT: RefCell<Option<SysError>> = const { RefCell::new(None) };
        /// dry-run の事後観測が次に返す値（消費される。無ければ正常値）。
        pub(super) static OBSERVE_SCRIPT: RefCell<Option<MountObservation>> =
            const { RefCell::new(None) };
        /// dry-run の devpts マウントが次に返す失敗（消費される）。
        pub(super) static DEVPTS_MOUNT_SCRIPT: RefCell<Option<SysError>> =
            const { RefCell::new(None) };
        /// dry-run の devpts 事後観測が次に返す値（消費される。無ければ正常値）。
        pub(super) static OBSERVE_PTS_SCRIPT: RefCell<Option<MountObservation>> =
            const { RefCell::new(None) };
        /// ホストの `/dev` として開く一時ディレクトリ（`None` なら実 `/dev` を開く）。
        pub(super) static HOST_DEV_SCRIPT: RefCell<Option<PathBuf>> =
            const { RefCell::new(None) };
        /// ホストのノードの照合が次に返す拒否（先頭から消費。空なら実際の照合）。
        pub(super) static VERIFY_SCRIPT: RefCell<Vec<sys::DeviceNodeError>> =
            const { RefCell::new(Vec::new()) };
        /// `open_tree` が次に返す結果（先頭から消費。空なら `Ok`）。
        pub(super) static OPEN_TREE_SCRIPT: RefCell<Vec<Result<(), SysError>>> =
            const { RefCell::new(Vec::new()) };
        /// `move_mount` が次に返す結果（先頭から消費。空なら `Ok`）。
        pub(super) static MOVE_MOUNT_SCRIPT: RefCell<Vec<Result<(), SysError>>> =
            const { RefCell::new(Vec::new()) };
        /// bind 後の再確認が次に観測する値（先頭から消費。空なら正常値）。
        pub(super) static OBSERVE_BOUND_SCRIPT: RefCell<Vec<BoundObservation>> =
            const { RefCell::new(Vec::new()) };
    }

    /// 記録とスクリプトをすべて消し、記録済みの `mknodat` 呼び出しを返す。
    fn take_calls() -> Vec<Call> {
        MKNOD_SCRIPT.with(|s| s.borrow_mut().clear());
        MOUNT_SCRIPT.with(|s| *s.borrow_mut() = None);
        OBSERVE_SCRIPT.with(|s| *s.borrow_mut() = None);
        DEVPTS_MOUNT_SCRIPT.with(|s| *s.borrow_mut() = None);
        OBSERVE_PTS_SCRIPT.with(|s| *s.borrow_mut() = None);
        HOST_DEV_SCRIPT.with(|s| *s.borrow_mut() = None);
        VERIFY_SCRIPT.with(|s| s.borrow_mut().clear());
        OPEN_TREE_SCRIPT.with(|s| s.borrow_mut().clear());
        MOVE_MOUNT_SCRIPT.with(|s| s.borrow_mut().clear());
        OBSERVE_BOUND_SCRIPT.with(|s| s.borrow_mut().clear());
        take_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Mknod {
                    name,
                    major,
                    minor,
                    mode,
                    ..
                } => Some((name, major, minor, mode)),
                _ => None,
            })
            .collect()
    }

    fn take_events() -> Vec<Event> {
        EVENTS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    fn run_at(root: BorrowedFd<'_>) -> Result<DeviceReport, ExecError> {
        create_default_devices_at(root, &|_| Ok(false), DevptsGidSource::Rootful)
    }

    /// `.0` は guard と同じパス（`t.0.join(..)` 用）。削除は guard の drop が行う（#1298）。
    struct Tmp(
        PathBuf,
        #[allow(dead_code)] crate::test_support::TestTempDir,
    );

    impl Tmp {
        fn new(label: &str) -> Self {
            let guard = crate::test_support::TestTempDir::new(&format!("devices-{label}"))
                .expect("create exclusive temp dir");
            Self(guard.path().to_path_buf(), guard)
        }
    }

    fn open_root(path: &Path) -> OwnedFd {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        sys::open_dir_path_nofollow(None, &c).unwrap()
    }

    /// CORE-1: 作成対象は OCI default devices の 6 種で、major/minor/モードが具体値と一致する。
    #[test]
    fn core1_default_device_table_is_exact() {
        let got: Vec<_> = DEFAULT_DEVICES
            .iter()
            .map(|d| (d.name.to_str().unwrap(), d.major, d.minor, d.mode))
            .collect();
        assert_eq!(
            got,
            vec![
                ("null", 1, 3, 0o666),
                ("zero", 1, 5, 0o666),
                ("full", 1, 7, 0o666),
                ("random", 1, 8, 0o666),
                ("urandom", 1, 9, 0o666),
                ("tty", 5, 0, 0o666),
            ]
        );
    }

    /// CORE-1・#1297: default symlink は OCI の 4 本で、名前は `dev` 直下の 1 要素。
    #[test]
    fn core1_default_link_table_is_exact() {
        let got: Vec<_> = DEFAULT_LINKS
            .iter()
            .map(|l| (l.name.to_str().unwrap(), l.target))
            .collect();
        assert_eq!(
            got,
            vec![
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
            ]
        );
        for l in &DEFAULT_LINKS {
            let n = l.name.to_str().unwrap();
            assert!(!n.contains('/') && n != "." && n != "..", "{n}");
        }
    }

    /// CORE-1・#1297: `dev` の無い rootfs に symlink 4 本が期待する参照先で作られる。
    #[test]
    fn core1_devices_create_default_links() {
        take_calls();
        let t = Tmp::new("links");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        assert_eq!(report.links.len(), 4);
        for (o, (n, tg)) in report.links.iter().zip([
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ]) {
            assert_eq!(
                (o.name, o.target, o.status),
                (n, tg, DeviceLinkStatus::Created)
            );
            let p = t.0.join("dev").join(n);
            assert!(
                std::fs::symlink_metadata(&p)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_link(&p).unwrap(), PathBuf::from(tg));
        }
        take_calls();
    }

    /// CORE-1・#1297: 期待どおりの既存 symlink は `AlreadyPresent` で受け入れ、変更しない。
    #[test]
    fn core1_devices_links_already_present_are_accepted() {
        take_calls();
        let t = Tmp::new("links-present");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        for l in &DEFAULT_LINKS {
            let n = l.name.to_str().unwrap();
            std::os::unix::fs::symlink(l.target, t.0.join("dev").join(n)).unwrap();
        }
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        assert!(
            report
                .links
                .iter()
                .all(|o| o.status == DeviceLinkStatus::AlreadyPresent)
        );
        assert_eq!(
            std::fs::read_link(t.0.join("dev/stdout")).unwrap(),
            PathBuf::from("/proc/self/fd/1")
        );
        take_calls();
    }

    /// CORE-1・#1297: 別の参照先・末尾 `/` 違い・外へ向かう相対参照は上書きせず拒否し、辿らない。
    #[test]
    fn core1_devices_link_with_other_target_is_rejected() {
        for (label, target) in [
            ("other", "/proc/1/fd"),
            ("slash", "/proc/self/fd/"),
            ("escape", "../../outside"),
        ] {
            take_calls();
            let t = Tmp::new(&format!("link-{label}"));
            let outside = t.0.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(rootfs.join("dev")).unwrap();
            std::os::unix::fs::symlink(target, rootfs.join("dev/fd")).unwrap();
            let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the existing entry dev/fd is not a symlink to /proc/self/fd"
            );
            assert_eq!(
                std::fs::read_link(rootfs.join("dev/fd")).unwrap(),
                PathBuf::from(target)
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
            take_calls();
        }
    }

    /// CORE-1・#1297: 既存エントリが通常ファイル・ディレクトリなら拒否し、内容を変えない。
    #[test]
    fn core1_devices_link_non_symlink_is_rejected() {
        take_calls();
        let t = Tmp::new("link-file");
        std::fs::create_dir_all(t.0.join("dev/fd")).unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(t.0.join("dev/fd").is_dir());
        std::fs::remove_dir(t.0.join("dev/fd")).unwrap();
        std::fs::write(t.0.join("dev/stdin"), b"keep").unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(
            err.message,
            "the existing entry dev/stdin is not a symlink to /proc/self/fd/0"
        );
        assert_eq!(std::fs::read(t.0.join("dev/stdin")).unwrap(), b"keep");
        take_calls();
    }

    /// CORE-1: `dev` が無ければ rootfs 配下に作り、6 種すべてを `dev` fd 起点の 1 要素名で作る。
    #[test]
    fn core1_devices_create_missing_dev_dir() {
        take_calls();
        let t = Tmp::new("missing");
        let root = open_root(&t.0);
        let report = run_at(root.as_fd()).unwrap();
        assert!(t.0.join("dev").is_dir());
        assert_eq!(report.nodes.len(), 6);
        assert_eq!(report.links.len(), 4);
        assert!(
            report
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::Created)
        );
        let want: Vec<Call> = vec![
            ("null".into(), 1, 3, 0o666),
            ("zero".into(), 1, 5, 0o666),
            ("full".into(), 1, 7, 0o666),
            ("random".into(), 1, 8, 0o666),
            ("urandom".into(), 1, 9, 0o666),
            ("tty".into(), 5, 0, 0o666),
        ];
        assert_eq!(take_calls(), want);
    }

    /// CORE-1: `dev` がホスト側ディレクトリへの symlink なら違反記録付きで拒否し、mknod は 0 回。
    #[test]
    fn core1_devices_reject_symlinked_dev() {
        take_calls();
        let t = Tmp::new("symlink");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("dev")).unwrap();
        let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(v.reason.as_str(), "path_symlink_or_not_directory");
        assert_eq!(v.behavior_id, "CORE-1");
        assert_eq!(
            v.subject.as_ref().map(|s| s.as_str().to_string()),
            Some(format!("{}/dev", rootfs.display()))
        );
        assert_eq!(take_calls(), Vec::<Call>::new());
        // dev 検証で失敗するため symlink 作成には進まず、外には 1 本も作られない。
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// CORE-1: `dev` が通常ファイルでも同様に拒否する。
    #[test]
    fn core1_devices_reject_dev_regular_file() {
        take_calls();
        let t = Tmp::new("file");
        std::fs::write(t.0.join("dev"), b"x").unwrap();
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "path_symlink_or_not_directory"
        );
        assert_eq!(take_calls(), Vec::<Call>::new());
    }

    /// CORE-1: `EEXIST` の既存エントリが通常ファイルなら拒否し、内容を変えない。
    #[test]
    fn core1_devices_eexist_regular_file_is_rejected() {
        take_calls();
        let t = Tmp::new("eexist");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/null"), b"keep").unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EEXIST))]);
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(std::fs::read(t.0.join("dev/null")).unwrap(), b"keep");
        assert_eq!(take_calls().len(), 1);
    }

    /// CORE-1: `EEXIST` の既存エントリが symlink でも（辿らず）拒否する。
    #[test]
    fn core1_devices_eexist_symlink_is_rejected() {
        take_calls();
        let t = Tmp::new("eexist-link");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::os::unix::fs::symlink("/dev/null", t.0.join("dev/null")).unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EEXIST))]);
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        take_calls();
    }

    /// CORE-1: 既存ノード検証は、文字デバイス・`rdev`・モード 0666 がすべて一致したときだけ通る。
    #[test]
    fn core1_devices_existing_node_check_is_exact() {
        let d = &DEFAULT_DEVICES[0];
        assert!(check_existing_node(true, 0x103, 0o666, d).is_ok());
        for (is_char, rdev, mode) in [
            (false, 0x103, 0o666),
            (true, 0x105, 0o666),
            (true, 0x103, 0o600),
        ] {
            let err = check_existing_node(is_char, rdev, mode, d).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the existing entry dev/null is not the expected character device 1:3 with mode 666"
            );
        }
    }

    /// CORE-1: rootful の `mknod` が `EPERM` なら `PermissionDenied`（段 `CreateDevices`）で fail-closed
    /// （rootless 経路へは縮退しない。rootless は #1660 で bind 供給になった）。
    #[test]
    fn core1_devices_eperm_fails_closed() {
        take_calls();
        let t = Tmp::new("eperm");
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EPERM))]);
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert!(err.violation.is_none());
        assert_eq!(take_calls().len(), 1);
    }

    /// CORE-1: 作成直後の検証は、文字デバイスかつ `rdev` 一致のときだけ通る。
    #[test]
    fn core1_devices_verify_rejects_swapped_node() {
        let d = &DEFAULT_DEVICES[0];
        assert!(check_created_node(true, 0x103, d).is_ok());
        for (is_char, rdev) in [(false, 0x103), (true, 0x105)] {
            let err = check_created_node(is_char, rdev, d).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the device node null was replaced right after creation"
            );
        }
    }

    fn count<F: Fn(&Event) -> bool>(events: &[Event], f: F) -> usize {
        events.iter().filter(|e| f(e)).count()
    }

    /// CORE-1・SEC-1・#1653: `dev` に tmpfs を載せてからノード 6 種・symlink 4 本を、マウントのルート fd
    /// 起点で作る（`dev` を開いた fd や名前の開き直しではない）。
    #[test]
    fn core1_1653_dev_tmpfs_then_nodes_then_links_from_mount_fd() {
        take_calls();
        let t = Tmp::new("order");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        let events = take_events();
        let Some(Event::MountDev {
            target,
            attr_bits,
            mode,
            size_bytes,
            fd,
        }) = events.first().cloned()
        else {
            panic!("first event must be the tmpfs mount: {events:?}");
        };
        assert_eq!(target, format!("{}/dev", t.0.display()));
        assert_eq!(attr_bits, 0x22);
        assert_eq!(mode, 0o755);
        assert_eq!(size_bytes, 67_108_864);
        let names: Vec<_> = events
            .iter()
            .skip(1)
            .map(|e| match e {
                Event::Mknod { dirfd, name, .. } => (*dirfd, format!("mknod {name}")),
                Event::Symlink {
                    dirfd,
                    name,
                    target,
                } => (*dirfd, format!("symlink {name} {target}")),
                Event::Mkdir { dirfd, name } => (*dirfd, format!("mkdir {name}")),
                // devpts のマウントは dirfd を持たない（付け替え先の実体は専用のテストで照合する）ため、
                // ここでは順序だけを見る。
                Event::MountDevpts { .. } => (fd, "mount devpts".to_owned()),
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        assert_eq!(
            names.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(),
            vec![
                "mknod null",
                "mknod zero",
                "mknod full",
                "mknod random",
                "mknod urandom",
                "mknod tty",
                "symlink fd /proc/self/fd",
                "symlink stdin /proc/self/fd/0",
                "symlink stdout /proc/self/fd/1",
                "symlink stderr /proc/self/fd/2",
                "mkdir pts",
                "mount devpts",
                "symlink ptmx pts/ptmx",
            ]
        );
        assert!(names.iter().all(|(d, _)| *d == fd), "dirfd must be {fd}");
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 0);
        assert!(
            report
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::Created)
        );
        assert!(
            report
                .links
                .iter()
                .all(|l| l.status == DeviceLinkStatus::Created)
        );
    }

    /// CORE-1・#1653: `dev` が symlink・通常ファイルなら何もマウントせず拒否する。
    #[test]
    fn core1_1653_symlinked_or_file_dev_is_rejected_without_mount() {
        for as_symlink in [true, false] {
            take_calls();
            let t = Tmp::new("reject");
            let outside = t.0.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(&rootfs).unwrap();
            if as_symlink {
                std::os::unix::fs::symlink(&outside, rootfs.join("dev")).unwrap();
            } else {
                std::fs::write(rootfs.join("dev"), b"keep").unwrap();
            }
            let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            let v = err.violation.as_ref().expect("violation record");
            assert_eq!(v.reason.as_str(), "path_symlink_or_not_directory");
            assert_eq!(v.behavior_id, "CORE-1");
            assert_eq!(take_events(), Vec::<Event>::new());
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
            if !as_symlink {
                assert_eq!(std::fs::read(rootfs.join("dev")).unwrap(), b"keep");
            }
        }
    }

    /// CORE-1・#1653: マウント後にノード作成が失敗したら自分のマウントを外し、自分で作った `dev` を消す。
    #[test]
    fn core1_1653_failure_after_mount_unmounts_and_removes_created_dev() {
        take_calls();
        let t = Tmp::new("rollback");
        MKNOD_SCRIPT.with(|s| {
            *s.borrow_mut() = vec![Ok(()), Ok(()), Err(SysError::Os(sys::EPERM))];
        });
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let events = take_events();
        assert_eq!(
            events.last(),
            Some(&Event::Umount(format!("{}/dev", t.0.display())))
        );
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
        assert!(!t.0.join("dev").exists());
        take_calls();
    }

    /// CORE-1・#1653: 作成後に `dev` が別ディレクトリへ差し替えられたら、後始末は差し替え後を消さず残す。
    #[test]
    fn core1_1653_rollback_keeps_swapped_dev() {
        let t = Tmp::new("swapped");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        let root = open_root(&t.0);
        let created = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
        let state = DevState {
            created_dev: Some(created),
            mounted: None,
            pts: PtsState::default(),
            binds: Vec::new(),
        };
        std::fs::rename(t.0.join("dev"), t.0.join("dev-moved")).unwrap();
        std::fs::create_dir(t.0.join("dev")).unwrap();
        roll_back_dev(root.as_fd(), &state);
        assert!(t.0.join("dev").is_dir());
        assert!(t.0.join("dev-moved").is_dir());
    }

    /// CORE-1・#1653: `dev` が作成時と同じ inode のままなら後始末で消す。
    #[test]
    fn core1_1653_rollback_removes_same_dev() {
        let t = Tmp::new("same");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        let root = open_root(&t.0);
        let created = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
        let state = DevState {
            created_dev: Some(created),
            mounted: None,
            pts: PtsState::default(),
            binds: Vec::new(),
        };
        roll_back_dev(root.as_fd(), &state);
        assert!(!t.0.join("dev").exists());
    }

    /// CORE-1・#1653: 既存の `dev`（内容あり）は、失敗してもマウントを外すだけで消さない。
    #[test]
    fn core1_1653_failure_keeps_preexisting_dev() {
        take_calls();
        let t = Tmp::new("keep");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/keep"), b"data").unwrap();
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EPERM))]);
        run_at(open_root(&t.0).as_fd()).unwrap_err();
        let events = take_events();
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
        assert_eq!(std::fs::read(t.0.join("dev/keep")).unwrap(), b"data");
        take_calls();
    }

    /// CORE-1・SEC-1・#1653: 事後検証（tmpfs でない・自分のマウントでない）に通らなければ拒否して巻き戻す。
    #[test]
    fn core1_1653_post_verification_failure_rolls_back() {
        for (obs, msg) in [
            (
                MountObservation {
                    magic: 0xEF53,
                    before_mnt_id: 1,
                    after_mnt_id: 2,
                    own_mnt_id: 2,
                },
                "the mount at /dev is not tmpfs after mount",
            ),
            (
                MountObservation {
                    magic: sys::TMPFS_MAGIC,
                    before_mnt_id: 1,
                    after_mnt_id: 2,
                    own_mnt_id: 3,
                },
                "the mount at /dev is not the mount created by this call",
            ),
        ] {
            take_calls();
            let t = Tmp::new("postverify");
            OBSERVE_SCRIPT.with(|s| *s.borrow_mut() = Some(obs));
            let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(err.message, msg);
            let events = take_events();
            assert_eq!(count(&events, |e| matches!(e, Event::Mknod { .. })), 0);
            assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 1);
            assert!(!t.0.join("dev").exists());
        }
    }

    /// CORE-1・#1653: 新マウント API 未対応は `Unimplemented` で拒否し、マウントしていないので外さない。
    #[test]
    fn core1_1653_mount_unsupported_is_unimplemented() {
        take_calls();
        let t = Tmp::new("unsupported");
        MOUNT_SCRIPT.with(|s| *s.borrow_mut() = Some(SysError::Unsupported));
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(take_events(), Vec::<Event>::new());
        assert!(!t.0.join("dev").exists());
        take_calls();
    }

    /// CORE-1・#1653: shared な `dev`・固定後に改名された `dev` はマウント前に拒否する。
    #[test]
    fn core1_1653_shared_or_moved_dev_is_rejected_before_mount() {
        take_calls();
        let t = Tmp::new("shared");
        let err = create_default_devices_at(
            open_root(&t.0).as_fd(),
            &|_| Ok(true),
            DevptsGidSource::Rootful,
        )
        .unwrap_err();
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "target_on_shared_mount"
        );
        assert_eq!(take_events(), Vec::<Event>::new());
        assert!(!t.0.join("dev").exists());

        let t = Tmp::new("moved");
        let dev = t.0.join("dev");
        let moved = t.0.join("dev-moved");
        let err = create_default_devices_at(
            open_root(&t.0).as_fd(),
            &|_| {
                std::fs::rename(&dev, &moved).unwrap();
                Ok(false)
            },
            DevptsGidSource::Rootful,
        )
        .unwrap_err();
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "target_moved"
        );
        assert_eq!(take_events(), Vec::<Event>::new());
        take_calls();
    }

    /// CORE-1・SEC-5・#1656: devpts の `gid=` の決定（rootful は 5、rootless は gid 5 が写像されたときだけ 5）。
    #[test]
    fn core1_sec5_1656_devpts_gid_decision_is_exact() {
        use crate::exec::IdMapping;
        let map = |entries: Vec<(u32, u32, u32)>| {
            IdMapSet::new(
                entries
                    .into_iter()
                    .map(|(container_id, host_id, count)| IdMapping {
                        container_id,
                        host_id,
                        count,
                    })
                    .collect(),
            )
            .unwrap()
        };
        assert_eq!(devpts_gid(DevptsGidSource::Rootful), sys::DevptsGid::Tty);
        // 範囲写像でコンテナ 1..65537 が写る → 5 は写像される。
        let ranged = map(vec![(0, 1000, 1), (1, 100_000, 65_536)]);
        assert_eq!(
            devpts_gid(DevptsGidSource::Rootless(&ranged)),
            sys::DevptsGid::Tty
        );
        // 単一 ID の写像（コンテナ 0 のみ）→ 5 は写像されない。
        let single = crate::rootless::single_id_mapping(1000).unwrap();
        assert_eq!(
            devpts_gid(DevptsGidSource::Rootless(&single)),
            sys::DevptsGid::Omitted
        );
        // 境界: 1..=4 までなら 5 は範囲外、5 だけを別行で写せば範囲内。
        let short = map(vec![(0, 1000, 1), (1, 100_000, 4)]);
        assert_eq!(
            devpts_gid(DevptsGidSource::Rootless(&short)),
            sys::DevptsGid::Omitted
        );
        let only5 = map(vec![(0, 1000, 1), (5, 200_005, 1)]);
        assert_eq!(
            devpts_gid(DevptsGidSource::Rootless(&only5)),
            sys::DevptsGid::Tty
        );
    }

    /// CORE-1・#1656: `gid=` を省いたときの構造化ログはバイト単位で固定（固定の語彙と数値だけ）。
    #[test]
    fn core1_1656_gid_omitted_log_line_is_exact() {
        assert_eq!(
            devpts_gid_omitted_log_line(),
            "{\"event\":\"devpts_gid_omitted\",\"container_gid\":5,\"reason\":\"rootless_gid_unmapped\"}"
        );
    }

    /// CORE-1・SEC-1・OCI-4・#1656: tmpfs → ノード → symlink の後に `pts` を作り、devpts を載せ、
    /// 最後に `ptmx` → `pts/ptmx` を `/dev` のマウント fd 起点で作る。
    #[test]
    fn core1_oci4_1656_order_mkdir_pts_then_devpts_then_ptmx() {
        take_calls();
        let t = Tmp::new("pts-order");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        let events = take_events();
        let Some(Event::MountDev { fd, .. }) = events.first().cloned() else {
            panic!("first event must be the tmpfs mount: {events:?}");
        };
        let tail = &events[events.len() - 3..];
        assert_eq!(
            tail[0],
            Event::Mkdir {
                dirfd: fd,
                name: "pts".into()
            }
        );
        let Event::MountDevpts {
            target,
            gid,
            attr_bits,
            ..
        } = tail[1].clone()
        else {
            panic!("devpts mount must follow mkdir: {tail:?}");
        };
        assert_eq!(target, format!("{}/dev/pts", t.0.display()));
        assert_eq!(gid, Some(5));
        assert_eq!(attr_bits, 0xA);
        assert_eq!(
            tail[2],
            Event::Symlink {
                dirfd: fd,
                name: "ptmx".into(),
                target: "pts/ptmx".into()
            }
        );
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 0);
        assert_eq!(count(&events, |e| matches!(e, Event::GidOmittedLog)), 0);
        assert_eq!(report.devpts.gid, Some(5));
        assert_eq!(report.devpts.pts_dir, DevptsDirStatus::Created);
        assert_eq!(report.devpts.ptmx.name, "ptmx");
        assert_eq!(report.devpts.ptmx.target, "pts/ptmx");
        assert_eq!(report.devpts.ptmx.status, DeviceLinkStatus::Created);
        assert_eq!(
            std::fs::read_link(t.0.join("dev/ptmx")).unwrap(),
            PathBuf::from("pts/ptmx")
        );
        assert!(t.0.join("dev/pts").is_dir());
    }

    /// CORE-1・SEC-5・#1656: gid 5 が写像されない rootless では `gid=` を渡さず、構造化ログを 1 件出す。
    #[test]
    fn core1_sec5_1656_unmapped_gid_omits_gid_and_logs_once() {
        take_calls();
        let t = Tmp::new("pts-nogid");
        let single = crate::rootless::single_id_mapping(1000).unwrap();
        let report = create_default_devices_at(
            open_root(&t.0).as_fd(),
            &|_| Ok(false),
            DevptsGidSource::Rootless(&single),
        )
        .unwrap();
        let events = take_events();
        assert_eq!(report.devpts.gid, None);
        let gids: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::MountDevpts { gid, .. } => Some(*gid),
                _ => None,
            })
            .collect();
        assert_eq!(gids, vec![None]);
        assert_eq!(count(&events, |e| matches!(e, Event::GidOmittedLog)), 1);
    }

    /// CORE-1・SEC-1・#1656: 既存の `ptmx` が別の参照先・通常ファイルなら上書きも unlink もせず拒否し、
    /// 載せた devpts と作った `pts` だけを巻き戻す。
    #[test]
    fn core1_1656_existing_ptmx_other_target_or_file_is_rejected() {
        for (label, kind) in [("abs", 0), ("escape", 1), ("file", 2)] {
            take_calls();
            let t = Tmp::new(&format!("ptmx-{label}"));
            let outside = t.0.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let rootfs = t.0.join("root");
            std::fs::create_dir_all(rootfs.join("dev")).unwrap();
            let ptmx = rootfs.join("dev/ptmx");
            match kind {
                0 => std::os::unix::fs::symlink("/dev/pts/ptmx", &ptmx).unwrap(),
                1 => std::os::unix::fs::symlink("../outside", &ptmx).unwrap(),
                _ => std::fs::write(&ptmx, b"keep").unwrap(),
            }
            let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the existing entry dev/ptmx is not a symlink to pts/ptmx"
            );
            match kind {
                0 => assert_eq!(
                    std::fs::read_link(&ptmx).unwrap(),
                    PathBuf::from("/dev/pts/ptmx")
                ),
                1 => assert_eq!(
                    std::fs::read_link(&ptmx).unwrap(),
                    PathBuf::from("../outside")
                ),
                _ => assert_eq!(std::fs::read(&ptmx).unwrap(), b"keep"),
            }
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
            let events = take_events();
            let umounts: Vec<_> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Umount(p) => Some(p.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                umounts,
                vec![
                    format!("{}/dev/pts", rootfs.display()),
                    format!("{}/dev", rootfs.display())
                ]
            );
            // 自分が作った `pts` は消え、既存の `ptmx` は残る。
            assert!(!rootfs.join("dev/pts").exists());
        }
    }

    /// CORE-1・#1656: 期待どおりの既存 `ptmx` は `AlreadyPresent` で受け入れ、作成扱いにしない。
    #[test]
    fn core1_1656_existing_ptmx_exact_is_accepted() {
        take_calls();
        let t = Tmp::new("ptmx-present");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::os::unix::fs::symlink("pts/ptmx", t.0.join("dev/ptmx")).unwrap();
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        assert_eq!(report.devpts.ptmx.status, DeviceLinkStatus::AlreadyPresent);
        take_calls();
    }

    /// CORE-1・SEC-1・#1656: devpts の事後検証（devpts でない）に通らなければ拒否し、devpts → `pts` →
    /// `/dev` の順で巻き戻す。無関係な既存エントリは残す。
    #[test]
    fn core1_1656_post_verification_failure_rolls_back_only_created() {
        take_calls();
        let t = Tmp::new("pts-postverify");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/keep"), b"data").unwrap();
        OBSERVE_PTS_SCRIPT.with(|s| {
            *s.borrow_mut() = Some(MountObservation {
                magic: sys::TMPFS_MAGIC,
                before_mnt_id: 1,
                after_mnt_id: 2,
                own_mnt_id: 2,
            })
        });
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(
            err.message,
            "the mount at /dev/pts is not devpts after mount"
        );
        let events = take_events();
        assert_eq!(
            events[events.len() - 2..],
            [
                Event::Umount(format!("{}/dev/pts", t.0.display())),
                Event::Umount(format!("{}/dev", t.0.display())),
            ]
        );
        assert!(!t.0.join("dev/pts").exists());
        assert!(!t.0.join("dev/ptmx").exists());
        assert_eq!(std::fs::read(t.0.join("dev/keep")).unwrap(), b"data");
    }

    /// CORE-1・#1656: devpts の新マウント API 未対応は `Unimplemented`。作った `pts` は消え、devpts は
    /// 載っていないので外さない（`/dev` の tmpfs だけ外す）。
    #[test]
    fn core1_1656_devpts_unsupported_is_unimplemented() {
        take_calls();
        let t = Tmp::new("pts-unsupported");
        DEVPTS_MOUNT_SCRIPT.with(|s| *s.borrow_mut() = Some(SysError::Unsupported));
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        let events = take_events();
        assert_eq!(
            events
                .iter()
                .filter_map(|e| match e {
                    Event::Umount(p) => Some(p.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![format!("{}/dev", t.0.display())]
        );
        // `pts` は消える。`dev` 自体は dry-run で実体のある symlink 4 本が残るため消えない（実機では tmpfs ごと外れる）。
        assert!(!t.0.join("dev/pts").exists());
        take_calls();
    }

    /// CORE-1・SEC-1・#1656: 既存の `pts` が外側への symlink なら違反記録付きで拒否し、devpts を載せず、
    /// 外側に何も作らない。
    #[test]
    fn core1_1656_symlinked_pts_is_rejected() {
        take_calls();
        let t = Tmp::new("pts-symlink");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let rootfs = t.0.join("root");
        std::fs::create_dir_all(rootfs.join("dev")).unwrap();
        std::os::unix::fs::symlink(&outside, rootfs.join("dev/pts")).unwrap();
        let err = run_at(open_root(&rootfs).as_fd()).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert_eq!(
            err.violation.as_ref().unwrap().reason.as_str(),
            "path_symlink_or_not_directory"
        );
        let events = take_events();
        assert_eq!(
            count(&events, |e| matches!(e, Event::MountDevpts { .. })),
            0
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert!(
            std::fs::symlink_metadata(rootfs.join("dev/pts"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// CORE-1・#1656: `ptmx` 作成後の失敗でも、自分が作った `ptmx` と `pts` は消え、既存の内容は残る。
    /// 差し替えられた `ptmx`（参照先が違う）は消さない。
    #[test]
    fn core1_1656_rollback_removes_created_ptmx_and_pts_only() {
        for swapped in [false, true] {
            let t = Tmp::new(&format!("pts-rollback-{swapped}"));
            std::fs::create_dir(t.0.join("dev")).unwrap();
            std::fs::write(t.0.join("dev/keep"), b"data").unwrap();
            let root = open_root(&t.0);
            let dev = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
            sys::mkdir_at(dev.as_fd(), c"pts", 0o755).unwrap();
            let pts = sys::open_dir_path_nofollow(Some(dev.as_fd()), c"pts").unwrap();
            let target = if swapped { "elsewhere" } else { "pts/ptmx" };
            std::os::unix::fs::symlink(target, t.0.join("dev/ptmx")).unwrap();
            let state = DevState {
                created_dev: None,
                mounted: Some(dev),
                pts: PtsState {
                    created: Some(pts),
                    mounted: None,
                    ptmx_created: true,
                },
                binds: Vec::new(),
            };
            roll_back_dev(root.as_fd(), &state);
            assert!(!t.0.join("dev/pts").exists());
            assert_eq!(std::fs::read(t.0.join("dev/keep")).unwrap(), b"data");
            assert_eq!(
                std::fs::symlink_metadata(t.0.join("dev/ptmx")).is_ok(),
                swapped,
                "swapped ptmx must be kept"
            );
            take_events();
        }
    }

    /// SUP-12・CORE-1（#1669 事後監査 P2）: `/dev` 配下の宛先（既定の `/dev/shm`）を載せるには、同じ rootfs に
    /// 対する `create_default_devices` の結果を要求し、rootfs の `dev` が今もその tmpfs のルートであることを
    /// 確かめる。証跡なし・差し替え・不在・別の rootfs の結果は、何も作らずに `FailedPrecondition` で拒否する。
    #[test]
    fn sup12_core1_dev_shm_requires_device_report_of_same_dev() {
        use super::super::tmpfs::check_dev_order;
        use crate::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
        let missing = "tmpfs mounts under /dev require create_default_devices to run first on the same rootfs";
        let mismatch = "the rootfs /dev is not the tmpfs mounted by create_default_devices";
        let expect_rejected = |e: ExecError, message: &str| {
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.stage, IsolationStage::MountTmpfs);
            assert_eq!(e.message, message);
            assert!(e.violation.is_none());
        };
        let mut shm = TmpfsMountSet::new();
        shm.ensure_default_dev_shm().expect("default /dev/shm");
        let mut scratch = TmpfsMountSet::new();
        scratch
            .push(TmpfsMountSpec::new("/scratch", None).expect("spec"))
            .expect("push");

        let t = Tmp::new("order-evidence");
        let root = open_root(&t.0);
        // `/dev` 配下の宛先が無い集合は証跡を見ない。
        check_dev_order(root.as_fd(), &scratch, None).expect("no /dev destination");
        check_dev_order(root.as_fd(), &TmpfsMountSet::new(), None).expect("empty set");
        // 証跡なしは何も作らずに拒否する。
        expect_rejected(
            check_dev_order(root.as_fd(), &shm, None).expect_err("no evidence"),
            missing,
        );
        assert!(!t.0.join("dev").exists());

        let report = run_at(root.as_fd()).expect("default devices");
        take_events();
        check_dev_order(root.as_fd(), &shm, Some(&report)).expect("same /dev");

        // 別の rootfs の結果は通さない。
        let other = Tmp::new("order-evidence-other");
        let other_root = open_root(&other.0);
        let other_report = run_at(other_root.as_fd()).expect("other default devices");
        take_events();
        expect_rejected(
            check_dev_order(root.as_fd(), &shm, Some(&other_report)).expect_err("other rootfs"),
            mismatch,
        );

        // `dev` を差し替えたら通さない（逆順の配線・重ね掛けで覆われた場合も同じ判定になる）。
        std::fs::rename(t.0.join("dev"), t.0.join("dev-old")).unwrap();
        std::fs::create_dir(t.0.join("dev")).unwrap();
        expect_rejected(
            check_dev_order(root.as_fd(), &shm, Some(&report)).expect_err("replaced /dev"),
            mismatch,
        );
        // `dev` が無ければ通さない。
        std::fs::remove_dir(t.0.join("dev")).unwrap();
        expect_rejected(
            check_dev_order(root.as_fd(), &shm, Some(&report)).expect_err("missing /dev"),
            mismatch,
        );
    }

    /// crate の `src` 配下の `.rs` を再帰的に集め、`(src からの相対パス, 内容)` を返す（ソース走査の試験用）。
    fn crate_sources() -> Vec<(String, String)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src.clone()];
        let mut out = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let rel = path
                        .strip_prefix(&src)
                        .expect("under src")
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.push((rel, std::fs::read_to_string(&path).expect("read source")));
                }
            }
        }
        out.sort();
        out
    }

    /// SEC-1・CORE-1（#1664 事後監査 P2）: nodev なしの tmpfs を載せる `sys::mount_dev_tmpfs_on` の呼び出しは
    /// 本モジュールの 1 か所（[`target::DevMountTarget`] を受ける `mount_dev_tmpfs_syscall`）だけで、固定パラメータ
    /// `DevTmpfsCreate::new` も本モジュールと `sys` の単体テストからしか作られない。crate 内の別の箇所から
    /// 利用者の `--tmpfs` の行き先などへ nodev なしの tmpfs を載せる誤配線を、ソースの走査で機械的に検出する
    /// （Rust の可視性は兄弟モジュールへの限定を表せないため。plugin の `sys.rs` のソース照合と同じ方式）。
    #[test]
    fn sec1_core1_dev_tmpfs_mount_has_single_call_site() {
        // 走査する語を分割して書き、本試験の行自体が一致しないようにする。
        let call = concat!("mount_dev_tmpfs", "_on(");
        let create = concat!("DevTmpfsCreate", "::new()");
        let mut calls = Vec::new();
        let mut creates = Vec::new();
        for (rel, text) in crate_sources() {
            for line in text.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                if code.contains(call) {
                    calls.push((rel.clone(), code.to_owned()));
                }
                if code.contains(create) && !creates.contains(&rel) {
                    creates.push(rel.clone());
                }
            }
        }
        assert_eq!(
            calls,
            vec![
                (
                    "exec/devices.rs".to_owned(),
                    format!("sys::{call}target.fd(), create)")
                ),
                ("sys.rs".to_owned(), format!("pub(crate) fn {call}")),
            ]
        );
        assert_eq!(
            creates,
            vec!["exec/devices.rs".to_owned(), "sys.rs".to_owned()]
        );
    }

    /// SEC-1・CORE-6（#1676・#1660）: rootfs の `nodev`（`sys::set_mount_nodev`）の呼び出しは
    /// `exec/rootfs.rs` の `nodev_syscall` の 1 か所だけで、`mount_setattr(2)` の syscall 番号を使うのも `sys` だけ。
    /// 本モジュールの `/dev` の tmpfs・devpts・rootless の bind（ホストのノードの複製）へ `nodev` を掛ける経路が
    /// 無いことを、ソースの走査で機械的に確かめる（`nodev` が及ぶとノードを開けなくなる）。
    #[test]
    fn sec1_core6_rootfs_nodev_has_single_call_site() {
        // 走査する語を分割して書き、本試験の行自体が一致しないようにする。
        let call = concat!("set_mount", "_nodev(");
        let number = concat!("SYS_MOUNT", "_SETATTR");
        let mut calls = Vec::new();
        let mut numbers = Vec::new();
        for (rel, text) in crate_sources() {
            for line in text.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                if code.contains(call) {
                    calls.push((rel.clone(), code.to_owned()));
                }
                if code.contains(number) && !numbers.contains(&rel) {
                    numbers.push(rel.clone());
                }
            }
        }
        assert_eq!(
            calls,
            vec![
                (
                    "exec/rootfs.rs".to_owned(),
                    format!("sys::{call}mount_top)")
                ),
                (
                    "sys.rs".to_owned(),
                    format!(
                        "pub(crate) fn {call}mount_top: BorrowedFd<'_>) -> Result<(), SysError> {{"
                    )
                ),
            ]
        );
        assert_eq!(numbers, vec!["sys.rs".to_owned()]);
    }

    // ---- rootless 経路: ホストのノードの bind（#1660。CORE-6・SEC-5・CORE-1）----

    /// rootless の呼び出し（単一 ID 写像。gid 5 は未写像）。
    fn run_rootless_at(root: BorrowedFd<'_>) -> Result<DeviceReport, ExecError> {
        let map = crate::rootless::single_id_mapping(1000).unwrap();
        create_default_devices_at(root, &|_| Ok(false), DevptsGidSource::Rootless(&map))
    }

    const NODE_NAMES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

    /// 出来事の列から rootless 経路の bind 系だけを `<種別> <名前>` で取り出す。
    fn bind_trace(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::OpenHostNode { name } => Some(format!("open-host {name}")),
                Event::VerifyHostNode { name } => Some(format!("verify {name}")),
                Event::CreateBindTarget { name } => Some(format!("create {name}")),
                Event::OpenTree { name } => Some(format!("open-tree {name}")),
                Event::MoveMount { name } => Some(format!("move-mount {name}")),
                Event::RecheckBound { name } => Some(format!("recheck {name}")),
                Event::RemoveBindTarget { name } => Some(format!("remove {name}")),
                _ => None,
            })
            .collect()
    }

    /// CORE-6・SEC-5・#1660: rootless は 6 種それぞれを「開く → 検証 → 空ファイル作成 → 複製 → 接続 → 再確認」の
    /// 順で bind し、`mknodat` は呼ばない。報告はすべて `BoundFromHost`。symlink 4 本と devpts は rootful と同じ。
    #[test]
    fn core6_sec5_1660_rootless_binds_six_nodes_in_order() {
        take_calls();
        let t = Tmp::new("bind-order");
        let report = run_rootless_at(open_root(&t.0).as_fd()).unwrap();
        let events = take_events();
        let mut expected = Vec::new();
        for n in NODE_NAMES {
            for step in [
                "open-host",
                "verify",
                "create",
                "open-tree",
                "move-mount",
                "recheck",
            ] {
                expected.push(format!("{step} {n}"));
            }
        }
        assert_eq!(bind_trace(&events), expected);
        assert_eq!(count(&events, |e| matches!(e, Event::Mknod { .. })), 0);
        assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 0);
        assert_eq!(report.nodes.len(), 6);
        for (n, name) in report.nodes.iter().zip(NODE_NAMES) {
            assert_eq!(n.name, name);
            assert_eq!(n.status, DeviceNodeStatus::BoundFromHost);
            assert_eq!(n.mode, 0o666);
        }
        // symlink 4 本・devpts・ptmx は rootful と同じ（gid 5 は未写像のため `gid=` なし）。
        let links: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Symlink { name, target, .. } => Some((name.as_str(), target.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(
            links,
            vec![
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
                ("ptmx", "pts/ptmx"),
            ]
        );
        assert_eq!(report.devpts.gid, None);
        // bind 先の空ファイルが tmpfs 上（dry-run では `dev` ディレクトリ）に実在する。
        for n in NODE_NAMES {
            let meta = std::fs::symlink_metadata(t.0.join("dev").join(n)).unwrap();
            assert!(meta.file_type().is_file(), "{n}");
            assert_eq!(meta.len(), 0, "{n}");
            assert_eq!(meta.mode() & 0o777, 0, "{n}");
        }
        take_calls();
    }

    /// CORE-1・#1660: rootful は従来どおり `mknodat` で作り、bind 系の出来事を一切起こさない。
    #[test]
    fn core1_1660_rootful_keeps_mknod_path() {
        take_calls();
        let t = Tmp::new("rootful-path");
        let report = run_at(open_root(&t.0).as_fd()).unwrap();
        let events = take_events();
        assert_eq!(count(&events, |e| matches!(e, Event::Mknod { .. })), 6);
        assert_eq!(bind_trace(&events), Vec::<String>::new());
        assert!(
            report
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::Created)
        );
        take_calls();
    }

    /// CORE-6・SEC-5・#1660: 供給方式は申告から明示的に決まり、`mknod` の失敗では切り替わらない。
    #[test]
    fn core6_1660_device_supply_follows_declared_model() {
        let map = crate::rootless::single_id_mapping(1000).unwrap();
        assert_eq!(device_supply(DevptsGidSource::Rootful), DeviceSupply::Mknod);
        assert_eq!(
            device_supply(DevptsGidSource::Rootless(&map)),
            DeviceSupply::BindFromHost
        );
        // rootful の `EPERM` は rootless 経路へ縮退せず、bind 系の出来事も起きない。
        take_calls();
        let t = Tmp::new("no-fallback");
        MKNOD_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Os(sys::EPERM))]);
        let err = run_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(bind_trace(&take_events()), Vec::<String>::new());
        take_calls();
    }

    /// 期待と違うホストのノードを `null` の位置に置いた rootless の実行結果（出来事と拒否）を返す。
    fn run_with_bad_host_null(label: &str, setup: impl Fn(&Path)) -> (Vec<Event>, ExecError) {
        take_calls();
        let host = Tmp::new(&format!("host-{label}"));
        setup(&host.0);
        HOST_DEV_SCRIPT.with(|s| *s.borrow_mut() = Some(host.0.clone()));
        let t = Tmp::new(&format!("bind-reject-{label}"));
        let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
        let events = take_events();
        take_calls();
        assert!(
            !t.0.join("dev").exists(),
            "{label}: created dev must be removed"
        );
        (events, err)
    }

    fn assert_host_node_rejected(label: &str, events: &[Event], err: &ExecError) {
        assert_eq!(err.code, ErrorCode::FailedPrecondition, "{label}");
        assert_eq!(err.stage, IsolationStage::CreateDevices, "{label}");
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(v.reason.as_str(), "host_device_node_unexpected", "{label}");
        assert_eq!(v.behavior_id, "SEC-5", "{label}");
        assert_eq!(
            v.audit_path().map(|p| p.as_path()),
            Some(Path::new("/dev/null")),
            "{label}"
        );
        assert_eq!(
            bind_trace(events),
            vec!["open-host null".to_owned(), "verify null".to_owned()],
            "{label}: nothing may be created or bound"
        );
        // 載せた tmpfs だけが外れる。
        assert_eq!(
            count(events, |e| matches!(e, Event::Umount(_))),
            1,
            "{label}"
        );
    }

    /// SEC-5・#1660: ホスト側の `null` が通常ファイル・実 `/dev/null` への symlink（辿らない）・`rdev` 違いなら、
    /// 違反つきで拒否し、空ファイルも bind も作らない。
    #[test]
    fn core6_sec5_1660_host_node_unexpected_is_rejected_without_bind() {
        let (events, err) = run_with_bad_host_null("regular", |dir| {
            std::fs::write(dir.join("null"), b"not a device").unwrap();
        });
        assert_host_node_rejected("regular", &events, &err);

        let (events, err) = run_with_bad_host_null("symlink", |dir| {
            std::os::unix::fs::symlink("/dev/null", dir.join("null")).unwrap();
        });
        assert_host_node_rejected("symlink", &events, &err);

        // `rdev` 違い（1:5）。非特権ではノードを作れないため、照合の拒否を差し込む。
        take_calls();
        VERIFY_SCRIPT.with(|s| {
            *s.borrow_mut() = vec![sys::DeviceNodeError::UnexpectedRdev {
                actual: sys::makedev(1, 5),
                expected: sys::makedev(1, 3),
            }]
        });
        let t = Tmp::new("bind-reject-rdev");
        let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
        let events = take_events();
        assert_host_node_rejected("rdev", &events, &err);
        take_calls();
    }

    /// 照合以外の失敗の写し方: `fstat` の失敗は違反なしの OS エラー、未対応は `Unimplemented`。
    #[test]
    fn core6_sec5_1660_host_node_error_mapping_is_exact() {
        let d = &DEFAULT_DEVICES[1];
        let err = host_node_error(sys::DeviceNodeError::Sys(SysError::Os(sys::EBADF)), d);
        assert!(err.violation.is_none());
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert!(
            err.message.starts_with("fstat(host /dev/zero) failed"),
            "{}",
            err.message
        );
        let err = host_node_error(sys::DeviceNodeError::Sys(SysError::Unsupported), d);
        assert_eq!(err.code, ErrorCode::Unimplemented);
        let err = host_node_error(sys::DeviceNodeError::NotCharDevice { mode: 0o100_644 }, d);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        let v = err.violation.as_ref().expect("violation record");
        assert_eq!(
            v.audit_path().map(|p| p.as_path()),
            Some(Path::new("/dev/zero"))
        );
    }

    /// CORE-1・#1660: 4 番目（random）の `move_mount` が失敗したら、接続済みの bind を逆順に外し、
    /// 作った 4 つの空ファイルだけを消し、tmpfs と `dev` も片付ける。
    #[test]
    fn core6_sec5_1660_failure_midway_detaches_binds_and_removes_created_targets() {
        take_calls();
        let t = Tmp::new("bind-midway");
        MOVE_MOUNT_SCRIPT.with(|s| {
            *s.borrow_mut() = vec![Ok(()), Ok(()), Ok(()), Err(SysError::Os(sys::EINVAL))];
        });
        let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert!(
            err.message.starts_with("move_mount(dev/random) failed"),
            "{}",
            err.message
        );
        let events = take_events();
        // 逆順: random（未接続。空ファイルだけ消す）→ full → zero → null（外してから消す）→ tmpfs。
        let tail: Vec<String> = events
            .iter()
            .skip_while(|e| !matches!(e, Event::MoveMount { name } if name == "random"))
            .skip(1)
            .map(|e| match e {
                Event::RemoveBindTarget { name } => format!("remove {name}"),
                Event::Umount(p) => {
                    let leaf = Path::new(p)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    format!("umount {leaf}")
                }
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        assert_eq!(
            tail,
            vec![
                "remove random",
                "umount full",
                "remove full",
                "umount zero",
                "remove zero",
                "umount null",
                "remove null",
                "umount dev",
            ]
        );
        assert!(!t.0.join("dev").exists());
        take_calls();
    }

    /// CORE-1・SEC-1・#1660: 名前が既に存在する（`EEXIST`）ときは受け入れず拒否し、既存のエントリは消さない。
    /// この呼び出しが作った空ファイルだけが消える。
    #[test]
    fn core6_sec5_1660_existing_bind_target_is_rejected_and_kept() {
        take_calls();
        let t = Tmp::new("bind-eexist");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        std::fs::write(t.0.join("dev/urandom"), b"keep").unwrap();
        let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(err.stage, IsolationStage::CreateDevices);
        assert!(err.violation.is_none());
        assert_eq!(err.message, "the bind target dev/urandom already exists");
        let events = take_events();
        let removed: Vec<_> = bind_trace(&events)
            .into_iter()
            .filter(|l| l.starts_with("remove "))
            .collect();
        assert_eq!(
            removed,
            vec!["remove random", "remove full", "remove zero", "remove null"]
        );
        for n in ["null", "zero", "full", "random"] {
            assert!(!t.0.join("dev").join(n).exists(), "{n}");
        }
        assert_eq!(std::fs::read(t.0.join("dev/urandom")).unwrap(), b"keep");
        take_calls();
    }

    /// CORE-1・#1660: 新マウント API が無い（`ENOSYS`）カーネルでは `Unimplemented` で拒否し、`mknodat` 等へ縮退しない。
    #[test]
    fn core6_sec5_1660_bind_api_unsupported_is_unimplemented() {
        for open_tree_fails in [true, false] {
            take_calls();
            let t = Tmp::new("bind-enosys");
            if open_tree_fails {
                OPEN_TREE_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Unsupported)]);
            } else {
                MOVE_MOUNT_SCRIPT.with(|s| *s.borrow_mut() = vec![Err(SysError::Unsupported)]);
            }
            let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Unimplemented);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert_eq!(
                err.message,
                "the rootless device bind requires the new mount API (open_tree, move_mount; Linux 5.2 or later)"
            );
            assert!(err.violation.is_none());
            let events = take_events();
            assert_eq!(count(&events, |e| matches!(e, Event::Mknod { .. })), 0);
            assert!(!t.0.join("dev").exists());
            take_calls();
        }
    }

    /// SEC-5・#1660: bind 後の再確認（文字デバイスでない・`rdev` 違い・別マウント）で拒否して巻き戻す。
    #[test]
    fn core6_sec5_1660_post_bind_recheck_mismatch_rolls_back() {
        let ok = BoundObservation {
            is_char: true,
            rdev: sys::makedev(1, 3),
            own_mnt_id: 7,
            after_mnt_id: 7,
        };
        for (obs, msg) in [
            (
                BoundObservation {
                    is_char: false,
                    ..ok
                },
                "the bound device node null does not match 1:3 after bind",
            ),
            (
                BoundObservation {
                    rdev: sys::makedev(1, 5),
                    ..ok
                },
                "the bound device node null does not match 1:3 after bind",
            ),
            (
                BoundObservation {
                    after_mnt_id: 8,
                    ..ok
                },
                "the bound device node null is not the mount created by this call",
            ),
        ] {
            take_calls();
            OBSERVE_BOUND_SCRIPT.with(|s| *s.borrow_mut() = vec![obs]);
            let t = Tmp::new("bind-recheck");
            let err = run_rootless_at(open_root(&t.0).as_fd()).unwrap_err();
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert!(err.violation.is_none());
            assert_eq!(err.message, msg);
            let events = take_events();
            assert_eq!(
                bind_trace(&events).last().map(String::as_str),
                Some("remove null")
            );
            assert_eq!(count(&events, |e| matches!(e, Event::Umount(_))), 2);
            assert!(!t.0.join("dev").exists());
            take_calls();
        }
        assert!(check_bound_node(ok, &DEFAULT_DEVICES[0]).is_ok());
    }

    /// 後始末は、名前が差し替えられていたら（作った空ファイルと別 inode）消さない。
    #[test]
    fn core6_sec5_1660_rollback_keeps_swapped_bind_target() {
        take_calls();
        let t = Tmp::new("bind-swapped");
        std::fs::create_dir(t.0.join("dev")).unwrap();
        let root = open_root(&t.0);
        let dev = sys::open_dir_path_nofollow(Some(root.as_fd()), c"dev").unwrap();
        let created = sys::create_file_excl_at(dev.as_fd(), c"null", 0).unwrap();
        std::fs::rename(t.0.join("dev/null"), t.0.join("dev/null-moved")).unwrap();
        std::fs::write(t.0.join("dev/null"), b"other").unwrap();
        let state = DevState {
            created_dev: None,
            mounted: Some(dev),
            pts: PtsState::default(),
            binds: vec![BoundNode {
                device: &DEFAULT_DEVICES[0],
                target: Some(created),
                mounted: None,
            }],
        };
        roll_back_dev(root.as_fd(), &state);
        assert_eq!(std::fs::read(t.0.join("dev/null")).unwrap(), b"other");
        assert!(t.0.join("dev/null-moved").exists());
        take_calls();
    }

    /// CORE-6・SEC-1（TASK-29 追補・#1659）: rootless の bind（#1660）で検証に使う `sys::HostDeviceNode` の固定表は、
    /// 作成対象の `DEFAULT_DEVICES` と順序込みで同じ `(major, minor)` の集合である。`sys` は上位層に依存しないため
    /// 表を 2 か所に持ち、どちらかだけを変えた（任意の major/minor を足した）ときにここで落とす。
    #[test]
    fn core6_sec1_host_device_node_table_matches_default_devices() {
        let defaults: Vec<(u32, u32)> =
            DEFAULT_DEVICES.iter().map(|d| (d.major, d.minor)).collect();
        let allowed: Vec<(u32, u32)> = sys::HostDeviceNode::ALL
            .iter()
            .map(|n| n.major_minor())
            .collect();
        assert_eq!(
            allowed,
            vec![(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0)]
        );
        assert_eq!(defaults, allowed);
    }
}
