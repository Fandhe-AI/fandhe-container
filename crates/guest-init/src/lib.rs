//! macOS ゲスト VM の initrd に入れる Rust 製 PID 1（MAC-1・MAC-2・TASK-64 追補・#1875・MS-5）。
//!
//! # 役割
//!
//! `fandhe-container-platform-macos` の `Vm::launch` が起動したゲストカーネルが最初に実行する。
//! 責務は次の 4 点に限る（5・6 は試験専用の追加）。
//!
//! 1. `/proc`・`/sys`・`/dev` を mount する。
//! 2. カーネルコマンドラインの `fandhe.virtiofs=<tag>:<mountpoint>:<ro|rw>` を untrusted として復号し、
//!    virtiofs を mount して共有ごとに 1 行を hvc0 へ報告する（[`process::process_directives`]）。
//! 3. 起動完了マーカー [`READY_MARKER`] を出し、以後は停止要求を受けるまで終了しない。ready の後は
//!    `waitpid(-1)` のループで直接の子と再親付けされた孤児を回収し続ける（[`reap`]。MAC-4・CORE-1・
//!    TASK-191・#2269）。回収ループが唯一の waiter で、以後に子を作る呼び出し元は `Child::wait` を使っては
//!    ならない。待ちは `SIGCHLD`・`SIGTERM`・`SIGPWR`（`run` の冒頭でスレッドを作る前にブロック済み）の
//!    `sigtimedwait` で、将来子を作る呼び出し元は exec の前にこのマスクを戻すこと。
//! 4. 協調停止（MAC-4・#2270）: 停止要求（ホストの VZ `requestStop` → 仮想 power button の `KEY_POWER` →
//!    [`power_button`] の監視スレッドが自分へ `SIGPWR`、または `SIGTERM`）で回収ループが戻ると、
//!    [`shutdown`] の手順（全プロセスへ `SIGTERM` → 猶予 → `SIGKILL` → `sync` → `reboot(RB_POWER_OFF)`）を
//!    実行する。ホスト側は猶予内に止まらなければ VZ の強制停止へ切り替える
//!    （`platform-macos::vm::Vm::shutdown`）。
//! 5. （試験専用）予約キー `fandhe.guest-test=virtiofs-io` があり、`fandhe-io` の RW mount が成功したときだけ、
//!    ready の後に共有の read / readdir / write のプローブ行を出す（[`probe`]。MAC-1・IO-5・#1876）。
//!    キーはホストの `reject_reserved_keys` により利用者指定では注入できず、本番の起動では走らない。
//! 6. （試験専用）予約キー `fandhe.guest-test=virtiofs-link` があり、`ro`（RO）・`rw`（RW）の mount が成功した
//!    共有ごとに、ready の後に symlink・ハードリンクの観測行を出す（[`link_probe`]。判定はしない。
//!    MAC-1・SEC-4・#1877・#1374）。
//!
//! # ホストとの契約
//!
//! SSOT はホスト側の `fandhe_container_platform_macos::guest_mount`（指示の書式・報告の書式・定数）。
//! 本 crate は静的なゲストバイナリへバックエンドを入れないため、規則を同じ内容で持ち直し
//! （[`directive`]・[`report`]）、`tests/contract.rs` が dev-dependency 経由で定数・復号結果・報告行の
//! 一致を機械照合する。契約を変えるときはホスト側と本 crate を同時に直す。
//!
//! # 失敗時の方針（fail-closed）
//!
//! 指示に 1 件でも不正があれば 1 件も mount しない。致命的な初期化失敗では [`READY_MARKER`] を出さない。
//! PID 1 が終了するとカーネルが panic するため、どの経路でも終了せず待機する。
//!
//! - `/dev` の devtmpfs の mount が `EBUSY`（既に mount 済み）のときは成功扱いにせず、`/proc` の mount 後に
//!   `/proc/self/mountinfo` を上限つきで読み、`devtmpfs` かつ `nosuid`・`noexec` でなければ
//!   `stage=dev errno=16` を出して停止する（[`mountinfo`]。#2139）。EBUSY は同じ superblock が同じ
//!   mount point に既にある場合に返るため fstype はほぼ devtmpfs で、問題になるのはオプションである
//!   （カーネルの自動 mount は `nosuid`・`noexec` を付けない）。検査に通らなくても console は検査前の `/dev` から
//!   開くため診断の出力は best-effort で、[`READY_MARKER`] が出ないことで fail-closed になる。
//! - panic hook が `stage=panic errno=5` の固定の 1 行を出して待機する（payload・位置は出さない。REPAIR-2）。
//!   hook は unwind でも `panic = "abort"` でも abort より前に呼ばれ戻らないため、将来 profile に
//!   `panic = "abort"` を入れても PID 1 は終了しない。残る経路（hook 内の二重 panic・OOM の
//!   `handle_alloc_error` による abort）ではカーネルが panic し、ホストは [`READY_MARKER`] のタイムアウトで
//!   fail-closed になるが原因は見えない。
//!
//! # unsafe の閉じ込め（REPAIR-9）
//!
//! lib のルートで `unsafe_code` を deny にし、`sys` だけを allow にする。`sys` の外に `unsafe` が入ると
//! コンパイルで落ちる（workspace の `undocumented_unsafe_blocks` が見ない `unsafe extern` ブロックも対象）。
//!
//! # mount 先の固定（MAC-1・SEC-1・#2268・#2080 P2-4）
//!
//! virtiofs の mount 先は文字列パスで検査・mount せず、`/` から要素ごとに `openat(O_PATH|O_DIRECTORY|
//! O_NOFOLLOW|O_CLOEXEC)` で辿った fd を `/proc/self/fd/<n>` として `mount(2)` に渡す（欠けた要素は
//! `mkdirat`、mode 0o755）。検査と mount が同じ fd を指すので、ゲスト内で子プロセスを動かしても差し替えで
//! mount 先はずれない。`/proc/self/fd` の解決は PID 1 自身が先に mount した proc に依る。
//!
//! 残る範囲: `/proc`・`/sys`・`/dev`・基底ディレクトリの作成と mount は他のプロセスが生まれる前に固定パスで
//! 行う。mount 後に試験専用プローブ（`probe`・`link_probe`）が文字列パスで共有へ触れる（本番の起動では
//! 走らない）。mount 後のディレクトリの rename は対象外。実 VM・aarch64 での確認は #1628。
//!
//! # 未実装（REPAIR-3）
//!
//! - EBUSY の分岐（実カーネルでの devtmpfs の二重 mount）と panic hook が PID 1 で待機へ落ちる挙動は CI では
//!   動かせない。単体テストは解析・分類・診断行だけを覆い、実機の VM での確認は #1628 に委ねる（#2139）。
//! - 協調停止: 実装済み（#2270）。残余: 実 VM での `requestStop` の到達（仮想 PL061 GPIO → `gpio-keys` →
//!   `KEY_POWER`。ゲストカーネルに `GPIO_PL061`・`KEYBOARD_GPIO`・`INPUT_EVDEV` が要る）と電源断は未確認で
//!   #1628・#2282（届かなければホストが猶予の後に強制停止する）。ゲスト内のコンテナの停止は `kill(-1)` の
//!   一般手順で、ゲスト内 CLI 経由で supervisor を順に止める手順は G6（#2273）以降。致命的な初期化失敗と
//!   panic hook の後の待機（`idle`）は停止要求に応じず、ホストの期限つきの強制停止に任せる。電源断が失敗した
//!   ときは診断行（`stage=poweroff`）を出し、PID 1 は終了せず回収を続ける。ゲスト内のコンテナ（将来）からの
//!   停止要求の偽装は、ゲスト内の非 root 実行（設計の項目 1）で防ぐ前提（非特権プロセスは PID 1 へ
//!   シグナルを送れない）。
//! - 子プロセスの回収（`waitpid`）: 実装済み（#2269）。`SIGCHLD` 駆動（#2270）で、子がいない間に別スレッドが
//!   作った子も即座に回収する。残余: main スレッド自身の panic の後は回収しない（hook の中で回収すると
//!   二重 panic の余地が生まれる）、実 VM（本物の PID 1・aarch64）での確認は #1628。終了コードの中継
//!   （`on_reaped` の配線）は G6（#2273）。
//! - 静的リンクのビルドと initrd への梱包は `scripts/build-guest-initrd.sh`（`make guest-initrd-build`。#1878）
//!   で行う（梱包までの確認のみ。実機の VM での起動は未確認で #1628）。

#![deny(unsafe_code)]

pub mod cmdline;
pub mod directive;
pub mod link_probe;
pub mod mountinfo;
pub mod power_button;
pub mod probe;
pub mod process;
pub mod reap;
pub mod report;
pub mod shutdown;

#[cfg(target_os = "linux")]
mod init;
// syscall の薄いラッパーの置き場。`unsafe` を許すのはここだけ（#4 の事前承認は `sys` に限る）。
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

#[cfg(target_os = "linux")]
pub use init::run;

/// 起動完了マーカー（初期化に成功し、指示の処理を終えた後に 1 行だけ出す）。
///
/// ホストの `vm_boot` では `FANDHE_CONTAINER_MACOS_VM_READY_MARKER` にこの文字列を指定する。
/// 既定のブートマーカー `Linux version`・報告行の接頭辞・`virtiofs_io` のプローブ接頭辞のいずれとも
/// 一致・包含の関係にない（単体テストで照合）。
pub const READY_MARKER: &str = "fandhe-guest: init ready v1";

// pid と連番だけの名前の一時ディレクトリを残骸に強くする共有部品（oci の結合試験の補助を取り込む。
// REPAIR-12・#3435）。std だけの試験専用モジュールで、静的リンクのゲストバイナリには入らない。
#[cfg(test)]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

// 試験が起こした子プロセスを期限つきで回収する共有補助（core の正本。REPAIR-5・#3410）。実プロセスの
// 試験（Linux のみ）で使う。
#[cfg(all(test, target_os = "linux"))]
#[path = "../../core/tests/support/reap.rs"]
mod test_reap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac1_ready_marker_does_not_collide() {
        assert_eq!(READY_MARKER, "fandhe-guest: init ready v1");
        // vm_boot の既定ブートマーカーと一致・包含の関係にない（validate_marker_pair が panic するため）。
        assert!(!READY_MARKER.contains("Linux version"));
        assert!(!"Linux version".contains(READY_MARKER));
        assert!(!READY_MARKER.starts_with(report::REPORT_PREFIX));
        assert!(!READY_MARKER.starts_with(report::PROBE_NAMESPACE));
        assert!(!READY_MARKER.starts_with(link_probe::LINK_NAMESPACE));
        // 名前空間・報告の接頭辞は互いにどちら向きにも前方一致しない（ホストの走査が誤認しない）。
        let all = [
            report::REPORT_PREFIX,
            report::PROBE_NAMESPACE,
            link_probe::LINK_NAMESPACE,
            READY_MARKER,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert!(i == j || !a.starts_with(b), "{a} / {b}");
            }
        }
    }
}
