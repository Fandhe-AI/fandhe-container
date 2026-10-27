//! macOS ゲスト VM の initrd に入れる Rust 製 PID 1（MAC-1・MAC-2・TASK-64 追補・#1875・MS-5）。
//!
//! # 役割
//!
//! `fandhe-container-platform-macos` の `Vm::launch` が起動したゲストカーネルが最初に実行する。
//! 責務は次の 3 点に限る（4・5 は試験専用の追加）。
//!
//! 1. `/proc`・`/sys`・`/dev` を mount する。
//! 2. カーネルコマンドラインの `fandhe.virtiofs=<tag>:<mountpoint>:<ro|rw>` を untrusted として復号し、
//!    virtiofs を mount して共有ごとに 1 行を hvc0 へ報告する（[`process::process_directives`]）。
//! 3. 起動完了マーカー [`READY_MARKER`] を出し、以後は終了しない。
//! 4. （試験専用）予約キー `fandhe.guest-test=virtiofs-io` があり、`fandhe-io` の RW mount が成功したときだけ、
//!    ready の後に共有の read / readdir / write のプローブ行を出す（[`probe`]。MAC-1・IO-5・#1876）。
//!    キーはホストの `reject_reserved_keys` により利用者指定では注入できず、本番の起動では走らない。
//! 5. （試験専用）予約キー `fandhe.guest-test=virtiofs-link` があり、`ro`（RO）・`rw`（RW）の mount が成功した
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
//! # 未実装（REPAIR-3）
//!
//! - mount 先の検査（`ensure_real_dir`）と文字列パスの `mount(2)` の間には TOCTOU の余地がある。mount 時に
//!   ゲスト内で動くのは PID 1 だけなので差し替える主体がいない。この前提はゲスト内で子プロセス（コンテナ）を
//!   動かした時点で崩れるため、その変更の前に fd 起点の mount（要素ごとの `openat`＋`O_NOFOLLOW` から
//!   `/proc/self/fd/<n>` へ mount、または `open_tree`／`move_mount`）へ移すことを前提条件とする
//!   （#2080・#1905）。`/proc`・`/sys`・`/dev` は他のプロセスが生まれる前に固定パスへ mount する。
//! - EBUSY の分岐（実カーネルでの devtmpfs の二重 mount）と panic hook が PID 1 で待機へ落ちる挙動は CI では
//!   動かせない。単体テストは解析・分類・診断行だけを覆い、実機の VM での確認は #1628 に委ねる（#2139）。
//! - 協調停止: `reboot(2)` 等は呼ばない。VM の停止はホストの VZ の強制停止に任せる（TASK-115）。
//! - 子プロセスの回収（`waitpid`）: 現状は子を作らない。ゲスト内でコンテナを実行する際に実装する。
//! - 静的リンクのビルドと initrd への梱包は `scripts/build-guest-initrd.sh`（`make guest-initrd-build`。#1878）
//!   で行う（梱包までの確認のみ。実機の VM での起動は未確認で #1628）。

#![deny(unsafe_code)]

pub mod cmdline;
pub mod directive;
pub mod link_probe;
pub mod mountinfo;
pub mod probe;
pub mod process;
pub mod report;

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
