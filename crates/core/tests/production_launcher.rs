//! 本番 `ProcessLauncher`（`oci_runtime::ProductionLauncher`）を `create` → `start` 経由で実プロセスに通す結合試験
//! （CORE-1・CORE-2・CORE-5・SEC-1・SEC-5・REPAIR-3・REPAIR-12。TASK-29 追補・#1818）。
//!
//! 既存の `oci_start.rs` / `oci_lifecycle.rs` は launcher が模擬で、本番 launcher を実プロセスで通した試験が
//! 無かった（`rootless.rs`・`rootless_file_owner.rs` も #2246 で本番 launcher 経由へ移行済み）。
//! 本試験は `start` が検証して組み立てた `LaunchSpec` を本番 launcher が中間プロセス経由で PID 1 として
//! 起動するところまでを、親から具体値で照合する。
//!
//! # 照合項目
//! - シナリオ A（正常起動。非 root）: `StartedContainer` の状態が Running で pid が `process().pid()` と一致する。
//!   ホストの `/proc/<pid>/status` の `NSpid` 末尾が 1。コンテナ内プローブ（stdout の固定語彙の行）で、
//!   PID 1・hostname・既定 `/dev` ノード 6 種の種別と `rdev`・symlink 4 本・`/dev/null` 書き込み・`/dev/zero` 読み出し・
//!   `NoNewPrivs: 1`・`Seccomp: 2`（制限ステージ適用の間接証拠）を照合する。cgroup はホストの `/proc/<pid>/cgroup` と
//!   プローブ内の `/proc/self/cgroup` が、作成した子 cgroup と完全一致する。終了後は回収され `/proc/<pid>` が消える
//! - シナリオ B（起動失敗で何も残らない。#1817）: rootfs から `proc/` を除いて pre-pivot 段を失敗させ、`start` が
//!   `Err`・状態が Created に戻る・`last_launch_may_have_left_process() == false`・`confirm_no_process` が `Ok`・
//!   テストプロセスの子が 0 件であることを照合する
//! - シナリオ C（拒否に副作用が無い）: 補助スレッドが生きている状態の `start` が `FailedPrecondition`（単一スレッド要求。
//!   CORE-1）で拒否され、状態が Created のままで子が作られないことを照合する
//! - シナリオ D（bind mount。#1915）: `mounts[]` に `/data` の bind（`rw`）を指定して start し、コンテナ内プローブが
//!   `/data` へ固定の内容を書く。親はホスト側の元ディレクトリに同じ内容のファイルが現れることを完全一致で、
//!   mountinfo 上の `/data` のオプションに `rw`・`nosuid`・`nodev` が含まれることを照合する
//! - シナリオ E（状態ルートの bind 拒否。#2066・SEC-1）: 状態ルート自身とその symlink 別名を bind の元にした start が
//!   `InvalidArgument` で拒否され、状態が Created のまま子が残らないことを照合する
//! - シナリオ F（保護パスと重なる bind 先の拒否。SEC-1・SEC-2・OCI-4・#2015）: `mounts[]` の bind 先を `linux.readonlyPaths` にも
//!   足した config の start が fork 前に `InvalidArgument` で拒否され、状態が Created のまま子が残らないことを照合する。
//!   Landlock の Mount 識別子照合（CORE-5・#2071）の拒否理由は単体試験が照合する（記録後の差し替えは config では作れない）
//! - シナリオ G（devtmpfs の bind 拒否。#2129・SEC-1）: ホストの `/dev`（fstype `devtmpfs`。`f_type` は tmpfs と同じで見分けられない）を
//!   `bind` / `rbind` で元にした start が、付け替えた自分のマウントの mountinfo の fstype 名で拒否される。起動は失敗し、
//!   状態が Created のまま子が残らず、後始末で bind 先（rootfs 内の `/data`）が残らないことを照合する
//! - シナリオ H（start 後の状態ルート移動。#2129・SEC-1）: start が状態ルートを固定した後、launcher が子を作る前に
//!   状態ルートを別名へ改名して同じパスに別の inode の複製を置くと、適用の段が記録パスを辿り直して食い違いを検出し fail-closed で拒否する。
//!   状態ルートが動かない場合に受理される側はシナリオ D が担う。状態が Created のまま子が残らず、bind 先も残らないことを照合する
//! - シナリオ I（範囲写像。`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ。CORE-6・SEC-5・#2009）: `RootlessSubordinateIds` の
//!   launcher（`SubordinateIdSource::system(USER)`）で start し、ホストから読んだ PID 1 の `uid_map` / `gid_map` が
//!   `/etc/subuid`・`/etc/subgid` の範囲写像（コンテナ 0 → 自 ID、コンテナ 1 以上 → subuid / subgid の範囲の先頭）と
//!   完全一致することを照合する。opt-in 時に前提（`uidmap`・自ユーザーの subuid / subgid 行・`USER`）が無ければ失敗とする。
//!   root で実行された場合は、この launcher の構築が `PermissionDenied`（SEC-5）で拒否されることだけを照合する
//! - シナリオ S の範囲写像版（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ。CORE-6・SEC-5・SUP-12・#2628）: ホストのファイルを
//!   `InjectedContent::from_file`（封印 memfd）にした注入を `RootlessSubordinateIds` の launcher で start し、注入の
//!   内容とモードがコンテナ内で具体値で一致することを照合する（呼び出し元のメモリ由来の内容は launcher が拒否する。
//!   holder のメモリに secret が無いことは `rootless_holder_memory` が照合する）。成功時は
//!   `production_launcher: injected secret reached the container under subordinate id mapping (scenario=S-subordinate)` を出す
//! - シナリオ Y（読み取り専用 rootfs。非 root。CORE-5・SEC-1・SUP-12・#2767）: `root.readonly=true` を start し、rootfs への新規作成・
//!   既存ファイルへの書き込み・mkdir がすべて `EROFS`（30。Landlock だけが止めた `EACCES` は失敗）、`/` の per-mount オプションに
//!   `ro` と `nodev`、`/proc` に `ro` が無い（非再帰）こと、`--tmpfs`（`/run`）・`/dev/shm`・`/dev/null`・rw の bind への書き込みが
//!   成功しホスト側に内容が現れることを照合する。成功時は
//!   `production_launcher: readonly rootfs refused writes with EROFS; tmpfs, /dev, bind writable (scenario=Y` を出す
//! - シナリオ V（sysctls。CRI-2・CORE-3・#2670）: `linux.sysctl` の `kernel.shmmax` がコンテナ内の IPC namespace で指定値になり、
//!   ホスト側の値が変わらないことを照合する。成功時は `production_launcher: sysctls applied (scenario=V` を出す
//! - シナリオ J（exec 後の capability と seccomp の実効。#2012・SEC-1・CORE-5）: コンテナ内プローブ（`--with-restrictions`）の
//!   `/proc/self/status` が `CapInh`・`CapAmb` = 0、`CapPrm`・`CapEff`・`CapBnd` = `0x0000_0000_a804_25fb`（OCI 既定の 14 個。
//!   公開 API の `OCI_DEFAULT_CAPABILITIES` から組んだマスクとリテラルの両方と照合）で、ホストから見た同プロセスの
//!   `/proc/<pid>/status` も同値であることを照合する。seccomp は、`mount(2)` が `EPERM`（`escape_probe_mount`。capability 不足でも
//!   `EPERM` になり得るため網羅確認）、許可された `openat` / `read`（`/proc/thread-self/status`）が成功する対照、
//!   `NoNewPrivs: 1`・`Seccomp: 2` を照合する
//! - シナリオ K（exec 後の seccomp の識別的な拒否。#2012・SEC-2・CORE-5）: コンテナ内プローブ（`--seccomp-kill <name>`）が
//!   `unshare` / `ptrace` / `kexec_load` を 1 件ずつ別の start で発行し、`ProcessExit::Signaled(31)`（SIGSYS。
//!   `SECCOMP_RET_KILL_PROCESS`）で終了することを照合する。フィルタが無ければ `unshare(0)` は成功して戻るため識別的になる
//! - シナリオ P（名前だけの `process.args[0]`。#2314・OCI-1・TASK-55 追補）: `args[0]` が `probe`（`/` 無し）、`process.env` の
//!   `PATH` が `/nonexistent:/opt/bin:/usr/local/bin` で、`/opt/bin/probe` は実行ビット無し・`/usr/local/bin/probe` が実行可能
//!   （`/probe` は削除して絶対パスの経路を断つ）。pivot 後に解決されて PID 1 として起動し、コンテナ内プローブが `READY` を
//!   出して終了コード 7（`ProcessExit::Exited(7)`）で終わることを照合する。`PATH` のどこにも無い名前は `start` の失敗
//!   （状態は Created のまま）か終了コード 127 で、成功起動にならず子も残らない
//! - シナリオ Q（SIGSYS 終了の `exit_signal` 補助記録の配送。#2236・SEC-4・ESC-06・REPAIR-5。issue 本文の「シナリオ I」にあたる）:
//!   単一スレッドの間に作った `ControlAuditRelay` を launcher の回収点の記録先（`exit_audit_sink`）にだけ渡し、start の後に補助スレッドを
//!   立てて複数スレッドにした状態で `--seccomp-kill unshare` のコンテナの終了（`Signaled(31)`）を回収する。`<状態ルート>/@audit.log` に
//!   当コンテナの `layer=exit_signal` の行がちょうど 1 行で、`signal` 31・`target_pid` = コンテナの PID・`syscall`/`arch` は null、
//!   再度の `wait` / `terminate` の後も 1 行のままであることを照合する。成功行の前に
//!   `production_launcher: exit_signal recorded once via audit relay (scenario=Q)` を出す
//! - シナリオ U（`rslave` の bind。#2669・OCI-4・CRI-2・SEC-1）: 元（一時ディレクトリ）が属するホスト側のマウントの伝播を
//!   `/proc/self/mountinfo` で先に読む。`shared:` か `master:` があれば `options: ["rbind", "rslave"]` の start が成功し、コンテナ内の
//!   mountinfo で bind 先に `master:` があり `shared:` が無いことを照合する（`private` の bind は `master:` が無いシナリオ D で照合済み）。
//!   どちらも無ければ（ホスト側が private）start が `FailedPrecondition` で失敗し、状態が Created のまま子が残らず、bind 先が
//!   rootfs に作られないことを照合する。どちらの分岐でも `production_launcher: scenario=rslave-bind host=<..> ...` を出す。
//!   ホスト側で後からマウントした内容がコンテナ内に見えること自体は root が要るため本試験では確かめない
//!   （`docs/verification/bind-rslave-propagation.md`）
//! - シナリオ S（launch 経路の entrypoint 系違反の記録。#2624・SEC-4・SUP-6）: 試験バイナリ自身のディレクトリを bind し、
//!   `args[0]` をその中の試験バイナリ（PID 1 の `/proc/self/exe` と同一の inode）にした start が `PermissionDenied` で失敗し、
//!   状態が Created のまま子が残らず、launcher の記録先に層 `entrypoint`・`reason=entrypoint_is_runtime_binary`・当コンテナの
//!   ID・パスなしのレコードがちょうど 1 件あることを照合する。成功行の前に
//!   `production_launcher: entrypoint violation recorded once and launch refused (scenario=S)` を出す
//! - シナリオ X（launch 経路の entrypoint の実行失敗。#2763・SEC-4・CORE-5・REPAIR-12）: 3 ケースの `start` が、期待する ErrorCode で
//!   失敗し、状態が Created のまま・`last_launch_may_have_left_process() == false`・`confirm_no_process` が `Ok`・子が残らず、
//!   専用の記録先に監査の記録が 0 件（違反ではない失敗は記録しない）であることを照合する。メッセージは `Exec` 段の固定文言で、
//!   `R` の前後の経路は公開 API から区別できない（成功行の `phase` は設計上の経路の表示）。
//!   (1) ローダ欠落: rootfs 内の `PT_INTERP` のローダを消すと `NotFound`。ローダは `R` の前の `prepare_exec_child`
//!   （`pin_interpreter`）で `O_PATH` で開かれ、不在はそこで拒否されるため、経路は `R` の前（`E <step> NOT_FOUND`）である。実カーネルで
//!   `R` の後に `ENOENT` を決定的に起こす手段は無く、`R` の後の `NOT_FOUND` は単体試験
//!   `sec4_2716_launch_fails_on_execveat_failure_after_ready_and_on_silence_after_ready` が担う。
//!   (2) 0644: 実行ビットの無いエントリポイントは launch では事前検査が無く、`R` の後の `execveat` が `EACCES` →
//!   `PermissionDenied`（`X PERMISSION_DENIED`）。(3) ゴミのバイト列: `#!` でも ELF でもない 0755 のファイルは `execveat` が
//!   `ENOEXEC` → `InvalidArgument`（`X INVALID_ARGUMENT`）。各ケースの固有の成功行
//!   `production_launcher: scenario=exec-failure case=<..> code=<..> phase=<..> ...` を CI が完全一致で照合する
//! - シナリオ I・O の拡張（補助グループ。OCI-1・SEC-5・CORE-6・#2667）: 範囲写像（`FANDHE_CONTAINER_TEST_ID_HELPER=1`）で
//!   `process.user` 1000:1000・`additionalGids` [3000, 2000] を指定すると、コンテナ内の `Groups:` が `2000,3000`、ホストから見た
//!   `/proc/<pid>/status` の `Groups:` が subgid 先頭 + 1999 / + 2999 になる（成功行 `scenario=groups-applied gids=2000,3000
//!   host_gids=<a>,<b>`）。単一 ID 写像で 0/0 に `additionalGids` [0] を指定した start は fork の前に `FailedPrecondition` で
//!   拒否され、状態は Created のまま子が残らない（成功行 `scenario=groups-single-id-refused`）
//! - シナリオ W（pod の user・ipc namespace への join。#2674・CRI-2・CORE-3・SEC-1・SEC-5）: コンテナ A を start し、B の
//!   `linux.namespaces` の `user`・`ipc` に `/proc/<A の pid>/ns/{user,ipc}` の path を入れて start する。ホストから読んだ B の
//!   `ns/user`・`ns/ipc` が A と同一で、`ns/pid`・`ns/mnt`・`ns/uts` は異なることを照合する。否定として、試験プロセス自身の
//!   namespace を指す path は fork の前に `PermissionDenied` で拒否され、状態は Created のまま子が残らない。成功行の前に
//!   `production_launcher: pod ipc namespace joined (scenario=W ...)` を出す
//! - root で実行された場合: 主経路は非 root（SEC-5）。launch が拒否され、状態が Created に戻り、子が残らないことだけを
//!   照合する（コンテナ内 root をホスト root へ写す起動は試さない）
//!
//! # 必要環境
//! - Linux 6.12 以上（Landlock ABI 6 以上。満たさないと launcher が起動を拒否するため、本試験は失敗する。CORE-5）
//! - 非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=0` 等の緩和が要る場合がある）
//! - 非特権ユーザーに委譲された cgroup v2 サブツリー（`DelegatedCgroup::detect` が成功すること）
//! - 動的リンクのためホストの共有ライブラリを rootfs へコピーする（ネットワークは不要）
//!
//! # 実機前提テストとしての分離
//! 上記の環境は GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行する（ci.md「実機前提
//! テスト」。既定集合で動くはずの試験を移したものではない）。実行された場合は user namespace の拒否・Landlock ABI
//! 不足・cgroup の委譲無しを含むあらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。同一 cgroup に他
//! プロセスがいると `prepare` が失敗するため、`cargo` を経由せず委譲スコープの中でビルド済みバイナリを直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test production_launcher --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/production_launcher-XXXX> --ignored
//! ```
//!
//! 前提（委譲 cgroup・範囲写像の `USER`・`uidmap`・subuid / subgid の自ユーザー行）の欠如は、1 行目
//! `production_launcher: PRECONDITION FAILED (test environment, not a cgroup delegation regression)` /
//! `(... not a subordinate id mapping regression)` で失敗する（分類は `tests/support/precondition.rs`。#2888・REPAIR-12）。
//!
//! シナリオ I（範囲写像）は `uidmap` パッケージ（`/usr/bin/newuidmap`・`/usr/bin/newgidmap`）と `/etc/subuid`・
//! `/etc/subgid` の自ユーザー行が要るため、`FANDHE_CONTAINER_TEST_ID_HELPER=1` を付けた時だけ実行する。実行時は成功行の前に
//! `production_launcher: subordinate id mapping verified (uid extents=N, gid extents=M)` を出す。
//!
//! シナリオ N（Loopback モード。NET-6・CORE-6・SEC-1・#3064）は `LaunchNetworkMode::Loopback` の起動で、コンテナ内プローブが出す
//! netns の識別子がホストと異なること・`/proc/self/net/dev` が `lo` とフォールバックトンネルだけであること・127.0.0.1 の自己宛て
//! UDP が届くこと（`lo` が down だと受信が期限切れになる。#2077）と、終了後に netns の pin（nsfs のマウント・他プロセスの
//! `ns/net`）が残らないことを照合し、`production_launcher: network loopback isolated lo up and self delivery ok; no netns pin
//! after terminate (scenario=N)` を出す。範囲写像の経路は `(scenario=N-subordinate)`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）。
//!
//! シナリオ Z（Host モードの netns 素性の同期点。NET-6・SEC-1・SEC-4・#3206）は `LaunchNetworkMode::Host` の起動で、exec 直前の
//! 同期点が受理することと（コンテナ内の netns の識別子がホストと同じ）、試験用に基準を実在しない (dev, ino) へ差し替えた
//! 起動が `FailedPrecondition`（メッセージは launcher の固定文言 `container launch failed in the NetnsVerify stage`。違反の理由は
//! 監査記録が担う）で拒否され、監査 sink に段 `netns_verify`・理由 `netns_identity_mismatch` の記録が 1 件残り、状態が Created のまま
//! 子が残らないことを照合する。成功行は `production_launcher: network host netns sync accepted; forged baseline rejected
//! with audit and no process (scenario=Z)`。Loopback の拒否は実機で作れない（子の netns は起動の時点まで未知）ため、
//! `judge` と立て替えの PID 1 を使う単体試験が受け持つ。
//!
//! シナリオ A-attach（Attachable モード。rootless の pasta 構成向けの同期点。NET-9・CORE-6・SEC-1・REPAIR-5・#1939）は
//! `LaunchNetworkMode::Attachable` とフック（`NetnsAttachHook`）の組で起動する。フックは受け取った netns・user namespace の fd の
//! 素性がホストと異なること（`/proc/self/ns/{net,user}` との比較）と、合図の前（フックの中。約 200 ms 待つ）に PID 1 が exec して
//! いないこと（子の `/proc/<pid>/status` の `Name:` が exec 後のエントリ名 `probe` でない）を確かめ、Ok を返す。受理の後は
//! コンテナ内プローブの `NETNS` がフックで受けた netns と一致しホストと異なること、`NETDEV_LO=true`・`NETDEV_EXTRA=none`・
//! `UDP_SELF=ok` を照合する。拒否の側は Err を返すフックで起動し、`start` の code が保たれ、メッセージが launcher の固定文言
//! `container launch failed in the NetnsAttach stage` で、状態が Created のまま子が残らないことを照合する。成功行は
//! `production_launcher: network attachable netns handed over before exec; hook failure left no process (scenario=attachable)`。
//! 範囲写像の経路は `(scenario=attachable-subordinate)`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）。
//!
//! 成功時の最終行: `production_launcher: pid1, default /dev nodes, landlock evidence, cgroup join verified; failed
//! launch left no process; bind mount visible on host; post-exec capabilities and seccomp verified (root=false)`（root 実行時は拒否のみ照合する旨の別の行）。
//!
//! # 既知の制約（REPAIR-3）
//! - Landlock の適用は、コンテナ内で `NoNewPrivs`・`Seccomp` を読む間接証拠に留まる。パス単位の拒否を直接観測する
//!   には `core` の公開 API の追加が要るため、本試験の範囲外（`landlock_implicit_dev` 等が単体で観測している）。
//!   capability と seccomp の実効はシナリオ J・K が exec 後のプロセスで直接照合する
//! - seccomp の識別は、シナリオ J の exec 後の `kcmp` の `EPERM`（test 限定の入口 `probe_denied_syscalls_for_test`。
//!   適用前の `kcmp` 対照は親側で要求し、満たさなければ前提欠如として失敗（1 行目 `production_launcher: PRECONDITION FAILED (test environment ...)`・#2788）とシナリオ K の SIGSYS が担う。`mount` の `EPERM` は網羅確認
//! - bind 以外の `mounts[]` の種類、`ro` の bind の実機での `EROFS` の観測（ルール生成と適用の段は #1917 で実装済み、実機の確認は #1916）、段ごとの個別観測（#1916）、`linux.resources`、
//!   supervisor 経由の起動（#1819）は対象外
//! - 実機での実行結果の記録は #1621（Phase 3 の分離系結合試験の実機実行。人間担当）

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("production_launcher: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("production_launcher: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // 子（コンテナ内）は同じバイナリを `--container-probe` で再実行したもの。
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
        return;
    }
    // 前提欠如の分類の自己照合（既定のテスト集合でも常に走る。#2788・REPAIR-12）。
    linux::self_check_precondition();
    real_entry::precondition::self_check();
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "production_launcher: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

// rootfs 構築の部品（`mkdir`・`install_binary_at`）を rootless 系の試験と共有する（#2246・REPAIR-1）。
// 本試験が使うのはその 2 つだけで、直接ステージ経路の部品は `seccomp` 専用、報告の部品は rootless 系専用のため、
// 未使用になる項目は real_entry.rs 側で個別に理由つきの dead_code 抑止を付けている（モジュール全体には抑止しない）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/real_entry.rs"]
mod real_entry;

#[cfg(target_os = "linux")]
#[path = "support/proc_status.rs"]
mod proc_status;

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use super::{real_entry, scratch_root};
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AUDIT_LOG_FILE_NAME, AuditLayer, AuditRecord, AuditSink, ControlAuditRelay, FileAuditSink,
    };
    use fandhe_container_core::capabilities::OCI_DEFAULT_CAPABILITIES;
    use fandhe_container_core::cgroups::{CgroupName, ContainerCgroup};
    use fandhe_container_core::exec::{
        EscapeSyscallProbe, IsolationPrivilege, ProbeOutcome, SeccompProbeRecord,
        escape_probe_mount, probe_denied_syscalls_for_test, probe_escape_syscall,
        probe_kcmp_self_for_test,
    };
    use fandhe_container_core::injected_files::{
        InjectedContent, InjectedFileMode, InjectedFileSet, InjectedFileSpec,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        AttachableNamespaces, LaunchIpcMode, LaunchNetworkMode, LaunchOptions, NetnsAttachHook,
        ProcessExit, ProcessLauncher, ProductionLauncher, StartTimeouts, SubordinateIdSource,
        create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::tmpfs::{TmpfsMountSet, TmpfsMountSpec};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateStore, TraitError,
    };
    use serde_json::json;

    /// launcher が子を作る直前（`cgroup_join_source` の呼び出し時。start の検証より後）に 1 回だけ実行する処理
    /// （シナリオ H が状態ルートを改名する。#2129）。
    type PreSpawnHook = Box<dyn FnOnce() + Send>;
    static PRE_SPAWN_HOOK: std::sync::Mutex<Option<PreSpawnHook>> = std::sync::Mutex::new(None);

    /// コンテナ内の hostname（config と照合する固有値）。
    const HOSTNAME: &str = "fandhe-prod-launcher";
    /// プローブが `READY` を出した後に待ち続ける（親が terminate するまで生存させる）。
    const PROBE_READY: &str = "READY";
    /// シナリオ D でコンテナ内が bind 先へ書く固定の内容（親がホスト側の同名ファイルと完全一致で照合する）。
    const BIND_CONTENT: &str = "written inside the container\n";
    /// シナリオ D の bind 先のコンテナ内パスと、書くファイル名。
    const BIND_DEST: &str = "/data";
    const BIND_FILE: &str = "from-container";
    /// シナリオ S（起動オプション。SUP-12・CORE-5・SEC-1・#2625）の注入ファイルのコンテナ内パス・内容（ダミー値）・モード。
    const LO_SECRET_PATH: &str = "/secrets/token";
    const LO_SECRET_CONTENT: &str = "dummy-secret-for-launch-options-test";
    const LO_SECRET_MODE: u32 = 0o440;
    /// シナリオ S で指定する tmpfs のコンテナ内パス。
    const LO_TMPFS_DEST: &str = "/run";
    /// シナリオ Y（読み取り専用 rootfs。#2767）: 試験が rootfs に先に置く既存ファイル・内容と、rw の bind に書く内容。
    const RO_MARKER_FILE: &str = "ro-marker";
    const RO_MARKER_CONTENT: &str = "ro-marker-original\n";
    const RO_DATA_FILE: &str = "y";
    const RO_DATA_CONTENT: &str = "written-to-rw-bind-under-readonly-root\n";
    /// 1 行の長さの上限（無制限確保を避ける。REPAIR-5 と同趣旨）。
    const LINE_MAX: u64 = 4096;
    /// 受け取る行数の上限。
    const LINES_MAX: usize = 256;

    /// 1 件の待ちの上限。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（未設定・不正値は 10 秒）。`StartTimeouts` が
    /// `START_TIMEOUT_MAX`（600 秒）以下を要求するため 295 秒に丸める。
    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s >= 1)
            .map_or(10, |s| s.min(295));
        Duration::from_secs(secs)
    }

    fn timeouts() -> StartTimeouts {
        let t = timeout();
        StartTimeouts::new(t, t, t).expect("start timeouts")
    }

    fn is_root() -> bool {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    /// 適用前の kcmp 対照の分類（#2788・CORE-5・SEC-4・REPAIR-12。純関数で自己照合する）。
    #[derive(Debug, PartialEq)]
    enum KcmpPrecondition {
        Ok,
        /// 外側の環境が kcmp を errno で拒否している（試験環境の問題で、フィルタの回帰ではない）。
        Denied {
            errno: i32,
        },
        /// 判定不能（`Unsupported`・`Failed`）。前提欠如とは断定しない。
        Unknown,
    }

    fn classify_kcmp_before(outcome: ProbeOutcome) -> KcmpPrecondition {
        match outcome {
            ProbeOutcome::Ok => KcmpPrecondition::Ok,
            ProbeOutcome::Errno(errno) => KcmpPrecondition::Denied { errno },
            ProbeOutcome::Unsupported | ProbeOutcome::Failed => KcmpPrecondition::Unknown,
        }
    }

    /// 前提欠如の panic メッセージ（1 行目で前提欠如と回帰を判別でき、値から決まるヒントだけを添える）。
    fn precondition_message(errno: i32, seccomp_before: &str) -> String {
        let hint = match (errno, seccomp_before) {
            (1, "0") => "kcmp is denied by something other than seccomp (e.g. an LSM)",
            (1, _) => {
                "an outer seccomp filter denies kcmp (e.g. Docker's default seccomp profile under make docker-ci)"
            }
            (38, _) => "the kernel does not provide kcmp (CONFIG_KCMP)",
            _ => "the environment denies kcmp",
        };
        format!(
            "production_launcher: PRECONDITION FAILED (test environment, not a seccomp filter regression): \
             kcmp(self, self, KCMP_VM) was denied with errno {errno} before the built-in seccomp stage \
             (Seccomp: {seccomp_before}).\n\
             hint: {hint}.\n\
             Run it on the host: cargo test -p fandhe-container-core --test production_launcher --no-run, then \
             systemd-run --user --scope -p Delegate=yes <binary> --ignored. See AGENTS.md production_launcher."
        )
    }

    /// 分類とメッセージの自己照合（`main` から既定集合でも毎回走らせる。#2788）。
    pub fn self_check_precondition() {
        assert_eq!(classify_kcmp_before(ProbeOutcome::Ok), KcmpPrecondition::Ok);
        assert_eq!(
            classify_kcmp_before(ProbeOutcome::Errno(1)),
            KcmpPrecondition::Denied { errno: 1 }
        );
        assert_eq!(
            classify_kcmp_before(ProbeOutcome::Unsupported),
            KcmpPrecondition::Unknown
        );
        assert_eq!(
            classify_kcmp_before(ProbeOutcome::Failed),
            KcmpPrecondition::Unknown
        );
        let msg = precondition_message(1, "2");
        assert_eq!(
            msg.lines().next(),
            Some(
                "production_launcher: PRECONDITION FAILED (test environment, not a seccomp filter regression): kcmp(self, self, KCMP_VM) was denied with errno 1 before the built-in seccomp stage (Seccomp: 2)."
            )
        );
        assert!(msg.contains("--ignored"), "{msg}");
        assert!(msg.contains("make docker-ci"), "{msg}");
        assert!(precondition_message(38, "0").contains("CONFIG_KCMP"));
    }

    /// `/proc/<x>/status` 形式のファイルから、`key` で始まる行の値（key の後ろ）を返す。
    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    /// 呼び出しプロセスの子（全スレッド分）の pid 一覧。
    fn children_of_self() -> Vec<String> {
        let mut out = Vec::new();
        let tasks = std::fs::read_dir("/proc/self/task").expect("read /proc/self/task");
        for t in tasks {
            let t = t.expect("task entry");
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(s.split_whitespace().map(str::to_string));
            }
        }
        out
    }

    /// `cond` が真になるまで `timeout()` までポーリングする（固定 sleep に頼らない）。
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork の前提。join 済みスレッドの消滅は僅かに遅れ得る）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch"
        );
    }

    // ----- コンテナ内プローブ ------------------------------------------------------------------------------

    /// rdev の major（glibc の `gnu_dev_major`）。
    fn dev_major(rdev: u64) -> u64 {
        ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)
    }

    /// rdev の minor（glibc の `gnu_dev_minor`）。
    fn dev_minor(rdev: u64) -> u64 {
        (rdev & 0xff) | ((rdev >> 12) & !0xff)
    }

    /// コンテナ内で動くプローブ。観測値を `KEY value` 形式の固定語彙で stdout へ出し、`READY` の後は親が
    /// 終了させるまで待つ。
    pub fn probe() {
        let mut out = std::io::stdout();
        let mut emit = |line: String| {
            writeln!(out, "{line}").expect("write probe line");
            out.flush().expect("flush probe line");
        };
        emit(format!("PID {}", std::process::id()));
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        emit(format!("HOSTNAME {hostname}"));
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        emit(format!("CGROUP {cgroup}"));
        let field = |key: &str| {
            status_field("/proc/self/status", key).unwrap_or_else(|| "missing".to_string())
        };
        emit(format!("NONEWPRIVS {}", field("NoNewPrivs:")));
        emit(format!("SECCOMP {}", field("Seccomp:")));
        for name in ["null", "zero", "full", "random", "urandom", "tty"] {
            let line = match std::fs::symlink_metadata(format!("/dev/{name}")) {
                Ok(m) if m.file_type().is_char_device() => {
                    format!(
                        "DEV {name} c {}:{}",
                        dev_major(m.rdev()),
                        dev_minor(m.rdev())
                    )
                }
                Ok(_) => format!("DEV {name} not-char"),
                Err(e) => format!("DEV {name} error:{:?}", e.kind()),
            };
            emit(line);
        }
        for name in ["fd", "stdin", "stdout", "stderr"] {
            let target = std::fs::read_link(format!("/dev/{name}")).map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |p| p.display().to_string(),
            );
            emit(format!("LINK {name} {target}"));
        }
        for name in ["pts", "shm"] {
            emit(format!(
                "DIR {name} {}",
                Path::new(&format!("/dev/{name}")).is_dir()
            ));
        }
        let wrote = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .and_then(|mut f| f.write_all(b"x"));
        emit(format!(
            "DEVNULL_WRITE {}",
            wrote.map_or_else(|e| format!("error:{:?}", e.kind()), |()| "ok".to_string())
        ));
        let mut buf = [0u8; 16];
        let read = std::fs::File::open("/dev/zero").and_then(|mut f| f.read(&mut buf));
        emit(format!(
            "DEVZERO_READ {}",
            read.map_or_else(|e| format!("error:{:?}", e.kind()), |n| n.to_string())
        ));
        // シナリオ L〜O・I の拡張(OCI-1・SEC-5): 作業ディレクトリと実・実効・保存・FS の uid / gid。
        let cwd = std::fs::read_link("/proc/self/cwd").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |p| p.display().to_string(),
        );
        emit(format!("CWD {cwd}"));
        for (name, key) in [("UIDS", "Uid:"), ("GIDS", "Gid:")] {
            emit(format!(
                "{name} {}",
                field(key).split_whitespace().collect::<Vec<_>>().join(",")
            ));
        }
        // シナリオ I の拡張（補助グループ。OCI-1・SEC-5・CORE-6・#2667）: `Groups:` をカンマ区切りで出す（空なら空文字）。
        emit(format!(
            "GROUPS {}",
            field("Groups:")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(",")
        ));
        // シナリオ K（exec 後の seccomp の識別的な拒否。#2012）: 禁止 syscall を 1 件発行する。フィルタが効いていれば
        // SIGSYS で終了して戻らない。戻った場合（フィルタ欠落）は固定語彙の行を出して正常終了し、親が失敗にする。
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--seccomp-kill") {
            let name = args.get(i + 1).map_or("missing", String::as_str);
            let which = match name {
                "unshare" => EscapeSyscallProbe::Unshare,
                "ptrace" => EscapeSyscallProbe::Ptrace,
                "kexec_load" => EscapeSyscallProbe::KexecLoad,
                other => panic!("unknown seccomp-kill probe {other}"),
            };
            emit(format!("SECCOMP_KILL_ATTEMPT {name}"));
            let outcome = probe_escape_syscall(which);
            emit(format!("SECCOMP_KILL_RETURNED {outcome:?}"));
            std::process::exit(0);
        }
        // シナリオ J（exec 後の capability と seccomp の実効。#2012）。
        if args.iter().any(|a| a == "--with-restrictions") {
            for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
                emit(format!("CAP {key} {}", field(&format!("{key}:"))));
            }
            // PID 1 かつ `Seccomp: 2` のときだけ発行される安全な入口。`mount` は seccomp が `EPERM` で拒否する。
            emit(format!("SECCOMP_MOUNT {:?}", escape_probe_mount()));
            // exec 後の PID 1 の記録（`kcmp` の errno を識別的に照合する。#2234）。入口は PID 1 かつ `Seccomp: 2` でだけ発行する。
            match probe_denied_syscalls_for_test() {
                Ok(rec) => {
                    for line in rec.render().lines() {
                        emit(format!("SECCOMP_RECORD {line}"));
                    }
                }
                Err(e) => emit(format!("SECCOMP_RECORD_ERROR {:?}", e.code)),
            }
            // 許可された syscall（`openat`・`read`）の対照。拒否一辺倒のフィルタ（全拒否）と区別する。
            let control = std::fs::read_to_string("/proc/thread-self/status");
            emit(format!(
                "SECCOMP_CONTROL {}",
                control.map_or_else(|e| format!("error:{:?}", e.kind()), |_| "ok".to_string())
            ));
        }
        // シナリオ N(Loopback モード。NET-6・CORE-6・#3064): 新しい netns の識別子・インターフェース・自己宛て UDP 配送を出す。
        if args.iter().any(|a| a == "--net-loopback") {
            net_loopback_probe(&mut emit);
        }
        // シナリオ V(sysctls の適用。#2670・CRI-2・CORE-3): コンテナ内の IPC namespace の `kernel.shmmax` を出す。
        if args.iter().any(|a| a == "--with-sysctl") {
            let v = std::fs::read_to_string("/proc/sys/kernel/shmmax").map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |s| s.trim().to_string(),
            );
            emit(format!("SYSCTL_SHMMAX {v}"));
        }
        // シナリオ D（bind mount。#1915）: bind 先へ固定の内容を書き、mountinfo 上のマウントオプションを出す。
        if std::env::args().any(|a| a == "--with-bind") {
            let wrote = std::fs::write(format!("{BIND_DEST}/{BIND_FILE}"), BIND_CONTENT);
            emit(format!(
                "BIND_WRITE {}",
                wrote.map_or_else(|e| format!("error:{:?}", e.kind()), |()| "ok".to_string())
            ));
            let opts = std::fs::read_to_string("/proc/self/mountinfo").map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |info| {
                    info.lines()
                        .filter_map(|l| {
                            let f: Vec<&str> = l.split_whitespace().collect();
                            (f.get(4).copied() == Some(BIND_DEST))
                                .then(|| f.get(5).copied().unwrap_or("").to_string())
                        })
                        .next_back()
                        .unwrap_or_else(|| "not-mounted".to_string())
                },
            );
            emit(format!("BIND_OPTS {opts}"));
        }
        // シナリオ U（`rslave` の bind。#2669）: bind 先のマウントの optional fields（`master:N` など）を出す。
        if std::env::args().any(|a| a == "--with-rslave") {
            let optional = std::fs::read_to_string("/proc/self/mountinfo").map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |info| {
                    info.lines()
                        .filter_map(|l| {
                            let f: Vec<&str> = l.split_whitespace().collect();
                            (f.get(4).copied() == Some(BIND_DEST)).then(|| {
                                f.iter()
                                    .skip(6)
                                    .take_while(|x| **x != "-")
                                    .copied()
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                        })
                        .next_back()
                        .unwrap_or_else(|| "not-mounted".to_string())
                },
            );
            emit(format!("RSLAVE_OPTIONAL {optional}"));
        }
        // シナリオ Y（読み取り専用 rootfs。#2767）: rootfs への書き込みの errno（VFS の EROFS=30 か、Landlock だけが止めた
        // EACCES=13 かを区別する）・`/` と `/proc` の per-mount オプション・書き込み可能であるべきマウントへの書き込み。
        if std::env::args().any(|a| a == "--with-readonly-root") {
            let errno = |r: std::io::Result<()>| {
                r.map_or_else(
                    |e| {
                        e.raw_os_error()
                            .map_or("none".to_string(), |n| n.to_string())
                    },
                    |()| "ok".to_string(),
                )
            };
            emit(format!(
                "RO_CREATE {}",
                errno(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open("/ro-probe-new")
                        .map(|_| ())
                )
            ));
            emit(format!(
                "RO_WRITE {}",
                errno(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(format!("/{RO_MARKER_FILE}"))
                        .map(|_| ())
                )
            ));
            emit(format!(
                "RO_MKDIR {}",
                errno(std::fs::create_dir("/ro-dir"))
            ));
            let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            let opts_of = |dest: &str| -> String {
                info.lines()
                    .filter_map(|l| {
                        let f: Vec<&str> = l.split_whitespace().collect();
                        (f.get(4).copied() == Some(dest))
                            .then(|| f.get(5).copied().unwrap_or("").to_string())
                    })
                    .next_back()
                    .unwrap_or_else(|| "not-mounted".to_string())
            };
            emit(format!("RO_ROOT_OPTS {}", opts_of("/")));
            emit(format!("RO_PROC_OPTS {}", opts_of("/proc")));
            emit(format!(
                "RO_RUN {}",
                errno(std::fs::write("/run/y", RO_DATA_CONTENT))
            ));
            emit(format!(
                "RO_SHM {}",
                errno(std::fs::write("/dev/shm/y", RO_DATA_CONTENT))
            ));
            emit(format!(
                "RO_DEVNULL {}",
                errno(std::fs::write("/dev/null", RO_DATA_CONTENT))
            ));
            emit(format!(
                "RO_DATA {}",
                errno(std::fs::write(
                    format!("{BIND_DEST}/{RO_DATA_FILE}"),
                    RO_DATA_CONTENT
                ))
            ));
        }
        // シナリオ S（起動オプション。#2625）: IPC namespace の識別子・指定 tmpfs の種別・`/dev/shm` の有無・注入ファイル。
        if std::env::args().any(|a| a == "--with-launch-options") {
            let ipc = std::fs::read_link("/proc/self/ns/ipc").map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |p| p.display().to_string(),
            );
            emit(format!("LO_IPC {ipc}"));
            let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            // mountinfo の 5 番目がマウント先、`-` の次が fs 種別。
            let fstype_of = |dest: &str| -> String {
                info.lines()
                    .filter_map(|l| {
                        let f: Vec<&str> = l.split_whitespace().collect();
                        let dash = f.iter().position(|x| *x == "-")?;
                        (f.get(4).copied() == Some(dest))
                            .then(|| f.get(dash + 1).copied().unwrap_or("").to_string())
                    })
                    .next_back()
                    .unwrap_or_else(|| "not-mounted".to_string())
            };
            emit(format!(
                "LO_TMPFS {LO_TMPFS_DEST} {}",
                fstype_of(LO_TMPFS_DEST)
            ));
            emit(format!("LO_SHM {}", fstype_of("/dev/shm")));
            emit(format!("LO_SECRET_DIR {}", fstype_of("/secrets")));
            let content = std::fs::read_to_string(LO_SECRET_PATH)
                .unwrap_or_else(|e| format!("error:{:?}", e.kind()));
            emit(format!("LO_SECRET {content}"));
            let mode = std::fs::metadata(LO_SECRET_PATH).map_or_else(
                |e| format!("error:{:?}", e.kind()),
                |m| format!("{:o}", m.permissions().mode() & 0o777),
            );
            emit(format!("LO_SECRET_MODE {mode}"));
        }
        emit(PROBE_READY.to_string());
        // シナリオ P（名前だけの args[0]。#2314）: READY の後に指定の終了コードで終わる。
        let args: Vec<String> = std::env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--exit-code")
            && let Some(code) = args.get(pos + 1).and_then(|c| c.parse::<i32>().ok())
        {
            std::process::exit(code);
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // ----- 親側の準備 --------------------------------------------------------------------------------------

    /// 一時 bundle（drop で削除。`create_dir` で排他的に作り、既存パスを再利用しない）。
    struct Bundle {
        dir: PathBuf,
    }

    /// 保護済みの親ディレクトリ（共通補助 `scratch_root`。tmpfiles の掃除と flock 競合の回避。#2840・#2887）。
    fn scratch_root() -> &'static Path {
        scratch_root::scratch_root("fandhe-prodlaunch", timeout())
    }

    impl Bundle {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = scratch_root().join(format!(
                "fandhe-prodlaunch-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir(&dir).expect("exclusively create bundle dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod bundle dir");
            Self { dir }
        }

        fn rootfs(&self) -> PathBuf {
            self.dir.join("rootfs")
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// 最小 rootfs を作る。`with_proc` が false なら `proc/` を作らない（シナリオ B の失敗注入）。
    /// 実体は `real_entry::install_binary_at`（rootless 系の試験と共有）。戻り値はプローブが使う
    /// `LD_LIBRARY_PATH` の値。
    fn make_rootfs(rootfs: &Path, with_proc: bool) -> String {
        let dirs: &[&str] = if with_proc {
            &["proc", "dev", "tmp", "etc"]
        } else {
            &["dev", "tmp", "etc"]
        };
        real_entry::install_binary_at(rootfs, "probe", dirs)
    }

    fn mkdir(path: &Path) {
        real_entry::mkdir(path);
    }

    /// 新しい netns でカーネルが自動生成するフォールバックトンネルデバイス名(モジュールのロード状況で有無が変わる)。
    const FALLBACK_TUNNEL_DEVICES: [&str; 10] = [
        "tunl0",
        "gre0",
        "gretap0",
        "erspan0",
        "ip_vti0",
        "ip6_vti0",
        "sit0",
        "ip6tnl0",
        "ip6gre0",
        "ip6erspan0",
    ];
    /// 自己宛て UDP の内容(固定)。
    const NET_PING: &[u8] = b"fandhe-loopback-ping";

    /// シナリオ N のコンテナ内プローブ(NET-6・#3064)。std だけを使い、`unsafe`・libc は使わない。
    fn net_loopback_probe(emit: &mut dyn FnMut(String)) {
        let ns = std::fs::read_link("/proc/self/ns/net").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |p| p.display().to_string(),
        );
        emit(format!("NETNS {ns}"));
        let names = std::fs::read_to_string("/proc/self/net/dev").map_or_else(
            |e| vec![format!("error:{:?}", e.kind())],
            |t| {
                t.lines()
                    .skip(2)
                    .filter_map(|l| l.split(':').next())
                    .map(|n| n.trim().to_string())
                    .collect()
            },
        );
        emit(format!("NETDEV_LO {}", names.iter().any(|n| n == "lo")));
        let extra: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|n| *n != "lo" && !FALLBACK_TUNNEL_DEVICES.contains(n))
            .collect();
        emit(format!(
            "NETDEV_EXTRA {}",
            if extra.is_empty() {
                "none".to_string()
            } else {
                extra.join(",")
            }
        ));
        let delivery = (|| -> Result<String, String> {
            let sock = std::net::UdpSocket::bind("127.0.0.1:0")
                .map_err(|e| format!("bind:{:?}", e.kind()))?;
            sock.set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| format!("timeout:{:?}", e.kind()))?;
            let me = sock
                .local_addr()
                .map_err(|e| format!("addr:{:?}", e.kind()))?;
            sock.send_to(NET_PING, me)
                .map_err(|e| format!("send:{:?}", e.kind()))?;
            let mut buf = [0u8; 64];
            let (n, from) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("recv:{:?}", e.kind()))?;
            if buf.get(..n) == Some(NET_PING) && from == me {
                Ok("ok".to_string())
            } else {
                Err("mismatch".to_string())
            }
        })();
        emit(format!(
            "UDP_SELF {}",
            delivery.unwrap_or_else(|e| format!("error:{e}"))
        ));
    }

    fn write_config(
        bundle: &Bundle,
        ld_library_path: &str,
        extra_args: &[&str],
        mounts: serde_json::Value,
    ) {
        write_config_with(bundle, ld_library_path, extra_args, mounts, "/", (0, 0));
    }

    /// `write_config` に `process.cwd` と `process.user`(uid, gid)を指定できる版(OCI-1・SEC-5)。
    fn write_config_with(
        bundle: &Bundle,
        ld_library_path: &str,
        extra_args: &[&str],
        mounts: serde_json::Value,
        cwd: &str,
        user: (u32, u32),
    ) {
        write_config_groups(bundle, ld_library_path, extra_args, mounts, cwd, user, &[]);
    }

    /// `write_config_with` に `process.user.additionalGids` を指定できる版(OCI-1・SEC-5・CORE-6・#2667)。
    fn write_config_groups(
        bundle: &Bundle,
        ld_library_path: &str,
        extra_args: &[&str],
        mounts: serde_json::Value,
        cwd: &str,
        (uid, gid): (u32, u32),
        additional_gids: &[u32],
    ) {
        let mut args = vec!["/probe", "--container-probe"];
        args.extend_from_slice(extra_args);
        let config = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": false},
            "hostname": HOSTNAME,
            "process": {
                "user": {"uid": uid, "gid": gid, "additionalGids": additional_gids},
                "args": args,
                "env": [
                    "PATH=/",
                    "TERM=dumb",
                    format!("LD_LIBRARY_PATH={ld_library_path}"),
                ],
                "cwd": cwd
            },
            "mounts": mounts,
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
            ]}
        });
        std::fs::write(
            bundle.dir.join("config.json"),
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("write config.json");
    }

    /// 書き出し済みの `config.json` の `root.readonly` を真にする（シナリオ Y。#2767）。
    fn set_root_readonly(bundle: &Bundle) {
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config.json"))
                .expect("parse config.json");
        config["root"]["readonly"] = json!(true);
        std::fs::write(
            &path,
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("write config.json");
    }

    /// 監査レコードをメモリへ追記するだけの sink（本試験は監査内容を照合しない）。
    struct MemSink(std::sync::Mutex<Vec<String>>);

    impl AuditSink for MemSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{record:?}"));
            Ok(())
        }
    }

    /// 子の出力を行単位で読んで送るリーダースレッド。1 行と総行数に上限を設ける。
    fn spawn_reader(
        stdout: Box<dyn std::io::Read + Send>,
    ) -> (mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            for _ in 0..LINES_MAX {
                let mut line = String::new();
                match (&mut reader).take(LINE_MAX).read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if tx.send(line.trim_end().to_string()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        (rx, handle)
    }

    /// `READY` までのプローブ出力を集める（期限つき）。
    fn collect_probe(rx: &mpsc::Receiver<String>) -> Vec<String> {
        let deadline = Instant::now() + timeout();
        let mut lines = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = rx
                .recv_timeout(left)
                .unwrap_or_else(|e| panic!("probe output ended before READY ({e}); got {lines:?}"));
            if line == PROBE_READY {
                return lines;
            }
            lines.push(line);
        }
    }

    fn value_of<'a>(lines: &'a [String], key: &str) -> &'a str {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')))
            .unwrap_or_else(|| panic!("probe line {key:?} missing in {lines:?}"))
    }

    struct Env {
        store: FileStateStore,
        _root: Bundle,
        launcher: Arc<dyn ProcessLauncher>,
        recorder: OpRecorder,
    }

    fn state_of(store: &FileStateStore, id: &ContainerId) -> ContainerState {
        store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get state")
            .status()
            .state()
    }

    /// `state.json` から読み戻した launch 時の分離の記録を検証する(SUP-6・CORE-5・SEC-1・#2007)。`/` の識別子は
    /// ホスト側の rootfs ディレクトリの `(st_dev, st_ino)` と一致し(bind は inode と `st_dev` を保つ)、ルールは
    /// 先頭が rootfs で、`bind_dest` があれば `mounts[0]` 由来の Mount ルールを含む。
    fn assert_recorded_launch_isolation(
        env: &Env,
        id: &ContainerId,
        bundle: &Bundle,
        bind_dest: Option<&str>,
    ) {
        use fandhe_container_core::launch_isolation::RecordedTarget;
        use std::os::unix::fs::MetadataExt as _;
        let record = env
            .store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get state");
        let iso = record
            .launch_isolation()
            .expect("launch_isolation recorded");
        let meta = std::fs::metadata(bundle.rootfs()).expect("rootfs metadata");
        assert_eq!(iso.root().dev(), meta.dev());
        assert_eq!(iso.root().ino(), meta.ino());
        let rules = iso.landlock().rules();
        assert!(
            matches!(
                rules.first().map(|r| r.target()),
                Some(RecordedTarget::Root)
            ),
            "first rule must be the rootfs"
        );
        assert_ne!(iso.landlock().handled(), 0);
        let mounts: Vec<(String, usize)> = rules
            .iter()
            .filter_map(|r| match r.target() {
                RecordedTarget::Mount { destination, index } => {
                    Some((destination.as_str().to_owned(), *index))
                }
                _ => None,
            })
            .collect();
        let want: Vec<(String, usize)> = bind_dest.map(|d| (d.to_owned(), 0)).into_iter().collect();
        assert_eq!(mounts, want);
    }

    fn do_create(env: &Env, bundle: &Bundle, id: &ContainerId) {
        let req = CreateRequest::new(id.clone(), bundle.dir.clone()).expect("absolute bundle");
        if let Err(e) = create(&env.store, &env.recorder, &req) {
            // 間欠失敗（#2840）の再発時に 1 回でロック保持者を特定できるよう、bundle の flock の保持者を出す（判定は変えない）。
            eprintln!(
                "create failed for {}: lock holders: {}",
                bundle.dir.display(),
                lock_holders(&bundle.dir)
            );
            panic!("create: {e:?}");
        }
    }

    /// `/proc/locks` から `path` の inode を持つ行と保持者の `comm` を文字列化する（診断専用。取れなければ "unknown"）。
    fn lock_holders(path: &Path) -> String {
        use std::os::unix::fs::MetadataExt;
        let Ok(md) = std::fs::metadata(path) else {
            return "unknown".to_owned();
        };
        let needle = format!(":{}", md.ino());
        let Ok(locks) = std::fs::read_to_string("/proc/locks") else {
            return "unknown".to_owned();
        };
        let rows: Vec<String> = locks
            .lines()
            .filter(|l| l.split_whitespace().any(|f| f.ends_with(&needle)))
            .map(|l| {
                let comm = l
                    .split_whitespace()
                    .nth(4)
                    .and_then(|pid| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok())
                    .unwrap_or_default();
                format!("[{l}] comm={}", comm.trim())
            })
            .collect();
        if rows.is_empty() {
            "none".to_owned()
        } else {
            rows.join("; ")
        }
    }

    pub fn run() {
        let root = is_root();
        // 前提（委譲 cgroup・範囲写像の helper ケースの `uidmap`・subuid / subgid・`USER`）の欠如は、回帰と見分けられる
        // `PRECONDITION FAILED` の 1 行目で失敗させる（#2888・REPAIR-12）。失敗の範囲は変えない。
        let delegated = real_entry::precondition::delegated_cgroup();
        if subordinate_requested() && !root {
            real_entry::precondition::require_subordinate_ids(own_ids().0);
        }
        let tag = std::process::id();
        let cg_id = ContainerId::new(format!("pl{tag}")).expect("container id");
        let cg_name = CgroupName::new(&cg_id).expect("cgroup name");
        // detect / prepare / join_hook は isolate（pivot）より前。pivot 後はホストの cgroupfs が見えない。
        let (container, _proof) = delegated
            .prepare(&cg_name)
            .expect("prepare container cgroup");
        let container: Arc<ContainerCgroup> = Arc::new(container);
        let expected_cgroup = format!(
            "0::{}/{}",
            delegated.path().trim_end_matches('/'),
            cg_name.as_str()
        );

        // 後始末は成否に関わらず行う（panic でも cgroup と一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenarios(root, &container, &expected_cgroup, tag);
        }));
        let removed = delegated.remove_child(&container);
        scratch_root::remove_scratch_root();
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");

        if root {
            println!(
                "production_launcher: launch refused for root, no process left (SEC-5) (root=true)"
            );
        } else {
            println!(
                "production_launcher: pid1, default /dev nodes, landlock evidence, cgroup join verified; failed launch left no process; bind mount visible on host; post-exec capabilities and seccomp verified (root=false)"
            );
        }
    }

    fn scenarios(root: bool, container: &Arc<ContainerCgroup>, expected_cgroup: &str, tag: u32) {
        let state_dir = Bundle::new("state");
        let store = FileStateStore::open(
            StateRoot::from_override(state_dir.dir.join("state")).expect("state root"),
        );
        // 状態ルートは 0700 で自分が作る（`open` が作成し所有者・権限を検査する）。
        let store = store.expect("open state store");

        let join_container = Arc::clone(container);
        let launcher = ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSingleId)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .cgroup_join_source(move || {
                let hook = PRE_SPAWN_HOOK
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(hook) = hook {
                    hook();
                }
                join_container.join_hook()
            })
            .build()
            .expect("build production launcher");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(launcher);
        let env = Env {
            store,
            _root: state_dir,
            launcher,
            recorder: OpRecorder::new(),
        };

        if root {
            scenario_root_refused(&env, tag);
            if subordinate_requested() {
                scenario_i_root_refused();
            }
            return;
        }
        scenario_a_normal(&env, expected_cgroup, tag);
        scenario_b_failed_launch_leaves_nothing(&env, tag);
        scenario_c_multithreaded_refused(&env, tag);
        scenario_d_bind_mount(&env, tag);
        scenario_u_rslave_bind(&env, tag);
        scenario_e_state_root_bind_refused(&env, tag);
        scenario_f_bind_over_protected_path_refused(&env, tag);
        scenario_g_devtmpfs_bind_refused(&env, tag);
        scenario_h_state_root_moved_after_start(&env, tag);
        scenario_s_launch_options(&env, tag);
        scenario_y_readonly_root(&env, tag);
        scenario_n_network_loopback(&env, tag, false);
        scenario_z_network_host_netns_sync(&env, tag);
        scenario_attachable_network(&env, tag, false);
        if subordinate_requested() {
            scenario_n_network_loopback(&env, tag, true);
            scenario_attachable_network(&env, tag, true);
            scenario_i_subordinate_ids(&env, tag);
            scenario_s_subordinate_sealed_inject(&env, tag);
        } else {
            println!(
                "production_launcher: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        scenario_j_exec_restrictions(&env, tag);
        scenario_k_seccomp_kill_after_exec(&env, tag);
        scenario_t_capabilities_drop(&env, tag);
        scenario_v_sysctls(&env, tag);
        scenario_w_pod_ipc_join(&env, tag);
        scenario_l_working_dir(&env, tag);
        scenario_m_n_working_dir_refused(&env, tag);
        scenario_o_user_outside_mapping_refused(&env, tag);
        scenario_o_groups_single_id_refused(&env, tag);
        scenario_p_bare_name_entrypoint(&env, tag);
        scenario_r_cwd_relative_entrypoint(&env, tag);
        scenario_s_entrypoint_violation_recorded(&env, container, tag);
        scenario_x_exec_failures(&env, container, tag);
        scenario_q_exit_signal_via_relay(&env, container, tag);
        if subordinate_requested() {
            scenario_i_user_applied(tag);
        }
    }

    /// シナリオ A: 正常起動。
    fn scenario_a_normal(env: &Env, expected_cgroup: &str, tag: u32) {
        let bundle = Bundle::new("a");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("pla{tag}")).expect("id");
        do_create(env, &bundle, &id);
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        // 検証は catch_unwind の中で行い、成否に関わらず terminate と回収を行ってから panic を再送出する
        // （`LaunchedProcess` は Drop で終了・回収しないため、ここで回収しないと実機にプロセスが残る）。
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // 起動直後の状態検証も保護範囲に含め、panic 時も terminate と回収を行う。
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_eq!(started.record().status().pid(), Some(pid));
            assert_eq!(state_of(&env.store, &id), ContainerState::Running);
            assert_recorded_launch_isolation(env, &id, &bundle, None);
            // ホストから見た PID 1 の確認（NSpid の末尾が 1）。
            let nspid = status_field(&format!("/proc/{pid}/status"), "NSpid:").expect("host NSpid");
            let parts: Vec<&str> = nspid.split_whitespace().collect();
            assert_eq!(parts.len(), 2, "NSpid must have two levels: {nspid:?}");
            assert_eq!(parts.first().copied(), Some(pid.to_string().as_str()));
            assert_eq!(parts.last().copied(), Some("1"));
            // 起動のたびに登録された CgroupJoin 段で、子 cgroup に参加している。
            let host_cgroup =
                std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("cgroup");
            assert_eq!(host_cgroup.trim(), expected_cgroup);

            // SEC-4・#2024: PID 1 が NEW_LISTENER で得た listener を launcher が検証して持っている。種別は notify で、
            // 1 回だけ取り出せ、PID 1 側（コンテナ内）には残らない（ホストから見た PID 1 の fd に notify が無い）。
            let listener = started
                .process()
                .take_seccomp_listener()
                .expect("seccomp listener handed over");
            let kind = std::fs::read_link(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&listener.as_fd())
            ))
            .expect("readlink of the listener");
            assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
            assert!(started.process().take_seccomp_listener().is_none());
            let pid1_fds: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
                .expect("pid1 fd dir")
                .filter_map(Result::ok)
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            assert!(
                !pid1_fds.iter().any(|p| p.contains("seccomp notify")),
                "the workload must not hold the listener: {pid1_fds:?}"
            );

            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            let (rx, reader) = spawn_reader(stdout);
            // 以降の検証が panic しても、起動済みプロセスの終了と回収を必ず行うため rx / reader は外へ預ける。
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);

            assert_eq!(value_of(&lines, "PID"), "1");
            assert_eq!(value_of(&lines, "HOSTNAME"), HOSTNAME);
            assert_eq!(value_of(&lines, "CGROUP"), expected_cgroup);
            // 制限ステージ（no_new_privs・seccomp）の適用の間接証拠。Landlock 本体の直接観測は範囲外（モジュール doc）。
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            for (name, major, minor) in [
                ("null", 1, 3),
                ("zero", 1, 5),
                ("full", 1, 7),
                ("random", 1, 8),
                ("urandom", 1, 9),
                ("tty", 5, 0),
            ] {
                assert_eq!(
                    value_of(&lines, &format!("DEV {name}")),
                    format!("c {major}:{minor}"),
                    "/dev/{name}"
                );
            }
            for (name, target) in [
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
            ] {
                assert_eq!(
                    value_of(&lines, &format!("LINK {name}")),
                    target,
                    "/dev/{name}"
                );
            }
            assert_eq!(value_of(&lines, "DIR pts"), "true");
            assert_eq!(value_of(&lines, "DIR shm"), "true");
            assert_eq!(value_of(&lines, "DEVNULL_WRITE"), "ok");
            assert_eq!(value_of(&lines, "DEVZERO_READ"), "16");
            println!(
                "production_launcher: scenario=ok pid={pid} nspid={nspid:?} hostname={HOSTNAME}"
            );
        }));

        // 終了と回収。
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            // 検証側の panic を優先する。terminate の失敗で元の panic を覆い隠さない。
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        // 出力パイプは子の終了で EOF になり、リーダーは終了する。次の start の前に必ず join する。
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ B: rootfs に `proc/` が無く pre-pivot 段が失敗する起動。何も残さない（#1817）。
    fn scenario_b_failed_launch_leaves_nothing(env: &Env, tag: u32) {
        let bundle = Bundle::new("b");
        let ld = make_rootfs(&bundle.rootfs(), false);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plb{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must fail without rootfs/proc"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            env.store
                .get(&GetStateRequest::new(id.clone()))
                .expect("get state")
                .launch_isolation()
                .is_none(),
            "a failed launch must leave no launch_isolation"
        );
        assert!(!env.launcher.last_launch_may_have_left_process());
        env.launcher
            .confirm_no_process(&id, timeout())
            .expect("confirm_no_process must be Ok for a cleanly failed launch");
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no intermediate process or PID 1 may remain: {:?}",
            children_of_self()
        );
        println!(
            "production_launcher: scenario=failed-launch code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ C: 補助スレッドが生きている状態の start は fork 前に拒否される（副作用なし）。
    fn scenario_c_multithreaded_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("c");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plc{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = stop_rx.recv_timeout(Duration::from_secs(60));
        });
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        let _ = stop_tx.send(());
        helper.join().expect("join helper");
        let err = match result {
            Ok(_) => panic!("start must be refused while a second thread is alive"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            children_of_self().is_empty(),
            "a refused launch must not fork"
        );
        println!("production_launcher: scenario=multithreaded-refused code=FailedPrecondition");
    }

    /// シナリオ D: `mounts[]` の bind mount が start と本番 launcher を通って適用される（#1915・OCI-4・IO-8・SEC-1）。
    /// コンテナ内が bind 先へ書いた内容がホスト側の元に完全一致で現れ、bind 先のマウントに `nosuid`・`nodev` が付く。
    fn scenario_d_bind_mount(env: &Env, tag: u32) {
        let src = Bundle::new("d-src");
        let bundle = Bundle::new("d");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-bind"], mounts);
        let id = ContainerId::new(format!("pld{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "start with bind mount failed: {:?} {}",
                e.code(),
                e.message()
            )
        });
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            assert_recorded_launch_isolation(env, &id, &bundle, Some(BIND_DEST));
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(value_of(&lines, "BIND_WRITE"), "ok");
            let opts = value_of(&lines, "BIND_OPTS");
            let opts: Vec<&str> = opts.split(',').collect();
            assert!(opts.contains(&"rw"), "{opts:?}");
            assert!(opts.contains(&"nosuid"), "{opts:?}");
            assert!(opts.contains(&"nodev"), "{opts:?}");
            let on_host = std::fs::read_to_string(src.dir.join(BIND_FILE)).expect("host file");
            assert_eq!(on_host, BIND_CONTENT);
            println!(
                "production_launcher: scenario=bind-mount pid={pid} dest={BIND_DEST} visible on host, nosuid+nodev"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// 元が属するホスト側のマウントの伝播（`/proc/self/mountinfo` の最長一致の行の optional fields。試験プロセスはホストの
    /// mount namespace にいる）。`(shared, slave)`。
    fn host_propagation_of(path: &Path) -> (bool, bool) {
        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let mut best: Option<(usize, bool, bool)> = None;
        for line in info.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let Some(mount_point) = f.get(4) else {
                continue;
            };
            if !path.starts_with(mount_point) {
                continue;
            }
            let optional: Vec<&str> = f
                .iter()
                .skip(6)
                .take_while(|x| **x != "-")
                .copied()
                .collect();
            let shared = optional.iter().any(|o| o.starts_with("shared:"));
            let slave = optional
                .iter()
                .any(|o| o.starts_with("master:") || o.starts_with("propagate_from:"));
            if best.is_none_or(|(len, _, _)| mount_point.len() >= len) {
                best = Some((mount_point.len(), shared, slave));
            }
        }
        let (_, shared, slave) = best.expect("a mount must contain the source directory");
        (shared, slave)
    }

    /// シナリオ U: `rslave` の bind（#2669・OCI-4・CRI-2・SEC-1）。ホスト側の元のマウントが shared か slave なら起動でき、
    /// コンテナ内の bind 先は `master:` を持ち `shared:` を持たない。ホスト側が private なら rootfs に触れる前に
    /// `FailedPrecondition` で拒否される（黙って private で載せない）。
    fn scenario_u_rslave_bind(env: &Env, tag: u32) {
        let src = Bundle::new("u-src");
        let bundle = Bundle::new("u");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["rbind", "rslave", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-rslave"], mounts);
        let id = ContainerId::new(format!("plu{tag}")).expect("id");
        do_create(env, &bundle, &id);
        let (host_shared, host_slave) = host_propagation_of(&src.dir);
        let host = match (host_shared, host_slave) {
            (true, _) => "shared",
            (false, true) => "slave",
            (false, false) => "private",
        };

        wait_single_thread();
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        if !(host_shared || host_slave) {
            let err = match result {
                Ok(_) => panic!("rslave bind of a private host mount must be refused"),
                Err(e) => e,
            };
            assert_eq!(
                err.code(),
                ErrorCode::FailedPrecondition,
                "{}",
                err.message()
            );
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            env.launcher
                .confirm_no_process(&id, timeout())
                .expect("confirm_no_process must be Ok for a cleanly failed launch");
            assert!(
                eventually(|| children_of_self().is_empty()),
                "no intermediate process or PID 1 may remain: {:?}",
                children_of_self()
            );
            assert!(
                !bundle.rootfs().join("data").exists(),
                "the bind destination must not be created in the rootfs"
            );
            println!(
                "production_launcher: scenario=rslave-bind host={host} refused code={:?} state=created children=0",
                err.code()
            );
            return;
        }
        let started = result.unwrap_or_else(|e| {
            panic!(
                "start with rslave bind failed: {:?} {}",
                e.code(),
                e.message()
            )
        });
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            let optional = value_of(&lines, "RSLAVE_OPTIONAL");
            let fields: Vec<&str> = optional.split(',').collect();
            assert!(
                fields.iter().any(|f| f.starts_with("master:")),
                "the rslave bind must be a slave in the container: {optional}"
            );
            assert!(
                !fields.iter().any(|f| f.starts_with("shared:")),
                "the rslave bind must not be shared in the container: {optional}"
            );
            println!(
                "production_launcher: scenario=rslave-bind host={host} pid={pid} dest={BIND_DEST} slave in the container, not shared"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ S(SUP-12・CORE-5・SEC-1・#2625): `ProductionLauncher::builder().launch_options(..)` で渡した
    /// `--ipc=host` + `--tmpfs /run` + 注入ファイルが、`create` → `start` の実プロセスへ実効状態として届くことを
    /// 具体値で照合する(IPC namespace の識別子がホストと一致・`/run` が tmpfs・`/dev/shm` を載せない・注入ファイルの
    /// 内容とモード・注入ディレクトリが専用 tmpfs)。supervisor の `ContainerOptions::launch_options` から同じ
    /// builder 呼び出しへ至る変換は supervisor 側の単体試験が担う。
    fn scenario_s_launch_options(env: &Env, tag: u32) {
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .push(TmpfsMountSpec::new(LO_TMPFS_DEST, None).expect("tmpfs spec"))
            .expect("push tmpfs");
        let mut inject = InjectedFileSet::new();
        inject
            .push(
                InjectedFileSpec::new(
                    LO_SECRET_PATH,
                    InjectedContent::from_bytes(LO_SECRET_CONTENT.as_bytes().to_vec())
                        .expect("content"),
                    InjectedFileMode::new(LO_SECRET_MODE).expect("mode"),
                )
                .expect("inject spec"),
            )
            .expect("push inject");
        let options =
            LaunchOptions::new(tmpfs, inject, LaunchIpcMode::Host).expect("launch options");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(
            ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSingleId)
                .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
                .launch_options(options)
                .build()
                .expect("build launcher with launch options"),
        );
        let host_ipc = std::fs::read_link("/proc/self/ns/ipc")
            .expect("host ipc ns")
            .display()
            .to_string();

        let bundle = Bundle::new("s");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-launch-options"], json!([]));
        let id = ContainerId::new(format!("plt{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            // ホストから見た PID 1 の IPC namespace も、コンテナ内の見え方も、起動側と同じ。
            let from_host = std::fs::read_link(format!("/proc/{pid}/ns/ipc"))
                .expect("container ipc ns from host")
                .display()
                .to_string();
            assert_eq!(from_host, host_ipc);
            assert_eq!(value_of(&lines, "LO_IPC"), host_ipc);
            assert_eq!(
                value_of(&lines, "LO_TMPFS"),
                format!("{LO_TMPFS_DEST} tmpfs")
            );
            // `--ipc=host` では専用の `/dev/shm` を載せない。
            assert_eq!(value_of(&lines, "LO_SHM"), "not-mounted");
            assert_eq!(value_of(&lines, "LO_SECRET_DIR"), "tmpfs");
            assert_eq!(value_of(&lines, "LO_SECRET"), LO_SECRET_CONTENT);
            assert_eq!(value_of(&lines, "LO_SECRET_MODE"), "440");
            println!(
                "production_launcher: launch options reached the container (scenario=S ipc=host tmpfs={LO_TMPFS_DEST} secret mode=440)"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ Y（読み取り専用 rootfs。CORE-5・SEC-1・SUP-12・#2767）: `root.readonly=true` の config を start し、
    /// rootfs への新規作成・既存ファイルへの書き込み・mkdir が **`EROFS`（30）** で拒否されることを照合する。
    /// Landlock だけが止めている場合は `EACCES`（13）になるため、これを失敗として扱う（VFS の読み取り専用化が効いていることの
    /// 判別条件。カーネルは `got_write` が無いとき Landlock のフックより先に `EROFS` を返す: `fs/namei.c` の `lookup_open`・
    /// `filename_create` と `fs/open.c` の `do_dentry_open` で書き込みアクセスの取得が `security_*` より先）。
    /// あわせて `/` の per-mount オプションに `ro` と `nodev` が含まれる（属性の追加だけで `nodev` が落ちない）こと、
    /// `/proc` に `ro` が付かない（非再帰）こと、`--tmpfs`（`/run`）・専用 `/dev`（`/dev/shm`・`/dev/null`）・rw の bind
    /// （`/data`）への書き込みが成功し、bind はホスト側に内容が現れることを照合する。非 root の経路だけで回す。
    fn scenario_y_readonly_root(env: &Env, tag: u32) {
        let _ = env;
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs
            .push(TmpfsMountSpec::new(LO_TMPFS_DEST, None).expect("tmpfs spec"))
            .expect("push tmpfs");
        // Private IPC では専用の `/dev/shm` が要る(`LaunchOptions::new` の検査)。ここで既定の 1 件を足す。
        tmpfs.ensure_default_dev_shm().expect("default dev shm");
        let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
            .expect("launch options");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(
            ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSingleId)
                .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
                .launch_options(options)
                .build()
                .expect("build launcher for readonly root"),
        );
        let src = Bundle::new("y-src");
        let bundle = Bundle::new("y");
        let ld = make_rootfs(&bundle.rootfs(), true);
        std::fs::write(bundle.rootfs().join(RO_MARKER_FILE), RO_MARKER_CONTENT).expect("marker");
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-readonly-root"], mounts);
        set_root_readonly(&bundle);
        let id = ContainerId::new(format!("ply{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            // EROFS = 30。13（EACCES）なら Landlock だけが止めていて、VFS の読み取り専用化が効いていない。
            for key in ["RO_CREATE", "RO_WRITE", "RO_MKDIR"] {
                assert_eq!(value_of(&lines, key), "30", "{key}: {lines:?}");
            }
            let root_opts: Vec<&str> = value_of(&lines, "RO_ROOT_OPTS").split(',').collect();
            assert!(root_opts.contains(&"ro"), "{root_opts:?}");
            assert!(root_opts.contains(&"nodev"), "{root_opts:?}");
            let proc_opts: Vec<&str> = value_of(&lines, "RO_PROC_OPTS").split(',').collect();
            assert!(!proc_opts.contains(&"ro"), "{proc_opts:?}");
            for key in ["RO_RUN", "RO_SHM", "RO_DEVNULL", "RO_DATA"] {
                assert_eq!(value_of(&lines, key), "ok", "{key}: {lines:?}");
            }
            let on_host = std::fs::read_to_string(src.dir.join(RO_DATA_FILE)).expect("host file");
            assert_eq!(on_host, RO_DATA_CONTENT);
            assert!(!bundle.rootfs().join("ro-probe-new").exists());
            assert!(!bundle.rootfs().join("ro-dir").exists());
            assert_eq!(
                std::fs::read_to_string(bundle.rootfs().join(RO_MARKER_FILE)).expect("marker"),
                RO_MARKER_CONTENT
            );
            println!(
                "production_launcher: readonly rootfs refused writes with EROFS; tmpfs, /dev, bind writable (scenario=Y root=ro nodev=kept tmpfs={LO_TMPFS_DEST})"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ I の opt-in 環境変数(`rootless_file_owner` の helper ケースと同じ流儀)。
    fn subordinate_requested() -> bool {
        std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1")
    }

    /// 起動ユーザーの euid / egid(`/proc/self/status` の実効 ID)。
    fn own_ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            std::fs::read_to_string("/proc/self/status")
                .expect("read status")
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
                .expect("parse id")
        };
        (id("Uid:"), id("Gid:"))
    }

    /// `RootlessSubordinateIds` の launcher を作る。所有者名は試験側が `USER` から渡す(ライブラリは読まない)。
    fn build_subordinate_launcher() -> Result<ProductionLauncher, TraitError> {
        ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSubordinateIds)
            .subordinate_ids(SubordinateIdSource::system(std::env::var("USER").ok())?)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .build()
    }

    /// シナリオ I(`FANDHE_CONTAINER_TEST_ID_HELPER=1`。CORE-6・SEC-5・#2009): `RootlessSubordinateIds` の launcher で
    /// 起動し、ホストから見た PID 1 の `uid_map` / `gid_map` が `/etc/subuid`・`/etc/subgid` の範囲写像と完全一致する
    /// (コンテナ 0 → 自 ID、コンテナ 1 以上 → subuid / subgid の範囲)ことを照合する。コンテナ内の
    /// `/proc/self/uid_map` は読み手基準の表示になるため照合に使わない。前提(`uidmap`・subuid / subgid の自ユーザー行)が
    /// 無ければ失敗とする。
    fn scenario_i_subordinate_ids(env: &Env, tag: u32) {
        use fandhe_container_core::rootless::{
            IdKind, SubIdOwner, TargetPid, load_subordinate_ids, read_id_map, rootless_mapping,
        };
        let launcher: Arc<dyn ProcessLauncher> =
            Arc::new(build_subordinate_launcher().expect("build subordinate launcher"));
        let (euid, egid) = own_ids();
        let name = std::env::var("USER").ok();
        let uowner = SubIdOwner::new(euid, name.clone()).expect("uid owner");
        let gowner = SubIdOwner::new(euid, name).expect("gid owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &uowner).expect("load /etc/subuid");
        let granges =
            load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
        assert!(
            !uranges.is_empty() && !granges.is_empty(),
            "scenario I requires subuid/subgid entries for the current user"
        );
        let want_uid = rootless_mapping(euid, &uranges).expect("uid range mapping");
        let want_gid = rootless_mapping(egid, &granges).expect("gid range mapping");

        let bundle = Bundle::new("i");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("pli{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let target = TargetPid::new(pid.get()).expect("target pid");
            let uid_map = read_id_map(target, IdKind::Uid).expect("read uid_map");
            let gid_map = read_id_map(target, IdKind::Gid).expect("read gid_map");
            assert_eq!(uid_map.as_slice(), want_uid.entries());
            assert_eq!(gid_map.as_slice(), want_gid.entries());
            assert!(uid_map.len() >= 2 && gid_map.len() >= 2, "{uid_map:?}");
            let first_sub_uid = uranges.first().expect("a subuid range").start();
            assert_eq!(
                uid_map.get(1).map(|m| (m.container_id, m.host_id)),
                Some((1, first_sub_uid))
            );

            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(value_of(&lines, "PID"), "1");
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            println!(
                "production_launcher: subordinate id mapping verified (uid extents={}, gid extents={})",
                uid_map.len(),
                gid_map.len()
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ S の範囲写像版(`FANDHE_CONTAINER_TEST_ID_HELPER=1`。CORE-6・SEC-5・SUP-12・#2628): ホストのファイルを
    /// 封印 memfd(`InjectedContent::from_file`)にした注入が、`RootlessSubordinateIds` の launcher で拒否されず、
    /// 内容とモードが具体値でコンテナへ届くことを照合する。呼び出し元のメモリの内容(`from_bytes`)は start の前に
    /// 拒否されることも照合する。
    fn scenario_s_subordinate_sealed_inject(env: &Env, tag: u32) {
        let host_dir = scratch_root().join(format!("fandhe-plt-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&host_dir);
        std::fs::create_dir_all(&host_dir).expect("host dir");
        let host_file = host_dir.join("secret");
        std::fs::write(&host_file, LO_SECRET_CONTENT).expect("write host secret");
        let build = |content: InjectedContent| -> Result<ProductionLauncher, TraitError> {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs
                .push(TmpfsMountSpec::new(LO_TMPFS_DEST, None).expect("tmpfs spec"))
                .expect("push tmpfs");
            let mut inject = InjectedFileSet::new();
            inject
                .push(
                    InjectedFileSpec::new(
                        LO_SECRET_PATH,
                        content,
                        InjectedFileMode::new(LO_SECRET_MODE).expect("mode"),
                    )
                    .expect("inject spec"),
                )
                .expect("push inject");
            let options =
                LaunchOptions::new(tmpfs, inject, LaunchIpcMode::Host).expect("launch options");
            ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSubordinateIds)
                .subordinate_ids(SubordinateIdSource::system(std::env::var("USER").ok())?)
                .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
                .launch_options(options)
                .build()
        };
        // 呼び出し元のメモリの内容は build で拒否される(fork 前)。
        let refused = build(
            InjectedContent::from_bytes(LO_SECRET_CONTENT.as_bytes().to_vec()).expect("content"),
        )
        .expect_err("caller-memory content must be refused under subordinate ids");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);

        let file = std::fs::File::open(&host_file).expect("open host secret");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(
            build(InjectedContent::from_file(&file).expect("sealed content"))
                .expect("build subordinate launcher with sealed injection"),
        );
        drop(file);
        let _ = std::fs::remove_dir_all(&host_dir);

        let bundle = Bundle::new("ss");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-launch-options"], json!([]));
        let id = ContainerId::new(format!("plss{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(value_of(&lines, "LO_SECRET_DIR"), "tmpfs");
            assert_eq!(value_of(&lines, "LO_SECRET"), LO_SECRET_CONTENT);
            assert_eq!(value_of(&lines, "LO_SECRET_MODE"), "440");
            println!(
                "production_launcher: injected secret reached the container under subordinate id mapping (scenario=S-subordinate)"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        let (rx, reader) = reader_slot.take().expect("reader slot");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// root で実行された場合のシナリオ I: `RootlessSubordinateIds` の構築が `PermissionDenied` で拒否される
    /// (コンテナ内 root をホスト root へ写さない。SEC-5・#2009)。
    fn scenario_i_root_refused() {
        let err = build_subordinate_launcher().expect_err("root must be refused");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        println!(
            "production_launcher: scenario=subordinate-root-refused code={:?}",
            err.code()
        );
    }

    /// 指定の `cwd`・`user` で create → start し、`READY` までのプローブ出力を返して terminate・回収する
    /// (OCI-1・SEC-5)。`prepare` は rootfs の準備(作業ディレクトリの作成など)。非 root の `user` のときは
    /// ホストから見た uid を `HOST_UIDS` 行として足す。
    fn run_probe_with(
        env: &Env,
        launcher: &Arc<dyn ProcessLauncher>,
        name: &str,
        cwd: &str,
        user: (u32, u32),
        prepare: &dyn Fn(&Path),
        tag: u32,
    ) -> Vec<String> {
        run_probe_groups(env, launcher, name, cwd, user, &[], prepare, tag)
    }

    /// `run_probe_with` に `additionalGids` を指定できる版。ホストから見た補助グループを `HOST_GROUPS` 行として足す
    /// (OCI-1・SEC-5・CORE-6・#2667)。
    // 既存の `run_probe_with` と同じ並びに `additionalGids` を足した試験用ヘルパーで、引数は呼び出し側の
    // 試験ごとに全て異なる値を取る。構造体に束ねると 1 回限りの型が増えるため抑止する。
    #[allow(clippy::too_many_arguments)]
    fn run_probe_groups(
        env: &Env,
        launcher: &Arc<dyn ProcessLauncher>,
        name: &str,
        cwd: &str,
        user: (u32, u32),
        additional_gids: &[u32],
        prepare: &dyn Fn(&Path),
        tag: u32,
    ) -> Vec<String> {
        let bundle = Bundle::new(name);
        let ld = make_rootfs(&bundle.rootfs(), true);
        prepare(&bundle.rootfs());
        write_config_groups(&bundle, &ld, &[], json!([]), cwd, user, additional_gids);
        let id = ContainerId::new(format!("pl{name}{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let mut lines = Vec::new();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let stdout = output.stdout.expect("container stdout");
            reader_slot = Some(spawn_reader(stdout));
            lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            if user != (0, 0) {
                let host = status_field(&format!("/proc/{pid}/status"), "Uid:")
                    .unwrap_or_else(|| "missing".to_string());
                lines.push(format!(
                    "HOST_UIDS {}",
                    host.split_whitespace().collect::<Vec<_>>().join(",")
                ));
                let groups = status_field(&format!("/proc/{pid}/status"), "Groups:")
                    .unwrap_or_else(|| "missing".to_string());
                lines.push(format!(
                    "HOST_GROUPS {}",
                    groups.split_whitespace().collect::<Vec<_>>().join(",")
                ));
            }
        }));
        finish_started(started, verified);
        if let Some((rx, reader)) = reader_slot.take() {
            reader.join().expect("join reader");
            drop(rx);
        }
        assert!(eventually(|| children_of_self().is_empty()));
        lines
    }

    /// シナリオ L(OCI-1・TASK-29): `process.cwd` が rootfs 内の既存ディレクトリ(`/work/dir`)なら、
    /// pivot 直後に fd 起点で移り、コンテナ内の `/proc/self/cwd` がそのパスを指す。`/` のときは `/` のまま。
    fn scenario_l_working_dir(env: &Env, tag: u32) {
        let mk = |root: &Path| mkdir(&root.join("work/dir"));
        let lines = run_probe_with(env, &env.launcher, "l", "/work/dir", (0, 0), &mk, tag);
        assert_eq!(value_of(&lines, "CWD"), "/work/dir");
        assert_eq!(value_of(&lines, "UIDS"), "0,0,0,0");
        let lines = run_probe_with(env, &env.launcher, "l0", "/", (0, 0), &mk, tag);
        assert_eq!(value_of(&lines, "CWD"), "/");
        println!("production_launcher: scenario=working-dir cwd=/work/dir applied, / kept");
    }

    /// シナリオ M・N(OCI-1・TASK-29・SEC-1): 存在しない `cwd` は `NotFound`、ファイルを指す・symlink を含む `cwd` は
    /// `InvalidArgument` で start が失敗し、状態は Created のまま子が残らない。
    fn scenario_m_n_working_dir_refused(env: &Env, tag: u32) {
        for (name, cwd, want) in [
            ("m", "/missing", ErrorCode::NotFound),
            ("n", "/afile", ErrorCode::InvalidArgument),
            ("ns", "/alink/x", ErrorCode::InvalidArgument),
        ] {
            let bundle = Bundle::new(name);
            let ld = make_rootfs(&bundle.rootfs(), true);
            std::fs::write(bundle.rootfs().join("afile"), b"x").expect("write file");
            mkdir(&bundle.rootfs().join("real/x"));
            std::os::unix::fs::symlink("real", bundle.rootfs().join("alink")).expect("symlink");
            write_config_with(&bundle, &ld, &[], json!([]), cwd, (0, 0));
            let id = ContainerId::new(format!("pl{name}{tag}")).expect("id");
            do_create(env, &bundle, &id);
            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must fail for cwd {cwd}"),
                Err(e) => e,
            };
            assert_eq!(err.code(), want, "{cwd}: {}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                eventually(|| children_of_self().is_empty()),
                "no child may remain: {:?}",
                children_of_self()
            );
            println!(
                "production_launcher: scenario=working-dir-refused cwd={cwd} code={:?} state=created children=0",
                err.code()
            );
        }
    }

    /// シナリオ O(OCI-1・SEC-5): 単一 ID 写像で 0/0 以外の `process.user` は、fork の前に `FailedPrecondition` で
    /// 拒否される(状態は Created のまま、子は残らない)。
    fn scenario_o_user_outside_mapping_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("o");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config_with(&bundle, &ld, &[], json!([]), "/", (1000, 1000));
        let id = ContainerId::new(format!("plo{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must fail for an unmapped user"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(children_of_self().is_empty());
        println!(
            "production_launcher: scenario=user-unmapped-refused code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ O の拡張(OCI-1・SEC-5・CORE-6・#2667): 単一 ID 写像では `setgroups` が `deny` のため、
    /// `additionalGids` の指定は fork の前に `FailedPrecondition` で拒否され、状態は Created のまま子が残らない。
    fn scenario_o_groups_single_id_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("og");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config_groups(&bundle, &ld, &[], json!([]), "/", (0, 0), &[0]);
        let id = ContainerId::new(format!("plog{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must fail for additionalGids under a single id mapping"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        assert_eq!(
            err.message(),
            "process.user.additionalGids requires a subordinate id mapping (SEC-5)"
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(children_of_self().is_empty());
        println!(
            "production_launcher: scenario=groups-single-id-refused code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ I の拡張(`FANDHE_CONTAINER_TEST_ID_HELPER=1`。OCI-1・SEC-5): 範囲写像で `process.user` 1000:1000 を
    /// 指定すると、コンテナ内の実・実効・保存・FS の uid / gid が 1000 になり、ホストから見た uid は
    /// 「subuid の先頭 + 999」になる(コンテナ 1 → subuid 先頭)。
    fn scenario_i_user_applied(tag: u32) {
        use fandhe_container_core::rootless::{SubIdOwner, load_subordinate_ids};
        let state_dir = Bundle::new("istate");
        let store = FileStateStore::open(
            StateRoot::from_override(state_dir.dir.join("state")).expect("state root"),
        )
        .expect("open state store");
        let launcher: Arc<dyn ProcessLauncher> =
            Arc::new(build_subordinate_launcher().expect("build subordinate launcher"));
        let env = Env {
            store,
            _root: state_dir,
            launcher: Arc::clone(&launcher),
            recorder: OpRecorder::new(),
        };
        let (euid, _) = own_ids();
        let owner = SubIdOwner::new(euid, std::env::var("USER").ok()).expect("owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &owner).expect("load /etc/subuid");
        let base = uranges.first().expect("a subuid range").start();
        let lines = run_probe_with(&env, &launcher, "iu", "/", (1000, 1000), &|_| (), tag);
        assert_eq!(value_of(&lines, "UIDS"), "1000,1000,1000,1000");
        assert_eq!(value_of(&lines, "GIDS"), "1000,1000,1000,1000");
        let host_uid = base + 999;
        assert!(
            value_of(&lines, "HOST_UIDS")
                .split(',')
                .all(|v| v == host_uid.to_string()),
            "{lines:?}"
        );
        println!("production_launcher: scenario=user-applied uid=gid=1000 host_uid={host_uid}");
        // 補助グループ(#2667): additionalGids [3000, 2000] は gid 写像内(コンテナ 1 → subgid 先頭)なので適用され、
        // コンテナ内の Groups: はカーネルがソートした 2000,3000、ホストからは subgid 先頭 + 1999 / + 2999 に見える。
        let gowner = SubIdOwner::new(euid, std::env::var("USER").ok()).expect("gid owner");
        let granges =
            load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
        let gbase = granges.first().expect("a subgid range").start();
        let lines = run_probe_groups(
            &env,
            &launcher,
            "ig",
            "/",
            (1000, 1000),
            &[3000, 2000],
            &|_| (),
            tag,
        );
        assert_eq!(value_of(&lines, "GROUPS"), "2000,3000", "{lines:?}");
        let host_gids = format!("{},{}", gbase + 1999, gbase + 2999);
        assert_eq!(value_of(&lines, "HOST_GROUPS"), host_gids, "{lines:?}");
        println!(
            "production_launcher: scenario=groups-applied gids=2000,3000 host_gids={host_gids}"
        );
    }

    /// シナリオ E: 状態ルート自身、または状態ルートへの symlink 別名を bind mount の元にした start は、本番 launcher
    /// へ渡る前に `InvalidArgument` で拒否され、状態は Created のまま子が残らない（SEC-1・SEC-4・#2066）。
    /// start 後の改名・別の bind mount による別名は、namespace 内の mount 権限が要るため本試験の範囲外
    /// （`exec::mount_binds` の単体試験が inode の鎖で照合する）。
    fn scenario_e_state_root_bind_refused(env: &Env, tag: u32) {
        let state_root = env._root.dir.join("state");
        let alias_dir = Bundle::new("e-alias");
        let alias = alias_dir.dir.join("state-alias");
        std::os::unix::fs::symlink(&state_root, &alias).expect("symlink alias of state root");
        for (label, source) in [("direct", state_root.clone()), ("symlink", alias)] {
            let bundle = Bundle::new("e");
            let ld = make_rootfs(&bundle.rootfs(), true);
            let mounts = json!([{
                "destination": BIND_DEST,
                "type": "bind",
                "source": source.to_str().expect("utf8 source path"),
                "options": ["bind", "rw"]
            }]);
            write_config(&bundle, &ld, &["--with-bind"], mounts);
            let id = ContainerId::new(format!("ple{label}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must refuse a bind of the state root ({label})"),
                Err(e) => e,
            };
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                children_of_self().is_empty(),
                "no process may be spawned for a refused bind ({label})"
            );
            println!(
                "production_launcher: scenario=state-root-bind-refused kind={label} code={:?}",
                err.code()
            );
        }
    }

    /// シナリオ F: `mounts[]` の bind 先が `linux.readonlyPaths` と重なる config は、fork 前に `InvalidArgument` で拒否される
    /// （SEC-1・SEC-2・OCI-4・#2015。`check_against_protected_paths`。同一・祖先・子孫を字句で拒否する）。
    ///
    /// 経緯: 旧シナリオ F は Landlock の Mount 識別子照合（CORE-5・#2071）を、`readonlyPaths` に `/dev` または bind 先を足して
    /// 「記録後に別のマウントが重なる」起動で通そうとしたが、どちらも start 入口の重なり検査が先に拒否するため
    /// launch 中の照合には到達しなかった。config だけでは記録後のマウント差し替えを作れない（`apply_readonly_paths` は
    /// symlink を辿らず、重なりは字句で拒否される）ので、本シナリオは入口の拒否の副作用の無さ（状態は Created のまま・
    /// 子が作られない）を固定する。Landlock 適用時の拒否理由そのもの（`ViolationReason::LandlockMountIdentityMismatch`）は
    /// `exec/landlock.rs`・`landlock/apply.rs` の単体試験が照合する。本番経路で記録後に差し替える試験は、test 限定の
    /// 注入口が core に無いため未実装。記録と一致する側はシナリオ A・D の成功が担う。
    fn scenario_f_bind_over_protected_path_refused(env: &Env, tag: u32) {
        let src = Bundle::new("f-src");
        let bundle = Bundle::new("f");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &[], mounts);
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config.json"))
                .expect("parse config.json");
        config["linux"]["readonlyPaths"] = json!([BIND_DEST]);
        std::fs::write(
            &path,
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("rewrite config.json");
        let id = ContainerId::new(format!("plf{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("start must refuse a bind destination that overlaps a readonly path"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            children_of_self().is_empty(),
            "no process may be spawned for a refused config: {:?}",
            children_of_self()
        );
        println!(
            "production_launcher: scenario=bind-over-protected-path-refused code={:?} state=created children=0",
            err.code()
        );
    }

    /// シナリオ G: ホストの `/dev`（devtmpfs）を `bind` / `rbind` の元にした start は、付け替えた自分のマウントの
    /// fstype 名（`devtmpfs`）で拒否され、後始末で bind 先が残らない（SEC-1・#2129）。`f_type` は tmpfs と同じ値の
    /// ため `fstatfs` の判定では通り、mountinfo の照合だけが拒否する。拒否理由そのものは `exec::bind_mounts` の
    /// 単体試験が照合する（launch 中の拒否は pivot 後の子で起き、状態 pipe では親へ届かない）。
    fn scenario_g_devtmpfs_bind_refused(env: &Env, tag: u32) {
        // 前提: ホストの `/dev` が devtmpfs であること（そうでない環境では本シナリオは意味を持たないため失敗させる）。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        assert!(
            mountinfo.lines().any(|l| {
                let (pre, post) = l.split_once(" - ").unwrap_or((l, ""));
                pre.split(' ').nth(4) == Some("/dev") && post.starts_with("devtmpfs ")
            }),
            "host /dev must be a devtmpfs mount for scenario G"
        );
        for label in ["bind", "rbind"] {
            let bundle = Bundle::new("g");
            let ld = make_rootfs(&bundle.rootfs(), true);
            let mounts = json!([{
                "destination": BIND_DEST,
                "type": "bind",
                "source": "/dev",
                "options": [label, "rw"]
            }]);
            write_config(&bundle, &ld, &["--with-bind"], mounts);
            let id = ContainerId::new(format!("plg{label}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(_) => panic!("start must refuse a devtmpfs bind source ({label})"),
                Err(e) => e,
            };
            assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(!env.launcher.last_launch_may_have_left_process());
            assert!(
                eventually(|| children_of_self().is_empty()),
                "no process may remain after a refused launch ({label}): {:?}",
                children_of_self()
            );
            // 後始末: 適用の段が rootfs 内に作った bind 先は取り除かれている。
            assert!(
                !bundle
                    .rootfs()
                    .join(BIND_DEST.trim_start_matches('/'))
                    .exists(),
                "the bind destination must be rolled back ({label})"
            );
            println!(
                "production_launcher: scenario=devtmpfs-bind-refused kind={label} code={:?} state=created children=0 dest-removed",
                err.code()
            );
        }
    }

    /// ディレクトリ木を別の場所へ複製する（通常ファイルとディレクトリのみ。権限を引き継ぐ）。
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir(to).expect("create copy dir");
        let mode = std::fs::metadata(from)
            .expect("stat source dir")
            .permissions();
        std::fs::set_permissions(to, mode).expect("chmod copy dir");
        for entry in std::fs::read_dir(from).expect("read source dir") {
            let entry = entry.expect("dir entry");
            let target = to.join(entry.file_name());
            let kind = entry.file_type().expect("file type");
            if kind.is_dir() {
                copy_tree(&entry.path(), &target);
            } else if kind.is_file() {
                std::fs::copy(entry.path(), &target).expect("copy file");
            } else {
                panic!("unexpected entry kind in state root: {:?}", entry.path());
            }
        }
    }

    /// シナリオ H: start が状態ルートを固定した後（launcher が子を作る直前）に状態ルートが改名されると、適用の段が
    /// 記録したパスを辿り直して食い違いを検出し、bind mount を行わず拒否する（SEC-1・#2129）。元は状態ルートと
    /// 無関係なディレクトリで、改名が無ければ受理される（シナリオ D と同じ構成）。子を作る前に 1 回だけ、状態ルートを
    /// 別名へ改名し、同じパスへ内容を複製した別の inode のディレクトリを置く（start の後始末が同じパスの状態ストアを
    /// 使い続けられるようにするため。固定した実体は改名先に残る）。
    fn scenario_h_state_root_moved_after_start(env: &Env, tag: u32) {
        let src = Bundle::new("h-src");
        let bundle = Bundle::new("h");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let mounts = json!([{
            "destination": BIND_DEST,
            "type": "bind",
            "source": src.dir.to_str().expect("utf8 source path"),
            "options": ["bind", "rw"]
        }]);
        write_config(&bundle, &ld, &["--with-bind"], mounts);
        let id = ContainerId::new(format!("plh{tag}")).expect("id");
        do_create(env, &bundle, &id);

        let state_root = env._root.dir.join("state");
        let moved = env._root.dir.join("state-moved");
        {
            let (from, to) = (state_root.clone(), moved.clone());
            *PRE_SPAWN_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(move || {
                std::fs::rename(&from, &to).expect("rename state root after start");
                copy_tree(&to, &from);
            }));
        }
        wait_single_thread();
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        // 固定した実体（改名先）は不要になる。同じパスの複製が以降の状態ルートになる。
        let renamed = moved.exists();
        if renamed {
            std::fs::remove_dir_all(&moved).expect("remove the renamed original state root");
        }
        assert!(
            renamed,
            "the pre-spawn hook must have renamed the state root"
        );
        let err = match result {
            Ok(_) => panic!("start must refuse when the state root moved after start"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::InvalidArgument, "{}", err.message());
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no process may remain after a refused launch: {:?}",
            children_of_self()
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(
            std::fs::read_dir(&src.dir)
                .expect("read bind source")
                .next()
                .is_none(),
            "nothing may be written to the bind source"
        );
        assert!(
            !bundle
                .rootfs()
                .join(BIND_DEST.trim_start_matches('/'))
                .exists(),
            "no bind destination may remain"
        );
        println!(
            "production_launcher: scenario=state-root-moved-after-start code={:?} state=created children=0",
            err.code()
        );
    }

    /// `/proc/<x>/status` の cap 行（16 桁の 16 進）を `u64` へ直す。
    fn cap_value(text: &str) -> u64 {
        u64::from_str_radix(text.trim(), 16)
            .unwrap_or_else(|e| panic!("cap field {text:?} is not hex: {e}"))
    }

    /// 起動済みの子を、成否に関わらず terminate して回収する共通後始末（panic を覆い隠さない）。
    fn finish_started(
        started: fandhe_container_core::oci_runtime::StartedContainer,
        verified: std::thread::Result<()>,
    ) {
        let pid = started.process().pid();
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "production_launcher: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
    }

    /// シナリオ J: exec 後の capability と seccomp の実効（#2012・SEC-1・CORE-5）。
    fn scenario_j_exec_restrictions(env: &Env, tag: u32) {
        // 公開 API の OCI 既定集合から組んだマスクと、リテラルの両方で照合する（`tests/capabilities.rs` の `mask_of` と同じ作り方）。
        let from_api = OCI_DEFAULT_CAPABILITIES
            .iter()
            .fold(0u64, |m, c| m | (1u64 << c.index()));
        const OCI_DEFAULT_MASK: u64 = 0x0000_0000_a804_25fb;
        assert_eq!(from_api, OCI_DEFAULT_MASK, "OCI default capability mask");

        // 適用前の kcmp 対照（親は組み込みフィルタを載せていない）。外側が拒否する環境は前提欠如として失敗させる（#2234）。
        let kcmp_before = probe_kcmp_self_for_test();
        let seccomp_before =
            status_field("/proc/self/status", "Seccomp:").unwrap_or_else(|| "unknown".to_string());
        match classify_kcmp_before(kcmp_before) {
            KcmpPrecondition::Ok => {}
            KcmpPrecondition::Denied { errno } => {
                panic!("{}", precondition_message(errno, &seccomp_before))
            }
            // 判定不能は前提欠如と表示せず、汎用の失敗にする（fail-closed）。
            KcmpPrecondition::Unknown => panic!(
                "production_launcher: kcmp control probe could not be evaluated (got {kcmp_before:?})"
            ),
        }

        let bundle = Bundle::new("j");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-restrictions"], json!([]));
        let id = ContainerId::new(format!("plj{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);

            // コンテナ内（exec 後の PID 1）から見た値。
            assert_eq!(value_of(&lines, "PID"), "1");
            for (key, want) in [
                ("CapInh", 0),
                ("CapAmb", 0),
                ("CapPrm", OCI_DEFAULT_MASK),
                ("CapEff", OCI_DEFAULT_MASK),
                ("CapBnd", OCI_DEFAULT_MASK),
            ] {
                assert_eq!(
                    cap_value(value_of(&lines, &format!("CAP {key}"))),
                    want,
                    "in-container {key}"
                );
                // ホストから見た同じプロセス（exec 後）の値。
                let host = status_field(&format!("/proc/{pid}/status"), &format!("{key}:"))
                    .unwrap_or_else(|| panic!("host {key} missing"));
                assert_eq!(cap_value(&host), want, "host view of {key}");
            }
            assert_eq!(value_of(&lines, "NONEWPRIVS"), "1");
            assert_eq!(value_of(&lines, "SECCOMP"), "2");
            // 拒否される syscall と、許可される syscall の対照。
            assert_eq!(value_of(&lines, "SECCOMP_MOUNT"), "Ok(Errno(1))");
            assert_eq!(value_of(&lines, "SECCOMP_CONTROL"), "ok");
            // 識別的な照合: kcmp の EPERM は seccomp 以外では生じない（親側の適用前の対照が成功している前提）。
            assert!(
                !lines.iter().any(|l| l.starts_with("SECCOMP_RECORD_ERROR")),
                "seccomp record probe failed: {lines:?}"
            );
            let record_text = lines
                .iter()
                .filter_map(|l| l.strip_prefix("SECCOMP_RECORD "))
                .collect::<Vec<_>>()
                .join("\n");
            let rec = SeccompProbeRecord::parse(&record_text)
                .unwrap_or_else(|e| panic!("parse post-exec seccomp record: {e}; {lines:?}"));
            assert_eq!(rec.kcmp, ProbeOutcome::Errno(1), "post-exec kcmp EPERM");
            assert_eq!(rec.seccomp_mode, "2", "post-exec SECCOMP_MODE_FILTER");
            assert_eq!(rec.control, ProbeOutcome::Ok, "post-exec control read");
            assert_eq!(rec.mount, ProbeOutcome::Errno(1), "post-exec mount EPERM");
            assert_eq!(
                rec.pivot_root,
                ProbeOutcome::Errno(1),
                "post-exec pivot_root EPERM"
            );
            assert_eq!(
                rec.umount2,
                ProbeOutcome::Errno(1),
                "post-exec umount2 EPERM"
            );
            println!("production_launcher: scenario=j pid={pid} post-exec caps and seccomp ok");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ T: `process.capabilities` の drop が exec 後の PID 1 に効く（#2666・SEC-1・CRI-2）。
    /// 3 集合を「OCI 既定 - CAP_NET_RAW - CAP_MKNOD」にすると、`CapPrm`・`CapEff`・`CapBnd` が
    /// `0xa80425fb` から bit 13・27 を除いた `0xa00405fb` になり、`CapInh`・`CapAmb` は 0 のまま。
    fn scenario_t_capabilities_drop(env: &Env, tag: u32) {
        const DROPPED_MASK: u64 = 0x0000_0000_a004_05fb;
        let names: Vec<&str> = OCI_DEFAULT_CAPABILITIES
            .iter()
            .filter(|c| c.as_str() != "CAP_NET_RAW" && c.as_str() != "CAP_MKNOD")
            .map(|c| c.as_str())
            .collect();
        let bundle = Bundle::new("t");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-restrictions"], json!([]));
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config")).expect("json");
        config["process"]["capabilities"] =
            json!({"bounding": names, "effective": names, "permitted": names});
        std::fs::write(&path, serde_json::to_vec(&config).expect("serialize")).expect("write");
        let id = ContainerId::new(format!("plv{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            for (key, want) in [
                ("CapInh", 0),
                ("CapAmb", 0),
                ("CapPrm", DROPPED_MASK),
                ("CapEff", DROPPED_MASK),
                ("CapBnd", DROPPED_MASK),
            ] {
                assert_eq!(
                    cap_value(value_of(&lines, &format!("CAP {key}"))),
                    want,
                    "in-container {key}"
                );
                let host = status_field(&format!("/proc/{pid}/status"), &format!("{key}:"))
                    .unwrap_or_else(|| panic!("host {key} missing"));
                assert_eq!(cap_value(&host), want, "host view of {key}");
            }
            println!(
                "production_launcher: capabilities drop applied (scenario=T pid={pid} cap_eff=0xa00405fb)"
            );
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// シナリオ N(NET-6・CORE-6・SEC-1・#3064): `Loopback` モードの起動で、コンテナがホストと別の netns に入り、
    /// `lo`(とカーネルのフォールバックトンネル)だけを持ち、`lo` が up で 127.0.0.1 の自己宛て UDP が届くことを
    /// 具体値で照合する(`lo` が down だと受信が期限切れになる: #2077)。コンテナの終了後に netns の pin
    /// (nsfs のマウント・自 uid で読める他プロセスの `ns/net`)が残らないことも照合する。
    /// `subordinate` が真なら範囲写像(holder の user namespace へ `setns` した後の unshare)の経路で回す。
    fn scenario_n_network_loopback(env: &Env, tag: u32, subordinate: bool) {
        let mut tmpfs = TmpfsMountSet::new();
        tmpfs.ensure_default_dev_shm().expect("default dev shm");
        let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
            .expect("launch options")
            .with_network(LaunchNetworkMode::Loopback);
        let mut builder = ProductionLauncher::builder();
        builder = if subordinate {
            builder
                .privilege(IsolationPrivilege::RootlessSubordinateIds)
                .subordinate_ids(
                    SubordinateIdSource::system(std::env::var("USER").ok())
                        .expect("subordinate ids"),
                )
        } else {
            builder.privilege(IsolationPrivilege::RootlessSingleId)
        };
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(
            builder
                .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
                .launch_options(options)
                .build()
                .expect("build launcher for loopback network"),
        );
        let host_netns = std::fs::read_link("/proc/self/ns/net")
            .expect("host net ns")
            .display()
            .to_string();

        let bundle = Bundle::new(if subordinate { "ns" } else { "n" });
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--net-loopback"], json!([]));
        // 他シナリオの id(`pl{name}{tag}`。例: working-dir-refused の `pln{tag}`)と衝突しない固有の接頭辞にする。
        let id = ContainerId::new(format!(
            "plnet{}{tag}",
            if subordinate { "sub" } else { "own" }
        ))
        .expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let mut container_netns = String::new();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            container_netns = value_of(&lines, "NETNS").to_string();
            assert!(
                container_netns.starts_with("net:["),
                "container netns: {container_netns}"
            );
            assert_ne!(container_netns, host_netns, "must not share the host netns");
            assert_eq!(value_of(&lines, "NETDEV_LO"), "true");
            assert_eq!(value_of(&lines, "NETDEV_EXTRA"), "none");
            assert_eq!(value_of(&lines, "UDP_SELF"), "ok");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
        // pin が残らない: nsfs のマウントも、自 uid で読める他プロセスの ns/net も、コンテナの netns を指さない。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        assert!(
            !mountinfo
                .lines()
                .any(|l| l.contains("nsfs") && l.contains(&container_netns)),
            "no nsfs mount may pin the container netns"
        );
        let held = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
            })
            .filter(|e| {
                std::fs::read_link(e.path().join("ns/net"))
                    .is_ok_and(|p| p.display().to_string() == container_netns)
            })
            .count();
        assert_eq!(held, 0, "no process may keep the container netns alive");
        // 成功行は固定文言(CI の照合が試験ソースの文字列リテラルから期待行を導出するため、プレースホルダを持たせない)。
        if subordinate {
            println!(
                "production_launcher: network loopback isolated lo up and self delivery ok; no netns pin after terminate (scenario=N-subordinate)"
            );
        } else {
            println!(
                "production_launcher: network loopback isolated lo up and self delivery ok; no netns pin after terminate (scenario=N)"
            );
        }
    }

    /// シナリオ Z(NET-6・SEC-1・SEC-4・#3206): `Host` モードの起動が exec 直前の netns 素性の同期点を通る(受理)ことと、
    /// 基準を差し替えた起動が拒否・監査・回収されることを具体値で照合する。
    fn scenario_z_network_host_netns_sync(env: &Env, tag: u32) {
        let host_netns = std::fs::read_link("/proc/self/ns/net")
            .expect("host net ns")
            .display()
            .to_string();
        let host_ino = std::fs::metadata("/proc/self/ns/net").expect("host ns meta");
        let make_launcher = |sink: Arc<MemSink>, forged: bool| -> Arc<dyn ProcessLauncher> {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs.ensure_default_dev_shm().expect("default dev shm");
            let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
                .expect("launch options")
                .with_network(LaunchNetworkMode::Host);
            let mut builder = ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSingleId)
                .audit_sink(sink)
                .launch_options(options);
            if forged {
                use std::os::unix::fs::MetadataExt as _;
                // 実在しない inode（0）。dev は本物のままで、素性が一致しない。
                builder = builder.netns_baseline_override_for_test(host_ino.dev(), 0);
            }
            Arc::new(builder.build().expect("build launcher for host network"))
        };

        // 受理: 基準は supervisor 自身の netns（差し替えなし）。コンテナ内の netns の識別子がホストと同じ。
        let accept_sink = Arc::new(MemSink(std::sync::Mutex::new(Vec::new())));
        let launcher = make_launcher(Arc::clone(&accept_sink), false);
        let bundle = Bundle::new("z");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--net-loopback"], json!([]));
        let id = ContainerId::new(format!("plnethost{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(
                value_of(&lines, "NETNS"),
                host_netns,
                "host mode must share the host netns"
            );
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            accept_sink
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "an accepted netns sync must record nothing"
        );
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after terminate"
        );

        // 拒否: 基準を差し替えた起動は FailedPrecondition で失敗し、監査に 1 件残り、子が残らない。
        let reject_sink = Arc::new(MemSink(std::sync::Mutex::new(Vec::new())));
        let launcher = make_launcher(Arc::clone(&reject_sink), true);
        let bundle = Bundle::new("zr");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--net-loopback"], json!([]));
        let id = ContainerId::new(format!("plnethostrej{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("a forged netns baseline must be rejected"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            ErrorCode::FailedPrecondition,
            "{}",
            err.message()
        );
        // launcher は ExecError を段名だけの固定文言へ写す(`to_trait_error`)。理由は下の監査記録で照合する。
        assert_eq!(
            err.message(),
            "container launch failed in the NetnsVerify stage"
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        let records = reject_sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(
            records
                .iter()
                .all(|r| r.contains("netns_identity_mismatch") && r.contains("netns_verify")),
            "{records:?}"
        );
        assert!(!launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "a rejected launch must leave no process: {:?}",
            children_of_self()
        );
        println!(
            "production_launcher: network host netns sync accepted; forged baseline rejected with audit and no process (scenario=Z)"
        );
    }

    /// シナリオ A-attach の試験用フック。受け取った fd の素性と、合図の前に exec が起きていないことを記録して、`result` を返す。
    struct AttachProbeHook {
        /// 受け取った (net の ino, user の ino)。
        seen: std::sync::Mutex<Option<(u64, u64)>>,
        /// フックの中で「PID 1 がまだ exec していない」を確かめられたか。
        not_exec_yet: std::sync::atomic::AtomicBool,
        result: Result<(), ErrorCode>,
    }

    impl NetnsAttachHook for AttachProbeHook {
        fn attach(
            &self,
            namespaces: AttachableNamespaces,
            _deadline: Instant,
        ) -> Result<(), TraitError> {
            let ino_of = |fd: std::os::fd::BorrowedFd<'_>| {
                std::fs::File::from(fd.try_clone_to_owned().expect("dup ns fd"))
                    .metadata()
                    .expect("ns fd metadata")
                    .ino()
            };
            let seen = (ino_of(namespaces.net()), ino_of(namespaces.user()));
            *self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seen);
            // 合図の前に PID 1 は exec していない: 子の `Name:` が exec 後のエントリ名 `probe` になるのは exec の後だけ。
            let exec_started = || {
                children_of_self().iter().any(|pid| {
                    std::fs::read_to_string(format!("/proc/{pid}/status"))
                        .ok()
                        .and_then(|s| s.lines().next().map(str::to_owned))
                        .is_some_and(|l| l.trim_end() == "Name:\tprobe")
                })
            };
            let before = exec_started();
            std::thread::sleep(Duration::from_millis(200));
            let after = exec_started();
            self.not_exec_yet
                .store(!before && !after, std::sync::atomic::Ordering::SeqCst);
            self.result
                .map_err(|code| TraitError::new(code, "attach hook detail"))
        }
    }

    /// シナリオ A-attach(NET-9・CORE-6・SEC-1・REPAIR-5・#1939): `Attachable` モードの同期点。受理の側は、フックが netns と
    /// user namespace の fd(ホストと異なる素性)を合図の前に受け取り、その時点で PID 1 が exec しておらず、合図の後に
    /// コンテナがフックで受けた netns の中で `lo` だけ up の状態で動くことを照合する。拒否の側は Err を返すフックで起動し、
    /// `start` の code と固定文言・状態 Created・子が残らないことを照合する。
    /// `subordinate` が真なら範囲写像の経路で回す。
    fn scenario_attachable_network(env: &Env, tag: u32, subordinate: bool) {
        use std::sync::atomic::Ordering;
        let make_launcher = |hook: Arc<AttachProbeHook>| -> Arc<dyn ProcessLauncher> {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs.ensure_default_dev_shm().expect("default dev shm");
            let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
                .expect("launch options")
                .with_network(LaunchNetworkMode::Attachable);
            let builder = if subordinate {
                ProductionLauncher::builder()
                    .privilege(IsolationPrivilege::RootlessSubordinateIds)
                    .subordinate_ids(
                        SubordinateIdSource::system(std::env::var("USER").ok())
                            .expect("subordinate ids"),
                    )
            } else {
                ProductionLauncher::builder().privilege(IsolationPrivilege::RootlessSingleId)
            };
            Arc::new(
                builder
                    .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
                    .launch_options(options)
                    .netns_attach_hook(hook)
                    .build()
                    .expect("build launcher for attachable network"),
            )
        };
        let host_net_ino = std::fs::metadata("/proc/self/ns/net")
            .expect("host net ns")
            .ino();
        let host_user_ino = std::fs::metadata("/proc/self/ns/user")
            .expect("host user ns")
            .ino();
        let suffix = if subordinate { "sub" } else { "own" };

        // 受理。
        let hook = Arc::new(AttachProbeHook {
            seen: std::sync::Mutex::new(None),
            not_exec_yet: std::sync::atomic::AtomicBool::new(false),
            result: Ok(()),
        });
        let launcher = make_launcher(Arc::clone(&hook));
        let bundle = Bundle::new(if subordinate { "nasub" } else { "na" });
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--net-loopback"], json!([]));
        let id = ContainerId::new(format!("plattach{suffix}{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let seen = *hook
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (hook_net, hook_user) = seen.expect("the hook must have been called once before exec");
        assert_ne!(hook_net, host_net_ino, "the handed netns must be new");
        assert_ne!(hook_user, host_user_ino, "the handed userns must be new");
        assert!(
            hook.not_exec_yet.load(Ordering::SeqCst),
            "the container must not exec before the launcher's acknowledgement"
        );
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(
                value_of(&lines, "NETNS"),
                format!("net:[{hook_net}]"),
                "the container must run in the netns handed to the hook"
            );
            assert_eq!(value_of(&lines, "NETDEV_LO"), "true");
            assert_eq!(value_of(&lines, "NETDEV_EXTRA"), "none");
            assert_eq!(value_of(&lines, "UDP_SELF"), "ok");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after terminate"
        );

        // 拒否: フックが Err なら exec させず、code を保ち、固定文言で、状態は Created のまま子が残らない。
        let hook = Arc::new(AttachProbeHook {
            seen: std::sync::Mutex::new(None),
            not_exec_yet: std::sync::atomic::AtomicBool::new(false),
            result: Err(ErrorCode::Unavailable),
        });
        let launcher = make_launcher(Arc::clone(&hook));
        let bundle = Bundle::new(if subordinate { "narsub" } else { "nar" });
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--net-loopback"], json!([]));
        let id = ContainerId::new(format!("plattachrej{suffix}{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let err = match start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(_) => panic!("a failing attach hook must reject the start"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::Unavailable, "{}", err.message());
        assert_eq!(
            err.message(),
            "container launch failed in the NetnsAttach stage"
        );
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(hook.not_exec_yet.load(Ordering::SeqCst));
        assert!(!launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "a rejected launch must leave no process: {:?}",
            children_of_self()
        );
        // 成功行は固定文言(CI の照合が試験ソースの文字列リテラルから期待行を導出するため、プレースホルダを持たせない)。
        if subordinate {
            println!(
                "production_launcher: network attachable netns handed over before exec; hook failure left no process (scenario=attachable-subordinate)"
            );
        } else {
            println!(
                "production_launcher: network attachable netns handed over before exec; hook failure left no process (scenario=attachable)"
            );
        }
    }

    /// シナリオ V: `linux.sysctl` の namespaced キー(IPC 系 `kernel.shmmax`)が実際の IPC namespace と procfs を通って
    /// コンテナ内で指定どおりの値になり、ホスト側の値が変わらないことを照合する(CRI-2・CORE-3・SEC-1・REPAIR-12・#2670)。
    fn scenario_v_sysctls(env: &Env, tag: u32) {
        const WANT: &str = "4194304";
        const HOST_FILE: &str = "/proc/sys/kernel/shmmax";
        let host_before = std::fs::read_to_string(HOST_FILE)
            .expect("read host shmmax")
            .trim()
            .to_string();
        assert_ne!(
            host_before, WANT,
            "host shmmax must differ from the value under test"
        );
        let bundle = Bundle::new("sysctl");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--with-sysctl"], json!([]));
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config")).expect("json");
        config["linux"]["sysctl"] = json!({"kernel.shmmax": WANT});
        std::fs::write(&path, serde_json::to_vec(&config).expect("serialize")).expect("write");
        let id = ContainerId::new(format!("plsy{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let lines = collect_probe(&reader_slot.as_ref().expect("reader slot").0);
            assert_eq!(
                value_of(&lines, "SYSCTL_SHMMAX"),
                WANT,
                "in-container shmmax"
            );
            let host_after = std::fs::read_to_string(HOST_FILE)
                .expect("read host shmmax")
                .trim()
                .to_string();
            assert_eq!(host_after, host_before, "host shmmax must be unchanged");
            println!(
                "production_launcher: sysctls applied (scenario=V shmmax={WANT} host_unchanged={host_before})"
            );
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// 起動済みコンテナの標準出力を読み、プローブの `READY` までを回収する（exec 後の状態を観測するため）。
    ///
    /// リーダースレッドは `READY` を送った時点で終了し、ここで join する。スレッドを残すと次の launch の前提
    /// （`wait_single_thread` の `Threads: 1`）に戻れないため（REPAIR-12）。`READY` の後のプローブは出力せず待つだけ。
    fn wait_probe_ready(started: &fandhe_container_core::oci_runtime::StartedContainer) {
        let output = started.process().take_output().expect("container output");
        let stdout = output.stdout.expect("container stdout");
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            for _ in 0..LINES_MAX {
                let mut line = String::new();
                match (&mut reader).take(LINE_MAX).read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        let line = line.trim_end().to_string();
                        let ready = line == PROBE_READY;
                        if tx.send(line).is_err() || ready {
                            return;
                        }
                    }
                }
            }
        });
        let _ = collect_probe(&rx);
        handle.join().expect("join reader");
    }

    /// 名前空間の識別子（`/proc/<pid>/ns/<name>` のリンク先。例 `ipc:[4026531839]`）。
    fn ns_link(pid: impl std::fmt::Display, name: &str) -> String {
        std::fs::read_link(format!("/proc/{pid}/ns/{name}"))
            .unwrap_or_else(|e| panic!("read_link /proc/{pid}/ns/{name}: {e}"))
            .display()
            .to_string()
    }

    /// シナリオ W: pod の user・ipc namespace への join（#2674・CRI-2・CORE-3・SEC-1・SEC-5）。
    fn scenario_w_pod_ipc_join(env: &Env, tag: u32) {
        // 否定: 試験プロセス自身の namespace を指す path は、fork の前に PermissionDenied で拒否される。
        {
            let bundle = Bundle::new("w-own");
            let ld = make_rootfs(&bundle.rootfs(), true);
            write_config(&bundle, &ld, &[], json!([]));
            patch_namespaces(
                &bundle,
                json!([
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"},
                    {"type": "ipc", "path": "/proc/self/ns/ipc"},
                    {"type": "user", "path": "/proc/self/ns/user"}
                ]),
            );
            let id = ContainerId::new(format!("plwn{tag}")).expect("id");
            do_create(env, &bundle, &id);
            wait_single_thread();
            let Err(err) = start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) else {
                panic!("joining the caller's own namespaces must be refused");
            };
            assert_eq!(err.code(), ErrorCode::PermissionDenied);
            assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            assert!(children_of_self().is_empty(), "no child may remain");
        }

        // 正常: A の user・ipc namespace に B が join する。
        let a_bundle = Bundle::new("w-a");
        let ld = make_rootfs(&a_bundle.rootfs(), true);
        write_config(&a_bundle, &ld, &[], json!([]));
        let a_id = ContainerId::new(format!("plwa{tag}")).expect("id");
        do_create(env, &a_bundle, &a_id);
        wait_single_thread();
        let a = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(a_id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start A failed: {:?} {}", e.code(), e.message()));
        let a_pid = a.process().pid();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_probe_ready(&a);
            let b_bundle = Bundle::new("w-b");
            let ld = make_rootfs(&b_bundle.rootfs(), true);
            write_config(&b_bundle, &ld, &[], json!([]));
            patch_namespaces(
                &b_bundle,
                json!([
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"},
                    {"type": "ipc", "path": format!("/proc/{a_pid}/ns/ipc")},
                    {"type": "user", "path": format!("/proc/{a_pid}/ns/user")}
                ]),
            );
            let b_id = ContainerId::new(format!("plwb{tag}")).expect("id");
            do_create(env, &b_bundle, &b_id);
            wait_single_thread();
            let b = start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(b_id.clone()),
                &timeouts(),
            )
            .unwrap_or_else(|e| panic!("start B failed: {:?} {}", e.code(), e.message()));
            let b_pid = b.process().pid();
            let b_verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                wait_probe_ready(&b);
                for shared in ["user", "ipc"] {
                    assert_eq!(
                        ns_link(b_pid, shared),
                        ns_link(a_pid, shared),
                        "B must share A's {shared} namespace"
                    );
                }
                for own in ["pid", "mnt", "uts"] {
                    assert_ne!(
                        ns_link(b_pid, own),
                        ns_link(a_pid, own),
                        "B must have its own {own} namespace"
                    );
                }
                // B の PID 1 は自分の pid namespace の PID 1(共有しない)。
                let nspid =
                    status_field(&format!("/proc/{b_pid}/status"), "NSpid:").expect("host NSpid");
                assert_eq!(nspid.split_whitespace().last(), Some("1"));
                println!(
                    "production_launcher: pod ipc namespace joined (scenario=W user and ipc shared, pid/mnt/uts separate, join of own namespaces refused)"
                );
            }));
            finish_started(b, b_verified);
        }));
        finish_started(a, verified);
        assert!(
            children_of_self().is_empty(),
            "no child may remain after terminate"
        );
    }

    /// 書き出した `config.json` の `linux.namespaces` を差し替える（シナリオ W）。
    fn patch_namespaces(bundle: &Bundle, namespaces: serde_json::Value) {
        let path = bundle.dir.join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read config")).expect("json");
        config["linux"]["namespaces"] = namespaces;
        std::fs::write(&path, serde_json::to_vec(&config).expect("serialize")).expect("write");
    }

    /// シナリオ K: exec 後の seccomp が禁止 syscall を SIGSYS で拒否する（#2012・SEC-2・CORE-5）。
    fn scenario_k_seccomp_kill_after_exec(env: &Env, tag: u32) {
        // SIGSYS（x86_64・aarch64 とも 31）。`SECCOMP_RET_KILL_PROCESS` は seccomp 以外では生じない。
        const SIGSYS: i32 = 31;
        for (n, name) in ["unshare", "ptrace", "kexec_load"].into_iter().enumerate() {
            let bundle = Bundle::new(&format!("k{n}"));
            let ld = make_rootfs(&bundle.rootfs(), true);
            write_config(&bundle, &ld, &["--seccomp-kill", name], json!([]));
            let id = ContainerId::new(format!("plk{n}{tag}")).expect("id");
            do_create(env, &bundle, &id);

            wait_single_thread();
            let started = start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            )
            .unwrap_or_else(|e| panic!("start failed ({name}): {:?} {}", e.code(), e.message()));
            let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> =
                None;
            let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let probe_pid = started.process().pid();
                let output = started.process().take_output().expect("container output");
                let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
                reader_slot = Some((rx, reader));
                let exit = started
                    .process()
                    .wait(timeout())
                    .expect("wait for the probe")
                    .unwrap_or_else(|| {
                        panic!(
                            "{name}: the probe did not exit within the timeout; {}",
                            crate::proc_status::excerpt(probe_pid.get())
                        )
                    });
                assert_eq!(
                    exit,
                    ProcessExit::Signaled(SIGSYS),
                    "{name}: a forbidden syscall must kill the process with SIGSYS"
                );
                // 出力は EOF まで読み、発行の直前の行があり、戻りの行が無いことを照合する。
                let rx = &reader_slot.as_ref().expect("reader slot").0;
                let mut lines = Vec::new();
                let deadline = Instant::now() + timeout();
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(left) {
                        Ok(line) => lines.push(line),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            panic!("{name}: the probe output did not reach EOF; got {lines:?}")
                        }
                    }
                }
                assert!(
                    lines.contains(&format!("SECCOMP_KILL_ATTEMPT {name}")),
                    "{name}: attempt line missing in {lines:?}"
                );
                assert!(
                    !lines.iter().any(|l| l.starts_with("SECCOMP_KILL_RETURNED")),
                    "{name}: the syscall returned instead of being killed: {lines:?}"
                );
                println!("production_launcher: scenario=k {name} killed with SIGSYS");
            }));
            finish_started(started, verified);
            let (rx, reader) = reader_slot.take().expect("reader slot");
            reader.join().expect("join reader");
            drop(rx);
            assert!(
                children_of_self().is_empty(),
                "no child may remain after terminate"
            );
        }
    }

    /// シナリオ Q（SEC-4・ESC-06・REPAIR-5・#2236。issue 本文の「シナリオ I」にあたる。I は範囲写像で使用済みのため Q とする）:
    /// SIGSYS で終了したコンテナの `exit_signal` 補助記録が、複数スレッドのプロセスから回収しても落ちず、本番と同じ配送経路
    /// （`ControlAuditRelay` → `FileAuditSink` → `<状態ルート>/@audit.log`）にちょうど 1 件残ることを照合する。
    ///
    /// 構成: 単一スレッドの間に relay を spawn し、launcher の回収点の記録先（`exit_audit_sink`）にだけ渡す（launch の時点の
    /// 記録先は `MemSink` のまま）。start の後に補助スレッドを立てて複数スレッドにしてから `wait` する（supervisor の監視スレッドが
    /// 回収する状況の再現）。relay の helper は test プロセスと同じ cgroup に残るが、cgroup の準備（`prepare`）は済んでいる。
    /// 照合: `@audit.log` の `layer=exit_signal` かつ当コンテナの行がちょうど 1 行で、`signal` 31・`target_pid` = コンテナの
    /// 回収した PID・`syscall`/`arch` は null。再度の `wait` / `terminate` の後も 1 行のまま（二重記録なし）。
    /// 複数スレッドの直接 `FileAuditSink` との対照（主経路は `isolation_unavailable`、代替経路はホスト依存）は、結果が
    /// ホストの権限で変わるため照合しない。
    fn scenario_q_exit_signal_via_relay(env: &Env, container: &Arc<ContainerCgroup>, tag: u32) {
        const SIGSYS: i32 = 31;
        let log = env._root.dir.join("state").join(AUDIT_LOG_FILE_NAME);
        wait_single_thread();
        let relay = Arc::new(
            ControlAuditRelay::spawn(FileAuditSink::in_state_store(&env.store))
                .expect("spawn the audit relay while single-threaded"),
        );
        let join_container = Arc::clone(container);
        let launcher = ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSingleId)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))))
            .exit_audit_sink(Arc::clone(&relay) as Arc<dyn AuditSink>)
            .cgroup_join_source(move || join_container.join_hook())
            .build()
            .expect("build the launcher with a relay for exit audit");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(launcher);

        let bundle = Bundle::new("q");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &["--seccomp-kill", "unshare"], json!([]));
        let id = ContainerId::new(format!("plq{tag}")).expect("id");
        do_create(env, &bundle, &id);
        let started = start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed (q): {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        // 以後は複数スレッド（補助スレッドは検証の終わりまで生かす）。
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = stop_rx.recv();
        });
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let threads: u32 = status_field("/proc/self/status", "Threads:")
                .and_then(|v| v.trim().parse().ok())
                .expect("Threads");
            assert!(
                threads >= 2,
                "the reap must run in a multi-threaded process"
            );
            let output = started.process().take_output().expect("container output");
            reader_slot = Some(spawn_reader(output.stdout.expect("container stdout")));
            let exit = started
                .process()
                .wait(timeout())
                .expect("wait for the probe")
                .unwrap_or_else(|| {
                    panic!(
                        "the probe must exit within the timeout; {}",
                        crate::proc_status::excerpt(pid.get())
                    )
                });
            assert_eq!(exit, ProcessExit::Signaled(SIGSYS));
            assert_eq!(
                started.process().wait(Duration::ZERO).expect("wait again"),
                Some(ProcessExit::Signaled(SIGSYS))
            );
            // 回収済みの後の terminate でも件数は増えない（この後 `finish_started` がもう 1 回呼ぶ）。
            started
                .process()
                .terminate(timeout())
                .expect("terminate after reap");
            let text = std::fs::read_to_string(&log).expect("the audit log must exist");
            let mine: Vec<&str> = text
                .lines()
                .filter(|l| {
                    l.contains("\"layer\":\"exit_signal\"")
                        && l.contains(&format!("\"container_id\":\"{}\"", id.as_str()))
                })
                .collect();
            assert_eq!(mine.len(), 1, "exactly one exit_signal line: {text:?}");
            let line = mine[0];
            assert!(
                line.contains(&format!("\"signal\":{SIGSYS},\"target_pid\":{pid},")),
                "signal/target_pid mismatch: {line}"
            );
            assert!(
                line.contains("\"syscall\":null,\"arch\":null"),
                "no syscall may be inferred: {line}"
            );
            println!("production_launcher: exit_signal recorded once via audit relay (scenario=Q)");
        }));
        finish_started(started, verified);
        drop(stop_tx);
        helper.join().expect("join helper thread");
        if let Some((rx, reader)) = reader_slot.take() {
            reader.join().expect("join reader");
            drop(rx);
        }
        drop(launcher);
        drop(relay);
        wait_single_thread();
        assert!(eventually(|| children_of_self().is_empty()));
    }

    /// シナリオ S（SEC-4・SUP-6・SEC-1・REPAIR-3・#2624）: エントリポイントがランタイム自身のバイナリ（PID 1 の
    /// `/proc/self/exe` と同じ `(st_dev, st_ino)`）の launch は、PID 1 が exec 前に状態 pipe へ返す違反が親（この
    /// テストプロセス = C）で層 `entrypoint` に記録され、起動失敗になる。
    ///
    /// 構成: 試験バイナリ自身のディレクトリを `/host-bin` へ bind し、`args[0]` をその中の試験バイナリの絶対パスにする
    /// （bind は inode と `st_dev` を保つため、PID 1 の `/proc/self/exe` と同一になる。PID 1 は fork 子で、exec していない）。
    /// 照合: `start` が `Err`（`PermissionDenied`）、状態は Created のまま、子が残らない。launcher の記録先に層
    /// `entrypoint`・`reason=entrypoint_is_runtime_binary`・当コンテナの ID・パスなしのレコードがちょうど 1 件。
    /// 成功行は変えず、固有の行を前に出す（`ci.yml` の grep は最終行だけを見る）。
    fn scenario_s_entrypoint_violation_recorded(
        env: &Env,
        container: &Arc<ContainerCgroup>,
        tag: u32,
    ) {
        struct RecSink(std::sync::Mutex<Vec<AuditRecord>>);
        impl AuditSink for RecSink {
            fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(record.clone());
                Ok(())
            }
        }
        const HOST_BIN: &str = "/host-bin";
        let exe = std::env::current_exe().expect("current_exe");
        let exe_dir = exe.parent().expect("exe dir").to_path_buf();
        let exe_name = exe.file_name().and_then(|n| n.to_str()).expect("exe name");

        let sink = Arc::new(RecSink(std::sync::Mutex::new(Vec::new())));
        let join_container = Arc::clone(container);
        let launcher = ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSingleId)
            .audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>)
            .cgroup_join_source(move || join_container.join_hook())
            .build()
            .expect("build the launcher with a recording sink");
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(launcher);

        let bundle = Bundle::new("s");
        let ld = make_rootfs(&bundle.rootfs(), true);
        mkdir(&bundle.rootfs().join(HOST_BIN.trim_start_matches('/')));
        let config = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": false},
            "hostname": HOSTNAME,
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": [format!("{HOST_BIN}/{exe_name}")],
                "env": ["PATH=/", "TERM=dumb", format!("LD_LIBRARY_PATH={ld}")],
                "cwd": "/"
            },
            "mounts": [{
                "destination": HOST_BIN,
                "type": "bind",
                "source": exe_dir.to_str().expect("utf8 exe dir"),
                "options": ["bind", "rw"]
            }],
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
            ]}
        });
        std::fs::write(
            bundle.dir.join("config.json"),
            serde_json::to_vec(&config).expect("serialize config"),
        )
        .expect("write config.json");
        let id = ContainerId::new(format!("pls{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        match start(
            &env.store,
            &env.recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Ok(started) => {
                let _ = started.into_parts().1.terminate(timeout());
                panic!("a launch of the runtime binary itself must be refused");
            }
            Err(e) => assert_eq!(e.code(), ErrorCode::PermissionDenied, "{}", e.message()),
        }
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        let records = sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(records.len(), 1, "exactly one record: {records:?}");
        assert_eq!(records[0].layer(), AuditLayer::Entrypoint);
        assert_eq!(
            records[0].reason().map(|r| r.as_str()),
            Some("entrypoint_is_runtime_binary")
        );
        assert_eq!(records[0].container_id(), Some(&id));
        assert_eq!(records[0].path(), None);
        drop(launcher);
        assert!(eventually(|| children_of_self().is_empty()));
        println!(
            "production_launcher: entrypoint violation recorded once and launch refused (scenario=S)"
        );
    }

    /// シナリオ X（#2763・SEC-4・CORE-5・REPAIR-12）: launch の entrypoint の実行失敗（ローダ欠落・0644・ゴミのバイト列）が、
    /// ErrorCode つきの起動失敗になり、何も残さず監査にも記録されない。
    ///
    /// ケースごとに専用の記録先を持つ launcher を作る（`scenarios()` 共有の `MemSink` は他のシナリオの記録が溜まり、
    /// 0 件を照合できない）。cgroup の join は `container` の `join_hook` を使う（シナリオ S と同じ）。
    fn scenario_x_exec_failures(env: &Env, container: &Arc<ContainerCgroup>, tag: u32) {
        struct RecSink(std::sync::Mutex<Vec<AuditRecord>>);
        impl AuditSink for RecSink {
            fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(record.clone());
                Ok(())
            }
        }
        /// 呼び出し側（supervisor / CLI / CRI）へ返るメッセージは、`R` の前の拒否も `R` の後の `execveat` の失敗も
        /// `Exec` 段の固定文言に揃う（パス・errno を載せない。`launch_error`）。経路（`phase`）は公開 API からは
        /// 見分けられないため、設計上の経路を成功行の表示として記す（`R` の後の経路は単体試験が別に固定する）。
        const EXEC_STAGE_MESSAGE: &str = "container launch failed in the Exec stage";

        // (case, 期待する ErrorCode, 設計上の経路の名前)
        let cases: [(&str, ErrorCode, &str); 3] = [
            ("loader-missing", ErrorCode::NotFound, "prepare"),
            ("not-executable", ErrorCode::PermissionDenied, "execveat"),
            ("garbage", ErrorCode::InvalidArgument, "execveat"),
        ];
        for (index, (case, expected, phase)) in cases.into_iter().enumerate() {
            let sink = Arc::new(RecSink(std::sync::Mutex::new(Vec::new())));
            let join_container = Arc::clone(container);
            let launcher = ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSingleId)
                .audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>)
                .cgroup_join_source(move || join_container.join_hook())
                .build()
                .expect("build the launcher with a recording sink");
            let launcher: Arc<dyn ProcessLauncher> = Arc::new(launcher);

            let bundle = Bundle::new(&format!("x{index}"));
            let ld = make_rootfs(&bundle.rootfs(), true);
            let root = bundle.rootfs();
            let entry = match case {
                "loader-missing" => {
                    // 動的ローダを rootfs から消す。ローダのパスは試験バイナリの `PT_INTERP`（静的リンクなら前提欠如で失敗）。
                    let exe = std::fs::read(std::env::current_exe().expect("current_exe"))
                        .expect("read the test binary");
                    let interp = real_entry::elf_interp(&exe)
                        .expect("the test binary must be dynamically linked (PT_INTERP)");
                    std::fs::remove_file(root.join(interp.trim_start_matches('/')))
                        .expect("remove the loader from the rootfs");
                    "/probe"
                }
                "not-executable" => {
                    std::fs::copy(root.join("probe"), root.join("probe-noexec"))
                        .expect("copy probe");
                    std::fs::set_permissions(
                        root.join("probe-noexec"),
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .expect("chmod 0644");
                    "/probe-noexec"
                }
                _ => {
                    std::fs::write(root.join("garbage"), b"this is not an executable image\n")
                        .expect("write the garbage entrypoint");
                    std::fs::set_permissions(
                        root.join("garbage"),
                        std::fs::Permissions::from_mode(0o755),
                    )
                    .expect("chmod 0755");
                    "/garbage"
                }
            };
            let config = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs", "readonly": false},
                "hostname": HOSTNAME,
                "process": {
                    "user": {"uid": 0, "gid": 0},
                    "args": [entry],
                    "env": ["PATH=/", "TERM=dumb", format!("LD_LIBRARY_PATH={ld}")],
                    "cwd": "/"
                },
                "mounts": [],
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
                ]}
            });
            std::fs::write(
                bundle.dir.join("config.json"),
                serde_json::to_vec(&config).expect("serialize config"),
            )
            .expect("write config.json");
            let id = ContainerId::new(format!("plx{index}{tag}")).expect("id");
            do_create(env, &bundle, &id);
            wait_single_thread();
            let err = match start(
                &env.store,
                &env.recorder,
                &launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Ok(started) => {
                    let _ = started.into_parts().1.terminate(timeout());
                    panic!("{case}: the launch must fail");
                }
                Err(e) => e,
            };
            assert_ne!(err.code(), ErrorCode::Timeout, "{case}: {}", err.message());
            assert_eq!(err.code(), expected, "{case}: {}", err.message());
            assert_eq!(err.message(), EXEC_STAGE_MESSAGE, "{case} ({phase})");
            assert_eq!(state_of(&env.store, &id), ContainerState::Created, "{case}");
            assert!(
                env.store
                    .get(&GetStateRequest::new(id.clone()))
                    .expect("get state")
                    .launch_isolation()
                    .is_none(),
                "{case}: a failed launch must leave no launch_isolation"
            );
            assert!(!launcher.last_launch_may_have_left_process(), "{case}");
            launcher
                .confirm_no_process(&id, timeout())
                .unwrap_or_else(|e| panic!("{case}: confirm_no_process: {e:?}"));
            let records = sink
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            assert!(
                records.is_empty(),
                "{case}: a non-violation failure must not be audited: {records:?}"
            );
            drop(launcher);
            assert!(
                eventually(|| children_of_self().is_empty()),
                "{case}: no process may remain: {:?}",
                children_of_self()
            );
            println!(
                "production_launcher: scenario=exec-failure case={case} code={:?} phase={phase} state=created audit=0 children=0",
                err.code()
            );
        }
    }

    /// シナリオ P（OCI-1・TASK-55 追補・#2314）: 名前だけの `process.args[0]` を、コンテナ内の `process.env` の
    /// `PATH` で pivot 後に解決して実行する。`PATH` の前方にある実行ビットの無い同名ファイルは飛ばし、後方の
    /// 実行可能な `probe` を PID 1 として起動し、コンテナ内プローブの `READY` と具体値の終了コード 7 を照合する。
    /// `PATH` のどこにも無い名前は、`start` が失敗するか子が終了コード 127 で終わる（`exec` 層の `NotFound` と
    /// 同じ。どちらでも子が残らず、成功起動には決してならない）。
    fn scenario_p_bare_name_entrypoint(env: &Env, tag: u32) {
        const EXIT_CODE: i32 = 7;
        let write_named = |bundle: &Bundle, ld: &str, path_env: &str, name: &str| {
            let config = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs", "readonly": false},
                "hostname": HOSTNAME,
                "process": {
                    "user": {"uid": 0, "gid": 0},
                    "args": [name, "--container-probe", "--exit-code", EXIT_CODE.to_string()],
                    "env": [
                        format!("PATH={path_env}"),
                        "TERM=dumb",
                        format!("LD_LIBRARY_PATH={ld}"),
                    ],
                    "cwd": "/"
                },
                "mounts": [],
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
                ]}
            });
            std::fs::write(
                bundle.dir.join("config.json"),
                serde_json::to_vec(&config).expect("serialize config"),
            )
            .expect("write config.json");
        };

        // P1: 前方の非実行ファイルを飛ばして後方の実行可能ファイルを解決し、終了コード 7 で終わる。
        let bundle = Bundle::new("p1");
        let ld = make_rootfs(&bundle.rootfs(), true);
        let root = bundle.rootfs();
        mkdir(&root.join("opt/bin"));
        mkdir(&root.join("usr/local/bin"));
        std::fs::write(root.join("opt/bin/probe"), b"not executable\n").expect("decoy");
        std::fs::set_permissions(
            root.join("opt/bin/probe"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod decoy");
        std::fs::copy(root.join("probe"), root.join("usr/local/bin/probe")).expect("copy probe");
        std::fs::set_permissions(
            root.join("usr/local/bin/probe"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod probe");
        // `/probe` が絶対パスの経路で拾われないよう、名前の解決は PATH だけに頼らせる。
        std::fs::remove_file(root.join("probe")).expect("remove /probe");
        write_named(
            &bundle,
            &ld,
            "/nonexistent:/opt/bin:/usr/local/bin",
            "probe",
        );
        let id = ContainerId::new(format!("plp1{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        let started = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> = None;
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            let output = started.process().take_output().expect("container output");
            let (rx, reader) = spawn_reader(output.stdout.expect("container stdout"));
            reader_slot = Some((rx, reader));
            let exit = started
                .process()
                .wait(timeout())
                .expect("wait for the probe")
                .expect("the probe did not exit within the timeout");
            assert_eq!(exit, ProcessExit::Exited(EXIT_CODE), "resolved probe exit");
            let mut lines = Vec::new();
            let rx = &reader_slot.as_ref().expect("reader slot").0;
            let deadline = Instant::now() + timeout();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(line) => lines.push(line),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        panic!("probe output did not reach EOF; got {lines:?}")
                    }
                }
            }
            assert_eq!(value_of(&lines, "PID"), "1");
            assert!(lines.contains(&PROBE_READY.to_string()), "{lines:?}");
        }));
        finish_started(started, verified);
        let (rx, reader) = reader_slot.take().expect("reader slot");
        reader.join().expect("join reader");
        drop(rx);
        assert!(eventually(|| children_of_self().is_empty()));

        // P2: PATH のどこにも無い名前は成功起動にならない（start の失敗なら Created のまま、起動後なら 127）。
        let bundle = Bundle::new("p2");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_named(&bundle, &ld, "/nonexistent:/opt/bin", "probe");
        let id = ContainerId::new(format!("plp2{tag}")).expect("id");
        do_create(env, &bundle, &id);
        wait_single_thread();
        match start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        ) {
            Err(e) => {
                println!(
                    "production_launcher: scenario=p2 start refused code={:?}",
                    e.code()
                );
                assert_eq!(state_of(&env.store, &id), ContainerState::Created);
            }
            Ok(started) => assert_started_child_exits_127(started),
        }
        assert!(eventually(|| children_of_self().is_empty()));
        println!(
            "production_launcher: scenario=bare-name resolved via PATH, exit code {EXIT_CODE}; missing name not started"
        );
    }

    /// 起動後に子が終了コード 127(`exec` 層の `NotFound` 相当)で終わることを確かめ、子と読み手を残さない。
    fn assert_started_child_exits_127(
        started: fandhe_container_core::oci_runtime::StartedContainer,
    ) {
        // 失敗の診断（子の stderr の 1 行）を終了状態の不一致の報告へ添えるため、待つ前に読み手を立てる
        // （CI だけで SIGSEGV が観測された原因の切り分け用。#2376）。
        let diag = started
            .process()
            .take_output()
            .and_then(|o| o.stderr)
            .map(spawn_reader);
        let exit = started.process().wait(timeout());
        let (_record, process) = started.into_parts();
        let _ = process.terminate(timeout());
        let mut lines: Vec<String> = Vec::new();
        if let Some((rx, reader)) = diag {
            let deadline = Instant::now() + timeout();
            while let Ok(line) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                lines.push(line);
            }
            // 子は terminate 済みで書き込み側は閉じるため、リーダーは EOF で終わる。終了を期限つきで待ち、
            // 終わっていれば join してスレッドを残さない（後続の wait_single_thread のため）。書き込み側が
            // 開いたままの場合だけ、join が無期限になるのを避けて切り離す（REPAIR-5）。
            if eventually(|| reader.is_finished()) {
                reader.join().expect("join diagnostic reader");
            } else {
                drop(reader);
            }
        }
        assert_eq!(
            exit.expect("wait"),
            Some(ProcessExit::Exited(127)),
            "child stderr: {lines:?}"
        );
    }

    /// シナリオ R（OCI-1・OCI-4・#2432）: `/` を含む相対パスの `process.args[0]` を、pivot と `process.cwd` の適用の
    /// 後に cwd 起点で解決して実行する。R1 は非ルート cwd の `./entrypoint.sh`、R2 は `bin/app` で、いずれも
    /// 具体値の終了コード 7 と `READY` を照合する。R3（不在）と R4（`bin/app/.` が通常ファイル `bin/app` を指す。
    /// ENOTDIR 相当で拒否）は成功起動にならず（start の失敗なら Created のまま、起動後なら 127）、子が残らない。
    fn scenario_r_cwd_relative_entrypoint(env: &Env, tag: u32) {
        const EXIT_CODE: i32 = 7;
        let setup = |name: &str, cwd: &str, arg0: &str, probe_at: Option<&str>| {
            let bundle = Bundle::new(name);
            let ld = make_rootfs(&bundle.rootfs(), true);
            let root = bundle.rootfs();
            mkdir(&root.join("work/bin"));
            if let Some(rel) = probe_at {
                std::fs::copy(root.join("probe"), root.join(rel)).expect("copy probe");
                std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(0o755))
                    .expect("chmod probe");
            }
            // `/probe` の絶対パスで拾われないよう、cwd 相対の解決だけに頼らせる。
            std::fs::remove_file(root.join("probe")).expect("remove /probe");
            let config = json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs", "readonly": false},
                "hostname": HOSTNAME,
                "process": {
                    "user": {"uid": 0, "gid": 0},
                    "args": [arg0, "--container-probe", "--exit-code", EXIT_CODE.to_string()],
                    "env": ["PATH=/nonexistent", "TERM=dumb", format!("LD_LIBRARY_PATH={ld}")],
                    "cwd": cwd
                },
                "mounts": [],
                "linux": {"namespaces": [
                    {"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "user"}
                ]}
            });
            std::fs::write(
                bundle.dir.join("config.json"),
                serde_json::to_vec(&config).expect("serialize config"),
            )
            .expect("write config.json");
            let id = ContainerId::new(format!("plr{name}{tag}")).expect("id");
            do_create(env, &bundle, &id);
            wait_single_thread();
            (bundle, id)
        };

        for (name, cwd, arg0, at) in [
            ("r1", "/work", "./entrypoint.sh", "work/entrypoint.sh"),
            ("r2", "/work", "bin/app", "work/bin/app"),
        ] {
            let (_bundle, id) = setup(name, cwd, arg0, Some(at));
            let started = start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            )
            .unwrap_or_else(|e| panic!("{name}: start failed: {:?} {}", e.code(), e.message()));
            let mut reader_slot: Option<(mpsc::Receiver<String>, std::thread::JoinHandle<()>)> =
                None;
            let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_eq!(started.record().status().state(), ContainerState::Running);
                let output = started.process().take_output().expect("container output");
                reader_slot = Some(spawn_reader(output.stdout.expect("container stdout")));
                let exit = started
                    .process()
                    .wait(timeout())
                    .expect("wait for the probe")
                    .expect("the probe did not exit within the timeout");
                assert_eq!(exit, ProcessExit::Exited(EXIT_CODE), "{name}: exit");
                let rx = &reader_slot.as_ref().expect("reader slot").0;
                let mut lines = Vec::new();
                let deadline = Instant::now() + timeout();
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(left) {
                        Ok(line) => lines.push(line),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            panic!("{name}: probe output did not reach EOF; got {lines:?}")
                        }
                    }
                }
                assert_eq!(value_of(&lines, "PID"), "1", "{name}");
                assert_eq!(value_of(&lines, "CWD"), "/work", "{name}");
                assert!(
                    lines.contains(&PROBE_READY.to_string()),
                    "{name}: {lines:?}"
                );
            }));
            finish_started(started, verified);
            let (rx, reader) = reader_slot.take().expect("reader slot");
            reader.join().expect("join reader");
            drop(rx);
            assert!(eventually(|| children_of_self().is_empty()));
        }

        // R3: 不在、R4: `bin/app/.`（bin/app は通常ファイル）。どちらも成功起動にならず、子が残らない。
        for (name, arg0, at) in [
            ("r3", "./nothere", None),
            ("r4", "bin/app/.", Some("work/bin/app")),
        ] {
            let (_bundle, id) = setup(name, "/work", arg0, at);
            match start(
                &env.store,
                &env.recorder,
                &env.launcher,
                &StartRequest::new(id.clone()),
                &timeouts(),
            ) {
                Err(e) => {
                    println!(
                        "production_launcher: scenario={name} start refused code={:?}",
                        e.code()
                    );
                    assert_eq!(state_of(&env.store, &id), ContainerState::Created);
                    assert!(!env.launcher.last_launch_may_have_left_process());
                }
                Ok(started) => assert_started_child_exits_127(started),
            }
            assert!(eventually(|| children_of_self().is_empty()));
        }
        println!(
            "production_launcher: scenario=cwd-relative resolved from cwd, exit code {EXIT_CODE}; missing and bin/app/. not started"
        );
    }

    /// root 実行: launch が拒否され、状態は Created に戻り、子が残らない（SEC-5。成功起動は試さない）。
    fn scenario_root_refused(env: &Env, tag: u32) {
        let bundle = Bundle::new("r");
        let ld = make_rootfs(&bundle.rootfs(), true);
        write_config(&bundle, &ld, &[], json!([]));
        let id = ContainerId::new(format!("plr{tag}")).expect("id");
        do_create(env, &bundle, &id);

        wait_single_thread();
        let result = start(
            &env.store,
            &env.recorder,
            &env.launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        );
        let err = match result {
            Ok(_) => panic!("start must be refused for root (SEC-5)"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(state_of(&env.store, &id), ContainerState::Created);
        assert!(!env.launcher.last_launch_may_have_left_process());
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after a refused root launch"
        );
        println!(
            "production_launcher: scenario=root-refused code={:?}",
            err.code()
        );
    }
}
