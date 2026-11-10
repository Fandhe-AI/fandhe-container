//! core 役 → plugin-microvm（UDS 境界）→ microVM の起動 → 停止の結合試験（TASK-117.4・#713。PLUG-1・MVM-1・PLUG-12・REPAIR-5・REPAIR-12）。
//!
//! 兄弟の `plugin-macos/tests/e2e.rs`（TASK-115.6）・`plugin-windows/tests/e2e.rs`（TASK-116.6）と同じ 2 層構成。
//! 「core」役は共有境界 crate `fandhe-container-plugin` の `UdsListener`（core が bind し plugin が connect する既存契約）を
//! 試験本体が担う。core 側の plugin-microvm 起動経路（`BackendKind` への追加）は #1869 の設計の 4.9 の範囲で未結線のため、
//! ここでは境界の wire 契約（ping / start / stop）を固定する（REPAIR-3）。
//!
//! - 層 A（既定集合・unix・KVM 不要）: plugin 役のスレッドが `main.rs` と同じ順
//!   （peer 認証つき connect → `MicrovmRuntimeAdapter` → `serve` → `stop_all`）を偽バックエンドで実行し、実 UDS 上で
//!   起動・停止・切断時の回収・起動失敗後の接続維持を具体値で照合する。あわせて `serve_until` と停止フラグ
//!   （SIGTERM 相当。#3747）で、実行中 VM の停止と、停止に入った後に届いた要求が処理されないことを照合する。
//! - 層 B（`#[ignore]`・実機前提）: 実バイナリを spawn し、Linux x86_64 では本物の `KvmBackend`（`/dev/kvm` が要る）、
//!   Linux aarch64 でも本物の `KvmBackend`（`/dev/kvm` と in-kernel vGICv3・`KVM_CAP_ARM_PSCI_0_2` が要る。#3959）、
//!   macOS aarch64 では本物の `HvfBackend`（Apple Silicon の macOS 15 以降と entitlement つきの署名が要る。TASK-192.18・#3800）で、
//!   合成ゲスト（Linux x86_64 は合成 bzImage、aarch64 は合成 arm64 Image）を起動・停止する。UDS ホップを含む完全な通し。手順は `AGENTS.md`「実機前提テスト」節。
//!
//! 層 B の合成ゲストは起動状態（x86_64 は boot_params の `HdrS` と cmd_line_ptr、Linux aarch64 は x0 が指す FDT の magic）を
//! 確かめて自己ループする。`KvmBackend` は block / net を付けない
//! ため、`crates/microvm/tests/microvm.rs` の virtio-mmio 照合ペイロードは使えない。ホスト側からゲストの exit の種別は
//! 観測できないので、停止理由 `requested`（停止要求の割り込みで止まった）が「正しいエントリで動き続けた」ことの判別材料になる。
//! 不正なら x86_64 は `ud2`、Linux aarch64 は PSCI SYSTEM_OFF で止まる。
//! shutdown を期待する負の対照は、停止要求と shutdown exit のどちらが先に観測されるかが競合し、
//! 寛容な assert になるため置かない。Linux aarch64 の層 B は、ネイティブ arm64 の CI が無く（#2274）型検査のみ
//! `cross-target-check` の `aarch64-unknown-linux-gnu` が担い、実機での実行は人間担当の #3781。
//! KVM の stop の結果行（`ignored=`・`unbind_failed=`・`unmap_failures=`）は `check_kvm_stop_line` で完全一致照合する（#4456）。
//! 待ちはすべて期限つきで、超過時は kill して失敗にする（REPAIR-5）。
#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fandhe_container_plugin::{
    ControlMessage, Frame, MessageId, RpcTimeout, UdsStream, decode_message, encode_message,
};

/// 0700 の一時ディレクトリ（`/tmp` 直下の短い名前。macOS の `sun_path` 104 バイト制限に収める）。
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for _ in 0..100u32 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p =
                PathBuf::from("/tmp").join(format!("fc-pmve-{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test dir: {e}"),
            }
        }
        panic!("could not create a unique test dir");
    }

    /// 0600 の通常ファイルを作り、絶対パス文字列を返す（adapter は symlink と相対パスを拒否する）。
    fn file(&self, name: &str, data: &[u8]) -> String {
        use std::io::Write;
        let p = self.0.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .expect("create file");
        f.write_all(data).expect("write file");
        // adapter は祖先の symlink も拒否するため正規化して返す（macOS の `/tmp` → `/private/tmp`。#3748）。
        std::fs::canonicalize(&p)
            .expect("canonicalize")
            .to_str()
            .expect("utf8 path")
            .to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // 排他作成した自前のディレクトリのみ
    }
}

/// KVM の stop の結果行を照合する（MVM-1・REPAIR-4・REPAIR-12・#4456）。
///
/// 実機前提の `real_kvm` / `real_kvm_arm64` の stop 試験が、plugin バイナリの stderr 全体を渡して呼ぶ。
/// 起点は `op=plugin.microvm.stop outcome=` を含む行で、ちょうど 1 行だけを選ぶ（`stop_all` や microvm 本体の
/// `unmap_failures=` を持つ行を取り違えないため）。`elapsed_us` と `ignored`（ゲストの通知の時機で変わる）は
/// 数字であることだけを見て、残りは `vms=0 unbind_failed=0 unmap_failures=0` をこの順で完全一致させる。
fn check_kvm_stop_line(err: &str) -> Result<(), String> {
    const ANCHOR: &str = "op=plugin.microvm.stop outcome=";
    let lines: Vec<&str> = err.lines().filter(|l| l.contains(ANCHOR)).collect();
    let line = match lines.as_slice() {
        [] => return Err("no plugin stop line".to_string()),
        [one] => *one,
        many => return Err(format!("multiple plugin stop lines: {}", many.len())),
    };
    let number = |key: &str| -> Result<&str, String> {
        let v = line
            .split(key)
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .unwrap_or("");
        if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
            Ok(v)
        } else {
            Err(format!("non-numeric {key}: {line}"))
        }
    };
    let us = number(" elapsed_us=")?;
    let ig = number(" ignored=")?;
    let expected = format!(
        "level=info op=plugin.microvm.stop outcome=ok elapsed_us={us} vms=0 ignored={ig} unbind_failed=0 unmap_failures=0"
    );
    if line == expected {
        Ok(())
    } else {
        Err(format!("unexpected stop line: {line}"))
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

fn request(id: u64, body: Vec<String>) -> Frame {
    encode_message(&ControlMessage::Request {
        id: MessageId::new(id),
        body,
    })
    .expect("encode")
}

/// 1 要求を送って応答 1 件を受ける（期限は既定の RPC 期限）。
fn call(stream: &mut UdsStream, id: u64, body: Vec<String>) -> ControlMessage<Vec<String>> {
    stream
        .write_frame(&request(id, body), RpcTimeout::default())
        .expect("write");
    let r = stream.read_frame(RpcTimeout::default()).expect("read");
    decode_message::<Vec<String>>(&r).expect("decode")
}

fn expect_ok(msg: ControlMessage<Vec<String>>, id: u64) -> Vec<String> {
    match msg {
        ControlMessage::Response { id: got, body } => {
            assert_eq!(got.get(), id);
            body
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// 層 A: 偽バックエンドの plugin 役（スレッド）と core 役（試験本体）を実 UDS で繋ぐ。
mod mock_core {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, UdsListener};
    use fandhe_container_plugin_microvm::adapter::{
        BootSpec, DetachedState, MicrovmBackend, MicrovmRuntimeAdapter, STOP_ALL_BUDGET,
        StopAllReport,
    };
    use fandhe_container_plugin_microvm::frame_loop::{LoopExit, serve, serve_until};

    const ACCEPT_WAIT: Duration = Duration::from_secs(20);
    const OUTCOME_WAIT: Duration = Duration::from_secs(30);

    type Outcome = (Result<LoopExit, PluginError>, StopAllReport);

    #[derive(Debug, PartialEq, Eq)]
    pub struct StartRecord {
        pub vcpus: u32,
        pub mem_bytes: u64,
        pub kernel: Vec<u8>,
        pub initrd: Option<Vec<u8>>,
        pub cmdline: String,
    }

    #[derive(Default)]
    pub struct Record {
        pub starts: Vec<StartRecord>,
        pub stops: Vec<(u32, Duration)>,
        pub start_err: Option<MicrovmErrorCode>,
        /// 設定すると stop がそのコードで失敗する（`DeadlineExceeded` で期限切れの切り離しを模擬。#3745）。
        pub stop_err: Option<MicrovmErrorCode>,
        /// 終了を観測済みにした VM の id（後から vCPU スレッドが終わった模擬。#3745）。
        pub exited: std::collections::BTreeSet<u32>,
        /// 設定すると成功した stop がこの ioeventfd 件数を返す（結果行の `ignored=` / `unbind_failed=` の経路。#4161）。
        pub stop_ioevent: Option<fandhe_container_microvm::interrupt::IoEventCounts>,
        /// 設定すると成功した stop がこの munmap 失敗件数を返す（`stop_all` の合算の経路。#4438）。
        pub stop_unmap: Option<u64>,
    }

    /// 起動・停止の引数を記録する偽バックエンド（adapter の `#[cfg(test)]` 版は非公開のため独自に持つ）。
    struct FakeBackend(Arc<Mutex<Record>>);

    impl MicrovmBackend for FakeBackend {
        type Running = u32;
        type ExitWatch = u32;

        fn start(&mut self, spec: BootSpec) -> Result<u32, MicrovmError> {
            let mut r = self.0.lock().expect("lock");
            if let Some(code) = r.start_err {
                return Err(MicrovmError::new(code, "fake"));
            }
            r.starts.push(StartRecord {
                vcpus: spec.vcpus,
                mem_bytes: spec.mem_bytes,
                kernel: spec.kernel,
                initrd: spec.initrd,
                cmdline: spec.cmdline,
            });
            Ok(u32::try_from(r.starts.len()).expect("small"))
        }

        fn stop(
            &mut self,
            vm: u32,
            deadline: Duration,
        ) -> Result<fandhe_container_plugin_microvm::adapter::StopOutcome, MicrovmError> {
            let mut r = self.0.lock().expect("lock");
            r.stops.push((vm, deadline));
            match r.stop_err {
                Some(code) => Err(MicrovmError::new(code, "fake stop")),
                None => Ok(fandhe_container_plugin_microvm::adapter::StopOutcome {
                    reason: "requested",
                    ioevent: r.stop_ioevent,
                    unmap_failures: r.stop_unmap,
                    vm_unmap_failures: None,
                }),
            }
        }

        fn exit_watch(&self, vm: &u32) -> u32 {
            *vm
        }

        fn exit_state(&self, watch: &u32) -> DetachedState {
            if self.0.lock().expect("lock").exited.contains(watch) {
                DetachedState::Released
            } else {
                DetachedState::Pending
            }
        }
    }

    pub struct E2e {
        pub dir: TempDir,
        pub stream: UdsStream,
        pub record: Arc<Mutex<Record>>,
        rx: Receiver<Outcome>,
        plugin: JoinHandle<()>,
    }

    impl E2e {
        pub fn start() -> Self {
            let dir = TempDir::new();
            let sock = dir.0.join("p.sock");
            let listener = UdsListener::bind(&sock).expect("bind");
            let record = Arc::new(Mutex::new(Record::default()));
            let (tx, rx) = channel();
            let rec = Arc::clone(&record);
            let plugin = std::thread::spawn(move || run_plugin(&sock, rec, &tx));
            let mut obs = JsonLinesPeerAuthObserver::new();
            let stream = listener.accept(ACCEPT_WAIT, &mut obs).expect("accept");
            assert_eq!(obs.len(), 0, "same-uid connect must not be rejected");
            Self {
                dir,
                stream,
                record,
                rx,
                plugin,
            }
        }

        /// 切断して plugin 役の終了結果を期限つきで受け取る（裸の join は使わない。REPAIR-5）。
        pub fn finish(self) -> Outcome {
            let Self {
                dir: _dir,
                stream,
                rx,
                plugin,
                ..
            } = self;
            drop(stream);
            let out = rx
                .recv_timeout(OUTCOME_WAIT)
                .expect("plugin role did not finish within deadline");
            plugin.join().expect("plugin thread");
            out
        }
    }

    /// 停止（`stop`）を試験が解放するまで待たせる偽バックエンド（#3747）。
    /// `start` は連番を返して記録し、`stop` は呼ばれたことを `stopping` で知らせ、`release` を期限つきで待つ。
    struct GatedBackend {
        rec: Arc<Mutex<Record>>,
        stopping: Sender<()>,
        release: Receiver<()>,
    }

    impl MicrovmBackend for GatedBackend {
        type Running = u32;
        type ExitWatch = u32;

        fn start(&mut self, spec: BootSpec) -> Result<u32, MicrovmError> {
            let mut r = self.rec.lock().expect("lock");
            r.starts.push(StartRecord {
                vcpus: spec.vcpus,
                mem_bytes: spec.mem_bytes,
                kernel: spec.kernel,
                initrd: spec.initrd,
                cmdline: spec.cmdline,
            });
            Ok(u32::try_from(r.starts.len()).expect("small"))
        }

        fn stop(
            &mut self,
            vm: u32,
            deadline: Duration,
        ) -> Result<fandhe_container_plugin_microvm::adapter::StopOutcome, MicrovmError> {
            self.rec.lock().expect("lock").stops.push((vm, deadline));
            let _ = self.stopping.send(());
            // STOP_ALL_BUDGET（4 秒）より短い期限で待つ（REPAIR-5）。
            let _ = self.release.recv_timeout(Duration::from_secs(3));
            Ok(fandhe_container_plugin_microvm::adapter::StopOutcome {
                reason: "requested",
                ioevent: None,
                unmap_failures: None,
                vm_unmap_failures: None,
            })
        }

        fn exit_watch(&self, vm: &u32) -> u32 {
            *vm
        }

        fn exit_state(&self, watch: &u32) -> DetachedState {
            if self.rec.lock().expect("lock").exited.contains(watch) {
                DetachedState::Released
            } else {
                DetachedState::Pending
            }
        }
    }

    /// 停止フラグつきの層 A（`serve_until`）。
    pub struct Shutdown {
        pub dir: TempDir,
        pub stream: UdsStream,
        pub record: Arc<Mutex<Record>>,
        pub flag: Arc<AtomicBool>,
        /// `stop` に入ったことの通知。
        pub stopping: Receiver<()>,
        /// `stop` の解放。
        pub release: Sender<()>,
        rx: Receiver<Outcome>,
        plugin: JoinHandle<()>,
    }

    impl Shutdown {
        pub fn start() -> Self {
            let dir = TempDir::new();
            let sock = dir.0.join("p.sock");
            let listener = UdsListener::bind(&sock).expect("bind");
            let record = Arc::new(Mutex::new(Record::default()));
            let flag = Arc::new(AtomicBool::new(false));
            let (tx, rx) = channel();
            let (stopping_tx, stopping) = channel();
            let (release, release_rx) = channel();
            let backend = GatedBackend {
                rec: Arc::clone(&record),
                stopping: stopping_tx,
                release: release_rx,
            };
            let fl = Arc::clone(&flag);
            let plugin = std::thread::spawn(move || {
                let mut obs = JsonLinesPeerAuthObserver::new();
                let mut stream =
                    UdsStream::connect(&sock, Duration::from_secs(5), &mut obs).expect("connect");
                let mut adapter = MicrovmRuntimeAdapter::new(backend);
                let outcome = serve_until(&mut stream, &mut adapter, &fl);
                let report = adapter.stop_all(STOP_ALL_BUDGET);
                let _ = tx.send((outcome, report));
            });
            let mut obs = JsonLinesPeerAuthObserver::new();
            let stream = listener.accept(ACCEPT_WAIT, &mut obs).expect("accept");
            Self {
                dir,
                stream,
                record,
                flag,
                stopping,
                release,
                rx,
                plugin,
            }
        }

        /// plugin 役の終了結果を期限つきで受け取る（裸の join は使わない。REPAIR-5）。
        pub fn outcome(self) -> Outcome {
            let Self {
                dir: _dir,
                stream: _stream,
                rx,
                plugin,
                ..
            } = self;
            let out = rx
                .recv_timeout(OUTCOME_WAIT)
                .expect("plugin role did not finish within deadline");
            plugin.join().expect("plugin thread");
            out
        }
    }

    /// `main.rs` と同じ順序（connect → adapter → serve → stop_all）。
    fn run_plugin(sock: &Path, record: Arc<Mutex<Record>>, tx: &Sender<Outcome>) {
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream =
            UdsStream::connect(sock, Duration::from_secs(5), &mut obs).expect("connect");
        let mut adapter = MicrovmRuntimeAdapter::new(FakeBackend(record));
        let outcome = serve(&mut stream, &mut adapter);
        let report = adapter.stop_all(STOP_ALL_BUDGET);
        let _ = tx.send((outcome, report));
    }
}

const KERNEL: &[u8] = b"synthetic-kernel-bytes";

/// PLUG-1・REPAIR-5: 停止フラグ（SIGTERM 相当）が立つと実行中 VM を `stop_all` で止めて抜け、
/// 停止に入った後に届いた要求は処理されない（応答なし・start は 1 回のまま）。
#[test]
fn task117_plug1_repair5_shutdown_flag_stops_running_vm_and_ignores_later_requests() {
    use fandhe_container_plugin::PluginErrorCode;
    use fandhe_container_plugin_microvm::adapter::StopAllReport;
    use fandhe_container_plugin_microvm::frame_loop::{IDLE_POLL, LoopExit};
    use std::sync::atomic::Ordering;

    let mut e = mock_core::Shutdown::start();
    let kernel = e.dir.file("k.bin", KERNEL);
    let start = s(&["start", "vm1", &kernel, "", "", "1", "64"]);
    assert_eq!(expect_ok(call(&mut e.stream, 1, start), 1), s(&["running"]));

    e.flag.store(true, Ordering::SeqCst);
    // 受信ループを抜けて stop_all が stop に入ったことを待つ（検知の遅れは最大 IDLE_POLL）。
    e.stopping
        .recv_timeout(IDLE_POLL + Duration::from_secs(3))
        .expect("stop_all did not start after the flag was set");

    // stop の中で止まっている間に 2 台目の start を送る。処理されないので応答は来ない。
    let second = s(&["start", "vm2", &kernel, "", "", "1", "64"]);
    e.stream
        .write_frame(&request(2, second), RpcTimeout::default())
        .expect("write");
    let err = e
        .stream
        .read_frame(RpcTimeout::new(Duration::from_millis(1500)).expect("timeout"))
        .expect_err("no response may arrive after shutdown");
    assert_eq!(err.code(), PluginErrorCode::Timeout);

    e.release.send(()).expect("release stop");
    let record = std::sync::Arc::clone(&e.record);
    let (exit, report) = e.outcome();
    assert!(matches!(exit, Ok(LoopExit::ShutdownRequested)), "{exit:?}");
    assert_eq!(
        report,
        StopAllReport {
            stopped: 1,
            failed: 0,
            remaining: 0,
            ioevent: None,
            unmap_failures: None,
            vm_unmap_failures: None
        }
    );
    let r = record.lock().expect("lock");
    assert_eq!(r.starts.len(), 1, "second start must not be processed");
    assert_eq!(r.stops.len(), 1);
}

#[test]
fn task117_4_plug1_mvm1_ping_start_stop_roundtrip_via_uds() {
    use fandhe_container_plugin_microvm::adapter::{STOP_DEADLINE, StopAllReport};
    use fandhe_container_plugin_microvm::frame_loop::LoopExit;

    let mut e = mock_core::E2e::start();
    let kernel = e.dir.file("k.bin", KERNEL);

    assert_eq!(
        expect_ok(call(&mut e.stream, 1, s(&["ping"])), 1),
        s(&["pong"])
    );
    let start = s(&["start", "vm1", &kernel, "", "console=ttyS0", "1", "64"]);
    assert_eq!(expect_ok(call(&mut e.stream, 2, start), 2), s(&["running"]));
    {
        let r = e.record.lock().expect("lock");
        assert_eq!(r.starts.len(), 1);
        let st = &r.starts[0];
        assert_eq!(st.vcpus, 1);
        assert_eq!(st.mem_bytes, 64 << 20);
        assert_eq!(st.kernel, KERNEL);
        assert_eq!(st.initrd, None);
        assert_eq!(st.cmdline, "console=ttyS0");
    }
    assert_eq!(
        expect_ok(call(&mut e.stream, 3, s(&["stop", "vm1"])), 3),
        s(&["stopped", "requested"])
    );
    assert_eq!(
        e.record.lock().expect("lock").stops,
        vec![(1, STOP_DEADLINE)]
    );

    let (exit, report) = e.finish();
    assert!(matches!(exit, Ok(LoopExit::PeerClosed)), "{exit:?}");
    assert_eq!(
        report,
        StopAllReport {
            stopped: 0,
            failed: 0,
            remaining: 0,
            ioevent: None,
            unmap_failures: None,
            vm_unmap_failures: None
        }
    );
}

/// 子プロセスで走らせる側を示す環境変数（stderr の構造化ログを観測するため自身を再起動する。#4161）。
const IOEVENT_CHILD_ENV: &str = "FANDHE_E2E_IOEVENT_CHILD";

/// `check_kvm_stop_line` の組み立てを偽の行で固定する（実機なしで動く。MVM-1・REPAIR-4・REPAIR-12・#4456）。
#[test]
fn mvm1_repair12_4456_kvm_stop_line_check_accepts_and_rejects_fixed_lines() {
    const OK: &str = "level=info op=plugin.microvm.stop outcome=ok elapsed_us=123 vms=0 ignored=0 unbind_failed=0 unmap_failures=0";
    let decoys = "level=info op=plugin.microvm.start outcome=ok elapsed_us=5 vms=1\nlevel=info op=microvm.vcpus_stopped reason=requested unmap_failures=0\n";
    assert_eq!(check_kvm_stop_line(&format!("{decoys}{OK}\n")), Ok(()));
    assert_eq!(
        check_kvm_stop_line(&OK.replace("ignored=0", "ignored=7")),
        Ok(())
    );

    let rejected = |input: &str, prefix: &str| {
        let r = check_kvm_stop_line(input);
        assert!(
            matches!(&r, Err(m) if m.starts_with(prefix)),
            "{input:?} -> {r:?}"
        );
    };
    rejected("", "no plugin stop line");
    rejected(decoys, "no plugin stop line");
    rejected(
        "level=warn op=plugin.microvm.stop_all stopped=1 failed=0 remaining=0 detached=0",
        "no plugin stop line",
    );
    rejected(&format!("{OK}\n{OK}"), "multiple plugin stop lines: 2");
    // HVF の形・#4161 の形（unmap_failures が無い）。
    rejected(
        "level=info op=plugin.microvm.stop outcome=ok elapsed_us=1 vms=0 unmap_failures=0",
        "non-numeric  ignored=",
    );
    rejected(
        "level=info op=plugin.microvm.stop outcome=ok elapsed_us=1 vms=0 ignored=2 unbind_failed=1",
        "unexpected stop line",
    );
    for bad in [
        "ignored=0 unbind_failed=0 unmap_failures=0|unbind_failed=0 ignored=0 unmap_failures=0",
        "ignored=0 unbind_failed=0 unmap_failures=0|ignored=0 unmap_failures=0 unbind_failed=0",
        "ignored=0 unbind_failed=0 unmap_failures=0|ignored=0 unbind_failed=1 unmap_failures=0",
        "ignored=0 unbind_failed=0 unmap_failures=0|ignored=0 unbind_failed=0 unmap_failures=1",
        "ignored=0 unbind_failed=0 unmap_failures=0|ignored=0 unbind_failed=0 unmap_failures=0 extra=1",
        "vms=0|vms=1",
    ] {
        let (from, to) = bad.split_once('|').expect("pair");
        rejected(&OK.replace(from, to), "unexpected stop line");
    }
    for bad in ["ignored=", "ignored=x", "ignored=-1"] {
        rejected(&OK.replace("ignored=0", bad), "non-numeric  ignored=");
    }
    for bad in ["elapsed_us=", "elapsed_us=abc"] {
        rejected(
            &OK.replace("elapsed_us=123", bad),
            "non-numeric  elapsed_us=",
        );
    }
    rejected(
        "level=error op=plugin.microvm.stop outcome=error code=INTERNAL elapsed_us=1 vms=0",
        "non-numeric  ignored=",
    );
}

/// MVM-1・REPAIR-4・#4161: backend が返した ioeventfd 件数 (2, 1) が、実際の要求処理（UDS の stop）を通って
/// 停止の結果行へ ` ignored=2 unbind_failed=1` として出る。UDS 応答は従来どおり `stopped requested` のまま。
///
/// 結果行は adapter がプロセスの stderr へ書くため、同一プロセス内では観測できない。そこでこの試験は自身を
/// 子プロセス（`--exact --nocapture`）として再実行し、親が子の stderr を期限つきで集めて照合する。
#[test]
fn mvm1_repair4_4161_stop_log_carries_ioevent_counts_via_uds() {
    use fandhe_container_microvm::interrupt::IoEventCounts;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if std::env::var_os(IOEVENT_CHILD_ENV).is_some() {
        // 子: 偽 backend が (2, 1) を返す構成で start → stop を通す。
        let mut e = mock_core::E2e::start();
        e.record.lock().expect("lock").stop_ioevent = Some(IoEventCounts::new(2, 1));
        let kernel = e.dir.file("k.bin", KERNEL);
        let start = s(&["start", "vm1", &kernel, "", "", "1", "64"]);
        assert_eq!(expect_ok(call(&mut e.stream, 1, start), 1), s(&["running"]));
        assert_eq!(
            expect_ok(call(&mut e.stream, 2, s(&["stop", "vm1"])), 2),
            s(&["stopped", "requested"])
        );
        let _ = e.finish();
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "mvm1_repair4_4161_stop_log_carries_ioevent_counts_via_uds",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(IOEVENT_CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let begin = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        if begin.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not finish within deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut err = String::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }
    assert!(status.success(), "child failed: {status:?}\n{err}");
    let stop_line = err
        .lines()
        .find(|l| l.contains("op=plugin.microvm.stop"))
        .unwrap_or_else(|| panic!("no stop log line in child stderr:\n{err}"));
    assert!(
        stop_line.starts_with("level=info op=plugin.microvm.stop outcome=ok elapsed_us="),
        "{stop_line}"
    );
    assert!(
        stop_line.ends_with(" vms=0 ignored=2 unbind_failed=1"),
        "{stop_line}"
    );
}

#[test]
fn task117_4_mvm1_start_with_initrd_reaches_backend() {
    let mut e = mock_core::E2e::start();
    let kernel = e.dir.file("k.bin", KERNEL);
    let initrd = e.dir.file("i.bin", b"initrd-bytes");
    let start = s(&["start", "vm1", &kernel, &initrd, "quiet", "1", "32"]);
    assert_eq!(expect_ok(call(&mut e.stream, 1, start), 1), s(&["running"]));
    {
        let r = e.record.lock().expect("lock");
        assert_eq!(r.starts[0].initrd.as_deref(), Some(&b"initrd-bytes"[..]));
        assert_eq!(r.starts[0].mem_bytes, 32 << 20);
        assert_eq!(r.starts[0].cmdline, "quiet");
    }
    let _ = e.finish();
}

#[test]
fn task117_4_mvm1_disconnect_with_running_vm_is_reclaimed_by_stop_all() {
    use fandhe_container_plugin_microvm::adapter::{STOP_DEADLINE, StopAllReport};
    use fandhe_container_plugin_microvm::frame_loop::LoopExit;

    let mut e = mock_core::E2e::start();
    let kernel = e.dir.file("k.bin", KERNEL);
    let start = s(&["start", "vm1", &kernel, "", "", "1", "64"]);
    assert_eq!(expect_ok(call(&mut e.stream, 1, start), 1), s(&["running"]));
    let record = std::sync::Arc::clone(&e.record);

    // stop を送らずに切断する。取り残された VM は plugin 側の stop_all が回収する。
    let (exit, report) = e.finish();
    assert!(matches!(exit, Ok(LoopExit::PeerClosed)), "{exit:?}");
    assert_eq!(
        report,
        StopAllReport {
            stopped: 1,
            failed: 0,
            remaining: 0,
            ioevent: None,
            unmap_failures: None,
            vm_unmap_failures: None
        }
    );
    let stops = record.lock().expect("lock").stops.clone();
    assert_eq!(stops.len(), 1);
    assert_eq!(stops[0].0, 1);
    assert!(stops[0].1 <= STOP_DEADLINE, "{:?}", stops[0].1);
}

/// MVM-1・REPAIR-4・#4438: 切断で取り残された 2 台を `stop_all` が回収したとき、件数が合算され、
/// `result_line` の具体値（` ignored=4 unbind_failed=2 unmap_failures=6`）に伝播する。
#[test]
fn mvm1_repair4_4438_disconnect_stop_all_sums_counts_into_result_line() {
    use fandhe_container_microvm::interrupt::IoEventCounts;
    use fandhe_container_plugin_microvm::adapter::StopAllReport;
    use fandhe_container_plugin_microvm::frame_loop::LoopExit;

    let mut e = mock_core::E2e::start();
    {
        let mut r = e.record.lock().expect("lock");
        r.stop_ioevent = Some(IoEventCounts::new(2, 1));
        r.stop_unmap = Some(3);
    }
    let kernel = e.dir.file("k.bin", KERNEL);
    for (id, name) in [(1, "vm1"), (2, "vm2")] {
        let start = s(&["start", name, &kernel, "", "", "1", "64"]);
        assert_eq!(
            expect_ok(call(&mut e.stream, id, start), id),
            s(&["running"])
        );
    }
    let (exit, report) = e.finish();
    assert!(matches!(exit, Ok(LoopExit::PeerClosed)), "{exit:?}");
    assert_eq!(
        report,
        StopAllReport {
            stopped: 2,
            failed: 0,
            remaining: 0,
            ioevent: Some(IoEventCounts::new(4, 2)),
            unmap_failures: Some(6),
            vm_unmap_failures: None
        }
    );
    assert_eq!(
        report.result_line(0),
        "level=info op=plugin.microvm.stop_all stopped=2 failed=0 remaining=0 detached=0 ignored=4 unbind_failed=2 unmap_failures=6"
    );
}

#[test]
fn task117_4_plug1_backend_start_failure_maps_to_error_frame_and_keeps_connection() {
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_plugin::PluginErrorCode;

    let mut e = mock_core::E2e::start();
    let kernel = e.dir.file("k.bin", KERNEL);
    e.record.lock().expect("lock").start_err = Some(MicrovmErrorCode::ResourceExhausted);
    let start = s(&["start", "vm1", &kernel, "", "", "1", "64"]);
    match call(&mut e.stream, 5, start) {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 5);
            assert_eq!(error.code(), PluginErrorCode::ResourceExhausted);
            assert_eq!(error.message(), "fake");
        }
        other => panic!("unexpected {other:?}"),
    }
    // 接続は維持され、失敗した VM は登録されていない。
    assert_eq!(
        expect_ok(call(&mut e.stream, 6, s(&["ping"])), 6),
        s(&["pong"])
    );
    match call(&mut e.stream, 7, s(&["stop", "vm1"])) {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 7);
            assert_eq!(error.code(), PluginErrorCode::NotFound);
        }
        other => panic!("unexpected {other:?}"),
    }
    let _ = e.finish();
}

/// `mkfifo` で FIFO を作る。起動失敗・非ゼロ終了・期限切れはすべて panic で失敗させる（REPAIR-5・REPAIR-12）。
fn make_fifo(path: &std::path::Path) {
    let mut child = std::process::Command::new("mkfifo")
        .arg(path)
        .spawn()
        .expect("spawn mkfifo");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait mkfifo") {
            Some(st) => break st,
            None if std::time::Instant::now() >= deadline => {
                let killed = child.kill();
                // kill 後の回収も有限期限で待つ（割り込み不能な待ちの子で無期限に止まらない）。
                let reap_deadline = std::time::Instant::now() + Duration::from_secs(5);
                let reaped = loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break true,
                        Ok(None) if std::time::Instant::now() < reap_deadline => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        _ => break false,
                    }
                };
                panic!("mkfifo did not exit within 10s (kill={killed:?}, reaped={reaped})");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    assert!(status.success(), "mkfifo failed: {status}");
}

/// イメージパスの読み取り失敗が、実際の UDS 経路で固定文言のエラー応答へ写る（ERR-1・SEC-1・PLUG-1・#3841）。
/// 最終要素の open は `O_NOCTTY` 付き（フラグ定数は sys の単体試験が具体値で固定）。lstat 後の tty 差し替えは
/// 公開 API からは作れないため、ここでは通常ファイルの読み取りが `O_NOCTTY` 付きでも成功すること（既存試験）と、
/// 実体でない・存在しない・権限なしの各入力が分類どおりに応答され、パス・OS 文言を漏らさないことを確かめる。
#[test]
fn sec1_err1_3841_image_open_failures_map_to_fixed_error_frames_via_uds() {
    use fandhe_container_plugin::PluginErrorCode;
    use std::os::unix::fs::PermissionsExt;

    let mut e = mock_core::E2e::start();
    let base = e.dir.0.clone();
    let good = e.dir.file("k.bin", KERNEL);
    let real_dir = std::fs::canonicalize(&base).expect("canonicalize");

    // 存在しない kernel / initrd は NOT_FOUND（文言は種別ごとの固定文）。
    let missing = real_dir
        .join("absent.bin")
        .to_str()
        .expect("utf8")
        .to_string();
    let mut id = 10u64;
    let mut expect_err = |e: &mut mock_core::E2e, body: Vec<String>| {
        id += 1;
        match call(&mut e.stream, id, body) {
            ControlMessage::Error { id: got, error } => {
                assert_eq!(got.get(), id);
                (error.code(), error.message().to_string())
            }
            other => panic!("unexpected {other:?}"),
        }
    };
    let r = expect_err(&mut e, s(&["start", "v1", &missing, "", "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::NotFound,
            "kernel image not found".to_string()
        )
    );
    let r = expect_err(&mut e, s(&["start", "v1", &good, &missing, "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::NotFound,
            "initrd image not found".to_string()
        )
    );

    // 最終要素が symlink / FIFO（通常ファイルではない）は INVALID_ARGUMENT。
    let link = real_dir.join("link.bin");
    std::os::unix::fs::symlink(&good, &link).expect("symlink");
    let link_s = link.to_str().expect("utf8").to_string();
    let r = expect_err(&mut e, s(&["start", "v1", &link_s, "", "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::InvalidArgument,
            "image must be a regular file".to_string()
        )
    );
    let fifo = real_dir.join("fifo.bin");
    make_fifo(&fifo);
    let fifo_s = fifo.to_str().expect("utf8").to_string();
    let r = expect_err(&mut e, s(&["start", "v1", &fifo_s, "", "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::InvalidArgument,
            "image must be a regular file".to_string()
        )
    );

    // 祖先が symlink のディレクトリは INVALID_ARGUMENT（祖先の文言）。
    let dir_link = real_dir.join("dlink");
    std::os::unix::fs::symlink(&real_dir, &dir_link).expect("symlink dir");
    let via = dir_link.join("k.bin").to_str().expect("utf8").to_string();
    let r = expect_err(&mut e, s(&["start", "v1", &via, "", "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::InvalidArgument,
            "image path ancestor must be a real directory".to_string()
        )
    );

    // 読み取り権限が無い通常ファイルは PERMISSION_DENIED。root では権限が効かず検証できないため、
    // 前提の不成立は省略せず明示的に失敗させる（非特権で実行する。REPAIR-12）。
    let secret = e.dir.file("noperm.bin", KERNEL);
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    assert!(
        std::fs::File::open(&secret).is_err(),
        "precondition failed: mode 000 file is readable (run as a non-root user)"
    );
    let r = expect_err(&mut e, s(&["start", "v1", &secret, "", "", "1", "64"]));
    assert_eq!(
        r,
        (
            PluginErrorCode::PermissionDenied,
            "permission denied reading image".to_string()
        )
    );

    // 失敗後も接続は維持され、VM は登録されていない。
    assert_eq!(
        expect_ok(call(&mut e.stream, 99, s(&["ping"])), 99),
        s(&["pong"])
    );
    assert!(e.record.lock().expect("lock").starts.is_empty());
    let _ = e.finish();
}

/// 停止期限切れで切り離した VM は、終了を観測するまで枠を返さず、観測後の start で枠が回収される（#3745・PLUG-1・REPAIR-5）。
#[test]
fn task117_4_mvm1_repair5_3745_detached_slot_reclaimed_after_exit_observed_via_uds() {
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_plugin::PluginErrorCode;
    use fandhe_container_plugin_microvm::adapter::MAX_VMS;

    let mut e = mock_core::E2e::start();
    let kernel = e.dir.file("k.bin", KERNEL);
    e.record.lock().expect("lock").stop_err = Some(MicrovmErrorCode::DeadlineExceeded);
    let mut id = 1u64;
    for i in 0..MAX_VMS {
        let name = format!("vm{i}");
        let start = s(&["start", &name, &kernel, "", "", "1", "64"]);
        assert_eq!(
            expect_ok(call(&mut e.stream, id, start), id),
            s(&["running"])
        );
        id += 1;
        match call(&mut e.stream, id, s(&["stop", &name])) {
            ControlMessage::Error { error, .. } => {
                assert_eq!(error.code(), PluginErrorCode::Timeout);
            }
            other => panic!("unexpected {other:?}"),
        }
        id += 1;
    }
    // 終了未観測の間は上限で拒否され続け、backend は追加で起動されない。
    for _ in 0..2 {
        let over = s(&["start", "over", &kernel, "", "", "1", "64"]);
        match call(&mut e.stream, id, over) {
            ControlMessage::Error { error, .. } => {
                assert_eq!(error.code(), PluginErrorCode::ResourceExhausted);
            }
            other => panic!("unexpected {other:?}"),
        }
        id += 1;
        assert_eq!(e.record.lock().expect("lock").starts.len(), MAX_VMS);
    }
    // vCPU スレッドの終了を観測できたら、次の start で枠が回収されて通る。
    e.record.lock().expect("lock").exited.insert(1);
    let again = s(&["start", "new", &kernel, "", "", "1", "64"]);
    assert_eq!(
        expect_ok(call(&mut e.stream, id, again), id),
        s(&["running"])
    );
    id += 1;
    assert_eq!(e.record.lock().expect("lock").starts.len(), MAX_VMS + 1);
    // 回収は観測した 1 件だけで、残りは再び上限に当たる。
    let over = s(&["start", "over2", &kernel, "", "", "1", "64"]);
    match call(&mut e.stream, id, over) {
        ControlMessage::Error { error, .. } => {
            assert_eq!(error.code(), PluginErrorCode::ResourceExhausted);
        }
        other => panic!("unexpected {other:?}"),
    }
    e.record.lock().expect("lock").stop_err = None;
    let _ = e.finish();
}

/// 期限つき回収の共有補助（層 B のみ。取り込みは cfg の内側に限る）。
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

/// 合成 bzImage の正本（`crates/microvm/tests/support/bzimage.rs`。複製しない・#3750）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../../microvm/tests/support/bzimage.rs"]
mod bzimage;

/// KVM 側の前提欠如と回帰の振り分けの正本（環境を示すコードだけ前提欠如にする。MVM-1・REPAIR-4・#3992）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "../../microvm/tests/support/kvm_precondition.rs"]
mod kvm_precondition;

/// 層 B の共有補助（実バイナリの spawn・期限つき回収・反射検査）。Linux x86_64 / aarch64 の KVM と macOS aarch64 の HVF が使う。
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod real_bin {
    use super::*;
    use std::io::Read;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use fandhe_container_plugin::PLUGIN_SOCKET_ENV;

    use super::reap;

    pub const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-microvm");
    pub const WAIT: Duration = Duration::from_secs(30);

    /// 実バイナリの子プロセスを保持する RAII ガード。assert 失敗・panic で drop されても
    /// 期限つきで kill と回収を行い、plugin を残さない（REPAIR-5）。
    pub struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn child(&mut self) -> &mut Child {
            self.0.as_mut().expect("child already taken")
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                reap::reap_or_report(&mut child, reap::reap_within());
            }
        }
    }

    pub fn spawn(sock: &Path) -> ChildGuard {
        ChildGuard(Some(spawn_raw(sock)))
    }

    fn spawn_raw(sock: &Path) -> Child {
        Command::new(BIN)
            .env_clear()
            .env(PLUGIN_SOCKET_ENV, sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn")
    }

    /// 期限内に子の終了を待ち (終了コード, stderr) を返す。超過時は kill して失敗にする。
    pub fn wait_exit(mut guard: ChildGuard) -> (i32, String) {
        let child = guard.child();
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if start.elapsed() > WAIT {
                // 以降の kill と回収はガードの drop が行う。
                panic!("plugin binary did not exit within deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut err = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        // 正常終了済みなのでガードの drop は kill しない（回収済みの子へ kill は失敗を無視）。
        guard.0 = None;
        (status.code().expect("exit code"), err)
    }

    pub fn assert_no_leak(err: &str, dir: &TempDir, kernel: &str) {
        assert!(!err.contains(dir.0.to_str().expect("utf8")), "{err}");
        assert!(!err.contains(kernel), "{err}");
        assert!(!err.contains("vm1"), "{err}");
    }
}

/// 層 B: 実バイナリ + 実 KVM（x86_64 Linux・`/dev/kvm` が要る実機前提）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod real_kvm {
    use super::*;

    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, UdsListener};

    use super::bzimage;
    use super::real_bin::{ChildGuard, assert_no_leak, spawn, wait_exit};

    /// boot_params の `HdrS` と cmd_line_ptr（0x20000）だけを確かめ、一致すれば自己ループする。不一致は `ud2`。
    fn guest_payload() -> Vec<u8> {
        let mut c: Vec<u8> = Vec::new();
        // cmp dword [rsi+0x202], "HdrS"; jne fail
        c.extend_from_slice(&[0x81, 0xBE, 0x02, 0x02, 0x00, 0x00, 0x48, 0x64, 0x72, 0x53]);
        c.extend_from_slice(&[0x75, 0x00]);
        let j1 = c.len() - 1;
        // cmp dword [rsi+0x228], 0x20000; jne fail
        c.extend_from_slice(&[0x81, 0xBE, 0x28, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
        c.extend_from_slice(&[0x75, 0x00]);
        let j2 = c.len() - 1;
        // jmp $
        c.extend_from_slice(&[0xEB, 0xFE]);
        let fail = c.len();
        c.extend_from_slice(&[0x0F, 0x0B]); // ud2
        for at in [j1, j2] {
            c[at] = u8::try_from(fail - (at + 1)).expect("rel8 fits");
        }
        c
    }

    fn precondition() {
        if let Err(e) = fandhe_container_microvm::device::KvmDevice::open() {
            panic!("{}", super::kvm_precondition::open_failure_line("e2e", &e));
        }
    }

    /// listener を立てて実バイナリを繋ぎ、ping と start（合成カーネル）まで進めた状態を返す。
    fn boot() -> (TempDir, ChildGuard, UdsStream, String) {
        precondition();
        let dir = TempDir::new();
        let sock = dir.0.join("p.sock");
        let kernel = dir.file("k.bin", &bzimage::synthetic_bzimage(&guest_payload()));
        let listener = UdsListener::bind(&sock).expect("bind");
        let child = spawn(&sock);
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream = listener
            .accept(Duration::from_secs(20), &mut obs)
            .expect("accept");
        assert_eq!(obs.len(), 0);
        assert_eq!(
            expect_ok(call(&mut stream, 1, s(&["ping"])), 1),
            s(&["pong"])
        );
        let start = s(&["start", "vm1", &kernel, "", "console=ttyS0", "1", "64"]);
        assert_eq!(expect_ok(call(&mut stream, 2, start), 2), s(&["running"]));
        // ゲストを走らせる時間を取る（不正なエントリなら ud2 で止まる）。
        std::thread::sleep(Duration::from_millis(200));
        (dir, child, stream, kernel)
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn task117_4_plug1_mvm1_real_kvm_start_stop_via_plugin_binary() {
        let (dir, child, mut stream, kernel) = boot();
        assert_eq!(
            expect_ok(call(&mut stream, 3, s(&["stop", "vm1"])), 3),
            s(&["stopped", "requested"])
        );
        drop(stream);
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            err.matches("op=plugin.microvm.start outcome=ok").count(),
            1,
            "{err}"
        );
        assert_eq!(
            err.matches("op=plugin.microvm.stop outcome=ok").count(),
            1,
            "{err}"
        );
        assert!(!err.contains("outcome=error"), "{err}");
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        // #4456・MVM-1・REPAIR-4: 本物の KvmBackend の stop の結果行は ignored= / unbind_failed= / unmap_failures= をこの順で必ず持つ。
        if let Err(why) = check_kvm_stop_line(&err) {
            panic!("{why}\n{err}");
        }
        assert_no_leak(&err, &dir, &kernel);
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm (MVM-1)"]
    fn task117_4_mvm1_real_kvm_disconnect_reclaims_running_vm() {
        let (dir, child, stream, kernel) = boot();
        drop(stream); // stop を送らずに切断する。
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        // stop_all が残った VM を failed=0 remaining=0 で止めたなら warn 行は出ない。
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        assert!(!err.contains("outcome=error"), "{err}");
        assert_no_leak(&err, &dir, &kernel);
    }
}

/// 合成 arm64 Image の正本（`crates/microvm/tests/support/arm64_image.rs`。複製しない・#3800）。
/// macOS aarch64 の HVF と Linux aarch64 の KVM（#3959）が使う。
#[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
#[path = "../../microvm/tests/support/arm64_image.rs"]
mod arm64_image;

/// 層 B: 実バイナリ + 実 KVM（Linux aarch64・`/dev/kvm` と in-kernel vGICv3・`KVM_CAP_ARM_PSCI_0_2` が要る実機前提。
/// #3959・MVM-1・PLUG-1・REPAIR-12）。`MicroVm` は arm64 Image + FDT で起動する。ネイティブ arm64 の CI が無く（#2274）、
/// 実機での実行は人間担当の #3781。KVM は 1 プロセスに複数 VM を作れるため `--test-threads=1` は不要。
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod real_kvm_arm64 {
    use super::*;

    use fandhe_container_microvm::device::KvmDevice;
    use fandhe_container_microvm::microvm::{MicroVm, MicroVmConfig};
    use fandhe_container_microvm::virtio_block::MemoryBlockBackend;
    use fandhe_container_microvm::virtio_net::MemoryNetBackend;
    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, UdsListener};

    use super::arm64_image;
    use super::real_bin::{ChildGuard, assert_no_leak, spawn, wait_exit};

    /// x0 が指す FDT の先頭 4 バイト（ビッグエンディアンの magic `0xd00dfeed`）だけを確かめ、一致すれば自己ループする。
    /// 不一致は PSCI SYSTEM_OFF（`hvc #0`）で止まり、停止理由が `guest_shutdown` になって `requested` の assert が落ちる。
    /// `b.ne` の即値（imm19 = 2、+8 バイト）は命令を並べ替えるときに再計算が要る。
    fn guest_payload() -> Vec<u32> {
        vec![
            0xB940_0001, // 0x00 ldr  w1, [x0]
            0x5AC0_0821, // 0x04 rev  w1, w1
            0x529F_DDA2, // 0x08 movz w2, #0xfeed
            0x72BA_01A2, // 0x0c movk w2, #0xd00d, lsl #16
            0x6B02_003F, // 0x10 cmp  w1, w2
            0x5400_0041, // 0x14 b.ne fail (+0x08)
            0x1400_0000, // 0x18 b .
            0xD2B0_8000, // 0x1c fail: movz x0, #0x8400, lsl #16
            0xF280_0100, // 0x20 movk x0, #0x8 (PSCI SYSTEM_OFF)
            0xD400_0002, // 0x24 hvc  #0
            0x1400_0000, // 0x28 b .
        ]
    }

    /// 前提を確かめる。`/dev/kvm` が開けても vGICv3 や PSCI 0.2 が無ければ plugin 側の start が Error になり回帰と見分けにくいため、
    /// 試験プロセス内で VM を組み立てて直ちに drop する。欠けていれば決まった 1 行目で失敗させる（skip しない）。
    fn precondition() {
        let dev = KvmDevice::open().unwrap_or_else(|e| {
            panic!("{}", super::kvm_precondition::open_failure_line("e2e", &e))
        });
        let config = MicroVmConfig::<MemoryBlockBackend, MemoryNetBackend> {
            vcpu_count: 1,
            mem_size: 64 << 20,
            block: vec![],
            net: vec![],
        };
        match MicroVm::assemble(&dev, config) {
            Ok(vm) => drop(vm),
            Err(e) => panic!(
                "{}",
                super::kvm_precondition::assemble_failure_line("e2e", &e)
            ),
        }
    }

    /// listener を立てて実バイナリを繋ぎ、ping と start（合成 arm64 Image）まで進めた状態を返す。
    fn boot() -> (TempDir, ChildGuard, UdsStream, String) {
        precondition();
        let dir = TempDir::new();
        let sock = dir.0.join("p.sock");
        let kernel = dir.file(
            "k.img",
            &arm64_image::synthetic_image_with_code(true, &guest_payload()),
        );
        let listener = UdsListener::bind(&sock).expect("bind");
        let child = spawn(&sock);
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream = listener
            .accept(Duration::from_secs(20), &mut obs)
            .expect("accept");
        assert_eq!(obs.len(), 0);
        assert_eq!(
            expect_ok(call(&mut stream, 1, s(&["ping"])), 1),
            s(&["pong"])
        );
        let start = s(&["start", "vm1", &kernel, "", "console=ttyS0", "1", "64"]);
        assert_eq!(expect_ok(call(&mut stream, 2, start), 2), s(&["running"]));
        // ゲストを走らせる時間を取る（不正なエントリ・x0 なら SYSTEM_OFF で止まる）。
        std::thread::sleep(Duration::from_millis(200));
        (dir, child, stream, kernel)
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn mvm1_3959_plug1_real_kvm_arm64_start_stop_via_plugin_binary() {
        let (dir, child, mut stream, kernel) = boot();
        assert_eq!(
            expect_ok(call(&mut stream, 3, s(&["stop", "vm1"])), 3),
            s(&["stopped", "requested"])
        );
        drop(stream);
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            err.matches("op=plugin.microvm.start outcome=ok").count(),
            1,
            "{err}"
        );
        assert_eq!(
            err.matches("op=plugin.microvm.stop outcome=ok").count(),
            1,
            "{err}"
        );
        assert!(!err.contains("outcome=error"), "{err}");
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        // #4456・MVM-1・REPAIR-4: 本物の KvmBackend の stop の結果行は ignored= / unbind_failed= / unmap_failures= をこの順で必ず持つ。
        if let Err(why) = check_kvm_stop_line(&err) {
            panic!("{why}\n{err}");
        }
        assert_no_leak(&err, &dir, &kernel);
    }

    #[test]
    #[ignore = "requires read/write access to /dev/kvm on an aarch64 host with a GICv3 and KVM_CAP_ARM_PSCI_0_2 (MVM-1)"]
    fn mvm1_3959_real_kvm_arm64_disconnect_reclaims_running_vm() {
        let (dir, child, stream, kernel) = boot();
        drop(stream); // stop を送らずに切断する。
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        // stop_all が残った VM を failed=0 remaining=0 で止めたなら warn 行は出ない。
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        assert!(!err.contains("outcome=error"), "{err}");
        assert_no_leak(&err, &dir, &kernel);
    }
}

/// 層 B: 実バイナリ + 実 Hypervisor.framework（macOS aarch64・Apple Silicon の macOS 15 以降・entitlement つきの署名が要る
/// 実機前提。TASK-192.18・#3800・MVM-5・MVM-1・PLUG-1）。
///
/// Hypervisor.framework は 1 プロセスに 1 VM のため、前提確認で試験プロセス内に作る VM は直ちに drop し、`--test-threads=1` で
/// 実行する（並列だと 2 件の前提確認がぶつかる）。待ちはすべて期限つき（REPAIR-5）。
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod real_hvf {
    use super::*;
    use std::process::Command;

    use fandhe_container_microvm::arm64_layout::Arm64Layout;
    use fandhe_container_microvm::error::MicrovmErrorCode;
    use fandhe_container_microvm::hvf::VmWithGic;
    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, UdsListener};

    use super::real_bin::{BIN, ChildGuard, assert_no_leak, spawn, wait_exit};
    use super::{arm64_image, reap};

    const ENTITLEMENT: &str = "com.apple.security.hypervisor";

    /// 前提を確かめる。欠けていれば決まった 1 行目で失敗させる（skip しない）。
    /// 試験バイナリ自身（VM を作れること）と plugin バイナリ（entitlement つきの署名）の両方に署名が要る。
    fn precondition() {
        let layout = Arm64Layout::new(64 << 20, 1, 0).expect("layout");
        match VmWithGic::create(&layout) {
            Ok(vm) => drop(vm),
            // 権限不足だけを環境の問題とする。GIC の呼び出しの失敗は回帰と読めるように別の行で出す（#3989）。
            Err(e) if e.code() == MicrovmErrorCode::PermissionDenied => {
                panic!("e2e: PRECONDITION FAILED (test environment, not a regression): {e}")
            }
            Err(e) => panic!("e2e: gic: {e}"),
        }
        let mut cmd = Command::new("codesign");
        cmd.args(["-d", "--entitlements", "-", BIN]);
        let signed = match reap::output_within(&mut cmd, Duration::from_secs(30)) {
            Ok(o) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                text.contains(ENTITLEMENT)
            }
            Err(_) => false,
        };
        if !signed {
            panic!(
                "e2e: PRECONDITION FAILED (test environment, not a regression): plugin binary is not signed with {ENTITLEMENT}"
            );
        }
    }

    /// listener を立てて実バイナリを繋ぎ、ping と start（合成 arm64 Image）まで進めた状態を返す。
    fn boot() -> (TempDir, ChildGuard, UdsStream, String) {
        precondition();
        let dir = TempDir::new();
        let sock = dir.0.join("p.sock");
        let kernel = dir.file("k.img", &arm64_image::synthetic_image(true));
        let listener = UdsListener::bind(&sock).expect("bind");
        let child = spawn(&sock);
        let mut obs = JsonLinesPeerAuthObserver::new();
        let mut stream = listener
            .accept(Duration::from_secs(20), &mut obs)
            .expect("accept");
        assert_eq!(obs.len(), 0);
        assert_eq!(
            expect_ok(call(&mut stream, 1, s(&["ping"])), 1),
            s(&["pong"])
        );
        let start = s(&["start", "vm1", &kernel, "", "console=ttyAMA0", "1", "64"]);
        assert_eq!(expect_ok(call(&mut stream, 2, start), 2), s(&["running"]));
        // ゲストを走らせる時間を取る（自己ループなので走り続ける）。
        std::thread::sleep(Duration::from_millis(200));
        (dir, child, stream, kernel)
    }

    #[test]
    #[ignore = "requires Apple silicon macOS 15+ and binaries signed with com.apple.security.hypervisor (MVM-5)"]
    fn task192_18_plug1_mvm5_real_hvf_start_stop_via_plugin_binary() {
        let (dir, child, mut stream, kernel) = boot();
        assert_eq!(
            expect_ok(call(&mut stream, 3, s(&["stop", "vm1"])), 3),
            s(&["stopped", "requested"])
        );
        drop(stream);
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            err.matches("op=plugin.microvm.start outcome=ok").count(),
            1,
            "{err}"
        );
        assert_eq!(
            err.matches("op=plugin.microvm.stop outcome=ok").count(),
            1,
            "{err}"
        );
        assert!(!err.contains("outcome=error"), "{err}");
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        // #4437・MVM-5・REPAIR-4: stop の結果行に ` unmap_failures=0` が 0 件でも付く。
        // microvm 本体の集約行 `op=hvf.microvm.stop ... unmap_failures=` と取り違えないよう、
        // `op=plugin.microvm.stop outcome=` の行を起点に完全一致で照合する（adapter が None のままなら不一致）。
        let line = err
            .lines()
            .find(|l| l.contains("op=plugin.microvm.stop outcome="))
            .unwrap_or_else(|| panic!("no plugin stop line: {err}"));
        let us = line
            .split(" elapsed_us=")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .unwrap_or_else(|| panic!("no elapsed_us: {line}"));
        assert!(
            !us.is_empty() && us.bytes().all(|b| b.is_ascii_digit()),
            "{line}"
        );
        // 末尾の ` vm_unmap_failures=0` は #4455（adapter が `None` のままなら不一致になる）。
        assert_eq!(
            line,
            format!(
                "level=info op=plugin.microvm.stop outcome=ok elapsed_us={us} vms=0 unmap_failures=0 vm_unmap_failures=0"
            ),
            "{err}"
        );
        assert_no_leak(&err, &dir, &kernel);
    }

    #[test]
    #[ignore = "requires Apple silicon macOS 15+ and binaries signed with com.apple.security.hypervisor (MVM-5)"]
    fn task192_18_mvm5_real_hvf_disconnect_reclaims_running_vm() {
        let (dir, child, stream, kernel) = boot();
        drop(stream); // stop を送らずに切断する。
        let (code, err) = wait_exit(child);
        assert_eq!(code, 0, "{err}");
        // stop_all が残った VM を failed=0 remaining=0 で止めたなら warn 行は出ない。
        assert!(!err.contains("op=plugin.microvm.stop_all"), "{err}");
        assert!(!err.contains("outcome=error"), "{err}");
        assert_no_leak(&err, &dir, &kernel);
    }
}
