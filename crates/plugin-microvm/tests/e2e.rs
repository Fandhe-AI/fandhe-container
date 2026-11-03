//! core 役 → plugin-microvm（UDS 境界）→ microVM の起動 → 停止の結合試験（TASK-117.4・#713。PLUG-1・MVM-1・PLUG-12・REPAIR-5・REPAIR-12）。
//!
//! 兄弟の `plugin-macos/tests/e2e.rs`（TASK-115.6）・`plugin-windows/tests/e2e.rs`（TASK-116.6）と同じ 2 層構成。
//! 「core」役は共有境界 crate `fandhe-container-plugin` の `UdsListener`（core が bind し plugin が connect する既存契約）を
//! 試験本体が担う。core 側の plugin-microvm 起動経路（`BackendKind` への追加）は #1869 の設計の 4.9 の範囲で未結線のため、
//! ここでは境界の wire 契約（ping / start / stop）を固定する（REPAIR-3）。
//!
//! - 層 A（既定集合・unix・KVM 不要）: plugin 役のスレッドが `main.rs` と同じ順
//!   （peer 認証つき connect → `MicrovmRuntimeAdapter` → `serve` → `stop_all`）を偽バックエンドで実行し、実 UDS 上で
//!   起動・停止・切断時の回収・起動失敗後の接続維持を具体値で照合する。
//! - 層 B（`#[ignore]`・Linux x86_64・`/dev/kvm` が要る実機前提）: 実バイナリを spawn し、本物の `KvmBackend` で合成
//!   bzImage を起動・停止する。UDS ホップを含む完全な通し。手順は `AGENTS.md`「実機前提テスト」節。
//!
//! 層 B の合成ゲストは boot_params（`HdrS` と cmd_line_ptr）を確かめて自己ループする。`KvmBackend` は block / net を付けない
//! ため、`crates/microvm/tests/microvm.rs` の virtio-mmio 照合ペイロードは使えない。ホスト側からゲストの exit の種別は
//! 観測できないので、停止理由 `requested`（停止要求の割り込みで止まった）が「正しいエントリで動き続けた」ことの判別材料になる。
//! ud2 だけのゲストで `guest_shutdown` を期待する負の対照は、停止要求と shutdown exit のどちらが先に観測されるかが競合し、
//! 寛容な assert になるため置かない。非 x86_64 では microvm の start が x86 専用のため層 B は置かない。
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
        p.to_str().expect("utf8 path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // 排他作成した自前のディレクトリのみ
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
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, UdsListener};
    use fandhe_container_plugin_microvm::adapter::{
        BootSpec, DetachedState, MicrovmBackend, MicrovmRuntimeAdapter, STOP_ALL_BUDGET,
        StopAllReport,
    };
    use fandhe_container_plugin_microvm::frame_loop::{LoopExit, serve};

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

        fn stop(&mut self, vm: u32, deadline: Duration) -> Result<&'static str, MicrovmError> {
            self.0.lock().expect("lock").stops.push((vm, deadline));
            Ok("requested")
        }

        fn exit_watch(&self, vm: &u32) -> u32 {
            *vm
        }

        fn exit_state(&self, _watch: &u32) -> DetachedState {
            DetachedState::Pending
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
            remaining: 0
        }
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
            remaining: 0
        }
    );
    let stops = record.lock().expect("lock").stops.clone();
    assert_eq!(stops.len(), 1);
    assert_eq!(stops[0].0, 1);
    assert!(stops[0].1 <= STOP_DEADLINE, "{:?}", stops[0].1);
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

/// 期限つき回収の共有補助（層 B のみ。取り込みは cfg の内側に限る）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

/// 層 B: 実バイナリ + 実 KVM（x86_64 Linux・`/dev/kvm` が要る実機前提）。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod real_kvm {
    use super::*;
    use std::io::Read;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PLUGIN_SOCKET_ENV, UdsListener};

    use super::reap;

    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-microvm");
    const WAIT: Duration = Duration::from_secs(30);

    /// 合成 bzImage（`crates/microvm/tests/microvm.rs` の同名関数と同じ組み立て。64-bit エントリは payload + 0x200）。
    /// 別 crate の試験との共通化は 1 PR・1 関心事の範囲外のため写している。残りの payload は `ud2` で埋める。
    fn synthetic_bzimage(entry_code: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 5 * 512 + 0x1000];
        let mut put = |off: usize, d: &[u8]| img[off..off + d.len()].copy_from_slice(d);
        put(0x1F1, &[4]);
        put(0x1FE, &0xAA55u16.to_le_bytes());
        put(0x201, &[0x62]);
        put(0x202, b"HdrS");
        put(0x206, &0x020Fu16.to_le_bytes());
        put(0x211, &[1]);
        put(0x22C, &0x3FF_FFFFu32.to_le_bytes());
        put(0x230, &0x20_0000u32.to_le_bytes());
        put(0x234, &[1]);
        put(0x236, &1u16.to_le_bytes());
        put(0x238, &2047u32.to_le_bytes());
        put(0x258, &0x100_0000u64.to_le_bytes());
        put(0x260, &0x40_0000u32.to_le_bytes());
        let payload = 5 * 512;
        for (i, b) in img[payload..].iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0x0F } else { 0x0B };
        }
        img[payload + 0x200..payload + 0x200 + entry_code.len()].copy_from_slice(entry_code);
        img
    }

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
            panic!("e2e: PRECONDITION FAILED (test environment, not a regression): {e}");
        }
    }

    /// 実バイナリの子プロセスを保持する RAII ガード。assert 失敗・panic で drop されても
    /// 期限つきで kill と回収を行い、plugin を残さない（REPAIR-5）。
    struct ChildGuard(Option<Child>);

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

    fn spawn(sock: &Path) -> ChildGuard {
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
    fn wait_exit(mut guard: ChildGuard) -> (i32, String) {
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

    /// listener を立てて実バイナリを繋ぎ、ping と start（合成カーネル）まで進めた状態を返す。
    fn boot() -> (TempDir, ChildGuard, UdsStream, String) {
        precondition();
        let dir = TempDir::new();
        let sock = dir.0.join("p.sock");
        let kernel = dir.file("k.bin", &synthetic_bzimage(&guest_payload()));
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

    fn assert_no_leak(err: &str, dir: &TempDir, kernel: &str) {
        assert!(!err.contains(dir.0.to_str().expect("utf8")), "{err}");
        assert!(!err.contains(kernel), "{err}");
        assert!(!err.contains("vm1"), "{err}");
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
