//! 非 x86_64 Linux の `start` で、backend の `Unimplemented` が plugin の `UNIMPLEMENTED` へ写り、応答文言が固定で
//! 入力（パス・id・cmdline）を反射しないことの照合（MVM-1・PLUG-1・REPAIR-12・TASK-117.4・#3751。親 #3724）。
//!
//! 本物の `KvmBackend` は使わない。`start` が最初に `/dev/kvm` を開くため、KVM の無い機では `Unimplemented` ではなく
//! NotFound / PermissionDenied になり、KVM を開かずに確かめる目的に合わないため。そこで microvm の `Unimplemented` を返す
//! 偽の `MicrovmBackend` を adapter（`MicrovmRuntimeAdapter`）へ差し、`RequestHandler::handle`（frame_loop が呼ぶ入口）から
//! 写像 `to_plugin_error` までを通す。aarch64 の本物の `KvmBackend` は `plan_layout_arm64` と
//! `assemble` の aarch64 分岐（#3696・#3899）を通って起動まで実装済みで、`Unimplemented` を返さない（実機での通しは未検証。#3781・#2274。
//! REPAIR-3: 未実施を装わない）。このため本物の backend で `Unimplemented` の写像を通しで確かめられる arch は現状無く、
//! 本試験は偽 backend による写像の照合に徹する（x86_64・aarch64 以外では `sys` の fail-closed の `Unsupported` が先に効きうる）。
//!
//! 実行の扱い: ネイティブ arm64 の CI が無いため、現状は `cross-target-check` の `aarch64-unknown-linux-gnu` の
//! 型検査・clippy（`--all-targets --all-features`）に留まり、実行はされない。x86_64 では cfg により空になる。
#![cfg(all(target_os = "linux", not(target_arch = "x86_64")))]

use std::cell::Cell;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_plugin::PluginErrorCode;
use fandhe_container_plugin_microvm::adapter::{
    BootSpec, DetachedState, MicrovmBackend, MicrovmRuntimeAdapter,
};
use fandhe_container_plugin_microvm::frame_loop::RequestHandler;

/// 入力へ混ぜる識別子。応答にこの文字列が現れたら入力の反射とみなす。
const MARKER: &str = "fc-pmv-noarch-marker";
/// 偽 backend が返す固定文言（microvm 側の文言は複製せず、写像が通すことだけを見る）。
const FAKE_MSG: &str = "fake backend: not implemented on this architecture";

/// 0700 の一時ディレクトリ。自分が作ったものだけを Drop で消す。
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        for _ in 0..100u32 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("{MARKER}-{}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test dir: {e}"),
            }
        }
        panic!("could not create a unique test dir");
    }

    /// 0600 の通常ファイルを排他作成し、絶対パス文字列を返す（adapter は相対パスと symlink を拒否する）。
    fn file(&self, name: &str, data: &[u8]) -> String {
        use std::io::Write;
        let p = self.0.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .expect("create test file");
        f.write_all(data).expect("write test file");
        p.to_str().expect("utf-8 path").to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `start` で必ず `Unimplemented` を返す偽 backend。呼ばれた回数を共有カウンタで外へ見せる。
struct UnimplementedBackend(Rc<Cell<usize>>);

impl MicrovmBackend for UnimplementedBackend {
    type Running = u32;
    type ExitWatch = u32;

    fn start(&mut self, _spec: BootSpec) -> Result<u32, MicrovmError> {
        self.0.set(self.0.get() + 1);
        Err(MicrovmError::new(MicrovmErrorCode::Unimplemented, FAKE_MSG))
    }

    fn stop(
        &mut self,
        _vm: u32,
        _deadline: Duration,
    ) -> Result<fandhe_container_plugin_microvm::adapter::StopOutcome, MicrovmError> {
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

    fn exit_state(&self, _watch: &u32) -> DetachedState {
        DetachedState::Pending
    }
}

/// MVM-1・PLUG-1・REPAIR-12（#3751）: backend の `Unimplemented` が `UNIMPLEMENTED` になり、文言は固定で入力を反射しない。
#[test]
fn mvm1_plug1_3751_non_x86_64_linux_start_unimplemented_maps_without_reflection() {
    let dir = TempDir::new();
    let kernel = dir.file("kernel", b"dummy kernel image");
    let calls = Rc::new(Cell::new(0));
    let mut adapter = MicrovmRuntimeAdapter::new(UnimplementedBackend(Rc::clone(&calls)));
    let id = format!("vm-{MARKER}");
    let cmdline = format!("console=ttyS0 {MARKER}");
    let body: Vec<String> = [
        "start",
        id.as_str(),
        kernel.as_str(),
        "",
        cmdline.as_str(),
        "1",
        "64",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let e = adapter.handle(&body).expect_err("start must fail");

    assert_eq!(e.code(), PluginErrorCode::Unimplemented);
    assert_eq!(e.code().as_str(), "UNIMPLEMENTED");
    assert_eq!(e.message(), FAKE_MSG);
    let dir_path = dir.0.to_str().expect("utf-8 path");
    for leaked in [
        kernel.as_str(),
        dir_path,
        id.as_str(),
        cmdline.as_str(),
        MARKER,
    ] {
        assert!(
            !e.message().contains(leaked),
            "response message must not reflect input: {leaked}"
        );
    }
    // 検証の前段で弾かれたのではなく、backend へ届いた後の写像であること。
    assert_eq!(calls.get(), 1);
    assert!(adapter.is_empty());
}
