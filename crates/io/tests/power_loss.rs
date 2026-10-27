//! 電源断・カーネルクラッシュ後の媒体永続化（IO-2）の実機前提試験（#1965・TASK-18 追補）。
//!
//! 役割: FLUSH ACK を返した書き込みが、ブロック層より下（媒体）へ出ているかを確かめる。
//! SIGKILL 試験（`crash_safety.rs`・IO-3）の再読込はページキャッシュ経由で、媒体への永続化は
//! 示せない。そこで loop デバイス上の ext4 に device-mapper の dm-flakey を挟み、FLUSH ACK を観測した
//! 直後に table を `drop_writes` へ切り替えて以降の書き込みを捨てる。サーバーを SIGKILL し、umount、
//! table を戻して再 mount した後のファイルを `check_disk_records` で seq 0..n と照合する
//! （xfstests の `_flakey_drop_and_remount` と同じ型）。方式の比較・推奨・範囲は
//! `docs/design/io-power-loss-verification.md`（オーナー承認待ち）を参照。
//!
//! # 実機前提（既定のテスト集合から外している）
//!
//! root・Linux（`syncfs` が使える 5.8 以上）・カーネルモジュール `dm_flakey`・`losetup`・`dmsetup`・
//! `mkfs.ext4`・`mount`・`umount` が要る。root を要する本体は `#[ignore]` で、人間が次で実行する
//! （Agent は root のコマンドを実行しない）。前提が欠けたら skip せず失敗する（fail-closed）。
//!
//! ```text
//! sudo -E cargo test -p fandhe-container-io --features crash-test-server --test power_loss \
//!     -- --ignored --exact linux::io2_flushed_data_survives_dm_flakey_drop_writes --nocapture
//! ```
//!
//! # 対象の限定（破壊的操作の安全性）
//!
//! 操作対象は、この試験が一時ディレクトリに作った疎なイメージファイルと、その loop デバイス・
//! dm デバイス・mount だけである。外から任意のデバイスやパスを渡す経路は無い。loop デバイスは
//! `/sys/block/loopN/loop/backing_file` で自分のイメージであることを照合してから使う。
//!
//! 示せないこと: 実際の電源断におけるディスクのキャッシュ挙動、macOS（`F_FULLFSYNC`）と
//! Windows（`FlushFileBuffers`）の永続化。未フラッシュ対照は結果を報告するだけで合否にしない
//! （期待値はオーナー判断待ち）。

#[cfg(target_os = "linux")]
#[path = "crash_safety/client_end.rs"]
mod client_end;
// crash_safety と共有するディスク照合（試行管理の `trial` は取り込まない）
#[cfg(target_os = "linux")]
#[path = "crash_safety/disk_check.rs"]
mod disk_check;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        AckReceipt, FrameKind, InFlightLimit, IoTimeout, NoopSendObserver, PipelineClient,
    };

    use crate::client_end::UnixClientEnd;
    use crate::disk_check::{RECORD_LEN, check_disk_records};

    /// イメージの大きさ（固定の上限。疎ファイル）。
    const IMAGE_BYTES: u64 = 64 * 1024 * 1024;
    const SECTOR_BYTES: u64 = 512;
    /// 1 試行で書く件数（バッチサイズ未満にして FLUSH で初めて永続化させる）。
    const WRITES: u64 = 30;
    /// 有効試行の目標（crash_safety と同じ）。
    const TRIALS: usize = 10;
    const CMD_TIMEOUT: Duration = Duration::from_secs(60);
    /// kill 後の子の回収を待つ上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    const READY_WAIT: Duration = Duration::from_secs(10);

    /// dm-flakey の table の状態。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FlakeyMode {
        /// 常に通す（up のみ）。
        Up,
        /// 以降の書き込みを捨てる（`drop_writes`）。
        DropWrites,
    }

    /// dm-flakey の table 行を組み立てる。書式は xfstests の `common/dmflakey` に合わせる
    /// （`<start> <len> flakey <dev> <offset> <up> <down> [<nfeat> <feat>...]`）。
    fn flakey_table(sectors: u64, dev: &str, mode: FlakeyMode) -> String {
        match mode {
            FlakeyMode::Up => format!("0 {sectors} flakey {dev} 0 180 0"),
            FlakeyMode::DropWrites => format!("0 {sectors} flakey {dev} 0 0 180 1 drop_writes"),
        }
    }

    /// dm 名に使える文字（試験が生成する値だけを受ける）。
    fn is_valid_dm_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// `/dev/loopN` の形か。
    fn loop_index(dev: &str) -> Option<u32> {
        dev.strip_prefix("/dev/loop")
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse().ok())
    }

    /// `/proc/self/mountinfo` から `mountpoint` の (FS 種別, source) を引く。
    fn mountinfo_entry(text: &str, mountpoint: &str) -> Option<(String, String)> {
        text.lines().find_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if left.split(' ').nth(4)? != mountpoint {
                return None;
            }
            let mut it = right.split(' ');
            let fstype = it.next()?.to_string();
            let source = it.next()?.to_string();
            Some((fstype, source))
        })
    }

    /// `/proc/self/status` の `Uid:` 行から実効 UID を返す。
    fn effective_uid(status: &str) -> Option<u32> {
        let line = status.lines().find(|l| l.starts_with("Uid:"))?;
        line.split_whitespace().nth(2)?.parse().ok()
    }

    fn require(cond: bool, what: &str) -> Result<(), String> {
        if cond {
            Ok(())
        } else {
            Err(format!("precondition failed: {what}"))
        }
    }

    /// kill 後の回収を有限時間だけ待つ（REPAIR-5）。割り込み不能待ち（D 状態）の子は
    /// SIGKILL でも終わらないため、期限内に回収できなければ打ち切って false を返す。
    fn reap_bounded(child: &mut Child) -> bool {
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) | Err(_) => return false,
            }
        }
    }

    /// 外部コマンドを期限つきで実行する（REPAIR-5）。シェルは経由しない。
    fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: spawn failed: {e}"))?;
        let deadline = Instant::now() + CMD_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let reaped = reap_bounded(&mut child);
                    return Err(format!("{program} {args:?}: timed out (reaped: {reaped})"));
                }
                Err(e) => return Err(format!("{program}: wait failed: {e}")),
            }
        };
        let mut out = String::new();
        if let Some(o) = child.stdout.take() {
            let _ = o.take(64 * 1024).read_to_string(&mut out);
        }
        let mut err = String::new();
        if let Some(e) = child.stderr.take() {
            let _ = e.take(64 * 1024).read_to_string(&mut err);
        }
        if status.success() {
            Ok(out)
        } else {
            Err(format!("{program} {args:?}: {status}: {}", err.trim()))
        }
    }

    /// `/sys/class/block/dm-*/dm/name` を走査して、指定名の dm デバイスがあるかを返す。
    /// 走査できなければ Err（不存在を確認できない）。
    fn dm_exists(name: &str) -> Result<bool, String> {
        let dir = std::fs::read_dir("/sys/class/block")
            .map_err(|e| format!("cannot read /sys/class/block: {e}"))?;
        for entry in dir {
            let entry = entry.map_err(|e| format!("cannot read dir entry: {e}"))?;
            if !entry.file_name().to_string_lossy().starts_with("dm-") {
                continue;
            }
            match std::fs::read_to_string(entry.path().join("dm/name")) {
                Ok(n) if n.trim() == name => return Ok(true),
                Ok(_) => {}
                // 走査中に消えたデバイスは対象外
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("cannot read dm name: {e}")),
            }
        }
        Ok(false)
    }

    /// `/sys/block/loop*/loop/backing_file` が自分のイメージを指す loop デバイスを探す。
    /// 走査できなければ Err（不存在を確認できない）。
    fn find_loop_for_image(image: &Path) -> Result<Option<String>, String> {
        let dir =
            std::fs::read_dir("/sys/block").map_err(|e| format!("cannot read /sys/block: {e}"))?;
        for entry in dir {
            let entry = entry.map_err(|e| format!("cannot read dir entry: {e}"))?;
            let fname = entry.file_name().to_string_lossy().into_owned();
            if !fname.starts_with("loop") {
                continue;
            }
            match std::fs::read_to_string(entry.path().join("loop/backing_file")) {
                Ok(b) if Path::new(b.trim()) == image => return Ok(Some(format!("/dev/{fname}"))),
                Ok(_) => {}
                // 未接続の loop には backing_file が無い
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("cannot read backing_file: {e}")),
            }
        }
        Ok(None)
    }

    /// loop・dm・mount を必ず外す後始末つきの試験装置。Drop は逆順で外す。
    struct Rig {
        root: PathBuf,
        image: PathBuf,
        mnt: PathBuf,
        dm_name: String,
        loop_dev: Option<String>,
        /// `losetup` を実行した（結果が不明でも作成済みの可能性がある）。cleanup が sysfs で照合する。
        loop_attempted: bool,
        dm_created: bool,
        /// `dmsetup create` を実行した（タイムアウト等で Err でもカーネル内に作成済みの可能性がある）。
        dm_attempted: bool,
        mounted: bool,
        sectors: u64,
    }

    impl Rig {
        fn dm_path(&self) -> String {
            format!("/dev/mapper/{}", self.dm_name)
        }

        fn new() -> Result<Self, String> {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
            require(
                effective_uid(&status) == Some(0),
                "must run as root (euid 0)",
            )?;
            let root = std::env::temp_dir().join(format!("fcio-pl-{}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
            let mnt = root.join("mnt");
            let dm_name = format!("fcio-pl-{}", std::process::id());
            require(is_valid_dm_name(&dm_name), "dm name charset")?;
            let mut rig = Self {
                image: root.join("disk.img"),
                mnt,
                root,
                dm_name,
                loop_dev: None,
                loop_attempted: false,
                dm_created: false,
                dm_attempted: false,
                mounted: false,
                sectors: IMAGE_BYTES / SECTOR_BYTES,
            };
            rig.setup()?;
            Ok(rig)
        }

        fn setup(&mut self) -> Result<(), String> {
            let f = std::fs::File::create(&self.image).map_err(|e| e.to_string())?;
            f.set_len(IMAGE_BYTES).map_err(|e| e.to_string())?;
            drop(f);
            std::fs::create_dir(&self.mnt).map_err(|e| e.to_string())?;
            let image = self.image.to_string_lossy().into_owned();
            // 結果が不明（タイムアウト等）でも接続済みの可能性があるため、実行前に試行を記録する
            self.loop_attempted = true;
            let dev = run_cmd("losetup", &["--find", "--show", &image])?
                .trim()
                .to_string();
            // 取得した名前を Drop が外せるよう、検証より先に記録する
            self.loop_dev = Some(dev.clone());
            let idx = loop_index(&dev).ok_or_else(|| format!("not a loop device: {dev}"))?;
            let backing =
                std::fs::read_to_string(format!("/sys/block/loop{idx}/loop/backing_file"))
                    .map_err(|e| format!("cannot read backing_file: {e}"))?;
            require(
                Path::new(backing.trim()) == self.image,
                "loop backing_file is our image",
            )?;
            let table = flakey_table(self.sectors, &dev, FlakeyMode::Up);
            self.dm_attempted = true;
            run_cmd("dmsetup", &["create", &self.dm_name, "--table", &table])?;
            self.dm_created = true;
            run_cmd("mkfs.ext4", &["-q", "-F", &self.dm_path()])?;
            self.mount()
        }

        fn mount(&mut self) -> Result<(), String> {
            let mnt = self.mnt.to_string_lossy().into_owned();
            run_cmd("mount", &["-t", "ext4", &self.dm_path(), &mnt])?;
            self.mounted = true;
            // mount した先が自分の dm 上の ext4 であることを確かめる（tmpfs 等を拒む）
            let info = std::fs::read_to_string("/proc/self/mountinfo")
                .map_err(|e| format!("cannot read mountinfo: {e}"))?;
            let entry = mountinfo_entry(&info, &mnt);
            require(
                entry.as_ref().map(|(t, _)| t.as_str()) == Some("ext4"),
                "mountpoint is ext4",
            )?;
            require(
                entry.as_ref().is_some_and(|(_, s)| s.starts_with("/dev/")),
                "mount source is a block device",
            )
        }

        fn umount(&mut self) -> Result<(), String> {
            let mnt = self.mnt.to_string_lossy().into_owned();
            run_cmd("umount", &[&mnt])?;
            self.mounted = false;
            Ok(())
        }

        /// 書き込みを止めずに table を差し替える（`suspend --nolockfs` → load → resume）。
        fn switch(&self, mode: FlakeyMode) -> Result<(), String> {
            let dev = self
                .loop_dev
                .as_deref()
                .ok_or_else(|| "loop device not set".to_string())?;
            let table = flakey_table(self.sectors, dev, mode);
            run_cmd("dmsetup", &["suspend", "--nolockfs", &self.dm_name])?;
            let load = run_cmd("dmsetup", &["load", &self.dm_name, "--table", &table]);
            // load が失敗しても必ず resume する（suspend のまま残さない）
            let resume = run_cmd("dmsetup", &["resume", &self.dm_name]);
            load.and(resume).map(|_| ())
        }
    }

    impl Rig {
        /// 実行結果が不明だった作成操作を sysfs で照合し、作成済みなら追跡へ取り込む。
        /// 存在の有無を確認できない場合は `failures` に積み、イメージと残存情報を保持させる。
        fn reconcile(&mut self, failures: &mut Vec<String>) -> bool {
            let before = failures.len();
            if self.dm_attempted && !self.dm_created {
                match dm_exists(&self.dm_name) {
                    Ok(true) => self.dm_created = true,
                    Ok(false) => {}
                    Err(e) => failures.push(format!("cannot confirm dm absence: {e}")),
                }
            }
            if self.loop_attempted && self.loop_dev.is_none() {
                match find_loop_for_image(&self.image) {
                    Ok(found) => self.loop_dev = found,
                    Err(e) => failures.push(format!("cannot confirm loop absence: {e}")),
                }
            }
            failures.len() > before
        }

        /// 逆順で解除する。失敗した段階は残し、1 つでも失敗したらイメージ・配置先を消さずに
        /// 残存情報を Err で返す（特権操作の後始末。使用中の backing image を unlink しない）。
        fn cleanup(&mut self) -> Result<(), String> {
            let mut failures: Vec<String> = Vec::new();
            // 照合できない作成操作が残る間は、使用中の恐れがある loop を外さずイメージも消さない
            let unconfirmed = self.reconcile(&mut failures);
            if self.mounted {
                let mnt = self.mnt.to_string_lossy().into_owned();
                match run_cmd("umount", &[&mnt]) {
                    Ok(_) => self.mounted = false,
                    Err(e) => failures.push(format!("umount: {e}")),
                }
            }
            // マウントが残るなら dm は使用中のため外さない
            if self.dm_created && !self.mounted {
                match run_cmd("dmsetup", &["remove", "--retry", &self.dm_name]) {
                    Ok(_) => self.dm_created = false,
                    Err(e) => failures.push(format!("dmsetup remove: {e}")),
                }
            }
            let loop_to_detach = if self.dm_created || unconfirmed {
                None
            } else {
                self.loop_dev.clone()
            };
            if let Some(dev) = loop_to_detach {
                match run_cmd("losetup", &["-d", &dev]) {
                    Ok(_) => self.loop_dev = None,
                    Err(e) => failures.push(format!("losetup -d: {e}")),
                }
            }
            if failures.is_empty() {
                // 自分が作った一時ディレクトリだけを消す
                let _ = std::fs::remove_dir_all(&self.root);
                Ok(())
            } else {
                Err(format!(
                    "cleanup incomplete, kept root={} image={} mnt={} dm={} loop={:?}: {}",
                    self.root.display(),
                    self.image.display(),
                    self.mnt.display(),
                    self.dm_name,
                    self.loop_dev,
                    failures.join("; ")
                ))
            }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            // 明示の cleanup 済みなら何もしない。失敗は残存情報として stderr に出す
            if let Err(e) = self.cleanup() {
                eprintln!("{{\"event\":\"cleanup_failed\",\"error\":{e:?}}}");
            }
        }
    }

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            if !reap_bounded(&mut self.0) {
                eprintln!("{{\"event\":\"child_not_reaped\",\"pid\":{}}}", self.0.id());
            }
        }
    }

    fn io_timeout(secs: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_secs(secs)).expect("timeout must be within the cap")
    }

    /// 1 試行の結果。
    struct Outcome {
        lost: u64,
        exact: bool,
    }

    /// 1 試行: 書く → (flush) → table を drop へ → SIGKILL → umount → 戻して mount → 照合。
    fn run_trial(rig: &mut Rig, index: usize, flush: bool) -> Result<Outcome, String> {
        let sock_dir =
            std::env::temp_dir().join(format!("fcio-pl-s-{}-{index}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&sock_dir)
            .map_err(|e| e.to_string())?;
        let result = trial_inner(rig, index, flush, &sock_dir);
        let _ = std::fs::remove_dir_all(&sock_dir);
        result
    }

    fn trial_inner(
        rig: &mut Rig,
        index: usize,
        flush: bool,
        sock_dir: &Path,
    ) -> Result<Outcome, String> {
        let data_dir = rig.mnt.join(format!("d{index}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&data_dir)
            .map_err(|e| e.to_string())?;
        let file = "data.bin";
        let mut command = Command::new(env!("CARGO_BIN_EXE_crash_test_server"));
        if !flush {
            command.arg("--batch-size").arg(WRITES.to_string());
        }
        let child = command
            .arg("--socket")
            .arg(sock_dir.join("s.sock"))
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--file")
            .arg(file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("crash_test_server spawn: {e}"))?;
        let mut child = ChildGuard(child);
        let stdout = child.0.stdout.take().ok_or("stdout not piped")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(READY_WAIT)
            .map_err(|_| "READY line did not arrive".to_string())?;
        require(line.trim_end() == "READY", "server printed READY")?;

        let stream = UnixStream::connect(sock_dir.join("s.sock")).map_err(|e| e.to_string())?;
        let limit = InFlightLimit::new(usize::try_from(WRITES).unwrap_or(0) + 2)
            .map_err(|e| e.to_string())?;
        let mut client = PipelineClient::new(UnixClientEnd::new(stream), limit, NoopSendObserver);
        for seq in 0..WRITES {
            client
                .send(FrameKind::Write, &seq.to_le_bytes(), io_timeout(5))
                .map_err(|e| e.to_string())?;
        }
        if flush {
            client
                .send(FrameKind::Flush, &[], io_timeout(5))
                .map_err(|e| e.to_string())?;
        }
        for _ in 0..WRITES {
            client.recv_ack(io_timeout(5)).map_err(|e| e.to_string())?;
        }
        if flush {
            match client.recv_ack(io_timeout(10)) {
                Ok(AckReceipt::Flush(_)) => {}
                Ok(_) => return Err("unexpected ack kind for FLUSH".to_string()),
                Err(e) => return Err(format!("FLUSH ACK not observed: {e}")),
            }
        }

        // FLUSH ACK の直後から以降の書き込みを捨てる（カーネルクラッシュ相当）
        rig.switch(FlakeyMode::DropWrites)?;
        let _ = child.0.kill();
        if !reap_bounded(&mut child.0) {
            return Err(format!(
                "server pid {} was not reaped in time",
                child.0.id()
            ));
        }
        drop(client);
        rig.umount()?;
        rig.switch(FlakeyMode::Up)?;
        rig.mount()?;

        let path = data_dir.join(file);
        let cap = WRITES * RECORD_LEN as u64 + 4096;
        let bytes = match std::fs::File::open(&path) {
            // ファイル自体が残っていなければ全件欠落。それ以外の失敗（EIO・権限等）は測定不能として Err
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("cannot open {}: {e}", path.display())),
            Ok(f) => {
                let mut b = Vec::new();
                f.take(cap)
                    .read_to_end(&mut b)
                    .map_err(|e| format!("read failed: {e}"))?;
                b
            }
        };
        let check = check_disk_records(&bytes, WRITES);
        Ok(Outcome {
            lost: check.lost(),
            exact: check.is_exact(),
        })
    }

    /// IO-2: FLUSH ACK 済みのデータが、以降の書き込みを捨てた媒体の再 mount 後に欠落・重複なく残る。
    /// 未フラッシュ対照は損失件数を報告するだけで合否にしない（期待値はオーナー判断待ち）。
    #[test]
    #[ignore = "requires root, dm_flakey, losetup, dmsetup, mkfs.ext4 (IO-2, #1965); run by a human"]
    fn io2_flushed_data_survives_dm_flakey_drop_writes() {
        let mut rig = match Rig::new() {
            Ok(r) => r,
            Err(e) => panic!("power_loss setup failed (fail-closed): {e}"),
        };
        let mut flushed_lost = 0;
        for i in 0..TRIALS {
            let o =
                run_trial(&mut rig, i, true).unwrap_or_else(|e| panic!("flushed trial {i}: {e}"));
            flushed_lost += o.lost;
            assert!(
                o.exact,
                "flushed trial {i}: records must be exactly 0..{WRITES}"
            );
        }
        let mut unflushed_lost = 0;
        for i in 0..TRIALS {
            match run_trial(&mut rig, TRIALS + i, false) {
                Ok(o) => unflushed_lost += o.lost,
                Err(e) => panic!("unflushed trial {i}: {e}"),
            }
        }
        println!(
            "power_loss_summary {{\"flushed_trials\":{TRIALS},\"flushed_lost\":{flushed_lost},\"unflushed_trials\":{TRIALS},\"unflushed_lost\":{unflushed_lost}}}"
        );
        // 後始末の失敗は試験の失敗にする（残存情報は Err に含まれる）
        if let Err(e) = rig.cleanup() {
            panic!("power_loss cleanup failed: {e}");
        }
        assert_eq!(flushed_lost, 0);
        println!("io2_flushed_data_survives_dm_flakey_drop_writes: ok");
    }

    #[test]
    fn flakey_table_matches_xfstests_form() {
        assert_eq!(
            flakey_table(131072, "/dev/loop3", FlakeyMode::Up),
            "0 131072 flakey /dev/loop3 0 180 0"
        );
        assert_eq!(
            flakey_table(131072, "/dev/loop3", FlakeyMode::DropWrites),
            "0 131072 flakey /dev/loop3 0 0 180 1 drop_writes"
        );
    }

    #[test]
    fn dm_name_and_loop_path_validation() {
        assert!(is_valid_dm_name("fcio-pl-123"));
        assert!(!is_valid_dm_name(""));
        assert!(!is_valid_dm_name("a b"));
        assert!(!is_valid_dm_name("a/b"));
        assert_eq!(loop_index("/dev/loop7"), Some(7));
        assert_eq!(loop_index("/dev/loop"), None);
        assert_eq!(loop_index("/dev/sda"), None);
        assert_eq!(loop_index("/dev/loop1p1"), None);
    }

    #[test]
    fn mountinfo_entry_finds_fstype_and_source() {
        let text = "36 35 98:0 / /mnt/a rw - ext4 /dev/mapper/x rw\n\
                    40 35 0:30 / /mnt/b rw,nosuid shared:1 - tmpfs tmpfs rw\n";
        assert_eq!(
            mountinfo_entry(text, "/mnt/a"),
            Some(("ext4".to_string(), "/dev/mapper/x".to_string()))
        );
        assert_eq!(
            mountinfo_entry(text, "/mnt/b"),
            Some(("tmpfs".to_string(), "tmpfs".to_string()))
        );
        assert_eq!(mountinfo_entry(text, "/mnt/c"), None);
    }

    #[test]
    fn effective_uid_reads_third_field() {
        assert_eq!(
            effective_uid("Name:\tx\nUid:\t1000\t0\t1000\t1000\n"),
            Some(0)
        );
        assert_eq!(effective_uid("Name:\tx\n"), None);
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn power_loss_is_linux_only() {
    // dm-flakey は Linux 固有。macOS・Windows の永続化は未検証（docs/design/io-power-loss-verification.md）。
}
