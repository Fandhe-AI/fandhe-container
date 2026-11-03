//! CUDA ワークロード統合テスト（実機前提。GPU-2・TASK-127.6・#552・MS-10）。
//!
//! # 検証内容
//! CDI の `deviceNodes`・`mounts`・`createContainer` フック・`env` を新しい PID / mount / UTS / IPC namespace
//! の rootfs へ当てて起動したコンテナ相当の環境で、CUDA の行列積が 5 回中 5 回成功し、CPU 参照値との最大相対誤差が
//! 1e-3 以下であること、および同じ実行の中で 4 種の namespace が分離されていること（独自の hostname・PID 1 が
//! 自プロセス・独自の mountinfo）を照合する（PoC-14 の dev-box02 実測: 5/5 成功・最大相対誤差 3.556650e-07）。
//!
//! # 未実装の宣言（REPAIR-3）
//! core の pre-pivot 段への CDI 適用の配線は #2774 で未実装のため、本試験は製品の create / start 経路を通らない。
//! 試験コードが `unshare(1)`・`mount(8)`・`pivot_root(8)` で core の `prepare_rootfs` 相当の順序を自分で組み立て、
//! gpu crate の公開 API（`cdi_apply::*`）だけを検証する。core の配線を検証するものではない。#2774 の完了後は、
//! core の経路で駆動する形へ移す。`unsafe` と依存を足さないため、特権操作は外部コマンドで行う。
//!
//! # 実行構造
//! 外側（root のテストプロセス）が試行ごとに作業ディレクトリと rootfs の複製を作り、自分自身を
//! `unshare --pid --fork --mount --uts --ipc` の下で再実行する（内側。環境変数 `FANDHE_GPU_CUDA_INNER=1`）。
//! 内側は新しい PID namespace の PID 1 として CDI を当て、`pivot_root` 後にワークロードを起動し、
//! namespace の証跡を `FC_GPU_INNER <key>=<value>` の行で標準出力へ出す。外側は証跡と出力行列を判定する。
//! ワークロードの自己申告は信用せず、出力行列を試験側で CPU 参照値と照合する。
//!
//! # 実機前提
//! root・NVIDIA GPU・CDI spec・rootfs 雛形・ビルド済みワークロードが要るため既定の集合から分離する
//! （必要環境・実行手順・環境変数は `AGENTS.md`「実機前提テスト」）。前提が欠けたときは skip せず panic する。
//! 純関数（参照値・誤差・判定・解析）の単体試験は既定の集合で回る。
#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_gpu::cdi_apply::env::apply_cdi_env;
use fandhe_container_gpu::cdi_apply::hooks::{
    CdiHookState, run_create_container_hooks, validate_create_container_hooks, verify_hook_stage,
};
use fandhe_container_gpu::cdi_apply::mounts::{CdiBindPropagation, cdi_bind_mounts};
use fandhe_container_gpu::cdi_apply::{create_device_nodes, resolve_device_nodes};
use fandhe_container_gpu::cdi_edits::{AggregatedEdits, aggregate_container_edits};
use fandhe_container_gpu::cdi_paths::{
    PathLayouts, detect_usr_merge_layout, normalize_cdi_spec_paths,
};
use fandhe_container_gpu::cdi_spec::{DeviceNode, read_cdi_spec_file};

const TEST_NAME: &str = "gpu2_cuda_workload_five_trials_with_namespace_isolation";
const TRIALS: u32 = 5;
const MAX_REL_ERR: f64 = 1e-3;
const SAMPLE_ROWS: usize = 64;
const DEFAULT_N: usize = 1024;
const MAX_N: usize = 8192;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const MAX_TIMEOUT_SECS: u64 = 1800;
const CMD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PROC_PIDS: usize = 16;
const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_DEVICES: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

const ENV_SPEC: &str = "FANDHE_CONTAINER_GPU_TEST_CDI_SPEC";
const ENV_DEVICES: &str = "FANDHE_CONTAINER_GPU_TEST_CDI_DEVICES";
const ENV_ROOTFS: &str = "FANDHE_CONTAINER_GPU_TEST_ROOTFS";
const ENV_WORKLOAD: &str = "FANDHE_CONTAINER_GPU_TEST_WORKLOAD";
const ENV_N: &str = "FANDHE_CONTAINER_GPU_TEST_MATRIX_N";
const ENV_TIMEOUT: &str = "FANDHE_CONTAINER_GPU_TEST_TIMEOUT_SECS";
const ENV_WORK_ROOT: &str = "FANDHE_CONTAINER_GPU_TEST_WORK_ROOT";
const ENV_INNER: &str = "FANDHE_GPU_CUDA_INNER";

// ---------------------------------------------------------------- 純関数（既定の集合で試験する）

/// 決定的な入力生成（xorshift32）。値は [0.5, 1.0)。参照値が 0 に近づかないようにする。
fn gen_matrix(seed: u32, count: usize) -> Vec<f32> {
    let mut x = seed.max(1);
    (0..count)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            // 23 ビットなら 0.5 + k / 2^24 が f32 で丸めなしに表せ、1.0 に届かない。
            0.5 + (x >> 9) as f32 / (1u32 << 24) as f32
        })
        .collect()
}

fn f32s_to_le(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

/// 長さが `n * n * 4` ちょうどでなければ拒否する（無制限確保の防止も兼ね、呼び出し側が上限を先に検査する）。
fn le_to_f32s(bytes: &[u8], n: usize) -> Result<Vec<f32>, String> {
    let want = n
        .checked_mul(n)
        .and_then(|c| c.checked_mul(4))
        .ok_or("matrix size overflow")?;
    if bytes.len() != want {
        return Err(format!("output size {} != expected {want}", bytes.len()));
    }
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(f32::from_le_bytes)
        .collect())
}

/// 検査する行の添字（最大 `SAMPLE_ROWS` 行を等間隔に抜き出す）。
fn sample_rows(n: usize) -> Vec<usize> {
    let step = (n / SAMPLE_ROWS).max(1);
    (0..n).step_by(step).take(SAMPLE_ROWS).collect()
}

/// 抜き出した行の CPU 参照値（f64 累算）。`(行, 列, 値)` ではなく行ごとの配列で返す。
fn cpu_reference_rows(a: &[f32], b: &[f32], n: usize, rows: &[usize]) -> Vec<Vec<f64>> {
    rows.iter()
        .map(|&i| {
            (0..n)
                .map(|j| {
                    (0..n)
                        .map(|k| {
                            let av = a.get(i * n + k).copied().unwrap_or(f32::NAN);
                            let bv = b.get(k * n + j).copied().unwrap_or(f32::NAN);
                            f64::from(av) * f64::from(bv)
                        })
                        .sum()
                })
                .collect()
        })
        .collect()
}

/// `(最大相対誤差, 非有限値の件数)`。参照値が 0 のときは絶対誤差を使う。
fn max_rel_err(c: &[f32], reference: &[Vec<f64>], rows: &[usize], n: usize) -> (f64, usize) {
    let mut max = 0.0f64;
    let mut nonfinite = 0usize;
    for (row, &i) in reference.iter().zip(rows) {
        for (j, &r) in row.iter().enumerate() {
            let g = f64::from(c.get(i * n + j).copied().unwrap_or(f32::NAN));
            if !g.is_finite() {
                nonfinite += 1;
                continue;
            }
            let err = if r == 0.0 {
                g.abs()
            } else {
                ((g - r) / r).abs()
            };
            max = max.max(err);
        }
    }
    (max, nonfinite)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    id: u64,
    mountpoint: String,
    options: Vec<String>,
}

/// mountinfo の `\040` 等の 8 進エスケープを戻す。
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b
            .get(i + 1..i + 4)
            .filter(|d| b.get(i) == Some(&b'\\') && d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok());
        match oct {
            Some(v) => {
                out.push(v);
                i += 4;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let id = f.next()?.parse().ok()?;
            let mountpoint = unescape_mountinfo(f.nth(3)?);
            let options = f.next()?.split(',').map(String::from).collect();
            Some(MountEntry {
                id,
                mountpoint,
                options,
            })
        })
        .collect()
}

fn read_mountinfo() -> Vec<MountEntry> {
    use std::io::Read as _;
    let mut text = String::new();
    fs::File::open("/proc/self/mountinfo")
        .and_then(|f| f.take(MAX_MOUNTINFO_BYTES).read_to_string(&mut text))
        .expect("read /proc/self/mountinfo");
    parse_mountinfo(&text)
}

/// 内側が出す証跡。
#[derive(Debug, Clone, PartialEq, Eq)]
struct InnerReport {
    ns: [String; 4],
    hostname: String,
    self_pid: u32,
    mount_ids: BTreeSet<u64>,
    hooks: String,
    device_nodes: usize,
    binds: usize,
    cuda_device: String,
}

const REPORT_PREFIX: &str = "FC_GPU_INNER ";

/// 必須の行が 1 つでも欠ける、または `done` が無い出力は拒否する（0 件実行 exit 0 の false-green 防止）。
fn parse_inner_report(out: &str) -> Result<InnerReport, String> {
    let kv: BTreeMap<&str, &str> = out
        .lines()
        .filter_map(|l| l.strip_prefix(REPORT_PREFIX))
        .filter_map(|l| l.split_once('='))
        .collect();
    let get = |k: &str| {
        kv.get(k)
            .copied()
            .ok_or_else(|| format!("missing report key {k}"))
    };
    if get("done")? != "1" {
        return Err("report not complete".into());
    }
    let num = |k: &str| -> Result<usize, String> {
        get(k)?.parse().map_err(|_| format!("bad number for {k}"))
    };
    let mount_ids = get("mount_ids")?
        .split(',')
        .map(|s| s.parse::<u64>().map_err(|_| "bad mount id".to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(InnerReport {
        ns: [
            get("ns_pid")?.into(),
            get("ns_mnt")?.into(),
            get("ns_uts")?.into(),
            get("ns_ipc")?.into(),
        ],
        hostname: get("hostname")?.into(),
        self_pid: get("self_pid")?.parse().map_err(|_| "bad self_pid")?,
        mount_ids,
        hooks: get("hooks")?.into(),
        device_nodes: num("device_nodes")?,
        binds: num("binds")?,
        cuda_device: get("cuda_device")?.into(),
    })
}

/// ホスト側の識別子。
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostIdent {
    ns: [String; 4],
    hostname: String,
    mount_ids: BTreeSet<u64>,
}

/// 4 種の namespace の分離（GPU-2）。1 つでも満たさなければ理由を返す。
fn check_isolation(host: &HostIdent, rep: &InnerReport, want_hostname: &str) -> Result<(), String> {
    for (i, name) in ["pid", "mnt", "uts", "ipc"].iter().enumerate() {
        if rep.ns.get(i) == host.ns.get(i) {
            return Err(format!("{name} namespace is shared with the host"));
        }
    }
    if rep.hostname != want_hostname || rep.hostname == host.hostname {
        return Err("hostname is not the container's own".into());
    }
    if rep.self_pid != 1 {
        return Err(format!("pid is {} (expected 1)", rep.self_pid));
    }
    if rep.mount_ids.is_empty() || !rep.mount_ids.is_disjoint(&host.mount_ids) {
        return Err("mountinfo is shared with the host".into());
    }
    Ok(())
}

// ---------------------------------------------------------------- 外部コマンド・環境

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p).map(|d| d.join(name)).find(|c| {
            fs::metadata(c)
                .map(|m| m.is_file() && m.mode() & 0o111 != 0)
                .unwrap_or(false)
        })
    })
}

/// 強制終了後の子の回収猶予（REPAIR-5）。割り込み不能な待ちの子で試験が止まらないよう有限にする。
const REAP_GRACE: Duration = Duration::from_secs(5);

/// 子を SIGKILL し、`REAP_GRACE` 内に `try_wait` で回収する。回収できなければ PID と残した作業領域を
/// 報告して即終了する（子が生きている可能性があるため作業領域は消さない。REPAIR-5・SEC-1）。
fn kill_and_reap(child: &mut std::process::Child, what: &str, leftover: Option<&Path>) {
    let _ = child.kill();
    let end = Instant::now() + REAP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                eprintln!(
                    "FATAL: {what} (pid {}) not reaped within {REAP_GRACE:?} after SIGKILL; leftover work dir: {}",
                    child.id(),
                    leftover.map_or("(none)".to_string(), |p| p.display().to_string())
                );
                std::process::exit(1);
            }
        }
    }
}

/// 期限つきで外部コマンドを実行する（REPAIR-5）。シェルを経由しない。
fn run_cmd(program: &str, args: &[&str], timeout: Duration) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn {program}: {e}"))?;
    let end = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(st)) => return Err(format!("{program} {args:?} exited with {st}")),
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                kill_and_reap(&mut child, program, None);
                return Err(format!("{program} timed out"));
            }
            Err(e) => return Err(format!("wait {program}: {e}")),
        }
    }
}

/// 新規作成のみで書く（`O_CREAT|O_EXCL` は既存要素・symlink に対して失敗し、辿らない。SEC-1）。
fn write_new(path: &Path, data: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|e| panic!("create_new {}: {e}", path.display()));
    f.write_all(data).expect("write input");
}

fn mount(args: &[&str]) {
    run_cmd("mount", args, CMD_TIMEOUT).unwrap_or_else(|e| panic!("mount {args:?}: {e}"));
}

fn path_env(name: &str) -> PathBuf {
    let v = std::env::var(name).unwrap_or_else(|_| panic!("PRECONDITION: {name} is not set"));
    let p = PathBuf::from(&v);
    let clean = p.is_absolute()
        && !v.contains('\0')
        && !p
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    assert!(clean, "{name} must be an absolute path without '..'");
    p
}

fn num_env(name: &str, default: u64, min: u64, max: u64) -> u64 {
    match std::env::var(name) {
        Err(_) => default,
        Ok(v) => {
            let n: u64 = v
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a number"));
            assert!(
                (min..=max).contains(&n),
                "{name} out of range {min}..={max}"
            );
            n
        }
    }
}

fn is_root() -> bool {
    fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

fn read_link_str(p: &str) -> String {
    fs::read_link(p)
        .unwrap_or_else(|e| panic!("read_link {p}: {e}"))
        .to_string_lossy()
        .into_owned()
}

fn ns_idents() -> [String; 4] {
    ["pid", "mnt", "uts", "ipc"].map(|n| read_link_str(&format!("/proc/self/ns/{n}")))
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read hostname")
        .trim_end()
        .to_string()
}

struct Spec {
    agg: AggregatedEdits,
}

/// CDI spec を読み、usr-merge を正規化して集計する。外側（早期失敗）と内側の両方が呼ぶ。
fn load_edits(spec_path: &Path, devices: &str, rootfs: &Path) -> Spec {
    let mut spec = read_cdi_spec_file(spec_path)
        .unwrap_or_else(|e| panic!("PRECONDITION: failed to read CDI spec: {e}"));
    let layouts = PathLayouts::new(
        detect_usr_merge_layout(Path::new("/")).expect("host layout"),
        detect_usr_merge_layout(rootfs).expect("rootfs layout"),
    );
    normalize_cdi_spec_paths(&mut spec, &layouts);
    let names: Vec<&str> = devices.split(',').filter(|s| !s.is_empty()).collect();
    assert!(!names.is_empty(), "{ENV_DEVICES} is empty");
    let agg = aggregate_container_edits(&spec, &names)
        .unwrap_or_else(|e| panic!("failed to aggregate CDI edits: {e}"));
    Spec { agg }
}

// ---------------------------------------------------------------- 外側

#[test]
#[ignore = "requires root, NVIDIA GPU, CDI spec, rootfs template and CUDA workload. GPU-2"]
fn gpu2_cuda_workload_five_trials_with_namespace_isolation() {
    if std::env::var(ENV_INNER).as_deref() == Ok("1") {
        inner_main();
        return;
    }
    assert!(
        is_root(),
        "this test must run as root (--ignored under sudo)"
    );
    let spec_path = path_env(ENV_SPEC);
    let rootfs_tpl = path_env(ENV_ROOTFS);
    let workload = path_env(ENV_WORKLOAD);
    let devices = std::env::var(ENV_DEVICES)
        .unwrap_or_else(|_| panic!("PRECONDITION: {ENV_DEVICES} is not set"));
    let n =
        usize::try_from(num_env(ENV_N, DEFAULT_N as u64, 64, MAX_N as u64)).unwrap_or(DEFAULT_N);
    assert!(n % 64 == 0, "{ENV_N} must be a multiple of 64");
    let timeout = num_env(ENV_TIMEOUT, DEFAULT_TIMEOUT_SECS, 1, MAX_TIMEOUT_SECS);
    let work_root = std::env::var_os(ENV_WORK_ROOT)
        .map(|_| path_env(ENV_WORK_ROOT))
        .unwrap_or_else(std::env::temp_dir);
    for tool in ["unshare", "mount", "pivot_root", "cp"] {
        assert!(
            which(tool).is_some(),
            "PRECONDITION: {tool} not found in PATH"
        );
    }
    let in_rootfs = |p: &Path| rootfs_tpl.join(p.strip_prefix("/").unwrap_or(p));
    assert!(
        fs::metadata(in_rootfs(&workload)).is_ok(),
        "PRECONDITION: workload is missing in the rootfs template"
    );
    assert!(
        ["usr/bin/umount", "bin/umount"]
            .iter()
            .any(|p| fs::metadata(rootfs_tpl.join(p)).is_ok()),
        "PRECONDITION: umount is missing in the rootfs template"
    );
    let probe = load_edits(&spec_path, &devices, &rootfs_tpl);
    assert!(
        !probe.agg.device_nodes().is_empty()
            && !probe.agg.mounts().is_empty()
            && !probe.agg.hooks().is_empty(),
        "PRECONDITION: the CDI spec must provide deviceNodes, mounts and hooks"
    );
    drop(probe);

    let exe = std::env::current_exe().expect("current_exe");
    let host = HostIdent {
        ns: ns_idents(),
        hostname: hostname(),
        mount_ids: read_mountinfo().iter().map(|m| m.id).collect(),
    };
    let rows = sample_rows(n);
    let mut worst = 0.0f64;
    let mut device_name = String::new();
    for trial in 1..=TRIALS {
        let work = work_root.join(format!("fc-gpu-cuda-{}-{trial}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .expect("create work dir");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_trial(
                trial,
                &work,
                &TrialCfg {
                    exe: &exe,
                    rootfs_tpl: &rootfs_tpl,
                    workload: &workload,
                    spec_path: &spec_path,
                    devices: &devices,
                    n,
                    timeout,
                    host: &host,
                    rows: &rows,
                },
            )
        }));
        // 後始末: 作業ディレクトリ配下にマウントが残っていれば、bind 先を辿ってホストを消さないよう削除しない。
        let leaked: Vec<String> = read_mountinfo()
            .into_iter()
            .filter(|m| Path::new(&m.mountpoint).starts_with(&work))
            .map(|m| m.mountpoint)
            .collect();
        assert!(
            leaked.is_empty(),
            "mounts leaked under work dir (not removed): {leaked:?}"
        );
        fs::remove_dir_all(&work).expect("remove work dir");
        match result {
            Ok((err, dev)) => {
                worst = worst.max(err);
                device_name = dev;
            }
            Err(p) => std::panic::resume_unwind(p),
        }
    }
    println!(
        "gpu2_cuda_workload: {TRIALS}/{TRIALS} trials passed (max_rel_err={worst:e} <= 1e-3, cuda_device={device_name}, pid/mnt/uts/ipc namespaces isolated)"
    );
}

/// 1 試行の共通設定（引数の数を抑えるためにまとめる）。
struct TrialCfg<'a> {
    exe: &'a Path,
    rootfs_tpl: &'a Path,
    workload: &'a Path,
    spec_path: &'a Path,
    devices: &'a str,
    n: usize,
    timeout: u64,
    host: &'a HostIdent,
    rows: &'a [usize],
}

fn run_trial(trial: u32, work: &Path, cfg: &TrialCfg<'_>) -> (f64, String) {
    let TrialCfg {
        exe,
        rootfs_tpl,
        workload,
        spec_path,
        devices,
        n,
        timeout,
        host,
        rows,
    } = *cfg;
    let rootfs = work.join("rootfs");
    run_cmd(
        "cp",
        &[
            "-a",
            &rootfs_tpl.to_string_lossy(),
            &rootfs.to_string_lossy(),
        ],
        Duration::from_secs(timeout),
    )
    .expect("copy rootfs template");
    let hooks_work = work.join("hooks-work");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&hooks_work)
        .expect("create hooks-work");
    // 雛形由来の symlink を拒否する（`cp -a` は symlink を保存する。root で開く前に検証。SEC-1）。
    assert!(
        fs::symlink_metadata(&rootfs).is_ok_and(|m| m.file_type().is_dir()),
        "rootfs copy must be a real directory"
    );
    let io_dir = rootfs.join("fc-cuda-io");
    assert!(
        fs::symlink_metadata(&io_dir).is_err(),
        "rootfs template must not contain fc-cuda-io (symlink or otherwise)"
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&io_dir)
        .expect("create io dir");
    let a = gen_matrix(0x9e37_79b9 ^ trial, n * n);
    let b = gen_matrix(0x85eb_ca6b ^ trial.wrapping_mul(7919), n * n);
    write_new(&io_dir.join("a.f32"), &f32s_to_le(&a));
    write_new(&io_dir.join("b.f32"), &f32s_to_le(&b));

    let out_path = work.join("inner.out");
    let err_path = work.join("inner.err");
    let want_hostname = format!("fc-gpu-cuda-{trial}");
    let mut child = Command::new("unshare")
        .args([
            "--pid",
            "--fork",
            "--mount",
            "--uts",
            "--ipc",
            "--propagation",
            "private",
            "--kill-child",
            "--",
        ])
        .arg(exe)
        .args([
            "--exact",
            TEST_NAME,
            "--ignored",
            "--no-capture",
            "--test-threads=1",
        ])
        .env(ENV_INNER, "1")
        .env(ENV_SPEC, spec_path)
        .env(ENV_DEVICES, devices)
        .env(ENV_WORKLOAD, workload)
        .env(ENV_N, n.to_string())
        .env(ENV_TIMEOUT, timeout.to_string())
        .env("FC_ROOTFS", &rootfs)
        .env("FC_HOOKS_WORK", &hooks_work)
        .env("FC_HOSTNAME", &want_hostname)
        .env("FC_HOST_NS", host.ns.join("\n"))
        .stdin(Stdio::null())
        .stdout(fs::File::create(&out_path).expect("create inner.out"))
        .stderr(fs::File::create(&err_path).expect("create inner.err"))
        .spawn()
        .expect("spawn unshare");
    let end = Instant::now() + Duration::from_secs(timeout);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
            None => {
                kill_and_reap(&mut child, "unshare inner", Some(work));
                panic!("trial {trial}: inner timed out after {timeout}s");
            }
        }
    };
    let out = fs::read_to_string(&out_path).unwrap_or_default();
    let tail = |s: &str| {
        s.chars()
            .rev()
            .take(4096)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    };
    assert!(
        status.success(),
        "trial {trial}: inner failed ({status})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        tail(&out),
        tail(&fs::read_to_string(&err_path).unwrap_or_default())
    );
    let rep =
        parse_inner_report(&out).unwrap_or_else(|e| panic!("trial {trial}: {e}\n{}", tail(&out)));
    check_isolation(host, &rep, &want_hostname).unwrap_or_else(|e| panic!("trial {trial}: {e}"));

    let c_path = io_dir.join("c.f32");
    let want = (n * n * 4) as u64;
    let len = fs::metadata(&c_path).expect("c.f32 missing").len();
    assert_eq!(len, want, "trial {trial}: output size");
    let c = le_to_f32s(&fs::read(&c_path).expect("read c"), n).expect("decode c");
    let reference = cpu_reference_rows(&a, &b, n, rows);
    let (err, nonfinite) = max_rel_err(&c, &reference, rows, n);
    assert_eq!(nonfinite, 0, "trial {trial}: non-finite outputs");
    assert!(
        err <= MAX_REL_ERR,
        "trial {trial}: max relative error {err:e} > 1e-3"
    );
    println!(
        "trial {trial}: ok max_rel_err={err:e} cuda_device={} hooks={} device_nodes={} binds={}",
        rep.cuda_device, rep.hooks, rep.device_nodes, rep.binds
    );
    (err, rep.cuda_device)
}

// ---------------------------------------------------------------- 内側（新しい PID namespace の PID 1）

fn emit(key: &str, value: impl std::fmt::Display) {
    println!("{REPORT_PREFIX}{key}={value}");
}

/// 宛先を 1 要素ずつ `symlink_metadata` で辿り、symlink は拒否（fail-closed）、欠けた要素は作る。
fn prepare_bind_target(rootfs: &Path, dest: &str, source_is_dir: bool) -> PathBuf {
    let rel = Path::new(dest)
        .strip_prefix("/")
        .expect("destination must be absolute");
    let comps: Vec<_> = rel.components().collect();
    let mut cur = rootfs.to_path_buf();
    for (idx, c) in comps.iter().enumerate() {
        cur.push(c);
        let last = idx + 1 == comps.len();
        match fs::symlink_metadata(&cur) {
            Ok(m) => {
                assert!(
                    !m.file_type().is_symlink(),
                    "bind destination crosses a symlink"
                );
                if last {
                    assert_eq!(m.is_dir(), source_is_dir, "bind destination type mismatch");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if last && !source_is_dir {
                    fs::File::create(&cur).expect("create bind target file");
                } else {
                    fs::create_dir(&cur).expect("create bind target dir");
                }
            }
            Err(e) => panic!("stat bind destination: {e}"),
        }
    }
    cur
}

fn inner_main() {
    let rootfs = path_env("FC_ROOTFS");
    let hooks_work = path_env("FC_HOOKS_WORK");
    let spec_path = path_env(ENV_SPEC);
    let workload = path_env(ENV_WORKLOAD);
    let devices = std::env::var(ENV_DEVICES).expect("devices");
    let want_hostname = std::env::var("FC_HOSTNAME").expect("hostname");
    let n = num_env(ENV_N, DEFAULT_N as u64, 64, MAX_N as u64);
    let timeout = Duration::from_secs(num_env(
        ENV_TIMEOUT,
        DEFAULT_TIMEOUT_SECS,
        1,
        MAX_TIMEOUT_SECS,
    ));
    let host_ns: Vec<String> = std::env::var("FC_HOST_NS")
        .expect("host ns")
        .lines()
        .map(String::from)
        .collect();

    // ガード: 分離を確かめるまで、ホスト名の書き込みもマウントもしない。
    assert_eq!(
        std::process::id(),
        1,
        "inner must be PID 1 of a new PID namespace"
    );
    let ns = ns_idents();
    assert!(
        ns.iter().zip(&host_ns).all(|(a, b)| a != b) && host_ns.len() == 4,
        "inner shares a namespace with the host"
    );
    // `/proc` はまだホストの procfs のため、ホストから見た pid が読める（フックの OCI state 用。PoC-14）。
    let host_pid: i32 = read_link_str("/proc/self").parse().expect("host pid");

    fs::write("/proc/sys/kernel/hostname", &want_hostname).expect("set hostname");
    assert_eq!(hostname(), want_hostname, "hostname not applied");

    let r = rootfs.to_string_lossy().into_owned();
    mount(&["--make-rprivate", "/"]);
    mount(&["--bind", &r, &r]);
    mount(&["-o", "remount,bind,nosuid,nodev", &r]);

    // /dev: tmpfs に既定のノードと CDI の deviceNodes を作る（ホストの /dev を読むので pivot の前）。
    let dev = rootfs.join("dev");
    let dev_s = dev.to_string_lossy().into_owned();
    mount(&[
        "-t",
        "tmpfs",
        "-o",
        "nosuid,noexec,mode=0755",
        "tmpfs",
        &dev_s,
    ]);
    let sp = load_edits(&spec_path, &devices, &rootfs);
    let agg = &sp.agg;
    let mut nodes: Vec<DeviceNode> = DEFAULT_DEVICES
        .iter()
        .map(|p| DeviceNode {
            path: (*p).to_owned(),
            host_path: None,
            r#type: None,
            major: None,
            minor: None,
            file_mode: None,
            permissions: None,
            uid: None,
            gid: None,
        })
        .collect();
    nodes.extend(agg.device_nodes().iter().cloned());
    let resolved =
        resolve_device_nodes(&nodes).unwrap_or_else(|e| panic!("resolve deviceNodes: {e}"));
    let dev_fd = fs::File::open(&dev).expect("open /dev root");
    let report = create_device_nodes(dev_fd.as_fd(), &resolved)
        .unwrap_or_else(|e| panic!("create deviceNodes: {e}"));
    assert_eq!(report.outcomes.len(), resolved.len(), "device node count");
    for (o, rn) in report.outcomes.iter().zip(&resolved) {
        assert_eq!(
            (o.observed_major, o.observed_minor),
            (u64::from(rn.major()), u64::from(rn.minor())),
            "device node major/minor"
        );
    }
    drop(dev_fd);
    let shm = dev.join("shm");
    fs::create_dir(&shm).expect("create /dev/shm");
    mount(&[
        "-t",
        "tmpfs",
        "-o",
        "nosuid,nodev,noexec",
        "tmpfs",
        &shm.to_string_lossy(),
    ]);

    // CDI mounts: bind して、指定したオプションが実マウントに出ていることを mountinfo で照合する。
    let binds = cdi_bind_mounts(agg).unwrap_or_else(|e| panic!("cdi_bind_mounts: {e}"));
    for bm in &binds {
        let src = Path::new(bm.source());
        let is_dir = fs::metadata(src).expect("stat bind source").is_dir();
        let target = prepare_bind_target(&rootfs, bm.destination(), is_dir);
        let t = target.to_string_lossy().into_owned();
        mount(&[
            if bm.recursive() { "--rbind" } else { "--bind" },
            bm.source(),
            &t,
        ]);
        let mut opts = vec!["remount", "bind"];
        if bm.read_only() {
            opts.push("ro");
        }
        if bm.nosuid() {
            opts.push("nosuid");
        }
        if bm.nodev() {
            opts.push("nodev");
        }
        if bm.noexec() {
            opts.push("noexec");
        }
        mount(&["-o", &opts.join(","), &t]);
        if bm.propagation() == CdiBindPropagation::HostSlave {
            mount(&["--make-rslave", &t]);
        }
        let entry = read_mountinfo()
            .into_iter()
            .rev()
            .find(|m| m.mountpoint == t)
            .expect("bind not in mountinfo");
        for (want, flag) in [
            (bm.read_only(), "ro"),
            (bm.nosuid(), "nosuid"),
            (bm.nodev(), "nodev"),
            (bm.noexec(), "noexec"),
        ] {
            assert!(
                !want || entry.options.iter().any(|o| o == flag),
                "bind option {flag} not applied"
            );
        }
    }

    // /proc は hooks の前（check_hook_stage_mountinfo が proc と自己 bind を要求する）。
    mount(&[
        "-t",
        "proc",
        "-o",
        "nosuid,nodev,noexec",
        "proc",
        &rootfs.join("proc").to_string_lossy(),
    ]);

    let hooks = validate_create_container_hooks(agg.hooks())
        .unwrap_or_else(|e| panic!("validate hooks: {e}"));
    let stage = verify_hook_stage(&rootfs).unwrap_or_else(|e| panic!("hook stage: {e}"));
    let state = CdiHookState::new(&want_hostname, host_pid).expect("hook state");
    let done =
        run_create_container_hooks(&stage, &hooks, &state, &hooks_work).unwrap_or_else(|e| {
            panic!(
                "hooks failed at index {}: {}\n{}",
                e.index, e.error, e.stderr
            )
        });
    assert_eq!(done.len(), hooks.len(), "hook count");

    let base = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "HOME=/root".to_string(),
        "CUDA_CACHE_DISABLE=1".to_string(),
    ];
    let cdi_env = apply_cdi_env(&base, agg)
        .unwrap_or_else(|e| panic!("apply env: {e}"))
        .into_env();

    // pivot_root: カーネルは root が旧 root の同じ mount namespace のプロセスの root と cwd を差し替えるため、
    // PID 1 である本プロセスも新 root へ移る（cwd を先に旧 root にしておく）。
    let old = rootfs.join(".fc-oldroot");
    fs::create_dir(&old).expect("create oldroot");
    std::env::set_current_dir("/").expect("chdir /");
    run_cmd("pivot_root", &[&r, &old.to_string_lossy()], CMD_TIMEOUT).expect("pivot_root");
    std::env::set_current_dir("/").expect("chdir / after pivot");
    let umount = ["/usr/bin/umount", "/bin/umount"]
        .into_iter()
        .find(|p| fs::metadata(p).is_ok())
        .expect("umount in rootfs");
    run_cmd(umount, &["-l", "/.fc-oldroot"], CMD_TIMEOUT).expect("umount oldroot");
    fs::remove_dir("/.fc-oldroot").expect("remove oldroot");

    // namespace の証跡（pivot 後、ワークロードと同じ実行の中で採る）。
    let ns = ns_idents();
    let mi = read_mountinfo();
    assert!(mi.iter().any(|m| m.mountpoint == "/"), "no / in mountinfo");
    assert!(
        !mi.iter().any(|m| m.mountpoint == "/.fc-oldroot"),
        "oldroot still mounted"
    );
    let pids: Vec<u32> = fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    assert!(
        pids.contains(&1) && pids.len() < MAX_PROC_PIDS,
        "unexpected pid list {pids:?}"
    );

    // ワークロード。標準出力・標準エラーは rootfs 内のファイルへ向け、cuda_device の行を拾う。
    let out_file = fs::File::create("/fc-cuda-io/stdout.txt").expect("create stdout.txt");
    let err_file = fs::File::create("/fc-cuda-io/stderr.txt").expect("create stderr.txt");
    let mut cmd = Command::new(&workload);
    cmd.args([
        n.to_string().as_str(),
        "/fc-cuda-io/a.f32",
        "/fc-cuda-io/b.f32",
        "/fc-cuda-io/c.f32",
    ])
    .env_clear()
    .stdin(Stdio::null())
    .stdout(out_file)
    .stderr(err_file);
    for kv in &cdi_env {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }
    let mut child = cmd.spawn().expect("spawn workload");
    let end = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().expect("try_wait workload") {
            Some(s) => break s,
            None if Instant::now() < end => std::thread::sleep(Duration::from_millis(50)),
            None => {
                kill_and_reap(&mut child, "workload", None);
                panic!("workload timed out");
            }
        }
    };
    let stderr_txt = fs::read_to_string("/fc-cuda-io/stderr.txt").unwrap_or_default();
    assert!(status.success(), "workload failed ({status}): {stderr_txt}");
    let stdout_txt = fs::read_to_string("/fc-cuda-io/stdout.txt").unwrap_or_default();
    let cuda_device = stdout_txt
        .lines()
        .find_map(|l| l.strip_prefix("cuda_device="))
        .filter(|d| !d.is_empty())
        .expect("workload did not report cuda_device")
        .to_string();

    for (k, v) in [
        ("ns_pid", &ns[0]),
        ("ns_mnt", &ns[1]),
        ("ns_uts", &ns[2]),
        ("ns_ipc", &ns[3]),
    ] {
        emit(k, v);
    }
    emit("hostname", hostname());
    emit("self_pid", std::process::id());
    emit(
        "mount_ids",
        mi.iter()
            .map(|m| m.id.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    emit("hooks", format!("{}/{}", done.len(), hooks.len()));
    emit("device_nodes", report.outcomes.len());
    emit("binds", binds.len());
    emit("cuda_device", cuda_device);
    emit("done", 1);
    let _ = std::io::stdout().flush();
}

// ---------------------------------------------------------------- 純関数の単体試験（既定の集合。GPU-2）

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(a: &[f32], b: &[f32], c: &[f32], n: usize) -> (f64, usize) {
        let rows = sample_rows(n);
        let r = cpu_reference_rows(a, b, n, &rows);
        max_rel_err(c, &r, &rows, n)
    }

    /// GPU-2: 参照値どおりなら誤差 0、2e-3 の相対ずれは 1e-3 を超え、NaN は非有限として数える。
    #[test]
    fn gpu2_rel_err_accepts_exact_and_rejects_perturbation() {
        let n = 2;
        let a = [1.0f32, 2.0, 3.0, 4.0];
        let b = [5.0f32, 6.0, 7.0, 8.0];
        let mut c = [19.0f32, 22.0, 43.0, 50.0];
        assert_eq!(rel(&a, &b, &c, n), (0.0, 0));
        c[1] = 22.0 * 1.002;
        let (err, nf) = rel(&a, &b, &c, n);
        assert!(err > MAX_REL_ERR && err < 2.1e-3 && nf == 0, "err={err}");
        c[1] = f32::NAN;
        assert_eq!(rel(&a, &b, &c, n).1, 1);
    }

    /// GPU-2: 既知の 2x2 の積の具体値。
    #[test]
    fn gpu2_cpu_reference_matches_known_2x2() {
        let r = cpu_reference_rows(&[1.0, 2.0, 3.0, 4.0], &[5.0, 6.0, 7.0, 8.0], 2, &[0, 1]);
        assert_eq!(r, vec![vec![19.0, 22.0], vec![43.0, 50.0]]);
        assert_eq!(sample_rows(1024).len(), 64);
        assert_eq!(sample_rows(1024)[1], 16);
    }

    /// GPU-2: 同じ seed で同じ列、値は [0.5, 1.0)。
    #[test]
    fn gpu2_input_generation_is_deterministic_and_bounded() {
        let a = gen_matrix(7, 100_000);
        assert_eq!(a, gen_matrix(7, 100_000));
        assert_ne!(a, gen_matrix(8, 100_000));
        assert!(a.iter().all(|v| (0.5..1.0).contains(v)));
    }

    /// GPU-2: 期待サイズと異なる出力は拒否し、一致すれば往復できる。
    #[test]
    fn gpu2_output_size_mismatch_is_rejected() {
        assert!(le_to_f32s(&[0u8; 15], 2).is_err());
        assert!(le_to_f32s(&[0u8; 17], 2).is_err());
        let v = [1.5f32, 2.5, 3.5, 4.5];
        assert_eq!(le_to_f32s(&f32s_to_le(&v), 2).unwrap(), v);
    }

    /// GPU-2: mountinfo から ID・マウントポイント・オプションを取り、`\040` を戻す。
    #[test]
    fn gpu2_mountinfo_parse_ids_options_and_unescape() {
        let line = "36 35 98:0 / /mnt/a\\040b ro,nosuid,nodev shared:1 - ext3 /dev/x rw\n";
        let m = parse_mountinfo(line);
        assert_eq!(
            m,
            vec![MountEntry {
                id: 36,
                mountpoint: "/mnt/a b".into(),
                options: vec!["ro".into(), "nosuid".into(), "nodev".into()],
            }]
        );
    }

    fn sample_out() -> String {
        [
            "noise before",
            "FC_GPU_INNER ns_pid=pid:[1]",
            "FC_GPU_INNER ns_mnt=mnt:[2]",
            "FC_GPU_INNER ns_uts=uts:[3]",
            "FC_GPU_INNER ns_ipc=ipc:[4]",
            "FC_GPU_INNER hostname=fc-gpu-cuda-1",
            "FC_GPU_INNER self_pid=1",
            "FC_GPU_INNER mount_ids=100,101",
            "FC_GPU_INNER hooks=2/2",
            "FC_GPU_INNER device_nodes=8",
            "FC_GPU_INNER binds=5",
            "FC_GPU_INNER cuda_device=NVIDIA Test GPU",
            "FC_GPU_INNER done=1",
        ]
        .join("\n")
    }

    /// GPU-2: 必須の行が欠けると失敗し、done が無くても失敗する。
    #[test]
    fn gpu2_inner_report_parse_rejects_missing_fields() {
        let rep = parse_inner_report(&sample_out()).unwrap();
        assert_eq!(rep.cuda_device, "NVIDIA Test GPU");
        assert_eq!(rep.mount_ids, BTreeSet::from([100, 101]));
        assert!(parse_inner_report("").is_err());
        let no_done = sample_out().replace("FC_GPU_INNER done=1", "");
        assert!(parse_inner_report(&no_done).is_err());
        let no_host = sample_out().replace("FC_GPU_INNER hostname=fc-gpu-cuda-1\n", "");
        assert!(parse_inner_report(&no_host).is_err());
    }

    /// GPU-2: namespace・hostname・pid・mount ID のどれか 1 つでも分離されていなければ判定が失敗する。
    #[test]
    fn gpu2_isolation_check_rejects_shared_ns_or_mount_ids() {
        let rep = parse_inner_report(&sample_out()).unwrap();
        let host = HostIdent {
            ns: ["pid:[9]", "mnt:[9]", "uts:[9]", "ipc:[9]"].map(String::from),
            hostname: "host".into(),
            mount_ids: BTreeSet::from([1, 2]),
        };
        assert_eq!(check_isolation(&host, &rep, "fc-gpu-cuda-1"), Ok(()));
        for i in 0..4 {
            let mut h = host.clone();
            h.ns[i] = rep.ns[i].clone();
            assert!(
                check_isolation(&h, &rep, "fc-gpu-cuda-1").is_err(),
                "ns {i}"
            );
        }
        let mut h = host.clone();
        h.hostname = rep.hostname.clone();
        assert!(check_isolation(&h, &rep, "fc-gpu-cuda-1").is_err());
        assert!(check_isolation(&host, &rep, "other").is_err());
        let mut r = rep.clone();
        r.self_pid = 2;
        assert!(check_isolation(&host, &r, "fc-gpu-cuda-1").is_err());
        let mut h = host.clone();
        h.mount_ids.insert(100);
        assert!(check_isolation(&h, &rep, "fc-gpu-cuda-1").is_err());
    }
}
