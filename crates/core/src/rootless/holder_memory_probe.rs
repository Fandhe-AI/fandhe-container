//! holder が継承するメモリに注入ファイルの secret が無いことを、実プロセスのメモリ走査で観測する試験専用の入口
//! (CORE-6・SEC-5・SUP-12・#2628)。`exec-test-support` feature を付けたビルドにだけ存在する。
//!
//! 範囲写像の起動では、中間プロセス I が `InjectedFileSet` を保持したまま ID 写像の holder(本番の
//! [`super::run_userns_holder`])を fork する。holder は exec せず dumpable なので、同じ uid のホスト側プロセスが
//! `/proc/<holder>/mem` で I の複製を読める(`docs/design/rootless-id-map-holder.md` §4)。本入口はその状況を
//! 実プロセスで作り、holder の `maps` の読める領域を `mem` から走査して secret(既知の 64 バイト)の一致件数を数える。
//!
//! - T(呼び出し側の試験。単一スレッドの `main`): secret を**自分のメモリへ載せずに**(I を fork した後で初めて
//!   ファイルを読む)走査する。Yama `ptrace_scope=1` でも祖先である T は `/proc/<holder>/mem` を読める
//! - I: [`HolderMemorySource`] に従って `InjectedFileSet` を作り、保持したまま holder を fork して READY を待つ。
//!   `SealedFile` は `InjectedContent::from_file`(本番の経路)、`CallerMemory` は `Vec` を読む陽性対照
//! - holder: 本番の `run_userns_holder`。READY の後は Release を受けずに生き続ける(走査の間、数ミリ秒で終わらせない)
//!
//! 実機前提(非特権 user namespace を許可するホスト)。入口は `tests/rootless_holder_memory.rs` だけが使う。

use std::io::{Read as _, Write as _};
use std::os::unix::fs::FileExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{MAPPER_REPLY_LEN, MapperReply, run_userns_holder};
use crate::injected_files::{InjectedContent, InjectedFileMode, InjectedFileSet, InjectedFileSpec};
use crate::sys;

/// I が注入内容をどう保持するか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderMemorySource {
    /// 本番の経路: ファイルから封印 memfd へ(`InjectedContent::from_file`)。
    SealedFile,
    /// 陽性対照: ファイルを `Vec` へ読む(`InjectedContent::from_bytes`。呼び出し元のメモリ)。
    CallerMemory,
}

/// 走査の観測値(判定は呼び出し側の試験が具体値で行う)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderMemoryObservation {
    /// holder の pid。
    pub holder_pid: u32,
    /// 走査できた(読み取りに成功した)領域の数。
    pub regions_scanned: usize,
    /// 走査したバイト数。
    pub bytes_scanned: u64,
    /// secret と一致した件数。
    pub hits: usize,
    /// holder が持つ fd のリンク先(memfd を持たないことの照合用)。
    pub fd_targets: Vec<String>,
}

fn fail(m: &str) -> String {
    format!("holder memory probe: {m}")
}

/// 試験用の注入先(固定)。
const DEST: &str = "/run/secrets/probe";

fn build_set(path: &Path, source: HolderMemorySource) -> Result<InjectedFileSet, String> {
    let content = match source {
        HolderMemorySource::SealedFile => {
            let file = std::fs::File::open(path).map_err(|e| fail(&format!("open: {e}")))?;
            InjectedContent::from_file(&file).map_err(|e| fail(&format!("from_file: {e:?}")))?
        }
        HolderMemorySource::CallerMemory => {
            let bytes = std::fs::read(path).map_err(|e| fail(&format!("read: {e}")))?;
            InjectedContent::from_bytes(bytes).map_err(|e| fail(&format!("from_bytes: {e:?}")))?
        }
    };
    let mut set = InjectedFileSet::new();
    let spec = InjectedFileSpec::new(DEST, content, InjectedFileMode::DEFAULT)
        .map_err(|e| fail(&format!("spec: {e:?}")))?;
    set.push(spec).map_err(|e| fail(&format!("push: {e:?}")))?;
    Ok(set)
}

/// 中間プロセス I の本体。成功なら holder の pid と準備完了の合図を `report` へ書き、呼び出し元の SIGKILL を待つ。
fn caller_process(
    path: &Path,
    source: HolderMemorySource,
    ctl: UnixStream,
    holder_end: UnixStream,
    mut report: UnixStream,
) -> Result<(), String> {
    let me = std::process::id();
    let timeout = Duration::from_secs(10);
    // 本番と同じく、注入集合を保持したまま holder を fork する。
    let set = build_set(path, source)?;
    let holder_pid = sys::fork_single_threaded(
        move || {
            run_userns_holder(
                me,
                holder_end,
                timeout,
                // Release を送らないため、走査が終わるまで生き続ける上限(呼び出し元が先に消す)。
                Duration::from_secs(60),
                Duration::from_secs(5),
                &mut std::io::sink(),
            )
        },
        70,
    )
    .map_err(|e| fail(&format!("fork holder: {e:?}")))?;
    report
        .write_all(&holder_pid.to_be_bytes())
        .map_err(|e| fail(&e.to_string()))?;
    let mut ctl = ctl;
    ctl.set_read_timeout(Some(timeout))
        .map_err(|e| fail(&e.to_string()))?;
    let mut buf = [0u8; MAPPER_REPLY_LEN];
    ctl.read_exact(&mut buf)
        .map_err(|e| fail(&format!("holder ready: {e}")))?;
    if MapperReply::decode(&buf) != Ok(MapperReply::Ok) {
        return Err(fail("holder did not report ready"));
    }
    report.write_all(&[1]).map_err(|e| fail(&e.to_string()))?;
    // 呼び出し元の SIGKILL を待つ(上限つき)。注入集合は fork の後も最後まで保持する。
    std::thread::sleep(Duration::from_secs(60));
    std::hint::black_box(&set);
    Ok(())
}

/// `/proc/<pid>/maps` の 1 行から、読める領域 `(開始, 終了)` を取り出す(`[vvar]` 等の読めない特殊領域は除く)。
fn readable_region(line: &str) -> Option<(u64, u64)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    if !perms.starts_with('r') {
        return None;
    }
    let name = line.split_whitespace().nth(5).unwrap_or("");
    if matches!(name, "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
        return None;
    }
    let (a, b) = range.split_once('-')?;
    Some((
        u64::from_str_radix(a, 16).ok()?,
        u64::from_str_radix(b, 16).ok()?,
    ))
}

/// `needle` の出現件数(重ならない走査。チャンク境界をまたぐ分は呼び出し側が重ねて渡す)。
fn count_hits(hay: &[u8], needle: &[u8]) -> usize {
    let Some(&first) = needle.first() else {
        return 0;
    };
    let mut hits = 0;
    let mut i = 0;
    while let Some(p) = hay
        .get(i..)
        .and_then(|s| s.iter().position(|&b| b == first))
    {
        let at = i + p;
        match hay.get(at..at + needle.len()) {
            Some(w) if w == needle => {
                hits += 1;
                i = at + needle.len();
            }
            Some(_) => i = at + 1,
            None => break,
        }
    }
    hits
}

/// `/proc/<pid>/mem` の読める領域をすべて走査して `needle` の一致件数を数える。
fn scan_process(pid: u32, needle: &[u8]) -> Result<(usize, u64, usize), String> {
    const CHUNK: usize = 1 << 20;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| fail(&format!("read maps: {e}")))?;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).map_err(|e| {
        fail(&format!(
            "open mem (ptrace access denied? Yama ptrace_scope>=2): {e}"
        ))
    })?;
    let (mut regions, mut bytes, mut hits) = (0usize, 0u64, 0usize);
    for line in maps.lines() {
        let Some((start, end)) = readable_region(line) else {
            continue;
        };
        let mut region_ok = true;
        let mut addr = start;
        let overlap = needle.len().saturating_sub(1);
        let mut buf = vec![0u8; CHUNK + overlap];
        while addr < end {
            let want = usize::try_from((end - addr).min((CHUNK + overlap) as u64)).unwrap_or(CHUNK);
            let Some(window) = buf.get_mut(..want) else {
                break;
            };
            match mem.read_at(window, addr) {
                Ok(n) if n > 0 => {
                    hits += count_hits(buf.get(..n).unwrap_or(&[]), needle);
                    bytes += n as u64;
                    // 次のチャンクは `CHUNK` ずつ進む(境界をまたぐ一致を重ねた分で拾う。重複計上は
                    // `overlap` が needle 長未満なので起きない)。
                    addr += (n.min(CHUNK)) as u64;
                    if n <= overlap {
                        break;
                    }
                }
                _ => {
                    region_ok = false;
                    break;
                }
            }
        }
        if region_ok {
            regions += 1;
        }
    }
    Ok((regions, bytes, hits))
}

/// `secret_path` の内容(既知の 64 バイト)を注入集合に持つ I から、本番の holder を fork して走査する。
///
/// 呼び出しプロセスを child subreaper にする(I を消した後の holder を回収するため)。`secret_path` は呼び出し側が
/// `/dev/urandom` の内容で作る(試験バイナリのリテラルにしない)。
pub fn observe_holder_memory(
    secret_path: PathBuf,
    source: HolderMemorySource,
) -> Result<HolderMemoryObservation, String> {
    sys::set_child_subreaper(true).map_err(|e| fail(&format!("subreaper: {e:?}")))?;
    let (ctl, holder_end) = UnixStream::pair().map_err(|e| fail(&e.to_string()))?;
    let (mut report_rd, report_wr) = UnixStream::pair().map_err(|e| fail(&e.to_string()))?;
    let path_for_child = secret_path.clone();
    let caller = sys::fork_single_threaded(
        move || match caller_process(&path_for_child, source, ctl, holder_end, report_wr) {
            Ok(()) => 0,
            Err(m) => {
                let _ = writeln!(std::io::stderr(), "{m}");
                71
            }
        },
        72,
    )
    .map_err(|e| fail(&format!("fork caller: {e:?}")))?;
    let cleanup = |holder: Option<u32>| {
        let _ = sys::kill_pid(caller, sys::Signal::Kill);
        if let Some(h) = holder {
            let _ = sys::kill_pid(h, sys::Signal::Kill);
        }
        for p in std::iter::once(caller).chain(holder) {
            for _ in 0..400 {
                if matches!(sys::wait_pid_nohang(p), Ok(Some(_)) | Err(_)) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    report_rd
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| fail(&e.to_string()))?;
    let mut pid_buf = [0u8; 4];
    if let Err(e) = report_rd.read_exact(&mut pid_buf) {
        cleanup(None);
        return Err(fail(&format!("caller did not report the holder: {e}")));
    }
    let holder_pid = u32::from_be_bytes(pid_buf);
    let mut ready = [0u8; 1];
    if let Err(e) = report_rd.read_exact(&mut ready) {
        cleanup(Some(holder_pid));
        return Err(fail(&format!("caller did not report ready: {e}")));
    }
    // holder が生まれた後で初めて secret を読む(fork の前に T のメモリへ載せない)。
    let result = std::fs::read(&secret_path)
        .map_err(|e| fail(&format!("read secret: {e}")))
        .and_then(|needle| {
            if needle.len() < 32 {
                return Err(fail("secret must be at least 32 bytes"));
            }
            let (regions_scanned, bytes_scanned, hits) = scan_process(holder_pid, &needle)?;
            let fd_targets = std::fs::read_dir(format!("/proc/{holder_pid}/fd"))
                .map_err(|e| fail(&format!("read fd dir: {e}")))?
                .filter_map(Result::ok)
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            Ok(HolderMemoryObservation {
                holder_pid,
                regions_scanned,
                bytes_scanned,
                hits,
                fd_targets,
            })
        });
    cleanup(Some(holder_pid));
    result
}
