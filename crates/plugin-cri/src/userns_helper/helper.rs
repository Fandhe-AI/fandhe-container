//! userns helper 本体（再 exec された単一スレッドのプロセス。Linux のみ。SEC-5・OCI-1・CORE-6・REPAIR-5。#4795）。
//!
//! 呼び出し元は `main.rs` の先頭の振り分け（第 1 引数が [`super::USERNS_HELPER_ARG`]）。tokio・thread・`LineSink` を作らない。
//! 契約の全体は `docs/design/userns-extract-helper.md`。手順の順序（変えない）:
//!
//! 1. argv の検査（隠し引数の後ろの余分な引数は応答なしで終了コード 2。パスを引数で受けない）
//! 2. non-dumpable にして読み戻す（exec 直後は dumpable が戻っているため最初に落とす）
//! 3. fd 3 以上を閉じる（`close_range`。失敗は `ENOSYS` を含め応答なしで終了コード 1）
//! 4. fd 0（制御 socket）と fd 1（対象ディレクトリ）を dup して所有する
//! 5. 権限モデルを `start` と同じ解決で得て、範囲写像の rootless でなければ `NoSubordinateIds`
//! 6. `Threads: 1` を確かめ（解決が一時スレッドを使う場合に備え、解決の後・参加の直前）、core の公開 API で user namespace へ参加
//! 7. 参加後に non-dumpable を再確認
//! 8. 要求 frame を読む（期限 [`REQUEST_READ_TIMEOUT`]。header を検査して決まった長さだけを固定長バッファへ読む）。要求を参加の後に読むのは、holder が呼び出し時点のメモリを複製するため、
//!    dumpable な holder が要求の bytes を持たないようにする（展開モードの fd・options も同じ窓に入れない）
//!    展開モード（#4847）は要求 frame（固定部 + レイヤーの記述）を読んだ後、blob の fd を `SCM_RIGHTS` で 1 通受ける（参加の後なので、
//!    dumpable な holder の複製に fd・要求の bytes は入らない。受信も [`REQUEST_READ_TIMEOUT`] の期限）。fd の数・token が
//!    要求と一致しなければ `InvalidRequest`。各 fd は `VerifiedLayerBlob::from_file`（信頼条件と digest・サイズの再検証）を通し、
//!    fd 1 を `/proc/self/fd/N` として開いた `ExtractRoot` へ、oci の `extract_image_layers_bounded_in` で展開する。
//!    所有者の方針は `ChownInUserNamespace` で、写像は参加に使ったもの（要求では受けない）。`--no-join`（試験専用）だけは写像が
//!    無いので `Keep`。期限は要求を受けた時点から `work_ms`。操作記録（`OciOpRecorder`）は捨てる（観測は親の呼び出し単位）。
//!    削除モード（H3。#4800）は fd 1（親ディレクトリ）の複製を `/proc/self/fd/N` として oci の `ExtractRoot` で開き、直下の
//!    固定名（[`RemoveTarget::child_name`]）の木を `remove_child_tree_bounded`（symlink を辿らない・マウントをまたがない・
//!    深さの上限）で消す。パス・名前は要求で受けない。helper 自身は期限を持たず、親の期限切れの kill で止まる（削除は冪等で、
//!    再実行が続きから消す）
//! 9. モード実行と応答 frame の書き込み。成功は終了コード 0、応答できた失敗は 1
//!
//! 応答の文言は固定語彙で、パス・errno・uid を含めない（REPAIR-4）。stderr は親が null にする。

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{
    IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet, isolate_rootless_subordinate,
    plan_rootless_subordinate,
};
use fandhe_container_core::rootless::{DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter};
use fandhe_container_oci::error::OciErrorCode;
use fandhe_container_oci::instrument::NoopOciOpRecorder;
use fandhe_container_oci::layer::VerifiedLayerBlob;
use fandhe_container_oci::layer::extract::{
    ExtractBudget, ExtractOptions, ExtractRoot, ImageLayer, OwnershipPolicy, SpecialBitsPolicy,
    extract_image_layers_bounded_in,
};

use super::USERNS_HELPER_ARG;
use super::wire::{
    EXTRACT_FD_TOKEN, ExtractReport, ExtractRequest, ExtractSpecialBits, HelperErrorCode,
    InspectReport, MAX_EXTRACT_PAYLOAD_BYTES, Mode, REQUEST_HEADER_LEN, RemoveTarget, Report,
    Request, StatReport, decode_request_header, encode_response, id_map_fingerprint,
};
use crate::image_ownership::to_oci_map;
use crate::sys::{fd_passing, hardening};

/// 参加に使った写像（uid・gid）。`--no-join` では無い。
type JoinedMaps = (IdMapSet, IdMapSet);

/// 要求 frame の読み取り期限（参加の後に読む。親の書き込みは参加の完了を待たずに済むため短くてよい。REPAIR-5）。
pub const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// 応答の書き込み期限。
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// `/proc/self/status` の読み取り上限。
const MAX_STATUS_BYTES: u64 = 64 * 1024;
/// `/proc/self/{uid,gid}_map` の読み取り上限。
const MAX_MAP_BYTES: u64 = 16 * 1024;

const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_BAD_ARGS: u8 = 2;

/// helper のエントリ。`args` は program 名を除いた argv で、先頭は [`USERNS_HELPER_ARG`]。
pub fn run_helper_main(args: Vec<OsString>) -> ExitCode {
    let Some(join) = parse_args(&args) else {
        return ExitCode::from(EXIT_BAD_ARGS);
    };
    if hardening::set_non_dumpable().is_err() || !matches!(hardening::get_dumpable(), Ok(0)) {
        return ExitCode::from(EXIT_FAILED);
    }
    if hardening::close_inherited_fds().is_err() {
        return ExitCode::from(EXIT_FAILED);
    }
    let Some((sock, target)) = take_stdio() else {
        return ExitCode::from(EXIT_FAILED);
    };
    let result = run(&sock, target, join);
    let mut sock = sock;
    let wrote = sock.write_all(&encode_response(&result)).is_ok();
    ExitCode::from(if wrote && result.is_ok() {
        EXIT_OK
    } else {
        EXIT_FAILED
    })
}

/// 隠し引数の後ろを検査する。`Some(true)` = 通常（参加する）、`Some(false)` = 試験専用の `--no-join`、`None` = 拒否。
fn parse_args(args: &[OsString]) -> Option<bool> {
    let (first, rest) = args.split_first()?;
    if first != USERNS_HELPER_ARG {
        return None;
    }
    match rest {
        [] => Some(true),
        #[cfg(feature = "userns-helper-test-support")]
        [flag] if flag == "--no-join" => Some(false),
        _ => None,
    }
}

/// fd 0 を socket として、fd 1 を対象ディレクトリとして dup して所有する（`from_raw_fd` は使わない）。
/// socket でなければ（期限を設定できなければ）`None`。
fn take_stdio() -> Option<(UnixStream, OwnedFd)> {
    let sock_fd = std::io::stdin().as_fd().try_clone_to_owned().ok()?;
    let target = std::io::stdout().as_fd().try_clone_to_owned().ok()?;
    let sock = UnixStream::from(sock_fd);
    sock.set_read_timeout(Some(REQUEST_READ_TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT)).ok()?;
    // fd 0 が socket でなければ getsockname が失敗する。
    sock.local_addr().ok()?;
    Some((sock, target))
}

fn run(sock: &UnixStream, target: OwnedFd, join: bool) -> Result<Report, HelperErrorCode> {
    let target = File::from(target);
    if !target
        .metadata()
        .map_err(|_| HelperErrorCode::Internal)?
        .is_dir()
    {
        return Err(HelperErrorCode::InvalidRequest);
    }
    let maps = if join {
        Some(join_user_namespace()?)
    } else {
        None
    };
    let request = read_request(sock)?;
    let received_at = Instant::now();
    let mode = match request {
        Request::Mode(mode) => mode,
        Request::Extract(req) => {
            return extract(sock, &target, &req, maps.as_ref(), received_at).map(Report::Extracted);
        }
    };
    match mode {
        Mode::Inspect => inspect(join).map(Report::Inspect),
        Mode::StatTarget => {
            let meta = target.metadata().map_err(|_| HelperErrorCode::Internal)?;
            Ok(Report::StatTarget(StatReport {
                uid: meta.uid(),
                gid: meta.gid(),
                mode: meta.mode() & 0o7777,
            }))
        }
        Mode::Remove(t) => remove_child_tree(&target, t).map(|()| Report::Removed),
    }
}

/// 展開モード（#4847）。blob の fd を受け、検証して、fd 1 の `ExtractRoot` へ展開する。失敗は固定語彙の分類だけで返す。
fn extract(
    sock: &UnixStream,
    target: &File,
    req: &ExtractRequest,
    maps: Option<&JoinedMaps>,
    received_at: Instant,
) -> Result<ExtractReport, HelperErrorCode> {
    // 参加した写像が親の期待（展開設定の写像）と一致しなければ、書き込みの前に拒否する（SEC-5・#4848。helper は起動ごとに
    // subuid / subgid を解決し直すため、親が記録した写像とずれうる。root は自 UID に写るので所有者の検査では見つからない）。
    if let Some((uid, gid)) = maps {
        let (want_uid, want_gid) = req.expected_map_fingerprints();
        let got_uid = to_oci_map(uid).map_err(|_| HelperErrorCode::Internal)?;
        let got_gid = to_oci_map(gid).map_err(|_| HelperErrorCode::Internal)?;
        if id_map_fingerprint(&got_uid) != *want_uid || id_map_fingerprint(&got_gid) != *want_gid {
            return Err(HelperErrorCode::IdMapMismatch);
        }
    }
    let deadline = received_at + Duration::from_millis(u64::from(req.work_ms()));
    let want = req.layers().len();
    // 0 件は launcher が SCM_RIGHTS を送らないため待たない（OCI-1。layers が空の正常なイメージ）。
    let fds = if want == 0 {
        Vec::new()
    } else {
        let got = fd_passing::recv_fds(sock.as_fd(), want).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                HelperErrorCode::RequestTimeout
            }
            _ => HelperErrorCode::InvalidRequest,
        })?;
        // 本数が要求とちょうど一致しなければ拒否する（受けた fd は drop で閉じる）。
        if got.token != EXTRACT_FD_TOKEN || got.fds.len() != want {
            return Err(HelperErrorCode::InvalidRequest);
        }
        got.fds
    };
    // blob を置いたストアの所有者は、名前空間の中から見た自分の euid（範囲写像ではホストの利用者が 0 に見える）。
    let status = read_bounded("/proc/self/status", MAX_STATUS_BYTES)?;
    let owner = fandhe_container_supervisor::privilege::parse_proc_status(&status)
        .map_err(|_| HelperErrorCode::Internal)?
        .uid
        .effective;
    let fail = |e: fandhe_container_oci::error::OciError| HelperErrorCode::ExtractFailed(e.code());
    let blobs = req
        .layers()
        .iter()
        .zip(fds)
        .map(|(l, fd)| {
            VerifiedLayerBlob::from_file(File::from(fd), l.digest(), l.size(), owner).map_err(fail)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let layers: Vec<ImageLayer<'_>> = blobs
        .iter()
        .zip(req.layers())
        .map(|(b, l)| ImageLayer::new(b, l.media_type(), l.diff_id()))
        .collect();
    let ownership = match maps {
        Some((uid, gid)) => OwnershipPolicy::ChownInUserNamespace {
            uid: to_oci_map(uid).map_err(|_| HelperErrorCode::Internal)?,
            gid: to_oci_map(gid).map_err(|_| HelperErrorCode::Internal)?,
        },
        // 試験専用の `--no-join`（参加しないので写像が無い）。本番のビルドには存在しない。
        None => OwnershipPolicy::Keep,
    };
    let special_bits = match req.special_bits() {
        ExtractSpecialBits::Strip => SpecialBitsPolicy::Strip,
        ExtractSpecialBits::PreserveIfChowned => SpecialBitsPolicy::PreserveIfChowned,
    };
    let options = ExtractOptions::new()
        .with_ownership(ownership)
        .with_special_bits(special_bits);
    let link = format!("/proc/self/fd/{}", target.as_raw_fd());
    let root = ExtractRoot::open_proc_fd_link(std::path::Path::new(&link)).map_err(fail)?;
    let budget = ExtractBudget::new().with_deadline(deadline);
    let done = extract_image_layers_bounded_in(
        &NoopOciOpRecorder,
        &layers,
        &root,
        req.max_uncompressed_bytes(),
        req.limits(),
        &options,
        &budget,
    )
    .map_err(fail)?;
    let entries: u64 = done.iter().map(|d| d.entries).sum();
    Ok(ExtractReport {
        layers: u32::try_from(done.len()).unwrap_or(u32::MAX),
        entries: u32::try_from(entries).unwrap_or(u32::MAX),
    })
}

/// fd 1（親ディレクトリ）の直下の固定名の木を消す。名前空間の中の能力は写像内の所有者の inode にしか効かず、oci の削除は
/// symlink を辿らず（リンク自体を unlink する）、マウントをまたがない（`FailedPrecondition` → `RemoveRefused`）。不在は成功（冪等）。
fn remove_child_tree(parent: &File, target: RemoveTarget) -> Result<(), HelperErrorCode> {
    // 複製した所有 fd の `/proc/self/fd/N` を magic link として開く（パスで探し直さず、渡された実体だけを根にする）。
    let link = format!("/proc/self/fd/{}", parent.as_raw_fd());
    let root = ExtractRoot::open_proc_fd_link(std::path::Path::new(&link))
        .map_err(|_| HelperErrorCode::RemoveFailed)?;
    root.remove_child_tree_bounded(target.child_name(), &ExtractBudget::new())
        .map_err(|e| match e.code() {
            OciErrorCode::FailedPrecondition | OciErrorCode::InvalidArgument => {
                HelperErrorCode::RemoveRefused
            }
            _ => HelperErrorCode::RemoveFailed,
        })
}

/// 範囲写像の user namespace へ参加する（手順 5〜7）。
fn join_user_namespace() -> Result<JoinedMaps, HelperErrorCode> {
    let (privilege, source) =
        fandhe_container_supervisor::start_entry::resolve_self_launch_privilege()
            .map_err(|_| HelperErrorCode::NoSubordinateIds)?;
    let (IsolationPrivilege::RootlessSubordinateIds, Some(source)) = (privilege, source) else {
        return Err(HelperErrorCode::NoSubordinateIds);
    };
    let status = read_bounded("/proc/self/status", MAX_STATUS_BYTES)?;
    let snap = fandhe_container_supervisor::privilege::parse_proc_status(&status)
        .map_err(|_| HelperErrorCode::Internal)?;
    let (euid, egid) = (snap.uid.effective, snap.gid.effective);
    let maps = source
        .resolve_id_maps(euid, egid)
        .map_err(|_| HelperErrorCode::NoSubordinateIds)?;
    let helper = HelperPaths::system_default().map_err(|_| HelperErrorCode::NoSubordinateIds)?;
    // 解決が一時スレッドを使った場合に備え、参加の直前に単一スレッドであることを確かめる。
    if threads_of(&read_bounded("/proc/self/status", MAX_STATUS_BYTES)?) != Some(1) {
        return Err(HelperErrorCode::MultiThreaded);
    }
    let config = IsolationConfig {
        namespaces: NamespaceSet::empty().with(Namespace::User),
        hostname: None,
    };
    let plan = plan_rootless_subordinate(
        &config,
        maps.uid().clone(),
        maps.gid().clone(),
        IdMapWriter::Helper(helper),
        DEFAULT_HELPER_TIMEOUT,
    )
    .map_err(|_| HelperErrorCode::JoinFailed)?;
    isolate_rootless_subordinate(&plan).map_err(|_| HelperErrorCode::JoinFailed)?;
    if !matches!(hardening::get_dumpable(), Ok(0)) {
        return Err(HelperErrorCode::NotNonDumpable);
    }
    Ok((maps.uid().clone(), maps.gid().clone()))
}

/// 要求を期限つきで読んで復号する。header の検査（上限・tag ごとの固定長）の後に、決まった長さ（高々
/// [`MAX_EXTRACT_PAYLOAD_BYTES`]）だけを固定長バッファへ読む（確保しない）。
fn read_request(sock: &UnixStream) -> Result<Request, HelperErrorCode> {
    let read = |buf: &mut [u8]| {
        (&*sock).read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                HelperErrorCode::RequestTimeout
            }
            _ => HelperErrorCode::InvalidRequest,
        })
    };
    let mut header = [0u8; REQUEST_HEADER_LEN];
    read(&mut header)?;
    let head = decode_request_header(&header)?;
    let mut payload = [0u8; MAX_EXTRACT_PAYLOAD_BYTES];
    let dst = payload
        .get_mut(..head.payload_len())
        .ok_or(HelperErrorCode::InvalidRequest)?;
    read(dst)?;
    head.request(payload.get(..head.payload_len()).unwrap_or(&[]))
}

fn inspect(joined: bool) -> Result<InspectReport, HelperErrorCode> {
    let status = read_bounded("/proc/self/status", MAX_STATUS_BYTES)?;
    let snap = fandhe_container_supervisor::privilege::parse_proc_status(&status)
        .map_err(|_| HelperErrorCode::Internal)?;
    let dumpable = hardening::get_dumpable().map_err(|_| HelperErrorCode::Internal)?;
    Ok(InspectReport {
        joined,
        threads: threads_of(&status).ok_or(HelperErrorCode::Internal)?,
        dumpable: u32::try_from(dumpable).map_err(|_| HelperErrorCode::Internal)?,
        euid: snap.uid.effective,
        egid: snap.gid.effective,
        uid_map_rows: map_rows(&read_bounded("/proc/self/uid_map", MAX_MAP_BYTES)?),
        gid_map_rows: map_rows(&read_bounded("/proc/self/gid_map", MAX_MAP_BYTES)?),
    })
}

fn read_bounded(path: &str, limit: u64) -> Result<String, HelperErrorCode> {
    let mut text = String::new();
    File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_string(&mut text))
        .map_err(|_| HelperErrorCode::Internal)?;
    if u64::try_from(text.len()).map_or(true, |n| n > limit) {
        return Err(HelperErrorCode::Internal);
    }
    Ok(text)
}

/// `/proc/<pid>/status` の `Threads:` の値。
fn threads_of(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

/// uid_map / gid_map の行数（空行を除く）。
fn map_rows(text: &str) -> u32 {
    u32::try_from(text.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-5・#4795: `Threads:` の抽出（他の項目に惑わされない）。
    #[test]
    fn sec5_4795_threads_is_parsed_from_status() {
        assert_eq!(threads_of("Name:\tx\nThreads:\t1\nVmRSS: 3 kB\n"), Some(1));
        assert_eq!(threads_of("Threads:\t12\n"), Some(12));
        assert_eq!(threads_of("Name:\tx\n"), None);
        assert_eq!(threads_of("Threads:\tmany\n"), None);
    }

    /// SEC-5・#4795: 写像の行数は空行を数えない。
    #[test]
    fn sec5_4795_map_rows_ignores_blank_lines() {
        assert_eq!(map_rows(""), 0);
        assert_eq!(
            map_rows("         0       1000          1\n         1     100000      65536\n"),
            2
        );
        assert_eq!(map_rows("0 1 1\n\n"), 1);
    }

    /// SEC-5・#4795: 引数の検査。隠し引数の後ろの余分な引数（パスの入力）は拒否する。
    #[test]
    fn sec5_4795_extra_arguments_are_rejected() {
        let a = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(parse_args(&a(&[USERNS_HELPER_ARG])), Some(true));
        assert_eq!(parse_args(&a(&[USERNS_HELPER_ARG, "/tmp/x"])), None);
        assert_eq!(parse_args(&a(&["other"])), None);
        assert_eq!(parse_args(&[]), None);
        #[cfg(feature = "userns-helper-test-support")]
        assert_eq!(
            parse_args(&a(&[USERNS_HELPER_ARG, "--no-join"])),
            Some(false)
        );
    }
}
