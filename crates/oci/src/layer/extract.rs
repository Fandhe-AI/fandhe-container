//! レイヤー tar のルート配下への安全な展開（TASK-52.3・OCI-1・MS-4・#409）。
//!
//! `layer` の gzip 展開（TASK-52.2。`GzipLayerReader`）が返す tar バイトストリームを、rootfs 相当の
//! ステージング用ディレクトリへ書き出す。レイヤー tar は非信頼入力のため、このモジュールは次を担う。
//!
//! - パス検証と正規化（`..`・絶対パス・NUL・過大な長さ / 深さの拒否）。
//! - 親ディレクトリの解決はルートに閉じ込める（symlink を辿ってもホストの絶対パスへ抜けない。chroot 意味論）。
//! - symlink エントリはリンク先がルートより上へ出る場合に拒否し、hardlink はルート内の通常ファイルに限る。
//! - デバイス・FIFO・sparse は拒否する（既定拒否の最小権限）。
//! - エントリ数と累積展開バイト数に必須の上限を課し、超過したら書き込み前に中断する（DoS 対策）。
//!
//! tar クレートは解析（エントリ列挙）だけに使い、`unpack` / `unpack_in` は使わない（#408 の承認条件）。
//!
//! # 呼び出し契約
//!
//! - 呼び出し側は先に `verify_blob_digest` を通すこと。
//! - `root` は呼び出し側が排他的に所有する既存の空ディレクトリ（ステージング）で、`root` 自体が
//!   symlink であってはならない。別プロセスが同時に `root` を書き換える競合（TOCTOU）は防げない。
//! - 失敗時は部分的な展開物が残るため、呼び出し側が `root` ごと破棄すること。
//! - tar の終端後に入力を EOF まで読み捨てる（gzip トレーラの CRC32・ISIZE 検証のため）。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - whiteout（`.wh.*`・`.wh..wh..opq`）の解釈は TASK-53 の担当。本モジュールは通常ファイルとして展開する。
//! - uid / gid の写像と `chown`（SEC-5）。展開物は実行ユーザー所有になる。setuid / setgid / sticky は
//!   mode にそのまま保持する（ホストでは実行されない前提。rootless の UID 写像は SEC-5 で扱う）。
//! - ディレクトリ fd 起点（`openat2` の `RESOLVE_IN_ROOT` 等）の解決。libc 系の依存承認後の後続課題。
//! - 大文字小文字非区別 FS・Unicode 正規化による名前衝突の検出（IO-5）。
//! - Windows ホストでの symlink エントリ（`Unimplemented` で拒否する）。

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};

use tar::{Archive, EntryType};

use super::{DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, oci_error_from_layer_io, open_gzip_layer};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};

/// エントリ数上限の参考既定値。API は上限を必須引数にしており、上限なしの経路は提供しない。
pub const DEFAULT_MAX_LAYER_ENTRIES: u64 = 1_000_000;

/// 累積展開バイト数上限の参考既定値（gzip 展開後サイズの参考既定値と同値）。
pub const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;

/// パス全体の最大バイト数（Linux の `PATH_MAX`）。
const MAX_PATH_BYTES: usize = 4096;
/// 1 コンポーネントの最大バイト数（`NAME_MAX`）。
const MAX_COMPONENT_BYTES: usize = 255;
/// 1 パスのコンポーネント数の上限。
const MAX_COMPONENTS: usize = 256;
/// symlink の追従回数の上限（`ELOOP` 相当）。
const MAX_SYMLINK_FOLLOWS: u32 = 40;
/// 複写バッファ長（メモリ使用量を入力サイズに依存させない）。
const COPY_BUF_LEN: usize = 64 * 1024;

/// 展開の上限（必須。将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractLimits {
    /// 受け付けるエントリ数の上限（超過は `ResourceExhausted`）。
    pub max_entries: u64,
    /// 累積展開バイト数の上限（ヘッダ宣言サイズで書き込み前に検査。超過は `ResourceExhausted`）。
    pub max_total_bytes: u64,
}

impl ExtractLimits {
    /// 上限を指定して作る。
    pub fn new(max_entries: u64, max_total_bytes: u64) -> Self {
        Self {
            max_entries,
            max_total_bytes,
        }
    }
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LAYER_ENTRIES, DEFAULT_MAX_EXTRACTED_BYTES)
    }
}

/// 展開に成功したレイヤーの結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedLayer {
    /// 処理したエントリ数（PAX グローバルヘッダを除く）。
    pub entries: u64,
    /// 書き出したファイル本体の累積バイト数。
    pub bytes: u64,
}

/// 計装なしの `extract_tar_with`（`NoopOciOpRecorder`）。
pub fn extract_tar<R: Read>(
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    extract_tar_with(&NoopOciOpRecorder, src, root, limits)
}

/// 展開全体を `OciOpKind::ExtractLayer` として `recorder` へ記録する（REPAIR-4）。
///
/// `src` は gzip 展開済みの tar バイトストリーム（通常は `GzipLayerReader`）。契約はモジュール冒頭を参照。
pub fn extract_tar_with<R: Read>(
    recorder: &dyn OciOpRecorder,
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    record_oci_op(recorder, OciOpKind::ExtractLayer, || {
        extract_inner(src, root, limits)
    })
}

/// 圧縮レイヤー blob（digest 検証済み）を開き、gzip 展開しながら `root` へ展開する便宜関数。
///
/// `max_uncompressed_bytes` は gzip 展開後（tar 全体）の上限で、`limits.max_total_bytes` とは別に効く。
pub fn extract_layer_blob(
    blob_path: &Path,
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    let reader = open_gzip_layer(blob_path, max_uncompressed_bytes)?;
    extract_tar(reader, root, limits)
}

/// 親ディレクトリの解決・種別ごとの処理を束ねる状態。
struct Extractor<'a> {
    root: &'a Path,
    limits: ExtractLimits,
    entries: u64,
    bytes: u64,
    /// 所有者の rwx が欠けるディレクトリの mode。子の作成を妨げないよう全エントリ処理後に適用する。
    deferred_dirs: Vec<(PathBuf, u32)>,
}

fn err(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

fn escapes() -> OciError {
    err(
        OciErrorCode::PermissionDenied,
        "entry path escapes the extraction root",
    )
}

/// tar 解析 / 読み取りの `io::Error` を構造化エラーへ写す。分類不能なものは tar 構文違反として `DataLoss`。
fn map_stream_err(e: std::io::Error) -> OciError {
    if let Some(v) = e.get_ref().and_then(|i| i.downcast_ref::<GuardViolation>()) {
        return err(v.code, v.msg);
    }
    let m = oci_error_from_layer_io(e);
    if m.code() == OciErrorCode::Internal {
        return err(OciErrorCode::DataLoss, "layer tar stream is malformed");
    }
    m
}

/// 拡張ヘッダ（GNU long name / long link・PAX）本体 1 件あたりの上限バイト数。
///
/// `max_total_bytes` は通常ファイル本体のみを制限するため、メタデータには独立した有限の上限を課す（OCI-1）。
/// パスは `MAX_PATH_BYTES` が上限であり、これを超える拡張ヘッダは正当なレイヤーに現れない。
const MAX_META_BYTES: u64 = 1024 * 1024;

/// `TarGuard` が返す検査違反（`io::Error` の内包値。`map_stream_err` が構造化エラーへ戻す）。
#[derive(Debug)]
struct GuardViolation {
    code: OciErrorCode,
    msg: &'static str,
}

impl std::fmt::Display for GuardViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for GuardViolation {}

fn guard_error(code: OciErrorCode, msg: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, GuardViolation { code, msg })
}

/// `tar` クレートが拡張ヘッダ本体をメモリへ確保する前に、宣言サイズを検査する読み取りアダプタ。
///
/// 512 バイトのヘッダブロック境界で自前に追跡し（データはそのまま通す）、次を拒否する。
/// - GNU long name / long link / PAX の宣言サイズが `MAX_META_BYTES` を超えるもの（確保前に中断する）。
/// - GNU sparse（`S`）: 拡張ヘッダブロックで追跡がずれるうえ、展開でも拒否する種別のため。
/// - PAX の `size` 上書き: ヘッダのサイズと食い違い、追跡をすり抜けて拡張ヘッダを隠せるため。
struct TarGuard<R> {
    inner: R,
    header: [u8; 512],
    filled: usize,
    /// 現在のエントリの本体（拡張ヘッダなら内容）の残りバイト数。
    payload_left: u64,
    /// 本体の後ろの 512 バイト境界パディングの残りバイト数。
    pad_left: u64,
    /// PAX ヘッダ本体の収集先（`size` 上書きの検出用。`MAX_META_BYTES` 以下）。
    pax: Option<Vec<u8>>,
}

impl<R> TarGuard<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 512],
            filled: 0,
            payload_left: 0,
            pad_left: 0,
            pax: None,
        }
    }

    fn on_header(&mut self) -> std::io::Result<()> {
        let h = tar::Header::from_byte_slice(&self.header);
        let ty = h.entry_type();
        // サイズが読めないヘッダは tar 側が構文違反として拒否する。
        let size = h.size().unwrap_or(0);
        if ty == EntryType::GNUSparse {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "sparse entries are not supported",
            ));
        }
        let is_pax = matches!(ty, EntryType::XHeader | EntryType::XGlobalHeader);
        let is_meta = is_pax || matches!(ty, EntryType::GNULongName | EntryType::GNULongLink);
        if is_meta && size > MAX_META_BYTES {
            return Err(guard_error(
                OciErrorCode::ResourceExhausted,
                "extended header exceeds the metadata size limit",
            ));
        }
        self.payload_left = size;
        self.pad_left = size.div_ceil(512).saturating_mul(512) - size;
        self.pax = is_pax.then(Vec::new);
        self.filled = 0;
        Ok(())
    }

    fn after_payload(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.pax.take()
            && p.windows(6).any(|w| w == b" size=")
        {
            return Err(guard_error(
                OciErrorCode::InvalidArgument,
                "pax size override is not supported",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for TarGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.payload_left > 0 {
            let n = usize::try_from(self.payload_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(&mut buf[..n])?;
            if let (Some(p), Some(got)) = (self.pax.as_mut(), buf.get(..r)) {
                p.extend_from_slice(got);
            }
            self.payload_left -= r as u64;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
            return Ok(r);
        }
        if self.pad_left > 0 {
            let n = usize::try_from(self.pad_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(&mut buf[..n])?;
            self.pad_left -= r as u64;
            return Ok(r);
        }
        let n = (512 - self.filled).min(buf.len());
        let r = self.inner.read(&mut buf[..n])?;
        self.header[self.filled..self.filled + r].copy_from_slice(&buf[..r]);
        self.filled += r;
        if self.filled == 512 {
            self.on_header()?;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
        }
        Ok(r)
    }
}
/// ファイルシステム操作の `io::Error` を写す（パス・OS メッセージは載せない）。
fn map_fs_err(e: &std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::PermissionDenied => err(
            OciErrorCode::PermissionDenied,
            "failed to write the extraction target",
        ),
        ErrorKind::NotFound => err(OciErrorCode::NotFound, "extraction path not found"),
        _ => err(
            OciErrorCode::Internal,
            "failed to write the extraction target",
        ),
    }
}

#[cfg(unix)]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(OsString::from_vec(b.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    let s = std::str::from_utf8(b).map_err(|_| {
        err(
            OciErrorCode::InvalidArgument,
            "entry path is not valid UTF-8",
        )
    })?;
    if s.contains(['\\', ':']) {
        return Err(escapes());
    }
    Ok(OsString::from(s))
}

/// アーカイブ内のパスを、`.` を除いたコンポーネント列へ正規化する（`..`・絶対パス・NUL・過大な長さを拒否）。
fn normalize_entry_path(raw: &[u8]) -> Result<Vec<OsString>, OciError> {
    if raw.is_empty() {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
    }
    if raw.len() > MAX_PATH_BYTES || raw.contains(&0) {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is invalid"));
    }
    if raw.first() == Some(&b'/') {
        return Err(escapes());
    }
    let mut out = Vec::new();
    for c in raw.split(|b| *b == b'/') {
        if c.is_empty() || c == b"." {
            continue;
        }
        if c == b".." {
            return Err(escapes());
        }
        if c.len() > MAX_COMPONENT_BYTES || out.len() >= MAX_COMPONENTS {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "entry path is too long or too deep",
            ));
        }
        out.push(bytes_to_os(c)?);
    }
    Ok(out)
}

/// `rel` の各コンポーネントを 1 つずつ `symlink_metadata` で確認しながら、ルート内の物理位置を解決する。
///
/// symlink は読み取ってルート基準で辿る（絶対ターゲットはルートへ戻し、`..` はルートで止める）ため、
/// ホストの任意パスへは出られない。`create` が真なら存在しないディレクトリを作る。
/// 戻り値はルートからの物理コンポーネント列。
fn resolve_dir(root: &Path, rel: &[OsString], create: bool) -> Result<Vec<OsString>, OciError> {
    let mut resolved: Vec<OsString> = Vec::new();
    let mut queue: VecDeque<OsString> = rel.iter().cloned().collect();
    let mut follows = 0u32;
    while let Some(c) = queue.pop_front() {
        if c == "." {
            continue;
        }
        if c == ".." {
            resolved.pop();
            continue;
        }
        let cand = join_resolved(root, &resolved, &c);
        match fs::symlink_metadata(&cand) {
            Ok(m) if m.is_dir() => resolved.push(c),
            Ok(m) if m.file_type().is_symlink() => {
                follows += 1;
                if follows > MAX_SYMLINK_FOLLOWS {
                    return Err(err(
                        OciErrorCode::InvalidArgument,
                        "too many symbolic links while resolving an entry path",
                    ));
                }
                let target = fs::read_link(&cand).map_err(|e| map_fs_err(&e))?;
                let mut pending = Vec::new();
                for comp in target.components() {
                    match comp {
                        Component::RootDir | Component::Prefix(_) => {
                            resolved.clear();
                            pending.clear();
                        }
                        Component::CurDir => {}
                        Component::ParentDir => pending.push(OsString::from("..")),
                        Component::Normal(n) => pending.push(n.to_os_string()),
                    }
                }
                for p in pending.into_iter().rev() {
                    queue.push_front(p);
                }
            }
            Ok(_) => {
                return Err(err(
                    OciErrorCode::FailedPrecondition,
                    "a parent path component is not a directory",
                ));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !create {
                    return Err(err(OciErrorCode::NotFound, "extraction path not found"));
                }
                fs::create_dir(&cand).map_err(|e| map_fs_err(&e))?;
                resolved.push(c);
            }
            Err(e) => return Err(map_fs_err(&e)),
        }
    }
    Ok(resolved)
}

/// ルートと解決済みコンポーネントから物理パスを作る。
fn join_resolved(root: &Path, resolved: &[OsString], name: &OsString) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(resolved);
    p.push(name);
    p
}

/// 最終コンポーネントを取り出す。コンポーネントが空（ルート自身）なら `None`。
fn split_last(mut comps: Vec<OsString>) -> Option<(Vec<OsString>, OsString)> {
    let last = comps.pop()?;
    Some((comps, last))
}

#[cfg(unix)]
fn mode_perms(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    fs::Permissions::from_mode(mode & 0o7777)
}

#[cfg(unix)]
fn apply_file_mode(f: &fs::File, mode: u32) -> Result<(), OciError> {
    f.set_permissions(mode_perms(mode))
        .map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn apply_file_mode(_f: &fs::File, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

#[cfg(unix)]
fn apply_dir_mode(path: &Path, mode: u32) -> Result<(), OciError> {
    fs::set_permissions(path, mode_perms(mode)).map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn apply_dir_mode(_path: &Path, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

/// 所有者の rwx がそろわない mode か（子の作成を妨げうるため適用を遅延する）。
fn needs_deferral(mode: u32) -> bool {
    mode & 0o700 != 0o700
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), OciError> {
    std::os::unix::fs::symlink(target, link).map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> Result<(), OciError> {
    Err(err(
        OciErrorCode::Unimplemented,
        "symlink entries are not supported on this host",
    ))
}

impl Extractor<'_> {
    /// 既存の非ディレクトリを除去する。ディレクトリなら `FailedPrecondition`。存在しなければ何もしない。
    fn clear_existing_non_dir(&self, path: &Path) -> Result<(), OciError> {
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() => Err(err(
                OciErrorCode::FailedPrecondition,
                "a directory already exists at the entry path",
            )),
            Ok(_) => fs::remove_file(path).map_err(|e| map_fs_err(&e)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(map_fs_err(&e)),
        }
    }

    fn make_dir(&mut self, comps: Vec<OsString>, mode: u32) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Ok(());
        };
        let resolved = resolve_dir(self.root, &parent, true)?;
        let path = join_resolved(self.root, &resolved, &name);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                fs::remove_file(&path).map_err(|e| map_fs_err(&e))?;
                fs::create_dir(&path).map_err(|e| map_fs_err(&e))?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                fs::create_dir(&path).map_err(|e| map_fs_err(&e))?;
            }
            Err(e) => return Err(map_fs_err(&e)),
        }
        // 同じディレクトリの再定義は後勝ち。先の遅延 mode を残すと finish_dirs が後の mode を上書きする。
        self.deferred_dirs.retain(|(p, _)| *p != path);
        if needs_deferral(mode) {
            self.deferred_dirs.push((path, mode));
            Ok(())
        } else {
            apply_dir_mode(&path, mode)
        }
    }

    fn write_file<R: Read>(
        &mut self,
        comps: Vec<OsString>,
        mode: u32,
        size: u64,
        data: &mut R,
    ) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        // 宣言サイズで累積上限を書き込み前に検査する（巨大宣言サイズによる DoS を防ぐ）。
        let next = self
            .bytes
            .checked_add(size)
            .filter(|n| *n <= self.limits.max_total_bytes)
            .ok_or_else(|| {
                err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the extracted size limit",
                )
            })?;
        let resolved = resolve_dir(self.root, &parent, true)?;
        let path = join_resolved(self.root, &resolved, &name);
        self.clear_existing_non_dir(&path)?;
        // create_new は O_CREAT|O_EXCL で、最終コンポーネントの symlink を追従しない。
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| map_fs_err(&e))?;
        let mut buf = vec![0u8; COPY_BUF_LEN];
        let mut written = 0u64;
        while written < size {
            let want = usize::try_from(size - written).map_or(buf.len(), |r| r.min(buf.len()));
            let Some(dst) = buf.get_mut(..want) else {
                break;
            };
            let n = match data.read(dst) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_stream_err(e)),
            };
            if let Some(chunk) = buf.get(..n) {
                f.write_all(chunk).map_err(|e| map_fs_err(&e))?;
            }
            written += n as u64;
        }
        if written != size {
            return Err(err(OciErrorCode::DataLoss, "layer tar stream is malformed"));
        }
        apply_file_mode(&f, mode)?;
        self.bytes = next;
        Ok(())
    }

    fn make_symlink(&mut self, comps: Vec<OsString>, target: &[u8]) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        if target.is_empty() || target.len() > MAX_PATH_BYTES || target.contains(&0) {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "symlink target is invalid",
            ));
        }
        let resolved = resolve_dir(self.root, &parent, true)?;
        // リンク先を配置ディレクトリ基準で字句的に検査し、ルートより上へ出るものを拒否する。
        let mut depth = if target.first() == Some(&b'/') {
            0
        } else {
            resolved.len()
        };
        for c in target.split(|b| *b == b'/') {
            if c.is_empty() || c == b"." {
                continue;
            }
            if c == b".." {
                depth = depth.checked_sub(1).ok_or_else(escapes)?;
            } else {
                depth += 1;
            }
        }
        let path = join_resolved(self.root, &resolved, &name);
        self.clear_existing_non_dir(&path)?;
        create_symlink(Path::new(&bytes_to_os(target)?), &path)
    }

    fn make_hardlink(&mut self, comps: Vec<OsString>, target: &[u8]) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        let Some((tparent, tname)) = split_last(normalize_entry_path(target)?) else {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "hardlink target is empty",
            ));
        };
        let tres = resolve_dir(self.root, &tparent, false)?;
        let tpath = join_resolved(self.root, &tres, &tname);
        match fs::symlink_metadata(&tpath) {
            Ok(m) if m.is_file() => {}
            Ok(_) => {
                return Err(err(
                    OciErrorCode::PermissionDenied,
                    "hardlink target is not a regular file",
                ));
            }
            Err(e) => return Err(map_fs_err(&e)),
        }
        let resolved = resolve_dir(self.root, &parent, true)?;
        let path = join_resolved(self.root, &resolved, &name);
        self.clear_existing_non_dir(&path)?;
        fs::hard_link(&tpath, &path).map_err(|e| map_fs_err(&e))
    }

    /// 遅延していたディレクトリの mode を深い順に適用する（実ディレクトリであることを再確認する）。
    fn finish_dirs(&mut self) -> Result<(), OciError> {
        let mut dirs = std::mem::take(&mut self.deferred_dirs);
        dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (path, mode) in dirs {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => apply_dir_mode(&path, mode)?,
                _ => {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "an extracted directory was replaced during extraction",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn extract_inner<R: Read>(
    mut src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    match fs::symlink_metadata(root) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "extraction root is not a directory",
            ));
        }
        Err(e) => return Err(map_fs_err(&e)),
    }
    let mut x = Extractor {
        root,
        limits,
        entries: 0,
        bytes: 0,
        deferred_dirs: Vec::new(),
    };
    {
        let mut archive = Archive::new(TarGuard::new(&mut src));
        for entry in archive.entries().map_err(map_stream_err)? {
            let mut entry = entry.map_err(map_stream_err)?;
            let ty = entry.header().entry_type();
            if ty == EntryType::XGlobalHeader {
                continue;
            }
            x.entries += 1;
            if x.entries > limits.max_entries {
                return Err(err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the entry count limit",
                ));
            }
            let raw_path = entry.path_bytes().into_owned();
            let is_dir_name = raw_path.last() == Some(&b'/');
            let comps = normalize_entry_path(&raw_path)?;
            let mode = entry.header().mode().map_err(map_stream_err)?;
            match ty {
                EntryType::Directory => x.make_dir(comps, mode)?,
                EntryType::Regular | EntryType::Continuous if is_dir_name => {
                    x.make_dir(comps, mode)?;
                }
                EntryType::Regular | EntryType::Continuous => {
                    let size = entry.size();
                    x.write_file(comps, mode, size, &mut entry)?;
                }
                EntryType::Symlink => {
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "symlink target is invalid")
                        })?;
                    x.make_symlink(comps, &target)?;
                }
                EntryType::Link => {
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "hardlink target is invalid")
                        })?;
                    x.make_hardlink(comps, &target)?;
                }
                _ => {
                    return Err(err(
                        OciErrorCode::PermissionDenied,
                        "unsupported entry type",
                    ));
                }
            }
        }
    }
    x.finish_dirs()?;
    // tar 終端後の残りを読み捨て、gzip トレーラ（CRC32・ISIZE）を検証させる。
    let mut buf = vec![0u8; COPY_BUF_LEN];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(oci_error_from_layer_io(e)),
        }
    }
    Ok(ExtractedLayer {
        entries: x.entries,
        bytes: x.bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::OciOpOutcome;
    use crate::instrument::testing::Collect;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// `base/root` を作る一時ディレクトリ。Drop で `base` ごと消す（番兵でルート外書き込みを検出する）。
    struct Sandbox {
        base: PathBuf,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let base =
                std::env::temp_dir().join(format!("fc-oci-extract-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            let root = base.join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(base.join("sentinel"), b"s").unwrap();
            Self { base, root }
        }

        /// ルート外に番兵以外が増えていないこと。
        fn assert_outside_untouched(&self) {
            let mut names: Vec<_> = fs::read_dir(&self.base)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            assert_eq!(names, vec!["root".to_string(), "sentinel".to_string()]);
            assert_eq!(fs::read(self.base.join("sentinel")).unwrap(), b"s");
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            // 0o555 等のディレクトリを消せるよう権限を戻す。
            #[cfg(unix)]
            restore_perms(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(unix)]
    fn restore_perms(p: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(m) = fs::symlink_metadata(p)
            && m.is_dir()
        {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    restore_perms(&e.path());
                }
            }
        }
    }

    /// 生バイトで 1 エントリ分（ヘッダ + パディング済みデータ）を組み立てる。
    /// `tar::Builder` は `..` や絶対パスを拒否するため、悪意あるアーカイブはここで手組みする。
    fn raw_entry(
        name: &[u8],
        ty: EntryType,
        link: &[u8],
        mode: u32,
        declared: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name);
            old.linkname[..link.len()].copy_from_slice(link);
        }
        h.set_entry_type(ty);
        h.set_mode(mode);
        h.set_size(declared);
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    fn file(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Regular,
            b"",
            mode,
            data.len() as u64,
            data,
        )
    }

    fn dir(name: &str, mode: u32) -> Vec<u8> {
        raw_entry(name.as_bytes(), EntryType::Directory, b"", mode, 0, b"")
    }

    fn symlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Symlink,
            target.as_bytes(),
            0o777,
            0,
            b"",
        )
    }

    #[cfg(unix)]
    fn hardlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Link,
            target.as_bytes(),
            0o644,
            0,
            b"",
        )
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    fn run(sb: &Sandbox, entries: &[Vec<u8>]) -> Result<ExtractedLayer, OciError> {
        extract_tar(
            archive(entries).as_slice(),
            &sb.root,
            ExtractLimits::new(1000, 1 << 20),
        )
    }

    fn code(r: Result<ExtractedLayer, OciError>) -> OciErrorCode {
        r.expect_err("must fail").code()
    }

    /// OCI-1: `..`・絶対パス・NUL・過大な長さは拒否され、ルート外には何も作られない。
    #[test]
    fn oci1_path_traversal_is_rejected() {
        for name in [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "a/b/../../..",
            "./../evil",
        ] {
            let sb = Sandbox::new();
            assert_eq!(
                code(run(&sb, &[file(name, 0o644, b"x")])),
                OciErrorCode::PermissionDenied,
                "{name}"
            );
            sb.assert_outside_untouched();
        }
        // 1 コンポーネント 256 バイトは GNU long name 経由でしか表せない。
        let sb = Sandbox::new();
        let long = "x".repeat(256);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let e = extract_tar(bytes.as_slice(), &sb.root, ExtractLimits::new(10, 100)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1: 通常の展開（暗黙の親ディレクトリ・`./` 正規化・mode・ルート自身の無視）。
    #[cfg(unix)]
    #[test]
    fn oci1_extracts_regular_tree_with_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                dir("./", 0o755),
                dir("etc/", 0o755),
                file("./etc/hosts", 0o644, b"127.0.0.1"),
                file("usr/bin/tool", 0o4755, b"bin"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (4, 12));
        assert_eq!(fs::read(sb.root.join("etc/hosts")).unwrap(), b"127.0.0.1");
        let mode = |p: &str| fs::metadata(sb.root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("etc/hosts"), 0o644);
        assert_eq!(mode("usr/bin/tool"), 0o4755);
        assert_eq!(mode("etc"), 0o755);
        sb.assert_outside_untouched();
    }

    /// OCI-1: 所有者の権限が欠けるディレクトリでも子を作れ、最終的に mode が適用される。
    #[cfg(unix)]
    #[test]
    fn oci1_readonly_directory_mode_is_deferred() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(&sb, &[dir("ro/", 0o555), file("ro/child", 0o644, b"c")]).unwrap();
        assert_eq!(fs::read(sb.root.join("ro/child")).unwrap(), b"c");
        let m = fs::metadata(sb.root.join("ro"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(m, 0o555);
    }

    /// OCI-1: 同じディレクトリの再定義は後勝ち（0555 の後に 0755 を定義すると最終 mode は 0755）。
    #[cfg(unix)]
    #[test]
    fn oci1_directory_redefinition_is_last_wins() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode_of = |sb: &Sandbox| {
            fs::metadata(sb.root.join("d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o555), dir("d/", 0o755)]).unwrap();
        assert_eq!(mode_of(&sb), 0o755);
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o755), dir("d/", 0o555)]).unwrap();
        assert_eq!(mode_of(&sb), 0o555);
    }

    /// OCI-1: 巨大な拡張ヘッダ（GNU long name / PAX）は本体を確保する前にメタデータ上限で拒否する。
    #[test]
    fn oci1_oversized_extended_header_is_rejected_before_read() {
        for ty in [
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XHeader,
        ] {
            let sb = Sandbox::new();
            // 宣言サイズだけ巨大で本体は無い。確保前に拒否されなければ DataLoss（切り詰め）になる。
            let e = raw_entry(b"././@LongLink", ty, b"", 0o644, 1 << 40, b"");
            assert_eq!(code(run(&sb, &[e])), OciErrorCode::ResourceExhausted);
        }
    }

    /// OCI-1: PAX の size 上書きは追跡をずらせるため拒否する。
    #[test]
    fn oci1_pax_size_override_is_rejected() {
        let sb = Sandbox::new();
        let rec = b"12 size=999\n";
        let e = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            rec.len() as u64,
            rec,
        );
        assert_eq!(
            code(run(&sb, &[e, file("f", 0o644, b"x")])),
            OciErrorCode::InvalidArgument
        );
    }

    /// OCI-1: symlink のターゲットがルートより上へ出るものは拒否、収まるものは成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_targets_are_confined() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("x", "../../etc")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("y", "..")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("z", "/..")])),
            OciErrorCode::PermissionDenied
        );
        assert!(fs::symlink_metadata(sb.root.join("x")).is_err());
        sb.assert_outside_untouched();

        let sb = Sandbox::new();
        run(
            &sb,
            &[
                symlink("a/b/rel", "../sibling"),
                symlink("abs", "/usr/bin/x"),
                symlink("dotdot", "a/b/../.."),
            ],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(sb.root.join("a/b/rel")).unwrap(),
            PathBuf::from("../sibling")
        );
        assert_eq!(
            fs::read_link(sb.root.join("abs")).unwrap(),
            PathBuf::from("/usr/bin/x")
        );
        sb.assert_outside_untouched();
    }

    /// OCI-1: ルートを指す絶対 symlink 越しの書き込みは、ホストではなく `root` 配下に作られる。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_traversal_stays_inside_root() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[symlink("link", "/"), file("link/etc/x", 0o644, b"in")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("etc/x")).unwrap(), b"in");
        sb.assert_outside_untouched();

        // 相対で上へ登るリンク経由でもルートで止まる。
        let sb = Sandbox::new();
        run(
            &sb,
            &[
                dir("d/", 0o755),
                symlink("d/up", "../"),
                file("d/up/d/up/f", 0o644, b"f"),
            ],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"f");
        sb.assert_outside_untouched();
    }

    /// OCI-1: symlink を指す名前への書き込みはリンク先に追従せず、リンクを置換する。
    #[cfg(unix)]
    #[test]
    fn oci1_write_over_symlink_replaces_link() {
        let sb = Sandbox::new();
        fs::write(sb.base.join("victim"), b"v").unwrap();
        // ルート外の絶対パスを指す symlink を先に直接置く（アーカイブ経由では作れない状態の再現）。
        std::os::unix::fs::symlink(sb.base.join("victim"), sb.root.join("t")).unwrap();
        run(&sb, &[file("t", 0o644, b"new")]).unwrap();
        assert_eq!(fs::read(sb.base.join("victim")).unwrap(), b"v");
        assert_eq!(fs::read(sb.root.join("t")).unwrap(), b"new");
    }

    /// OCI-1: ループする symlink は追従回数の上限で拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_loop_is_rejected() {
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                symlink("a", "b"),
                symlink("b", "a"),
                file("a/x", 0o644, b"x"),
            ],
        );
        assert_eq!(code(r), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1: エントリ数は上限ちょうどが成功し、上限 + 1 は中断して以降を作らない。
    #[test]
    fn oci1_entry_count_limit() {
        let es = [
            file("a", 0o644, b"1"),
            file("b", 0o644, b"2"),
            file("c", 0o644, b"3"),
        ];
        let sb = Sandbox::new();
        let r = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(3, 100),
        )
        .unwrap();
        assert_eq!(r.entries, 3);

        let sb = Sandbox::new();
        let e = extract_tar(
            archive(&es).as_slice(),
            &sb.root,
            ExtractLimits::new(2, 100),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(sb.root.join("b").exists());
        assert!(!sb.root.join("c").exists());
    }

    /// OCI-1: 累積サイズは上限ちょうどが成功し、超過は中断する。巨大な宣言サイズは書き込み前に拒否する。
    #[test]
    fn oci1_total_bytes_limit() {
        let es = [file("a", 0o644, b"1234"), file("b", 0o644, b"5678")];
        let sb = Sandbox::new();
        let r = extract_tar(archive(&es).as_slice(), &sb.root, ExtractLimits::new(10, 8)).unwrap();
        assert_eq!(r.bytes, 8);

        let sb = Sandbox::new();
        let e = extract_tar(archive(&es).as_slice(), &sb.root, ExtractLimits::new(10, 7))
            .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(!sb.root.join("b").exists());

        let sb = Sandbox::new();
        let huge = raw_entry(b"big", EntryType::Regular, b"", 0o644, 10 << 30, b"tiny");
        assert_eq!(code(run(&sb, &[huge])), OciErrorCode::ResourceExhausted);
        assert!(!sb.root.join("big").exists());
    }

    /// OCI-1: hardlink はルート内の通常ファイルへのみ成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_hardlink_rules() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[file("orig", 0o644, b"data"), hardlink("sub/copy", "orig")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("sub/copy")).unwrap(), b"data");

        for (es, want) in [
            (
                vec![hardlink("h", "../sentinel")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![hardlink("h", "/etc/passwd")],
                OciErrorCode::PermissionDenied,
            ),
            (vec![hardlink("h", "missing")], OciErrorCode::NotFound),
            (
                vec![symlink("s", "orig"), hardlink("h", "s")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![dir("d/", 0o755), hardlink("h", "d")],
                OciErrorCode::PermissionDenied,
            ),
        ] {
            let sb = Sandbox::new();
            assert_eq!(code(run(&sb, &es)), want);
            sb.assert_outside_untouched();
        }
    }

    /// OCI-1: デバイス・FIFO は拒否する。
    #[test]
    fn oci1_special_entries_are_rejected() {
        for ty in [EntryType::Char, EntryType::Block, EntryType::Fifo] {
            let sb = Sandbox::new();
            let e = raw_entry(b"dev", ty, b"", 0o644, 0, b"");
            assert_eq!(
                code(run(&sb, &[e])),
                OciErrorCode::PermissionDenied,
                "{ty:?}"
            );
            assert!(!sb.root.join("dev").exists());
        }
    }

    /// OCI-1: sparse エントリは拒否する（tar 側の解析で不正な sparse ヘッダとして DataLoss になる）。
    #[test]
    fn oci1_sparse_entry_is_rejected() {
        let sb = Sandbox::new();
        let e = raw_entry(b"sp", EntryType::GNUSparse, b"", 0o644, 0, b"");
        assert_eq!(code(run(&sb, &[e])), OciErrorCode::DataLoss);
        assert!(!sb.root.join("sp").exists());
    }

    /// OCI-1: 後勝ち・ディレクトリ上へのファイルは拒否・長いパス（GNU long name）。
    #[test]
    fn oci1_duplicates_and_long_names() {
        let sb = Sandbox::new();
        run(&sb, &[file("f", 0o644, b"one"), file("f", 0o644, b"two")]).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"two");

        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[dir("d/", 0o755), file("d", 0o644, b"x")])),
            OciErrorCode::FailedPrecondition
        );

        let sb = Sandbox::new();
        let long: String = (0..8)
            .map(|i| format!("{}{i}/", "d".repeat(60)))
            .collect::<String>()
            + "leaf";
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"ok"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        extract_tar(bytes.as_slice(), &sb.root, ExtractLimits::new(10, 100)).unwrap();
        assert_eq!(fs::read(sb.root.join(&long)).unwrap(), b"ok");
    }

    /// OCI-1: 途中で切れた tar は DataLoss。
    #[test]
    fn oci1_truncated_tar_is_data_loss() {
        let sb = Sandbox::new();
        let mut bytes = archive(&[file("f", 0o644, &[7u8; 2000])]);
        bytes.truncate(512 + 700);
        let e = extract_tar(bytes.as_slice(), &sb.root, ExtractLimits::new(10, 1 << 20))
            .expect_err("truncated");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// OCI-1: gzip トレーラ破損は終端後の読み捨てで DataLoss になる。上限は gzip 側でも効く。
    #[test]
    fn oci1_gzip_trailer_is_verified_after_tar_end() {
        use crate::layer::GzipLayerReader;
        let tar_bytes = archive(&[file("f", 0o644, b"hello")]);
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar_bytes).unwrap();
        let gz = e.finish().unwrap();

        let sb = Sandbox::new();
        let r = extract_tar(
            GzipLayerReader::new(gz.as_slice(), 1 << 20),
            &sb.root,
            ExtractLimits::new(10, 100),
        )
        .unwrap();
        assert_eq!(r.bytes, 5);

        let mut bad = gz.clone();
        let n = bad.len();
        bad[n - 8] ^= 0xff; // CRC32 を壊す。
        let sb = Sandbox::new();
        let e = extract_tar(
            GzipLayerReader::new(bad.as_slice(), 1 << 20),
            &sb.root,
            ExtractLimits::new(10, 100),
        )
        .expect_err("crc");
        assert_eq!(e.code(), OciErrorCode::DataLoss);

        let sb = Sandbox::new();
        let e = extract_tar(
            GzipLayerReader::new(gz.as_slice(), 600),
            &sb.root,
            ExtractLimits::new(10, 100),
        )
        .expect_err("gzip limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// REPAIR-4: 成功と失敗でそれぞれ 1 件、種別 `oci.layer.extract` が記録される。
    #[test]
    fn repair4_records_extract_operation() {
        let c = Collect::default();
        let sb = Sandbox::new();
        extract_tar_with(
            &c,
            archive(&[file("f", 0o644, b"x")]).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 10),
        )
        .unwrap();
        extract_tar_with(
            &c,
            archive(&[file("../f", 0o644, b"x")]).as_slice(),
            &sb.root,
            ExtractLimits::new(10, 10),
        )
        .unwrap_err();
        let items = c.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind().as_str(), "oci.layer.extract");
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }

    /// root が通常ファイルなら InvalidArgument。
    #[test]
    fn root_must_be_directory() {
        let sb = Sandbox::new();
        let f = sb.base.join("sentinel");
        let e = extract_tar(archive(&[]).as_slice(), &f, ExtractLimits::new(1, 1)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// 非 unix ホストでは symlink エントリを Unimplemented で拒否する。
    #[cfg(not(unix))]
    #[test]
    fn symlink_is_unimplemented_on_non_unix() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("a", "b")])),
            OciErrorCode::Unimplemented
        );
    }
}
