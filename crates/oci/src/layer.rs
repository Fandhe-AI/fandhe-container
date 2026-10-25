//! 取得済み blob の sha256 digest 検証（TASK-52.1・OCI-1・MS-4・#405）。
//!
//! `RegistryClient::fetch_blob`（TASK-51.4）が保存した blob はサイズ検証のみで、本文のハッシュは
//! descriptor の digest と未突合である。このモジュールはファイルを固定長バッファで読んで sha256 を計算し、
//! 参照 digest と完全一致しなければ `DataLoss` で拒否する（fail-closed。ソフトウェアとデータの完全性）。
//!
//! 呼び出し契約: layer 展開（TASK-52.x）やキャッシュ公開の前に、呼び出し側が本検証を通すこと。
//! イメージの展開へ渡す blob は、検証済みを型で表す `VerifiedLayerBlob`（下記）で作る（#2309）。
//! 検証対象は呼び出し側が管理するステージング領域のファイル（pull では `PullSession` の `<root>/staging/<pull-id>/`。#474）とし、パスはエラー文言に載せない。
//! 未実装（後続 issue）: `fetch_blob` 内への組み込み、manifest 本文の digest 突合。tar 展開は子モジュール `extract` に実装済みで、キャッシュ格納と展開の配線は cri の `image_pull` が担う（#2323）。
//!
//! 開いたハンドルでの検証（OCI-1・#446）: 呼び出し側が blob の所有者・権限・ハードリンク数を確認してから
//! 内容を検証する場合（`fandhe-container-cri` の `PullImage` のキャッシュ再利用・公開）は、
//! `open_blob_nofollow` で最終要素の symlink を辿らずに開き、そのハンドルのメタデータを確認したうえで
//! `verify_blob_file_digest` に同じハンドルを渡す。パスを再解決しないため、確認と読み取りの間に
//! 別のファイルへ差し替えられない。個別の関数（`open_blob_nofollow`・`verify_blob_file_digest`）は信頼条件を判定しない。
//! 信頼条件・digest・サイズを同じハンドルで確かめる入口が `VerifiedLayerBlob::open` で、イメージ展開
//! （`extract::extract_image_layers`）はこの値だけを受ける（#2309）。パスを受ける `verify_blob_digest(_with)`・
//! `verify_fetched_blob(_with)`・`open_gzip_layer`・`decompress_layer_to_writer(_with)` は、呼び出し側が排他的に所有する
//! 0700 のステージングにある blob に限る部品で、キャッシュの再利用と展開には使わない。
//!
//! gzip 展開（TASK-52.2・OCI-1・#407）: digest 検証済みの圧縮 blob を `GzipLayerReader` で逐次展開し、
//! 後続の tar 展開（TASK-52.3）へ tar バイトストリームとして渡す。展開後サイズの上限は必須引数で、
//! 超過した最初の読み取りで中断する（decompression bomb 対策。メモリ使用量は展開サイズに依存しない）。
//! 呼び出し契約: 展開の前に `verify_blob_digest`（ステージングのパス）か `VerifiedLayerBlob::open` を通すこと。digest は圧縮 blob に対する値であり、
//! 展開後 tar の diff_id（config の `rootfs.diff_ids`）との突合は `extract::extract_image_layers` が行う
//! （#2017・OCI-1）。gzip トレーラ（CRC32・ISIZE）は EOF まで読み切ったときにだけ検証されるため、
//! tar 側は EOF まで読むこと。
//!
//! レイヤーの `mediaType` による入口の選択（#2017・OCI-1）: `LayerMediaType::parse` が gzip / 非圧縮 tar を
//! 区別し、非圧縮は `PlainLayerReader`（gzip と同じ展開後サイズ上限つき）で開く。zstd など未対応の
//! `mediaType` は推測で開かず `Unimplemented` で拒否する（zstd 対応の要否は #2029 で判断）。
//!
//! tar 展開（TASK-52.3・OCI-1・#409）は子モジュール `extract` が担う（呼び出し契約と未実装項目はそちらを参照）。
//! 複数レイヤーの重ね合わせ展開（TASK-52.4・#410）も同モジュールの `extract_layers` / `extract_layer_blobs`。

mod anchored;
pub mod extract;
pub mod idmap;
mod rootfs_read;

pub use rootfs_read::read_rootfs_file;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use anchored::remove_name_tree;

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek as _, SeekFrom, Write};
use std::path::Path;

use flate2::read::MultiGzDecoder;
use sha2::{Digest as _, Sha256};

use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::manifest::{
    MEDIA_TYPE_DOCKER_LAYER_FOREIGN_GZIP, MEDIA_TYPE_DOCKER_LAYER_GZIP, MEDIA_TYPE_OCI_LAYER_GZIP,
    MEDIA_TYPE_OCI_LAYER_NONDIST_GZIP, MEDIA_TYPE_OCI_LAYER_NONDIST_TAR, MEDIA_TYPE_OCI_LAYER_TAR,
};
use crate::reference::Digest;
use crate::registry::FetchedBlob;

/// 読み込みバッファ長（メモリ使用量を入力サイズに依存させない）。
const HASH_BUF_LEN: usize = 64 * 1024;

/// digest 検証に成功した blob（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedBlob {
    /// 本文から計算し、参照 digest と一致を確認した digest。
    pub digest: Digest,
    /// 読み取ったバイト数。
    pub size: u64,
}

/// 書き手のいない FIFO 等で `open` が無期限に止まらないよう、Unix では非ブロッキングで開く（REPAIR-5）。
/// 通常ファイルの読み取りには影響しない。値は OS ごとの `O_NONBLOCK`（libc 依存を増やさないため定数で持つ）。
#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;

/// 種別確認前にブロックしない設定で blob ファイルを開く。
fn open_blob(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(O_NONBLOCK);
    }
    opts.open(path)
}

/// blob ファイルを開き、同一ハンドルで通常ファイルであることを確認する（FIFO 等で読みがブロックするのを避ける）。
fn open_regular_blob(path: &Path) -> Result<File, OciError> {
    let file = open_blob(path).map_err(map_io_error)?;
    let meta = file.metadata().map_err(map_io_error)?;
    if !meta.is_file() {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "blob path is not a regular file",
        ));
    }
    Ok(file)
}

/// 最終要素の symlink を辿らずに、通常ファイルの blob を読み取り専用で開く（OCI-1・#446）。
///
/// 呼び出し側（`fandhe-container-cri` の `PullImage`）は、返ったハンドルの `metadata`（fstat）で所有者・権限・
/// ハードリンク数を確認し、同じハンドルを [`verify_blob_file_digest`] へ渡す。手順は次のとおり。
///
/// 1. `symlink_metadata`（lstat）で通常ファイルであることを確認する（symlink・FIFO・デバイス等は開かずに拒否する）
/// 2. 非ブロッキングで開く（1 の後に FIFO へ差し替えられても `open` が止まらない。REPAIR-5）
/// 3. 開いたハンドルの fstat と、開いた後に取り直した lstat の `dev` / `ino` が一致し、どちらも通常ファイルで
///    あることを確認する。ハンドルを保持している間は inode が再利用されないため、一致すれば `path` の
///    エントリ自身が開いたファイルであり、symlink を辿った先ではないと言える
///
/// `O_NOFOLLOW` を使わないのは、値が OS・アーキテクチャごとに異なり（Linux でも x86_64 と aarch64 で違う）、
/// libc 依存なしに全ターゲットの値を持つと取り違えの余地が増えるため。`dev` / `ino` の照合は Unix 共通で書ける。
///
/// エラー: 存在しなければ `NotFound`、通常ファイルでなければ（symlink を含む）`InvalidArgument`、
/// 開く間に差し替えられたら `FailedPrecondition`。
/// 非 Unix: 標準ライブラリの安定版 API ではファイルの同一性（`dev` / `ino` 相当）を取得できず、symlink を
/// 辿っていないことを確認できないため、開かずに `Unimplemented` で拒否する（fail-closed）。
pub fn open_blob_nofollow(path: &Path) -> Result<File, OciError> {
    open_blob_nofollow_inner(path, &|| {}, &|| {})
}

/// [`open_blob_nofollow`] の本体。`after_precheck` は手順 1 と 2 の間、`after_open` は手順 2 と 3 の間で呼ばれ、
/// 試験が各時点での差し替えを再現するために使う（本番の呼び出しは何もしない）。
#[cfg(unix)]
fn open_blob_nofollow_inner(
    path: &Path,
    after_precheck: &dyn Fn(),
    after_open: &dyn Fn(),
) -> Result<File, OciError> {
    use std::os::unix::fs::MetadataExt as _;
    let not_regular = || {
        OciError::new(
            OciErrorCode::InvalidArgument,
            "blob path is not a regular file",
        )
    };
    let before = std::fs::symlink_metadata(path).map_err(map_io_error)?;
    if !before.file_type().is_file() {
        return Err(not_regular());
    }
    after_precheck();
    let file = open_blob(path).map_err(map_io_error)?;
    let opened = file.metadata().map_err(map_io_error)?;
    after_open();
    let after = std::fs::symlink_metadata(path).map_err(map_io_error)?;
    if !opened.file_type().is_file() || !after.file_type().is_file() {
        return Err(not_regular());
    }
    if (opened.dev(), opened.ino()) != (after.dev(), after.ino()) {
        return Err(OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob path changed while opening",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_blob_nofollow_inner(
    _path: &Path,
    _after_precheck: &dyn Fn(),
    _after_open: &dyn Fn(),
) -> Result<File, OciError> {
    Err(OciError::new(
        OciErrorCode::Unimplemented,
        "symlink-safe blob open is not supported on this platform",
    ))
}

/// 計装なしの `verify_blob_digest_with`（`NoopOciOpRecorder`）。
pub fn verify_blob_digest(
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest_with(&NoopOciOpRecorder, path, expected, max_bytes)
}

/// 検証全体（open 失敗を含む）を `OciOpKind::VerifyBlobDigest` として `recorder` へ記録する（REPAIR-4）。
pub fn verify_blob_digest_with(
    recorder: &dyn OciOpRecorder,
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    record_oci_op(recorder, OciOpKind::VerifyBlobDigest, || {
        verify_blob_digest_inner(path, expected, max_bytes)
    })
}

/// `path` の blob の sha256 を計算し `expected` と比較する（OCI-1）。
///
/// `max_bytes` は読み取り上限で、呼び出し側は `descriptor.size` または `RegistryClientConfig::max_blob_bytes`
/// を渡す。超過は `ResourceExhausted`、不一致は `DataLoss`、通常ファイル以外は `InvalidArgument`。
fn verify_blob_digest_inner(
    path: &Path,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    let file = open_regular_blob(path)?;
    digest_of_open_blob(&file, expected, max_bytes)
}

/// 計装なしの `verify_blob_file_digest_with`（`NoopOciOpRecorder`）。
pub fn verify_blob_file_digest(
    file: &File,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    verify_blob_file_digest_with(&NoopOciOpRecorder, file, expected, max_bytes)
}

/// 開いた blob ファイルのハンドルの内容を `expected` と比較する（OCI-1・#446）。検証全体を
/// `OciOpKind::VerifyBlobDigest` として `recorder` へ記録する（REPAIR-4）。
///
/// [`verify_blob_digest_with`] と違いパスを開き直さない。呼び出し側がハンドルのメタデータ（所有者・権限・
/// ハードリンク数）を確認した、そのファイル自身の内容を検証するための入口（[`open_blob_nofollow`] と組で使う）。
/// ハンドルが通常ファイルでなければ `InvalidArgument`。読み取り位置は先頭へ戻してから読むため、
/// 呼び出し前の位置に依らず全体を検証する（検証後の位置は末尾）。`max_bytes`・不一致の扱いは
/// `verify_blob_digest` と同じ。
pub fn verify_blob_file_digest_with(
    recorder: &dyn OciOpRecorder,
    file: &File,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    record_oci_op(recorder, OciOpKind::VerifyBlobDigest, || {
        verify_blob_file_digest_inner(file, expected, max_bytes)
    })
}

/// 計装なしのハンドル検証本体（[`verify_blob_file_digest_with`] と [`VerifiedLayerBlob::open_with`] が
/// それぞれ自分の計装の内側で呼ぶ。二重に記録しないため記録を持たない）。
fn verify_blob_file_digest_inner(
    file: &File,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    let meta = file.metadata().map_err(map_io_error)?;
    if !meta.is_file() {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "blob path is not a regular file",
        ));
    }
    let mut handle = file;
    handle.seek(SeekFrom::Start(0)).map_err(map_io_error)?;
    digest_of_open_blob(file, expected, max_bytes)
}

/// 開いたハンドルを現在位置から EOF まで読み、sha256 を `expected` と比較する（パス・ハンドル両入口の共通部）。
fn digest_of_open_blob(
    file: &File,
    expected: &Digest,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    let (hex, size) = sha256_hex_of_reader(file, max_bytes)?;
    let actual = format!("sha256:{hex}");
    if actual != expected.as_str() {
        return Err(OciError::new(
            OciErrorCode::DataLoss,
            "blob digest does not match the descriptor",
        ));
    }
    Ok(VerifiedBlob {
        digest: Digest::parse(&actual)?,
        size,
    })
}

/// メモリ上のバイト列の sha256 を `expected` と比較する（OCI-1・#2433）。
///
/// config のように「読んだバイト列そのものを解析する」入力で、照合と解析の対象がずれないようにするための入口
/// （別経路で digest を確かめてから再度読み直すと、その間の差し替えが解析結果に混ざる）。
/// 不一致は `DataLoss`。呼び出し側が長さの上限を先に確かめてから渡すこと。
pub fn verify_bytes_digest(bytes: &[u8], expected: &Digest) -> Result<(), OciError> {
    let (hex, _) = sha256_hex_of_reader(bytes, u64::MAX)?;
    if format!("sha256:{hex}") != expected.as_str() {
        return Err(OciError::new(
            OciErrorCode::DataLoss,
            "blob digest does not match the descriptor",
        ));
    }
    Ok(())
}

/// `fetch_blob` の戻り値を、要求した digest に対して検証する薄いラッパー。
pub fn verify_fetched_blob(blob: &FetchedBlob, max_bytes: u64) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest(&blob.path, &blob.digest, max_bytes)
}

/// 計装つきの `verify_fetched_blob`。
pub fn verify_fetched_blob_with(
    recorder: &dyn OciOpRecorder,
    blob: &FetchedBlob,
    max_bytes: u64,
) -> Result<VerifiedBlob, OciError> {
    verify_blob_digest_with(recorder, &blob.path, &blob.digest, max_bytes)
}

/// 公開してよい blob の信頼条件の違反を返す（OCI-1・SEC。unix のみ。違反なしは `None`）。
///
/// 条件は通常ファイル・所有者が `owner`・ハードリンク数 1（ストア外の名前から同じ inode を書き換えられない）・
/// group / other 書き込み不可。非 unix は所有者・リンク数を標準ライブラリで取得できないため通常ファイルかだけを見る。
pub(crate) fn blob_trust_violation(
    m: &std::fs::Metadata,
    owner: Option<u32>,
) -> Option<&'static str> {
    if !m.is_file() {
        return Some("blob is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if owner.is_some_and(|o| m.uid() != o) {
            return Some("blob has an unexpected owner");
        }
        if m.nlink() != 1 {
            return Some("blob has extra hard links");
        }
        if m.mode() & 0o022 != 0 {
            return Some("blob is writable by group or others");
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    None
}

/// 信頼条件と digest を同じハンドルで確かめたレイヤー blob（OCI-1・#2309）。イメージ展開の入口
/// （`extract::extract_image_layers` ほか）はこの値だけを受ける。
///
/// 「digest 検証済みの blob」という呼び出し契約を型で表す。構築経路は [`VerifiedLayerBlob::open`] の 1 本だけで、
/// `File` から直接作る経路は無い。構築では (1) [`open_blob_nofollow`] で symlink を辿らずに開き、(2) 同じハンドルの
/// fstat で信頼条件（通常ファイル・所有者・ハードリンク数 1・group / other 書き込み不可）を確かめ、(3) 同じハンドルを
/// [`verify_blob_file_digest`] で検証する。以後の展開はこのハンドルから読み、パスを開き直さないため、
/// 検証と展開の間にパスのエントリを別のファイルへ差し替えられても展開物は変わらない。
/// 同じ inode への上書きは展開側がパス 3 で diff_id を再計算して検出する（`DataLoss`）。
#[derive(Debug)]
#[non_exhaustive]
pub struct VerifiedLayerBlob {
    file: File,
    digest: Digest,
    size: u64,
}

impl VerifiedLayerBlob {
    /// 計装なしの [`VerifiedLayerBlob::open_with`]（`NoopOciOpRecorder`）。
    pub fn open(path: &Path, expected: &Digest, size: u64, owner: u32) -> Result<Self, OciError> {
        Self::open_with(&NoopOciOpRecorder, path, expected, size, owner)
    }

    /// `path` の blob を開いて信頼条件と digest を確かめる。open・信頼条件の検査・digest・サイズ照合の全体を
    /// `OciOpKind::VerifyBlobDigest` として一度だけ `recorder` へ記録する（失敗も記録。REPAIR-4）。
    ///
    /// `expected` と `size` は manifest の descriptor の `digest` と `size`。読み取り上限は `size` で、超過は
    /// `ResourceExhausted`、digest の不一致と実サイズが `size` と違う場合は `DataLoss`。`owner` は blob を置いた
    /// ストア（ステージング）の所有者の uid で、省略できない（fail-closed）。
    /// エラー: 存在しなければ `NotFound`、通常ファイルでなければ（symlink を含む）`InvalidArgument`、開く間の差し替えと
    /// 信頼条件の違反は `FailedPrecondition`。
    /// 非 Unix: ハンドルの同一性と所有者を標準ライブラリで確かめられないため、開かずに `Unimplemented` で拒否する。
    pub fn open_with(
        recorder: &dyn OciOpRecorder,
        path: &Path,
        expected: &Digest,
        size: u64,
        owner: u32,
    ) -> Result<Self, OciError> {
        record_oci_op(recorder, OciOpKind::VerifyBlobDigest, || {
            let file = open_blob_nofollow(path)?;
            let meta = file.metadata().map_err(map_io_error)?;
            if let Some(v) = blob_trust_violation(&meta, Some(owner)) {
                return Err(OciError::new(OciErrorCode::FailedPrecondition, v));
            }
            let verified = verify_blob_file_digest_inner(&file, expected, size)?;
            if verified.size != size {
                return Err(OciError::new(
                    OciErrorCode::DataLoss,
                    "layer blob size does not match the descriptor",
                ));
            }
            Ok(Self {
                file,
                digest: verified.digest,
                size: verified.size,
            })
        })
    }

    /// 検証済みの digest（descriptor の `digest` と一致した値）。
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// 検証済みのサイズ（descriptor の `size` と一致した値）。
    pub fn size(&self) -> u64 {
        self.size
    }

    /// 展開側が読み取りに使うハンドル（モジュール内限定。パスは持たない）。
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}

/// Reader を EOF まで読み、小文字 hex の sha256 と読み取りバイト数を返す。
fn sha256_hex_of_reader<R: Read>(mut r: R, max_bytes: u64) -> Result<(String, u64), OciError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io_error(e)),
        };
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "blob exceeds the size limit while hashing",
            ));
        }
        if let Some(chunk) = buf.get(..n) {
            hasher.update(chunk);
        }
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        // String への write は失敗しない。
        let _ = write!(hex, "{b:02x}");
    }
    Ok((hex, total))
}

/// I/O エラーを構造化エラーへ写す（パス・OS メッセージは載せない）。
fn map_io_error(e: std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::NotFound => OciError::new(OciErrorCode::NotFound, "blob file not found"),
        ErrorKind::PermissionDenied => {
            OciError::new(OciErrorCode::PermissionDenied, "blob file is not readable")
        }
        _ => OciError::new(OciErrorCode::Internal, "failed to read blob file"),
    }
}

/// 展開後サイズ上限の参考既定値（`RegistryClientConfig::max_blob_bytes` と同オーダーの 8 GiB）。
/// API は上限を必須引数にしており、上限なしの経路は提供しない。
pub const DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// gzip 展開に成功したレイヤーの結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecompressedLayer {
    /// 展開後（tar）のバイト数。
    pub size: u64,
}

/// レイヤー blob の `mediaType` から決まる読み取り方式（#2017・OCI-1）。
///
/// image-spec のレイヤー `mediaType` のうち対応するものだけを持つ。マジックバイトからの推測はしない
/// （宣言と実体が食い違えば、その後の gzip / tar 解析で失敗して拒否される）。
/// zstd（`...tar+zstd`）は #2029 の判断まで未対応で、[`LayerMediaType::parse`] が `Unimplemented` を返す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayerMediaType {
    /// 非圧縮の tar。
    Tar,
    /// gzip 圧縮の tar。
    TarGzip,
}

/// レイヤー `mediaType` の受理表の 1 行（#2311・OCI-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerMediaTypeEntry {
    /// `mediaType` の文字列（完全一致で照合する）。
    pub media_type: &'static str,
    /// 展開側（[`LayerMediaType::parse`]）が使う読み取り方式。
    pub kind: LayerMediaType,
    /// pull の事前拒否（`manifest::ensure_supported_layer_media_types`）が受けるか。
    pub pull: bool,
}

/// レイヤー `mediaType` の受理集合の単一の真実源（#2311・OCI-1）。
///
/// 展開側（[`LayerMediaType::parse`]）は全 6 行を受け、pull の事前拒否は `pull: true` の行だけを受ける。
/// 両者はこの表から導出するため、食い違いは表の `pull` 列に現れ、試験で固定する（pull は展開の部分集合）。
///
/// 暫定の決定（オーナー確認待ち）: pull は現状維持で gzip の 2 種のみ。理由は次のとおり。
/// - pull の受理範囲を広げない（fail-closed。#2037 の受け入れ条件を変えない）。
/// - nondistributable / foreign は descriptor の外部 `urls` を参照しうるが、registry の blob 取得は対応しない。
/// - 非圧縮 tar を pull で受けるかは #2037 の受け入れ条件の変更にあたるため、オーナーが判断する。
///
/// 展開側は検証済みハンドル（`VerifiedLayerBlob`）で渡された blob に限って 6 種を受ける。
/// zstd は #2029 の判断まで表に無い。
pub const LAYER_MEDIA_TYPES: &[LayerMediaTypeEntry] = &[
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_OCI_LAYER_TAR,
        kind: LayerMediaType::Tar,
        pull: false,
    },
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_OCI_LAYER_NONDIST_TAR,
        kind: LayerMediaType::Tar,
        pull: false,
    },
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_OCI_LAYER_GZIP,
        kind: LayerMediaType::TarGzip,
        pull: true,
    },
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_OCI_LAYER_NONDIST_GZIP,
        kind: LayerMediaType::TarGzip,
        pull: false,
    },
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_DOCKER_LAYER_GZIP,
        kind: LayerMediaType::TarGzip,
        pull: true,
    },
    LayerMediaTypeEntry {
        media_type: MEDIA_TYPE_DOCKER_LAYER_FOREIGN_GZIP,
        kind: LayerMediaType::TarGzip,
        pull: false,
    },
];

/// pull の事前拒否が受ける `mediaType` か（[`LAYER_MEDIA_TYPES`] の `pull` 列。完全一致）。
///
/// `manifest::ensure_supported_layer_media_types` から blob 取得前に呼ばれる。
pub(crate) fn is_pull_supported_layer_media_type(media_type: &str) -> bool {
    LAYER_MEDIA_TYPES
        .iter()
        .any(|e| e.pull && e.media_type == media_type)
}

impl LayerMediaType {
    /// `mediaType` 文字列（完全一致。パラメータ・大文字小文字の揺れは受けない）から読み取り方式を決める。
    ///
    /// [`LAYER_MEDIA_TYPES`] の表引き。表に無い値（zstd を含む）は `Unimplemented`。
    pub fn parse(media_type: &str) -> Result<Self, OciError> {
        LAYER_MEDIA_TYPES
            .iter()
            .find(|e| e.media_type == media_type)
            .map(|e| e.kind)
            .ok_or_else(|| {
                OciError::new(OciErrorCode::Unimplemented, "unsupported layer mediaType")
            })
    }
}

/// 展開後サイズ上限の超過を `io::Error` の source として運ぶ内部マーカー。
#[derive(Debug)]
struct LayerLimitExceeded;

impl std::fmt::Display for LayerLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("layer exceeds the uncompressed size limit")
    }
}

impl std::error::Error for LayerLimitExceeded {}

fn limit_exceeded_io_error() -> std::io::Error {
    std::io::Error::other(LayerLimitExceeded)
}

/// gzip（マルチメンバ対応）を逐次展開し、展開後サイズ上限を強制する `Read`（TASK-52.2・OCI-1）。
///
/// 後続の tar 展開（TASK-52.3）が tar パイプラインの入力として使う。上限と同じサイズは成功し、
/// 1 バイトでも超えると `io::Error` を返して以降も同じエラーを返し続ける（中断後に再開しない）。
/// I/O エラーは `oci_error_from_layer_io` で `OciError` へ写せる。tar 側は EOF まで読み切ること
/// （gzip トレーラの CRC32・ISIZE は EOF で検証される）。
pub struct GzipLayerReader<R: Read> {
    inner: MultiGzDecoder<R>,
    max: u64,
    total: u64,
    exceeded: bool,
}

impl<R: Read> GzipLayerReader<R> {
    /// 圧縮ストリーム `src` と展開後サイズの上限 `max_uncompressed_bytes` から作る。
    pub fn new(src: R, max_uncompressed_bytes: u64) -> Self {
        Self {
            inner: MultiGzDecoder::new(src),
            max: max_uncompressed_bytes,
            total: 0,
            exceeded: false,
        }
    }

    /// これまでに展開して返したバイト数。
    pub fn total_out(&self) -> u64 {
        self.total
    }
}

impl<R: Read> Read for GzipLayerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.exceeded {
            return Err(limit_exceeded_io_error());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.max.saturating_sub(self.total);
        if remaining == 0 {
            // 上限ちょうどまで読んだ後。続きが 1 バイトでもあれば超過、EOF なら成功（トレーラも検証される）。
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.exceeded = true;
                    Err(limit_exceeded_io_error())
                }
            };
        }
        let cap = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let Some(dst) = buf.get_mut(..cap) else {
            return Ok(0);
        };
        let n = self.inner.read(dst)?;
        self.total = self.total.saturating_add(n as u64);
        Ok(n)
    }
}

/// 非圧縮 tar レイヤーを逐次読み、`GzipLayerReader` と同じ上限規則（ちょうど上限は成功・超過は中断し
/// 以降も失敗）を強制する `Read`（#2017・OCI-1）。
pub struct PlainLayerReader<R: Read> {
    inner: R,
    max: u64,
    total: u64,
    exceeded: bool,
}

impl<R: Read> PlainLayerReader<R> {
    /// 入力 `src` と読み取りバイト数の上限 `max_bytes` から作る。
    pub fn new(src: R, max_bytes: u64) -> Self {
        Self {
            inner: src,
            max: max_bytes,
            total: 0,
            exceeded: false,
        }
    }

    /// これまでに返したバイト数。
    pub fn total_out(&self) -> u64 {
        self.total
    }
}

impl<R: Read> Read for PlainLayerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.exceeded {
            return Err(limit_exceeded_io_error());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.max.saturating_sub(self.total);
        if remaining == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.exceeded = true;
                    Err(limit_exceeded_io_error())
                }
            };
        }
        let cap = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let Some(dst) = buf.get_mut(..cap) else {
            return Ok(0);
        };
        let n = self.inner.read(dst)?;
        self.total = self.total.saturating_add(n as u64);
        Ok(n)
    }
}

/// レイヤー読み取りの `io::Error` を構造化エラーへ写す（tar 展開側も共用できる）。
///
/// 上限超過は `ResourceExhausted`、gzip の形式不正・CRC32 / ISIZE 不一致・途中切れは `DataLoss`、
/// それ以外は `Internal`。メッセージにパス・OS メッセージは載せない。
pub fn oci_error_from_layer_io(e: std::io::Error) -> OciError {
    if e.get_ref()
        .is_some_and(|s| s.downcast_ref::<LayerLimitExceeded>().is_some())
    {
        return OciError::new(
            OciErrorCode::ResourceExhausted,
            "layer exceeds the uncompressed size limit",
        );
    }
    match e.kind() {
        ErrorKind::InvalidData | ErrorKind::InvalidInput | ErrorKind::UnexpectedEof => {
            OciError::new(OciErrorCode::DataLoss, "layer gzip stream is corrupt")
        }
        _ => OciError::new(OciErrorCode::Internal, "failed to read layer stream"),
    }
}

/// 圧縮レイヤー blob を開いて `GzipLayerReader` を返す。通常ファイル以外は `InvalidArgument`。
pub fn open_gzip_layer(
    path: &Path,
    max_uncompressed_bytes: u64,
) -> Result<GzipLayerReader<File>, OciError> {
    let file = open_regular_blob(path)?;
    Ok(GzipLayerReader::new(file, max_uncompressed_bytes))
}

/// 計装なしの `decompress_layer_to_writer_with`（`NoopOciOpRecorder`）。
pub fn decompress_layer_to_writer<W: Write>(
    path: &Path,
    max_uncompressed_bytes: u64,
    dst: &mut W,
) -> Result<DecompressedLayer, OciError> {
    decompress_layer_to_writer_with(&NoopOciOpRecorder, path, max_uncompressed_bytes, dst)
}

/// 展開全体（open 失敗を含む）を `OciOpKind::DecompressLayer` として記録する（REPAIR-4）。
///
/// 失敗時（上限超過・破損）に `dst` へ書かれた分は不完全なため、呼び出し側が破棄する
/// （ステージング領域の一時ファイルへ書き、成功時のみ公開する契約）。`dst` への書き込みは
/// 上限以下に収まる。書き込み先のエラーは `Internal`。
pub fn decompress_layer_to_writer_with<W: Write>(
    recorder: &dyn OciOpRecorder,
    path: &Path,
    max_uncompressed_bytes: u64,
    dst: &mut W,
) -> Result<DecompressedLayer, OciError> {
    record_oci_op(recorder, OciOpKind::DecompressLayer, || {
        let mut r = open_gzip_layer(path, max_uncompressed_bytes)?;
        copy_decompressed(&mut r, dst)
    })
}

/// `r` を EOF まで固定長バッファで `dst` へ複写する。
fn copy_decompressed<R: Read, W: Write>(
    r: &mut GzipLayerReader<R>,
    dst: &mut W,
) -> Result<DecompressedLayer, OciError> {
    let mut buf = vec![0u8; HASH_BUF_LEN];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(oci_error_from_layer_io(e)),
        };
        if let Some(chunk) = buf.get(..n) {
            dst.write_all(chunk).map_err(|_| {
                OciError::new(OciErrorCode::Internal, "failed to write decompressed layer")
            })?;
        }
    }
    Ok(DecompressedLayer {
        size: r.total_out(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    const EMPTY: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const MSG: &str = "blob digest does not match the descriptor";

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-oci-layer-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn digest_of(data: &[u8]) -> Digest {
        let (hex, _) = sha256_hex_of_reader(data, u64::MAX).unwrap();
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    /// OCI-1: 既知ベクタで一致する。
    #[test]
    fn oci1_known_vectors_match() {
        let d = tmp_dir("known");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 10).unwrap();
        assert_eq!(v.digest.as_str(), ABC);
        assert_eq!(v.size, 3);
        std::fs::write(&p, b"").unwrap();
        let v = verify_blob_digest(&p, &Digest::parse(EMPTY).unwrap(), 10).unwrap();
        assert_eq!(v.size, 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: 改ざん（書き換え・追記・切り詰め）は DataLoss。
    #[test]
    fn oci1_tampered_blob_is_rejected() {
        let d = tmp_dir("tamper");
        let p = d.join("b");
        let original = b"hello blob".to_vec();
        let expected = digest_of(&original);
        let mut flipped = original.clone();
        flipped[0] ^= 1;
        let mut appended = original.clone();
        appended.push(0);
        let truncated = original[..original.len() - 1].to_vec();
        for data in [flipped, appended, truncated] {
            std::fs::write(&p, &data).unwrap();
            let e = verify_blob_digest(&p, &expected, 1024).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss);
            assert_eq!(e.code().as_str(), "DATA_LOSS");
            assert_eq!(e.message(), MSG);
        }
        std::fs::write(&p, &original).unwrap();
        assert!(verify_blob_digest(&p, &expected, 1024).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1: チャンク境界をまたぐ入力でも一貫する。
    #[test]
    fn oci1_multi_chunk_inputs() {
        let d = tmp_dir("chunks");
        let p = d.join("b");
        for len in [HASH_BUF_LEN, HASH_BUF_LEN + 1, HASH_BUF_LEN * 2] {
            let data = vec![0xa5u8; len];
            std::fs::write(&p, &data).unwrap();
            let v = verify_blob_digest(&p, &digest_of(&data), u64::MAX).unwrap();
            assert_eq!(v.size, len as u64);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_size_limit_exceeded() {
        let d = tmp_dir("limit");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let e = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 2).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 3).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oci1_missing_and_directory_paths() {
        let d = tmp_dir("paths");
        let e = verify_blob_digest(&d.join("none"), &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        // ディレクトリは OS により open 自体が失敗するか通常ファイルでないとして拒否される。
        let e = verify_blob_digest(&d, &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert!(matches!(
            e.code(),
            OciErrorCode::InvalidArgument | OciErrorCode::PermissionDenied | OciErrorCode::Internal
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    struct Flaky {
        step: u8,
    }
    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.step += 1;
            match self.step {
                1 => Err(io::Error::from(ErrorKind::Interrupted)),
                2 => {
                    buf[..3].copy_from_slice(b"abc");
                    Ok(3)
                }
                _ => Ok(0),
            }
        }
    }

    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn oci1_interrupted_is_retried_and_other_errors_propagate() {
        let (hex, n) = sha256_hex_of_reader(Flaky { step: 0 }, 10).unwrap();
        assert_eq!(format!("sha256:{hex}"), ABC);
        assert_eq!(n, 3);
        let e = sha256_hex_of_reader(Broken, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Internal);
    }

    #[test]
    fn oci1_verify_fetched_blob() {
        let d = tmp_dir("fetched");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let mut blob = FetchedBlob {
            path: p.clone(),
            size: 3,
            digest: Digest::parse(ABC).unwrap(),
        };
        assert_eq!(verify_fetched_blob(&blob, 10).unwrap().size, 3);
        blob.digest = Digest::parse(EMPTY).unwrap();
        let e = verify_fetched_blob(&blob, 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-5: 書き手のいない FIFO でも停止せず InvalidArgument で拒否する。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn oci1_fifo_does_not_hang() {
        let d = tmp_dir("fifo");
        let p = d.join("f");
        let st = std::process::Command::new("mkfifo").arg(&p).status();
        assert!(matches!(st, Ok(s) if s.success()), "mkfifo is required");
        let (tx, rx) = std::sync::mpsc::channel();
        let pc = p.clone();
        std::thread::spawn(move || {
            let r = verify_blob_digest(&pc, &Digest::parse(ABC).unwrap(), 10);
            let _ = tx.send(r);
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("verify must not block on a FIFO");
        assert_eq!(r.unwrap_err().code(), OciErrorCode::InvalidArgument);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: 開いたハンドルの内容を検証する。読み取り位置に依らず全体を読み、検証対象は
    /// パスではなくハンドルのファイルである（検証後にパスを差し替えても結果が変わらない）。
    #[test]
    fn oci1_verify_blob_file_digest_reads_the_given_handle() {
        let d = tmp_dir("handle");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let mut f = File::open(&p).unwrap();
        let mut head = [0u8; 2];
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"ab");
        let v = verify_blob_file_digest(&f, &Digest::parse(ABC).unwrap(), 3).unwrap();
        assert_eq!(v.digest.as_str(), ABC);
        assert_eq!(v.size, 3);

        // パスを別内容のファイルへ差し替える（rename）。ハンドルは元のファイルを指したまま。
        std::fs::write(d.join("other"), b"tampered").unwrap();
        std::fs::rename(d.join("other"), &p).unwrap();
        let v = verify_blob_file_digest(&f, &Digest::parse(ABC).unwrap(), 3).unwrap();
        assert_eq!(v.size, 3);
        let e = verify_blob_digest(&p, &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);

        let e = verify_blob_file_digest(&f, &Digest::parse(EMPTY).unwrap(), 3).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), MSG);
        let e = verify_blob_file_digest(&f, &Digest::parse(ABC).unwrap(), 2).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: ハンドルが通常ファイルでなければ（ディレクトリ）読まずに InvalidArgument。
    #[cfg(unix)]
    #[test]
    fn oci1_verify_blob_file_digest_rejects_non_regular_handle() {
        let d = tmp_dir("handle-dir");
        let dir_handle = File::open(&d).unwrap();
        let e = verify_blob_file_digest(&dir_handle, &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert_eq!(e.message(), "blob path is not a regular file");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-4・#446: ハンドル入口の検証も成功・DataLoss が 1 件ずつ記録される。
    #[test]
    fn oci1_verify_blob_file_digest_is_recorded() {
        use crate::instrument::OciOpOutcome;
        let d = tmp_dir("handle-rec");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let f = File::open(&p).unwrap();
        let c = Collect::default();
        verify_blob_file_digest_with(&c, &f, &Digest::parse(ABC).unwrap(), 10).unwrap();
        verify_blob_file_digest_with(&c, &f, &Digest::parse(EMPTY).unwrap(), 10).unwrap_err();
        let v = c.0.lock().unwrap();
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|s| s.kind() == OciOpKind::VerifyBlobDigest));
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::DataLoss));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-4・#2309: `VerifiedLayerBlob::open_with` は open 失敗・短い blob（digest 一致でもサイズ不一致）を
    /// 含め、成功 1 件または失敗 1 件だけを記録する（成功の後に DataLoss を返さない）。
    #[cfg(unix)]
    #[test]
    fn repair4_verified_layer_blob_open_records_once_including_failures() {
        use crate::instrument::OciOpOutcome;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let d = tmp_dir("vlb-rec");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = std::fs::metadata(&p).unwrap().uid();
        let abc = Digest::parse(ABC).unwrap();

        let c = Collect::default();
        VerifiedLayerBlob::open_with(&c, &p, &abc, 3, uid).unwrap();
        VerifiedLayerBlob::open_with(&c, &d.join("missing"), &abc, 3, uid).unwrap_err();
        let e = VerifiedLayerBlob::open_with(&c, &p, &abc, 10, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        let e = VerifiedLayerBlob::open_with(&c, &p, &abc, 3, uid.wrapping_add(1)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let v = c.0.lock().unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::NotFound));
        assert_eq!(v[2].error_code(), Some(OciErrorCode::DataLoss));
        assert_eq!(v[3].error_code(), Some(OciErrorCode::FailedPrecondition));
        drop(v);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: 通常ファイルは開け、symlink（先が通常ファイルでも）・ディレクトリ・未存在は拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_open_blob_nofollow_rejects_symlink_and_non_regular() {
        let d = tmp_dir("nofollow");
        let real = d.join("real");
        std::fs::write(&real, b"abc").unwrap();
        let f = open_blob_nofollow(&real).unwrap();
        let v = verify_blob_file_digest(&f, &Digest::parse(ABC).unwrap(), 3).unwrap();
        assert_eq!(v.size, 3);

        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = open_blob_nofollow(&link).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert_eq!(e.message(), "blob path is not a regular file");

        let e = open_blob_nofollow(&d).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        let e = open_blob_nofollow(&d.join("none")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: lstat の後に symlink へ差し替えられても、辿った先のファイルを返さない（TOCTOU）。
    #[cfg(unix)]
    #[test]
    fn oci1_open_blob_nofollow_rejects_symlink_swapped_in_after_precheck() {
        let d = tmp_dir("nofollow-swap");
        let outside = d.join("outside");
        std::fs::write(&outside, b"abc").unwrap();
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let swap = || {
            std::fs::remove_file(&p).unwrap();
            std::os::unix::fs::symlink(&outside, &p).unwrap();
        };
        let e = open_blob_nofollow_inner(&p, &swap, &|| {}).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert_eq!(e.message(), "blob path is not a regular file");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: open の後にパスが別の通常ファイルへ差し替えられたら（dev / ino 不一致）FailedPrecondition。
    /// lstat と open の間の差し替えは、差し替え後のファイル自身を開くため受理する（ハンドルとパスが一致する）。
    #[cfg(unix)]
    #[test]
    fn oci1_open_blob_nofollow_detects_replacement_by_identity() {
        let d = tmp_dir("nofollow-ident");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let replace = || {
            std::fs::write(d.join("other"), b"").unwrap();
            std::fs::rename(d.join("other"), &p).unwrap();
        };
        let e = open_blob_nofollow_inner(&p, &|| {}, &replace).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob path changed while opening");

        std::fs::write(&p, b"abc").unwrap();
        let f = open_blob_nofollow_inner(&p, &replace, &|| {}).unwrap();
        let v = verify_blob_file_digest(&f, &Digest::parse(EMPTY).unwrap(), 10).unwrap();
        assert_eq!(v.size, 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-5・#446: FIFO は開かずに拒否し、lstat の後に FIFO へ差し替えられても open で止まらない。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn oci1_open_blob_nofollow_does_not_hang_on_fifo() {
        let d = tmp_dir("nofollow-fifo");
        let fifo = d.join("f");
        let st = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(matches!(st, Ok(s) if s.success()), "mkfifo is required");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (fifo_c, p_c) = (fifo.clone(), p.clone());
        std::thread::spawn(move || {
            let direct = open_blob_nofollow(&fifo_c).map(|_| ());
            let swap = || {
                std::fs::remove_file(&p_c).unwrap();
                let st = std::process::Command::new("mkfifo").arg(&p_c).status();
                assert!(matches!(st, Ok(s) if s.success()), "mkfifo is required");
            };
            let swapped = open_blob_nofollow_inner(&p_c, &swap, &|| {}).map(|_| ());
            let _ = tx.send((direct, swapped));
        });
        let (direct, swapped) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("open must not block on a FIFO");
        assert_eq!(direct.unwrap_err().code(), OciErrorCode::InvalidArgument);
        assert_eq!(swapped.unwrap_err().code(), OciErrorCode::InvalidArgument);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#446: 非 Unix では symlink を辿っていないことを確認できないため、開かずに Unimplemented で拒否する。
    #[cfg(not(unix))]
    #[test]
    fn oci1_open_blob_nofollow_is_rejected_without_file_identity() {
        let d = tmp_dir("nofollow-nonunix");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let e = open_blob_nofollow(&p).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[derive(Debug, Default)]
    struct Collect(std::sync::Mutex<Vec<crate::instrument::OciOpSample>>);
    impl OciOpRecorder for Collect {
        fn record_oci_op(&self, s: &crate::instrument::OciOpSample) {
            self.0.lock().unwrap().push(*s);
        }
    }

    /// REPAIR-4: 成功・DataLoss・open 失敗がそれぞれ 1 件記録される。
    #[test]
    fn oci1_verify_is_recorded() {
        use crate::instrument::OciOpOutcome;
        let d = tmp_dir("rec");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let c = Collect::default();
        verify_blob_digest_with(&c, &p, &Digest::parse(ABC).unwrap(), 10).unwrap();
        verify_blob_digest_with(&c, &p, &Digest::parse(EMPTY).unwrap(), 10).unwrap_err();
        verify_blob_digest_with(&c, &d.join("none"), &Digest::parse(ABC).unwrap(), 10).unwrap_err();
        let v = c.0.lock().unwrap();
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|s| s.kind() == OciOpKind::VerifyBlobDigest));
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[0].error_code(), None);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::DataLoss));
        assert_eq!(v[2].error_code(), Some(OciErrorCode::NotFound));
        std::fs::remove_dir_all(&d).unwrap();
    }

    // ---- gzip 展開（TASK-52.2・OCI-1） ----

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn decompress_bytes(
        gzdata: &[u8],
        max: u64,
        tag: &str,
    ) -> (Result<DecompressedLayer, OciError>, Vec<u8>) {
        let d = tmp_dir(tag);
        let p = d.join("l");
        std::fs::write(&p, gzdata).unwrap();
        let mut out = Vec::new();
        let r = decompress_layer_to_writer(&p, max, &mut out);
        std::fs::remove_dir_all(&d).unwrap();
        (r, out)
    }

    /// OCI-1: tar 風 512 バイトブロックとチャンク境界をまたぐ入力が一致して展開される。
    #[test]
    fn oci1_gzip_roundtrip() {
        for len in [
            0usize,
            512,
            1536,
            HASH_BUF_LEN - 1,
            HASH_BUF_LEN,
            HASH_BUF_LEN + 1,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (r, out) = decompress_bytes(&gz(&data), u64::MAX, &format!("gzrt{len}"));
            assert_eq!(r.unwrap().size, len as u64);
            assert_eq!(out, data);
        }
    }

    /// OCI-1: マルチメンバ gzip は連結結果として展開される。
    #[test]
    fn oci1_gzip_multi_member() {
        let mut z = gz(b"hello ");
        z.extend(gz(b"world"));
        let (r, out) = decompress_bytes(&z, 100, "gzmm");
        assert_eq!(r.unwrap().size, 11);
        assert_eq!(out, b"hello world");
    }

    /// OCI-1: 上限と同じサイズは成功し、上限 + 1 は ResourceExhausted。
    #[test]
    fn oci1_gzip_limit_boundary() {
        let z = gz(&[7u8; 1000]);
        let (r, out) = decompress_bytes(&z, 1000, "gzlb1");
        assert_eq!(r.unwrap().size, 1000);
        assert_eq!(out.len(), 1000);
        let (r, out) = decompress_bytes(&z, 999, "gzlb2");
        let e = r.unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the uncompressed size limit");
        assert_eq!(out.len(), 999);
    }

    /// OCI-1: decompression bomb は上限で中断し、書き込み量が上限を超えない。
    #[test]
    fn oci1_gzip_bomb_is_aborted() {
        let z = gz(&vec![0u8; 8 * 1024 * 1024]);
        assert!(z.len() < 64 * 1024);
        let max = 1024 * 1024;
        let (r, out) = decompress_bytes(&z, max, "gzbomb");
        assert_eq!(r.unwrap_err().code(), OciErrorCode::ResourceExhausted);
        assert_eq!(out.len() as u64, max);
    }

    /// OCI-1: 破損入力（マジック違い・途中切れ・CRC32/ISIZE 改ざん・平文）は DataLoss。
    #[test]
    fn oci1_gzip_corrupt_inputs() {
        let good = gz(&vec![1u8; 4096]);
        let n = good.len();
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xff;
        let mut bad_crc = good.clone();
        bad_crc[n - 8] ^= 1;
        let mut bad_isize = good.clone();
        bad_isize[n - 1] ^= 1;
        let cases = [
            bad_magic,
            good[..5].to_vec(),
            good[..n / 2].to_vec(),
            bad_crc,
            bad_isize,
            vec![b'x'; 1024],
        ];
        for (i, c) in cases.iter().enumerate() {
            let (r, _) = decompress_bytes(c, u64::MAX, &format!("gzbad{i}"));
            let e = r.unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss, "case={i}");
            assert_eq!(e.message(), "layer gzip stream is corrupt");
        }
    }

    /// OCI-1: 上限超過後の read は再開せずエラーを返し続ける。
    #[test]
    fn oci1_gzip_reader_does_not_resume_after_limit() {
        let z = gz(&[3u8; 100]);
        let mut r = GzipLayerReader::new(&z[..], 10);
        let mut buf = [0u8; 64];
        assert_eq!(r.read(&mut buf).unwrap(), 10);
        for _ in 0..3 {
            let e = r.read(&mut buf).unwrap_err();
            assert_eq!(
                oci_error_from_layer_io(e).code(),
                OciErrorCode::ResourceExhausted
            );
        }
    }

    /// OCI-1・REPAIR-4: open 失敗と計装（成功・上限超過・破損が 1 件ずつ）。
    #[test]
    fn oci1_gzip_paths_and_recording() {
        use crate::instrument::OciOpOutcome;
        let d = tmp_dir("gzrec");
        let p = d.join("l");
        std::fs::write(&p, gz(b"abc")).unwrap();
        let c = Collect::default();
        let mut out = Vec::new();
        decompress_layer_to_writer_with(&c, &p, 10, &mut out).unwrap();
        decompress_layer_to_writer_with(&c, &p, 2, &mut out).unwrap_err();
        std::fs::write(&p, b"not gzip").unwrap();
        decompress_layer_to_writer_with(&c, &p, 10, &mut out).unwrap_err();
        let e = decompress_layer_to_writer(&d.join("none"), 10, &mut out).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        let v = c.0.lock().unwrap();
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|s| s.kind() == OciOpKind::DecompressLayer));
        assert_eq!(v[0].outcome(), OciOpOutcome::Success);
        assert_eq!(v[1].error_code(), Some(OciErrorCode::ResourceExhausted));
        assert_eq!(v[2].error_code(), Some(OciErrorCode::DataLoss));
        drop(v);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// REPAIR-5: 書き手のいない FIFO でも gzip 展開は停止せず InvalidArgument。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn oci1_gzip_fifo_does_not_hang() {
        let d = tmp_dir("gzfifo");
        let p = d.join("f");
        let st = std::process::Command::new("mkfifo").arg(&p).status();
        assert!(matches!(st, Ok(s) if s.success()), "mkfifo is required");
        let e = open_gzip_layer(&p, 10).err().expect("must reject a FIFO");
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// 下位 reader の I/O エラーは Internal、正常系の複写は具体値で一致する。
    #[test]
    fn oci1_gzip_io_error_mapping() {
        let e = oci_error_from_layer_io(io::Error::from(ErrorKind::BrokenPipe));
        assert_eq!(e.code(), OciErrorCode::Internal);
        let mut r = GzipLayerReader::new(Broken, 10);
        let e = r.read(&mut [0u8; 8]).unwrap_err();
        assert_eq!(oci_error_from_layer_io(e).code(), OciErrorCode::Internal);
        let z = gz(b"abc");
        let mut ok = GzipLayerReader::new(&z[..], 10);
        let mut out = Vec::new();
        assert_eq!(copy_decompressed(&mut ok, &mut out).unwrap().size, 3);
        assert_eq!(out, b"abc");
    }

    /// OCI-1: mediaType の対応表（成功 6 種・未対応は Unimplemented）。
    #[test]
    fn oci1_layer_media_type_table() {
        for (m, want) in [
            (
                "application/vnd.oci.image.layer.v1.tar",
                LayerMediaType::Tar,
            ),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar",
                LayerMediaType::Tar,
            ),
            (
                "application/vnd.oci.image.layer.v1.tar+gzip",
                LayerMediaType::TarGzip,
            ),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                LayerMediaType::TarGzip,
            ),
            (
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                LayerMediaType::TarGzip,
            ),
            (
                "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
                LayerMediaType::TarGzip,
            ),
        ] {
            assert_eq!(LayerMediaType::parse(m).unwrap(), want, "{m}");
        }
        for m in [
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
            "application/octet-stream",
            "",
            "application/vnd.oci.image.layer.v1.tar+GZIP",
            "application/vnd.oci.image.layer.v1.tar+gzip; q=1",
        ] {
            assert_eq!(
                LayerMediaType::parse(m).unwrap_err().code(),
                OciErrorCode::Unimplemented,
                "{m}"
            );
        }
    }

    /// OCI-1・#2311: pull の受理集合は展開の部分集合で、両集合は具体値に固定される。
    #[test]
    fn oci1_pull_set_is_subset_of_extract_set() {
        let mut pull: Vec<&str> = Vec::new();
        let mut extract_only: Vec<&str> = Vec::new();
        for e in LAYER_MEDIA_TYPES {
            assert_eq!(
                LayerMediaType::parse(e.media_type).unwrap(),
                e.kind,
                "{}",
                e.media_type
            );
            assert_eq!(is_pull_supported_layer_media_type(e.media_type), e.pull);
            if e.pull {
                pull.push(e.media_type);
            } else {
                extract_only.push(e.media_type);
            }
        }
        pull.sort_unstable();
        extract_only.sort_unstable();
        assert_eq!(
            pull,
            vec![
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "application/vnd.oci.image.layer.v1.tar+gzip",
            ]
        );
        assert_eq!(
            extract_only,
            vec![
                "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
                "application/vnd.oci.image.layer.nondistributable.v1.tar",
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                "application/vnd.oci.image.layer.v1.tar",
            ]
        );
    }

    /// OCI-1・#2311: 表に重複する mediaType が無い。
    #[test]
    fn oci1_layer_media_type_table_has_no_duplicates() {
        let mut v: Vec<&str> = LAYER_MEDIA_TYPES.iter().map(|e| e.media_type).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n);
        assert_eq!(n, 6);
    }

    /// OCI-1: 非圧縮レイヤーの上限境界（ちょうどは成功・1 バイト超過で中断し以降も失敗）。
    #[test]
    fn oci1_plain_layer_reader_limit_boundary() {
        let data = [7u8; 10];
        let mut ok = PlainLayerReader::new(&data[..], 10);
        let mut out = Vec::new();
        ok.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 10);
        assert_eq!(ok.total_out(), 10);

        let mut over = PlainLayerReader::new(&data[..], 9);
        let mut out = Vec::new();
        let e = over.read_to_end(&mut out).unwrap_err();
        assert_eq!(
            oci_error_from_layer_io(e).code(),
            OciErrorCode::ResourceExhausted
        );
        let mut b = [0u8; 4];
        assert!(over.read(&mut b).is_err());
    }

    /// 0600 のファイルを書く（umask に依らず信頼条件を満たす）。
    #[cfg(unix)]
    fn write_0600(path: &Path, data: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, data).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn uid_of(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).unwrap().uid()
    }

    /// OCI-1・#2309: 信頼条件を満たす blob は検証済みの値になり、digest とサイズが載る。
    #[cfg(unix)]
    #[test]
    fn oci1_verified_layer_blob_accepts_trusted_blob() {
        let d = tmp_dir("vlb-ok");
        let p = d.join("b");
        write_0600(&p, b"abc");
        let b = VerifiedLayerBlob::open(&p, &Digest::parse(ABC).unwrap(), 3, uid_of(&p)).unwrap();
        assert_eq!(b.digest().as_str(), ABC);
        assert_eq!(b.size(), 3);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#2309: symlink の blob は辿らずに拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_verified_layer_blob_rejects_symlink() {
        let d = tmp_dir("vlb-link");
        let real = d.join("real");
        write_0600(&real, b"abc");
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = VerifiedLayerBlob::open(&link, &Digest::parse(ABC).unwrap(), 3, uid_of(&real))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert_eq!(e.message(), "blob path is not a regular file");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#2309: 期待と違う所有者の blob は拒否する（実ファイルの uid と違う値を渡して再現する）。
    #[cfg(unix)]
    #[test]
    fn oci1_verified_layer_blob_rejects_foreign_owner() {
        let d = tmp_dir("vlb-owner");
        let p = d.join("b");
        write_0600(&p, b"abc");
        let e = VerifiedLayerBlob::open(&p, &Digest::parse(ABC).unwrap(), 3, uid_of(&p) ^ 1)
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob has an unexpected owner");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#2309: ハードリンクが増えた blob と group 書き込み可の blob は拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_verified_layer_blob_rejects_extra_links_and_group_writable() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmp_dir("vlb-mode");
        let p = d.join("b");
        write_0600(&p, b"abc");
        let uid = uid_of(&p);
        let abc = Digest::parse(ABC).unwrap();
        std::fs::hard_link(&p, d.join("b2")).unwrap();
        let e = VerifiedLayerBlob::open(&p, &abc, 3, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob has extra hard links");
        let q = d.join("c");
        write_0600(&q, b"abc");
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o620)).unwrap();
        let e = VerifiedLayerBlob::open(&q, &abc, 3, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob is writable by group or others");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#2309: digest の不一致・宣言より短い blob は `DataLoss`、長い blob は `ResourceExhausted`。
    #[cfg(unix)]
    #[test]
    fn oci1_verified_layer_blob_rejects_digest_or_size_mismatch() {
        let d = tmp_dir("vlb-digest");
        let p = d.join("b");
        write_0600(&p, b"abc");
        let uid = uid_of(&p);
        let e = VerifiedLayerBlob::open(&p, &Digest::parse(EMPTY).unwrap(), 3, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), MSG);
        let abc = Digest::parse(ABC).unwrap();
        let e = VerifiedLayerBlob::open(&p, &abc, 4, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), "layer blob size does not match the descriptor");
        let e = VerifiedLayerBlob::open(&p, &abc, 2, uid).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// OCI-1・#2309: 非 Unix では開かずに `Unimplemented`。
    #[cfg(not(unix))]
    #[test]
    fn oci1_verified_layer_blob_is_unimplemented_off_unix() {
        let d = tmp_dir("vlb-off-unix");
        let p = d.join("b");
        std::fs::write(&p, b"abc").unwrap();
        let e = VerifiedLayerBlob::open(&p, &Digest::parse(ABC).unwrap(), 3, 0).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
