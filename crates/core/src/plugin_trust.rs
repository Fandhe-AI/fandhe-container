//! plugin 候補の所有者・モード・symlink 実体解決・sha256 許可済みハッシュ検証（TASK-122.1〜122.3・PLUG-11・MS-3）。
//!
//! # 役割と呼び出し元
//!
//! [`crate::plugin_discovery`] が列挙した **未検証** の候補（[`PluginCandidate`]）に対し、
//! 「探索先ディレクトリと plugin バイナリの所有者が core の実効 UID または root であり、
//! group / other に書き込み権限がないこと」を確認する（PLUG-11）。検証を通ったファイルは
//! 検証済みの fd を持つ [`VerifiedPluginFile`] として返し、後続のハッシュ照合（TASK-122.3。
//! [`VerifiedPluginFile::verify_hash`]）・登録処理は **パスを開き直さずこの fd だけを使う** 契約とする（検証と使用の間の差し替え
//! 〔TOCTOU〕を避ける）。
//!
//! # 検証方式
//!
//! - ディレクトリは `/` から 1 要素ずつ `O_PATH|O_DIRECTORY|O_NOFOLLOW` の fd 相対 open で辿り、
//!   ルート・全祖先・探索先のそれぞれを開いた fd への `fstat` で判定する（中間 symlink は拒否、
//!   祖先の所有者・モードも探索先と同一基準で検証する）
//! - ファイルは検証済みディレクトリ fd からの相対 open（`openat`）で開き、開いた同一 fd への
//!   `fstat` で判定する。パスの再 stat / lstat はしない
//! - plugin ファイル名が symlink（チェーン含む）のときは、カーネルに追従 open（`O_NOFOLLOW`
//!   なし）でチェーンを辿らせて **一度だけ** 実体 fd を得て、その fd の所有者・モードを判定する
//!   （symlink 自体の属性では判定しない）。ホップ上限超過・ループはカーネルの `ELOOP`
//!   （上限 40）を [`PluginTrustErrorKind::SymlinkLoop`] に写し、自前のループは持たない。
//!   実体の正規パスは `/proc/thread-self/fd/N` の `readlink` で得て、その親ディレクトリを
//!   通常の探索先と同じ `/` からの fd 相対ウォークで全祖先まで検証し、検証済み親からの
//!   `O_PATH|O_NOFOLLOW` open の `dev/ino` が保持 fd と一致することを確かめる（保持 fd が
//!   検証済みの祖先連鎖の下にあることの証明。パスから fd を開き直さない）
//! - 判定基準はディレクトリ・ファイルとも同一で、所有者が root か実効 UID であり、かつ
//!   `mode & 0o022 == 0`。sticky bit 付きでも例外にしない
//!
//! # ハッシュ照合（TASK-122.3・PLUG-11）
//!
//! 既定の検証方式は「許可済み sha256 ハッシュ一覧に一致するバイナリのみ登録する」方式
//! （TASK-122.h1・#280）。[`VerifiedPluginFile::sha256`] / [`VerifiedPluginFile::verify_hash`] は
//! 所有者・モード検証と **同一の保持 fd** の内容を先頭から固定長バッファでストリーミング計算し、
//! シグネチャにパスを取らない（パスの再オープンによる TOCTOU を型の上で排除する）。成功後の
//! fd オフセットは 0 に巻き戻す（後続が先頭から読める）。失敗時のオフセットは不定で、呼び出し側は
//! fd を破棄する。照合に成功した fd は type-state の [`HashVerifiedPluginFile`] で返し、後続の
//! 登録処理が「ハッシュ照合済み」を型で要求できる。
//!
//! ## 許可一覧の設定形式
//!
//! 許可一覧は **設定ファイル方式** で、core バイナリへの埋め込み値は持たない（plugin 追加のたびに
//! core を変えない。PLUG-4。既定の一覧は空で全件拒否）。形式は LF 区切りの UTF-8 テキストで
//! `sha256sum` の出力と互換とする（[`AllowedPluginHashes::parse`]）。
//!
//! - 1 行 1 件。行頭の 64 桁 hex がダイジェスト。空白以降は表示用ラベルとして解釈せず無視する
//! - 空行と `#` 始まりの行は無視する。行末の `\r` は許容する
//! - 不正な行が 1 件でもあれば全体をエラーにする（部分採用しない。fail-closed）
//! - 上限は全体 [`MAX_ALLOWLIST_BYTES`]・件数 [`MAX_ALLOWLIST_ENTRIES`]
//!
//! [`AllowedPluginHashes::parse`] は **バイト列のみ** を受け取り、パスからのロードは提供しない。
//! 一覧ファイル自体も信頼できる所有者・group/other 書き込み不可であることを呼び出し側が fd 経由で
//! 検証した内容だけを渡す契約とする（一覧が書き換え可能だと検証が無効になる）。
//!
//! # 限界（REPAIR-3。実装済みを装わない）
//!
//! - sticky bit 付きの祖先（`/tmp` 等）も例外にせず拒否する（fail-closed）。plugin は
//!   他ユーザーが書き込めない祖先配下にのみ置ける
//! - symlink を辿るのは plugin ファイル名（最終要素）だけ。探索先ディレクトリ自体や祖先の
//!   symlink は従来どおり `NotDirectory` で拒否する
//! - チェーン中間ホップの symlink が置かれたディレクトリ自体は検証しない（検証するのは探索先
//!   連鎖と、最終実体およびその祖先連鎖）。最終実体は信頼できる所有者・書き込み不可の祖先配下に
//!   限られ、内容の同一性はハッシュ照合（TASK-122.3）で担保する前提
//! - symlink 経由の検証は実体の正規パスの取得に `/proc` を要する。未マウント環境では `Io` で
//!   拒否する（fail-closed）
//! - 署名の照合は未実装。ハッシュ照合は「計算時点」の内容を保証するもので、信頼された所有者
//!   （root / 実効 UID）自身が計算後に内容を書き換える場合は防げない。起動も照合済み fd 経由
//!   （fexecve 相当）にしない限り保証は切れる（配線は後続）
//! - 許可一覧ファイルの置き場所・指定方法（CLI フラグ / 固定パス）と、一覧ファイル自体の
//!   所有者・モード検証の配線は未実装（呼び出し側の契約。上記）
//! - 検証方式の切替点（TASK-122.4・#282）は未実装で、本モジュールはハッシュ一覧方式の実体のみ
//!   を提供する
//! - レジストリへの配線は未実施で、本モジュール単体では未検証候補の登録を防がない
//! - setuid / setgid ビット・ACL・拡張属性は判定対象外（PLUG-11 の記述範囲外）
//! - 非 Linux は同等検証が未実装のため常に拒否する（fail-closed。macOS / Windows の「相当」
//!   検証は spec で未確定）
//! - エラーの error-format 準拠の整形は TASK-122.5（#283）。本モジュールは機械可読な
//!   [`PluginTrustErrorKind`] と [`TraitError`] への変換までを担う
//!
//! 本モジュールは `unsafe` を持たない（Linux では `sys` のラッパーと std のみを使う）。

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest as _, Sha256};

use crate::plugin_discovery::PluginCandidate;
use crate::traits::{ErrorCode, TraitError};

/// 検証対象の種別（拒否メッセージと種別チェックの切替に使う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTarget {
    /// 探索先ディレクトリ。
    Directory,
    /// plugin バイナリ（通常ファイル）。
    File,
}

/// 拒否理由（機械可読。TASK-122.5 が error-format へ整形する入力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginTrustErrorKind {
    /// 所有者が実効 UID でも root でもない。
    UntrustedOwner,
    /// group または other に書き込みビットがある。
    GroupOrOtherWritable,
    /// 通常ファイルでない（symlink・FIFO・デバイス・ディレクトリ等）。
    NotRegularFile,
    /// 探索先がディレクトリでない、または symlink。
    NotDirectory,
    /// 相対パス・NUL 入り・1 要素でないファイル名など。
    InvalidPath,
    /// open / fstat の失敗、または検証中の実体不一致。
    Io,
    /// symlink のループ、またはホップ上限を超えるチェーン（PLUG-11・TASK-122.2）。
    SymlinkLoop,
    /// 非 Linux・対応外アーキテクチャ（同等検証が未実装）。
    Unsupported,
    /// sha256 が許可済みハッシュ一覧に含まれない（PLUG-11・TASK-122.3）。
    HashMismatch,
    /// バイナリが [`MAX_PLUGIN_BINARY_BYTES`] を超える（ハッシュ計算の無制限読み取りを防ぐ）。
    TooLarge,
}

/// 検証の拒否。種別・対象・パスを持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginTrustError {
    kind: PluginTrustErrorKind,
    target: TrustTarget,
    path: PathBuf,
}

impl PluginTrustError {
    fn new(kind: PluginTrustErrorKind, target: TrustTarget, path: &Path) -> Self {
        Self {
            kind,
            target,
            path: path.to_path_buf(),
        }
    }

    /// 拒否理由を返す。
    pub fn kind(&self) -> PluginTrustErrorKind {
        self.kind
    }

    /// 拒否された対象の種別を返す。
    pub fn target(&self) -> TrustTarget {
        self.target
    }

    /// 拒否された対象のパスを返す。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for PluginTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let target = match self.target {
            TrustTarget::Directory => "plugin directory",
            TrustTarget::File => "plugin file",
        };
        let reason = match self.kind {
            PluginTrustErrorKind::UntrustedOwner => "owner is neither root nor the effective user",
            PluginTrustErrorKind::GroupOrOtherWritable => "writable by group or other",
            PluginTrustErrorKind::NotRegularFile => "not a regular file",
            PluginTrustErrorKind::NotDirectory => "not a directory (or a symlink)",
            PluginTrustErrorKind::InvalidPath => "invalid path",
            PluginTrustErrorKind::Io => "failed to open or stat",
            PluginTrustErrorKind::SymlinkLoop => "symlink loop or chain too long",
            PluginTrustErrorKind::Unsupported => {
                "ownership verification is not supported on this platform"
            }
            PluginTrustErrorKind::HashMismatch => "sha256 digest is not in the allowed hash list",
            PluginTrustErrorKind::TooLarge => "file exceeds the maximum allowed size",
        };
        write!(f, "{target} rejected: {reason}: {}", self.path.display())
    }
}

impl std::error::Error for PluginTrustError {}

impl From<PluginTrustError> for TraitError {
    fn from(e: PluginTrustError) -> Self {
        let code = match e.kind {
            PluginTrustErrorKind::UntrustedOwner
            | PluginTrustErrorKind::GroupOrOtherWritable
            | PluginTrustErrorKind::HashMismatch => ErrorCode::PermissionDenied,
            PluginTrustErrorKind::NotRegularFile
            | PluginTrustErrorKind::NotDirectory
            | PluginTrustErrorKind::SymlinkLoop
            | PluginTrustErrorKind::TooLarge
            | PluginTrustErrorKind::InvalidPath => ErrorCode::InvalidArgument,
            PluginTrustErrorKind::Io => ErrorCode::Internal,
            PluginTrustErrorKind::Unsupported => ErrorCode::Unimplemented,
        };
        TraitError::new(code, e.to_string())
    }
}

/// 所有者とモードの判定（純関数・syscall なし・3 OS で単体テスト可能）。
///
/// 所有者が root でも `runner_uid` でもなければ `UntrustedOwner`、`mode & 0o022` が非零なら
/// `GroupOrOtherWritable`（所有者不正を先に返す）。sticky bit 付きでも例外にしない。
pub fn check_owner_and_mode(
    owner_uid: u32,
    mode: u32,
    runner_uid: u32,
) -> Result<(), PluginTrustErrorKind> {
    if owner_uid != 0 && owner_uid != runner_uid {
        return Err(PluginTrustErrorKind::UntrustedOwner);
    }
    if mode & 0o022 != 0 {
        return Err(PluginTrustErrorKind::GroupOrOtherWritable);
    }
    Ok(())
}

/// ファイル名が 1 要素（`/`・`.`・`..`・空・NUL を含まない）であることを確認する。
/// バイト列で判定し OS 非依存にする（非 UTF-8 も扱う）。
#[cfg(any(target_os = "linux", test))]
fn is_single_component(name: &OsStr) -> bool {
    let s = name.to_string_lossy();
    !(s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\0'))
}

/// 検証済みの plugin ファイル。開いた fd を保持し、後続（ハッシュ照合・登録）はこの fd だけを
/// 使う（パスを開き直さない契約。TASK-122.3 へ引き継ぐ）。
#[derive(Debug)]
pub struct VerifiedPluginFile {
    file: File,
    /// `sha256` の seek→read→巻き戻しを直列化する排他（共有 fd のオフセット競合による誤ダイジェスト防止）。
    hash_lock: Mutex<()>,
    owner_uid: u32,
    mode: u32,
    path: PathBuf,
    resolved_path: PathBuf,
}

impl VerifiedPluginFile {
    /// 検証済みの読み取り用ファイルを借用する。
    pub fn file(&self) -> &File {
        &self.file
    }

    /// 検証済みファイルの所有権を取り出す。
    pub fn into_file(self) -> File {
        self.file
    }

    /// fstat で観測した所有者 UID。
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// fstat で観測した `st_mode`（種別ビット込み）。
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// 検証時のパス（symlink の場合は発見時の symlink 側。表示用。再 open に使わない）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 実体の正規パス（symlink・`..` を含まない。通常ファイルでは [`Self::path`] と同一。
    /// 表示用で再 open に使わない。TASK-122.2）。
    pub fn resolved_path(&self) -> &Path {
        &self.resolved_path
    }
}
/// plugin バイナリとして受理するサイズの上限（1 GiB）。ハッシュ計算の読み取り量を縛る（REPAIR-5）。
pub const MAX_PLUGIN_BINARY_BYTES: u64 = 1 << 30;

/// 許可一覧ファイル（バイト列）の上限（1 MiB）。
pub const MAX_ALLOWLIST_BYTES: usize = 1 << 20;

/// 許可一覧の件数上限。
pub const MAX_ALLOWLIST_ENTRIES: usize = 4096;

/// ハッシュ計算の読み取りバッファ長（ファイルサイズに比例する確保をしない）。
const HASH_BUF_LEN: usize = 64 * 1024;

/// sha256 ダイジェスト（32 バイト固定。REPAIR-2。壊れた長さを表現できない newtype）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// 生のバイト列から作る。
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 生のバイト列を返す。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 厳密に 64 桁の ASCII hex（大文字小文字可）のみ受理する。`sha256:` 接頭辞・空白・
    /// 桁数違いは拒否する。添字アクセスは使わない。
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let (pairs, _) = b.as_chunks::<2>();
        for (slot, [hi, lo]) in out.iter_mut().zip(pairs) {
            let hi = char::from(*hi).to_digit(16)?;
            let lo = char::from(*lo).to_digit(16)?;
            *slot = u8::try_from(hi * 16 + lo).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for Sha256Digest {
    /// 小文字 hex 64 桁。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// `r` を EOF まで固定長バッファで読み、sha256 を計算する。累積が `max_bytes` を超えたら
/// `InvalidData` で失敗する（検証後に伸長されたファイルへの備え）。`Interrupted` は再試行する。
fn sha256_of_reader<R: Read>(mut r: R, max_bytes: u64) -> std::io::Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    let mut total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "input exceeds the size limit",
            ));
        }
        let Some(chunk) = buf.get(..n) else {
            return Err(std::io::Error::other("read length exceeds buffer"));
        };
        hasher.update(chunk);
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

/// 許可一覧の構文エラー種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowedHashesParseErrorKind {
    /// 行頭が 64 桁 hex でない、または hex の直後が空白でない。
    InvalidDigest,
    /// 件数が [`MAX_ALLOWLIST_ENTRIES`] を超える。
    TooManyEntries,
    /// 入力が [`MAX_ALLOWLIST_BYTES`] を超える。
    TooLarge,
    /// UTF-8 でない。
    NotUtf8,
}

/// 許可一覧の構文エラー（行番号は 1 始まり。入力全体の問題では 0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedHashesParseError {
    kind: AllowedHashesParseErrorKind,
    line: usize,
}

impl AllowedHashesParseError {
    /// エラー種別。
    pub fn kind(&self) -> AllowedHashesParseErrorKind {
        self.kind
    }

    /// 1 始まりの行番号（入力全体に関わるエラーは 0）。
    pub fn line(&self) -> usize {
        self.line
    }
}

impl fmt::Display for AllowedHashesParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            AllowedHashesParseErrorKind::InvalidDigest => "invalid sha256 digest",
            AllowedHashesParseErrorKind::TooManyEntries => "too many entries",
            AllowedHashesParseErrorKind::TooLarge => "allowed hash list is too large",
            AllowedHashesParseErrorKind::NotUtf8 => "allowed hash list is not valid UTF-8",
        };
        if self.line == 0 {
            write!(f, "{reason}")
        } else {
            write!(f, "{reason} at line {}", self.line)
        }
    }
}

impl std::error::Error for AllowedHashesParseError {}

impl From<AllowedHashesParseError> for TraitError {
    fn from(e: AllowedHashesParseError) -> Self {
        TraitError::new(ErrorCode::InvalidArgument, e.to_string())
    }
}

/// 許可済み plugin バイナリの sha256 一覧（PLUG-11・TASK-122.3）。
///
/// 設定形式（設定ファイル方式・`sha256sum` 互換テキスト・埋め込みなし）はモジュール doc を参照。
/// **空の一覧は全件拒否**（fail-closed）。ハッシュは秘密でないため通常の等値比較を使う。
/// 呼び出し元（plugin 登録経路。配線は後続）は、信頼検証済みの一覧ファイルの内容だけを
/// [`Self::parse`] へ渡すこと。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedPluginHashes {
    digests: BTreeSet<Sha256Digest>,
}

impl AllowedPluginHashes {
    /// ダイジェスト列から作る（件数上限は [`Self::parse`] のみで検査する。試験・呼び出し側の組み立て用）。
    pub fn from_digests(digests: impl IntoIterator<Item = Sha256Digest>) -> Self {
        Self {
            digests: digests.into_iter().collect(),
        }
    }

    /// 許可一覧テキストを解析する。形式・上限はモジュール doc を参照。不正行があれば全体を拒否する。
    pub fn parse(bytes: &[u8]) -> Result<Self, AllowedHashesParseError> {
        let err = |kind, line| AllowedHashesParseError { kind, line };
        if bytes.len() > MAX_ALLOWLIST_BYTES {
            return Err(err(AllowedHashesParseErrorKind::TooLarge, 0));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| err(AllowedHashesParseErrorKind::NotUtf8, 0))?;
        let mut digests = BTreeSet::new();
        // 重複行も 1 行 1 件として数える（集合長では重複が計上されず上限を迂回できるため）。
        let mut entry_count = 0usize;
        for (idx, raw) in text.split('\n').enumerate() {
            let line_no = idx + 1;
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // 行頭の 64 文字が hex、その後は空白（ラベル）か行末のみ許容する。
            let (hex, rest) = match trimmed.char_indices().nth(64) {
                Some((i, _)) => trimmed.split_at(i),
                None => (trimmed, ""),
            };
            if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
                return Err(err(AllowedHashesParseErrorKind::InvalidDigest, line_no));
            }
            let digest = Sha256Digest::from_hex(hex)
                .ok_or_else(|| err(AllowedHashesParseErrorKind::InvalidDigest, line_no))?;
            digests.insert(digest);
            entry_count += 1;
            if entry_count > MAX_ALLOWLIST_ENTRIES {
                return Err(err(AllowedHashesParseErrorKind::TooManyEntries, line_no));
            }
        }
        Ok(Self { digests })
    }

    /// 一覧に含まれるか。
    pub fn contains(&self, digest: &Sha256Digest) -> bool {
        self.digests.contains(digest)
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.digests.len()
    }

    /// 空か（空は全件拒否）。
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

impl VerifiedPluginFile {
    /// 保持 fd の内容の sha256 を計算する（TASK-122.3）。
    ///
    /// **パスを取らない**ため再オープンはできず、所有者・モード検証と同じ fd を読む（TOCTOU 回避）。
    /// fd を先頭へ seek して計算し、成功時は先頭へ戻す。seek〜読み取り〜巻き戻しは内部 Mutex で直列化するため、
    /// 共有参照からの並行呼び出しでも結果は干渉しない（[`Self::file`] 経由の外部読み取りは対象外）。失敗時のオフセットは不定のため呼び出し側は
    /// fd を破棄する。サイズが [`MAX_PLUGIN_BINARY_BYTES`] を超えれば `TooLarge`。
    pub fn sha256(&self) -> Result<Sha256Digest, PluginTrustError> {
        let err = |k| PluginTrustError::new(k, TrustTarget::File, &self.path);
        let md = self
            .file
            .metadata()
            .map_err(|_| err(PluginTrustErrorKind::Io))?;
        if md.len() > MAX_PLUGIN_BINARY_BYTES {
            return Err(err(PluginTrustErrorKind::TooLarge));
        }
        // 共有 fd のオフセットを動かすため、ハッシュ計算全体（seek〜巻き戻し）を排他する。
        // 毒化しても fd 自体は無傷で、毎回先頭へ seek するため回復して続行してよい。
        let _guard = self
            .hash_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut f = &self.file;
        f.seek(SeekFrom::Start(0))
            .map_err(|_| err(PluginTrustErrorKind::Io))?;
        let digest = sha256_of_reader(f, MAX_PLUGIN_BINARY_BYTES).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                err(PluginTrustErrorKind::TooLarge)
            } else {
                err(PluginTrustErrorKind::Io)
            }
        })?;
        f.seek(SeekFrom::Start(0))
            .map_err(|_| err(PluginTrustErrorKind::Io))?;
        Ok(digest)
    }

    /// sha256 を計算して許可一覧と照合する。不一致（空一覧を含む）は `HashMismatch`。
    /// 成功した fd は [`HashVerifiedPluginFile`] として返す（オフセットは 0）。
    pub fn verify_hash(
        self,
        allowed: &AllowedPluginHashes,
    ) -> Result<HashVerifiedPluginFile, PluginTrustError> {
        let digest = self.sha256()?;
        if !allowed.contains(&digest) {
            return Err(PluginTrustError::new(
                PluginTrustErrorKind::HashMismatch,
                TrustTarget::File,
                &self.path,
            ));
        }
        Ok(HashVerifiedPluginFile { file: self, digest })
    }
}

/// 所有者・モード検証に加えて sha256 許可一覧との照合を通った plugin ファイル（type-state）。
/// 構築は [`VerifiedPluginFile::verify_hash`] のみ。後続のレジストリ配線が型でハッシュ照合済みを
/// 要求できる（TASK-122.3）。
#[derive(Debug)]
pub struct HashVerifiedPluginFile {
    file: VerifiedPluginFile,
    digest: Sha256Digest,
}

impl HashVerifiedPluginFile {
    /// 検証済みファイルを借用する。
    pub fn file(&self) -> &VerifiedPluginFile {
        &self.file
    }

    /// 検証済みファイルを取り出す。
    pub fn into_file(self) -> VerifiedPluginFile {
        self.file
    }

    /// 照合した sha256。
    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// 検証時のパス（表示用）。
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// 実体の正規パス（表示用）。
    pub fn resolved_path(&self) -> &Path {
        self.file.resolved_path()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::sys::{self, SysError};
    use std::ffi::CString;
    use std::fs::Metadata;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    /// 検証済みの探索先ディレクトリ fd。ファイルはここからの相対 open で開く。
    #[derive(Debug)]
    pub struct VerifiedPluginDir {
        fd: OwnedFd,
        path: PathBuf,
        /// 試験用変種の信頼起点。symlink 実体の祖先検証へ引き継ぐ（本番ビルドには存在しない）。
        #[cfg(test)]
        anchor: Option<PathBuf>,
    }

    fn map_sys(e: SysError, dir_open: bool) -> PluginTrustErrorKind {
        match e {
            SysError::Unsupported => PluginTrustErrorKind::Unsupported,
            SysError::Os(n) if n == sys::ENOTDIR => {
                if dir_open {
                    PluginTrustErrorKind::NotDirectory
                } else {
                    PluginTrustErrorKind::NotRegularFile
                }
            }
            SysError::Os(n) if n == sys::ELOOP => PluginTrustErrorKind::NotRegularFile,
            _ => PluginTrustErrorKind::Io,
        }
    }

    /// 追従 open（symlink を辿る経路）専用の errno 写像。`ELOOP` はループ・ホップ上限超過。
    fn map_sys_follow(e: SysError) -> PluginTrustErrorKind {
        match e {
            SysError::Unsupported => PluginTrustErrorKind::Unsupported,
            SysError::Os(n) if n == sys::ELOOP => PluginTrustErrorKind::SymlinkLoop,
            SysError::Os(n) if n == sys::ENOTDIR => PluginTrustErrorKind::NotRegularFile,
            _ => PluginTrustErrorKind::Io,
        }
    }

    /// fd への fstat（std の `File::metadata`）。fd は複製して見るだけで元の fd は閉じない。
    fn fstat(fd: &OwnedFd) -> std::io::Result<Metadata> {
        File::from(fd.as_fd().try_clone_to_owned()?).metadata()
    }

    /// 開いた dir fd を fstat で検証する（ディレクトリであること・所有者・モード）。
    fn check_dir_fd(fd: &OwnedFd, shown: &Path, runner_uid: u32) -> Result<(), PluginTrustError> {
        let err = |k| PluginTrustError::new(k, TrustTarget::Directory, shown);
        let md = fstat(fd).map_err(|_| err(PluginTrustErrorKind::Io))?;
        if !md.is_dir() {
            return Err(err(PluginTrustErrorKind::NotDirectory));
        }
        check_owner_and_mode(md.uid(), md.mode(), runner_uid).map_err(err)
    }

    /// 探索先ディレクトリを `/` から 1 要素ずつ fd 相対（`O_PATH|O_DIRECTORY|O_NOFOLLOW`）で
    /// 辿り、ルート・全祖先・探索先のすべてを fstat で検証して最終 fd を固定して返す。
    ///
    /// 祖先の symlink は `O_NOFOLLOW|O_DIRECTORY` により `NotDirectory` で拒否され、祖先の
    /// 所有者・モードが不正（他ユーザー書き込み可能な `/tmp` 等）なら拒否する（PLUG-11）。
    /// `.`・`..` を含むパスは `InvalidPath`。
    pub fn verify_plugin_dir(dir: &Path) -> Result<VerifiedPluginDir, PluginTrustError> {
        walk_verify(dir, None)
    }

    /// [`verify_plugin_dir`] の試験用変種。`anchor`（`dir` の祖先または `dir` 自身）までの
    /// 要素は symlink 拒否つきで辿るが所有者・モードを検証せず、`anchor` より下だけを検証する。
    /// 祖先検証を省略できる迂回経路のため `cfg(test)` 限定の非公開とし、公開 API・本番ビルドに
    /// 含めない（PLUG-11）。
    #[cfg(test)]
    pub(super) fn verify_plugin_dir_below(
        anchor: &Path,
        dir: &Path,
    ) -> Result<VerifiedPluginDir, PluginTrustError> {
        if !dir.starts_with(anchor) {
            return Err(PluginTrustError::new(
                PluginTrustErrorKind::InvalidPath,
                TrustTarget::Directory,
                dir,
            ));
        }
        walk_verify(dir, Some(anchor))
    }

    fn walk_verify(
        dir: &Path,
        anchor: Option<&Path>,
    ) -> Result<VerifiedPluginDir, PluginTrustError> {
        let err = |k| PluginTrustError::new(k, TrustTarget::Directory, dir);
        if !dir.is_absolute() {
            return Err(err(PluginTrustErrorKind::InvalidPath));
        }
        // `Path::components()` は途中・末尾の `.` を黙って正規化するため、正規化前の生バイト列で
        // `.` 要素を検出して拒否する（契約: `.`・`..` は InvalidPath）。
        if dir
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|e| e == b".")
        {
            return Err(err(PluginTrustErrorKind::InvalidPath));
        }
        let runner_uid = sys::effective_uid();
        let mut shown = PathBuf::new();
        let mut cur: Option<OwnedFd> = None;
        for comp in dir.components() {
            let name: &OsStr = match comp {
                Component::RootDir => OsStr::new("/"),
                Component::Normal(n) => n,
                _ => return Err(err(PluginTrustErrorKind::InvalidPath)),
            };
            shown.push(name);
            let c = CString::new(name.as_bytes())
                .map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
            let parent = cur.as_ref().map(|f| f.as_fd());
            let fd = sys::open_dir_path_nofollow(parent, &c).map_err(|e| {
                PluginTrustError::new(map_sys(e, true), TrustTarget::Directory, &shown)
            })?;
            // anchor 以上（試験用変種のみ）は所有者・モードを検証せず、種別だけ確認する。
            if anchor.is_some_and(|a| a.starts_with(&shown)) {
                let md = fstat(&fd).map_err(|_| err(PluginTrustErrorKind::Io))?;
                if !md.is_dir() {
                    return Err(PluginTrustError::new(
                        PluginTrustErrorKind::NotDirectory,
                        TrustTarget::Directory,
                        &shown,
                    ));
                }
            } else {
                check_dir_fd(&fd, &shown, runner_uid)?;
            }
            cur = Some(fd);
        }
        let fd = cur.ok_or_else(|| err(PluginTrustErrorKind::InvalidPath))?;
        Ok(VerifiedPluginDir {
            fd,
            path: dir.to_path_buf(),
            #[cfg(test)]
            anchor: anchor.map(Path::to_path_buf),
        })
    }

    impl VerifiedPluginDir {
        /// 検証済みディレクトリ fd からの相対 open で 1 要素のファイルを開き、同じ fd への
        /// fstat で検証する。
        pub fn verify_file(
            &self,
            file_name: &OsStr,
        ) -> Result<VerifiedPluginFile, PluginTrustError> {
            let path = self.path.join(file_name);
            let err = |k| PluginTrustError::new(k, TrustTarget::File, &path);
            if !is_single_component(file_name) {
                return Err(err(PluginTrustErrorKind::InvalidPath));
            }
            let c = CString::new(file_name.as_bytes())
                .map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
            // (a) O_PATH（ブロックしない）で種別を先に確認し、FIFO 等への O_RDONLY open の
            // ハングを避ける（REPAIR-5）。
            let probe =
                sys::open_path_nofollow(self.fd.as_fd(), &c).map_err(|e| err(map_sys(e, false)))?;
            let probe_md = fstat(&probe).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if probe_md.file_type().is_symlink() {
                return self.verify_symlink(&c, path);
            }
            if !probe_md.is_file() {
                return Err(err(PluginTrustErrorKind::NotRegularFile));
            }
            // (b) 読み取り用 fd を O_NONBLOCK で開き（O_PATH 確認後に FIFO へ差し替えられても
            // open 自体が止まらない。REPAIR-5）、正とする判定はこの fd への fstat で行う。
            let rfd = sys::open_read_nonblock_at(self.fd.as_fd(), &c)
                .map_err(|e| err(map_sys(e, false)))?;
            let md = fstat(&rfd).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if !md.is_file() {
                return Err(err(PluginTrustErrorKind::NotRegularFile));
            }
            if md.dev() != probe_md.dev() || md.ino() != probe_md.ino() {
                return Err(err(PluginTrustErrorKind::Io));
            }
            check_owner_and_mode(md.uid(), md.mode(), sys::effective_uid()).map_err(err)?;
            Ok(VerifiedPluginFile {
                file: File::from(rfd),
                hash_lock: Mutex::new(()),
                owner_uid: md.uid(),
                mode: md.mode(),
                resolved_path: path.clone(),
                path,
            })
        }

        /// `name` が symlink のときの検証（PLUG-11・TASK-122.2）。カーネルに最終要素の
        /// チェーンを辿らせて保持 fd を一度だけ得て、実体 inode と実体の全祖先を検証する。
        fn verify_symlink(
            &self,
            name: &CString,
            path: PathBuf,
        ) -> Result<VerifiedPluginFile, PluginTrustError> {
            let err = |k| PluginTrustError::new(k, TrustTarget::File, &path);
            // (1) 追従 O_PATH で実体を一度だけ解決して固定する（FIFO・デバイスの open による
            // ハング・副作用を避ける。REPAIR-5）。ループ・ホップ超過はここで ELOOP。
            let probe = sys::open_path_follow_at(self.fd.as_fd(), name)
                .map_err(|e| err(map_sys_follow(e)))?;
            let probe_md = fstat(&probe).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if !probe_md.is_file() {
                return Err(err(PluginTrustErrorKind::NotRegularFile));
            }
            // (2) 保持 fd は固定済みの O_PATH fd から開き直す。symlink チェーンを再走査しない
            // ため、probe 後に張り替えられても別の実体は開かれない（通常ファイルと確認済み）。
            let rfd = sys::reopen_pinned_read_nonblock(probe.as_fd())
                .map_err(|e| err(map_sys(e, false)))?;
            let md = fstat(&rfd).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if !md.is_file() {
                return Err(err(PluginTrustErrorKind::NotRegularFile));
            }
            if md.dev() != probe_md.dev() || md.ino() != probe_md.ino() {
                return Err(err(PluginTrustErrorKind::Io));
            }
            // (3) 判定は実体 inode に対して行う（symlink の lrwxrwxrwx は使わない）。
            check_owner_and_mode(md.uid(), md.mode(), sys::effective_uid()).map_err(err)?;
            // (4) 実体の正規パスを保持 fd の magic link から得る。
            let magic = PathBuf::from(format!("/proc/thread-self/fd/{}", rfd.as_raw_fd()));
            let resolved = std::fs::read_link(&magic).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if !resolved.is_absolute() {
                return Err(err(PluginTrustErrorKind::Io));
            }
            let (Some(real_parent), Some(real_name)) = (resolved.parent(), resolved.file_name())
            else {
                return Err(err(PluginTrustErrorKind::Io));
            };
            // 削除済みの実体は `... (deleted)` 付きで返るが、正当な実名が同じ接尾辞を持ちうるため
            // 文字列では判定しない。(6) の検証済み親からの open と保持 fd の dev/ino 照合で
            // 実体の存在を確かめる（削除済みなら ENOENT か inode 不一致で拒否される）。
            if !is_single_component(real_name) {
                return Err(err(PluginTrustErrorKind::Io));
            }
            // (5) 実体の親と全祖先を探索先と同一基準で検証する。
            #[cfg(test)]
            let anchor = self.anchor.as_deref();
            #[cfg(not(test))]
            let anchor: Option<&Path> = None;
            let real_dir = walk_verify(real_parent, anchor)?;
            // (6) 検証済み親の下の実体が保持 fd と同一 inode であることを確かめる（保持 fd が
            // 検証済みの祖先連鎖の下にある証明。この fd は fstat のみに使い、引き渡さない）。
            let real_c = CString::new(real_name.as_bytes())
                .map_err(|_| err(PluginTrustErrorKind::InvalidPath))?;
            let bound = sys::open_path_nofollow(real_dir.fd.as_fd(), &real_c)
                .map_err(|e| err(map_sys(e, false)))?;
            let bound_md = fstat(&bound).map_err(|_| err(PluginTrustErrorKind::Io))?;
            if bound_md.dev() != md.dev() || bound_md.ino() != md.ino() {
                return Err(err(PluginTrustErrorKind::Io));
            }
            Ok(VerifiedPluginFile {
                file: File::from(rfd),
                hash_lock: Mutex::new(()),
                owner_uid: md.uid(),
                mode: md.mode(),
                path,
                resolved_path: resolved,
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    /// 検証済みの探索先ディレクトリ（非 Linux では生成されない）。
    #[derive(Debug)]
    pub struct VerifiedPluginDir {
        _private: (),
    }

    /// 非 Linux は同等検証が未実装のため常に拒否する（fail-closed。PLUG-11・REPAIR-3）。
    pub fn verify_plugin_dir(dir: &Path) -> Result<VerifiedPluginDir, PluginTrustError> {
        Err(PluginTrustError::new(
            PluginTrustErrorKind::Unsupported,
            TrustTarget::Directory,
            dir,
        ))
    }

    impl VerifiedPluginDir {
        /// 非 Linux では到達しない（`verify_plugin_dir` が常に拒否する）。
        pub fn verify_file(
            &self,
            _file_name: &OsStr,
        ) -> Result<VerifiedPluginFile, PluginTrustError> {
            Err(PluginTrustError::new(
                PluginTrustErrorKind::Unsupported,
                TrustTarget::File,
                Path::new(""),
            ))
        }
    }
}

pub use imp::{VerifiedPluginDir, verify_plugin_dir};

/// 候補 1 件の検証（親ディレクトリ → ファイルの順）。
///
/// 返る [`VerifiedPluginFile`] の fd を後続が使い、パスを開き直さないこと。
pub fn verify_candidate(
    candidate: &PluginCandidate,
) -> Result<VerifiedPluginFile, PluginTrustError> {
    let path = candidate.path();
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(PluginTrustError::new(
            PluginTrustErrorKind::InvalidPath,
            TrustTarget::File,
            path,
        ));
    };
    verify_plugin_dir(parent)?.verify_file(name)
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn plug11_task122_1_accepts_runner_or_root_without_group_other_write() {
        assert_eq!(check_owner_and_mode(1000, 0o755, 1000), Ok(()));
        assert_eq!(check_owner_and_mode(0, 0o755, 1000), Ok(()));
        assert_eq!(check_owner_and_mode(1000, 0o100_644, 1000), Ok(()));
        assert_eq!(check_owner_and_mode(0, 0o700, 0), Ok(()));
    }

    #[test]
    fn plug11_task122_1_rejects_foreign_owner() {
        assert_eq!(
            check_owner_and_mode(1001, 0o755, 1000),
            Err(PluginTrustErrorKind::UntrustedOwner)
        );
    }

    #[test]
    fn plug11_task122_1_rejects_group_or_other_writable() {
        for mode in [0o775, 0o757, 0o777, 0o1777, 0o100_664, 0o100_646] {
            assert_eq!(
                check_owner_and_mode(1000, mode, 1000),
                Err(PluginTrustErrorKind::GroupOrOtherWritable),
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn plug11_task122_1_owner_checked_before_mode() {
        assert_eq!(
            check_owner_and_mode(1001, 0o777, 1000),
            Err(PluginTrustErrorKind::UntrustedOwner)
        );
    }

    #[test]
    fn plug11_task122_1_file_name_must_be_single_component() {
        for bad in ["a/b", "..", ".", "", "a\0b", "/abs"] {
            assert!(!is_single_component(&OsString::from(bad)), "{bad:?}");
        }
        assert!(is_single_component(OsStr::new("fandhe-container-plugin-x")));
    }

    #[test]
    fn plug11_task122_1_error_code_mapping() {
        let p = Path::new("/x");
        let cases = [
            (
                PluginTrustErrorKind::UntrustedOwner,
                ErrorCode::PermissionDenied,
            ),
            (
                PluginTrustErrorKind::GroupOrOtherWritable,
                ErrorCode::PermissionDenied,
            ),
            (
                PluginTrustErrorKind::NotRegularFile,
                ErrorCode::InvalidArgument,
            ),
            (
                PluginTrustErrorKind::InvalidPath,
                ErrorCode::InvalidArgument,
            ),
            (
                PluginTrustErrorKind::SymlinkLoop,
                ErrorCode::InvalidArgument,
            ),
            (PluginTrustErrorKind::Io, ErrorCode::Internal),
            (PluginTrustErrorKind::Unsupported, ErrorCode::Unimplemented),
            (
                PluginTrustErrorKind::HashMismatch,
                ErrorCode::PermissionDenied,
            ),
            (PluginTrustErrorKind::TooLarge, ErrorCode::InvalidArgument),
        ];
        for (k, c) in cases {
            let e: TraitError = PluginTrustError::new(k, TrustTarget::File, p).into();
            assert_eq!(e.code(), c);
        }
    }

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn plug11_task122_3_known_digests() {
        let d = sha256_of_reader(&b""[..], 10).unwrap();
        assert_eq!(d.to_string(), EMPTY_SHA);
        let d = sha256_of_reader(&b"abc"[..], 10).unwrap();
        assert_eq!(d.to_string(), ABC_SHA);
    }

    #[test]
    fn plug11_task122_3_streaming_matches_one_shot_across_buffer_boundary() {
        for len in [
            HASH_BUF_LEN - 1,
            HASH_BUF_LEN,
            HASH_BUF_LEN + 1,
            3 * HASH_BUF_LEN + 7,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let streamed = sha256_of_reader(&data[..], u64::MAX).unwrap();
            let oneshot = Sha256Digest(Sha256::digest(&data).into());
            assert_eq!(streamed, oneshot, "len {len}");
        }
    }

    #[test]
    fn plug11_task122_3_reader_rejects_over_limit() {
        let data = [0u8; 11];
        let e = sha256_of_reader(&data[..], 10).expect_err("over limit");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(sha256_of_reader(&data[..10], 10).is_ok());
    }

    #[test]
    fn plug11_task122_3_from_hex_strict() {
        assert_eq!(
            Sha256Digest::from_hex(ABC_SHA).unwrap().to_string(),
            ABC_SHA
        );
        let upper = ABC_SHA.to_uppercase();
        assert_eq!(Sha256Digest::from_hex(&upper).unwrap().to_string(), ABC_SHA);
        let short = &ABC_SHA[..63];
        let long = format!("{ABC_SHA}0");
        let prefixed = format!("sha256:{ABC_SHA}");
        let spaced = format!(" {}", &ABC_SHA[..63]);
        let non_hex = format!("g{}", &ABC_SHA[1..]);
        let multibyte = format!("{}é", &ABC_SHA[..62]);
        for bad in [short, &long, &prefixed, &spaced, &non_hex, &multibyte, ""] {
            assert_eq!(Sha256Digest::from_hex(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn plug11_task122_3_parse_accepts_comments_labels_crlf() {
        let text = format!(
            "# header\n\n{EMPTY_SHA}  plugin-a\r\n   {ABC_SHA}\t*plugin-b\n{}\n",
            ABC_SHA.to_uppercase()
        );
        let l = AllowedPluginHashes::parse(text.as_bytes()).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.contains(&Sha256Digest::from_hex(EMPTY_SHA).unwrap()));
        assert!(l.contains(&Sha256Digest::from_hex(ABC_SHA).unwrap()));
    }

    #[test]
    fn plug11_task122_3_parse_rejects_bad_lines_with_line_number() {
        let text = format!("{ABC_SHA}\nnot-a-digest\n");
        let e = AllowedPluginHashes::parse(text.as_bytes()).expect_err("bad");
        assert_eq!(e.kind(), AllowedHashesParseErrorKind::InvalidDigest);
        assert_eq!(e.line(), 2);
        assert_eq!(e.to_string(), "invalid sha256 digest at line 2");
        // hex の直後が空白でない（65 桁連続）は拒否する。
        let text = format!("{ABC_SHA}0 label\n");
        let e = AllowedPluginHashes::parse(text.as_bytes()).expect_err("bad");
        assert_eq!(e.line(), 1);
        let te: TraitError = e.into();
        assert_eq!(te.code(), ErrorCode::InvalidArgument);
        let e = AllowedPluginHashes::parse(&[0xff, 0xfe]).expect_err("utf8");
        assert_eq!(e.kind(), AllowedHashesParseErrorKind::NotUtf8);
    }

    #[test]
    fn plug11_task122_3_parse_enforces_limits() {
        let big = vec![b'#'; MAX_ALLOWLIST_BYTES + 1];
        let e = AllowedPluginHashes::parse(&big).expect_err("too large");
        assert_eq!(e.kind(), AllowedHashesParseErrorKind::TooLarge);

        let mut text = String::new();
        for i in 0..=MAX_ALLOWLIST_ENTRIES {
            text.push_str(&format!("{i:064x}\n"));
        }
        let e = AllowedPluginHashes::parse(text.as_bytes()).expect_err("too many");
        assert_eq!(e.kind(), AllowedHashesParseErrorKind::TooManyEntries);

        // 重複行も件数に計上される（全行同一でも上限超過で拒否）。
        let dup = format!("{:064x}\n", 1).repeat(MAX_ALLOWLIST_ENTRIES + 1);
        let e = AllowedPluginHashes::parse(dup.as_bytes()).expect_err("too many dups");
        assert_eq!(e.kind(), AllowedHashesParseErrorKind::TooManyEntries);
        assert_eq!(e.line(), MAX_ALLOWLIST_ENTRIES + 1);
    }

    #[test]
    fn plug11_task122_3_empty_list_rejects_everything() {
        let l = AllowedPluginHashes::parse(b"# only comments\n").unwrap();
        assert!(l.is_empty());
        assert!(!l.contains(&Sha256Digest::from_hex(EMPTY_SHA).unwrap()));
        assert!(!AllowedPluginHashes::default().contains(&Sha256Digest::from_bytes([0; 32])));
    }
}
