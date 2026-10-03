//! `--add-host` / `--dns` の利用者入力（hostname・IP）を副作用の前に検証する純粋関数群
//! （NET-12・TASK-185.1・#335・ERR-1・MS-8）。
//!
//! CLI / stack が `--add-host` / `--dns` を受け取った直後に呼ばれ、`/etc/hosts` 追記・`resolv.conf`
//! 書き換え・DNS ヘルパー設定変更の前に不正値をコンテナ作成前に拒否する。後続の `/etc/hosts` 追記
//! （TASK-185.2・#345）・上流転送（TASK-185.3・#346）・host/none の `--dns` 反映（TASK-185.4・#347）・
//! 軽量運用の `--dns` 直接書き込み（TASK-146.2・#336）から再利用される。
//!
//! `--add-host <hostname>:<ip>` は最初の `:` で 2 分割する（[`AddHostEntry::parse`]。残り全体を IP とするため
//! `::1` 等の IPv6 表記をそのまま渡せる）。検証済みエントリはコンテナの hosts ファイルへ追記できる
//! （[`apply_add_hosts`]。TASK-185.2・#345）。追記先は「管理ルート（コンテナ状態ディレクトリ）」と
//! そこからの相対パスで指定し、ルート配下の既存の通常ファイルに限る（`/etc/hosts` のような管理外の
//! ファイルは絶対パス・`..`・symlink・管理ルート内の bind mount 経由のいずれでも指せない）。
//! ネットワークモード（bridge / host / none）を引数に取らないため全モードで同じ処理になる。hosts ファイルの
//! 生成・コンテナへの bind mount は runtime / core 側の責務で、本モジュールは既存の通常ファイルへ追記するだけ
//! （無ければ作らず `NOT_FOUND`）。
//! 追記先は symlink（途中ディレクトリを含む）・ハードリンク（nlink != 1）・他ユーザー所有を拒否し、
//! 書き込み失敗時は同じロック下で書き込み前の長さへ戻す。巻き戻しにも失敗した場合は
//! 不完全な行が残りうるため `DATA_LOSS` で通常の失敗と区別して返す。
//!
//! host/none の `--dns` 反映と none の loopback 制限は子モジュール `resolv_conf`（TASK-185.4・#347）。
//! 上流転送（TASK-185.3）は未実装（REPAIR-3）。エラーの `message` は固定の英語文字列で、
//! 入力値を載せない（ログ・ファイルへの行注入を防ぐ）。`dns_helper::DnsName`（小文字化・末尾ドット除去）
//! とは意味論が異なり、ここでは入力をそのまま保持し、末尾ドット（空ラベル）は拒否する。

pub mod resolv_conf;

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{NetError, NetErrorCode};
use crate::instrument::{NetOpKind, NetOpRecorder, NoopNetOpRecorder, record_net_op};

/// hostname 全体の最大バイト長（RFC 1123）。
const MAX_HOSTNAME_LEN: usize = 253;
/// ラベルの最大バイト長（RFC 1123）。
const MAX_LABEL_LEN: usize = 63;
/// IPv6 の最長テキスト表記（IPv4 射影を含む）のバイト長。
const MAX_IP_TEXT_LEN: usize = 45;
/// `--add-host` 1 件の最大バイト長（hostname + `:` + IP）。分割前に検査する。
const MAX_ADD_HOST_LEN: usize = MAX_HOSTNAME_LEN + 1 + MAX_IP_TEXT_LEN;
/// `--add-host` の最大件数。spec（NET-12）に件数規定は無く、無制限確保を避けるための実装上限。
pub const MAX_ADD_HOST_ENTRIES: usize = 256;
/// 追記先 hosts ファイルの最大バイト数（実装上限。これを超える既存ファイルへは追記しない）。
const MAX_HOSTS_FILE_BYTES: u64 = 1024 * 1024;
/// hosts ファイルの排他ロック取得の待ち上限（REPAIR-5。超過は `TIMEOUT`）。
const HOSTS_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 排他ロックの再試行間隔。
const HOSTS_LOCK_POLL: Duration = Duration::from_millis(10);
/// 同一プロセス内の追記を直列化する（flock はプロセス間用で、同一プロセスの別 fd 同士も
/// 直列化するが、ロック待ちを持たずに済ませるため先にこのミューテックスで順序付ける）。
static HOSTS_APPEND_GUARD: Mutex<()> = Mutex::new(());

/// 入力検証の違反理由（機械可読）。`NetError`（`INVALID_ARGUMENT`）へ変換できる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InputViolation {
    /// 改行・制御文字・空白を含む（hostname・IP 共通）。
    ControlOrWhitespace,
    /// hostname が空。
    EmptyHostname,
    /// hostname の総長が 253 バイトを超える。
    HostnameTooLong,
    /// ラベル長が 0（空ラベル・末尾ドット）または 63 を超える。
    LabelLength,
    /// ラベルの先頭または末尾がハイフン。
    LabelHyphenEdge,
    /// ASCII 英数字・ハイフン・区切りの `.` 以外の文字を含む。
    InvalidHostnameChar,
    /// IPv4 / IPv6 のいずれとしても解釈できない。
    NotIpAddress,
    /// `--add-host` の値に `<hostname>:<ip>` の区切り `:` が無い。
    MissingHostIpSeparator,
    /// `--add-host` の 1 件が長すぎる（hostname + `:` + IP の上限超過）。
    AddHostTooLong,
    /// `--add-host` の件数が上限（[`MAX_ADD_HOST_ENTRIES`]）を超える。
    TooManyAddHosts,
    /// none モードで loopback 以外の `--dns` を指定した。
    NotLoopbackForNoneMode,
}

impl InputViolation {
    /// 違反理由の機械可読な識別子。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControlOrWhitespace => "CONTROL_OR_WHITESPACE",
            Self::EmptyHostname => "EMPTY_HOSTNAME",
            Self::HostnameTooLong => "HOSTNAME_TOO_LONG",
            Self::LabelLength => "LABEL_LENGTH",
            Self::LabelHyphenEdge => "LABEL_HYPHEN_EDGE",
            Self::InvalidHostnameChar => "INVALID_HOSTNAME_CHAR",
            Self::NotIpAddress => "NOT_IP_ADDRESS",
            Self::MissingHostIpSeparator => "MISSING_SEPARATOR",
            Self::AddHostTooLong => "ADD_HOST_TOO_LONG",
            Self::TooManyAddHosts => "TOO_MANY_ADD_HOSTS",
            Self::NotLoopbackForNoneMode => "NOT_LOOPBACK_FOR_NONE_MODE",
        }
    }

    /// 固定の英語メッセージ（入力値を含めない）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::ControlOrWhitespace => "invalid input: contains control character or whitespace",
            Self::EmptyHostname => "invalid hostname: empty",
            Self::HostnameTooLong => "invalid hostname: exceeds 253 characters",
            Self::LabelLength => "invalid hostname: label must be 1 to 63 characters",
            Self::LabelHyphenEdge => "invalid hostname: label must not start or end with hyphen",
            Self::InvalidHostnameChar => {
                "invalid hostname: only ASCII letters, digits, hyphens and dots are allowed"
            }
            Self::NotIpAddress => "invalid IP address: not a valid IPv4 or IPv6 address",
            Self::MissingHostIpSeparator => "invalid add-host: expected <hostname>:<ip>",
            Self::AddHostTooLong => "invalid add-host: entry is too long",
            Self::TooManyAddHosts => "invalid add-host: too many entries",
            Self::NotLoopbackForNoneMode => {
                "invalid --dns for none network mode: only loopback addresses (127.0.0.0/8, ::1) are allowed"
            }
        }
    }
}

impl From<InputViolation> for NetError {
    fn from(v: InputViolation) -> Self {
        NetError::new(NetErrorCode::InvalidArgument, v.message())
    }
}

/// 改行・制御文字・空白を含むか（`trim` による暗黙補正はしない）。
fn has_control_or_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// RFC 1123 で検証済みのホスト名（`--add-host` の hostname 部）。
///
/// 入力をそのまま保持する（小文字化・末尾ドット除去はしない）。全数字のラベルは RFC 1123 上有効のため
/// `"123"` のような値も受理する。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostName(String);

impl HostName {
    /// hostname を検証して返す。総長 1〜253、各ラベル 1〜63 文字の ASCII 英数字・ハイフン
    /// （先頭・末尾ハイフン不可）。違反は `INVALID_ARGUMENT` の `NetError`（NET-12）。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        Self::validate(s)?;
        Ok(Self(s.to_owned()))
    }

    fn validate(s: &str) -> Result<(), InputViolation> {
        if has_control_or_whitespace(s) {
            return Err(InputViolation::ControlOrWhitespace);
        }
        if s.is_empty() {
            return Err(InputViolation::EmptyHostname);
        }
        if s.len() > MAX_HOSTNAME_LEN {
            return Err(InputViolation::HostnameTooLong);
        }
        for label in s.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(InputViolation::LabelLength);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(InputViolation::InvalidHostnameChar);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(InputViolation::LabelHyphenEdge);
            }
        }
        Ok(())
    }

    /// 検証済み hostname を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `--add-host` の IP 部・`--dns` の値を IPv4 / IPv6 として検証する（NET-12）。
///
/// std のパーサに従い fail-closed: 先頭ゼロのオクテット（`010.0.0.1`）・ゾーン ID（`fe80::1%eth0`）・
/// 角括弧（`[::1]`）・CIDR（`1.2.3.4/24`）は拒否し、IPv4 射影（`::ffff:192.0.2.1`）は受理する。
/// アドレス種別（loopback 等）の制限は行わない（none モードの loopback 制限は `resolv_conf` が行う。TASK-185.4）。
pub fn parse_ip_addr(s: &str) -> Result<IpAddr, NetError> {
    if has_control_or_whitespace(s) {
        return Err(InputViolation::ControlOrWhitespace.into());
    }
    s.parse::<IpAddr>()
        .map_err(|_| InputViolation::NotIpAddress.into())
}

/// 検証済みの `--add-host` 1 件（hostname と IP）。不正値を表現できない型で、hosts ファイルへ書く行は
/// この型からのみ描画する（行注入を型で防ぐ。NET-12）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddHostEntry {
    host: HostName,
    ip: IpAddr,
}

impl AddHostEntry {
    /// `<hostname>:<ip>` を最初の `:` で 2 分割して検証する。左が hostname、残り全体が IP
    /// （hostname は `:` を含まないため `host:::1` は (`host`, `::1`)）。違反は `INVALID_ARGUMENT`（NET-12）。
    pub fn parse(s: &str) -> Result<Self, NetError> {
        if s.len() > MAX_ADD_HOST_LEN {
            return Err(InputViolation::AddHostTooLong.into());
        }
        let (host, ip) = s
            .split_once(':')
            .ok_or(InputViolation::MissingHostIpSeparator)?;
        Ok(Self {
            host: HostName::parse(host)?,
            ip: parse_ip_addr(ip)?,
        })
    }

    /// 検証済み hostname。
    pub fn host(&self) -> &HostName {
        &self.host
    }

    /// 検証済み IP。
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
}

/// 複数の `--add-host` 値を全件検証して返す。1 件でも不正、または件数が上限超過なら `Err`（副作用なし）。
pub fn parse_add_hosts<'a, I>(raw: I) -> Result<Vec<AddHostEntry>, NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for s in raw {
        if out.len() >= MAX_ADD_HOST_ENTRIES {
            return Err(InputViolation::TooManyAddHosts.into());
        }
        out.push(AddHostEntry::parse(s)?);
    }
    Ok(out)
}

/// hosts ファイル形式の行（`<ip>\t<hostname>\n`）へ描画する。IP は `IpAddr` の正規化表記になる。
pub fn render_hosts_lines(entries: &[AddHostEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!("{}\t{}\n", e.ip, e.host.as_str()));
    }
    out
}

fn io_err(msg: &'static str) -> NetError {
    NetError::new(NetErrorCode::Internal, msg)
}

/// 開いた fd が通常ファイルでパスと同一であること（open 前後の差し替え・symlink 化の検知）を確認する。
fn verify_hosts_file(file: &File, path: &Path) -> Result<(), NetError> {
    let meta = file
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?;
    if !meta.file_type().is_file() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path is not a regular file",
        ));
    }
    if meta.len() > MAX_HOSTS_FILE_BYTES {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "hosts file is too large",
        ));
    }
    let via_path =
        std::fs::symlink_metadata(path).map_err(|_| io_err("failed to stat hosts file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // ハードリンク経由でコンテナ外のファイルへ追記させない（rootfs・マウント境界）。
        // 管理下の hosts ファイルは他のどこからもリンクされない（nlink == 1）。
        if meta.nlink() != 1 {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "hosts file has multiple hard links",
            ));
        }
        // 所有者は実効 UID と一致すること（他ユーザー所有のファイルへ追記しない）。
        #[cfg(target_os = "linux")]
        if meta.uid() != crate::sys::effective_uid() {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "hosts file is not owned by the current user",
            ));
        }
        if via_path.dev() != meta.dev() || via_path.ino() != meta.ino() {
            return Err(NetError::new(
                NetErrorCode::FailedPrecondition,
                "hosts file was replaced while opening",
            ));
        }
    }
    #[cfg(not(unix))]
    if !via_path.file_type().is_file() {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file was replaced while opening",
        ));
    }
    Ok(())
}

/// 管理ルート配下の相対パスを安全に解決する（NET-12・TASK-185.2。コンテナ分離の境界）。
///
/// `rel` は空でない相対パスで、全要素が通常の名前（絶対パス・`..`・`.`・Windows のプレフィックスは拒否）。
/// 途中ディレクトリは symlink でない実ディレクトリであること、最終要素は symlink でない通常ファイルで
/// あることを確認する。返すのは正規化済みルートに `rel` を連結したパスで、呼び出し側は開いた後に
/// [`verify_within_root`] で実体がルート配下にあることを再確認する。
fn resolve_in_root(managed_root: &Path, rel: &Path) -> Result<(PathBuf, PathBuf), NetError> {
    let root = std::fs::canonicalize(managed_root).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            NetError::new(NetErrorCode::NotFound, "managed root does not exist")
        } else {
            io_err("failed to resolve managed root")
        }
    })?;
    let mut comps = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => comps.push(n),
            _ => {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    "hosts path must be a plain relative path inside the managed root",
                ));
            }
        }
    }
    let Some((last, dirs)) = comps.split_last() else {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path must not be empty",
        ));
    };
    let mut cur = root.clone();
    for d in dirs {
        cur.push(d);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(NetError::new(
                    NetErrorCode::InvalidArgument,
                    "hosts path has a non-directory or symlink component",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(NetError::new(
                    NetErrorCode::NotFound,
                    "hosts file does not exist",
                ));
            }
            Err(_) => return Err(io_err("failed to stat hosts file")),
        }
    }
    cur.push(last);
    Ok((root, cur))
}

/// 開いた hosts ファイルの実体（シンボリックリンク解決後）が正規化済みルート配下にあることを確認する。
fn verify_within_root(root: &Path, path: &Path) -> Result<(), NetError> {
    let real = std::fs::canonicalize(path).map_err(|_| io_err("failed to resolve hosts file"))?;
    if !real.starts_with(root) {
        return Err(NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file resolves outside the managed root",
        ));
    }
    Ok(())
}

/// `/proc/self/mountinfo` の 1 フィールド内の 8 進エスケープ（`\040` 等）を元に戻す。
#[cfg(target_os = "linux")]
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b
            .get(i + 1..i + 4)
            .filter(|d| b[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        if let Some(d) = oct {
            let v = d.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
            out.push((v & 0xff) as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// mountinfo の本文に、`root` 配下（`root` 自身は除く）かつ `path` の祖先または `path` 自身である
/// マウントポイントが含まれるかを返す（管理ルート内の bind mount 検出。パス要素ごとに判定する）。
#[cfg(target_os = "linux")]
fn mountinfo_has_inner_mount(text: &str, root: &Path, path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    text.lines().any(|line| {
        let Some(mp) = line.split(' ').nth(4) else {
            return false;
        };
        let mp = Path::new(std::ffi::OsStr::from_bytes(&unescape_mountinfo(mp))).to_path_buf();
        mp != root && mp.starts_with(root) && path.starts_with(&mp)
    })
}

/// 管理ルート内に外部ファイルを指す mount（bind mount 等）が無いことを確認する（P0・rootfs / マウント境界）。
///
/// `canonicalize` は mount を辿れないため、(1) 開いた fd のデバイスがルートと同一であること、
/// (2) Linux では `/proc/self/mountinfo` に hosts パスまたはその祖先（ルートより下）のマウントポイントが
/// 無いこと、を検査する。読めない・巨大な場合は fail-closed で拒否する。
fn verify_no_foreign_mount(root: &Path, path: &Path, file: &File) -> Result<(), NetError> {
    #[cfg_attr(not(unix), allow(unused_variables))]
    let foreign = || {
        NetError::new(
            NetErrorCode::FailedPrecondition,
            "hosts file lives on a mount outside the managed root",
        )
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let fm = file
            .metadata()
            .map_err(|_| io_err("failed to stat hosts file"))?;
        let rm = std::fs::metadata(root).map_err(|_| io_err("failed to stat managed root"))?;
        if fm.dev() != rm.dev() {
            return Err(foreign());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut text = String::new();
        File::open("/proc/self/mountinfo")
            .and_then(|f| f.take(MAX_MOUNTINFO_BYTES + 1).read_to_string(&mut text))
            .map_err(|_| io_err("failed to read mountinfo"))?;
        if u64::try_from(text.len()).is_ok_and(|n| n > MAX_MOUNTINFO_BYTES) {
            return Err(io_err("mountinfo is too large"));
        }
        if mountinfo_has_inner_mount(&text, root, path) {
            return Err(foreign());
        }
    }
    #[cfg(not(any(unix, target_os = "linux")))]
    let _ = (root, path, file);
    Ok(())
}

/// `/proc/self/mountinfo` の読み込み上限（無制限確保の防止）。
#[cfg(target_os = "linux")]
const MAX_MOUNTINFO_BYTES: u64 = 4 * 1024 * 1024;

/// 書き込み失敗後に書き込み前の長さへ戻し、結果に応じたエラーを返す。
///
/// 巻き戻し（切り詰め + fsync）まで成功した場合のみ通常の `INTERNAL`（ファイルは元の内容）。
/// 失敗した場合は不完全な行が残りうるため `DATA_LOSS` で区別する（再試行はその後ろへ追記してしまうため
/// 呼び出し側は hosts ファイルを再生成するなど復旧が必要）。`sync_all` 失敗後の切り詰めも
/// 永続化を確認するため再度 fsync する。
fn rollback_after_failure(file: &File, len: u64) -> NetError {
    if file.set_len(len).and_then(|_| file.sync_all()).is_ok() {
        io_err("failed to write hosts file")
    } else {
        NetError::new(
            NetErrorCode::DataLoss,
            "failed to write hosts file and failed to roll back; file may be corrupted",
        )
    }
}

/// hosts ファイルの排他ロックを期限つきで取得する（プロセス間の直列化。REPAIR-5）。
///
/// `deadline` は呼び出し側が決めた全体の期限で、同一プロセス内ミューテックス待ちと共有する。
fn lock_exclusive_bounded(file: &File, deadline: Instant) -> Result<(), NetError> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for hosts file lock",
                    ));
                }
                std::thread::sleep(HOSTS_LOCK_POLL);
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(io_err("failed to lock hosts file"));
            }
        }
    }
}

/// 同一プロセス内の追記ミューテックスを期限つきで取得する（`try_lock` のポーリング。REPAIR-5）。
///
/// 先行追記が `sync_all` 等で停止しても、後続は `deadline` で `TIMEOUT` を返し無期限には待たない。
fn lock_guard_bounded(deadline: Instant) -> Result<std::sync::MutexGuard<'static, ()>, NetError> {
    loop {
        match HOSTS_APPEND_GUARD.try_lock() {
            Ok(g) => return Ok(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(NetError::new(
                        NetErrorCode::Timeout,
                        "timed out waiting for hosts append lock",
                    ));
                }
                std::thread::sleep(HOSTS_LOCK_POLL);
            }
        }
    }
}

/// 検証済みエントリをコンテナの hosts ファイルへ追記する（NET-12・TASK-185.2）。
///
/// `managed_root` は管理ルート（コンテナ状態ディレクトリ）、`hosts_rel` はその配下の hosts ファイルへの
/// 相対パスで、ネットワークモードに依存しない。ルート外（絶対パス・`..`・symlink 経由）は指せない。
/// 既存の通常ファイルにのみ追記し（symlink・非通常ファイルは拒否、無ければ `NOT_FOUND` で作成しない）、
/// tmp + rename は使わない（bind mount 済みファイルの inode を保つため）。`O_APPEND` で 1 回の
/// `write_all` にまとめ、既存内容の末尾が改行でなければ先頭に改行を補う。`entries` が空なら何も開かない。
pub fn append_add_hosts(
    managed_root: &Path,
    hosts_rel: &Path,
    entries: &[AddHostEntry],
) -> Result<(), NetError> {
    if entries.is_empty() {
        return Ok(());
    }
    // 公開 API 単体でも件数を上限検証する（parse_add_hosts を経由しない呼び出しでの無制限確保を防ぐ）。
    if entries.len() > MAX_ADD_HOST_ENTRIES {
        return Err(InputViolation::TooManyAddHosts.into());
    }
    let (root, hosts_path) = resolve_in_root(managed_root, hosts_rel)?;
    let hosts_path = hosts_path.as_path();
    let meta = match std::fs::symlink_metadata(hosts_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(NetError::new(
                NetErrorCode::NotFound,
                "hosts file does not exist",
            ));
        }
        Err(_) => return Err(io_err("failed to stat hosts file")),
    };
    if !meta.file_type().is_file() {
        return Err(NetError::new(
            NetErrorCode::InvalidArgument,
            "hosts path is not a regular file",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(hosts_path)
        .map_err(|_| io_err("failed to open hosts file"))?;
    verify_within_root(&root, hosts_path)?;
    // 長さ取得・末尾改行判定・上限判定・追記を 1 つの排他区間にする（並行追記による上限超過・
    // 古い末尾内容に基づく改行判定を防ぐ）。ロックは file の Drop で解放される。
    let deadline = Instant::now() + HOSTS_LOCK_TIMEOUT;
    let _guard = lock_guard_bounded(deadline)?;
    lock_exclusive_bounded(&file, deadline)?;
    verify_hosts_file(&file, hosts_path)?;
    verify_no_foreign_mount(&root, hosts_path, &file)?;

    let len = file
        .metadata()
        .map_err(|_| io_err("failed to stat hosts file"))?
        .len();
    let mut payload = String::new();
    if len > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))
            .and_then(|_| file.read_exact(&mut last))
            .map_err(|_| io_err("failed to read hosts file"))?;
        if last[0] != b'\n' {
            payload.push('\n');
        }
    }
    payload.push_str(&render_hosts_lines(entries));
    // 追記後のファイルサイズが上限を超える場合は書き込まない（既存 1 MiB ちょうどへの追記も拒否）。
    let new_len = u64::try_from(payload.len())
        .ok()
        .and_then(|p| len.checked_add(p));
    if new_len.is_none_or(|n| n > MAX_HOSTS_FILE_BYTES) {
        return Err(NetError::new(
            NetErrorCode::ResourceExhausted,
            "hosts file would exceed size limit",
        ));
    }
    // 容量不足等で途中まで書いて失敗すると不完全な行が残り、再試行でその後ろへ追記されてしまう。
    // 排他ロックを保持したまま書き込み前の長さへ戻し、失敗後のファイルを元の状態に保つ。
    let written = file
        .write_all(payload.as_bytes())
        .and_then(|_| file.sync_all());
    if written.is_err() {
        return Err(rollback_after_failure(&file, len));
    }
    Ok(())
}

/// `--add-host` の生値を全件検証してから hosts ファイルへ追記する入口（NET-12・TASK-185.2）。
///
/// 検証が全件通るまでファイルを開かないため、検証失敗時に hosts ファイルは変更されない。
/// 計測しない呼び出し口で、成否・所要時間を記録するには [`apply_add_hosts_with_recorder`] を使う。
pub fn apply_add_hosts<'a, I>(managed_root: &Path, hosts_rel: &Path, raw: I) -> Result<(), NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    apply_add_hosts_with_recorder(managed_root, hosts_rel, raw, &NoopNetOpRecorder)
}

/// [`apply_add_hosts`] に計装を付けた入口（REPAIR-4）。検証から追記・fsync までの成否と所要時間を
/// `NetOpKind::AddHostsApply` として `recorder` へ渡す（入力値・パスは記録しない）。
pub fn apply_add_hosts_with_recorder<'a, I>(
    managed_root: &Path,
    hosts_rel: &Path,
    raw: I,
    recorder: &dyn NetOpRecorder,
) -> Result<(), NetError>
where
    I: IntoIterator<Item = &'a str>,
{
    record_net_op(recorder, NetOpKind::AddHostsApply, || {
        let entries = parse_add_hosts(raw)?;
        append_add_hosts(managed_root, hosts_rel, &entries)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_err(s: &str) -> NetError {
        HostName::parse(s).expect_err(s)
    }

    fn assert_violation(e: &NetError, v: InputViolation) {
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(e.message(), v.message());
    }

    /// NET-12: 正常な hostname は入力のまま受理する。
    #[test]
    fn accepts_valid_hostnames() {
        for s in [
            "localhost",
            "my-host",
            "a.example.com",
            "Web01.Example",
            "123",
        ] {
            assert_eq!(HostName::parse(s).unwrap().as_str(), s);
        }
    }

    /// NET-12・R1: 空 hostname。
    #[test]
    fn rejects_empty_hostname() {
        assert_violation(&host_err(""), InputViolation::EmptyHostname);
    }

    /// NET-12・R2: ラベル長・総長の境界値。
    #[test]
    fn label_and_total_length_boundaries() {
        assert!(HostName::parse(&"a".repeat(63)).is_ok());
        assert_violation(&host_err(&"a".repeat(64)), InputViolation::LabelLength);

        let total253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(total253.len(), 253);
        assert!(HostName::parse(&total253).is_ok());
        let total254 = format!("{total253}d");
        assert_eq!(total254.len(), 254);
        assert_violation(&host_err(&total254), InputViolation::HostnameTooLong);
    }

    /// NET-12・R2: ハイフン端・空ラベル・文字種。
    #[test]
    fn rejects_bad_labels() {
        for s in ["-a.b", "a-.b", "a.-b"] {
            assert_violation(&host_err(s), InputViolation::LabelHyphenEdge);
        }
        for s in ["a..b", "a.", ".a"] {
            assert_violation(&host_err(s), InputViolation::LabelLength);
        }
        for s in ["a_b", "例え.jp"] {
            assert_violation(&host_err(s), InputViolation::InvalidHostnameChar);
        }
    }

    /// NET-12・R3: IP の受理（値も照合）。
    #[test]
    fn accepts_ip_addresses() {
        assert_eq!(parse_ip_addr("192.0.2.1").unwrap().to_string(), "192.0.2.1");
        assert_eq!(parse_ip_addr("::1").unwrap().to_string(), "::1");
        assert_eq!(
            parse_ip_addr("2001:db8::1").unwrap().to_string(),
            "2001:db8::1"
        );
        assert!(parse_ip_addr("::ffff:192.0.2.1").unwrap().is_ipv6());
    }

    /// NET-12・R3: IPv4 / IPv6 として解釈できない値。
    #[test]
    fn rejects_non_ip() {
        for s in [
            "",
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4/24",
            "[::1]",
            "fe80::1%eth0",
            "010.0.0.1",
            "example.com",
        ] {
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::NotIpAddress);
        }
    }

    /// NET-12・R4: 制御文字・空白は hostname・IP の両方で最優先で拒否する。
    #[test]
    fn rejects_control_and_whitespace() {
        let bad = [
            "a\nb",
            "a\rb",
            "a\tb",
            "a\0b",
            "a\x7fb",
            "a\u{85}b",
            "a\u{a0}b",
            "a\u{3000}b",
            " a",
            "a ",
            "my host",
        ];
        for s in bad {
            assert_violation(&host_err(s), InputViolation::ControlOrWhitespace);
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::ControlOrWhitespace);
        }
        for s in [" 192.0.2.1", "192.0.2.1 ", "192.0.2.1\n"] {
            let e = parse_ip_addr(s).expect_err(s);
            assert_violation(&e, InputViolation::ControlOrWhitespace);
        }
        assert_violation(
            &host_err("a\n1.2.3.4 evil"),
            InputViolation::ControlOrWhitespace,
        );
    }

    /// NET-12・R5・ERR-1: 理由の識別子・メッセージ・NetError 変換の具体値。
    #[test]
    fn violation_strings_and_net_error() {
        let table = [
            (InputViolation::ControlOrWhitespace, "CONTROL_OR_WHITESPACE"),
            (InputViolation::EmptyHostname, "EMPTY_HOSTNAME"),
            (InputViolation::HostnameTooLong, "HOSTNAME_TOO_LONG"),
            (InputViolation::LabelLength, "LABEL_LENGTH"),
            (InputViolation::LabelHyphenEdge, "LABEL_HYPHEN_EDGE"),
            (InputViolation::InvalidHostnameChar, "INVALID_HOSTNAME_CHAR"),
            (InputViolation::NotIpAddress, "NOT_IP_ADDRESS"),
            (InputViolation::MissingHostIpSeparator, "MISSING_SEPARATOR"),
            (InputViolation::AddHostTooLong, "ADD_HOST_TOO_LONG"),
            (InputViolation::TooManyAddHosts, "TOO_MANY_ADD_HOSTS"),
            (
                InputViolation::NotLoopbackForNoneMode,
                "NOT_LOOPBACK_FOR_NONE_MODE",
            ),
        ];
        for (v, s) in table {
            assert_eq!(v.as_str(), s);
        }
        let e: NetError = InputViolation::EmptyHostname.into();
        assert_eq!(e.code().as_str(), "INVALID_ARGUMENT");
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: invalid hostname: empty");
    }

    /// NET-12: エラーメッセージに入力値を載せない（ログ注入防止）。
    #[test]
    fn message_does_not_echo_input() {
        let e = host_err("evil\ninjected");
        assert!(!e.message().contains("evil"));
        let e = parse_ip_addr("evil\ninjected").unwrap_err();
        assert!(!e.message().contains("evil"));
    }

    fn entry_err(s: &str) -> NetError {
        AddHostEntry::parse(s).expect_err(s)
    }

    /// NET-12: 最初の `:` で分割し、残り全体を IP とする（IPv6 を含む）。
    #[test]
    fn add_host_splits_on_first_colon() {
        for (raw, host, ip) in [
            ("host:192.0.2.1", "host", "192.0.2.1"),
            ("host:::1", "host", "::1"),
            ("host:2001:db8::1", "host", "2001:db8::1"),
            (
                "a.example:::ffff:192.0.2.1",
                "a.example",
                "::ffff:192.0.2.1",
            ),
        ] {
            let e = AddHostEntry::parse(raw).unwrap();
            assert_eq!(e.host().as_str(), host);
            assert_eq!(e.ip().to_string(), ip);
        }
    }

    /// NET-12・ERR-1: 分割・検証の拒否（INVALID_ARGUMENT と理由を具体値で照合）。
    #[test]
    fn add_host_rejects_bad_entries() {
        for (raw, v) in [
            ("host:", InputViolation::NotIpAddress),
            (":1.2.3.4", InputViolation::EmptyHostname),
            ("host", InputViolation::MissingHostIpSeparator),
            ("", InputViolation::MissingHostIpSeparator),
            ("host:fe80::1%eth0", InputViolation::NotIpAddress),
            ("host:[::1]", InputViolation::NotIpAddress),
            ("host:host-gateway", InputViolation::NotIpAddress),
            ("bad host:1.2.3.4", InputViolation::ControlOrWhitespace),
            (
                "a\n1.2.3.4 evil:1.2.3.4",
                InputViolation::ControlOrWhitespace,
            ),
            ("host:1.2.3.4\n", InputViolation::ControlOrWhitespace),
        ] {
            assert_violation(&entry_err(raw), v);
        }
        let long = format!("{}:1.2.3.4", "a".repeat(MAX_ADD_HOST_LEN));
        assert_violation(&entry_err(&long), InputViolation::AddHostTooLong);
    }

    /// NET-12: 複数件は順序どおり、1 件でも不正なら全体が Err、件数は上限ちょうどまで。
    #[test]
    fn parse_add_hosts_all_or_nothing_and_limit() {
        let v = parse_add_hosts(["web:192.0.2.1", "db:2001:db8::1"]).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].host().as_str(), "web");
        assert_eq!(v[1].ip().to_string(), "2001:db8::1");
        assert_violation(
            &parse_add_hosts(["web:192.0.2.1", "bad host:192.0.2.2"]).unwrap_err(),
            InputViolation::ControlOrWhitespace,
        );
        let ok = vec!["h:192.0.2.1"; MAX_ADD_HOST_ENTRIES];
        assert_eq!(parse_add_hosts(ok.iter().copied()).unwrap().len(), 256);
        let over = vec!["h:192.0.2.1"; MAX_ADD_HOST_ENTRIES + 1];
        assert_violation(
            &parse_add_hosts(over.iter().copied()).unwrap_err(),
            InputViolation::TooManyAddHosts,
        );
    }

    /// NET-12: hosts 行の描画（タブ区切り・IPv6 正規化表記）。
    #[test]
    fn render_lines_exact_bytes() {
        let v = parse_add_hosts(["web:192.0.2.1", "db:2001:DB8:0:0:0:0:0:1"]).unwrap();
        assert_eq!(render_hosts_lines(&v), "192.0.2.1\tweb\n2001:db8::1\tdb\n");
        assert_eq!(render_hosts_lines(&[]), "");
    }

    /// ケースごとの一時管理ルート。`.0` は管理ルート配下の hosts ファイルの絶対パス（相対名は `hosts`）。
    struct TmpFile {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
    }
    impl TmpFile {
        fn new(case: &str, content: Option<&str>) -> Self {
            let root =
                std::env::temp_dir().join(format!("fc-addhost-{}-{case}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("hosts");
            if let Some(c) = content {
                std::fs::write(&path, c).unwrap();
            }
            Self { root, path }
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn run<'a>(f: &TmpFile, raw: impl IntoIterator<Item = &'a str>) -> Result<(), NetError> {
        apply_add_hosts(&f.root, Path::new("hosts"), raw)
    }

    /// NET-12・TASK-185.2: 既存内容の後ろへ追記される。
    #[test]
    fn append_to_existing_file() {
        let f = TmpFile::new("append", Some("127.0.0.1\tlocalhost\n"));
        run(&f, ["web:192.0.2.1", "db:::1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "127.0.0.1\tlocalhost\n192.0.2.1\tweb\n::1\tdb\n"
        );
    }

    /// NET-12: 末尾改行が無い既存内容には改行を補って行の癒着を防ぐ。
    #[test]
    fn append_adds_missing_newline() {
        let f = TmpFile::new("nonl", Some("127.0.0.1\tlocalhost"));
        run(&f, ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "127.0.0.1\tlocalhost\n192.0.2.1\tweb\n"
        );
    }

    /// NET-12: 空ファイルへは改行を補わない。空エントリはファイルを変更しない。
    #[test]
    fn append_empty_file_and_empty_entries() {
        let f = TmpFile::new("empty", Some(""));
        run(&f, ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&f.path).unwrap(),
            "192.0.2.1\tweb\n"
        );
        let g = TmpFile::new("noentries", Some("x"));
        run(&g, std::iter::empty()).unwrap();
        assert_eq!(std::fs::read_to_string(&g.path).unwrap(), "x");
    }

    /// NET-12: append_add_hosts 単体でも件数上限を検証し、ファイルを変更しない。
    #[test]
    fn append_rejects_too_many_entries() {
        let f = TmpFile::new("toomany", Some("x\n"));
        let one = AddHostEntry::parse("h:192.0.2.1").unwrap();
        let entries = vec![one; MAX_ADD_HOST_ENTRIES + 1];
        let e = append_add_hosts(&f.root, Path::new("hosts"), &entries).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"x\n");
    }

    /// NET-12: 追記後に上限を超えるファイルは拒否し、ちょうど上限に収まる場合は許可する。
    #[test]
    fn append_rejects_growth_beyond_size_limit() {
        let line = "192.0.2.1\th\n"; // 12 バイト
        let max = MAX_HOSTS_FILE_BYTES as usize;
        let ok = TmpFile::new("fits", Some(&"a".repeat(max - line.len() - 1)));
        // 末尾改行なし: 改行 1 + 行 12 でちょうど上限。
        run(&ok, ["h:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::metadata(&ok.path).unwrap().len(),
            MAX_HOSTS_FILE_BYTES
        );

        let full = TmpFile::new("full", Some(&"a".repeat(max)));
        let e = run(&full, ["h:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
        assert_eq!(
            std::fs::metadata(&full.path).unwrap().len(),
            MAX_HOSTS_FILE_BYTES
        );

        let near = TmpFile::new("near", Some(&"a".repeat(max - line.len())));
        let e = run(&near, ["h:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::ResourceExhausted);
    }

    /// NET-12: 存在しないパスは NOT_FOUND で、ファイルを作らない。
    #[test]
    fn missing_file_is_not_created() {
        let f = TmpFile::new("missing", None);
        let e = run(&f, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::NotFound);
        assert!(!f.path.exists());
    }

    /// NET-12: ディレクトリ（非通常ファイル）は INVALID_ARGUMENT。
    #[test]
    fn directory_is_rejected() {
        let f = TmpFile::new("dir", None);
        std::fs::create_dir(f.root.join("sub")).unwrap();
        let e = apply_add_hosts(&f.root, Path::new("sub"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
    }

    /// NET-12: symlink は拒否し、リンク先を変更しない。
    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected() {
        let target = TmpFile::new("symtarget", Some("orig\n"));
        let link = TmpFile::new("symlink", None);
        std::os::unix::fs::symlink(&target.path, &link.path).unwrap();
        let e = run(&link, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_to_string(&target.path).unwrap(), "orig\n");
    }

    /// NET-12: ハードリンクされたファイルへは追記せず、リンク先も変更しない。
    #[cfg(unix)]
    #[test]
    fn hard_link_is_rejected() {
        let target = TmpFile::new("hltarget", Some("orig\n"));
        let link = TmpFile::new("hllink", None);
        std::fs::hard_link(&target.path, &link.path).unwrap();
        let e = run(&link, ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(std::fs::read_to_string(&target.path).unwrap(), "orig\n");
    }

    /// NET-12・P0: 管理ルート外を指す相対パス（`..`・絶対パス・`.`・空）は拒否し、ファイルを変更しない。
    #[test]
    fn paths_escaping_managed_root_are_rejected() {
        let outside = TmpFile::new("outside", Some("orig\n"));
        let f = TmpFile::new("inside", Some("in\n"));
        let up = Path::new("..")
            .join(outside.root.file_name().unwrap())
            .join("hosts");
        for rel in [
            up.as_path(),
            outside.path.as_path(), // 絶対パス（管理ルート外）
            Path::new("./hosts"),
            Path::new(""),
        ] {
            let e = apply_add_hosts(&f.root, rel, ["web:192.0.2.1"]).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{rel:?}");
        }
        assert_eq!(std::fs::read_to_string(&outside.path).unwrap(), "orig\n");
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), "in\n");
    }

    /// NET-12・P0: 管理ルート配下でも途中ディレクトリが管理外への symlink なら拒否する。
    #[cfg(unix)]
    #[test]
    fn symlinked_directory_component_is_rejected() {
        let outside = TmpFile::new("symdir-out", Some("orig\n"));
        let f = TmpFile::new("symdir-in", None);
        std::os::unix::fs::symlink(&outside.root, f.root.join("link")).unwrap();
        let e = apply_add_hosts(&f.root, Path::new("link/hosts"), ["web:192.0.2.1"]).unwrap_err();
        assert_eq!(e.code(), NetErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_to_string(&outside.path).unwrap(), "orig\n");
    }

    /// NET-12: 管理ルート配下のサブディレクトリの hosts ファイルには追記できる。
    #[test]
    fn nested_relative_path_inside_root_is_accepted() {
        let f = TmpFile::new("nested", None);
        std::fs::create_dir(f.root.join("c1")).unwrap();
        std::fs::write(f.root.join("c1").join("hosts"), "a\n").unwrap();
        apply_add_hosts(&f.root, Path::new("c1/hosts"), ["web:192.0.2.1"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(f.root.join("c1").join("hosts")).unwrap(),
            "a\n192.0.2.1\tweb\n"
        );
    }

    /// NET-12・P1: 巻き戻しに失敗したら `DATA_LOSS`（復旧不能）で区別して返す。
    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_detects_inner_bind_mount() {
        let root = Path::new("/run/c/1");
        let hosts = Path::new("/run/c/1/etc/hosts");
        let mi = |mp: &str| format!("100 90 8:1 /x {mp} rw - ext4 /dev/sda1 rw\n");
        // ファイル自体・祖先ディレクトリへの mount は検出する
        assert!(mountinfo_has_inner_mount(
            &mi("/run/c/1/etc/hosts"),
            root,
            hosts
        ));
        assert!(mountinfo_has_inner_mount(&mi("/run/c/1/etc"), root, hosts));
        // ルート自身・ルート外・無関係な兄弟は検出しない
        assert!(!mountinfo_has_inner_mount(&mi("/run/c/1"), root, hosts));
        assert!(!mountinfo_has_inner_mount(&mi("/run"), root, hosts));
        assert!(!mountinfo_has_inner_mount(&mi("/run/c/1/var"), root, hosts));
        // 8 進エスケープ（空白）を復元して比較する
        let sp = Path::new("/run/c/1/e tc/hosts");
        assert!(mountinfo_has_inner_mount(
            &mi("/run/c/1/e\\040tc"),
            root,
            sp
        ));
    }

    #[test]
    fn rollback_failure_is_reported_as_data_loss() {
        let f = TmpFile::new("rollback-fail", Some("abc\n"));
        // 読み取り専用 fd では set_len が失敗する。
        let ro = File::open(&f.path).unwrap();
        let e = rollback_after_failure(&ro, 0);
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"abc\n");
    }

    /// NET-12・P1: 巻き戻しに成功したら元の長さに戻り、通常の `INTERNAL` を返す。
    #[test]
    fn rollback_success_restores_length_and_is_internal() {
        let f = TmpFile::new("rollback-ok", Some("abc\npartial"));
        let rw = OpenOptions::new().write(true).open(&f.path).unwrap();
        let e = rollback_after_failure(&rw, 4);
        assert_eq!(e.code(), NetErrorCode::Internal);
        assert_eq!(std::fs::read(&f.path).unwrap(), b"abc\n");
    }

    /// NET-12・TASK-185.2 受け入れ基準: 検証失敗時に hosts ファイルは 1 バイトも変わらない。
    #[test]
    fn validation_failure_leaves_file_untouched() {
        let init = "127.0.0.1\tlocalhost\n";
        let f = TmpFile::new("untouched", Some(init));
        let cases: [&[&str]; 6] = [
            &["bad host:192.0.2.2", "ok:192.0.2.1"],
            &["ok:192.0.2.1", "bad host:192.0.2.2"],
            &["ok:192.0.2.1", "nosep", "ok2:192.0.2.3"],
            &["ok:192.0.2.1", "h:999.1.1.1"],
            &["ok:192.0.2.1", "h:1.2.3.4\nevil"],
            &["ok:192.0.2.1", "h:"],
        ];
        for c in cases {
            let e = run(&f, c.iter().copied()).unwrap_err();
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "{c:?}");
            assert_eq!(std::fs::read(&f.path).unwrap(), init.as_bytes(), "{c:?}");
        }
    }

    /// REPAIR-4: 成功・失敗（検証失敗）が `AddHostsApply` として 1 件ずつ記録される。
    #[test]
    fn apply_records_success_and_failure() {
        use crate::instrument::NetOpOutcome;
        use crate::instrument::testing::Collect;
        let f = TmpFile::new("record", Some("127.0.0.1\tlocalhost\n"));
        let c = Collect::default();
        apply_add_hosts_with_recorder(&f.root, Path::new("hosts"), ["web:192.0.2.1"], &c).unwrap();
        apply_add_hosts_with_recorder(&f.root, Path::new("hosts"), ["bad host:192.0.2.1"], &c)
            .unwrap_err();
        assert_eq!(
            c.kinds(),
            vec![
                (NetOpKind::AddHostsApply, NetOpOutcome::Success),
                (NetOpKind::AddHostsApply, NetOpOutcome::Failure),
            ]
        );
    }

    /// NET-12: 並行追記でも上限を超えず、各行が欠落・混在せずちょうど 1 回ずつ入る。
    #[test]
    fn concurrent_appends_are_serialized() {
        let f = TmpFile::new("concurrent", Some(""));
        let path = f.path.clone();
        let root = f.root.clone();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = root.clone();
                std::thread::spawn(move || {
                    let v = format!("h{i}:192.0.2.{i}");
                    apply_add_hosts(&p, Path::new("hosts"), [v.as_str()]).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let got = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = got.lines().collect();
        lines.sort_unstable();
        let want: Vec<String> = (0..8).map(|i| format!("192.0.2.{i}\th{i}")).collect();
        assert_eq!(lines, want.iter().map(String::as_str).collect::<Vec<_>>());
    }
}
