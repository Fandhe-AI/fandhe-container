//! ゲスト内 virtiofs mount の指示・報告契約と、ホスト側の結果待機（MAC-1・TASK-65.3・MS-5）。
//!
//! VM 起動後、追加操作なしで各 virtiofs 共有をゲスト内の指定パスへ mount し、失敗を `Vm::launch` の
//! エラーにするための OS 非依存層。全 OS でビルドし 3 OS CI でテストする。Virtualization.framework には触れない。
//!
//! # 契約（ホスト実装の SSOT。ゲスト init はこの書式に従う）
//!
//! - ホスト → ゲスト（指示）: カーネルコマンドライン末尾へ共有 1 件につき
//!   `fandhe.virtiofs=<tag>:<mountpoint>:<ro|rw>` を空白区切りで 1 つ連結する（[`encode_directives`]）。
//!   `:` は tag の文字種（`VirtiofsTag`）とも mount point の文字種（[`GuestMountPoint`]）とも重ならない。
//!   `ro` / `rw` は共有の `ShareAccess` から導き、指示で権限が広がることはない。ゲスト側は
//!   [`parse_directives`] で復号する。ユーザー指定のコマンドラインに `fandhe.` 始まりのトークンがあれば
//!   [`reject_reserved_keys`] が拒否し、検証済みの型を迂回した指示の差し込みを防ぐ。
//! - ゲスト → ホスト（報告）: シリアルコンソール（hvc0）へ行頭固定の
//!   `fandhe-guest: virtiofs-mount v1 tag=<tag> result=ok` または
//!   `fandhe-guest: virtiofs-mount v1 tag=<tag> result=error errno=<1..=4095>` を共有ごとに 1 行出す
//!   （[`parse_report_line`]。末尾の `\r` は許容、他の揺れは不正行）。カーネルが起動時に出す
//!   `Kernel command line: ...` は行頭が `fandhe-guest:` でないため報告と誤認しない。
//! - mount point は `/mnt/fandhe` 配下に限る。`/`・`/proc`・`/sys`・`/dev` 等を覆う mount を構造的に表現できない。
//!
//! # 呼び出し文脈
//!
//! `config::VmConfigSpec::effective_cmdline` が指示を連結し、`console_log` の書き出しスレッドが
//! [`ReportScanner`] でゲスト出力を走査して [`ReportItem`] を有界チャネルへ送り、`vm::Vm::launch` が
//! [`GuestMountWatch::wait`] で期限付きに待つ（REPAIR-5）。
//!
//! # 信頼前提と限界
//!
//! ゲストの出力は untrusted。行バッファは固定長、チャネルは有界で `try_send` のみ（書き出しスレッドを止めない）。
//! 侵害されたゲストは自身の mount 結果について嘘をつけるが、共有範囲・アクセス権は VZ のデバイス構成で
//! 強制されるためホスト側の境界は弱まらない。`launch` が返った後は受信側を破棄し、以後の報告は無視する。
//!
//! # 未実装（REPAIR-3）
//!
//! 指示を読んで `mount(2)` を実行し報告を出すゲスト init（TASK-64 の Rust 製 init）は本リポに未存在。
//! 実機の end-to-end 検証は TASK-65.4。mount 後の再接続・エラー処理は TASK-65.5。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use crate::config::ConfigError;
use crate::error::GuestMountError;
use crate::virtiofs::{MAX_VIRTIOFS_SHARES, ShareAccess, VirtiofsSharesSpec, VirtiofsTag};
use crate::vm::VmState;

/// ゲスト内 mount point の固定基底。
pub const GUEST_MOUNT_BASE: &str = "/mnt/fandhe";

/// mount point 全体の最大バイト数。
pub const MAX_GUEST_MOUNT_POINT_BYTES: usize = 128;

/// mount point の 1 要素の最大バイト数。
pub const MAX_GUEST_MOUNT_ELEMENT_BYTES: usize = 64;

/// mount point の基底以降の最大要素数。
pub const MAX_GUEST_MOUNT_DEPTH: usize = 4;

/// 指示トークンのキー（`=` まで）。
pub const DIRECTIVE_KEY: &str = "fandhe.virtiofs=";

/// 予約キーの接頭辞（ユーザー cmdline では使えない）。
pub const RESERVED_KEY_PREFIX: &str = "fandhe.";

/// 報告行の接頭辞（行頭固定）。
pub const REPORT_PREFIX: &str = "fandhe-guest: virtiofs-mount";

/// 報告 1 行の最大バイト数（改行を除く）。超えた行は改行まで読み捨てる。
pub const MAX_REPORT_LINE_BYTES: usize = 256;

/// `Vm::launch` が待機する間隔（VM 停止の検知粒度）。
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// ゲスト内の mount point。`GUEST_MOUNT_BASE` 配下の検証済みパスのみ（REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMountPoint(String);

impl GuestMountPoint {
    /// 基底配下・要素の文字種・長さ・深さを検証して生成する。長さを先に検証してから所有化する。
    pub fn try_new(path: &str) -> Result<Self, ConfigError> {
        if path.len() > MAX_GUEST_MOUNT_POINT_BYTES {
            return Err(ConfigError::GuestMountPointTooLong {
                len: path.len(),
                max: MAX_GUEST_MOUNT_POINT_BYTES,
            });
        }
        let rest = path
            .strip_prefix(GUEST_MOUNT_BASE)
            .and_then(|r| r.strip_prefix('/'))
            .ok_or(ConfigError::GuestMountPointNotUnderBase)?;
        let mut offset = path.len().saturating_sub(rest.len());
        for (depth, element) in rest.split('/').enumerate() {
            if depth >= MAX_GUEST_MOUNT_DEPTH
                || element.is_empty()
                || element == "."
                || element == ".."
            {
                return Err(ConfigError::GuestMountPointInvalid { index: offset });
            }
            if element.len() > MAX_GUEST_MOUNT_ELEMENT_BYTES {
                return Err(ConfigError::GuestMountPointTooLong {
                    len: element.len(),
                    max: MAX_GUEST_MOUNT_ELEMENT_BYTES,
                });
            }
            if let Some(i) = element
                .bytes()
                .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
            {
                return Err(ConfigError::GuestMountPointInvalid { index: offset + i });
            }
            offset = offset.saturating_add(element.len()).saturating_add(1);
        }
        Ok(Self(path.to_string()))
    }

    /// 検証済みのパス文字列。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 2 つの mount point が同一または一方が他方の配下か（要素単位・大文字小文字非区別で fail-closed）。
    pub(crate) fn overlaps(&self, other: &GuestMountPoint) -> bool {
        self.0
            .split('/')
            .zip(other.0.split('/'))
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

/// 共有に対応するゲスト mount 指示（ゲスト init が復号して使う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMountDirective {
    /// virtiofs 共有タグ。
    pub tag: VirtiofsTag,
    /// ゲスト内の mount point。
    pub mount_point: GuestMountPoint,
    /// アクセス権（ReadOnly は必ず `ro`）。
    pub access: ShareAccess,
}

/// 指示トークンの復号失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveError {
    /// 指示の件数が `MAX_VIRTIOFS_SHARES` を超えた。
    TooMany,
    /// 書式不正（`index` は指示トークンの通し番号）。
    Malformed { index: usize },
}

/// guest_mount 指定のある共有を指示トークン列（空白区切り）にする。指定が無ければ空文字列。
pub fn encode_directives(shares: &VirtiofsSharesSpec) -> String {
    let tokens: Vec<String> = shares
        .shares()
        .iter()
        .filter_map(|s| {
            let mp = s.guest_mount.as_ref()?;
            let mode = if s.access.is_read_only() { "ro" } else { "rw" };
            Some(format!(
                "{DIRECTIVE_KEY}{}:{}:{mode}",
                s.tag.as_str(),
                mp.as_str()
            ))
        })
        .collect();
    tokens.join(" ")
}

/// コマンドラインから指示トークンを復号する（ゲスト init 側の対。他のトークンは無視する）。
pub fn parse_directives(cmdline: &str) -> Result<Vec<GuestMountDirective>, DirectiveError> {
    let mut out = Vec::new();
    // /proc/cmdline は末尾に改行を持つため、空白類（改行・タブ含む）で区切る。
    for token in cmdline.split_ascii_whitespace() {
        let Some(body) = token.strip_prefix(DIRECTIVE_KEY) else {
            continue;
        };
        let index = out.len();
        if index >= MAX_VIRTIOFS_SHARES {
            return Err(DirectiveError::TooMany);
        }
        let bad = DirectiveError::Malformed { index };
        let parts: Vec<&str> = body.split(':').collect();
        let [tag, mp, mode] = parts.as_slice() else {
            return Err(bad);
        };
        let access = match *mode {
            "ro" => ShareAccess::ReadOnly,
            "rw" => ShareAccess::ReadWrite,
            _ => return Err(bad),
        };
        out.push(GuestMountDirective {
            tag: VirtiofsTag::try_new(tag).map_err(|_| bad)?,
            mount_point: GuestMountPoint::try_new(mp).map_err(|_| bad)?,
            access,
        });
    }
    Ok(out)
}

/// ユーザー指定のコマンドラインに予約キー（`fandhe.` 始まり）のトークンがあれば拒否する。
pub fn reject_reserved_keys(cmdline: &str) -> Result<(), ConfigError> {
    let mut offset = 0usize;
    for token in cmdline.split(' ') {
        if token.starts_with(RESERVED_KEY_PREFIX) {
            return Err(ConfigError::CommandLineReservedKey { index: offset });
        }
        offset = offset.saturating_add(token.len()).saturating_add(1);
    }
    Ok(())
}

/// ゲストの mount 結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestMountOutcome {
    /// mount に成功した。
    Mounted,
    /// 失敗した（ゲストの errno。1..=4095）。
    Failed { errno: u16 },
}

/// ゲストが報告した 1 共有分の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMountReport {
    /// 共有タグ。
    pub tag: VirtiofsTag,
    /// 結果。
    pub outcome: GuestMountOutcome,
}

/// 接頭辞は報告行だが書式が不正だった（理由は固定文字列）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportParseError {
    /// 不正の理由（英語の固定文字列）。
    pub reason: &'static str,
}

/// 書き出しスレッドから待機側へ渡す 1 件。
pub type ReportItem = Result<GuestMountReport, ReportParseError>;

/// 1 行（改行を除く）が報告行なら復号する。接頭辞が一致しない行は `None`（カーネルログ等）。
pub fn parse_report_line(line: &[u8]) -> Option<ReportItem> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if !line.starts_with(REPORT_PREFIX.as_bytes()) {
        return None;
    }
    let err = |reason| Some(Err(ReportParseError { reason }));
    let Ok(text) = std::str::from_utf8(line) else {
        return err("not valid UTF-8");
    };
    let tokens: Vec<&str> = text.split(' ').collect();
    let (tag_tok, rest) = match tokens.as_slice() {
        ["fandhe-guest:", "virtiofs-mount", "v1", tag, rest @ ..] => (*tag, rest),
        _ => return err("unexpected format or version"),
    };
    let Some(tag) = tag_tok.strip_prefix("tag=") else {
        return err("missing tag field");
    };
    let Ok(tag) = VirtiofsTag::try_new(tag) else {
        return err("invalid tag");
    };
    let outcome = match rest {
        ["result=ok"] => GuestMountOutcome::Mounted,
        ["result=error", errno] => {
            let parsed = errno
                .strip_prefix("errno=")
                .filter(|d| !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|d| d.parse::<u16>().ok())
                .filter(|n| (1..=4095).contains(n));
            match parsed {
                Some(errno) => GuestMountOutcome::Failed { errno },
                None => return err("invalid errno"),
            }
        }
        _ => return err("unexpected result field"),
    };
    Some(Ok(GuestMountReport { tag, outcome }))
}

/// チャンク分割されたゲスト出力を行へ組み立てて報告行だけ取り出す、固定長バッファの走査器。
///
/// 長さ上限（[`MAX_REPORT_LINE_BYTES`]）を超えた行は改行まで読み捨てる（無制限確保の防止）。
#[derive(Debug)]
pub struct ReportScanner {
    buf: [u8; MAX_REPORT_LINE_BYTES],
    len: usize,
    discarding: bool,
}

impl Default for ReportScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportScanner {
    /// 空の走査器。
    pub fn new() -> Self {
        Self {
            buf: [0; MAX_REPORT_LINE_BYTES],
            len: 0,
            discarding: false,
        }
    }

    /// 出力の一部を渡し、完成した報告行ごとに `on_item` を呼ぶ。
    pub fn feed(&mut self, chunk: &[u8], on_item: &mut dyn FnMut(ReportItem)) {
        for &b in chunk {
            if b == b'\n' {
                if !self.discarding
                    && let Some(line) = self.buf.get(..self.len)
                    && let Some(item) = parse_report_line(line)
                {
                    on_item(item);
                }
                self.len = 0;
                self.discarding = false;
            } else if self.discarding {
                continue;
            } else if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = b;
                self.len += 1;
            } else {
                self.discarding = true;
                self.len = 0;
            }
        }
    }
}

/// 期待する tag 集合に対する報告の状態機械。
#[derive(Debug)]
pub struct GuestMountTracker {
    expected: Vec<String>,
    reported: Vec<String>,
}

/// [`GuestMountTracker::apply`] の結果。
#[derive(Debug, PartialEq, Eq)]
pub enum TrackerStatus {
    /// まだ報告待ちの共有がある。
    Pending,
    /// 全共有が mount に成功した。
    AllMounted,
    /// 失敗（または不正な報告）で起動を失敗にする。
    Failed(GuestMountError),
}

impl GuestMountTracker {
    /// 期待する tag 集合から作る。
    pub fn new(expected: Vec<String>) -> Self {
        Self {
            expected,
            reported: Vec::new(),
        }
    }

    /// 報告 1 件を適用する。未知 tag・矛盾する重複・書式不正・失敗報告は `Failed`。
    ///
    /// 成功報告の同一内容の重複は無視する。失敗報告は即 `Failed` になるため記録せず、同じ tag の
    /// 成功済み後の失敗報告は「矛盾する重複」として `InvalidReport` にする。
    pub fn apply(&mut self, item: ReportItem) -> TrackerStatus {
        let report = match item {
            Ok(r) => r,
            Err(e) => {
                return TrackerStatus::Failed(GuestMountError::InvalidReport {
                    reason: e.reason.to_string(),
                });
            }
        };
        let tag = report.tag.as_str();
        if !self.expected.iter().any(|t| t == tag) {
            return TrackerStatus::Failed(GuestMountError::InvalidReport {
                reason: format!("unknown tag '{tag}'"),
            });
        }
        let already_mounted = self.reported.iter().any(|t| t == tag);
        match report.outcome {
            GuestMountOutcome::Mounted => {
                if !already_mounted {
                    self.reported.push(tag.to_string());
                }
                self.status()
            }
            GuestMountOutcome::Failed { .. } if already_mounted => {
                TrackerStatus::Failed(GuestMountError::InvalidReport {
                    reason: format!("conflicting duplicate report for tag '{tag}'"),
                })
            }
            GuestMountOutcome::Failed { errno } => TrackerStatus::Failed(GuestMountError::Failed {
                tag: tag.to_string(),
                errno,
            }),
        }
    }

    fn status(&self) -> TrackerStatus {
        if self.pending().is_empty() {
            TrackerStatus::AllMounted
        } else {
            TrackerStatus::Pending
        }
    }

    /// 未報告の tag。
    pub fn pending(&self) -> Vec<String> {
        self.expected
            .iter()
            .filter(|t| !self.reported.contains(t))
            .cloned()
            .collect()
    }
}

/// 全共有の mount 報告を期限付きで待つ（REPAIR-5）。
///
/// `poll_interval` ごとに `is_alive`（引数は全体期限までの残り時間。照会はこの時間内に終えること。
/// 照会が決着しなかった場合は `Ok` を返して稼働中とみなす）を確認し、VM が停止していれば `VmStopped` で早期に失敗させる。
/// 停止前に届いていた報告は先に処理する。送信側が破棄されたら `ReportChannelClosed`。
pub fn await_guest_mounts(
    rx: &Receiver<ReportItem>,
    tracker: &mut GuestMountTracker,
    overflow: &AtomicBool,
    timeout: Duration,
    poll_interval: Duration,
    mut is_alive: impl FnMut(Duration) -> Result<(), VmState>,
) -> Result<(), GuestMountError> {
    if tracker.pending().is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        // 報告が溢れて破棄されたなら、成功報告の喪失（誤った timeout）や失敗報告の喪失を避けるため即失敗にする。
        if overflow.load(Ordering::Acquire) {
            return Err(overflow_error());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(GuestMountError::Timeout {
                after: timeout,
                pending: tracker.pending(),
            });
        }
        match rx.recv_timeout(remaining.min(poll_interval)) {
            Ok(item) => match tracker.apply(item) {
                TrackerStatus::Pending => {}
                TrackerStatus::AllMounted => {
                    if overflow.load(Ordering::Acquire) {
                        return Err(overflow_error());
                    }
                    // 成功確定前にも VM の稼働を確認する（停止済みなら成功を返さない）。
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    return match is_alive(remaining) {
                        Ok(()) => Ok(()),
                        Err(state) => Err(GuestMountError::VmStopped { state }),
                    };
                }
                TrackerStatus::Failed(e) => return Err(e),
            },
            Err(RecvTimeoutError::Timeout) => {
                // 状態照会にも残り時間を上限として渡し、全体の期限を超えさせない（REPAIR-5）。
                let remaining = deadline.saturating_duration_since(Instant::now());
                if let Err(state) = is_alive(remaining) {
                    return Err(GuestMountError::VmStopped { state });
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(GuestMountError::ReportChannelClosed);
            }
        }
    }
}

fn overflow_error() -> GuestMountError {
    GuestMountError::InvalidReport {
        reason: "report channel overflow".to_string(),
    }
}

/// 書き出しスレッド側の報告送信口。チャネルが満杯で報告を捨てた場合は溢れフラグを立て、
/// 待機側（[`await_guest_mounts`]）が起動を失敗にできるようにする。
#[derive(Debug)]
pub struct ReportSender {
    tx: SyncSender<ReportItem>,
    overflow: Arc<AtomicBool>,
}

impl ReportSender {
    /// 送信側と溢れフラグから作る。
    pub fn new(tx: SyncSender<ReportItem>, overflow: Arc<AtomicBool>) -> Self {
        Self { tx, overflow }
    }

    /// 非ブロッキングで送る。満杯なら溢れフラグを立てる。受信側が破棄済みなら `false`。
    pub fn deliver(&self, item: ReportItem) -> bool {
        match self.tx.try_send(item) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.overflow.store(true, Ordering::Release);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

/// `Vm::launch` が待機に使う受信側と期待 tag 集合。
#[derive(Debug)]
pub struct GuestMountWatch {
    rx: Receiver<ReportItem>,
    expected: Vec<String>,
    overflow: Arc<AtomicBool>,
}

impl GuestMountWatch {
    /// 報告チャネル（有界）を作り、書き出しスレッド用の送信側と待機用の watch を返す。
    pub fn channel(expected: Vec<String>) -> (ReportSender, GuestMountWatch) {
        let (tx, rx) = sync_channel(MAX_VIRTIOFS_SHARES * 2);
        let overflow = Arc::new(AtomicBool::new(false));
        let sender = ReportSender::new(tx, Arc::clone(&overflow));
        (
            sender,
            GuestMountWatch {
                rx,
                expected,
                overflow,
            },
        )
    }

    /// 全共有の報告が揃うまで `timeout` を上限に待つ。受信側は返った時点で破棄される。
    pub fn wait(
        self,
        timeout: Duration,
        is_alive: impl FnMut(Duration) -> Result<(), VmState>,
    ) -> Result<(), GuestMountError> {
        let mut tracker = GuestMountTracker::new(self.expected);
        await_guest_mounts(
            &self.rx,
            &mut tracker,
            &self.overflow,
            timeout,
            POLL_INTERVAL,
            is_alive,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtiofs::{SharedDirectoryPath, VirtiofsShareSpec};

    fn mp(s: &str) -> GuestMountPoint {
        GuestMountPoint::try_new(s).unwrap()
    }

    fn tag(s: &str) -> VirtiofsTag {
        VirtiofsTag::try_new(s).unwrap()
    }

    fn ok_report(t: &str) -> ReportItem {
        Ok(GuestMountReport {
            tag: tag(t),
            outcome: GuestMountOutcome::Mounted,
        })
    }

    /// テスト専用の一時ディレクトリ（作成直後に実体化する）。
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let raw = std::env::temp_dir().join(format!(
                "fandhe-macos-guest-mount-{name}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&raw).expect("create temp dir");
            Self(std::fs::canonicalize(&raw).expect("canonicalize temp dir"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// MAC-1・TASK-65.3: /proc/cmdline 末尾の改行があっても最後の指示を復号できる。
    #[test]
    fn parse_directives_tolerates_trailing_newline() {
        let got =
            parse_directives("console=hvc0 fandhe.virtiofs=data:/mnt/fandhe/data:ro\n").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].access, ShareAccess::ReadOnly);
    }

    /// MAC-1・TASK-65.3: mount point の境界値。
    #[test]
    fn mount_point_validation() {
        assert_eq!(mp("/mnt/fandhe/data").as_str(), "/mnt/fandhe/data");
        assert_eq!(mp("/mnt/fandhe/a/b/c/d").as_str(), "/mnt/fandhe/a/b/c/d");
        let long_ok = format!("{GUEST_MOUNT_BASE}/{}", "a".repeat(64));
        assert!(GuestMountPoint::try_new(&long_ok).is_ok());
        let too_long_element = format!("{GUEST_MOUNT_BASE}/{}", "a".repeat(65));
        let cases: Vec<(&str, ConfigError)> = vec![
            ("/mnt/fandhe", ConfigError::GuestMountPointNotUnderBase),
            (
                "/mnt/fandhe/",
                ConfigError::GuestMountPointInvalid { index: 12 },
            ),
            ("/proc", ConfigError::GuestMountPointNotUnderBase),
            ("/mnt/fandhex/a", ConfigError::GuestMountPointNotUnderBase),
            (
                "/mnt/fandhe/..",
                ConfigError::GuestMountPointInvalid { index: 12 },
            ),
            (
                "/mnt/fandhe/.",
                ConfigError::GuestMountPointInvalid { index: 12 },
            ),
            (
                "/mnt/fandhe/a//b",
                ConfigError::GuestMountPointInvalid { index: 14 },
            ),
            (
                "/mnt/fandhe/a b",
                ConfigError::GuestMountPointInvalid { index: 13 },
            ),
            (
                "/mnt/fandhe/a:b",
                ConfigError::GuestMountPointInvalid { index: 13 },
            ),
            (
                "/mnt/fandhe/é",
                ConfigError::GuestMountPointInvalid { index: 12 },
            ),
            (
                "/mnt/fandhe/a/b/c/d/e",
                ConfigError::GuestMountPointInvalid { index: 20 },
            ),
            (
                &too_long_element,
                ConfigError::GuestMountPointTooLong { len: 65, max: 64 },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(GuestMountPoint::try_new(input), Err(expected), "{input}");
        }
        let too_long = format!("{GUEST_MOUNT_BASE}/{}", "a/".repeat(60));
        assert_eq!(
            GuestMountPoint::try_new(&too_long),
            Err(ConfigError::GuestMountPointTooLong {
                len: too_long.len(),
                max: 128
            })
        );
    }

    /// MAC-1・TASK-65.3: 重複・入れ子の判定は要素単位。
    #[test]
    fn mount_point_overlap() {
        assert!(mp("/mnt/fandhe/a").overlaps(&mp("/mnt/fandhe/a")));
        assert!(mp("/mnt/fandhe/a").overlaps(&mp("/mnt/fandhe/a/b")));
        assert!(mp("/mnt/fandhe/a/b").overlaps(&mp("/mnt/fandhe/a")));
        assert!(mp("/mnt/fandhe/A").overlaps(&mp("/mnt/fandhe/a")));
        assert!(!mp("/mnt/fandhe/a").overlaps(&mp("/mnt/fandhe/ab")));
        assert!(!mp("/mnt/fandhe/a/b").overlaps(&mp("/mnt/fandhe/a/c")));
    }

    /// MAC-1・TASK-65.3: エンコード結果の完全一致と往復一致。ReadOnly は必ず ro。
    #[test]
    fn directives_roundtrip() {
        let t = TempDir::new("directives");
        let host = SharedDirectoryPath::try_new(&t.0).unwrap();
        let shares = VirtiofsSharesSpec::try_new(vec![
            VirtiofsShareSpec::new(tag("data"), host.clone(), ShareAccess::ReadOnly)
                .with_guest_mount(mp("/mnt/fandhe/data")),
            VirtiofsShareSpec::new(tag("work.1"), host.clone(), ShareAccess::ReadWrite)
                .with_guest_mount(mp("/mnt/fandhe/w/x")),
            VirtiofsShareSpec::new(tag("nomount"), host, ShareAccess::ReadWrite),
        ])
        .unwrap();
        let encoded = encode_directives(&shares);
        assert_eq!(
            encoded,
            "fandhe.virtiofs=data:/mnt/fandhe/data:ro fandhe.virtiofs=work.1:/mnt/fandhe/w/x:rw"
        );
        let cmdline = format!("console=hvc0 {encoded} quiet");
        assert_eq!(
            parse_directives(&cmdline).unwrap(),
            vec![
                GuestMountDirective {
                    tag: tag("data"),
                    mount_point: mp("/mnt/fandhe/data"),
                    access: ShareAccess::ReadOnly
                },
                GuestMountDirective {
                    tag: tag("work.1"),
                    mount_point: mp("/mnt/fandhe/w/x"),
                    access: ShareAccess::ReadWrite
                },
            ]
        );
        assert_eq!(encode_directives(&VirtiofsSharesSpec::default()), "");
    }

    /// MAC-1・TASK-65.3: 不正な指示の復号は拒否し、件数を打ち切る。
    #[test]
    fn directives_parse_rejects_malformed() {
        let bad = Err(DirectiveError::Malformed { index: 0 });
        assert_eq!(parse_directives("fandhe.virtiofs=a:/mnt/fandhe/x"), bad);
        assert_eq!(
            parse_directives("fandhe.virtiofs=a:/mnt/fandhe/x:ro:z"),
            bad
        );
        assert_eq!(parse_directives("fandhe.virtiofs=a:/mnt/fandhe/x:RW"), bad);
        assert_eq!(parse_directives("fandhe.virtiofs=a:/etc:ro"), bad);
        assert_eq!(parse_directives("fandhe.virtiofs=:/mnt/fandhe/x:ro"), bad);
        let many = "fandhe.virtiofs=a:/mnt/fandhe/x:ro ".repeat(9);
        assert_eq!(parse_directives(&many), Err(DirectiveError::TooMany));
        assert_eq!(parse_directives("quiet ro"), Ok(vec![]));
    }

    /// MAC-1・TASK-65.3: 予約キーは `fandhe.virtiofs=` でも `fandhe.x=` でも拒否する。
    #[test]
    fn reserved_keys_rejected() {
        assert_eq!(reject_reserved_keys("console=hvc0 quiet"), Ok(()));
        assert_eq!(reject_reserved_keys(""), Ok(()));
        assert_eq!(
            reject_reserved_keys("console=hvc0 fandhe.virtiofs=a:/mnt/fandhe/x:rw"),
            Err(ConfigError::CommandLineReservedKey { index: 13 })
        );
        assert_eq!(
            reject_reserved_keys("fandhe.x=1"),
            Err(ConfigError::CommandLineReservedKey { index: 0 })
        );
        assert_eq!(reject_reserved_keys("xfandhe.x=1 fandhe=1"), Ok(()));
    }

    /// MAC-1・TASK-65.3: 報告行の受理と、境界・不正行の個別確認。
    #[test]
    fn report_line_parsing() {
        let p = |s: &str| parse_report_line(s.as_bytes());
        assert_eq!(
            p("fandhe-guest: virtiofs-mount v1 tag=data result=ok"),
            Some(ok_report("data"))
        );
        assert_eq!(
            p("fandhe-guest: virtiofs-mount v1 tag=data result=ok\r"),
            Some(ok_report("data"))
        );
        assert_eq!(
            p("fandhe-guest: virtiofs-mount v1 tag=d result=error errno=19"),
            Some(Ok(GuestMountReport {
                tag: tag("d"),
                outcome: GuestMountOutcome::Failed { errno: 19 }
            }))
        );
        for errno in ["0", "4096", "x", "", "-1", "00019999"] {
            let line = format!("fandhe-guest: virtiofs-mount v1 tag=d result=error errno={errno}");
            assert_eq!(
                p(&line),
                Some(Err(ReportParseError {
                    reason: "invalid errno"
                })),
                "{errno}"
            );
        }
        assert_eq!(
            p("fandhe-guest: virtiofs-mount v1 tag=d"),
            Some(Err(ReportParseError {
                reason: "unexpected result field"
            }))
        );
        for bad in [
            "fandhe-guest: virtiofs-mount v1 tag=data result=ok extra=1",
            "fandhe-guest: virtiofs-mount v1  tag=data result=ok",
            "fandhe-guest: virtiofs-mount v2 tag=data result=ok",
            "fandhe-guest: virtiofs-mount v1 tag=data result=ok ",
            "fandhe-guest: virtiofs-mount v1 result=ok tag=data",
        ] {
            assert!(matches!(p(bad), Some(Err(_))), "{bad}");
        }
        // 行頭が一致しない行（先頭空白・カーネルの cmdline エコー）は報告ではない。
        assert_eq!(
            p(" fandhe-guest: virtiofs-mount v1 tag=data result=ok"),
            None
        );
        assert_eq!(
            p("Kernel command line: console=hvc0 fandhe.virtiofs=data:/mnt/fandhe/data:ro"),
            None
        );
        assert_eq!(p(""), None);
    }

    fn scan(chunks: &[&[u8]]) -> Vec<ReportItem> {
        let mut s = ReportScanner::new();
        let mut out = Vec::new();
        for c in chunks {
            s.feed(c, &mut |i| out.push(i));
        }
        out
    }

    /// MAC-1・TASK-65.3: チャンク分割・長大行・CRLF の走査。
    #[test]
    fn scanner_handles_chunks_and_long_lines() {
        let line = b"fandhe-guest: virtiofs-mount v1 tag=data result=ok\r\n";
        assert_eq!(scan(&[line]), vec![ok_report("data")]);
        let (a, b) = line.split_at(20);
        assert_eq!(scan(&[a, b]), vec![ok_report("data")]);
        let singles: Vec<&[u8]> = line.chunks(1).collect();
        assert_eq!(scan(&singles), vec![ok_report("data")]);
        // 256 バイトちょうどの行は走査される（空白詰めで書式不正になる）。
        let mut exact = b"fandhe-guest: virtiofs-mount v1 tag=data result=ok".to_vec();
        exact.resize(MAX_REPORT_LINE_BYTES, b' ');
        exact.push(b'\n');
        assert!(matches!(scan(&[&exact]).as_slice(), [Err(_)]));
        // 257 バイトの行は読み捨てられ、次の行は影響を受けない。
        let mut long = b"fandhe-guest: virtiofs-mount v1 tag=data result=ok".to_vec();
        long.resize(MAX_REPORT_LINE_BYTES + 1, b' ');
        long.push(b'\n');
        long.extend_from_slice(line);
        assert_eq!(scan(&[&long]), vec![ok_report("data")]);
        // 改行のない巨大出力でも状態は固定長。
        let junk = vec![b'x'; 100_000];
        assert_eq!(scan(&[&junk, b"\n", line]), vec![ok_report("data")]);
    }

    fn tracker(tags: &[&str]) -> GuestMountTracker {
        GuestMountTracker::new(tags.iter().map(|t| t.to_string()).collect())
    }

    /// MAC-1・TASK-65.3: 状態機械の全成功・失敗・未知 tag・重複。
    #[test]
    fn tracker_transitions() {
        let mut t = tracker(&["a", "b"]);
        assert_eq!(t.apply(ok_report("a")), TrackerStatus::Pending);
        assert_eq!(t.apply(ok_report("a")), TrackerStatus::Pending);
        assert_eq!(t.pending(), vec!["b".to_string()]);
        assert_eq!(t.apply(ok_report("b")), TrackerStatus::AllMounted);

        let failed = |name: &str, errno| {
            Ok(GuestMountReport {
                tag: tag(name),
                outcome: GuestMountOutcome::Failed { errno },
            })
        };
        let mut t = tracker(&["a", "b"]);
        assert_eq!(
            t.apply(failed("b", 2)),
            TrackerStatus::Failed(GuestMountError::Failed {
                tag: "b".into(),
                errno: 2
            })
        );

        let mut t = tracker(&["a"]);
        assert_eq!(
            t.apply(ok_report("zzz")),
            TrackerStatus::Failed(GuestMountError::InvalidReport {
                reason: "unknown tag 'zzz'".into()
            })
        );

        let mut t = tracker(&["a", "b"]);
        t.apply(ok_report("a"));
        assert_eq!(
            t.apply(failed("a", 5)),
            TrackerStatus::Failed(GuestMountError::InvalidReport {
                reason: "conflicting duplicate report for tag 'a'".into()
            })
        );

        let mut t = tracker(&["a"]);
        assert_eq!(
            t.apply(Err(ReportParseError {
                reason: "invalid tag"
            })),
            TrackerStatus::Failed(GuestMountError::InvalidReport {
                reason: "invalid tag".into()
            })
        );
    }

    const TICK: Duration = Duration::from_millis(5);

    /// MAC-1・REPAIR-5・TASK-65.3: 待機の成功・期限切れ・VM 停止・送信側切断。
    #[test]
    fn await_outcomes() {
        let alive = |_: Duration| Ok(());
        let no_overflow = AtomicBool::new(false);

        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        tx.send(ok_report("a")).unwrap();
        tx.send(ok_report("b")).unwrap();
        let mut t = tracker(&["a", "b"]);
        assert_eq!(
            await_guest_mounts(
                &rx,
                &mut t,
                &no_overflow,
                Duration::from_secs(5),
                TICK,
                alive
            ),
            Ok(())
        );

        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        tx.send(ok_report("a")).unwrap();
        let mut t = tracker(&["a", "b"]);
        assert_eq!(
            await_guest_mounts(
                &rx,
                &mut t,
                &no_overflow,
                Duration::from_millis(100),
                TICK,
                alive
            ),
            Err(GuestMountError::Timeout {
                after: Duration::from_millis(100),
                pending: vec!["b".into()]
            })
        );

        let mut t = tracker(&["a"]);
        assert_eq!(
            await_guest_mounts(
                &rx,
                &mut t,
                &no_overflow,
                Duration::from_secs(5),
                TICK,
                |_| Err(VmState::Stopped)
            ),
            Err(GuestMountError::VmStopped {
                state: VmState::Stopped
            })
        );

        drop(tx);
        let mut t = tracker(&["a", "b"]);
        assert_eq!(
            await_guest_mounts(
                &rx,
                &mut t,
                &no_overflow,
                Duration::from_secs(5),
                TICK,
                alive
            ),
            Err(GuestMountError::ReportChannelClosed)
        );
    }

    /// MAC-1・TASK-65.3: watch は期待 tag 集合で待つ。
    #[test]
    fn watch_waits_for_expected_tags() {
        let (tx, watch) = GuestMountWatch::channel(vec!["a".into()]);
        assert!(tx.deliver(ok_report("a")));
        assert_eq!(watch.wait(Duration::from_secs(5), |_| Ok(())), Ok(()));
    }

    /// MAC-1・REPAIR-5・TASK-65.3: 報告がチャネルから溢れたら待機は即失敗する（報告の黙殺で誤 timeout にしない）。
    #[test]
    fn watch_fails_on_report_overflow() {
        let (tx, watch) = GuestMountWatch::channel(vec!["a".into()]);
        for _ in 0..(MAX_VIRTIOFS_SHARES * 2 + 1) {
            assert!(tx.deliver(ok_report("zzz")));
        }
        assert_eq!(
            watch.wait(Duration::from_secs(5), |_| Ok(())),
            Err(GuestMountError::InvalidReport {
                reason: "report channel overflow".into()
            })
        );
    }

    /// MAC-1・TASK-65.3: 全共有 mount 済みでも VM が停止していれば成功にしない。
    #[test]
    fn all_mounted_but_vm_stopped_fails() {
        let (tx, watch) = GuestMountWatch::channel(vec!["a".into()]);
        assert!(tx.deliver(ok_report("a")));
        assert_eq!(
            watch.wait(Duration::from_secs(5), |_| Err(VmState::Stopped)),
            Err(GuestMountError::VmStopped {
                state: VmState::Stopped
            })
        );
    }
}
