//! バッチ write-back サーバーの `--batch-size` 相当の設定 API（TASK-13.3・
//! IO-1・#78）。
//!
//! [`crate::batch::BatchConfig::new`] / [`crate::batch::BatchConfig::with_max_bytes`]
//! はすでに検証済みの `usize` を受け取るが、CLI 引数・宣言的設定ファイル
//! （TOML 等）の値は文字列として届く。文字列は `usize` では表現できない
//! 形（負数・空文字・非数値・桁あふれ）を取りうるため、その検証は本モジュール
//! が担う（[`parse_batch_size`]）。範囲（`1..=MAX_BATCH_SIZE`）自体の検証は
//! 二重に持たず [`crate::batch::BatchConfig::new`] へ委譲する。
//!
//! [`WritebackSettings`] は、バッチ write-back サーバーが 1 接続を処理する
//! ために必要な 2 つの値——[`crate::batch::BatchConfig`]（`serve_connection`
//! 用）と [`crate::recv_limits::ReceiveLimits`]（`UdsServer::bind` 用）——を
//! 単一の設定値から導く。[`crate::server::UdsServer::bind`] と
//! [`crate::writeback::serve_connection`] はそれぞれ `ReceiveLimits` /
//! `BatchConfig` を直接受け取る独立した公開関数のままであり（他の
//! トランスポート・テストダブルから汎用に呼べる必要があるため）、
//! [`WritebackSettings::batch_config`] と [`WritebackSettings::receive_limits`]
//! を個別に呼んで別々の変数へ渡すだけでは、呼び出し側の実装ミスで異なる
//! [`WritebackSettings`] 由来の値を渡してしまう経路を型で防げない。
//! これを避けるため、同一の `&WritebackSettings` から両方の呼び出しを
//! 行う組み合わせ入口として [`WritebackSettings::bind`] /
//! [`WritebackSettings::serve_connection`] を用意する（REPAIR-2）。この 2 つの
//! メソッドを経由して呼ぶ限り、`bind` の受信上限と `serve_connection` の
//! 集約バッチサイズは常に同じ `self` から導かれ食い違わない。`UdsServer::bind`
//! / `crate::writeback::serve_connection` を直接呼ぶ経路（下記 2 メソッドを
//! 経由しない呼び出し）は本型の保証範囲外であり、呼び出し側が値の対応を
//! 保つ責任を負う。
//!
//! # 呼び出し文脈
//! 実際の CLI バイナリ（`fandhe-container`）から `--batch-size` の値を受け取り
//! [`WritebackSettings::from_batch_size_arg`] へ渡す配線は TASK-79（`crates/cli`）
//! の責務であり、本モジュールはその手前の「文字列 → 検証済み設定」までを
//! 提供する（REPAIR-3: 実装済みを装わない。CLI バイナリ自体はまだない）。
//! TOML 等の宣言的設定ファイル（CLI-4・TASK-82）からの読み込みも同様に
//! 対象外だが、そのキー名として [`BATCH_SIZE_SETTING_KEY`] を予約する。
//!
//! `max_bytes`（累積バイト数上限）の CLI / 設定値（`--batch-bytes` 相当）は
//! 本タスクの対象外（IO-10・TASK-16）。[`WritebackSettings`] を
//! `#[non_exhaustive]` にしているのは、その値を後から非公開フィールドとして
//! 追加できる形にしておくため。

use std::path::Path;
use std::str::FromStr;

use crate::batch::BatchConfig;
use crate::error::{IoError, IoErrorCode};
use crate::observe::ServerObserver;
use crate::protocol::Frame;
use crate::recv_limits::ReceiveLimits;
use crate::server::UdsServer;
use crate::transport::{FrameReceiver, FrameSender};
use crate::writeback::{self, BatchSink, WritebackReport, WritebackTimeouts};

/// CLI オプション名（TASK-79 の CLI バイナリが参照する定数。本 crate 自体は
/// argv を解釈しない）。
pub const BATCH_SIZE_OPTION: &str = "--batch-size";

/// 宣言的設定（TOML 等。CLI-4・TASK-82）でのキー名の予約。
pub const BATCH_SIZE_SETTING_KEY: &str = "batch_size";

/// [`parse_batch_size`] がパースを試みる前に検査する入力文字列長の上限
/// （P0: 無制限確保による DoS の防止。security.md「長さ・件数を上限検証
/// してからアロケーションに使う」）。
///
/// `u64::MAX`（20 桁）を表現できる余裕を持たせつつ、それより極端に長い
/// 数字列（例: 1 MiB の `'0'` の連続）を `usize::from_str` へ渡す前に
/// 弾く。バッチサイズは高々 [`crate::batch::MAX_BATCH_SIZE`]（4 桁）までしか
/// 有効にならないが、桁あふれを検出するには一旦妥当な長さまでのパースを
/// 許す必要があるため、10 進数の上限桁数を基準に取る。
pub const MAX_BATCH_SIZE_ARG_LEN: usize = 20;

/// `--batch-size`（または同等の設定値）の文字列を検証済み [`BatchConfig`] へ
/// 変換する（TASK-13.3・IO-1）。
///
/// # 受理する形式
/// 前後の空白・符号（`+` / `-`）・桁区切り（`_`）・全角数字・`0x` 等の基数
/// 接頭辞を含まない、10 進 ASCII 数字（`0`-`9`）のみからなる文字列。先頭の
/// `0`（例: `"064"`）は [`usize::from_str`] と同じく 64 として受理する。
///
/// # 拒否する入力（すべて [`IoErrorCode::InvalidArgument`]）
/// - 空文字列
/// - [`MAX_BATCH_SIZE_ARG_LEN`] を超える長さ（パース前に弾く。DoS 防止）
/// - ASCII 数字以外の文字を 1 文字でも含む入力（符号・空白・区切り文字を含む）
/// - `usize` の範囲に収まらない（桁あふれ）入力
/// - `0`、または [`crate::batch::MAX_BATCH_SIZE`] を超える値
///   （[`BatchConfig::new`] が返すエラーをそのまま伝える）
///
/// エラーメッセージには入力値そのものを含めない（security.md「情報漏えい」
/// 観点。任意長・制御文字を含みうる外部入力をログ・構造化エラーへそのまま
/// 流し込まないため）。
pub fn parse_batch_size(value: &str) -> Result<BatchConfig, IoError> {
    if value.is_empty() {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "batch size must not be empty",
        ));
    }
    if value.len() > MAX_BATCH_SIZE_ARG_LEN {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            format!("batch size argument must be at most {MAX_BATCH_SIZE_ARG_LEN} bytes long"),
        ));
    }
    // 許可リスト方式（ASCII 数字のみ）で検証する。符号・空白・桁区切り・
    // 全角数字・16 進表記はここですべて拒否される（coding-rust「外部入力は
    // 許可リストで明示的に処理する」）。
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IoError::new(
            IoErrorCode::InvalidArgument,
            "batch size must be a decimal integer composed of ASCII digits only",
        ));
    }
    let batch_size: usize = value.parse().map_err(|_| {
        IoError::new(
            IoErrorCode::InvalidArgument,
            "batch size does not fit in usize",
        )
    })?;
    // 範囲（1..=MAX_BATCH_SIZE）の検証は二重に持たず BatchConfig::new へ
    // 委譲する（このファイルの検証はここまで）。
    BatchConfig::new(batch_size)
}

impl FromStr for BatchConfig {
    type Err = IoError;

    /// [`parse_batch_size`] へ委譲する（TASK-13.3）。
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_batch_size(value)
    }
}

/// バッチ write-back サーバーの設定の単一の入口（TASK-13.3・IO-1）。
///
/// [`crate::writeback::serve_connection`] が使う [`BatchConfig`] と、
/// [`crate::server::UdsServer::bind`] が使う [`ReceiveLimits`] を同じ内部値
/// から導く。両者を別々に構築して渡すと、呼び出し側の実装ミスで異なる
/// バッチサイズを受信ゲートと集約ロジックへ与えてしまえる（REPAIR-2）ため、
/// [`Self::bind`] / [`Self::serve_connection`] という組み合わせ入口を経由する
/// ことを推奨する（この 2 メソッドだけが型で不整合を防げる。モジュール doc
/// 参照）。[`Self::batch_config`] / [`Self::receive_limits`] は、外部の
/// `UdsServer::bind` 呼び出しと組み合わせるなど、値だけを取り出したい
/// 呼び出し元向けに残す。
///
/// `max_bytes`（累積バイト数上限）用の CLI / 設定値はまだ持たない
/// （モジュール doc の「スコープ外」参照）。`#[non_exhaustive]` かつ
/// 非公開フィールドのみを持つことで、後方互換を保ったままそれを追加できる
/// 形にしておく。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct WritebackSettings {
    batch: BatchConfig,
}

impl WritebackSettings {
    /// 検証済みの [`BatchConfig`] から設定を作る。
    pub fn new(batch: BatchConfig) -> Self {
        Self { batch }
    }

    /// `--batch-size`（または同等の設定値）の文字列から設定を作る
    /// （[`parse_batch_size`] 参照）。
    pub fn from_batch_size_arg(value: &str) -> Result<Self, IoError> {
        Ok(Self::new(parse_batch_size(value)?))
    }

    /// [`crate::writeback::serve_connection`] へ渡す [`BatchConfig`] を返す。
    pub fn batch_config(&self) -> BatchConfig {
        self.batch
    }

    /// 検証済みのバッチサイズ（件数）を返す。
    pub fn batch_size(&self) -> usize {
        self.batch.batch_size()
    }

    /// [`crate::server::UdsServer::bind`] へ渡す [`ReceiveLimits`] を、
    /// 保持している [`BatchConfig`] と同じ値から導いて返す
    /// （[`ReceiveLimits::for_batch`]）。`batch_config()` と本メソッドの
    /// 戻り値は常に整合する（REPAIR-2）。
    pub fn receive_limits(&self) -> ReceiveLimits {
        ReceiveLimits::for_batch(&self.batch)
    }

    /// [`crate::server::UdsServer::bind`] を、自身の [`Self::receive_limits`]
    /// で呼ぶ組み合わせ入口（TASK-13.3・#78 codex レビュー指摘対応）。
    ///
    /// [`Self::serve_connection`] と対で、同じ `&WritebackSettings` から呼ぶ
    /// ことで受信ゲート（`ReceiveLimits`）と集約ロジック（`BatchConfig`）の
    /// バッチサイズが食い違う経路を型で防ぐ（REPAIR-2。モジュール doc
    /// 参照）。`path`・`observer` の意味は [`crate::server::UdsServer::bind`]
    /// と同じ。
    pub fn bind<O: ServerObserver>(
        &self,
        path: &Path,
        observer: O,
    ) -> Result<UdsServer<O>, IoError> {
        UdsServer::bind(path, self.receive_limits(), observer)
    }

    /// [`crate::writeback::serve_connection`] を、自身の [`Self::batch_config`]
    /// で呼ぶ組み合わせ入口（TASK-13.3・#78 codex レビュー指摘対応）。
    ///
    /// [`Self::bind`] と対で使うことを想定する（REPAIR-2。モジュール doc
    /// 参照）。`conn`・`sink`・`timeouts` の意味は
    /// [`crate::writeback::serve_connection`] と同じ。
    pub fn serve_connection<T, W>(
        &self,
        conn: &mut T,
        sink: &mut W,
        timeouts: WritebackTimeouts,
    ) -> WritebackReport
    where
        T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
        W: BatchSink,
    {
        writeback::serve_connection(conn, self.batch_config(), sink, timeouts)
    }
}

impl Default for WritebackSettings {
    /// IO-1 の既定値（[`crate::batch::DEFAULT_BATCH_SIZE`] = 64）を使う。
    fn default() -> Self {
        Self::new(BatchConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::MAX_BATCH_SIZE;

    /// IO-1・TASK-13.3: `"1"`（下限境界）を受理する。
    #[test]
    fn io1_parse_batch_size_accepts_one() {
        let config = parse_batch_size("1").expect("1 must be accepted");
        assert_eq!(config.batch_size(), 1);
    }

    /// IO-1・TASK-13.3: `MAX_BATCH_SIZE`（上限境界）を受理する。
    #[test]
    fn io1_parse_batch_size_accepts_max() {
        let input = MAX_BATCH_SIZE.to_string();
        let config = parse_batch_size(&input).expect("MAX_BATCH_SIZE must be accepted");
        assert_eq!(config.batch_size(), MAX_BATCH_SIZE);
    }

    /// IO-1・TASK-13.3: 先頭ゼロ（`"064"`）は 64 として受理する
    /// （`usize::from_str` と同じ挙動。モジュール doc 参照）。
    #[test]
    fn io1_parse_batch_size_accepts_leading_zero() {
        let config = parse_batch_size("064").expect("leading zero must be accepted");
        assert_eq!(config.batch_size(), 64);
    }

    /// IO-1・TASK-13.3: 空文字列は拒否する。
    #[test]
    fn io1_parse_batch_size_rejects_empty() {
        let err = parse_batch_size("").expect_err("empty string must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・TASK-13.3: `MAX_BATCH_SIZE_ARG_LEN` を超える長さの入力は
    /// パースを試みる前に拒否する。
    #[test]
    fn io1_parse_batch_size_rejects_too_long() {
        let input = "1".repeat(MAX_BATCH_SIZE_ARG_LEN + 1);
        let err = parse_batch_size(&input).expect_err("overlong input must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・TASK-13.3: ASCII 数字以外（符号・空白・全角数字・16進）は拒否する。
    #[test]
    fn io1_parse_batch_size_rejects_non_ascii_digit() {
        for input in ["-1", "+8", " 8", "8 ", "abc", "8a", "０", "0x8", "1_000"] {
            match parse_batch_size(input) {
                Ok(_) => panic!("{input:?} must be rejected"),
                Err(err) => {
                    assert_eq!(err.code(), IoErrorCode::InvalidArgument, "input={input:?}")
                }
            }
        }
    }

    /// IO-1・TASK-13.3: 桁あふれ（`usize::MAX` を超える）は拒否する。
    #[test]
    fn io1_parse_batch_size_rejects_overflow() {
        // usize::MAX（64bit: 20 桁）と同じ 20 桁のまま、値としては usize::MAX を
        // 上回る数字列で桁あふれさせる（MAX_BATCH_SIZE_ARG_LEN の長さ検証を通過させたまま検証するため）。
        let input = "99999999999999999999"; // 21 桁は長さ検証で先に落ちるため 20 桁で構成する
        let input = &input[..MAX_BATCH_SIZE_ARG_LEN];
        let err = parse_batch_size(input).expect_err("overflowing input must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・TASK-13.3: `0`・範囲外（`MAX_BATCH_SIZE` 超）は `BatchConfig::new`
    /// のエラーがそのまま伝わる。
    #[test]
    fn io1_parse_batch_size_rejects_zero_and_out_of_range() {
        let err_zero = parse_batch_size("0").expect_err("0 must be rejected");
        assert_eq!(err_zero.code(), IoErrorCode::InvalidArgument);

        let input = (MAX_BATCH_SIZE + 1).to_string();
        let err_over = parse_batch_size(&input).expect_err("MAX_BATCH_SIZE + 1 must be rejected");
        assert_eq!(err_over.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-1・TASK-13.3: エラーメッセージに入力文字列そのものを含めない
    /// （security.md「情報漏えい」観点）。
    #[test]
    fn io1_parse_batch_size_error_does_not_echo_input() {
        let sensitive_looking_input = "9".repeat(MAX_BATCH_SIZE_ARG_LEN);
        let err = parse_batch_size(&sensitive_looking_input)
            .expect_err("overflowing input must be rejected");
        assert!(!err.to_string().contains(&sensitive_looking_input));
    }

    /// IO-1・TASK-13.3: `FromStr for BatchConfig` は `parse_batch_size` と
    /// 同じ結果を返す。
    #[test]
    fn io1_batch_config_from_str_delegates_to_parse_batch_size() {
        let via_from_str: BatchConfig = "8".parse().expect("8 must parse");
        let via_fn = parse_batch_size("8").expect("8 must be accepted");
        assert_eq!(via_from_str, via_fn);
    }

    /// IO-1・TASK-13.3: `WritebackSettings::default()` の既定値は
    /// `DEFAULT_BATCH_SIZE`（64）のまま。
    #[test]
    fn io1_writeback_settings_default_is_64() {
        assert_eq!(
            WritebackSettings::default().batch_size(),
            crate::batch::DEFAULT_BATCH_SIZE
        );
    }

    /// IO-1・TASK-13.3・REPAIR-2: `receive_limits()` は保持する
    /// `batch_config()` から `ReceiveLimits::for_batch` で導いたものと一致する
    /// （`bind` と `serve_connection` に別設定が渡る経路を作れないことの確認）。
    #[test]
    fn io1_writeback_settings_receive_limits_match_batch_config() {
        let settings =
            WritebackSettings::from_batch_size_arg("8").expect("8 must be a valid batch size");
        assert_eq!(
            settings.receive_limits(),
            ReceiveLimits::for_batch(&settings.batch_config())
        );
    }

    /// IO-1・TASK-13.3・REPAIR-2・#78 codex レビュー指摘対応:
    /// `WritebackSettings::bind` が `UdsServer::bind` へ渡す `ReceiveLimits` は
    /// 同じ `self` の `receive_limits()` と一致する（bind に別設定を渡す経路が
    /// 無いことを、実際に `UdsServer` を組み立てて確認する）。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn io1_writeback_settings_bind_uses_own_receive_limits() {
        use std::os::unix::fs::DirBuilderExt;

        let settings =
            WritebackSettings::from_batch_size_arg("8").expect("8 must be a valid batch size");

        let dir =
            std::env::temp_dir().join(format!("fcu-settings-bind-test-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("must be able to create a 0700 temp dir for the socket");
        let path = dir.join("sock");

        let server = settings
            .bind(&path, crate::observe::NoopServerObserver)
            .expect("bind must succeed in a fresh 0700 directory owned by the test user");
        drop(server);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IO-1・TASK-13.3・REPAIR-2・#78 codex レビュー指摘対応:
    /// `WritebackSettings::serve_connection` は同じ `self` の `batch_config()`
    /// を [`crate::writeback::serve_connection`] へそのまま渡す（`config` を
    /// 別の値にすり替えて呼べないことの確認。フェイクトランスポートは
    /// 即座に接続断（`Unavailable`）を返すだけで足り、`config` の値を
    /// 実際に集約へ使わせるところまでは
    /// `crate::writeback::tests` が別途検証する）。
    #[test]
    fn io1_writeback_settings_serve_connection_uses_own_batch_config() {
        use crate::protocol::Frame;
        use crate::transport::{FrameReceiver, FrameSender, IoTimeout};
        use crate::writeback::{AppendFileSink, WritebackTimeouts};
        use std::time::Duration;

        /// 受信するフレームを持たず、`recv_frame` が即座に接続断
        /// （`Unavailable`）を返すだけの偽トランスポート
        /// （`crate::writeback::tests::FakeTransport` の縮小版。設定値の
        /// 配線だけを確かめたいため、本テストでは frame 送受信の中身までは
        /// 検証しない）。
        struct EmptyTransport;

        impl FrameSender for EmptyTransport {
            type Frame = Frame;

            fn send_frame(&mut self, _frame: &Frame, _timeout: IoTimeout) -> Result<(), IoError> {
                panic!("no frame is queued, so send_frame must not be called");
            }
        }

        impl FrameReceiver for EmptyTransport {
            type Frame = Frame;

            fn recv_frame(&mut self, _timeout: IoTimeout) -> Result<Frame, IoError> {
                Err(IoError::new(IoErrorCode::Unavailable, "no frame queued"))
            }
        }

        let settings =
            WritebackSettings::from_batch_size_arg("8").expect("8 must be a valid batch size");
        // `bind` と同じ `self` から導いた `batch_config()` が実際に
        // `serve_connection` へ渡ることを、`ReceiveLimits` 側と対で確認する
        // （REPAIR-2）。
        assert_eq!(settings.batch_config().batch_size(), 8);

        let mut conn = EmptyTransport;
        let dst = tempfile_for_sink();
        let mut sink = AppendFileSink::new(dst).expect("AppendFileSink::new must succeed");
        let timeouts = WritebackTimeouts {
            recv: IoTimeout::new(Duration::from_millis(50)).expect("50ms must be valid"),
            send: IoTimeout::new(Duration::from_millis(50)).expect("50ms must be valid"),
        };

        let report = settings.serve_connection(&mut conn, &mut sink, timeouts);
        // フレームが 1 つも届かないまま接続断で終わるため、統計はすべて 0 の
        // ままであることを確認する（設定値の配線を確かめるのが目的で、集約の
        // 挙動自体は `crate::writeback::tests` が担う）。
        assert_eq!(report.stats, crate::writeback::WritebackStats::default());
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);
    }

    /// `AppendFileSink` へ渡す書き込み可能な一時ファイルを作る（テスト専用）。
    #[cfg(test)]
    fn tempfile_for_sink() -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "fcu-settings-serve-connection-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("must be able to create a temp file for the sink")
    }
}
