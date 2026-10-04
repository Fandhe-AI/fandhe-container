//! WSL2 検出の結合試験（`tests/wsl2_detect.rs`。TASK-67.3・WIN-1・REPAIR-5・REPAIR-12）が `wsl.exe` の
//! 代わりに起動する偽の実行ファイル。
//!
//! これはテスト専用の道具であり、本物の `wsl.exe` の出力を保証するものではない（REPAIR-3。出力例は
//! 解析器のユニットテストと同じく模したもので、実機での確認は TASK-67.6・#377）。専用 feature
//! `wsl2-test-support` でのみビルドされ、リリース成果物には入らない。
//!
//! # 振る舞いの選び方
//!
//! 被試験側は固定の引数（`--version` / `-l -v`）と環境変数 `WSL_UTF8=1` しか渡さないため、振る舞い
//! （モード）は実行ファイル名 `fake_wsl-<mode>`（Windows は `.exe` 付き）から決める。結合試験は本 bin を
//! モードごとの名前でリンク（またはコピー）して渡す。
//!
//! - 引数が `--version` / `-l -v` 以外、または `WSL_UTF8` が `1` でなければ終了コード 64 / 65
//!   （被試験側が引数・環境変数を正しく渡していることの確認）
//! - 未知のモードは終了コード 2
//!
//! | モード | `--version` | `-l -v` |
//! | ---- | ---- | ---- |
//! | `ok` | 英語のバージョン（0） | 英語の一覧（0） |
//! | `utf16` | UTF-16LE（BOM 付き）のバージョン（0） | UTF-16LE（BOM 付き）の日本語の一覧（0） |
//! | `nodistro` | 英語のバージョン（0） | 0 件の案内文と `WSL_E_DEFAULT_DISTRO_NOT_FOUND`（1） |
//! | `v1only` | 英語のバージョン（0） | WSL1 のディストリのみ（0） |
//! | `disabled` | `WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED`（1） | 同左（1） |
//! | `denied` | `E_ACCESSDENIED`（1） | 同左（1） |
//! | `garbage` | 未知の形式（0） | 未知の形式（0） |
//! | `hang` | 60 秒眠る | 60 秒眠る |
//! | `flood` | 128 KiB を出力（0） | 同左（0） |

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

const EN_VERSION: &str = "WSL version: 2.1.5.0\r\nKernel version: 5.15.146.1-2\r\nWSLg version: 1.0.60\r\nWindows version: 10.0.22631.3296\r\n";
const EN_LIST: &str = "  NAME              STATE           VERSION\r\n* Ubuntu            Running         2\r\n  docker-desktop    Stopped         2\r\n  Legacy            Stopped         1\r\n";
const JA_LIST: &str =
    "  名前      状態      バージョン\r\n* Ubuntu    実行中    2\r\n  Debian    停止      2\r\n";
const V1_LIST: &str = "  NAME      STATE      VERSION\r\n* Legacy    Running    1\r\n";
const NO_DISTRO: &str = "Windows Subsystem for Linux has no installed distributions.\r\nUse 'wsl.exe --list --online' to list available distributions\r\nand 'wsl.exe --install <Distro>' to install.\r\nError code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n";
const DISABLED: &str = "The Windows Subsystem for Linux optional component is not enabled.\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n";
const DENIED: &str = "Access is denied.\r\nError code: Wsl/Service/E_ACCESSDENIED\r\n";

/// 呼び出された引数の種類。
enum Call {
    Version,
    List,
}

fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// 実行ファイル名 `fake_wsl-<mode>` からモードを取り出す。
fn mode() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let stem = exe.file_stem()?.to_str()?;
    stem.strip_prefix("fake_wsl-").map(str::to_string)
}

fn emit(bytes: &[u8], code: u8) -> ExitCode {
    let mut out = std::io::stdout().lock();
    if out.write_all(bytes).and_then(|()| out.flush()).is_err() {
        return ExitCode::from(3);
    }
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let call = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => Call::Version,
        ["-l", "-v"] => Call::List,
        _ => return ExitCode::from(64),
    };
    if std::env::var("WSL_UTF8").as_deref() != Ok("1") {
        return ExitCode::from(65);
    }
    let Some(mode) = mode() else {
        return ExitCode::from(2);
    };
    match (mode.as_str(), call) {
        ("ok" | "nodistro" | "v1only", Call::Version) => emit(EN_VERSION.as_bytes(), 0),
        ("ok", Call::List) => emit(EN_LIST.as_bytes(), 0),
        ("utf16", Call::Version) => emit(&utf16le_with_bom(EN_VERSION), 0),
        ("utf16", Call::List) => emit(&utf16le_with_bom(JA_LIST), 0),
        ("nodistro", Call::List) => emit(NO_DISTRO.as_bytes(), 1),
        ("v1only", Call::List) => emit(V1_LIST.as_bytes(), 0),
        ("disabled", _) => emit(DISABLED.as_bytes(), 1),
        ("denied", _) => emit(DENIED.as_bytes(), 1),
        ("garbage", _) => emit(b"hello from an unknown tool\n", 0),
        ("hang", _) => {
            std::thread::sleep(Duration::from_secs(60));
            ExitCode::SUCCESS
        }
        ("flood", _) => emit(&vec![b'x'; 128 * 1024], 0),
        _ => ExitCode::from(2),
    }
}
