//! `wsl.exe` 出力のデコードと解析（TASK-67.3・WIN-1・ERR-1）。
//!
//! すべて純粋関数で、3 OS でユニットテストできる。入力は untrusted なので `unwrap` / 添字アクセスを
//! 使わず、未知の形式・不正なエンコーディング・上限超過は `Err`（fail-closed）にする。
//! 呼び出し元は `wsl2` モジュール（`interpret_*`）。

use super::run::Captured;
use super::{
    DistroState, MAX_DISTROS, Wsl2Error, Wsl2ErrorCode, WslDistro, WslMajorVersion, WslVersionInfo,
};

/// 1 行の長さ上限（バイト）。
const MAX_LINE_BYTES: usize = 1024;
/// ディストリ名の長さ上限（文字数）。
const MAX_NAME_CHARS: usize = 128;
/// バージョン文字列の長さ上限。
const MAX_VERSION_CHARS: usize = 64;
/// エラー抜粋の長さ上限（バイト。サニタイズ後は ASCII のみ）。
const MAX_EXCERPT_BYTES: usize = 128;
/// 未知の状態語を保持する長さ上限（文字数）。
const MAX_STATE_CHARS: usize = 32;

/// 失敗出力の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// WSL 機能または仮想マシン プラットフォームが無効。
    WslDisabled,
    /// WSL がアクセス拒否（`E_ACCESSDENIED` 等）を返した。
    PermissionDenied,
    /// ディストリが 1 件もない。
    NoDistro,
    /// 上記以外。
    Unknown,
}

fn data_loss(msg: &str) -> Wsl2Error {
    Wsl2Error::new(Wsl2ErrorCode::DataLoss, msg)
}

fn decode_utf16le(body: &[u8]) -> Result<String, Wsl2Error> {
    let (units, rest) = body.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(data_loss("UTF-16 output has an odd byte length"));
    }
    char::decode_utf16(units.iter().map(|c| u16::from_le_bytes(*c)))
        .collect::<Result<String, _>>()
        .map_err(|_| data_loss("output is not valid UTF-16"))
}

/// stdout のバイト列を文字列にする。UTF-16LE（BOM あり・なし）と UTF-8 を受け付ける。
///
/// `WSL_UTF8=1` に対応しない古い WSL は UTF-16LE で出力する。BOM なしの判定は文字種の割合に
/// 依存させず、「末尾以外に NUL バイトがある」（UTF-8 テキストは内部に NUL を含まない）で行う。
/// NUL が全くない場合は UTF-8 として扱う（`wsl.exe` の UTF-16 出力は ASCII の改行や空白を含むため
/// 必ず NUL を持つ）。読めなければ `DATA_LOSS`。行末以外の `\r` も `DATA_LOSS`（[`normalize_line_endings`]）。
pub(super) fn decode_output(bytes: &[u8]) -> Result<String, Wsl2Error> {
    if bytes.is_empty() {
        return Err(data_loss("wsl.exe produced no output"));
    }
    let text = if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        decode_utf16le(body)?
    } else {
        let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        let has_interior_nul = bytes.get(..end).is_some_and(|h| h.contains(&0));
        if has_interior_nul {
            decode_utf16le(bytes)?
        } else {
            let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
            std::str::from_utf8(body)
                .map_err(|_| data_loss("output is not valid UTF-8"))?
                .to_string()
        }
    };
    let text = normalize_line_endings(text.trim_matches('\0'))?;
    if text.trim().is_empty() {
        return Err(data_loss("wsl.exe produced no output"));
    }
    Ok(text)
}

/// 行末の復帰文字だけを取り除く。`\r` の連続の直後が `\n` か末尾なら除去し（`wsl.exe` は UTF-16 出力で
/// `\r\r\n` を出す）、それ以外の位置の `\r` は `DATA_LOSS` にする。
///
/// 行の途中の `\r` は表示を巻き戻してディストリ名等を偽装でき、空白扱いで列の区切りにもなるため、
/// 後段の検証に頼らずここで拒否する（外部入力の fail-closed。WIN-1）。
fn normalize_line_endings(text: &str) -> Result<String, Wsl2Error> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\r' {
            out.push(c);
            continue;
        }
        while chars.next_if_eq(&'\r').is_some() {}
        match chars.peek() {
            None | Some('\n') => {}
            Some(_) => return Err(data_loss("carriage return outside a line ending")),
        }
    }
    Ok(out)
}

fn check_line_len(line: &str) -> Result<(), Wsl2Error> {
    if line.len() > MAX_LINE_BYTES {
        return Err(Wsl2Error::new(
            Wsl2ErrorCode::ResourceExhausted,
            "output line exceeded the length limit",
        ));
    }
    Ok(())
}

/// 外部出力の文字列（ディストリ名・未知の状態語）に許さない文字か。
///
/// 制御文字（Cc）に加え、Unicode の書式文字（一般カテゴリ Cf。ゼロ幅文字・双方向制御・BOM・
/// 不可視の演算子・タグ文字等）と行区切り・段落区切り（U+2028・U+2029）を対象にする。
/// 表示上は見えない・並びを入れ替える文字で別のディストリ名に偽装されるのを防ぐ（依存を増やさず、
/// Cf の範囲は Unicode 16.0 の一覧を直接持つ）。
fn is_disallowed_text_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}

fn is_version_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_VERSION_CHARS
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// `wsl --version` の出力から WSL・カーネル・Windows のバージョンを取り出す。
///
/// ラベルは英語・日本語に対応し、WSL とカーネルのどちらかが取れなければ `DATA_LOSS`（未知ロケールは fail-closed）。
pub(super) fn parse_version(text: &str) -> Result<WslVersionInfo, Wsl2Error> {
    let mut wsl = None;
    let mut kernel = None;
    let mut windows = None;
    for line in text.lines() {
        check_line_len(line)?;
        let Some((label, value)) = line.split_once([':', '：']) else {
            continue;
        };
        let label = label.trim().to_lowercase();
        let value = value.trim();
        let slot = if label.contains("kernel") || label.contains("カーネル") {
            &mut kernel
        } else if label.starts_with("windows") {
            &mut windows
        } else if label.starts_with("wsl") && !label.starts_with("wslg") {
            &mut wsl
        } else {
            continue;
        };
        if slot.is_none() {
            if !is_version_token(value) {
                return Err(data_loss("version value has an unexpected format"));
            }
            *slot = Some(value.to_string());
        }
    }
    match (wsl, kernel) {
        (Some(wsl_version), Some(kernel_version)) => Ok(WslVersionInfo {
            wsl_version,
            kernel_version,
            windows_version: windows,
        }),
        _ => Err(data_loss("unrecognized `wsl --version` output format")),
    }
}

/// 既知の状態語（英語・日本語ロケール。大文字小文字は区別しない）を状態に写す。未知なら `None`。
fn known_state(word: &str) -> Option<DistroState> {
    match word.to_lowercase().as_str() {
        "running" | "実行中" => Some(DistroState::Running),
        "stopped" | "停止" => Some(DistroState::Stopped),
        "installing" => Some(DistroState::Installing),
        "uninstalling" => Some(DistroState::Uninstalling),
        "converting" => Some(DistroState::Converting),
        _ => None,
    }
}

fn parse_state(tokens: &[&str]) -> DistroState {
    let joined = tokens.join(" ");
    match known_state(&joined) {
        Some(state) => state,
        None => DistroState::Other(
            joined
                .chars()
                .filter(|c| !is_disallowed_text_char(*c))
                .take(MAX_STATE_CHARS)
                .collect(),
        ),
    }
}

/// ヘッダー行が既知の列名（NAME / STATE / VERSION と日本語ロケールの 名前 / 状態 / バージョン）を
/// この順で 3 列ちょうど持つか（想定外の先頭出力を拒否して fail-closed にする）。
fn is_known_header(header: &str) -> bool {
    const KNOWN: [[&str; 3]; 2] = [["name", "state", "version"], ["名前", "状態", "バージョン"]];
    let tokens: Vec<String> = header
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .collect();
    KNOWN
        .iter()
        .any(|k| tokens.len() == 3 && tokens.iter().zip(k.iter()).all(|(a, b)| a == b))
}

/// ヘッダー行から 2 列目（STATE）・3 列目（VERSION）が始まる文字位置を返す（列境界。空白区切りのトークン先頭）。
fn column_starts(header: &str) -> Option<(usize, usize)> {
    let mut starts = Vec::new();
    let mut prev_space = true;
    for (i, c) in header.chars().enumerate() {
        let space = c.is_whitespace();
        if !space && prev_space {
            starts.push(i);
        }
        prev_space = space;
    }
    match starts.as_slice() {
        [_, state, version] => Some((*state, *version)),
        _ => None,
    }
}

/// 1 行を（既定フラグ, 名前, 状態, バージョントークン）へ分ける。分けられなければ `None`（DATA_LOSS）。
///
/// 名前は可変幅で空白を含みうるため、次の順で境界を決める（名前の途中を状態とみなさない）:
/// 1. 末尾のトークンをバージョン、その直前のトークンが既知の状態語（[`known_state`]）なら状態とし、
///    残りを名前とする（名前が列幅を越えて STATE 列がずれた行でも、名前の末尾語を状態と取り違えない）。
/// 2. 状態語が未知なら、ヘッダーの STATE・VERSION 列の開始位置で分ける。列が揃っている行とみなすのは、
///    STATE 列・VERSION 列のどちらの直前も空白で開始位置が非空白、かつ VERSION 列以降が 1 トークンの
///    場合だけ（複数語の未知の状態語も保つ）。
/// 3. どちらでもない行は名前と状態の境界を決められないため、推測せず `None` を返す（fail-closed）。
fn split_row(
    line: &str,
    state_col: usize,
    version_col: usize,
) -> Option<(bool, String, String, String)> {
    let mut chars: Vec<char> = line.chars().collect();
    let first = chars.iter().position(|c| !c.is_whitespace())?;
    let is_default = first < state_col && chars.get(first) == Some(&'*');
    if is_default {
        // 位置を保つため '*' は空白に置き換える。
        *chars.get_mut(first)? = ' ';
    }
    let all: String = chars.iter().collect();
    let (head, ver) = all.trim().rsplit_once(char::is_whitespace)?;
    if let Some((name, state)) = head.trim_end().rsplit_once(char::is_whitespace)
        && known_state(state).is_some()
    {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        return Some((
            is_default,
            name.to_string(),
            state.to_string(),
            ver.to_string(),
        ));
    }
    let boundary = |col: usize| {
        col > 0
            && chars.get(col).is_some_and(|c| !c.is_whitespace())
            && chars.get(col - 1).is_some_and(|c| c.is_whitespace())
    };
    let ver_tail: String = chars.get(version_col..).unwrap_or(&[]).iter().collect();
    let aligned = version_col > state_col
        && boundary(state_col)
        && boundary(version_col)
        && ver_tail.split_whitespace().count() == 1;
    if !aligned {
        return None;
    }
    let name: String = chars.get(..state_col)?.iter().collect();
    let state: String = chars.get(state_col..version_col)?.iter().collect();
    let (name, state, ver) = (name.trim(), state.trim(), ver_tail.trim());
    if name.is_empty() || state.is_empty() {
        return None;
    }
    Some((
        is_default,
        name.to_string(),
        state.to_string(),
        ver.to_string(),
    ))
}

/// `wsl -l -v` の出力からディストリ一覧を取り出す（ヘッダーのみなら空）。
///
/// ヘッダー行は検証して読み飛ばし、各行を「（`*`）名前 / 状態 / バージョン」に分ける（境界の決め方は
/// [`split_row`]。空白を含む名前を保ち、境界を決められない行は `DATA_LOSS`）。
pub(super) fn parse_distros(text: &str) -> Result<Vec<WslDistro>, Wsl2Error> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| data_loss("wsl.exe produced no output"))?;
    check_line_len(header)?;
    if !is_known_header(header) {
        return Err(data_loss("unrecognized `wsl -l -v` header"));
    }
    let (state_col, version_col) =
        column_starts(header).ok_or_else(|| data_loss("unrecognized `wsl -l -v` header"))?;
    let mut distros = Vec::new();
    for line in lines {
        check_line_len(line)?;
        if distros.len() >= MAX_DISTROS {
            return Err(Wsl2Error::new(
                Wsl2ErrorCode::ResourceExhausted,
                "too many distributions in output",
            ));
        }
        let Some((is_default, name, state, ver)) = split_row(line, state_col, version_col) else {
            return Err(data_loss("unrecognized distribution row"));
        };
        if name.chars().count() > MAX_NAME_CHARS || name.chars().any(is_disallowed_text_char) {
            return Err(data_loss("distribution name has an unexpected format"));
        }
        let version = match ver.as_str() {
            "1" => WslMajorVersion::V1,
            "2" => WslMajorVersion::V2,
            _ => return Err(data_loss("unsupported WSL version in distribution row")),
        };
        let state_tokens: Vec<&str> = state.split_whitespace().collect();
        distros.push(WslDistro {
            name,
            state: parse_state(&state_tokens),
            version,
            is_default,
        });
    }
    Ok(distros)
}

/// 失敗出力（stdout と stderr）を既知トークンで分類する（ロケール非依存の識別子を使う）。
pub(super) fn classify_failure(out: &Captured) -> Failure {
    let mut text = String::new();
    for bytes in [&out.stdout, &out.stderr] {
        if let Ok(s) = decode_output(bytes) {
            text.push_str(&s.to_ascii_lowercase());
            text.push('\n');
        }
    }
    const DISABLED: [&str; 5] = [
        "wsl_e_wsl_optional_component_required",
        "hcs_e_hyperv_not_installed",
        "0x8007019e",
        "0x80370102",
        "wsl_e_vmcompute_not_ready",
    ];
    // アクセス拒否（`E_ACCESSDENIED`・Win32 の `ERROR_ACCESS_DENIED`・その HRESULT `0x80070005`）。
    const ACCESS_DENIED: [&str; 3] = ["e_accessdenied", "error_access_denied", "0x80070005"];
    // ロケール依存の説明文は使わず、専用のエラー識別子のみで 0 件を判定する。
    const NO_DISTRO: &str = "wsl_e_default_distro_not_found";
    let has_id = |ids: &[&str]| error_id_tokens(&text).any(|t| ids.contains(&t));
    if has_id(&DISABLED) {
        Failure::WslDisabled
    } else if has_id(&ACCESS_DENIED) {
        Failure::PermissionDenied
    } else if only_error_id_is(&text, NO_DISTRO) {
        Failure::NoDistro
    } else {
        Failure::Unknown
    }
}

/// `text`（小文字化済み）に現れるエラー識別子らしいトークンが `expected` だけか（1 回以上現れ、
/// それ以外の識別子を 1 つも含まない）。
///
/// 0 件判定に別の失敗理由が併記された出力（`E_ACCESSDENIED`・`ERROR_*`・`RPC_S_*`・HRESULT 等）を
/// 空の一覧として見落とさないよう、既知の接頭辞を列挙する方式ではなく、識別子の形をしたトークンを
/// すべて拾って許可リスト（`expected` のみ）と照合する（fail-closed。ERR-1）。
/// トークンは ASCII 英数字と `_` の連続で、`_` を含むもの（`WSL_E_*`・`E_*` 等の定数名）と
/// `0x` で始まる 16 進数（HRESULT）を識別子とみなす。案内文の単語・URL・コマンド例
/// （`wsl.exe --list --online`・`https://aka.ms/wslstore` 等）は `_` を含まないので対象外。
fn only_error_id_is(text: &str, expected: &str) -> bool {
    let mut found = false;
    for token in error_id_tokens(text) {
        if token != expected {
            return false;
        }
        found = true;
    }
    found
}

/// `text`（小文字化済み）からエラー識別子の形をしたトークンを列挙する（判定規則は [`only_error_id_is`]）。
///
/// 分類（無効・アクセス拒否・0 件）はすべてこのトークンとの完全一致で行い、部分一致で別の識別子を
/// 取り違えないようにする。
fn error_id_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| {
            let is_hex = token
                .strip_prefix("0x")
                .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()));
            token.contains('_') || is_hex
        })
}

/// エラーメッセージに載せる出力の抜粋。印字可能 ASCII 以外は `?` にし、128 バイト以下に切る。
pub(super) fn excerpt(out: &Captured) -> String {
    let text = [&out.stderr, &out.stdout]
        .into_iter()
        .find_map(|b| decode_output(b).ok())
        .unwrap_or_default();
    text.chars()
        .take(MAX_EXCERPT_BYTES)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else if c.is_ascii_whitespace() {
                ' '
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str, bom: bool) -> Vec<u8> {
        let mut v = if bom { vec![0xFF, 0xFE] } else { vec![] };
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    const EN_VERSION: &str = "WSL version: 2.1.5.0\r\nKernel version: 5.15.146.1-2\r\nWSLg version: 1.0.60\r\nMSRDC version: 1.2.5105\r\nDirect3D version: 1.611.1-81528511\r\nDXCore version: 10.0.25131.1002-220531-1700.rs-onecore-base2-hyp\r\nWindows version: 10.0.22631.3296\r\n";
    const JA_VERSION: &str = "WSL バージョン: 2.1.5.0\nカーネル バージョン: 5.15.146.1-2\nWSLg バージョン: 1.0.60\nWindows バージョン: 10.0.22631.3296\n";
    const EN_LIST: &str = "  NAME              STATE           VERSION\r\n* Ubuntu            Running         2\r\n  docker-desktop    Stopped         2\r\n  Legacy            Stopped         1\r\n";

    /// ディストリ 0 件時の `wsl.exe -l -v` 出力を模した例（英語。案内文・コマンド例・URL を含む）。
    const NO_DISTRO_FULL: &str = "Windows Subsystem for Linux has no installed distributions.\r\nYou can resolve this by installing a distribution with the instructions below:\r\n\r\nUse 'wsl.exe --list --online' to list available distributions\r\nand 'wsl.exe --install <Distro>' to install.\r\n\r\nDistributions can also be installed by visiting the Microsoft Store:\r\nhttps://aka.ms/wslstore\r\nError code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n";
    /// 同（日本語ロケールを想定した例。識別子はロケール非依存）。
    const NO_DISTRO_FULL_JA: &str = "Linux 用 Windows サブシステムには、ディストリビューションがインストールされていません。\r\n'wsl.exe --list --online' を使用して利用可能なディストリビューションを一覧表示し、\r\n'wsl.exe --install <Distro>' を使用してインストールします。\r\nhttps://aka.ms/wslstore\r\nエラー コード: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND\r\n";

    fn cap(success: bool, stdout: &[u8], stderr: &[u8]) -> Captured {
        Captured {
            success,
            code: Some(if success { 0 } else { 1 }),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    /// WIN-1: UTF-16LE（BOM あり・なし）と UTF-8、`\r\r\n`、末尾 NUL のデコード。
    #[test]
    fn decode_variants() {
        assert_eq!(
            decode_output(&utf16le("ab\r\r\ncd", true)).unwrap(),
            "ab\n\ncd".replace("\n\n", "\n")
        );
        assert_eq!(
            decode_output(&utf16le("WSL version: 2\r\n", false)).unwrap(),
            "WSL version: 2\n"
        );
        assert_eq!(
            decode_output(b"WSL version: 2\r\n\0\0").unwrap(),
            "WSL version: 2\n"
        );
        assert_eq!(decode_output("日本語".as_bytes()).unwrap(), "日本語");
    }

    /// WIN-1: 行末の `\r`（`\r\n`・`\r\r\n`・末尾）は除き、行の途中の `\r` は DATA_LOSS にする。
    #[test]
    fn carriage_return_only_at_line_end() {
        assert_eq!(decode_output(b"ab\r\r\ncd\r").unwrap(), "ab\ncd");
        assert_eq!(decode_output(b"x\r\n\0\0").unwrap(), "x\n");
        assert_eq!(
            decode_output(&utf16le("x\r\r\ny\r\n", true)).unwrap(),
            "x\ny\n"
        );
        for bad in [
            &b"ab\rcd"[..],
            &b"NAME STATE VERSION\r\nUbuntu\rRunning 2\r\n"[..],
            &b"NAME STATE VERSION\r\nUbu\r\rntu Running 2\r\n"[..],
        ] {
            assert_eq!(
                decode_output(bad).unwrap_err().code(),
                Wsl2ErrorCode::DataLoss,
                "{bad:?}"
            );
        }
        let bad16 = utf16le("NAME STATE VERSION\r\nEvil\rUbuntu Running 2\r\n", false);
        assert_eq!(
            decode_output(&bad16).unwrap_err().code(),
            Wsl2ErrorCode::DataLoss
        );
    }

    /// 異常系: 空・奇数長 UTF-16・不正サロゲート・不正 UTF-8 は DATA_LOSS。
    #[test]
    fn decode_errors() {
        for bad in [
            &b""[..],
            &[0xFF, 0xFE, 0x41][..],
            &[0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00][..],
            &[0xC3, 0x28][..],
            &b"\r\n \r\n"[..],
        ] {
            let e = decode_output(bad).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::DataLoss, "{bad:?}");
        }
    }

    /// WIN-1: `--version` の英語・日本語・UTF-16LE の具体値。
    #[test]
    fn version_parses() {
        let v = parse_version(&decode_output(&utf16le(EN_VERSION, false)).unwrap()).unwrap();
        assert_eq!(v.wsl_version, "2.1.5.0");
        assert_eq!(v.kernel_version, "5.15.146.1-2");
        assert_eq!(v.windows_version.as_deref(), Some("10.0.22631.3296"));
        let v = parse_version(&decode_output(JA_VERSION.as_bytes()).unwrap()).unwrap();
        assert_eq!(v.wsl_version, "2.1.5.0");
        assert_eq!(v.kernel_version, "5.15.146.1-2");
        assert_eq!(v.windows_version.as_deref(), Some("10.0.22631.3296"));
    }

    /// 異常系: ラベル不明・値が不正・行長超過は Err。
    #[test]
    fn version_errors() {
        assert_eq!(
            parse_version("garbage\n").unwrap_err().code(),
            Wsl2ErrorCode::DataLoss
        );
        assert_eq!(
            parse_version("WSL version: 2.1\nKernel version: a b c\n")
                .unwrap_err()
                .code(),
            Wsl2ErrorCode::DataLoss
        );
        assert_eq!(
            parse_version("WSL version: 2.1\n").unwrap_err().code(),
            Wsl2ErrorCode::DataLoss
        );
        let long = format!("WSL version: {}\n", "1".repeat(2000));
        assert_eq!(
            parse_version(&long).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
    }

    /// WIN-1: `-l -v` の既定・状態・V1 混在の具体値。
    #[test]
    fn list_parses() {
        let d = parse_distros(&decode_output(EN_LIST.as_bytes()).unwrap()).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].name, "Ubuntu");
        assert!(d[0].is_default);
        assert_eq!(d[0].state, DistroState::Running);
        assert_eq!(d[0].version, WslMajorVersion::V2);
        assert_eq!(d[1].name, "docker-desktop");
        assert!(!d[1].is_default);
        assert_eq!(d[1].state, DistroState::Stopped);
        assert_eq!(d[2].version, WslMajorVersion::V1);
    }

    /// ローカライズされた状態語・ヘッダーのみ。
    #[test]
    fn list_localized_and_empty() {
        let ja =
            "  名前     状態         バージョン\n* Ubuntu 実行中    2\n  Deb    Foo Bar    2\n";
        // 列がずれた行（全角幅の差など）でも末尾 2 トークンで分けられる。
        let d = parse_distros("  名前 状態 バージョン\n  Deb 停止 2\n").unwrap();
        assert_eq!(d[0].name, "Deb");
        assert_eq!(d[0].state, DistroState::Stopped);
        let d = parse_distros(ja).unwrap();
        assert_eq!(d[0].state, DistroState::Running);
        assert_eq!(d[1].state, DistroState::Other("Foo Bar".into()));
        assert!(parse_distros("  NAME STATE VERSION\n").unwrap().is_empty());
    }

    /// 想定外の先頭行（列名・順序・列数が違う）は拒否する。
    #[test]
    fn unexpected_header_is_rejected() {
        for h in [
            "Some banner text here\n",
            "STATE NAME VERSION\n",
            "NAME STATE\n",
            "NAME STATE VERSION EXTRA\n",
            "foo bar baz\n",
        ] {
            let t = format!("{h}Ubuntu Running 2\n");
            let e = parse_distros(&t).unwrap_err();
            assert_eq!(e.code(), Wsl2ErrorCode::DataLoss, "{h}");
        }
    }

    /// 空白を含むディストリ名は列境界で保たれ、状態に混入しない。
    #[test]
    fn list_name_with_spaces() {
        let t = "  NAME              STATE           VERSION\n* My Distro Name    Running         2\n  Other One         Stopped         1\n";
        let d = parse_distros(t).unwrap();
        assert_eq!(d[0].name, "My Distro Name");
        assert!(d[0].is_default);
        assert_eq!(d[0].state, DistroState::Running);
        assert_eq!(d[1].name, "Other One");
        assert_eq!(d[1].state, DistroState::Stopped);
        assert_eq!(d[1].version, WslMajorVersion::V1);
        // 列がずれた行でも名前は切り詰めない。
        let d = parse_distros("NAME STATE VERSION\nMy Distro Running 2\n").unwrap();
        assert_eq!(d[0].name, "My Distro");
        assert_eq!(d[0].state, DistroState::Running);
    }

    /// 名前が列境界を越え、境界直前に名前中の空白がある行でも名前を切り詰めない。
    #[test]
    fn list_name_straddles_column() {
        let t = "  NAME      STATE     VERSION\n* Very Long Distro Name Running   2\n  Ab Cdefghijkl Stopped   2\n";
        let d = parse_distros(t).unwrap();
        assert_eq!(d[0].name, "Very Long Distro Name");
        assert_eq!(d[0].state, DistroState::Running);
        assert_eq!(d[1].name, "Ab Cdefghijkl");
        assert_eq!(d[1].state, DistroState::Stopped);
        assert_eq!(d[1].version, WslMajorVersion::V2);
    }

    /// WIN-1: 名前の単語の先頭がたまたま STATE 列（11 文字目）と VERSION 列（26 文字目）に揃っても、
    /// 行末の既知の状態語を状態とし、名前の末尾語を状態と取り違えない。未知の状態語で列が揃わない行は
    /// 境界を決められないので DATA_LOSS。
    #[test]
    fn list_known_state_wins_over_coincidental_columns() {
        let t = "  NAME     STATE          VERSION\n* My Linux Distro Running 2\n";
        let d = parse_distros(t).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "My Linux Distro");
        assert_eq!(d[0].state, DistroState::Running);
        assert_eq!(d[0].version, WslMajorVersion::V2);
        assert!(d[0].is_default);
        // 名前の末尾語が状態語と同じでも、最後の状態語を状態とする。
        let d = parse_distros("NAME STATE VERSION\nUbuntu Running Stopped 2\n").unwrap();
        assert_eq!(d[0].name, "Ubuntu Running");
        assert_eq!(d[0].state, DistroState::Stopped);
        for bad in [
            "NAME STATE VERSION\nMy Distro Weird 2\n",
            "NAME STATE VERSION\nRunning 2\n",
        ] {
            assert_eq!(
                parse_distros(bad).unwrap_err().code(),
                Wsl2ErrorCode::DataLoss,
                "{bad}"
            );
        }
    }

    /// WIN-1: 日本語を多く含む BOM なし UTF-16LE も UTF-16 として解析できる。
    #[test]
    fn decode_japanese_utf16_without_bom() {
        let src =
            "  名前          状態          バージョン\n* あいうえおかきくけこ 実行中        2\n";
        let d = parse_distros(&decode_output(&utf16le(src, false)).unwrap()).unwrap();
        assert_eq!(d[0].name, "あいうえおかきくけこ");
        assert_eq!(d[0].state, DistroState::Running);
    }

    /// 異常系: ごみ・バージョン 3・トークン不足・件数超過は Err。
    #[test]
    fn list_errors() {
        for bad in [
            "garbage\n",
            "NAME STATE VERSION\nUbuntu Running 3\n",
            "NAME STATE VERSION\nUbuntu 2\n",
        ] {
            assert_eq!(
                parse_distros(bad).unwrap_err().code(),
                Wsl2ErrorCode::DataLoss,
                "{bad}"
            );
        }
        let mut many = String::from("NAME STATE VERSION\n");
        for i in 0..=MAX_DISTROS {
            many.push_str(&format!("d{i} Stopped 2\n"));
        }
        assert_eq!(
            parse_distros(&many).unwrap_err().code(),
            Wsl2ErrorCode::ResourceExhausted
        );
    }

    /// WIN-1: ディストリ名に制御文字・Unicode 書式文字（Cf）・行 / 段落区切りがあれば DATA_LOSS、
    /// 未知の状態語からは取り除く。通常の日本語名は受け付ける。
    #[test]
    fn list_rejects_invisible_chars() {
        for c in [
            '\u{0007}',
            '\u{00AD}',
            '\u{061C}',
            '\u{200B}',
            '\u{200F}',
            '\u{2028}',
            '\u{202E}',
            '\u{2066}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{E0041}',
        ] {
            let text = format!("NAME STATE VERSION\nUbu{c}ntu Running 2\n");
            assert_eq!(
                parse_distros(&text).unwrap_err().code(),
                Wsl2ErrorCode::DataLoss,
                "U+{:04X}",
                c as u32
            );
        }
        let ok = parse_distros("NAME STATE VERSION\nUbuntu-日本語 Running 2\n").unwrap();
        assert_eq!(ok[0].name, "Ubuntu-日本語");
        // 未知の状態語は列が揃った行でのみ受け付ける（STATE 列は 10 文字目・VERSION 列は 24 文字目）。
        let ok = parse_distros(
            "  NAME    STATE         VERSION\n  Deb     Weird\u{202E}\u{200B}State  2\n",
        )
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].name, "Deb");
        assert_eq!(ok[0].state, DistroState::Other("WeirdState".to_string()));
    }

    /// ERR-1: 失敗トークンの分類と抜粋のサニタイズ。
    #[test]
    fn classify_and_excerpt() {
        let disabled = cap(
            false,
            &utf16le(
                "Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED",
                false,
            ),
            b"",
        );
        assert_eq!(classify_failure(&disabled), Failure::WslDisabled);
        let none = cap(
            false,
            b"",
            &utf16le("Wsl/Service/WSL_E_DEFAULT_DISTRO_NOT_FOUND", false),
        );
        assert_eq!(classify_failure(&none), Failure::NoDistro);
        // 別の失敗理由が併記された場合は 0 件扱いにしない。
        let mixed = cap(
            false,
            b"",
            &utf16le(
                "WSL_E_DEFAULT_DISTRO_NOT_FOUND\nError code: Wsl/Service/E_ACCESSDENIED 0x80070005",
                false,
            ),
        );
        assert_eq!(classify_failure(&mixed), Failure::PermissionDenied);
        // HRESULT を伴わない別の識別子（`E_ACCESSDENIED`）の併記も 0 件扱いにしない。
        for (other, want) in [
            (
                "Error code: Wsl/Service/E_ACCESSDENIED",
                Failure::PermissionDenied,
            ),
            ("ERROR_FILE_NOT_FOUND", Failure::Unknown),
            ("RPC_S_SERVER_UNAVAILABLE", Failure::Unknown),
            ("Wsl/Service/0x80070005", Failure::PermissionDenied),
        ] {
            let mixed = cap(
                false,
                b"",
                &utf16le(
                    &format!("Error code: Wsl/Service/WSL_E_DEFAULT_DISTRO_NOT_FOUND\n{other}"),
                    false,
                ),
            );
            assert_eq!(classify_failure(&mixed), want, "{other}");
        }
        // 0 件時の案内文（コマンド例・URL を含む）は識別子として拾わず、0 件と判定する。
        let full = cap(false, NO_DISTRO_FULL.as_bytes(), b"");
        assert_eq!(classify_failure(&full), Failure::NoDistro);
        let ja = cap(false, &utf16le(NO_DISTRO_FULL_JA, false), b"");
        assert_eq!(classify_failure(&ja), Failure::NoDistro);
        // ERR-1: アクセス拒否の識別子は単独でも PermissionDenied。無効の識別子が併記されたら無効を優先し、
        // 識別子の一部だけが一致するトークンは拾わない（完全一致）。
        for (text, want) in [
            (
                "Error code: Wsl/Service/E_ACCESSDENIED",
                Failure::PermissionDenied,
            ),
            ("ERROR_ACCESS_DENIED", Failure::PermissionDenied),
            ("Wsl/0x80070005", Failure::PermissionDenied),
            (
                "Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\nE_ACCESSDENIED",
                Failure::WslDisabled,
            ),
            ("Wsl/Service/WSL_E_ACCESSDENIED_EXTRA", Failure::Unknown),
            ("Wsl/0x800700051", Failure::Unknown),
        ] {
            let c = cap(false, b"", &utf16le(text, false));
            assert_eq!(classify_failure(&c), want, "{text}");
        }
        let phrase_only = cap(false, b"", b"has no installed distributions");
        assert_eq!(classify_failure(&phrase_only), Failure::Unknown);
        let usage = cap(false, b"Usage: wsl.exe [Argument]\n", b"");
        assert_eq!(classify_failure(&usage), Failure::Unknown);
        let noisy = cap(false, "日本語\u{7}".repeat(100).as_bytes(), b"");
        let ex = excerpt(&noisy);
        assert!(ex.len() <= MAX_EXCERPT_BYTES);
        assert!(ex.chars().all(|c| c.is_ascii_graphic() || c == ' '));
    }
}
