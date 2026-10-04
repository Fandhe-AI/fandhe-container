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
/// 必ず NUL を持つ）。読めなければ `DATA_LOSS`。
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
    let text: String = text.replace('\r', "").trim_matches('\0').to_string();
    if text.trim().is_empty() {
        return Err(data_loss("wsl.exe produced no output"));
    }
    Ok(text)
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

fn parse_state(tokens: &[&str]) -> DistroState {
    let joined = tokens.join(" ");
    match joined.to_lowercase().as_str() {
        "running" | "実行中" => DistroState::Running,
        "stopped" | "停止" => DistroState::Stopped,
        "installing" => DistroState::Installing,
        "uninstalling" => DistroState::Uninstalling,
        "converting" => DistroState::Converting,
        _ => DistroState::Other(
            joined
                .chars()
                .filter(|c| !c.is_control())
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

/// 1 行を（既定フラグ, 名前, 状態トークン列, バージョントークン）へ分ける。
///
/// ヘッダーの STATE・VERSION 列の開始位置で名前・状態・バージョンを分け、空白を含むディストリ名を
/// 切り詰めない。列が揃っている行とみなすのは、STATE 列・VERSION 列のどちらの直前も空白で
/// 開始位置が非空白、かつ VERSION 列以降が 1 トークンの場合だけ（名前が列境界を越えた行は
/// この条件を満たさない）。それ以外は末尾 2 トークンを状態・バージョン、残りを名前とする
/// （この場合の状態は 1 語のみ）。
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
    if aligned {
        let name: String = chars.get(..state_col)?.iter().collect();
        let state: String = chars.get(state_col..version_col)?.iter().collect();
        let (name, state, ver) = (name.trim(), state.trim(), ver_tail.trim());
        if name.is_empty() || state.is_empty() {
            return None;
        }
        return Some((
            is_default,
            name.to_string(),
            state.to_string(),
            ver.to_string(),
        ));
    }
    let all: String = chars.iter().collect();
    let (head, ver) = all.trim().rsplit_once(char::is_whitespace)?;
    let (name, state) = head.trim_end().rsplit_once(char::is_whitespace)?;
    let name = name.trim();
    if name.is_empty() {
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
/// ヘッダー行は読み飛ばし、各行はヘッダーの列境界で「（`*`）名前 / 状態 / バージョン」に分ける
/// （空白を含む名前を保つ。位置が合わない行は末尾 2 トークンで分ける）。
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
        if name.chars().count() > MAX_NAME_CHARS || name.chars().any(|c| c.is_control()) {
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
    // ロケール依存の説明文は使わず、専用のエラー識別子のみで 0 件を判定する。
    const NO_DISTRO: &str = "wsl_e_default_distro_not_found";
    if DISABLED.iter().any(|t| text.contains(t)) {
        Failure::WslDisabled
    } else if text.contains(NO_DISTRO) && !has_other_error_id(&text, NO_DISTRO) {
        Failure::NoDistro
    } else {
        Failure::Unknown
    }
}

/// `text` に `allowed` 以外のエラー識別子（`wsl_e_*`・`hcs_e_*`・`0x8…` の HRESULT）が併記されているか。
///
/// 別の失敗理由が 0 件判定に紛れ込み、失敗が空の一覧として見落とされるのを防ぐ（fail-closed）。
fn has_other_error_id(text: &str, allowed: &str) -> bool {
    let masked = text.replace(allowed, " ");
    ["wsl_e_", "hcs_e_", "0x8", "0xc"]
        .iter()
        .any(|p| masked.contains(p))
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
        assert_eq!(classify_failure(&mixed), Failure::Unknown);
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
