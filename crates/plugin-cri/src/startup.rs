//! 起動引数の解析（TASK-114.1・#457・TASK-114.3.1・#849・PLUG-1）。
//!
//! 呼び出し元は `main.rs` のみ。argv は外部入力として扱い、件数と合計バイト数を
//! `PLUGIN_ARGS_MAX_*`（plugin 境界機構と同じ上限）で検証してから解釈する。
//! 診断は固定文言のみで、引数の値は含めない。
//! 受ける形は `--help`（単独）・`--socket <PATH>`・`--socket=<PATH>`。socket パスは絶対パスで `..` を含まないこと
//! だけをここで検証し、配置ディレクトリの所有者・0700・symlink・`sun_path` 長は bind 側（`UdsListener::bind`）に任せる。
//! ストリーミングサーバーの外部公開は既定で閉じ、`--streaming-bind <ADDR>`・`--streaming-allow-external`・`--streaming-advertise <IP>`
//! （`=` 形も可）を明示したときだけ開く（#4110・CRI-6・REPAIR-3）。値は `SocketAddr` / `IpAddr` として解釈し、cri の
//! `StreamingConfig::validate()` に通してから受ける。TLS も認証も無く、URL のトークンが唯一の認可なので、前段の守りが前提になる。
//! 既定の socket パスの解決は未定義（spec に定めが無い。#459 と #1869 の設計〔承認と実装 issue の起票は #2232〕で決める）ため、引数なしは成功を装わず失敗させる（REPAIR-3）。

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, PathBuf};

use fandhe_container_plugin::{
    PLUGIN_ARGS_MAX_BYTES, PLUGIN_ARGS_MAX_COUNT, PluginError, PluginErrorCode,
};

/// 未知の引数・`--help` の誤用に対する固定文言。
pub const MSG_UNEXPECTED_ARGUMENT: &str = "unexpected argument";
/// 件数・バイト数の上限超過に対する固定文言。
pub const MSG_ARGS_TOO_LARGE: &str = "too many or too long arguments";
/// `--socket` の値の欠落・重複・不正なパスに対する固定文言。
pub const MSG_INVALID_SOCKET: &str = "invalid --socket argument";
/// `--streaming-*` の値の欠落・重複・不正な値・組み合わせ違反に対する固定文言（値は含めない）。
pub const MSG_INVALID_STREAMING: &str = "invalid --streaming-* argument";
/// 既定の socket パスが未定義であることを伝える固定文言（成功終了で実装済みを装わない。REPAIR-3）。
pub const MSG_SOCKET_DEFAULT_UNDEFINED: &str =
    "default socket path is not defined yet; pass --socket <PATH>";

/// ストリーミングサーバーの待ち受けに関する起動引数（#4110・CRI-6・REPAIR-3）。
///
/// 既定（全未指定）は `StreamingConfig::default()`（`127.0.0.1:0`・外部公開なし）と同じ。`main.rs` が
/// [`crate::streaming::production_streaming_config_with`] で `StreamingConfig` へ写す。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamingOptions {
    /// `--streaming-bind`: 待ち受けアドレス。未指定は loopback の既定。
    pub bind: Option<SocketAddr>,
    /// `--streaming-allow-external`: 非 loopback での待ち受けの明示 opt-in。
    pub allow_external: bool,
    /// `--streaming-advertise`: 発行 URL に埋め込む広告アドレス。
    pub advertise: Option<IpAddr>,
}

/// 解析結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invocation {
    /// `--help`: usage を出して終了する。
    Help,
    /// 引数なし: 既定の socket が未定義のため起動できない（`main.rs` が `UNIMPLEMENTED` にする）。
    Run,
    /// `--socket <PATH>`: 指定の UDS で RuntimeService をサーブする（`server::serve`）。
    Serve {
        /// 検証済み（絶対パス・`..` なし・NUL なし）の socket パス。
        socket: PathBuf,
        /// 検証済みのストリーミング待ち受けの指定（既定は loopback）。
        streaming: StreamingOptions,
    },
}

/// usage（末尾改行つき 1 行）。
pub fn usage() -> &'static str {
    "usage: fandhe-container-plugin-cri [--help] | --socket <PATH> [--streaming-bind <ADDR>] [--streaming-allow-external] [--streaming-advertise <IP>]\n"
}

fn invalid(msg: &'static str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

/// `--socket=<PATH>` 等の接頭辞をバイト列のまま除く（非 UTF-8 の有効な Unix パスを拒否しない）。
fn strip_prefix_arg(a: &OsString, prefix: &str) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        a.as_bytes()
            .strip_prefix(prefix.as_bytes())
            .map(|v| OsString::from_vec(v.to_vec()))
    }
    #[cfg(not(unix))]
    {
        a.to_str()
            .and_then(|s| s.strip_prefix(prefix))
            .map(OsString::from)
    }
}

fn strip_socket_prefix(a: &OsString) -> Option<OsString> {
    strip_prefix_arg(a, "--socket=")
}

/// 値を UTF-8 の文字列として `T` に解釈する（欠落・空・非 UTF-8・不正は `None`）。
fn parse_value<T: std::str::FromStr>(value: Option<OsString>) -> Option<T> {
    let s = value?.into_string().ok()?;
    if s.is_empty() { None } else { s.parse().ok() }
}

/// socket パスを検証する（空でない・NUL なし・絶対・`..` なし）。
fn validate_socket(value: OsString) -> Result<PathBuf, PluginError> {
    #[cfg(unix)]
    let has_nul = {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().contains(&0)
    };
    #[cfg(not(unix))]
    let has_nul = value.to_string_lossy().contains('\0');
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || has_nul
        || !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid(MSG_INVALID_SOCKET));
    }
    Ok(path)
}

/// 組み合わせの検査。cri の `StreamingConfig::validate()`（非 loopback は allow-external 必須・ワイルドカードは広告必須・
/// 広告は具体的なユニキャスト）に通すほか、外部公開していないのに opt-in だけ・広告だけが立つ紛らわしい指定を拒む。
fn streaming_is_consistent(o: &StreamingOptions) -> bool {
    let external_bind = o.bind.is_some_and(|b| !b.ip().is_loopback());
    if o.allow_external && !external_bind {
        return false;
    }
    if o.advertise.is_some() && !o.allow_external {
        return false;
    }
    crate::streaming::production_streaming_config_with(o)
        .validate()
        .is_ok()
}

/// 引数（`argv[0]` を除く）を解析する。
///
/// `--help` がちょうど 1 個だけなら `Help`、引数なしなら `Run`、`--socket` がちょうど 1 回なら `Serve`、
/// それ以外は `InvalidArgument`。
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, PluginError> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut all = Vec::new();
    for a in args {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(a.len());
        if count > PLUGIN_ARGS_MAX_COUNT || bytes > PLUGIN_ARGS_MAX_BYTES {
            return Err(invalid(MSG_ARGS_TOO_LARGE));
        }
        all.push(a);
    }
    let mut help = false;
    let mut other = false;
    let mut socket: Option<PathBuf> = None;
    let mut socket_error = false;
    let mut streaming = StreamingOptions::default();
    let mut streaming_given = false;
    let mut streaming_error = false;
    let mut seen_bind = false;
    let mut seen_advertise = false;
    let mut iter = all.into_iter();
    while let Some(a) = iter.next() {
        if a == "--help" && !help {
            help = true;
            continue;
        }
        if a == "--streaming-allow-external" {
            streaming_given = true;
            if streaming.allow_external {
                streaming_error = true;
            }
            streaming.allow_external = true;
            continue;
        }
        let bind_value = if a == "--streaming-bind" {
            Some(iter.next())
        } else {
            strip_prefix_arg(&a, "--streaming-bind=").map(Some)
        };
        if let Some(v) = bind_value {
            streaming_given = true;
            if seen_bind {
                streaming_error = true;
            }
            seen_bind = true;
            match parse_value::<SocketAddr>(v) {
                Some(addr) => streaming.bind = Some(addr),
                None => streaming_error = true,
            }
            continue;
        }
        let adv_value = if a == "--streaming-advertise" {
            Some(iter.next())
        } else {
            strip_prefix_arg(&a, "--streaming-advertise=").map(Some)
        };
        if let Some(v) = adv_value {
            streaming_given = true;
            if seen_advertise {
                streaming_error = true;
            }
            seen_advertise = true;
            match parse_value::<IpAddr>(v) {
                Some(ip) => streaming.advertise = Some(ip),
                None => streaming_error = true,
            }
            continue;
        }
        let value = if a == "--socket" {
            // 値の欠落は不正（None のまま下で socket_error になる）。
            iter.next()
        } else if let Some(v) = strip_socket_prefix(&a) {
            Some(v)
        } else {
            other = true;
            continue;
        };
        if socket.is_some() || socket_error {
            socket_error = true;
            continue;
        }
        match value.map(validate_socket) {
            Some(Ok(p)) => socket = Some(p),
            _ => socket_error = true,
        }
    }
    let socket_given = socket.is_some() || socket_error;
    if other || (help && (socket_given || streaming_given)) || (streaming_given && !socket_given) {
        return Err(invalid(MSG_UNEXPECTED_ARGUMENT));
    }
    if socket_error {
        return Err(invalid(MSG_INVALID_SOCKET));
    }
    if streaming_given && (streaming_error || !streaming_is_consistent(&streaming)) {
        return Err(invalid(MSG_INVALID_STREAMING));
    }
    Ok(match (help, socket) {
        (true, _) => Invocation::Help,
        (false, Some(socket)) => Invocation::Serve { socket, streaming },
        (false, None) => Invocation::Run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Invocation, PluginError> {
        parse_args(a.iter().map(OsString::from))
    }

    fn msg(r: Result<Invocation, PluginError>) -> (PluginErrorCode, String) {
        let e = r.expect_err("must fail");
        (e.code(), e.message().to_string())
    }

    /// 非 UTF-8 のバイト列を含む `--socket=<PATH>` も受ける。
    #[cfg(unix)]
    #[test]
    fn socket_equals_form_accepts_non_utf8_path() {
        use std::os::unix::ffi::OsStringExt;
        let arg = OsString::from_vec(b"--socket=/run/\xff.sock".to_vec());
        let r = parse_args([arg]).expect("must parse");
        match r {
            Invocation::Serve { socket, .. } => {
                assert_eq!(socket.as_os_str().as_encoded_bytes(), b"/run/\xff.sock")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// PLUG-1: 引数なしは Run。
    #[test]
    fn no_args_is_run() {
        assert_eq!(p(&[]).expect("ok"), Invocation::Run);
    }

    #[test]
    fn help_alone_is_help() {
        assert_eq!(p(&["--help"]).expect("ok"), Invocation::Help);
    }

    #[test]
    fn unexpected_arguments_are_rejected() {
        for a in [
            &["--help", "--help"][..],
            &["--foo"],
            &["positional"],
            &["--help", "x"],
            &["x", "--help"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_UNEXPECTED_ARGUMENT.to_string()
                ),
                "args: {a:?}"
            );
        }
    }

    #[test]
    fn too_many_args_are_rejected() {
        let v = vec![OsString::from("a"); PLUGIN_ARGS_MAX_COUNT + 1];
        assert_eq!(
            msg(parse_args(v)),
            (
                PluginErrorCode::InvalidArgument,
                MSG_ARGS_TOO_LARGE.to_string()
            )
        );
    }

    #[test]
    fn too_long_arg_is_rejected() {
        let v = vec![OsString::from("a".repeat(PLUGIN_ARGS_MAX_BYTES + 1))];
        assert_eq!(
            msg(parse_args(v)),
            (
                PluginErrorCode::InvalidArgument,
                MSG_ARGS_TOO_LARGE.to_string()
            )
        );
    }

    #[test]
    fn usage_is_fixed() {
        assert_eq!(
            usage(),
            "usage: fandhe-container-plugin-cri [--help] | --socket <PATH> [--streaming-bind <ADDR>] [--streaming-allow-external] [--streaming-advertise <IP>]\n"
        );
    }

    /// PLUG-1: `--socket` は 2 つの形で受ける。
    #[test]
    #[cfg(unix)]
    fn socket_both_forms_serve() {
        let want = Invocation::Serve {
            socket: PathBuf::from("/run/x/s.sock"),
            streaming: StreamingOptions::default(),
        };
        assert_eq!(p(&["--socket", "/run/x/s.sock"]).expect("ok"), want);
        assert_eq!(p(&["--socket=/run/x/s.sock"]).expect("ok"), want);
    }

    #[test]
    fn invalid_socket_values_are_rejected_without_echo() {
        for a in [
            &["--socket"][..],
            &["--socket="],
            &["--socket", ""],
            &["--socket", "rel/s.sock"],
            &["--socket=/a/../b.sock"],
            &["--socket", "/a/s.sock", "--socket", "/b/s.sock"],
            &["--socket", "/a/s.sock", "--socket=/b/s.sock"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_INVALID_SOCKET.to_string()
                ),
                "args: {a:?}"
            );
        }
    }

    #[test]
    fn help_with_socket_is_rejected() {
        for a in [
            &["--help", "--socket", "/a/s"][..],
            &["--socket=/a/s", "--help"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_UNEXPECTED_ARGUMENT.to_string()
                ),
                "args: {a:?}"
            );
        }
    }

    fn streaming_of(a: &[&str]) -> StreamingOptions {
        match p(a).expect("ok") {
            Invocation::Serve { streaming, .. } => streaming,
            other => panic!("unexpected: {other:?}"),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    /// CRI-6・#4110: ストリーミング引数なしは loopback の既定のまま。
    #[test]
    fn cri6_4110_serve_without_streaming_flags_is_loopback_default() {
        let o = streaming_of(&["--socket", "/run/x/s.sock"]);
        assert_eq!(o, StreamingOptions::default());
        let c = crate::streaming::production_streaming_config_with(&o);
        assert_eq!(c.bind, "127.0.0.1:0".parse::<SocketAddr>().expect("addr"));
        assert!(!c.allow_external);
        assert_eq!(c.advertise_addr, None);
    }

    /// CRI-6・#4110: 3 つの引数は 2 つの形で同じ値になる。
    #[test]
    fn cri6_4110_streaming_flags_both_forms() {
        let want = StreamingOptions {
            bind: Some("0.0.0.0:10010".parse().expect("addr")),
            allow_external: true,
            advertise: Some(ip("192.0.2.7")),
        };
        assert_eq!(
            streaming_of(&[
                "--socket",
                "/a/s",
                "--streaming-bind",
                "0.0.0.0:10010",
                "--streaming-allow-external",
                "--streaming-advertise",
                "192.0.2.7",
            ]),
            want
        );
        assert_eq!(
            streaming_of(&[
                "--streaming-advertise=192.0.2.7",
                "--streaming-allow-external",
                "--socket=/a/s",
                "--streaming-bind=0.0.0.0:10010",
            ]),
            want
        );
        let v6 = streaming_of(&[
            "--socket=/a/s",
            "--streaming-bind=[::]:0",
            "--streaming-allow-external",
            "--streaming-advertise=2001:db8::1",
        ]);
        assert_eq!(v6.bind, Some("[::]:0".parse().expect("addr")));
        assert_eq!(v6.advertise, Some(ip("2001:db8::1")));
    }

    /// CRI-6・#4110: loopback のポート固定は opt-in なしで受ける（allow_external は立たない）。
    #[test]
    fn cri6_4110_loopback_bind_without_opt_in_is_accepted() {
        let o = streaming_of(&["--socket=/a/s", "--streaming-bind=127.0.0.1:9000"]);
        assert_eq!(o.bind, Some("127.0.0.1:9000".parse().expect("addr")));
        assert!(!o.allow_external);
    }

    /// CRI-6・#4110・REPAIR-4: 不正な指定は固定文言で、値を含めない。
    #[test]
    fn cri6_4110_invalid_streaming_values_are_rejected_without_echo() {
        let s = ["--socket", "/a/s"];
        let cases: Vec<Vec<&str>> = vec![
            vec!["--streaming-bind"],
            vec!["--streaming-bind="],
            vec!["--streaming-bind", "abc"],
            vec!["--streaming-bind=192.0.2.1"],
            vec![
                "--streaming-bind=127.0.0.1:1",
                "--streaming-bind=127.0.0.1:2",
            ],
            vec!["--streaming-bind=0.0.0.0:0"],
            vec!["--streaming-bind=192.0.2.1:0"],
            vec!["--streaming-bind=0.0.0.0:0", "--streaming-allow-external"],
            vec![
                "--streaming-bind=0.0.0.0:0",
                "--streaming-allow-external",
                "--streaming-advertise=0.0.0.0",
            ],
            vec![
                "--streaming-bind=0.0.0.0:0",
                "--streaming-allow-external",
                "--streaming-advertise=::",
            ],
            vec![
                "--streaming-bind=0.0.0.0:0",
                "--streaming-allow-external",
                "--streaming-advertise=224.0.0.1",
            ],
            vec![
                "--streaming-bind=0.0.0.0:0",
                "--streaming-allow-external",
                "--streaming-advertise",
            ],
            vec!["--streaming-advertise=192.0.2.7"],
            vec!["--streaming-allow-external"],
            vec![
                "--streaming-bind=127.0.0.1:9000",
                "--streaming-allow-external",
            ],
            vec![
                "--streaming-bind=192.0.2.1:0",
                "--streaming-allow-external",
                "--streaming-allow-external",
            ],
        ];
        for c in cases {
            let args: Vec<&str> = s.iter().copied().chain(c.iter().copied()).collect();
            let (code, m) = msg(p(&args));
            assert_eq!(code, PluginErrorCode::InvalidArgument, "args: {args:?}");
            assert_eq!(m, MSG_INVALID_STREAMING, "args: {args:?}");
            assert!(!m.contains("192.0.2") && !m.contains("0.0.0.0"));
        }
        // 具体的な外部アドレスは広告なしでも受ける（URL はその IP になる）。
        let o = streaming_of(&[
            "--socket=/a/s",
            "--streaming-bind=192.0.2.1:0",
            "--streaming-allow-external",
        ]);
        assert!(o.allow_external);
    }

    /// CRI-6・#4110: socket なし・--help との併用は未知の引数として拒む。
    #[test]
    fn cri6_4110_streaming_flags_without_socket_or_with_help_are_unexpected() {
        for a in [
            &["--streaming-bind=127.0.0.1:9000"][..],
            &["--streaming-allow-external"],
            &["--help", "--streaming-allow-external"],
            &["--socket=/a/s", "--help", "--streaming-bind=127.0.0.1:1"],
        ] {
            assert_eq!(
                msg(p(a)),
                (
                    PluginErrorCode::InvalidArgument,
                    MSG_UNEXPECTED_ARGUMENT.to_string()
                ),
                "args: {a:?}"
            );
        }
    }
}
