//! ゲスト init の virtiofs symlink・ハードリンク観測行の契約と、ホスト側の復号器（MAC-1・SEC-4・REPAIR-3・
//! TASK-65.1 追補・#1877・#1374）。
//!
//! `crates/guest-init` の観測モード（起動条件は [`crate::guest_mount::GuestTestMode::VirtiofsLink`]）が hvc0 へ
//! 出す行を、ホストの結合試験 `tests/virtiofs_link.rs`（macOS 実機）が解釈する。ゲスト出力は untrusted として
//! 扱い、名前空間を持つ行で契約の形に外れるものは位置によらず不正にする（fail-closed）。OS 非依存の純 std で、
//! 3 OS の単体テストで具体値を固定する。guest-init 側の生成と本モジュールの復号の一致は
//! `crates/guest-init/tests/contract.rs` が照合する。
//!
//! 本モジュールは**観測の良し悪しを判定しない**。行の形が契約どおりか・終端 `done` があるかだけを見る。
//! 観測結果の解釈と #1374 の条件 1・2 の記録は人間、拒否範囲を緩めるかはオーナーの判断（条件 3〜5）。
//!
//! # 行の形（v1。正常時は観測 18 行 + done）
//!
//! `fandhe-guest-test: virtiofs-link v1 share=<ro|rw> name=<固定名> op=<op> result=<結果>`。共有の mount が
//! 不成立のときだけ `share=<s> op=mount result=missing`（`name=` なし）。最後に
//! `fandhe-guest-test: virtiofs-link v1 done`。結果の語彙と各 op の意味はゲスト側 `link_probe` の `//!` が正。
//!
//! # 観測できないもの
//!
//! 共有範囲外を指す symlink と既存のハードリンク（`nlink > 1`）は、`VmConfigSpec::check_share_conflicts` が
//! 起動前に拒否するため fixture に入れられず、観測できない。
//!
//! 接頭辞は `guest_mount::REPORT_PREFIX`・`guest_probe::PROBE_NAMESPACE` と先頭から食い違うため、mount 報告や
//! virtiofs-io のプローブの走査に誤認されない（逆も同じ）。

/// link 行の名前空間。これで始まる行は版数によらず link 行として扱う（契約外なら不正）。
pub const LINK_NAMESPACE: &str = "fandhe-guest-test: virtiofs-link ";
/// 本モジュールが解釈する版（v1）の接頭辞。[`LINK_NAMESPACE`] で始まる。
pub const LINK_PREFIX: &str = "fandhe-guest-test: virtiofs-link v1 ";
/// 1 行の最大バイト数（改行を除く）。
pub const MAX_LINK_LINE_BYTES: usize = 256;
/// read の 1 行の上限（改行を除く）。
pub const MAX_LINK_READ_BYTES: usize = 64;
/// 集約する行数の上限（正常時は 19 行。超えたら不正）。
pub const MAX_LINK_LINES: usize = 64;
/// 読み取り専用の共有のタグ。
pub const RO_TAG: &str = "ro";
/// 読み取り専用の共有のゲスト内 mount point。
pub const RO_MOUNT: &str = "/mnt/fandhe/ro";
/// 読み書きできる共有のタグ。
pub const RW_TAG: &str = "rw";
/// 読み書きできる共有のゲスト内 mount point。
pub const RW_MOUNT: &str = "/mnt/fandhe/rw";
/// `ro` で観測するリンクの名前（この順）。
pub const RO_LINK_NAMES: [&str; 3] = ["inside_link", "abs_inside_link", "dangling_inside_link"];
/// `rw` にゲストが作る通常ファイル。
pub const RW_SRC_NAME: &str = "src";
/// `rw` にゲストが作る symlink（`sym -> src`）。
pub const RW_SYM_NAME: &str = "sym";
/// `rw` にゲストが作るハードリンク（`hard` ← `src`）。
pub const RW_HARD_NAME: &str = "hard";
/// `src` に書かれる 1 行。
pub const RW_SRC_LINE: &str = "fandhe-virtiofs-link-v1";
/// 終端行。
pub const LINK_DONE_LINE: &str = "fandhe-guest-test: virtiofs-link v1 done";

/// 復号したログ。判定はしない（行の形の健全性だけを持つ）。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LinkLog {
    /// 契約の形に合った観測行（[`LINK_PREFIX`] の後ろ。`done` は含まない）。出現順。
    pub lines: Vec<String>,
    /// 終端 `done` を観測したか。
    pub done: bool,
    /// 名前空間を持つが契約に外れる行・done の重複・done より後の行・行数超過（位置によらず不正）。
    pub invalid: bool,
}

/// `result=` 以降が `op` ごとの語彙どおりか。`value=` は行末までを値とする（空白を含みうる）。
fn result_matches_contract(op: &str, result: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let kind = |s: &str| matches!(s, "file" | "dir" | "symlink" | "other");
    if result == "ok" {
        // 引数なしの ok は create・symlink・link だけ。
        return matches!(op, "create" | "symlink" | "link");
    }
    if result.starts_with("ok value=") {
        return matches!(op, "readlink" | "read");
    }
    if let Some(rest) = result.strip_prefix("ok kind=") {
        let mut it = rest.split(' ');
        let (k, n, z) = (it.next(), it.next(), it.next());
        let fields_ok = k.is_some_and(kind)
            && n.and_then(|n| n.strip_prefix("nlink=")).is_some_and(digits)
            && z.and_then(|z| z.strip_prefix("size=")).is_some_and(digits);
        return matches!(op, "lstat" | "stat") && fields_ok && it.next().is_none();
    }
    if let Some(e) = result.strip_prefix("error errno=") {
        return digits(e);
    }
    if let Some(k) = result.strip_prefix("not-regular kind=") {
        return op == "read" && kind(k);
    }
    result == "unprintable" && matches!(op, "readlink" | "read")
}

/// 名前空間を持つ 1 行が契約の形か（`done` は別扱い）。上限・UTF-8・制御文字に加え、`share`・`name`・`op`・
/// `result` の固定語彙と op ごとの結果フィールドの組み合わせを検証する。余分なトークン・未知の語・必須
/// フィールドの欠落は不正（MAC-1・SEC-4）。観測の良し悪し自体は判定しない。
fn decode_observation(line: &[u8]) -> Option<&str> {
    if line.len() > MAX_LINK_LINE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(line).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    let rest = text.strip_prefix(LINK_PREFIX)?;
    let (share, tail) = rest.strip_prefix("share=")?.split_once(' ')?;
    let names: &[&str] = match share {
        RO_TAG => &RO_LINK_NAMES,
        RW_TAG => &[RW_SRC_NAME, RW_SYM_NAME, RW_HARD_NAME],
        _ => return None,
    };
    // mount 不成立の行だけ `name=` を持たない。
    if let Some(r) = tail.strip_prefix("op=mount ") {
        return (r == "result=missing").then_some(rest);
    }
    let (name, tail) = tail.strip_prefix("name=")?.split_once(' ')?;
    let (op, result) = tail.strip_prefix("op=")?.split_once(' ')?;
    let known_op = matches!(
        op,
        "readlink" | "lstat" | "stat" | "read" | "create" | "symlink" | "link"
    );
    let result = result.strip_prefix("result=")?;
    (names.contains(&name) && known_op && result_matches_contract(op, result)).then_some(rest)
}

/// ログ全体を畳み込む。ログは生バイトのまま `\n` で行に分割する（lossy 変換すると非 UTF-8 の行が置換文字で
/// 受理されてしまうため）。行末の `\r` は除く。名前空間を持たない行（カーネル出力・mount 報告・ready・
/// virtiofs-io のプローブ行）は無視する。
pub fn parse_link_log(log: impl AsRef<[u8]>) -> LinkLog {
    let mut out = LinkLog::default();
    for line in log.as_ref().split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !line.starts_with(LINK_NAMESPACE.as_bytes()) {
            continue;
        }
        if out.done {
            // done は最終行でなければならない（重複 done も後続の行もここで弾く）。
            out.invalid = true;
            continue;
        }
        if line == LINK_DONE_LINE.as_bytes() {
            out.done = true;
            continue;
        }
        match decode_observation(line) {
            Some(rest) if out.lines.len() < MAX_LINK_LINES => out.lines.push(rest.to_string()),
            _ => out.invalid = true,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "fandhe-guest-test: virtiofs-link v1 ";

    fn log(lines: &[String]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    /// MAC-1・SEC-4・#1877: 定数は固定値で、名前空間は他の行の名前空間と包含関係にない。
    #[test]
    fn mac1_sec4_link_constants_are_fixed_and_disjoint() {
        assert_eq!(LINK_NAMESPACE, "fandhe-guest-test: virtiofs-link ");
        assert_eq!(LINK_PREFIX, "fandhe-guest-test: virtiofs-link v1 ");
        assert_eq!(LINK_DONE_LINE, format!("{P}done"));
        assert!(LINK_PREFIX.starts_with(LINK_NAMESPACE));
        for other in [
            crate::guest_mount::REPORT_PREFIX,
            crate::guest_probe::PROBE_NAMESPACE,
        ] {
            assert!(!LINK_NAMESPACE.starts_with(other));
            assert!(!other.starts_with(LINK_NAMESPACE));
        }
        assert_eq!((RO_TAG, RO_MOUNT), ("ro", "/mnt/fandhe/ro"));
        assert_eq!((RW_TAG, RW_MOUNT), ("rw", "/mnt/fandhe/rw"));
        assert!(RO_MOUNT.starts_with(crate::guest_mount::GUEST_MOUNT_BASE));
        assert!(RW_MOUNT.starts_with(crate::guest_mount::GUEST_MOUNT_BASE));
    }

    /// MAC-1・SEC-4・#1877: 正常な観測行と done は受理し、他の名前空間の行は無視する。
    #[test]
    fn mac1_sec4_parse_accepts_observations_and_ignores_other_lines() {
        let text = format!(
            "Linux version x\nfandhe-guest: virtiofs-mount v1 tag=ro result=ok\n\
             fandhe-guest: init ready v1\n\
             {P}share=ro name=inside_link op=readlink result=ok value=inside.txt\r\n\
             fandhe-guest-test: virtiofs-io v1 op=read value=x\n\
             {P}share=rw op=mount result=missing\n\
             {P}done\n"
        );
        assert_eq!(
            parse_link_log(&text),
            LinkLog {
                lines: vec![
                    "share=ro name=inside_link op=readlink result=ok value=inside.txt".to_string(),
                    "share=rw op=mount result=missing".to_string(),
                ],
                done: true,
                invalid: false,
            }
        );
        assert_eq!(parse_link_log(""), LinkLog::default());
        // done が無ければ done=false のまま（待ち続ける側が期限で打ち切る）。
        let partial = parse_link_log(format!("{P}share=ro op=mount result=missing\n"));
        assert!(!partial.done && !partial.invalid);
    }

    /// MAC-1・SEC-4・#1877: 契約外の名前空間つきの行・done の重複・done 後の行・行数超過はすべて不正にする。
    #[test]
    fn mac1_sec4_parse_rejects_malformed_lines_fail_closed() {
        let ok = format!("{P}share=ro name=inside_link op=stat result=ok kind=file nlink=1 size=1");
        let long = format!(
            "{P}share=ro name=inside_link op=readlink result=ok value={}",
            "a".repeat(300)
        );
        let boundary = format!(
            "{P}share=ro name=inside_link op=readlink result=ok value={}",
            "a".repeat(
                MAX_LINK_LINE_BYTES
                    - P.len()
                    - "share=ro name=inside_link op=readlink result=ok value=".len()
            )
        );
        assert_eq!(boundary.len(), 256);
        assert!(!parse_link_log(log(&[boundary])).invalid);
        for (name, bad) in [
            (
                "v2",
                "fandhe-guest-test: virtiofs-link v2 share=ro op=mount result=missing".to_string(),
            ),
            (
                "no version",
                "fandhe-guest-test: virtiofs-link share=ro".to_string(),
            ),
            ("unknown shape", format!("{P}hello")),
            (
                "unknown share",
                format!("{P}share=xx op=mount result=missing"),
            ),
            ("too long", long),
            (
                "control char",
                format!("{P}share=ro name=inside_link op=readlink result=ok value=a\u{1b}[2J"),
            ),
            ("done with tail", format!("{P}done now")),
            ("garbage after share", format!("{P}share=ro garbage")),
            (
                "garbage after mount",
                format!("{P}share=ro op=mount result=missing extra"),
            ),
            (
                "unknown op",
                format!("{P}share=ro name=inside_link op=chmod result=ok"),
            ),
            (
                "unknown result",
                format!("{P}share=ro name=inside_link op=stat result=weird"),
            ),
            (
                "unknown name",
                format!("{P}share=rw name=evil op=create result=ok"),
            ),
            (
                "name of other share",
                format!("{P}share=ro name=src op=lstat result=error errno=2"),
            ),
            (
                "missing name",
                format!("{P}share=ro op=stat result=ok kind=file nlink=1 size=1"),
            ),
            (
                "missing result",
                format!("{P}share=ro name=inside_link op=stat"),
            ),
            (
                "stat without fields",
                format!("{P}share=ro name=inside_link op=stat result=ok"),
            ),
            (
                "stat with extra field",
                format!(
                    "{P}share=ro name=inside_link op=stat result=ok kind=file nlink=1 size=1 x=y"
                ),
            ),
            (
                "stat bad kind",
                format!("{P}share=ro name=inside_link op=stat result=ok kind=door nlink=1 size=1"),
            ),
            (
                "errno not digits",
                format!("{P}share=ro name=inside_link op=stat result=error errno=ENOENT"),
            ),
            (
                "create with value",
                format!("{P}share=rw name=src op=create result=ok value=x"),
            ),
            (
                "not-regular on stat",
                format!("{P}share=ro name=inside_link op=stat result=not-regular kind=dir"),
            ),
            (
                "unprintable on lstat",
                format!("{P}share=ro name=inside_link op=lstat result=unprintable"),
            ),
            (
                "mount not missing",
                format!("{P}share=ro op=mount result=ok"),
            ),
        ] {
            let parsed = parse_link_log(log(&[bad]));
            assert!(parsed.invalid, "{name}");
            assert!(parsed.lines.is_empty(), "{name}");
        }
        // 非 UTF-8 のバイト列は置換文字で受理しない。
        let mut bytes =
            format!("{P}share=ro name=inside_link op=readlink result=ok value=").into_bytes();
        bytes.extend_from_slice(&[0xff, b'\n']);
        assert!(parse_link_log(&bytes).invalid);
        // done の重複・done 後の行。
        let done = format!("{P}done");
        assert!(parse_link_log(log(&[done.clone(), done.clone()])).invalid);
        assert!(parse_link_log(log(&[done.clone(), ok.clone()])).invalid);
        assert!(!parse_link_log(log(&[ok.clone(), done])).invalid);
        // 行数の上限。
        let many = vec![ok; MAX_LINK_LINES + 1];
        let parsed = parse_link_log(log(&many));
        assert!(parsed.invalid);
        assert_eq!(parsed.lines.len(), MAX_LINK_LINES);
    }
}
