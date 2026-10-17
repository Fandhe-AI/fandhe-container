//! ゲスト init の virtiofs プローブ行の契約と、ホスト側の復号器（MAC-1・IO-5・TASK-65.4 追補・#1876）。
//!
//! `crates/guest-init` の試験用プローブ（起動条件は [`crate::guest_mount::GuestTestMode`]）が hvc0 へ出す行を、
//! ホストの結合試験 `tests/virtiofs_io.rs`（macOS 実機）が解釈する。ゲスト出力は untrusted として扱い、
//! 名前空間を持つ行で契約の形に復号できないものは位置によらず不正にする（fail-closed）。OS 非依存の純 std
//! で、3 OS の単体テストで具体値を固定する。guest-init 側の生成と本モジュールの復号の一致は
//! `crates/guest-init/tests/contract.rs` が往復で照合する。
//!
//! # 行の形（v1）
//!
//! - `fandhe-guest-test: virtiofs-io v1 op=read value=<in/read.txt の 1 行目>`
//! - `fandhe-guest-test: virtiofs-io v1 op=readdir entries=<in/dir の名前のカンマ区切り>`
//! - `fandhe-guest-test: virtiofs-io v1 op=write result=done`（`out/write.txt` へ書いて sync 後）
//! - 失敗時 `... op=<op> result=error`、最後に `fandhe-guest-test: virtiofs-io v1 done`
//!
//! # 順序
//!
//! mount 報告（`fandhe-guest: virtiofs-mount ...`）→ 起動完了マーカー → プローブ行 → `done`。ready は
//! 名前空間 [`PROBE_NAMESPACE`] に属さないため `done` が最後であることの判定に影響しない。
//!
//! 接頭辞は `guest_mount::REPORT_PREFIX` と先頭から食い違うため、mount 報告の走査に誤認されない。

use std::collections::BTreeSet;

/// プローブ行の名前空間。これで始まる行は版数によらずプローブ行として扱う（契約外なら不正）。
pub const PROBE_NAMESPACE: &str = "fandhe-guest-test: virtiofs-io ";
/// 本モジュールが解釈する版（v1）の接頭辞。[`PROBE_NAMESPACE`] で始まる。
pub const PROBE_PREFIX: &str = "fandhe-guest-test: virtiofs-io v1 ";
/// プローブ用の共有タグ（RW）。
pub const SHARE_TAG: &str = "fandhe-io";
/// プローブ用共有のゲスト内 mount point。
pub const GUEST_MOUNT: &str = "/mnt/fandhe/io";
/// プローブ 1 行の最大バイト数（改行を除く）。
pub const MAX_PROBE_LINE_BYTES: usize = 256;
/// `out/write.txt` に書く 1 行の内容。
pub const WRITE_LINE: &str = "fandhe-virtiofs-write-v1";
/// `out/write.txt` に書く行数。
pub const WRITE_LINES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeItem {
    /// `op=read value=...`。
    Read(String),
    Readdir(String),
    Write,
    OpError(String),
    Done,
}

/// 1 行の分類結果。名前空間を持つ行は `Other` にならない（取りこぼしを不正として表に出すため）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeLine {
    /// プローブ名前空間で始まらない行（カーネル出力等）。無視してよい。
    Other,
    /// プローブ名前空間で始まるが契約の形に復号できない行。fail-closed で不正とする。
    Malformed,
    Item(ProbeItem),
}

/// 1 行を分類する。名前空間の判定は行頭の生バイトで先に行い、その後の上限超過・非 UTF-8・
/// 版数違い・未知 op・空 value はすべて `Malformed` とする（無視して見逃さない）。
pub fn parse_probe_line(line: &[u8]) -> ProbeLine {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if !line.starts_with(PROBE_NAMESPACE.as_bytes()) {
        return ProbeLine::Other;
    }
    if line.len() > MAX_PROBE_LINE_BYTES {
        return ProbeLine::Malformed;
    }
    decode_probe_item(line).map_or(ProbeLine::Malformed, ProbeLine::Item)
}

/// 名前空間を持つ行を v1 の契約どおりに復号する。形が崩れていれば `None`。
pub fn decode_probe_item(line: &[u8]) -> Option<ProbeItem> {
    let text = std::str::from_utf8(line).ok()?;
    let rest = text.strip_prefix(PROBE_PREFIX)?;
    if rest == "done" {
        return Some(ProbeItem::Done);
    }
    let rest = rest.strip_prefix("op=")?;
    let (op, field) = rest.split_once(' ')?;
    if field == "result=error" {
        return matches!(op, "read" | "readdir" | "write")
            .then(|| ProbeItem::OpError(op.to_string()));
    }
    match (op, field) {
        ("read", f) => f
            .strip_prefix("value=")
            .filter(|v| !v.is_empty())
            .map(|v| ProbeItem::Read(v.to_string())),
        ("readdir", f) => f
            .strip_prefix("entries=")
            .filter(|v| !v.is_empty())
            .map(|v| ProbeItem::Readdir(v.to_string())),
        ("write", "result=done") => Some(ProbeItem::Write),
        _ => None,
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProbeLog {
    pub read: Option<String>,
    pub readdir: Option<String>,
    pub write_done: bool,
    pub errors: Vec<String>,
    pub done: bool,
    /// 同じ op の重複報告・done の重複・done 以降の後続報告・全 op 報告前の done・
    /// 復号できないプローブ行（矛盾の有無・位置によらず不正として扱う）。
    pub invalid: bool,
}

impl ProbeLog {
    /// 指定 op の失敗報告（`result=error`）があるか。
    pub fn has_error(&self, op: &str) -> bool {
        self.errors.iter().any(|e| e == op)
    }

    /// 指定 op の報告（成功値または失敗）が出ているか。
    pub fn reported(&self, op: &str) -> bool {
        let ok = match op {
            "read" => self.read.is_some(),
            "readdir" => self.readdir.is_some(),
            _ => self.write_done,
        };
        ok || self.has_error(op)
    }
}

/// ログ全体を畳み込む。プローブ契約（AGENTS.md「最後に done」）に従い、次を `invalid`
/// （fail-closed）とする: op ごとの重複報告・done の重複・done 以降の後続報告・
/// read / readdir / write の全報告が揃う前の done・名前空間を持つが復号できない行（done の前後とも）。
///
/// ログは生バイトのまま `\n` で行に分割する（lossy 変換すると非 UTF-8 のプローブ行が置換文字で
/// 受理されてしまうため）。行末の `\r` は `parse_probe_line` が除く。
pub fn parse_probe_log(log: impl AsRef<[u8]>) -> ProbeLog {
    let mut out = ProbeLog::default();
    for line in log.as_ref().split(|b| *b == b'\n') {
        let item = match parse_probe_line(line) {
            ProbeLine::Other => continue,
            ProbeLine::Malformed => {
                out.invalid = true;
                continue;
            }
            ProbeLine::Item(item) => item,
        };
        if out.done {
            // done は最終行でなければならない（重複 done も後続報告もここで弾く）。
            out.invalid = true;
            continue;
        }
        match item {
            // 成功・失敗を合わせて op ごとに 1 回だけ報告できる。2 回目は種別によらず不正。
            ProbeItem::Read(v) => {
                out.invalid |= out.reported("read");
                out.read = Some(v);
            }
            ProbeItem::Readdir(v) => {
                out.invalid |= out.reported("readdir");
                out.readdir = Some(v);
            }
            ProbeItem::Write => {
                out.invalid |= out.reported("write");
                out.write_done = true;
            }
            ProbeItem::OpError(op) => {
                out.invalid |= out.reported(&op);
                out.errors.push(op);
            }
            ProbeItem::Done => {
                out.invalid |= !["read", "readdir", "write"]
                    .iter()
                    .all(|op| out.reported(op));
                out.done = true;
            }
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct EntriesMismatch {
    pub missing: BTreeSet<String>,
    pub extra: BTreeSet<String>,
    /// 報告内で 2 回以上現れたエントリ（集合化で潰れるため別枠で検出する）。
    pub duplicate: BTreeSet<String>,
    /// 空要素の数（`a,,b`・末尾 `,` 等。ゲストの報告形式の崩れとして余剰と同様に拒否する）。
    pub empty: usize,
}

/// 期待集合と報告（カンマ区切り）を比較し、不足・余剰・重複・空要素をすべて返す。
pub fn compare_entries(expected: &BTreeSet<String>, reported: &str) -> Result<(), EntriesMismatch> {
    let mut got: BTreeSet<String> = BTreeSet::new();
    let mut duplicate: BTreeSet<String> = BTreeSet::new();
    let mut empty = 0usize;
    for e in reported.split(',') {
        if e.is_empty() {
            empty += 1;
        } else if !got.insert(e.to_string()) {
            duplicate.insert(e.to_string());
        }
    }
    let missing: BTreeSet<String> = expected.difference(&got).cloned().collect();
    let extra: BTreeSet<String> = got.difference(expected).cloned().collect();
    if missing.is_empty() && extra.is_empty() && duplicate.is_empty() && empty == 0 {
        Ok(())
    } else {
        Err(EntriesMismatch {
            missing,
            extra,
            duplicate,
            empty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_mount;

    /// MAC-1・IO-5・TASK-65.4: プローブ行は mount 報告の走査（`fandhe-guest:`）に誤認されない。
    #[test]
    fn mac1_io5_probe_prefix_does_not_overlap_mount_report_prefix() {
        assert!(PROBE_PREFIX.starts_with(PROBE_NAMESPACE));
        assert!(!PROBE_NAMESPACE.starts_with(guest_mount::REPORT_PREFIX));
        assert!(!guest_mount::REPORT_PREFIX.starts_with(PROBE_NAMESPACE));
        assert!(!PROBE_PREFIX.starts_with(guest_mount::REPORT_PREFIX));
        assert!(!guest_mount::REPORT_PREFIX.starts_with(PROBE_PREFIX));
        for line in [
            "fandhe-guest-test: virtiofs-io v1 op=read value=abc",
            "fandhe-guest-test: virtiofs-io v1 done",
        ] {
            assert!(guest_mount::parse_report_line(line.as_bytes()).is_none());
        }
    }

    /// MAC-1・IO-5・TASK-65.4: プローブ行の解釈を具体値で固定する。
    #[test]
    fn mac1_io5_parse_probe_line_cases() {
        let p = |s: &str| parse_probe_line(s.as_bytes());
        let pre = PROBE_PREFIX;
        assert_eq!(
            p(&format!("{pre}op=read value=tok1")),
            ProbeLine::Item(ProbeItem::Read("tok1".into()))
        );
        assert_eq!(
            p(&format!("{pre}op=readdir entries=a-1,b-1,c-1")),
            ProbeLine::Item(ProbeItem::Readdir("a-1,b-1,c-1".into()))
        );
        assert_eq!(
            p(&format!("{pre}op=write result=done")),
            ProbeLine::Item(ProbeItem::Write)
        );
        assert_eq!(
            p(&format!("{pre}op=readdir result=error")),
            ProbeLine::Item(ProbeItem::OpError("readdir".into()))
        );
        assert_eq!(p(&format!("{pre}done")), ProbeLine::Item(ProbeItem::Done));
        // CRLF は許容する。
        assert_eq!(
            p(&format!("{pre}op=read value=tok1\r")),
            ProbeLine::Item(ProbeItem::Read("tok1".into()))
        );
        // 名前空間を持たない行・行頭以外に現れた接頭辞は無視する。
        assert_eq!(p("[    0.1] virtio-fs: probe"), ProbeLine::Other);
        assert_eq!(p(&format!("x {pre}op=read value=tok1")), ProbeLine::Other);
        // 名前空間を持つが契約外の行は不正: 上限超過・未知 op・空 value・未知の field・
        // done の後ろの余剰・版数違い・版数なし・非 UTF-8。
        let long = format!("{pre}op=read value={}", "a".repeat(MAX_PROBE_LINE_BYTES));
        assert_eq!(p(&long), ProbeLine::Malformed);
        assert_eq!(
            p(&format!("{pre}op=chmod result=error")),
            ProbeLine::Malformed
        );
        assert_eq!(p(&format!("{pre}op=chmod value=x")), ProbeLine::Malformed);
        assert_eq!(p(&format!("{pre}op=read value=")), ProbeLine::Malformed);
        assert_eq!(p(&format!("{pre}op=write result=ok")), ProbeLine::Malformed);
        assert_eq!(p(&format!("{pre}op=read")), ProbeLine::Malformed);
        assert_eq!(p(&format!("{pre}done now")), ProbeLine::Malformed);
        assert_eq!(p(pre), ProbeLine::Malformed);
        assert_eq!(
            p("fandhe-guest-test: virtiofs-io v2 op=read value=tok1"),
            ProbeLine::Malformed
        );
        assert_eq!(
            p("fandhe-guest-test: virtiofs-io done"),
            ProbeLine::Malformed
        );
        let mut non_utf8 = format!("{pre}op=read value=").into_bytes();
        non_utf8.push(0xff);
        assert_eq!(parse_probe_line(&non_utf8), ProbeLine::Malformed);
    }

    /// MAC-1・IO-5・TASK-65.4: 同じ op の重複報告は不正として扱う（fail-closed）。
    #[test]
    fn mac1_io5_parse_probe_log_rejects_duplicate_or_conflicting_reports() {
        let pre = PROBE_PREFIX;
        let ok = parse_probe_log(format!(
            "kernel noise\n{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n{pre}done\n"
        ));
        assert_eq!(ok.read.as_deref(), Some("t"));
        assert!(ok.write_done && ok.done && !ok.invalid);
        let dup = parse_probe_log(format!("{pre}op=read value=t\n{pre}op=read value=u\n"));
        assert!(dup.invalid);
        let dup_w = parse_probe_log(format!(
            "{pre}op=write result=done\n{pre}op=write result=done\n"
        ));
        assert!(dup_w.invalid);
    }

    /// MAC-1・IO-5・TASK-65.4: done は全 op 報告後の最終行でなければ不正（fail-closed）。
    #[test]
    fn mac1_io5_parse_probe_log_requires_done_last_and_complete() {
        let pre = PROBE_PREFIX;
        let body =
            format!("{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n");
        // 全 op の報告後に done が 1 回だけなら有効。
        let ok = parse_probe_log(format!("{body}{pre}done\n"));
        assert!(ok.done && !ok.invalid);
        // 失敗報告も「報告済み」として数える。
        let err = parse_probe_log(format!(
            "{pre}op=read result=error\n{pre}op=readdir result=error\n{pre}op=write result=error\n{pre}done\n"
        ));
        assert!(err.done && !err.invalid);
        // 失敗報告の重複、および成功と失敗の混在も同じ op の重複として不正。
        let dup_err = parse_probe_log(format!(
            "{pre}op=read result=error\n{pre}op=read result=error\n"
        ));
        assert!(dup_err.invalid);
        let mixed = parse_probe_log(format!(
            "{pre}op=write result=done\n{pre}op=write result=error\n"
        ));
        assert!(mixed.invalid);
        // 早過ぎる done。
        let early = parse_probe_log(format!("{pre}op=read value=t\n{pre}done\n"));
        assert!(early.done && early.invalid);
        // done の重複。
        let dup = parse_probe_log(format!("{body}{pre}done\n{pre}done\n"));
        assert!(dup.invalid);
        // done 以降の後続報告（エラー含む）。
        let late = parse_probe_log(format!("{body}{pre}done\n{pre}op=write result=error\n"));
        assert!(late.invalid);
    }

    /// MAC-1・IO-5・TASK-65.4: 復号できないプローブ行は done の前後とも不正（fail-closed）。
    #[test]
    fn mac1_io5_parse_probe_log_rejects_malformed_probe_lines() {
        let pre = PROBE_PREFIX;
        let body =
            format!("{pre}op=read value=t\n{pre}op=readdir entries=a\n{pre}op=write result=done\n");
        // 名前空間を持たない行は混ざっても有効のまま。
        let noise = parse_probe_log(format!(
            "[    0.1] boot\n{body}random output\n{pre}done\nreboot: Power down\n"
        ));
        assert_eq!(noise.read.as_deref(), Some("t"));
        assert_eq!(noise.readdir.as_deref(), Some("a"));
        assert!(noise.write_done && noise.done && !noise.invalid);
        // done の後の未知 op・形式崩れ・版数違い。
        for late in [
            format!("{pre}op=chmod result=error"),
            format!("{pre}op=read value="),
            "fandhe-guest-test: virtiofs-io v2 done".to_string(),
        ] {
            let log = parse_probe_log(format!("{body}{pre}done\n{late}\n"));
            assert!(log.done && log.invalid, "after done: {late}");
        }
        // done の前に現れた形式崩れも、他の報告が揃っていても不正。
        let early = parse_probe_log(format!("{pre}op=write result=ok\n{body}{pre}done\n"));
        assert!(early.done && early.write_done && early.invalid);
        // 非 UTF-8 の値を持つプローブ行は生バイトのまま判定し、置換文字で受理しない。
        let mut raw = format!("{pre}op=read value=t").into_bytes();
        raw.push(0xff);
        raw.extend_from_slice(
            format!("\n{pre}op=readdir entries=a\n{pre}op=write result=done\n{pre}done\n")
                .as_bytes(),
        );
        let bad = parse_probe_log(&raw);
        assert_eq!(bad.read, None);
        assert!(bad.done && bad.invalid);
        // 非 UTF-8 のカーネル出力（名前空間を持たない行）は無視し、CRLF の行も受理する。
        let mut crlf = vec![0xff, 0xfe, b'\n'];
        crlf.extend_from_slice(
            format!("{body}{pre}done\n")
                .replace('\n', "\r\n")
                .as_bytes(),
        );
        let ok = parse_probe_log(&crlf);
        assert_eq!(ok.read.as_deref(), Some("t"));
        assert!(ok.done && !ok.invalid);
    }

    /// MAC-1・IO-5・TASK-65.4: 不足・余剰・重複・空要素をすべて検出する。
    #[test]
    fn mac1_io5_compare_entries_detects_missing_and_extra() {
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        let exp = set(&["a", "b", "c"]);
        assert_eq!(compare_entries(&exp, "c,a,b"), Ok(()));
        assert_eq!(
            compare_entries(&exp, "a,b"),
            Err(EntriesMismatch {
                missing: set(&["c"]),
                extra: set(&[]),
                duplicate: set(&[]),
                empty: 0
            })
        );
        assert_eq!(
            compare_entries(&exp, "a,b,c,d"),
            Err(EntriesMismatch {
                missing: set(&[]),
                extra: set(&["d"]),
                duplicate: set(&[]),
                empty: 0
            })
        );
        assert_eq!(
            compare_entries(&exp, "a,x"),
            Err(EntriesMismatch {
                missing: set(&["b", "c"]),
                extra: set(&["x"]),
                duplicate: set(&[]),
                empty: 0
            })
        );
        assert_eq!(
            compare_entries(&exp, ""),
            Err(EntriesMismatch {
                missing: exp.clone(),
                extra: set(&[]),
                duplicate: set(&[]),
                empty: 1
            })
        );
        assert_eq!(
            compare_entries(&exp, "a,a,b,c"),
            Err(EntriesMismatch {
                missing: set(&[]),
                extra: set(&[]),
                duplicate: set(&["a"]),
                empty: 0
            })
        );
        // 空要素（末尾・途中・先頭のカンマ）は他が一致していても不一致。
        for (reported, empty) in [("a,b,c,", 1), ("a,,b,c", 1), (",a,b,c", 1), ("a,b,,c,", 2)] {
            assert_eq!(
                compare_entries(&exp, reported),
                Err(EntriesMismatch {
                    missing: set(&[]),
                    extra: set(&[]),
                    duplicate: set(&[]),
                    empty
                }),
                "{reported}"
            );
        }
    }
}
