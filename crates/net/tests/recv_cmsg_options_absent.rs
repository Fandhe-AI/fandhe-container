//! net crate の `src/` が、受信ソケットで fd を運ぶ cmsg を有効にするオプションを使わないことの機械照合。
//!
//! `sys/holder.rs` の `recv_with_fds` は `SCM_RIGHTS` 以外の fd 付き cmsg（`SO_PASSPIDFD` の `SCM_PIDFD` 等）
//! を有効にしない前提で、`parse_scm_rights` が他の cmsg を読み飛ばす。前提が崩れると届いた fd が誰にも所有されず
//! 漏れるため、`SO_PASSPIDFD`・`SO_PASSRIGHTS`・`SO_PASSSEC` が `src/` に現れたら失敗にする
//! （SEC-1・REPAIR-5・REPAIR-12・#4544・#4531）。
//!
//! 除外するのは `trim_start()` が `//` で始まる行（行全体がコメント）だけ。行末コメント・ブロックコメント・
//! 文字列リテラル内の出現は fail-closed で検出扱いにする。
//!
//! 残余: 名前を使わない数値の直書き（`setsockopt(fd, 1, 76, ..)`）は検出しない。`tests/` は走査しない
//! （製品の受信ソケットは `src/` にある）。複数行の raw 文字列内で行頭が `//` の行は見逃しうる。
//! `SO_PASSCRED`・`SCM_PIDFD` は対象外。

use std::path::{Path, PathBuf};

const FORBIDDEN: [&str; 3] = ["SO_PASSPIDFD", "SO_PASSRIGHTS", "SO_PASSSEC"];

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// 禁止名の出現を `(行番号（1 始まり）, 名前)` で返す。識別子の境界で判定する。
fn find_forbidden(src: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for name in FORBIDDEN {
            for (pos, _) in line.match_indices(name) {
                let before_ok = line
                    .get(..pos)
                    .and_then(|s| s.chars().next_back())
                    .is_none_or(|c| !is_ident(c));
                let after_ok = line
                    .get(pos + name.len()..)
                    .and_then(|s| s.chars().next())
                    .is_none_or(|c| !is_ident(c));
                if before_ok && after_ok {
                    found.push((idx + 1, name));
                }
            }
        }
    }
    found
}

/// `dir` 配下の `.rs` を再帰的に集める（symlink は辿らない）。
/// 列挙・エントリ取得・metadata 取得の失敗は対象パス付きのエラーで返す（検査漏れを許さない）。
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("cannot read entry under {}: {e}", dir.display()))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.is_dir() {
            collect_rs_files(&path, out)?;
        } else if meta.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn sec1_4544_find_forbidden_synthetic_cases() {
    assert_eq!(
        find_forbidden("pub const SO_PASSPIDFD: i32 = 76;"),
        vec![(1, "SO_PASSPIDFD")]
    );
    assert_eq!(
        find_forbidden("setsockopt(fd, SOL_SOCKET, libc::SO_PASSSEC, p, l);"),
        vec![(1, "SO_PASSSEC")]
    );
    assert_eq!(
        find_forbidden("x(SO_PASSRIGHTS)"),
        vec![(1, "SO_PASSRIGHTS")]
    );
    assert_eq!(
        find_forbidden("let x = 1; // SO_PASSPIDFD"),
        vec![(1, "SO_PASSPIDFD")]
    );
    assert_eq!(
        find_forbidden("let s = \"SO_PASSSEC\";"),
        vec![(1, "SO_PASSSEC")]
    );
    assert_eq!(
        find_forbidden("/// SO_PASSPIDFD で届く SCM_PIDFD\n//! SO_PASSSEC\n    // SO_PASSRIGHTS"),
        vec![]
    );
    assert_eq!(
        find_forbidden("SO_PASSSECX XSO_PASSPIDFD SO_PASSCRED SO_PASSRIGHTS_2"),
        vec![]
    );
    assert_eq!(
        find_forbidden("a\n// c\nSO_PASSSEC\nb\nSO_PASSPIDFD"),
        vec![(3, "SO_PASSSEC"), (5, "SO_PASSPIDFD")]
    );
}

#[test]
fn sec1_4544_net_src_does_not_enable_fd_carrying_cmsg_options() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files).unwrap_or_else(|e| panic!("scan failed: {e}"));
    files.sort();
    assert!(
        files.len() >= 10,
        "scan path is broken: only {} .rs files under {}",
        files.len(),
        src_dir.display()
    );
    let holder = src_dir.join("sys").join("holder.rs");
    assert!(
        files.contains(&holder),
        "scan path is broken: {} not found",
        holder.display()
    );
    let mut violations = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", f.display()));
        for (line, name) in find_forbidden(&text) {
            violations.push(format!("{}:{line}: {name}", f.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "crates/net must not enable SO_PASSPIDFD / SO_PASSRIGHTS / SO_PASSSEC on sockets read by recv_with_fds.\n\
         If you need one, update parse_scm_rights (parsing) and adopt_scm_rights (ownership and close) in \
         crates/net/src/sys/holder.rs in the same change, and revise the receive-socket precondition section \
         of the recv_with_fds doc (SEC-1, #4531, #4544).\nviolations:\n{}",
        violations.join("\n")
    );
}
