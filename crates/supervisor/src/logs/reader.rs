//! コンテナログの読み出しの正規入口（`logs` コマンドの本体。CLI-1・SUP-7・TASK-79 追補・#1543。関連: REPAIR-1・REPAIR-5）。
//!
//! CLI の `logs <id>` が `<state_root>/@container-logs`（[`super::container_log_dir`]）と [`super::container_log_rotation_config`]
//! を渡して [`read_container_log`] を呼ぶ。書き手は [`super::RotatingFileSink`]（supervisor の bin が開く）で、
//! レコード形式・ファイル名の写像・symlink を辿らない open の契約はどれも supervisor の持ち物のため、読み出しも
//! ここに置く（形式が変わっても直すのが 1 crate で済む。REPAIR-1）。
//!
//! # 契約
//! - 出力は、古い世代（`<enc>.log.<n>`、`n` が大きいほど古い）から現在ログ（`<enc>.log`）の順に、ファイルのバイト列を
//!   そのまま連結する。レコードのタグ（`stdout ` / `stderr `）・LF・書き込み失敗で途中切れの末尾も加工しない。
//!   ロックファイル・他 ID は含めない（[`super::log_file_paths`] が選ぶ）。
//! - ログが無い（ディレクトリが無い・ファイルが 0 件・0 バイト）は成功で、何も出力しない。
//! - 端末制御文字（ESC 系を含む）はエスケープしない。ログはコンテナ利用者のデータであり、端末へ直接出すと
//!   解釈され得る。呼び出し側（CLI）の doc に回避策を記す。
//! - 出力先への書き込みが詰まれば `cat` と同じく書き先次第で待つ（本関数は出力先にタイムアウトを持たない）。
//!
//! # ローテーションとの競合（REPAIR-5）
//! 1 回の試行は「一覧 → 古い順に全部 open（`fstat` で dev / ino / len を記録）→ 各パスと一覧を再確認」で、
//! 再確認が一致したときだけ成立とする。ずれたら全 fd を閉じて最大 [`MAX_SNAPSHOT_ATTEMPTS`] 回やり直し、
//! 尽きれば `Unavailable` を返す。成立後は握った fd から記録した `len` だけを固定バッファで流す（rename / unlink
//! されても fd の中身は変わらないため、抜けも重複も出さない。`len` 以降の追記は今回は出さない）。
//!
//! # 上限
//! 読む合計は `max_file_bytes × (generations + 1)`、ファイル数は `generations + 1` まで（ローテーション中に 1 世代
//! 増える余裕）。超えたら 1 バイトも出さず `FailedPrecondition` で失敗する（黙って切り詰めない）。
//! メモリは固定 8 KiB のバッファ 1 本。FIFO への差し替えは `open_for_read`（`O_NONBLOCK | O_NOFOLLOW` と種別照合）で止まらない。
//!
//! # 未実装（REPAIR-3）
//! 非 unix では dev / ino 相当で再確認できないため `Unimplemented` で fail-closed にする（非 Linux の CLI は
//! plugin 経由で、この入口まで来ない。TASK-114・TASK-125）。`--follow` / `--tail` / ストリーム別出力 / エスケープ表示は未提供（CLI-1 の拡張）。

use std::io::Write;
use std::path::Path;

use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

use super::rotating::RotationConfig;

/// 世代の入れ替わりで再試行する回数の上限（無限に回らない。REPAIR-5）。
pub const MAX_SNAPSHOT_ATTEMPTS: u32 = 3;

/// 読み出しの結果（将来の拡張に備えた構造体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogReadReport {
    files: u32,
    bytes: u64,
}

impl LogReadReport {
    /// 読んだファイル数（現在ログ・世代の合計）。
    pub fn files(&self) -> u32 {
        self.files
    }

    /// 出力先へ書いたバイト数。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// 読み出しの失敗。出力先の失敗と読み取り側の失敗を分ける（CLI が別の文言へ写すため）。
#[derive(Debug)]
pub enum LogReadFailure {
    /// ログ側の失敗。`Unavailable`（入れ替わりが収まらない）と `FailedPrecondition`（上限超過）以外は `Internal` に
    /// まとめる（パス・errno を含めない。ERR-1）。
    Source(TraitError),
    /// 出力先（stdout）への書き込みの失敗。
    Output,
}

fn source(code: ErrorCode, msg: &'static str) -> LogReadFailure {
    LogReadFailure::Source(TraitError::new(code, msg))
}

/// `id` のコンテナログを古い順に `out` へ書く。ログが無ければ何も書かず成功。
#[cfg(unix)]
pub fn read_container_log(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    out: &mut dyn Write,
) -> Result<LogReadReport, LogReadFailure> {
    imp::read(dir, id, config, out, &mut |_| {})
}

/// 非 unix は再確認の手段が無いため fail-closed（モジュール doc「未実装」）。
#[cfg(not(unix))]
pub fn read_container_log(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    out: &mut dyn Write,
) -> Result<LogReadReport, LogReadFailure> {
    let _ = (dir, id, config, out);
    Err(source(
        ErrorCode::Unimplemented,
        "reading container logs is not supported on this platform",
    ))
}

#[cfg(unix)]
mod imp {
    use std::fs::{self, File};
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

    use super::super::rotating::{
        RotationConfig, is_replaced_during_open, log_file_paths, open_for_read,
    };
    use super::{LogReadFailure, LogReadReport, MAX_SNAPSHOT_ATTEMPTS, source};

    /// 流すときの固定バッファ。
    const COPY_BUFFER_BYTES: usize = 8 * 1024;

    const MSG_READ: &str = "container log could not be read";

    /// 開いた 1 ファイルの記録（fd と、開いた時点の dev / ino / len）。
    struct Opened {
        path: PathBuf,
        file: File,
        dev: u64,
        ino: u64,
        len: u64,
    }

    enum Attempt {
        Done(Vec<Opened>),
        /// 世代が入れ替わった。やり直す。
        Retry,
    }

    fn read_error(e: TraitError) -> LogReadFailure {
        match e.code() {
            ErrorCode::Unavailable | ErrorCode::FailedPrecondition => LogReadFailure::Source(e),
            _ => source(ErrorCode::Internal, MSG_READ),
        }
    }

    /// 1 回のスナップショットを作る。`hook` は全 open の後・再確認の前に呼ばれる（試験用の差し込み口）。
    fn snapshot(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        attempt: u32,
        hook: &mut dyn FnMut(u32),
    ) -> Result<Attempt, LogReadFailure> {
        let paths = log_file_paths(dir, id).map_err(read_error)?;
        let max_files = u64::from(config.generations()).saturating_add(1);
        if u64::try_from(paths.len()).unwrap_or(u64::MAX) > max_files {
            return Err(source(
                ErrorCode::FailedPrecondition,
                "container log exceeds the read limit",
            ));
        }
        let mut opened: Vec<Opened> = Vec::with_capacity(paths.len());
        for path in &paths {
            let file = match open_for_read(path) {
                Ok(f) => f,
                // 一覧の後にローテーションで消えた。やり直す。
                Err(e) if e.code() == ErrorCode::NotFound => return Ok(Attempt::Retry),
                // lstat と open の間に同じ世代パスが別の通常ファイルへ入れ替わった（ローテーション）。やり直す。
                Err(e) if is_replaced_during_open(&e) => return Ok(Attempt::Retry),
                Err(e) => return Err(read_error(e)),
            };
            let meta = file
                .metadata()
                .map_err(|_| source(ErrorCode::Internal, MSG_READ))?;
            opened.push(Opened {
                path: path.clone(),
                file,
                dev: meta.dev(),
                ino: meta.ino(),
                len: meta.len(),
            });
        }
        hook(attempt);
        for o in &opened {
            match fs::symlink_metadata(&o.path) {
                Ok(m) if m.dev() == o.dev && m.ino() == o.ino => {}
                Ok(_) => return Ok(Attempt::Retry),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Attempt::Retry),
                Err(_) => return Err(source(ErrorCode::Internal, MSG_READ)),
            }
        }
        let again = log_file_paths(dir, id).map_err(read_error)?;
        if again != paths {
            return Ok(Attempt::Retry);
        }
        Ok(Attempt::Done(opened))
    }

    pub(super) fn read(
        dir: &Path,
        id: &ContainerId,
        config: RotationConfig,
        out: &mut dyn Write,
        hook: &mut dyn FnMut(u32),
    ) -> Result<LogReadReport, LogReadFailure> {
        // ディレクトリが無い = まだ何も書かれていない。`log_file_paths` の検査エラーと区別するため先に見る。
        if let Err(e) = fs::symlink_metadata(dir) {
            if e.kind() == ErrorKind::NotFound {
                return Ok(LogReadReport::default());
            }
            return Err(source(ErrorCode::Internal, MSG_READ));
        }
        let mut snap = None;
        for attempt in 0..MAX_SNAPSHOT_ATTEMPTS {
            match snapshot(dir, id, config, attempt, hook)? {
                Attempt::Done(o) => {
                    snap = Some(o);
                    break;
                }
                Attempt::Retry => {}
            }
        }
        let Some(opened) = snap else {
            return Err(source(
                ErrorCode::Unavailable,
                "container log is rotating; retry",
            ));
        };
        let limit = config
            .max_file_bytes()
            .saturating_mul(u64::from(config.generations()).saturating_add(1));
        let total = opened.iter().fold(0u64, |acc, o| acc.saturating_add(o.len));
        if total > limit {
            return Err(source(
                ErrorCode::FailedPrecondition,
                "container log exceeds the read limit",
            ));
        }
        let mut written = 0u64;
        let mut files = 0u32;
        let mut buf = [0u8; COPY_BUFFER_BYTES];
        for o in opened {
            let mut reader = o.file.take(o.len);
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => return Err(source(ErrorCode::Internal, MSG_READ)),
                };
                let Some(chunk) = buf.get(..n) else {
                    return Err(source(ErrorCode::Internal, MSG_READ));
                };
                out.write_all(chunk).map_err(|_| LogReadFailure::Output)?;
                written = written.saturating_add(n as u64);
            }
            files = files.saturating_add(1);
        }
        out.flush().map_err(|_| LogReadFailure::Output)?;
        Ok(LogReadReport {
            files,
            bytes: written,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fc-sup-rd-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).expect("mkdir");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }
        fn put(&self, name: &str, body: &[u8]) {
            fs::write(self.0.join(name), body).expect("write");
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("id")
    }

    fn small() -> RotationConfig {
        RotationConfig::default()
    }

    fn read_with(
        dir: &Path,
        id: &str,
        config: RotationConfig,
        hook: &mut dyn FnMut(u32),
    ) -> (Result<LogReadReport, LogReadFailure>, Vec<u8>) {
        let mut out = Vec::new();
        let r = imp::read(dir, &cid(id), config, &mut out, hook);
        (r, out)
    }

    fn code(r: Result<LogReadReport, LogReadFailure>) -> ErrorCode {
        match r {
            Err(LogReadFailure::Source(e)) => e.code(),
            other => panic!("expected Source error, got {other:?}"),
        }
    }

    /// SUP-7・CLI-1: 世代をまたいで古い順にバイト単位で連結する。ロックと他 ID は含めない。
    #[test]
    fn sup7_reads_generations_oldest_first_byte_exact() {
        let t = Tmp::new("gen");
        t.put("c1.log.2", b"stdout a\n");
        t.put("c1.log.1", b"stderr b\n");
        t.put("c1.log", b"stdout c\x1b[0m\n");
        t.put("c1.log.lock", b"");
        t.put("c2.log", b"stdout other\n");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        let rep = r.expect("ok");
        assert_eq!(out, b"stdout a\nstderr b\nstdout c\x1b[0m\n");
        assert_eq!(rep.files(), 3);
        assert_eq!(rep.bytes(), 9 + 9 + 13);
    }

    /// SUP-7・IO-5: 大文字の ID は小文字化した名前へ写る。
    #[test]
    fn sup7_uppercase_id_maps_to_encoded_name() {
        let t = Tmp::new("upper");
        t.put("_web.log", b"stdout w\n");
        let (r, out) = read_with(&t.0, "Web", small(), &mut |_| {});
        r.expect("ok");
        assert_eq!(out, b"stdout w\n");
    }

    /// CLI-1: ディレクトリが無い・空・0 バイトはどれも空の成功。
    #[test]
    fn cli1_no_logs_is_empty_success() {
        let t = Tmp::new("none");
        let missing = t.0.join("absent");
        let (r, out) = read_with(&missing, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok"), LogReadReport::default());
        assert!(out.is_empty());
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok").files(), 0);
        assert!(out.is_empty());
        t.put("c1.log", b"");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(r.expect("ok").bytes(), 0);
        assert!(out.is_empty());
    }

    /// SUP-7: 世代の位置の symlink・名前空間の別名は Internal（辿らない）。
    #[test]
    fn sup7_symlink_and_alias_are_internal() {
        let t = Tmp::new("sym");
        t.put("target", b"secret\n");
        std::os::unix::fs::symlink(t.0.join("target"), t.0.join("c1.log.1")).expect("symlink");
        t.put("c1.log", b"stdout x\n");
        let (r, out) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(code(r), ErrorCode::Internal);
        assert!(out.is_empty());
        let t = Tmp::new("alias");
        t.put("C1.log", b"stdout x\n");
        let (r, _) = read_with(&t.0, "c1", small(), &mut |_| {});
        assert_eq!(code(r), ErrorCode::Internal);
    }

    /// REPAIR-5: 合計バイトの上限超過は何も出さず FailedPrecondition。
    #[test]
    fn repair5_total_bytes_over_limit_fails_without_output() {
        let cfg = RotationConfig::new(super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let t = Tmp::new("big");
        let part = vec![b'x'; usize::try_from(cfg.max_file_bytes()).expect("usize")];
        t.put("c1.log.1", &part);
        t.put("c1.log", &part);
        // 上限は max × (1 + 1) 以内なので成功する。
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        r.expect("at limit");
        assert_eq!(out.len(), part.len() * 2);
        // 両方が 1 バイト超過して合計が上限を超える。
        let mut over = part.clone();
        over.push(b'y');
        t.put("c1.log", &over);
        t.put("c1.log.1", &over);
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        assert_eq!(code(r), ErrorCode::FailedPrecondition);
        assert!(out.is_empty());
    }

    /// REPAIR-5: ファイル数が generations + 1 を超えたら FailedPrecondition。
    #[test]
    fn repair5_file_count_over_limit_fails() {
        let cfg = RotationConfig::new(super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let t = Tmp::new("count");
        t.put("c1.log.2", b"stdout a\n");
        t.put("c1.log.1", b"stdout b\n");
        t.put("c1.log", b"stdout c\n");
        let (r, out) = read_with(&t.0, "c1", cfg, &mut |_| {});
        assert_eq!(code(r), ErrorCode::FailedPrecondition);
        assert!(out.is_empty());
    }

    struct Failing;

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// ERR-1: 出力先の失敗は Output で、Source と区別される。
    #[test]
    fn err1_output_failure_is_distinct() {
        let t = Tmp::new("out");
        t.put("c1.log", b"stdout a\n");
        let r = imp::read(&t.0, &cid("c1"), small(), &mut Failing, &mut |_| {});
        assert!(matches!(r, Err(LogReadFailure::Output)));
    }

    /// REPAIR-5: open 後にパスが別の実体へ替わったら 1 回やり直して成功する（旧内容の取りこぼしを出さない）。
    #[test]
    fn repair5_swap_once_retries_and_succeeds() {
        let t = Tmp::new("swap1");
        t.put("c1.log.1", b"stdout old\n");
        t.put("c1.log", b"stdout cur\n");
        let dir = t.0.clone();
        let mut hook = |attempt: u32| {
            if attempt == 0 {
                // ローテーション: 現在ログを .1 へ、新しい現在ログを作る。
                fs::rename(dir.join("c1.log.1"), dir.join("c1.log.2")).expect("r1");
                fs::rename(dir.join("c1.log"), dir.join("c1.log.1")).expect("r2");
                fs::write(dir.join("c1.log"), b"stdout new\n").expect("w");
            }
        };
        let (r, out) = read_with(&t.0, "c1", small(), &mut hook);
        r.expect("ok");
        assert_eq!(out, b"stdout old\nstdout cur\nstdout new\n");
    }

    /// REPAIR-5: 毎回替わるなら 3 回で Unavailable（無限に回らない）。
    #[test]
    fn repair5_always_swapping_is_unavailable() {
        let t = Tmp::new("swapn");
        t.put("c1.log", b"stdout cur\n");
        let dir = t.0.clone();
        let mut calls = 0u32;
        let mut hook = |_: u32| {
            calls += 1;
            let tmp = dir.join("tmp");
            fs::write(&tmp, b"stdout other\n").expect("w");
            fs::rename(&tmp, dir.join("c1.log")).expect("r");
        };
        let (r, out) = read_with(&t.0, "c1", small(), &mut hook);
        assert_eq!(code(r), ErrorCode::Unavailable);
        assert!(out.is_empty());
        assert_eq!(calls, MAX_SNAPSHOT_ATTEMPTS);
    }
}
