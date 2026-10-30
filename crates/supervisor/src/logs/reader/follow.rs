//! `logs --follow` の追従ループ（unix。CLI-1・SUP-7。関連: REPAIR-5）。
//!
//! [`super::imp::read_with`] がスナップショットを出し終えた後に [`run`] を呼ぶ。固定間隔のポーリング（inotify / kqueue は
//! 使わない。`unsafe`・`sys` の宣言を増やさず、3 OS で同じ挙動にするため）で、現在ログの追記を完全な行（LF まで）だけ出す。
//!
//! # ローテーションの追い方
//! 書き手（[`crate::logs::RotatingFileSink`]）の順序は「バッファの書き出し → `sync_data` → close → 世代の rename →
//! 現在ログの新規作成」で、rename した後の旧ファイルにはもう書かれない。そこで保持中の fd の (dev, ino) と現在ログの
//! パスの (dev, ino) を毎回比べ、違えば（または rename から新規作成までの隙間で `NotFound` なら）次の順に進める。
//! 1. 保持中の fd を EOF まで出し切る（切れた末尾も出す）。
//! 2. 一貫したスナップショット（[`super::imp::open_consistent`]。入れ替わりは有界でやり直す）を取り、一覧から保持中の
//!    ファイルを (dev, ino) で探す。それより新しい世代を古い順に全部出し、新しい現在ログを先頭から保持し直す。
//! 3. 保持中のファイルが一覧に無い場合、世代数以上のローテーションがポーリングの間に起きて読めない世代があり得る。
//!    黙って飛ばさず `Unavailable`（[`super::FOLLOW_OUTRAN_MESSAGE`]）で失敗する。一覧が空（`delete` によるログの削除）なら
//!    出し切って成功で終わる。
//!
//! 保持する fd は保持中の 1 本と、スナップショットの一時的な `generations + 1` 本以下で、見たことのある inode の集合は
//! 持たない。fd を保持している間はその inode が解放されないため、ino の再利用で別のファイルと誤って一致することはない。
//! 世代数 1 では、ローテーションの隙間（現在ログの削除から新規作成まで）とログの削除を区別できず、ポーリングの間の複数回の
//! ローテーションも検出できない（照合する一つ前の世代が無い）ため、追従を拒否する（#2605。案内は [`super`] のモジュール doc）。
//!
//! # コンテナの停止での終了
//! 終了条件と理由は [`run`] と [`super`] のモジュール doc を参照（書き手のロックの解放と状態が `Running` でないこと、の両方）。

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use fandhe_container_core::traits::{ContainerId, ErrorCode};

use super::super::rotating::{RotationConfig, current_log_path, sink_is_active};
use super::imp::{
    Opened, check_bytes, check_limit, feed_range, internal, is_current_log, last_lf_end,
    open_consistent, read_error, scan_error,
};
use super::record::Scanner;
use super::{ContainerActivity, FOLLOW_OUTRAN_MESSAGE, FollowOptions, LogReadFailure, source};

/// 時計とスリープの差し込み口。製品は `Instant` と `thread::sleep`、試験は進める時計と書き手の模擬を渡す。
pub(super) struct Driver<'a> {
    /// 追従の開始からの経過時間。
    pub(super) elapsed: &'a mut dyn FnMut() -> Duration,
    /// ポーリング間の待ち。
    pub(super) sleep: &'a mut dyn FnMut(Duration),
    /// コンテナの稼働状態の probe（書き手がいなくなったときだけ呼ぶ。終了条件は [`run`] の doc を参照）。
    pub(super) activity: &'a mut dyn FnMut() -> ContainerActivity,
}

/// 初回のスナップショットを出し終えた状態の引き継ぎ。
pub(super) struct Start {
    pub(super) opened: Vec<Opened>,
    /// 各ファイルで出し終えた範囲の終端と、現在ログか。
    pub(super) plan: Vec<(u64, bool)>,
    pub(super) scanner: Scanner,
}

/// 保持中のファイル（最後に出したファイル）。
struct Held {
    file: fs::File,
    dev: u64,
    ino: u64,
    offset: u64,
}

/// 追従ループ。次のいずれかで、残りを出し切って成功で戻る。
/// - 期限（[`FollowOptions::deadline`]）に達した回。
/// - コンテナの停止: 書き手（sink）がいない（[`sink_is_active`] が `false`）**かつ** `driver.activity` が `Running` でも
///   `Unknown` でもない（`NotRunning`）とき。最終の `poll_once` でローテーションの追従を済ませ、保持中のファイルを
///   切れた末尾まで出し切る。ロックの検査は毎回、状態の probe はロックが解放されたときだけ呼ぶ。
///   ロックの検査の失敗（種別違反など）は読み取りの失敗として返す（fail-closed）。
///
/// 戻り値は追従中に新たに読んだファイル数（初回のスナップショット分を含まない）。
pub(super) fn run(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    follow: FollowOptions,
    start: Start,
    out: &mut dyn Write,
    driver: &mut Driver<'_>,
) -> Result<u32, LogReadFailure> {
    if config.generations() < 2 {
        return Err(source(ErrorCode::Unavailable, FOLLOW_OUTRAN_MESSAGE));
    }
    let mut scanner = start.scanner;
    let mut held: Option<Held> = None;
    let n = start.opened.len();
    for (i, (o, (limit, _current))) in start.opened.into_iter().zip(start.plan).enumerate() {
        if i + 1 == n {
            held = Some(Held {
                file: o.file,
                dev: o.dev,
                ino: o.ino,
                offset: limit,
            });
        }
    }
    let mut extra = 0u32;
    loop {
        let ended = poll_once(dir, id, config, &mut held, &mut scanner, out, &mut extra)?;
        out.flush().map_err(|_| LogReadFailure::Output)?;
        if ended {
            return Ok(extra);
        }
        if !sink_is_active(dir, id).map_err(read_error)?
            && (driver.activity)() == ContainerActivity::NotRunning
        {
            // 書き手は最終 flush を済ませて close 済み。ローテーションの残りと切れた末尾を出し切る。
            let ended = poll_once(dir, id, config, &mut held, &mut scanner, out, &mut extra)?;
            if !ended && let Some(h) = held.as_mut() {
                drain_all(h, &mut scanner, out, config)?;
            }
            out.flush().map_err(|_| LogReadFailure::Output)?;
            return Ok(extra);
        }
        let elapsed = (driver.elapsed)();
        if elapsed >= follow.deadline() {
            return Ok(extra);
        }
        let remaining = follow.deadline() - elapsed;
        (driver.sleep)(follow.poll_interval().min(remaining));
    }
}

/// ポーリング 1 回。ログが削除されて出し切ったら `true`。
fn poll_once(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    held: &mut Option<Held>,
    scanner: &mut Scanner,
    out: &mut dyn Write,
    extra: &mut u32,
) -> Result<bool, LogReadFailure> {
    if let Some(h) = held.as_mut() {
        feed_new(h, scanner, out, config)?;
    }
    let rotated = match held.as_ref() {
        None => true,
        Some(h) => match fs::symlink_metadata(dir) {
            Ok(_) => {
                let cur = current_log_path(dir, id).map_err(read_error)?;
                match fs::symlink_metadata(&cur) {
                    Ok(m) => m.dev() != h.dev || m.ino() != h.ino,
                    Err(e) if e.kind() == ErrorKind::NotFound => true,
                    Err(_) => return Err(internal()),
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => true,
            Err(_) => return Err(internal()),
        },
    };
    if !rotated {
        return Ok(false);
    }
    if advance(dir, id, config, held, scanner, out, extra)? {
        return Ok(true);
    }
    if let Some(h) = held.as_mut() {
        feed_new(h, scanner, out, config)?;
    }
    Ok(false)
}

/// 保持中のファイルが現在ログでなくなった（または未取得の）ときの切り替え。ログが削除されていたら `true`。
fn advance(
    dir: &Path,
    id: &ContainerId,
    config: RotationConfig,
    held: &mut Option<Held>,
    scanner: &mut Scanner,
    out: &mut dyn Write,
    extra: &mut u32,
) -> Result<bool, LogReadFailure> {
    if let Some(h) = held.as_mut() {
        drain_all(h, scanner, out, config)?;
    }
    let opened = open_consistent(dir, id, config, &mut |_| {})?;
    // 新しいスナップショットの合計も読み出す前に上限で検証する（初回と同じ。REPAIR-5）。
    check_limit(&opened, config)?;
    let first_new = match held.as_ref() {
        Some(h) => match opened.iter().position(|o| o.dev == h.dev && o.ino == h.ino) {
            Some(i) => i + 1,
            None if opened.is_empty() => return Ok(true),
            None => return Err(source(ErrorCode::Unavailable, FOLLOW_OUTRAN_MESSAGE)),
        },
        None => 0,
    };
    let n = opened.len();
    for (i, o) in opened.into_iter().enumerate().skip(first_new) {
        *extra = extra.saturating_add(1);
        let last = i + 1 == n;
        if last && is_current_log(&o.path) {
            *held = Some(Held {
                file: o.file,
                dev: o.dev,
                ino: o.ino,
                offset: 0,
            });
            continue;
        }
        // 確定済みの世代（書き手はもう書かない）。切れた末尾も含めて全部出す。
        feed_range(&o.file, 0, o.len, scanner, Some(&mut *out))?;
        scanner.end_file(Some(&mut *out)).map_err(scan_error)?;
        if last {
            *held = Some(Held {
                file: o.file,
                dev: o.dev,
                ino: o.ino,
                offset: o.len,
            });
        }
    }
    Ok(false)
}

/// 保持中のファイルの、まだ出していない完全な行（最後の LF まで）を出す。
fn feed_new(
    h: &mut Held,
    scanner: &mut Scanner,
    out: &mut dyn Write,
    config: RotationConfig,
) -> Result<(), LogReadFailure> {
    let len = h.file.metadata().map_err(|_| internal())?.len();
    if len < h.offset {
        return Err(internal());
    }
    check_bytes(len - h.offset, config)?;
    if len == h.offset {
        return Ok(());
    }
    let end = last_lf_end(&h.file, len, h.offset)?;
    if end > h.offset {
        feed_range(&h.file, h.offset, end, scanner, Some(out))?;
        h.offset = end;
    }
    Ok(())
}

/// 保持中のファイルを EOF まで（切れた末尾を含めて）出し切る。出し切った後は何度呼んでも何も出さない。
fn drain_all(
    h: &mut Held,
    scanner: &mut Scanner,
    out: &mut dyn Write,
    config: RotationConfig,
) -> Result<(), LogReadFailure> {
    let len = h.file.metadata().map_err(|_| internal())?.len();
    if len < h.offset {
        return Err(internal());
    }
    check_bytes(len - h.offset, config)?;
    if len > h.offset {
        feed_range(&h.file, h.offset, len, scanner, Some(&mut *out))?;
    }
    scanner.end_file(Some(out)).map_err(scan_error)?;
    h.offset = len;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::imp::read_with;
    use super::super::{LogReadOptions, LogReadReport};
    use super::*;
    use fandhe_container_core::traits::ErrorCode;
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::logs::StreamKind;

    /// 第 2 要素は残骸を消して作った実体（Drop で後始末する。REPAIR-12・#3435）。
    struct Tmp(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);

    impl Tmp {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fc-sup-fo-{tag}-{}-{n}", std::process::id()));
            // 残骸・PID 再利用との衝突を避けるため排他作成し、既存の名前は消さず別名で作る（0700。REPAIR-12・#3475）。
            let root = crate::test_root::test_root_at(p);
            Self(root.to_path_buf(), root)
        }
    }

    fn append(dir: &Path, name: &str, body: &[u8]) {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .expect("open");
        f.write_all(body).expect("write");
    }

    /// 書き手のローテーション（現在ログを世代 1 へ送り、古い世代を後ろへずらして、新しい現在ログを作る）。
    fn rotate(dir: &Path, new_current: Option<&[u8]>) {
        let _ = fs::rename(dir.join("c1.log.1"), dir.join("c1.log.2"));
        fs::rename(dir.join("c1.log"), dir.join("c1.log.1")).expect("rotate");
        if let Some(b) = new_current {
            fs::write(dir.join("c1.log"), b).expect("new current");
        }
    }

    struct Outcome {
        result: Result<LogReadReport, LogReadFailure>,
        out: Vec<u8>,
        sleeps: u32,
    }

    /// 時計を進めながら追従を回す。`script(round)` は各ポーリング間のスリープで呼ばれる（書き手の模擬）。
    fn follow_run(dir: &Path, opts: LogReadOptions, script: &mut dyn FnMut(u32)) -> Outcome {
        follow_run_probe(dir, opts, script, &mut || ContainerActivity::Running)
    }

    fn follow_run_probe(
        dir: &Path,
        opts: LogReadOptions,
        script: &mut dyn FnMut(u32),
        activity: &mut dyn FnMut() -> ContainerActivity,
    ) -> Outcome {
        let now = Rc::new(Cell::new(Duration::ZERO));
        let n2 = Rc::clone(&now);
        let sleeps = Rc::new(Cell::new(0u32));
        let s2 = Rc::clone(&sleeps);
        let mut elapsed = move || n2.get();
        let mut sleep = |d: Duration| {
            now.set(now.get() + d);
            let r = s2.get();
            s2.set(r + 1);
            script(r);
        };
        let mut driver = Driver {
            elapsed: &mut elapsed,
            sleep: &mut sleep,
            activity,
        };
        let mut out = Vec::new();
        let result = read_with(
            dir,
            &ContainerId::new("c1").expect("id"),
            RotationConfig::default(),
            &opts,
            &mut out,
            &mut |_| {},
            &mut driver,
        );
        Outcome {
            result,
            out,
            sleeps: sleeps.get(),
        }
    }

    fn follow_opts() -> LogReadOptions {
        LogReadOptions::default().with_follow(
            FollowOptions::new(Duration::from_millis(1000))
                .expect("deadline")
                .with_poll_interval(Duration::from_millis(200))
                .expect("interval"),
        )
    }

    /// SUP-7・CLI-1: スナップショットの後の追記が出る。
    #[test]
    fn sup7_follow_appends_after_snapshot() {
        let t = Tmp::new("append");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\n");
    }

    /// SUP-7: LF の来ていない部分行は出さない（スナップショットの末尾も追記の途中も）。
    #[test]
    fn sup7_follow_waits_for_lf() {
        let t = Tmp::new("waitlf");
        fs::write(t.0.join("c1.log"), b"stdout a\nstdout par").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"tial");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\n");

        let t = Tmp::new("waitlf2");
        fs::write(t.0.join("c1.log"), b"stdout a\nstdout par").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"tial\n");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout partial\n");
    }

    /// SUP-7: 1 回のローテーションをまたいでも欠落・重複しない。
    #[test]
    fn sup7_follow_single_rotation_no_loss_no_dup() {
        let t = Tmp::new("rot1");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
                rotate(&dir, Some(b"stdout c\n"));
            }
            if r == 1 {
                append(&dir, "c1.log", b"stdout d\n");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\nstdout c\nstdout d\n");
    }

    /// SUP-7: ポーリングの間に世代数の範囲内で複数回ローテーションしても、中間の世代を順に出す。
    #[test]
    fn sup7_follow_rotation_within_generations_between_polls() {
        let t = Tmp::new("rot2");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
                rotate(&dir, Some(b"stdout c\n"));
                append(&dir, "c1.log", b"stdout d\n");
                rotate(&dir, Some(b"stdout e\n"));
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\nstdout c\nstdout d\nstdout e\n");
    }

    /// SUP-7: 保持中のファイルが一覧から消えるほど速いローテーションは、黙って飛ばさず Unavailable。
    #[test]
    fn sup7_follow_outran_rotation_is_unavailable() {
        let t = Tmp::new("outran");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
                rotate(&dir, Some(b"stdout c\n"));
                rotate(&dir, Some(b"stdout d\n"));
                rotate(&dir, Some(b"stdout e\n"));
            }
        });
        match o.result {
            Err(LogReadFailure::Source(e)) => {
                assert_eq!(e.code(), ErrorCode::Unavailable);
                assert_eq!(e.message(), FOLLOW_OUTRAN_MESSAGE);
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
        // 失敗までに出した分は欠落も重複も無い（保持中の分は出し切ってから失敗する）。
        assert_eq!(o.out, b"stdout a\nstdout b\n");
    }

    /// SUP-7: ログが削除されたら出し切って成功で終わる。
    #[test]
    fn sup7_follow_logs_removed_ends_success() {
        let t = Tmp::new("removed");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
                fs::remove_file(dir.join("c1.log")).expect("rm");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\n");
        assert_eq!(o.sleeps, 1);
    }

    /// REPAIR-5: 期限に達したら成功で終わる（時計を進めて 200ms × 5 回）。
    #[test]
    fn repair5_follow_deadline_ends() {
        let t = Tmp::new("deadline");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let o = follow_run(&t.0, follow_opts(), &mut |_| {});
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\n");
        assert_eq!(o.sleeps, 5);
    }

    /// SUP-7: rename から新規作成までの隙間（現在ログが無い）を見ても、後から現れた現在ログを先頭から追う。
    #[test]
    fn sup7_follow_notfound_window_retries() {
        let t = Tmp::new("window");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stdout b\n");
                rotate(&dir, None);
            }
            if r == 1 {
                fs::write(dir.join("c1.log"), b"stdout c\n").expect("new current");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\nstdout c\n");
    }

    /// SUP-7: ログがまだ無い（ディレクトリも無い）状態から始めて、書かれ始めたら追う。
    #[test]
    fn sup7_follow_starts_before_any_log() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("early");
        let dir = t.0.join("logs");
        let d2 = dir.clone();
        let o = follow_run(&dir, follow_opts(), &mut |r| {
            if r == 0 {
                fs::create_dir_all(&d2).expect("mkdir");
                fs::set_permissions(&d2, fs::Permissions::from_mode(0o700)).expect("chmod");
                append(&d2, "c1.log", b"stdout x\n");
            }
        });
        let rep = o.result.expect("ok");
        assert_eq!(o.out, b"stdout x\n");
        // 追従中に読んだファイルも計上される。
        assert_eq!(rep.files(), 1);
    }

    /// REPAIR-5・SUP-7: 追従中に増えた量が上限を超えたら、読み出す前に `FailedPrecondition` で失敗する。
    #[test]
    fn repair5_follow_enforces_read_limit_on_growth() {
        let t = Tmp::new("growlimit");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let o = follow_run(&t.0, follow_opts(), &mut |r| {
            if r == 0 {
                let f = fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join("c1.log"))
                    .expect("open");
                f.set_len(1 << 40).expect("sparse grow");
            }
        });
        match o.result {
            Err(LogReadFailure::Source(e)) => assert_eq!(e.code(), ErrorCode::FailedPrecondition),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(o.out, b"stdout a\n");
    }

    /// CLI-1: 追従でもストリームの絞り込みとエスケープが効く。
    #[test]
    fn cli1_follow_applies_stream_and_escape() {
        let t = Tmp::new("filter");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let opts = follow_opts()
            .with_stream(StreamKind::Stderr)
            .with_escape(true);
        let o = follow_run(&t.0, opts, &mut |r| {
            if r == 0 {
                append(&dir, "c1.log", b"stderr b\x1b[1m\nstdout c\n");
            }
        });
        o.result.expect("ok");
        assert_eq!(o.out, b"stderr b^[[1m\n");
    }

    /// REPAIR-5: 世代数 1 は隙間とログ削除を区別できないため追従を拒否する。
    #[test]
    fn repair5_follow_rejects_single_generation() {
        let t = Tmp::new("gen1");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let cfg =
            RotationConfig::new(super::super::super::rotating::MIN_LOG_FILE_BYTES, 1).expect("cfg");
        let now = Cell::new(Duration::ZERO);
        let mut elapsed = || now.get();
        let mut sleep = |_: Duration| {};
        let mut activity = || ContainerActivity::Running;
        let mut driver = Driver {
            elapsed: &mut elapsed,
            sleep: &mut sleep,
            activity: &mut activity,
        };
        let mut out = Vec::new();
        let r = read_with(
            &t.0,
            &ContainerId::new("c1").expect("id"),
            cfg,
            &follow_opts(),
            &mut out,
            &mut |_| {},
            &mut driver,
        );
        assert!(matches!(
            r,
            Err(LogReadFailure::Source(ref e)) if e.code() == ErrorCode::Unavailable
        ));
    }

    use crate::logs::{LogSink, RotatingFileSink};

    fn cid() -> ContainerId {
        ContainerId::new("c1").expect("id")
    }

    /// CLI-1: sink が生きている間は、状態が NotRunning でも終わらず期限まで続き、probe も呼ばれない。
    #[test]
    fn cli1_follow_continues_while_sink_alive() {
        let t = Tmp::new("alive");
        let sink = RotatingFileSink::open(&t.0, &cid(), RotationConfig::default()).expect("sink");
        sink.append(StreamKind::Stdout, b"a").expect("append");
        let calls = Cell::new(0u32);
        let o = follow_run_probe(&t.0, follow_opts(), &mut |_| {}, &mut || {
            calls.set(calls.get() + 1);
            ContainerActivity::NotRunning
        });
        o.result.expect("ok");
        assert_eq!(calls.get(), 0);
        assert_eq!(o.sleeps, 5);
        drop(sink);
    }

    /// CLI-1: sink の drop 後に NotRunning なら、未 flush だった行も出して期限より前に成功で終わる。
    #[test]
    fn cli1_follow_ends_after_sink_drop_and_not_running_with_final_flush() {
        let t = Tmp::new("stop");
        let sink = RotatingFileSink::open(&t.0, &cid(), RotationConfig::default()).expect("sink");
        sink.append(StreamKind::Stdout, b"a").expect("append");
        sink.flush().expect("flush");
        let mut sink = Some(sink);
        let o = follow_run_probe(
            &t.0,
            follow_opts(),
            &mut |r| {
                if r == 0 {
                    sink.as_ref()
                        .expect("sink")
                        .append(StreamKind::Stdout, b"b")
                        .expect("append");
                }
                if r == 1 {
                    drop(sink.take());
                }
            },
            &mut || ContainerActivity::NotRunning,
        );
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\n");
        assert!(o.sleeps < 5, "sleeps={}", o.sleeps);
    }

    /// CLI-1: sink がいなくても Running / Unknown の間は続く（restart の間・状態ストアの一時的な失敗）。
    #[test]
    fn cli1_follow_continues_when_running_or_unknown() {
        for act in [ContainerActivity::Running, ContainerActivity::Unknown] {
            let t = Tmp::new("cont");
            fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
            let o = follow_run_probe(&t.0, follow_opts(), &mut |_| {}, &mut || act);
            o.result.expect("ok");
            assert_eq!(o.sleeps, 5, "{act:?}");
        }
    }

    /// CLI-1: 停止の直前にローテーションがあっても、欠落・重複なく出し切る。
    #[test]
    fn cli1_follow_stop_after_rotation_no_loss_no_dup() {
        let t = Tmp::new("stoprot");
        fs::write(t.0.join("c1.log"), b"stdout a\n").expect("seed");
        let dir = t.0.clone();
        let stopped = Cell::new(false);
        let o = follow_run_probe(
            &t.0,
            follow_opts(),
            &mut |r| {
                if r == 0 {
                    append(&dir, "c1.log", b"stdout b\n");
                    rotate(&dir, Some(b"stdout c\n"));
                    stopped.set(true);
                }
            },
            &mut || {
                if stopped.get() {
                    ContainerActivity::NotRunning
                } else {
                    ContainerActivity::Running
                }
            },
        );
        o.result.expect("ok");
        assert_eq!(o.out, b"stdout a\nstdout b\nstdout c\n");
    }
}
