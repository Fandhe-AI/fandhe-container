//! `RotatingFileSink` のユニットテスト（SUP-7・TASK-164.2・#506）。root 不要・一時ディレクトリのみ。

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// 後始末つきの一時ディレクトリ（unix では 0700 にして check_dir を通す）。
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-sup7-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(p)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id() -> ContainerId {
    ContainerId::new("c1").unwrap()
}

fn small() -> RotationConfig {
    RotationConfig::new(MIN_LOG_FILE_BYTES, 3).unwrap()
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        // 排他ロック用の空ファイル（`<id>.log.lock`）はログ世代ではないため除く。
        .filter(|n| !n.ends_with(".lock"))
        .collect();
    v.sort();
    v
}

#[test]
fn sup7_task164_2_config_bounds() {
    assert!(RotationConfig::new(MIN_LOG_FILE_BYTES - 1, 3).is_err());
    assert!(RotationConfig::new(MAX_LOG_FILE_BYTES + 1, 3).is_err());
    assert!(RotationConfig::new(MIN_LOG_FILE_BYTES, 0).is_err());
    assert!(RotationConfig::new(MIN_LOG_FILE_BYTES, MAX_LOG_GENERATIONS + 1).is_err());
    let e = RotationConfig::new(MIN_LOG_FILE_BYTES, 0).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(RotationConfig::new(MIN_LOG_FILE_BYTES, 1).is_ok());
    assert!(RotationConfig::new(MAX_LOG_FILE_BYTES, MAX_LOG_GENERATIONS).is_ok());
    let d = RotationConfig::default();
    assert_eq!(d.max_file_bytes(), 1024 * 1024);
    assert_eq!(d.generations(), 3);
    assert_eq!(MIN_LOG_FILE_BYTES, 65_544);
}

#[test]
fn sup7_task164_2_record_format_and_byte_exactness() {
    let t = TmpDir::new("fmt");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"hello").unwrap();
    s.append(StreamKind::Stderr, b"").unwrap();
    s.append(StreamKind::Stdout, b"\xff\xfe\r").unwrap();
    s.flush().unwrap();
    let got = fs::read(t.0.join("c1.log")).unwrap();
    assert_eq!(got, b"stdout hello\nstderr \nstdout \xff\xfe\r\n");
}

#[test]
fn sup7_task164_2_oversized_line_is_truncated() {
    let t = TmpDir::new("trunc");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stderr, &vec![b'x'; MAX_LINE_BYTES + 100])
        .unwrap();
    let len = fs::metadata(t.0.join("c1.log")).unwrap().len();
    assert_eq!(len, MIN_LOG_FILE_BYTES);
}

/// 受け入れ条件: 世代切り替えのたびに全ファイルが上限以内。
#[test]
fn sup7_task164_2_files_never_exceed_limit_across_rotations() {
    let t = TmpDir::new("limit");
    let cfg = small();
    let s = RotatingFileSink::open(&t.0, &id(), cfg).unwrap();
    // 1 レコード 1000 バイト（"stdout " 7 + 992 + LF 1）。
    let line = vec![b'a'; 992];
    for _ in 0..400 {
        s.append(StreamKind::Stdout, &line).unwrap();
        for f in files(&t.0) {
            let len = fs::metadata(t.0.join(&f)).unwrap().len();
            assert!(len <= cfg.max_file_bytes(), "{f} has {len} bytes");
        }
    }
    assert_eq!(s.rotations().unwrap(), 6);
    assert_eq!(files(&t.0), ["c1.log", "c1.log.1", "c1.log.2"]);
}

/// 残り容量とレコード長がちょうど一致する場合は回さず、1 バイト超えると回す。
#[test]
fn sup7_task164_2_exact_fit_does_not_rotate_but_one_more_byte_does() {
    let t = TmpDir::new("exact");
    let cfg = small();
    let s = RotatingFileSink::open(&t.0, &id(), cfg).unwrap();
    s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
        .unwrap();
    assert_eq!(s.rotations().unwrap(), 0);
    assert_eq!(
        fs::metadata(t.0.join("c1.log")).unwrap().len(),
        cfg.max_file_bytes()
    );
    s.append(StreamKind::Stdout, b"").unwrap();
    assert_eq!(s.rotations().unwrap(), 1);
    s.flush().unwrap();
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout \n");
    assert_eq!(
        fs::metadata(t.0.join("c1.log.1")).unwrap().len(),
        cfg.max_file_bytes()
    );
}

#[test]
fn sup7_task164_2_concatenation_has_no_loss_or_duplication_within_retention() {
    let t = TmpDir::new("concat");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    let pad = "p".repeat(30_000);
    let total = 10;
    for i in 0..total {
        s.append(StreamKind::Stdout, format!("{i:03}{pad}").as_bytes())
            .unwrap();
    }
    let mut all = Vec::new();
    for f in ["c1.log.2", "c1.log.1", "c1.log"] {
        if let Ok(b) = fs::read(t.0.join(f)) {
            assert_eq!(b.last().copied(), Some(b'\n'));
            all.extend(b);
        }
    }
    let nums: Vec<u32> = all
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            std::str::from_utf8(l.get(7..10).unwrap())
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    // 古い世代が消えるので連続した末尾の範囲になる（欠落・重複なし）。
    let first = *nums.first().unwrap();
    let expect: Vec<u32> = (first..total).collect();
    assert_eq!(nums, expect);
    assert!(first > 0);
}

#[test]
fn sup7_task164_2_single_generation_keeps_no_history() {
    let t = TmpDir::new("gen1");
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 1).unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), cfg).unwrap();
    for _ in 0..5 {
        s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
            .unwrap();
    }
    assert_eq!(files(&t.0), ["c1.log"]);
    assert_eq!(s.rotations().unwrap(), 4);
}

#[test]
fn sup7_task164_2_open_moves_existing_log_to_generation_one() {
    let t = TmpDir::new("reopen");
    fs::write(t.0.join("c1.log"), b"old\n").unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    assert_eq!(fs::read(t.0.join("c1.log.1")).unwrap(), b"old\n");
    assert_eq!(fs::metadata(t.0.join("c1.log")).unwrap().len(), 0);
    assert_eq!(s.rotations().unwrap(), 0);
}

#[test]
fn sup7_task164_2_open_rejects_missing_or_non_directory() {
    let t = TmpDir::new("baddir");
    let e = RotatingFileSink::open(&t.0.join("nope"), &id(), small())
        .err()
        .unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    fs::write(t.0.join("f"), b"").unwrap();
    let e = RotatingFileSink::open(&t.0.join("f"), &id(), small())
        .err()
        .unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

/// 現在ログ・世代が symlink なら、リンクも参照先も変更せずに拒否する（参照先への追記・サイズ上限の
/// すり抜けを防ぐ）。
#[cfg(unix)]
#[test]
fn sup7_task164_2_open_rejects_symlink_logs_without_touching_target() {
    for name in ["c1.log", "c1.log.1"] {
        let t = TmpDir::new("symlink");
        let target = t.0.join("target");
        fs::write(&target, b"keep\n").unwrap();
        std::os::unix::fs::symlink(&target, t.0.join(name)).unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{name}");
        assert_eq!(fs::read(&target).unwrap(), b"keep\n");
        assert_eq!(fs::read_link(t.0.join(name)).unwrap(), target);
        assert_eq!(files(&t.0), [name, "target"]);
    }
}

/// open 後に現在ログが symlink へ差し替えられても、ローテーションはリンクを動かすだけで参照先へ書かない
/// （現在ログは create_new でしか開かない）。
#[cfg(unix)]
#[test]
fn sup7_task164_2_rotation_does_not_write_through_swapped_symlink() {
    let t = TmpDir::new("swap");
    let target = t.0.join("target");
    fs::write(&target, b"keep\n").unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
        .unwrap();
    fs::remove_file(t.0.join("c1.log")).unwrap();
    std::os::unix::fs::symlink(&target, t.0.join("c1.log")).unwrap();
    s.append(StreamKind::Stdout, b"x").unwrap();
    s.flush().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"keep\n");
    assert_eq!(fs::read_link(t.0.join("c1.log.1")).unwrap(), target);
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout x\n");
}

#[cfg(unix)]
#[test]
fn sup7_task164_2_open_rejects_symlink_dir_and_writable_dir_and_sets_0600() {
    use std::os::unix::fs::PermissionsExt;
    let t = TmpDir::new("perm");
    let real = t.0.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = t.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let e = RotatingFileSink::open(&link, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);

    fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).unwrap();
    let e = RotatingFileSink::open(&real, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::PermissionDenied);

    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    RotatingFileSink::open(&real, &id(), small()).unwrap();
    let mode = fs::metadata(real.join("c1.log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn sup7_task164_2_rotation_failure_fixes_sink_in_failed_state() {
    let t = TmpDir::new("fail");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    // 世代 1 を通常ファイル、その宛先の世代 2 を空でないディレクトリにして rename を失敗させる。
    fs::write(t.0.join("c1.log.1"), b"g1").unwrap();
    let blocker = t.0.join("c1.log.2");
    fs::create_dir(&blocker).unwrap();
    fs::write(blocker.join("x"), b"").unwrap();
    s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
        .unwrap();
    let e = s.append(StreamKind::Stdout, b"next").unwrap_err();
    assert_eq!(e.code(), ErrorCode::Internal);
    let msg = e.to_string();
    assert!(!msg.contains("c1") && !msg.contains("next"), "{msg}");
    let e2 = s.append(StreamKind::Stderr, b"other").unwrap_err();
    assert_eq!(e2.code(), ErrorCode::Internal);
}

#[test]
fn sup7_task164_2_concurrent_appends_keep_records_whole() {
    let t = TmpDir::new("conc");
    let s = Arc::new(RotatingFileSink::open(&t.0, &id(), small()).unwrap());
    let mut hs = Vec::new();
    for kind in [StreamKind::Stdout, StreamKind::Stderr] {
        let s = Arc::clone(&s);
        hs.push(std::thread::spawn(move || {
            for i in 0..500 {
                s.append(kind, format!("line-{i}").as_bytes()).unwrap();
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    s.flush().unwrap();
    let b = fs::read(t.0.join("c1.log")).unwrap();
    let lines: Vec<&[u8]> = b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1000);
    for l in lines {
        let s = std::str::from_utf8(l).unwrap();
        assert!(
            s.starts_with("stdout line-") || s.starts_with("stderr line-"),
            "{s}"
        );
    }
}

#[test]
fn sup7_task164_2_open_rejects_oversized_existing_files() {
    let t = TmpDir::new("oversize");
    let big = vec![b'x'; (MIN_LOG_FILE_BYTES + 1) as usize];
    fs::write(t.0.join("c1.log.1"), &big).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    // 何も動かしていない。
    assert_eq!(files(&t.0), vec!["c1.log.1".to_string()]);
    // 現在ログが超過している場合も同様。
    fs::remove_file(t.0.join("c1.log.1")).unwrap();
    fs::write(t.0.join("c1.log"), &big).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(files(&t.0), vec!["c1.log".to_string()]);
}

#[test]
fn sup7_task164_2_open_rejects_directory_generations_without_changes() {
    for name in ["c1.log.1", "c1.log"] {
        let t = TmpDir::new("dirgen");
        fs::create_dir(t.0.join(name)).unwrap();
        fs::write(t.0.join(name).join("data"), b"payload").unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        // 何も動かしていない（ディレクトリも中身もそのまま）。
        assert_eq!(files(&t.0), vec![name.to_string()]);
        assert_eq!(fs::read(t.0.join(name).join("data")).unwrap(), b"payload");
    }
}

#[test]
fn sup7_task164_2_open_accepts_existing_files_within_limit() {
    let t = TmpDir::new("withinlimit");
    fs::write(t.0.join("c1.log"), vec![b'x'; MIN_LOG_FILE_BYTES as usize]).unwrap();
    RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    assert_eq!(
        files(&t.0),
        vec!["c1.log".to_string(), "c1.log.1".to_string()]
    );
}

#[test]
fn sup7_task164_2_open_rejects_names_exceeding_name_max() {
    let t = TmpDir::new("namemax");
    // ".log"(4) + ".lock"(5) 付与で 255 を超える長さ（247 + 9 = 256）。
    let long = ContainerId::new("a".repeat(247)).unwrap();
    let e = RotatingFileSink::open(&t.0, &long, small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(files(&t.0).is_empty());
    // ロックファイル名も含めて 255 バイトに収まる長さ（246 + 9 = 255）は受理する。
    let fit = ContainerId::new("a".repeat(246)).unwrap();
    RotatingFileSink::open(&t.0, &fit, small()).unwrap();
    let one = RotationConfig::new(MIN_LOG_FILE_BYTES, 1).unwrap();
    // 255 バイト ID は世代数 1 でも ".log" 付与で超えるため拒否。
    let max = ContainerId::new("b".repeat(255)).unwrap();
    assert!(RotatingFileSink::open(&t.0, &max, one).is_err());
}

/// 世代数を減らして開き直したとき、範囲外の旧世代が残るなら拒否する（上限契約。何も動かさない）。
#[test]
fn sup7_task164_2_open_rejects_stale_generations_after_reducing_count() {
    let t = TmpDir::new("stale");
    {
        let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 3).unwrap();
        let s = RotatingFileSink::open(&t.0, &id(), cfg).unwrap();
        for _ in 0..3 {
            s.append(StreamKind::Stdout, b"x").unwrap();
        }
    }
    fs::write(t.0.join("c1.log.1"), b"a").unwrap();
    fs::write(t.0.join("c1.log.2"), b"b").unwrap();
    let before = files(&t.0);
    let one = RotationConfig::new(MIN_LOG_FILE_BYTES, 1).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), one).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(files(&t.0), before);
    // 2 世代でも c1.log.2 が範囲外なので拒否する。
    let two = RotationConfig::new(MIN_LOG_FILE_BYTES, 2).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), two).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    // 元の 3 世代なら開ける。
    let three = RotationConfig::new(MIN_LOG_FILE_BYTES, 3).unwrap();
    assert!(RotatingFileSink::open(&t.0, &id(), three).is_ok());
}

/// 番号上限（MAX_LOG_GENERATIONS）以上・桁あふれの旧世代も見逃さず拒否し、無関係なファイルは無視する。
#[test]
fn sup7_task164_2_open_rejects_stale_generations_at_or_above_max() {
    for stale in ["c1.log.16", "c1.log.17", "c1.log.99999999999999999999999"] {
        let t = TmpDir::new("stale-hi");
        fs::write(t.0.join(stale), b"old").unwrap();
        let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 16).unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), cfg).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{stale}");
    }
    // 名前空間（`c1.log`・`c1.log.lock`・`c1.log.<数字>`）の外の名前は無視する。`c1.log.log*` は
    // ID `c1.log` の sink の名前で、`c1.log.15` は 16 世代の範囲内。
    let t = TmpDir::new("stale-other");
    let others = [
        "c1.log.x",
        "c1.log.1x",
        "c1.log.-1",
        "c1.log.1.bak",
        "c1.log.log",
        "c1.log.log.20",
        "c1.log.log.lock",
        "c2.log.20",
        "c1.log.15",
    ];
    for other in others {
        fs::write(t.0.join(other), b"o").unwrap();
    }
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 16).unwrap();
    assert!(RotatingFileSink::open(&t.0, &id(), cfg).is_ok());
    // `files` はロックファイル（`.lock`）を除いて返す。
    let mut expect: Vec<&str> = others.to_vec();
    expect.retain(|n| !n.ends_with(".lock"));
    expect.push("c1.log");
    expect.sort_unstable();
    assert_eq!(files(&t.0), expect);
}

/// SUP-7: `.` を含む ID（`c1` と `c1.log`）は名前空間が重ならず、同じディレクトリで互いの世代を
/// 旧世代と誤認せずにローテーションできる。
#[test]
fn sup7_task164_2_dotted_sibling_ids_do_not_share_namespace() {
    let t = TmpDir::new("sibling");
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 2).unwrap();
    let sibling = ContainerId::new("c1.log").unwrap();
    for round in 0..3 {
        let a = RotatingFileSink::open(&t.0, &id(), cfg).unwrap();
        let b = RotatingFileSink::open(&t.0, &sibling, cfg).unwrap();
        for s in [&a, &b] {
            s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
                .unwrap();
            s.append(StreamKind::Stdout, b"x").unwrap();
            assert_eq!(s.rotations().unwrap(), 1, "round {round}");
        }
    }
    assert_eq!(
        files(&t.0),
        ["c1.log", "c1.log.1", "c1.log.log", "c1.log.log.1"]
    );
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout x\n");
    assert_eq!(fs::read(t.0.join("c1.log.log")).unwrap(), b"stdout x\n");
}

/// SUP-7: 世代番号 0・先頭 0 つきの番号は、ローテーションが送らないまま残って上限
/// `max_file_bytes × generations` を破るため、世代数によらず拒否する（何も動かさない）。
#[test]
fn sup7_task164_2_open_rejects_zero_and_non_canonical_generation_numbers() {
    for bad in ["c1.log.0", "c1.log.00", "c1.log.01", "c1.log.002"] {
        for generations in [1, 3, 16] {
            let t = TmpDir::new("gen-zero");
            fs::write(t.0.join(bad), b"old").unwrap();
            let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, generations).unwrap();
            let e = RotatingFileSink::open(&t.0, &id(), cfg).err().unwrap();
            assert_eq!(
                e.code(),
                ErrorCode::InvalidArgument,
                "{bad} / {generations}"
            );
            assert_eq!(files(&t.0), [bad]);
            assert_eq!(fs::read(t.0.join(bad)).unwrap(), b"old");
        }
    }
}

/// SUP-7・IO-5: ASCII の大文字小文字だけが違う名前は、大文字小文字非区別 FS では sink のファイルと同じ
/// 実体を指す（区別する FS ではローテーションが送らない余分なファイルになる）ため拒否する。
#[test]
fn sup7_task164_2_open_rejects_case_variant_names_in_namespace() {
    for bad in ["C1.log", "c1.LOG.1", "C1.LOG.7", "c1.log.LOCK"] {
        let t = TmpDir::new("case-variant");
        fs::write(t.0.join(bad), b"old").unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        match fs::read(t.0.join(bad)) {
            Ok(bytes) => assert_eq!(bytes, b"old", "{bad}"),
            // 大文字小文字非区別 FS では `c1.log.LOCK` が sink 自身のロックファイルと同じ実体になり、
            // open 失敗時のロックファイル掃除で消える（SUP-7・#1469）。他の名前は必ず残る。
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{bad}");
                assert_eq!(bad, "c1.log.LOCK");
            }
        }
    }
}

/// SUP-7: 既存の現在ログが空なら世代を消費しない（出力の無い開き直しで保持中の世代を押し出さない）。
#[test]
fn sup7_task164_2_reopen_with_empty_current_log_keeps_generations() {
    let t = TmpDir::new("empty-reopen");
    fs::write(t.0.join("c1.log.1"), b"g1\n").unwrap();
    fs::write(t.0.join("c1.log.2"), b"g2\n").unwrap();
    for _ in 0..4 {
        let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
        assert_eq!(s.rotations().unwrap(), 0);
    }
    assert_eq!(files(&t.0), ["c1.log", "c1.log.1", "c1.log.2"]);
    assert_eq!(fs::read(t.0.join("c1.log.1")).unwrap(), b"g1\n");
    assert_eq!(fs::read(t.0.join("c1.log.2")).unwrap(), b"g2\n");
    // 1 行でも書いてあれば、次の open で世代 1 へ送る。
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"new").unwrap();
    drop(s);
    RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"");
    assert_eq!(fs::read(t.0.join("c1.log.1")).unwrap(), b"stdout new\n");
    assert_eq!(fs::read(t.0.join("c1.log.2")).unwrap(), b"g1\n");
}

/// 親要素が symlink の経路は、リンク先が正当なディレクトリでも拒否する（状態ルート外への逸脱防止）。
#[cfg(unix)]
#[test]
fn sup7_task164_2_open_rejects_symlinked_parent_component() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let t = TmpDir::new("parent-link");
    let real = t.0.join("real");
    fs::create_dir(&real).unwrap();
    let sub = real.join("logs");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
    let link = t.0.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // root 所有のリンクは OS 標準として許容する仕様のため、root 実行時は拒否検証の対象外。
    if fs::symlink_metadata(&link).unwrap().uid() != 0 {
        let e = RotatingFileSink::open(&link.join("logs"), &id(), small())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(!sub.join("c1.log").exists());
    }
    // 末尾の区切り文字つきの symlink（lstat が辿る）も、最終要素の symlink として拒否する。
    let leaf = t.0.join("leaf");
    std::os::unix::fs::symlink(&sub, &leaf).unwrap();
    for tail in ["/", "/.", "//"] {
        let mut p = leaf.clone().into_os_string();
        p.push(tail);
        let e = RotatingFileSink::open(Path::new(&p), &id(), small())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{tail}");
    }
    assert!(!sub.join("c1.log").exists());
    assert!(!sub.join("c1.log.lock").exists());
    // `..` 要素は拒否する。
    let dotdot = real.join("..").join("real").join("logs");
    let e = RotatingFileSink::open(&dotdot, &id(), small())
        .err()
        .unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    // 実体パスなら開ける。
    assert!(RotatingFileSink::open(&sub, &id(), small()).is_ok());
}

/// 大文字小文字だけが異なる ID でも、ファイル名が小文字のみへ可逆変換され衝突しない（IO-5。
/// 大文字小文字非区別 FS を想定）。
#[test]
fn sup7_task164_2_case_only_different_ids_do_not_collide() {
    let t = TmpDir::new("case");
    let upper = ContainerId::new("A").unwrap();
    let lower = ContainerId::new("a").unwrap();
    let under = ContainerId::new("_a").unwrap();
    let sa = RotatingFileSink::open(&t.0, &upper, small()).unwrap();
    sa.append(StreamKind::Stdout, b"upper").unwrap();
    let sb = RotatingFileSink::open(&t.0, &lower, small()).unwrap();
    sb.append(StreamKind::Stdout, b"lower").unwrap();
    let sc = RotatingFileSink::open(&t.0, &under, small()).unwrap();
    sc.append(StreamKind::Stdout, b"under").unwrap();
    for sink in [&sa, &sb, &sc] {
        sink.flush().unwrap();
    }
    // 世代へ退避されたファイルはなく、全ファイル名が小文字のみ。
    assert_eq!(files(&t.0), ["__a.log", "_a.log", "a.log"]);
    assert!(fs::read(t.0.join("_a.log")).unwrap().ends_with(b"upper\n"));
    assert!(fs::read(t.0.join("a.log")).unwrap().ends_with(b"lower\n"));
    assert!(fs::read(t.0.join("__a.log")).unwrap().ends_with(b"under\n"));
}

#[test]
fn sup7_task164_2_second_open_of_same_id_is_rejected_without_moving_files() {
    let d = TmpDir::new("lock");
    let first = RotatingFileSink::open(&d.0, &id(), small()).unwrap();
    first.append(StreamKind::Stdout, b"keep").unwrap();
    let err = RotatingFileSink::open(&d.0, &id(), small())
        .err()
        .expect("second open must be rejected");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    // 使用中のログは退避されず、先の sink はそのまま現在ログへ書ける。
    assert_eq!(files(&d.0), vec!["c1.log"]);
    first.append(StreamKind::Stdout, b"more").unwrap();
    first.flush().unwrap();
    assert_eq!(
        fs::read(d.0.join("c1.log")).unwrap(),
        b"stdout keep\nstdout more\n"
    );
    // 別 ID は同じディレクトリで同時に開ける。
    let other = ContainerId::new("c2").unwrap();
    assert!(RotatingFileSink::open(&d.0, &other, small()).is_ok());
    // 解放後は開き直せる（open 時の退避で 1 世代進む）。
    drop(first);
    assert!(RotatingFileSink::open(&d.0, &id(), small()).is_ok());
    assert_eq!(files(&d.0), vec!["c1.log", "c1.log.1", "c2.log"]);
}

#[test]
fn sup7_task164_2_append_rejects_line_feed_without_failing_sink() {
    let d = TmpDir::new("lf");
    let sink = RotatingFileSink::open(&d.0, &id(), small()).unwrap();
    let err = sink.append(StreamKind::Stdout, b"a\nb").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    // 拒否は sink を失敗状態にせず、何も書かない。
    sink.append(StreamKind::Stderr, b"ok").unwrap();
    sink.flush().unwrap();
    assert_eq!(fs::read(d.0.join("c1.log")).unwrap(), b"stderr ok\n");
}

/// SUP-7: 切り詰めで捨てる範囲（MAX_LINE_BYTES より後ろ）の LF は記録されないので拒否しない。
/// 記録する範囲の LF は末尾 1 バイトでも拒否する。
#[test]
fn sup7_task164_2_line_feed_is_checked_on_the_truncated_range() {
    let d = TmpDir::new("lf-trunc");
    let sink = RotatingFileSink::open(&d.0, &id(), small()).unwrap();
    let mut beyond = vec![b'x'; MAX_LINE_BYTES + 10];
    *beyond.get_mut(MAX_LINE_BYTES).unwrap() = b'\n';
    *beyond.last_mut().unwrap() = b'\n';
    sink.append(StreamKind::Stdout, &beyond).unwrap();
    let got = fs::read(d.0.join("c1.log")).unwrap();
    let mut expect = b"stdout ".to_vec();
    expect.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES));
    expect.push(b'\n');
    assert_eq!(got, expect);

    let mut inside = vec![b'x'; MAX_LINE_BYTES + 10];
    *inside.get_mut(MAX_LINE_BYTES - 1).unwrap() = b'\n';
    let err = sink.append(StreamKind::Stdout, &inside).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    // 拒否では何も書かず、ローテーションもしない。
    assert_eq!(fs::read(d.0.join("c1.log")).unwrap(), expect);
    assert_eq!(sink.rotations().unwrap(), 0);
}

/// SUP-7: stream 名 + 区切りは MAX_TAG_BYTES 以内（MIN_LOG_FILE_BYTES が最大 1 レコード長である前提）。
#[test]
fn sup7_task164_2_stream_tags_fit_in_max_tag_bytes() {
    assert_eq!(StreamKind::Stdout.as_str(), "stdout");
    assert_eq!(StreamKind::Stderr.as_str(), "stderr");
    for kind in [StreamKind::Stdout, StreamKind::Stderr] {
        assert_eq!(kind.as_str().len() + 1, MAX_TAG_BYTES);
    }
}

/// SUP-7: ロックファイルは空の通常ファイル（unix は 0600）で、sink を閉じても残る。
#[test]
fn sup7_task164_2_lock_file_is_empty_regular_file() {
    let d = TmpDir::new("lockfile");
    let sink = RotatingFileSink::open(&d.0, &id(), small()).unwrap();
    sink.append(StreamKind::Stdout, b"x").unwrap();
    drop(sink);
    let m = fs::symlink_metadata(d.0.join("c1.log.lock")).unwrap();
    assert!(m.file_type().is_file());
    assert_eq!(m.len(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }
    let mut all: Vec<String> = fs::read_dir(&d.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    all.sort();
    assert_eq!(all, ["c1.log", "c1.log.lock"]);
}

/// SUP-7: ロックファイルの位置にある symlink・ディレクトリは辿らず拒否し、参照先もログも変更しない。
#[test]
fn sup7_task164_2_open_rejects_non_regular_lock_path() {
    let d = TmpDir::new("lock-dir");
    fs::create_dir(d.0.join("c1.log.lock")).unwrap();
    fs::write(d.0.join("c1.log"), b"old\n").unwrap();
    let e = RotatingFileSink::open(&d.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(fs::read(d.0.join("c1.log")).unwrap(), b"old\n");
    assert!(!d.0.join("c1.log.1").exists());

    #[cfg(unix)]
    {
        let d = TmpDir::new("lock-link");
        let target = d.0.join("target");
        fs::write(&target, b"keep\n").unwrap();
        std::os::unix::fs::symlink(&target, d.0.join("c1.log.lock")).unwrap();
        fs::write(d.0.join("c1.log"), b"old\n").unwrap();
        let e = RotatingFileSink::open(&d.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(fs::read(&target).unwrap(), b"keep\n");
        assert_eq!(fs::read(d.0.join("c1.log")).unwrap(), b"old\n");
        assert!(!d.0.join("c1.log.1").exists());
    }
}

/// SUP-7: 相対パスの dir は拒否する（CWD より上の要素を検査できない）。
#[test]
fn sup7_task164_2_open_rejects_relative_dir() {
    for rel in ["logs", ".", "./logs"] {
        let e = RotatingFileSink::open(Path::new(rel), &id(), small())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{rel}");
        assert_eq!(e.message(), "log directory must be an absolute path");
    }
}

/// SUP-7: 末尾の区切り文字・`.` つきの実ディレクトリは、組み直した同じディレクトリとして開ける。
#[test]
fn sup7_task164_2_open_normalizes_trailing_separator() {
    let d = TmpDir::new("trail");
    let mut p = d.0.clone().into_os_string();
    p.push(std::path::MAIN_SEPARATOR_STR);
    p.push(".");
    p.push(std::path::MAIN_SEPARATOR_STR);
    let s = RotatingFileSink::open(Path::new(&p), &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"x").unwrap();
    s.flush().unwrap();
    assert_eq!(fs::read(d.0.join("c1.log")).unwrap(), b"stdout x\n");
}

/// IO-5: Windows の予約デバイス名で始まる ID は `_0` を前置した名前へ写し、他の ID の名前と衝突しない。
#[test]
fn sup7_task164_2_reserved_device_names_are_escaped() {
    let cases = [
        ("con", "_0con"),
        ("nul", "_0nul"),
        ("prn", "_0prn"),
        ("aux", "_0aux"),
        ("com1", "_0com1"),
        ("lpt0", "_0lpt0"),
        ("nul.v2", "_0nul.v2"),
        ("con-1", "con-1"),
        ("console", "console"),
        ("com10", "com10"),
        ("com", "com"),
        ("x.con", "x.con"),
        ("CON", "_c_o_n"),
        ("Nul", "_nul"),
        ("_0con", "__0con"),
        ("a_B.c", "a___b.c"),
    ];
    for (id, stem) in cases {
        assert_eq!(encode_file_stem(id), stem, "{id}");
    }
    let mut stems: Vec<&str> = cases.iter().map(|c| c.1).collect();
    stems.sort_unstable();
    stems.dedup();
    assert_eq!(stems.len(), cases.len());

    let d = TmpDir::new("reserved");
    let nul = ContainerId::new("nul").unwrap();
    let s = RotatingFileSink::open(&d.0, &nul, small()).unwrap();
    s.append(StreamKind::Stdout, b"x").unwrap();
    s.flush().unwrap();
    assert_eq!(files(&d.0), ["_0nul.log"]);
    assert_eq!(fs::read(d.0.join("_0nul.log")).unwrap(), b"stdout x\n");
}

// ---- TASK-164.3（#507・SUP-7）: バッファ・フラッシュ制御 ----

/// 連番つきの 992 バイトの行本体（レコードは `stdout ` + 行 + LF で 1000 バイトの固定長）。
fn numbered_line(i: usize) -> Vec<u8> {
    let mut l = format!("{i:06}").into_bytes();
    l.resize(992, b'p');
    l
}

/// 世代を渡した順に連結して連番（stream 名の後の 6 桁）の列を取り出す。各ファイルは LF で終わること。
fn seqs_in(dir: &Path, names: &[&str]) -> Vec<usize> {
    let mut out = Vec::new();
    for n in names {
        let Ok(b) = fs::read(dir.join(n)) else {
            continue;
        };
        assert_eq!(b.last().copied(), Some(b'\n'), "{n} ends mid-record");
        for rec in b.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
            assert_eq!(rec.len(), 999, "{n} has a torn record");
            let num = std::str::from_utf8(rec.get(7..13).unwrap()).unwrap();
            out.push(num.parse().unwrap());
        }
    }
    out
}

/// ローテーション境界を跨いでも、flush を呼ばずに旧世代が書き切られ、欠落・重複がない。
#[test]
fn sup7_task164_3_boundary_has_no_loss_or_duplication_without_explicit_flush() {
    let t = TmpDir::new("b164-3");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    // 1 レコード 1000 バイト。65 件で 65000 バイト、66 件目で上限（65544）を超えて回る。
    for i in 0..66 {
        s.append(StreamKind::Stdout, &numbered_line(i)).unwrap();
    }
    assert_eq!(s.rotations().unwrap(), 1);
    // flush していなくても退避済みの世代は完全（65 レコード = 65000 バイト）。
    assert_eq!(fs::metadata(t.0.join("c1.log.1")).unwrap().len(), 65_000);
    assert_eq!(
        seqs_in(&t.0, &["c1.log.1"]),
        (0..65).collect::<Vec<usize>>()
    );
    s.flush().unwrap();
    assert_eq!(
        seqs_in(&t.0, &["c1.log.2", "c1.log.1", "c1.log"]),
        (0..66).collect::<Vec<usize>>()
    );
    // 多数の境界を跨いでも同様（保持範囲内の連続した末尾）。
    for i in 66..400 {
        s.append(StreamKind::Stdout, &numbered_line(i)).unwrap();
    }
    s.flush().unwrap();
    let got = seqs_in(&t.0, &["c1.log.2", "c1.log.1", "c1.log"]);
    let first = got.first().copied().unwrap();
    assert_eq!(got, (first..400).collect::<Vec<usize>>());
    assert_eq!(s.rotations().unwrap(), 6);
}

/// stdout / stderr の 2 スレッドが境界を跨いで追記しても、ストリームごとに連番が欠落・重複しない。
#[test]
fn sup7_task164_3_concurrent_streams_across_boundaries() {
    let t = TmpDir::new("conc164-3");
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 16).unwrap();
    let s = Arc::new(RotatingFileSink::open(&t.0, &id(), cfg).unwrap());
    let mut hs = Vec::new();
    for kind in [StreamKind::Stdout, StreamKind::Stderr] {
        let s = Arc::clone(&s);
        hs.push(std::thread::spawn(move || {
            for i in 0..300 {
                s.append(kind, &numbered_line(i)).unwrap();
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    s.flush().unwrap();
    assert!(s.rotations().unwrap() >= 1);
    let mut names: Vec<String> = (1..16).rev().map(|n| format!("c1.log.{n}")).collect();
    names.push("c1.log".to_string());
    let mut per = [Vec::new(), Vec::new()];
    for n in &names {
        let Ok(b) = fs::read(t.0.join(n)) else {
            continue;
        };
        assert_eq!(b.last().copied(), Some(b'\n'));
        for rec in b.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
            let idx = usize::from(rec.starts_with(b"stderr "));
            let num: usize = std::str::from_utf8(rec.get(7..13).unwrap())
                .unwrap()
                .parse()
                .unwrap();
            per[idx].push(num);
        }
    }
    for seq in per {
        assert_eq!(seq, (0..300).collect::<Vec<usize>>());
    }
}

/// バッファ中は未書き出しで、flush で書き出される。
#[test]
fn sup7_task164_3_small_append_is_buffered_until_flush() {
    let t = TmpDir::new("buf164-3");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"hi").unwrap();
    assert_eq!(fs::metadata(t.0.join("c1.log")).unwrap().len(), 0);
    s.flush().unwrap();
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout hi\n");
}

/// flush せずに drop しても、バッファ内のレコードは書き出される。
#[test]
fn sup7_task164_3_drop_writes_buffered_records() {
    let t = TmpDir::new("drop164-3");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"one").unwrap();
    s.append(StreamKind::Stderr, b"two").unwrap();
    drop(s);
    assert_eq!(
        fs::read(t.0.join("c1.log")).unwrap(),
        b"stdout one\nstderr two\n"
    );
}

/// `sync` はバッファを書き出す。
#[test]
fn sup7_task164_3_sync_makes_content_visible() {
    let t = TmpDir::new("sync164-3");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"durable").unwrap();
    s.sync().unwrap();
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout durable\n");
}

/// 失敗状態の sink では flush / sync も `Internal`（固定文言）。
#[test]
fn sup7_task164_3_flush_and_sync_fail_in_failed_state() {
    let t = TmpDir::new("failed164-3");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    fs::write(t.0.join("c1.log.1"), b"g1").unwrap();
    let blocker = t.0.join("c1.log.2");
    fs::create_dir(&blocker).unwrap();
    fs::write(blocker.join("x"), b"").unwrap();
    s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
        .unwrap();
    assert!(s.append(StreamKind::Stdout, b"next").is_err());
    for e in [s.flush().unwrap_err(), s.sync().unwrap_err()] {
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(!e.to_string().contains("c1"), "{e}");
    }
}

/// 世代番号に抜けがある状態（中断されたローテーションの名残）から開き直しても、重複しない。
#[test]
fn sup7_task164_3_reopen_after_gap_in_generations_has_no_duplication() {
    let t = TmpDir::new("gap164-3");
    fs::write(t.0.join("c1.log"), b"stdout cur\n").unwrap();
    fs::write(t.0.join("c1.log.2"), b"stdout old\n").unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"new").unwrap();
    s.flush().unwrap();
    let mut all = Vec::new();
    for n in ["c1.log.2", "c1.log.1", "c1.log"] {
        if let Ok(b) = fs::read(t.0.join(n)) {
            all.extend(b);
        }
    }
    assert_eq!(all, b"stdout old\nstdout cur\nstdout new\n");
}

// ---- TASK-164 追補（#1470）: Windows のログローテーション失敗時の扱いとロック検査 ----

/// IO-5: 畳み込みで ASCII へ写る非 ASCII 文字だけを写し、それ以外はそのまま返す（FS 非依存・全 OS）。
#[test]
fn sup7_io5_task164_fold_for_alias_values() {
    assert_eq!(fold_for_alias("C1.LOG"), "c1.log");
    assert_eq!(fold_for_alias("c1.lo\u{212A}"), "c1.lok");
    assert_eq!(fold_for_alias("c1.log.\u{017F}"), "c1.log.s");
    assert_eq!(fold_for_alias("\u{0131}\u{0130}"), "ii");
    assert_eq!(fold_for_alias("ログ.txt"), "ログ.txt");
}

/// IO-5: Unicode の畳み込みで名前空間に入る別名は拒否し、既存ファイルは動かさない。
#[test]
fn sup7_io5_task164_open_rejects_unicode_case_fold_aliases() {
    // ID `c1k` の base `c1k.log` に対し、K を U+212A にした別名・ロック名・世代名の別名。
    let kid = ContainerId::new("c1k").unwrap();
    for alias in ["c1\u{212A}.log", "c1k.log.loc\u{212A}", "c1k.log.\u{0131}"] {
        let t = TmpDir::new("fold");
        fs::write(t.0.join(alias), b"user").unwrap();
        fs::write(t.0.join("c1k.log"), b"old\n").unwrap();
        let r = RotatingFileSink::open(&t.0, &kid, small());
        // `c1k.log.\u{0131}` は数字ではないので名前空間に入らない（受理される）。他 2 件は拒否される。
        if alias.ends_with('\u{0131}') {
            assert!(r.is_ok(), "{alias}");
            continue;
        }
        let e = r.err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{alias}");
        assert_eq!(fs::read(t.0.join("c1k.log")).unwrap(), b"old\n");
        assert!(!t.0.join("c1k.log.1").exists());
    }
}

/// IO-5: 名前空間に入らない非 ASCII 名は無視され、open は成功する。
#[test]
fn sup7_io5_task164_open_ignores_unrelated_non_ascii_names() {
    let t = TmpDir::new("fold-ok");
    fs::write(t.0.join("ログ.txt"), b"user").unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    drop(s);
    assert_eq!(fs::read(t.0.join("ログ.txt")).unwrap(), b"user");
}

/// SUP-7: 再試行は一過性の失敗だけで、予算内なら成功し、回数は具体値で一致する。
#[test]
fn sup7_task164_retry_transient_succeeds_within_budget() {
    use std::cell::Cell;
    let calls = Cell::new(0u32);
    let sleeps = Cell::new(0u32);
    let mut left = 4;
    let r = retry_transient(
        || {
            calls.set(calls.get() + 1);
            if calls.get() <= 3 {
                Err(io::Error::from(ErrorKind::WouldBlock))
            } else {
                Ok(7u8)
            }
        },
        |e| e.kind() == ErrorKind::WouldBlock,
        &mut left,
        || sleeps.set(sleeps.get() + 1),
    );
    assert_eq!(r.unwrap(), 7);
    assert_eq!((calls.get(), sleeps.get(), left), (4, 3, 1));
}

/// SUP-7・REPAIR-5: 予算が尽きたら最後のエラーを返し、待ちは予算分だけ。非一過性は即失敗で待たない。
#[test]
fn sup7_task164_retry_transient_is_bounded_and_skips_permanent_errors() {
    use std::cell::Cell;
    let calls = Cell::new(0u32);
    let sleeps = Cell::new(0u32);
    let mut left = 4;
    let r: io::Result<()> = retry_transient(
        || {
            calls.set(calls.get() + 1);
            Err(io::Error::from(ErrorKind::WouldBlock))
        },
        |_| true,
        &mut left,
        || sleeps.set(sleeps.get() + 1),
    );
    assert_eq!(r.unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!((calls.get(), sleeps.get(), left), (5, 4, 0));

    let calls = Cell::new(0u32);
    let sleeps = Cell::new(0u32);
    let mut left = 4;
    let r: io::Result<()> = retry_transient(
        || {
            calls.set(calls.get() + 1);
            Err(io::Error::from(ErrorKind::PermissionDenied))
        },
        |_| false,
        &mut left,
        || sleeps.set(sleeps.get() + 1),
    );
    assert_eq!(r.unwrap_err().kind(), ErrorKind::PermissionDenied);
    assert_eq!((calls.get(), sleeps.get(), left), (1, 0, 4));
}

/// SUP-7: 総待ち時間（既定の再試行方針）は logs の最小の待ち上限 100ms を十分下回る。
#[test]
fn sup7_task164_default_retry_budget_is_under_cancel_settle() {
    let total = RenameRetry::DEFAULT.interval * RenameRetry::DEFAULT.max_sleeps;
    assert_eq!(total, Duration::from_millis(40));
}

/// SUP-7・IO-5: 読み出し入口は通常ファイルを読め、ディレクトリ・不在は拒否する。
#[test]
fn sup7_task164_open_for_read_reads_regular_and_rejects_others() {
    use std::io::Read;
    let t = TmpDir::new("ofr");
    fs::write(t.0.join("a.log"), b"hello\n").unwrap();
    let mut buf = String::new();
    open_for_read(&t.0.join("a.log"))
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();
    assert_eq!(buf, "hello\n");
    fs::create_dir(t.0.join("d")).unwrap();
    assert_eq!(
        open_for_read(&t.0.join("d")).err().unwrap().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        open_for_read(&t.0.join("missing")).err().unwrap().code(),
        ErrorCode::NotFound
    );
}

#[cfg(unix)]
#[test]
fn sup7_task164_open_for_read_rejects_symlink_without_reading_target() {
    let t = TmpDir::new("ofr-link");
    fs::write(t.0.join("target"), b"secret").unwrap();
    std::os::unix::fs::symlink(t.0.join("target"), t.0.join("c1.log.1")).unwrap();
    let e = open_for_read(&t.0.join("c1.log.1")).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

/// SUP-7・REPAIR-5: FIFO（直接・FIFO を指す symlink）は open で停止せず `InvalidArgument` で拒否される。
#[cfg(unix)]
#[test]
fn sup7_task164_open_for_read_rejects_fifo_without_blocking() {
    let t = TmpDir::new("ofr-fifo");
    let fifo = t.0.join("c1.log");
    // 前提不備は skip せず失敗させる（AGENTS.md）。FIFO を作れなければ検証が成立しない。
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must be runnable on unix test hosts");
    assert!(made.success(), "mkfifo must succeed on unix test hosts");
    assert_eq!(
        open_for_read(&fifo).err().unwrap().code(),
        ErrorCode::InvalidArgument
    );
    std::os::unix::fs::symlink(&fifo, t.0.join("c1.log.1")).unwrap();
    assert_eq!(
        open_for_read(&t.0.join("c1.log.1")).err().unwrap().code(),
        ErrorCode::InvalidArgument
    );
    // 検査後の差し替えを模す: 非ブロッキング open は書き手不在の FIFO でも即座に返る。
    let f = crate::container_options::env::open_nonblocking(&fifo).unwrap();
    assert!(!f.metadata().unwrap().file_type().is_file());
}

/// SUP-7: ロックファイルを作れない（書き込み不可ディレクトリ）ときは `NotFound` でなく `Internal`。
#[cfg(unix)]
#[test]
fn sup7_task164_acquire_lock_create_failure_is_internal() {
    use std::os::unix::fs::PermissionsExt;
    let t = TmpDir::new("lock-ro");
    fs::set_permissions(&t.0, fs::Permissions::from_mode(0o500)).unwrap();
    let probe = fs::File::create(t.0.join("probe"));
    let result = acquire_lock(&t.0, "c1.log");
    fs::set_permissions(&t.0, fs::Permissions::from_mode(0o700)).unwrap();
    if probe.is_ok() {
        return; // root 等で権限が効かない環境では検証できない
    }
    assert_eq!(result.err().unwrap().code(), ErrorCode::Internal);
}

/// SUP-7: 既存のロックファイルは再利用され、ディレクトリは `InvalidArgument`。
#[test]
fn sup7_task164_acquire_lock_existing_cases() {
    let t = TmpDir::new("lock-existing");
    drop(acquire_lock(&t.0, "a.log").unwrap());
    drop(acquire_lock(&t.0, "a.log").unwrap());
    fs::create_dir(t.0.join("b.log.lock")).unwrap();
    assert_eq!(
        acquire_lock(&t.0, "b.log").err().unwrap().code(),
        ErrorCode::InvalidArgument
    );
}

/// Windows 限定（実行は windows-latest の CI）: 削除共有つきの読み手・削除共有なしの読み手と世代 rename。
#[cfg(windows)]
mod windows_share {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::Instant;

    /// 現在ログを満たし、次の append でローテーションが起きる状態の sink を作る。
    fn full_sink(t: &TmpDir) -> RotatingFileSink {
        let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
        s.append(StreamKind::Stdout, &vec![b'a'; MAX_LINE_BYTES])
            .unwrap();
        s.flush().unwrap();
        s
    }

    /// 削除共有なし（READ | WRITE のみ）で開く。
    fn open_without_delete_share(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(path)
            .unwrap()
    }

    /// SUP-7・WIN-4: `open_for_read`（削除共有つき）で開いたままでもローテーションは成功する。
    #[test]
    fn sup7_task164_windows_rotation_succeeds_with_delete_sharing_reader() {
        let t = TmpDir::new("win-share");
        let s = full_sink(&t);
        let _reader = open_for_read(&t.0.join("c1.log")).unwrap();
        s.append(StreamKind::Stdout, b"next").unwrap();
        assert_eq!(s.rotations().unwrap(), 1);
        assert_eq!(files(&t.0), vec!["c1.log", "c1.log.1"]);
    }

    /// SUP-7・REPAIR-5: 削除共有なしの読み手が居座ると、有界時間で失敗し sink は失敗状態に固定される。
    #[test]
    fn sup7_task164_windows_rotation_fails_closed_with_non_sharing_reader() {
        let t = TmpDir::new("win-noshare");
        let s = full_sink(&t);
        let _reader = open_without_delete_share(&t.0.join("c1.log"));
        let start = Instant::now();
        let e = s.append(StreamKind::Stdout, b"next").unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert!(start.elapsed() < Duration::from_secs(5));
        let e2 = s.append(StreamKind::Stderr, b"other").unwrap_err();
        assert_eq!(e2.code(), ErrorCode::Internal);
    }

    /// SUP-7: 再試行予算の内に読み手が閉じれば、ローテーションは成功する（再書き込みなし）。
    #[test]
    fn sup7_task164_windows_rotation_retries_until_reader_closes() {
        let t = TmpDir::new("win-retry");
        let mut s = full_sink(&t);
        // 解放までの時間に余裕を持たせるため、テストでは予算を長くする（50 × 10ms）。
        s.retry = RenameRetry {
            interval: Duration::from_millis(10),
            max_sleeps: 50,
        };
        let reader = open_without_delete_share(&t.0.join("c1.log"));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(30));
            drop(reader);
        });
        tx.send(()).unwrap();
        s.append(StreamKind::Stdout, b"next").unwrap();
        h.join().unwrap();
        assert_eq!(s.rotations().unwrap(), 1);
        assert_eq!(files(&t.0), vec!["c1.log", "c1.log.1"]);
    }

    /// WIN-4・SUP-7: 既存ロックファイルありでも open でき、2 回目の open は FailedPrecondition。
    #[test]
    fn sup7_task164_windows_existing_lock_file_is_reused_with_identity_check() {
        let t = TmpDir::new("win-lock");
        fs::write(t.0.join("c1.log.lock"), b"").unwrap();
        let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        drop(s);
    }
}

// ---- ロックファイルの掃除経路（SUP-7・TASK-164 追補・#1469）----

/// `.lock` を除外しない全エントリ名（ソート済み）。
fn all_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// 3 世代（`c1.log`・`.1`・`.2`）が揃うまで書いてから閉じる。
fn fill_three_generations(dir: &Path, id: &ContainerId) {
    let s = RotatingFileSink::open(dir, id, small()).unwrap();
    let line = vec![b'a'; 992];
    for _ in 0..400 {
        s.append(StreamKind::Stdout, &line).unwrap();
    }
}

/// SUP-7: 名前の分類は表のとおり（open・削除・列挙が同じ判定を使う）。
#[test]
fn sup7_task164_1469_classify_name_table() {
    let b = "c1.log";
    assert_eq!(classify_name(b, "c1.log"), NameClass::Current);
    assert_eq!(classify_name(b, "c1.log.lock"), NameClass::Lock);
    assert_eq!(classify_name(b, "c1.log.1"), NameClass::Generation(1));
    assert_eq!(classify_name(b, "c1.log.16"), NameClass::Generation(16));
    for rejected in [
        "c1.log.0",
        "c1.log.01",
        "C1.LOG",
        "c1.log.LOCK",
        "c1.log.99999999999999999999",
    ] {
        assert!(
            matches!(classify_name(b, rejected), NameClass::Rejected(_)),
            "{rejected}"
        );
    }
    for other in [
        "c2.log",
        "c1.log.log",
        "c1.log.lock.1",
        "c1.log.x",
        "c1.logx",
    ] {
        assert_eq!(classify_name(b, other), NameClass::Other, "{other}");
    }
}

/// SUP-7: 上限超過の既存ログで open が失敗しても、ロックファイルを残さない。
#[test]
fn sup7_task164_1469_open_failure_removes_lock_file() {
    let t = TmpDir::new("openfail");
    let big = vec![b'z'; usize::try_from(MIN_LOG_FILE_BYTES).unwrap() + 1];
    fs::write(t.0.join("c1.log"), &big).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(all_files(&t.0), ["c1.log"]);
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), big);
}

/// SUP-7: 名前空間違反（世代数以上・世代 0・大文字別名・ディレクトリ世代）でもロックを残さない。
#[test]
fn sup7_task164_1469_namespace_rejection_removes_lock_file() {
    for bad in ["c1.log.3", "c1.log.0", "C1.LOG.1"] {
        let t = TmpDir::new("nsfail");
        fs::write(t.0.join(bad), b"x\n").unwrap();
        let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
        assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad}");
        assert_eq!(all_files(&t.0), [bad], "{bad}");
    }
    let t = TmpDir::new("nsdir");
    fs::create_dir(t.0.join("c1.log.1")).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(all_files(&t.0), ["c1.log.1"]);
}

/// SUP-7: 既存の空ロックファイルがあっても、検査失敗後に消える。
#[test]
fn sup7_task164_1469_open_failure_removes_preexisting_lock_file() {
    let t = TmpDir::new("prelock");
    fs::write(t.0.join("c1.log.lock"), b"").unwrap();
    fs::write(t.0.join("c1.log.5"), b"x\n").unwrap();
    assert!(RotatingFileSink::open(&t.0, &id(), small()).is_err());
    assert_eq!(all_files(&t.0), ["c1.log.5"]);
}

/// SUP-7: 競合した open（FailedPrecondition）は先行 sink のロックファイルを消さない。
#[test]
fn sup7_task164_1469_contended_open_keeps_lock_file() {
    let t = TmpDir::new("contend");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    let e = RotatingFileSink::open(&t.0, &id(), small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(all_files(&t.0), ["c1.log", "c1.log.lock"]);
    s.append(StreamKind::Stdout, b"ok").unwrap();
    s.flush().unwrap();
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout ok\n");
}

/// SUP-7: sink 生存中の remove_all は拒否し、何も消さない。
#[test]
fn sup7_task164_1469_remove_all_refused_while_sink_alive() {
    let t = TmpDir::new("alive");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"keep").unwrap();
    let e = RotatingFileSink::remove_all(&t.0, &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(all_files(&t.0), ["c1.log", "c1.log.lock"]);
    s.append(StreamKind::Stdout, b"more").unwrap();
    s.flush().unwrap();
    assert_eq!(
        fs::read(t.0.join("c1.log")).unwrap(),
        b"stdout keep\nstdout more\n"
    );
}

/// SUP-7: remove_all は現在ログ・全世代・ロックファイルを消し、別 ID・無関係なファイルは残す。
#[test]
fn sup7_task164_1469_remove_all_removes_logs_and_lock_only_for_the_id() {
    let t = TmpDir::new("removeall");
    fill_three_generations(&t.0, &id());
    let other = ContainerId::new("c2").unwrap();
    let keep = RotatingFileSink::open(&t.0, &other, small()).unwrap();
    fs::write(t.0.join("note.txt"), b"n").unwrap();
    assert_eq!(
        all_files(&t.0),
        [
            "c1.log",
            "c1.log.1",
            "c1.log.2",
            "c1.log.lock",
            "c2.log",
            "c2.log.lock",
            "note.txt"
        ]
    );
    let r = RotatingFileSink::remove_all(&t.0, &id()).unwrap();
    assert_eq!(r.log_files(), 3);
    assert_eq!(all_files(&t.0), ["c2.log", "c2.log.lock", "note.txt"]);
    drop(keep);
}

/// SUP-7: 何も無い状態の remove_all は成功し（冪等）、ロックファイルも残さない。
#[test]
fn sup7_task164_1469_remove_all_is_idempotent() {
    let t = TmpDir::new("idem");
    for _ in 0..2 {
        let r = RotatingFileSink::remove_all(&t.0, &id()).unwrap();
        assert_eq!(r.log_files(), 0);
        assert_eq!(all_files(&t.0), Vec::<String>::new());
    }
}

/// SUP-7: 設定世代数を超える番号の世代も消す。
#[test]
fn sup7_task164_1469_remove_all_removes_generations_beyond_config() {
    let t = TmpDir::new("beyond");
    fs::write(t.0.join("c1.log"), b"a\n").unwrap();
    fs::write(t.0.join("c1.log.7"), b"b\n").unwrap();
    let r = RotatingFileSink::remove_all(&t.0, &id()).unwrap();
    assert_eq!(r.log_files(), 2);
    assert_eq!(all_files(&t.0), Vec::<String>::new());
}

/// SUP-7: 削除後に同じ ID で開き直せ、世代を消費しない。
#[test]
fn sup7_task164_1469_reopen_after_remove_all() {
    let t = TmpDir::new("reopen");
    fill_three_generations(&t.0, &id());
    RotatingFileSink::remove_all(&t.0, &id()).unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"x").unwrap();
    s.flush().unwrap();
    assert_eq!(all_files(&t.0), ["c1.log", "c1.log.lock"]);
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"stdout x\n");
}

/// SUP-7: 受理できない名前・ディレクトリがあれば何も消さず拒否する（ロックファイルは残さない）。
#[test]
fn sup7_task164_1469_remove_all_rejection_removes_nothing() {
    let t = TmpDir::new("reject");
    fs::write(t.0.join("c1.log"), b"keep\n").unwrap();
    fs::write(t.0.join("c1.log.0"), b"bad\n").unwrap();
    let e = RotatingFileSink::remove_all(&t.0, &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(all_files(&t.0), ["c1.log", "c1.log.0"]);
    assert_eq!(fs::read(t.0.join("c1.log")).unwrap(), b"keep\n");

    let t = TmpDir::new("rejectdir");
    fs::write(t.0.join("c1.log"), b"keep\n").unwrap();
    fs::create_dir(t.0.join("c1.log.2")).unwrap();
    let e = RotatingFileSink::remove_all(&t.0, &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(all_files(&t.0), ["c1.log", "c1.log.2"]);
}

/// SUP-7: symlink の世代は辿らず、リンク自体だけを消す。
#[cfg(unix)]
#[test]
fn sup7_task164_1469_remove_all_does_not_follow_symlinks() {
    let t = TmpDir::new("symlink");
    let outside = TmpDir::new("symlink-out");
    fs::write(outside.0.join("target.txt"), b"keep\n").unwrap();
    std::os::unix::fs::symlink(outside.0.join("target.txt"), t.0.join("c1.log.1")).unwrap();
    let r = RotatingFileSink::remove_all(&t.0, &id()).unwrap();
    assert_eq!(r.log_files(), 1);
    assert_eq!(all_files(&t.0), Vec::<String>::new());
    assert_eq!(fs::read(outside.0.join("target.txt")).unwrap(), b"keep\n");
}

/// SUP-7: dir 検証は open と同じ（相対パス・存在しないディレクトリは拒否）。
#[test]
fn sup7_task164_1469_remove_all_validates_dir() {
    let e = RotatingFileSink::remove_all(Path::new("relative"), &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    let t = TmpDir::new("nodir");
    let e = RotatingFileSink::remove_all(&t.0.join("missing"), &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
}

/// SUP-7: 読み出し側の列挙はロックファイル・別 ID・無関係なファイルを含めない。
#[test]
fn sup7_task164_1469_log_file_paths_excludes_lock_file() {
    let t = TmpDir::new("list");
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    let line = vec![b'a'; 992];
    for _ in 0..400 {
        s.append(StreamKind::Stdout, &line).unwrap();
    }
    let other = ContainerId::new("c2").unwrap();
    let _o = RotatingFileSink::open(&t.0, &other, small()).unwrap();
    fs::write(t.0.join("note.txt"), b"n").unwrap();
    let names: Vec<String> = log_file_paths(&t.0, &id())
        .unwrap()
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["c1.log.2", "c1.log.1", "c1.log"]);
}

/// SUP-7: 列挙は受理できないエントリを拒否し、ログが無ければ空を返す。
#[test]
fn sup7_task164_1469_log_file_paths_rejects_and_empty() {
    let t = TmpDir::new("listrej");
    assert_eq!(log_file_paths(&t.0, &id()).unwrap(), Vec::<PathBuf>::new());
    fs::create_dir(t.0.join("c1.log.1")).unwrap();
    let e = log_file_paths(&t.0, &id()).unwrap_err();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    #[cfg(unix)]
    {
        let t = TmpDir::new("listlink");
        std::os::unix::fs::symlink(t.0.join("nowhere"), t.0.join("c1.log.1")).unwrap();
        let e = log_file_paths(&t.0, &id()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }
}

/// SUP-7: 取得中にロックファイルが差し替えられた場合（孤立 inode）は成功扱いにしない（unix）。
#[cfg(unix)]
#[test]
fn sup7_task164_1469_replaced_lock_file_is_not_accepted() {
    let t = TmpDir::new("replaced");
    let path = t.0.join("c1.log.lock");
    let held = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    // パスを消して別の実体で作り直す。held は孤立 inode になる。
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"").unwrap();
    let e = verify_lock_is_current(&held, &path).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    // パスが無い場合も同様。
    fs::remove_file(&path).unwrap();
    let e = verify_lock_is_current(&held, &path).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
}
