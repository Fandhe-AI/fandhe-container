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

#[cfg(unix)]
#[test]
fn sup7_task164_2_symlink_log_target_is_not_modified() {
    let t = TmpDir::new("symlink");
    let target = t.0.join("target");
    fs::write(&target, b"keep\n").unwrap();
    std::os::unix::fs::symlink(&target, t.0.join("c1.log")).unwrap();
    let s = RotatingFileSink::open(&t.0, &id(), small()).unwrap();
    s.append(StreamKind::Stdout, b"x").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"keep\n");
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
    // ".log"(4) + ".2"(2) 付与で 255 を超える長さ（250 + 6 = 256）。
    let long = ContainerId::new("a".repeat(250)).unwrap();
    let e = RotatingFileSink::open(&t.0, &long, small()).err().unwrap();
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert!(files(&t.0).is_empty());
    // 世代数 1 なら ".log" のみで 254 バイトに収まる。
    let one = RotationConfig::new(MIN_LOG_FILE_BYTES, 1).unwrap();
    RotatingFileSink::open(&t.0, &long, one).unwrap();
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
    let t = TmpDir::new("stale-other");
    for other in ["c1.log.x", "c1.log.01", "c1.log.", "c2.log.20", "c1.log.15"] {
        fs::write(t.0.join(other), b"o").unwrap();
    }
    let cfg = RotationConfig::new(MIN_LOG_FILE_BYTES, 16).unwrap();
    assert!(RotatingFileSink::open(&t.0, &id(), cfg).is_ok());
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
    // 世代へ退避されたファイルはなく、全ファイル名が小文字のみ。
    assert_eq!(files(&t.0), ["__a.log", "_a.log", "a.log"]);
    assert!(fs::read(t.0.join("_a.log")).unwrap().ends_with(b"upper\n"));
    assert!(fs::read(t.0.join("a.log")).unwrap().ends_with(b"lower\n"));
    assert!(fs::read(t.0.join("__a.log")).unwrap().ends_with(b"under\n"));
}
