//! `inspect` 出力を実 `StateStore`（core の `FileStateStore`）経由で検証する結合テスト（SUP-11・TASK-168.1・#523・REPAIR-12）。
//!
//! 実ストアへ書いたレコードを `inspect` で読み、`write_json` の出力バイト列を JSON として機械的にパースして
//! キー集合・型・値を具体値で照合する。supervisor は serde を持たないため、テスト内に平坦な 1 オブジェクト
//! 専用の最小パーサを置く。`FileStateStore` は Linux 限定のため試験本体は `linux` モジュールに置く。
//! root 不要で既定のテスト集合で動く。

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, ErrorCode, HealthStatus, StateStore,
        SupervisionState, UpdateStateRequest,
    };
    use fandhe_container_supervisor::inspect::inspect;
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テスト用一時ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("fandhe-sup-insp-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// パース結果の JSON 値（平坦な 1 オブジェクトに必要な型のみ）。
    #[derive(Debug, PartialEq)]
    enum V {
        Null,
        Num(i64),
        Str(String),
    }

    /// `{"k":v,...}` 形式（値は文字列・整数・null のみ）を厳密にパースする。余剰・不足は panic。
    fn parse_flat_object(text: &str) -> BTreeMap<String, V> {
        let b = text.as_bytes();
        let mut i = 0;
        assert_eq!(b[i], b'{', "must start with an object");
        i += 1;
        let mut map = BTreeMap::new();
        loop {
            let key = parse_str(b, &mut i);
            assert_eq!(b[i], b':');
            i += 1;
            let v = match b[i] {
                b'"' => V::Str(parse_str(b, &mut i)),
                b'n' => {
                    assert_eq!(&b[i..i + 4], b"null");
                    i += 4;
                    V::Null
                }
                _ => {
                    let s = i;
                    if b[i] == b'-' {
                        i += 1;
                    }
                    while b[i].is_ascii_digit() {
                        i += 1;
                    }
                    V::Num(text[s..i].parse().unwrap())
                }
            };
            assert!(map.insert(key, v).is_none(), "duplicate key");
            match b[i] {
                b',' => i += 1,
                b'}' => {
                    i += 1;
                    break;
                }
                c => panic!("unexpected byte {c}"),
            }
        }
        assert_eq!(i, b.len(), "trailing bytes after object");
        map
    }

    /// `"` から始まる JSON 文字列を読む（`\"` `\\` `\n` `\r` `\t` `\uXXXX` のみ対応）。
    fn parse_str(b: &[u8], i: &mut usize) -> String {
        assert_eq!(b[*i], b'"');
        *i += 1;
        let mut out = Vec::new();
        loop {
            match b[*i] {
                b'"' => {
                    *i += 1;
                    return String::from_utf8(out).unwrap();
                }
                b'\\' => {
                    *i += 1;
                    match b[*i] {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                            let c = char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap();
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                            *i += 4;
                        }
                        c => panic!("unsupported escape {c}"),
                    }
                    *i += 1;
                }
                c => {
                    out.push(c);
                    *i += 1;
                }
            }
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    const KEYS: [&str; 11] = [
        "bundle",
        "cgroupInstance",
        "cgroupScope",
        "exitCode",
        "health",
        "id",
        "pid",
        "restartCount",
        "revision",
        "status",
        "supervisorPid",
    ];

    /// `inspect` の出力を write_json 経由で取り出し、末尾 LF 1 個・1 行を確認してパースする。
    fn render(store: &dyn StateStore, id: &str) -> BTreeMap<String, V> {
        let report = inspect(store, &cid(id)).unwrap();
        let mut buf = Vec::new();
        report.write_json(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let body = text.strip_suffix('\n').expect("trailing LF");
        assert!(!body.contains('\n'), "must be a single line");
        parse_flat_object(body)
    }

    fn s(v: &str) -> V {
        V::Str(v.to_string())
    }

    /// 実ストアの `created` レコードが、null を含む全キー・具体値で出力される。
    #[test]
    fn sup11_task168_1_real_store_created_record_output() {
        let t = TmpDir::new("created");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let bundle = t.path().join("bundle");
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("web-1"), None), bundle.clone())
                .unwrap();
        let created = store.create(&req).unwrap();

        let m = render(store.as_ref(), "web-1");
        assert_eq!(m.keys().map(String::as_str).collect::<Vec<_>>(), KEYS);
        assert_eq!(m["id"], s("web-1"));
        assert_eq!(m["status"], s("created"));
        assert_eq!(m["pid"], V::Null);
        assert_eq!(m["exitCode"], V::Null);
        assert_eq!(m["bundle"], s(&bundle.to_string_lossy()));
        assert_eq!(m["revision"], V::Num(created.revision().value() as i64));
        assert_eq!(m["cgroupScope"], V::Null);
        assert_eq!(m["cgroupInstance"], V::Null);
        assert_eq!(m["supervisorPid"], V::Null);
        assert_eq!(m["health"], V::Null);
        assert_eq!(m["restartCount"], V::Num(0));
    }

    /// supervisor が書いた running + 監視項目が、ストアを開き直しても出力へ反映される。
    #[test]
    fn sup11_task168_1_real_store_supervised_record_output() {
        let t = TmpDir::new("running");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let bundle = t.path().join("bundle");
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("c1"), None), bundle.clone())
                .unwrap();
        store.create(&req).unwrap();
        let mut st = SupervisedState::attach(store, cid("c1")).unwrap();
        let rec = st
            .write(
                ContainerStatus::running(cid("c1"), NonZeroU32::new(4321)),
                SupervisionState::new(NonZeroU32::new(1234), Some(HealthStatus::Healthy), 3),
            )
            .unwrap();

        let reopened = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let m = render(reopened.as_ref(), "c1");
        assert_eq!(m.keys().map(String::as_str).collect::<Vec<_>>(), KEYS);
        assert_eq!(m["status"], s("running"));
        assert_eq!(m["pid"], V::Num(4321));
        assert_eq!(m["supervisorPid"], V::Num(1234));
        assert_eq!(m["health"], s("healthy"));
        assert_eq!(m["restartCount"], V::Num(3));
        assert_eq!(m["revision"], V::Num(rec.revision().value() as i64));
        assert_eq!(m["bundle"], s(&bundle.to_string_lossy()));
    }

    /// 停止後の exitCode と、CLI 側 update 後の revision 更新が出力に反映される。
    #[test]
    fn sup11_task168_1_real_store_stopped_exit_code_output() {
        let t = TmpDir::new("stopped");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let req = CreateStateRequest::new(
            ContainerStatus::created(cid("c1"), None),
            t.path().join("bundle"),
        )
        .unwrap();
        let created = store.create(&req).unwrap();
        let updated = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::stopped(cid("c1"), Some(137)),
                created.revision(),
            ))
            .unwrap();

        let m = render(store.as_ref(), "c1");
        assert_eq!(m["status"], s("stopped"));
        assert_eq!(m["exitCode"], V::Num(137));
        assert_eq!(m["revision"], V::Num(updated.revision().value() as i64));
    }

    /// 実ストアにレコードがなければ `NotFound` をそのまま返し、出力は作られない。
    #[test]
    fn sup11_task168_1_real_store_missing_record_is_not_found() {
        let t = TmpDir::new("missing");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let e = inspect(store.as_ref(), &cid("nope")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::NotFound);
    }

    /// 破損した `state.json` は panic せずエラーで返る。
    #[test]
    fn sup11_task168_1_real_store_corrupted_state_is_error() {
        let t = TmpDir::new("corrupt");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let req = CreateStateRequest::new(
            ContainerStatus::created(cid("c1"), None),
            t.path().join("bundle"),
        )
        .unwrap();
        store.create(&req).unwrap();
        fs::write(t.path().join("c1").join("state.json"), "not json").unwrap();
        assert!(inspect(store.as_ref(), &cid("c1")).is_err());
    }
}

/// Linux 以外では core が `Unimplemented` を返し、そのまま伝播する（CLI-1）。
#[cfg(not(target_os = "linux"))]
#[test]
fn sup11_task168_1_open_store_is_unimplemented_outside_linux() {
    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_supervisor::state::open_default_store;
    let root = std::env::temp_dir().join(format!("fandhe-sup-insp-nolinux-{}", std::process::id()));
    let e = open_default_store(Some(root)).err().unwrap();
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}
