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
            // 既存パスは削除せず、`create_dir`（原子的な新規作成）が AlreadyExists を返したら
            // 連番を進めて別名で再試行する（所有確認なしの remove_dir_all を避ける）。
            loop {
                let n = COUNTER.fetch_add(1, Ordering::SeqCst);
                let p = std::env::temp_dir()
                    .join(format!("fandhe-sup-insp-{tag}-{}-{n}", std::process::id()));
                match fs::create_dir(&p) {
                    Ok(()) => {
                        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
                        return Self(p);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create_dir {}: {e}", p.display()),
                }
            }
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

    /// `{"k":v,...}` 形式（値は文字列・整数・null のみ）を RFC 8259 の文法どおり厳密にパースする。
    ///
    /// 空白・入れ子・小数は `inspect` の出力契約に無いため受け付けない。不正な入力は理由つきの `Err` にし、
    /// 添字の範囲外も panic させず `Err` にする（パーサ自体の厳密さを下の試験で具体値照合するため）。
    fn parse_flat_object(text: &str) -> Result<BTreeMap<String, V>, String> {
        let b = text.as_bytes();
        let mut i = 0;
        expect(b, &mut i, b'{')?;
        let mut map = BTreeMap::new();
        loop {
            let key = parse_str(b, &mut i)?;
            expect(b, &mut i, b':')?;
            let v = match peek(b, i)? {
                b'"' => V::Str(parse_str(b, &mut i)?),
                b'n' => {
                    if b.get(i..i + 4) != Some(b"null".as_slice()) {
                        return Err(format!("invalid literal at {i}"));
                    }
                    i += 4;
                    V::Null
                }
                _ => V::Num(parse_int(b, &mut i)?),
            };
            if map.insert(key.clone(), v).is_some() {
                return Err(format!("duplicate key {key}"));
            }
            match peek(b, i)? {
                b',' => i += 1,
                b'}' => {
                    i += 1;
                    break;
                }
                c => return Err(format!("unexpected byte 0x{c:02x} at {i}")),
            }
        }
        if i != b.len() {
            return Err(format!("trailing bytes at {i}"));
        }
        Ok(map)
    }

    fn peek(b: &[u8], i: usize) -> Result<u8, String> {
        b.get(i)
            .copied()
            .ok_or_else(|| format!("unexpected end at {i}"))
    }

    fn expect(b: &[u8], i: &mut usize, want: u8) -> Result<(), String> {
        let c = peek(b, *i)?;
        if c != want {
            return Err(format!("unexpected byte 0x{c:02x} at {i}", i = *i));
        }
        *i += 1;
        Ok(())
    }

    /// JSON の整数（`-?(0|[1-9][0-9]*)`）を読む。先頭ゼロ・符号のみ・`+` は不正として拒否する。
    fn parse_int(b: &[u8], i: &mut usize) -> Result<i64, String> {
        let start = *i;
        if peek(b, *i)? == b'-' {
            *i += 1;
        }
        let digits = *i;
        while b.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        let d = b.get(digits..*i).unwrap_or_default();
        if d.is_empty() || (d.len() > 1 && d.first() == Some(&b'0')) {
            return Err(format!("invalid number at {start}"));
        }
        std::str::from_utf8(b.get(start..*i).unwrap_or_default())
            .map_err(|e| e.to_string())?
            .parse()
            .map_err(|e| format!("invalid number at {start}: {e}"))
    }

    /// `"` から始まる JSON 文字列を読む。
    ///
    /// RFC 8259 が文字列内で禁じる未エスケープの制御文字（U+0000〜U+001F。タブ・CR・LF を含む）と、
    /// 未定義のエスケープ・16 進 4 桁でない `\u`・単独サロゲートを拒否する。
    fn parse_str(b: &[u8], i: &mut usize) -> Result<String, String> {
        expect(b, i, b'"')?;
        let mut out = Vec::new();
        loop {
            let c = peek(b, *i)?;
            match c {
                b'"' => {
                    *i += 1;
                    return String::from_utf8(out).map_err(|e| e.to_string());
                }
                b'\\' => {
                    *i += 1;
                    match peek(b, *i)? {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = b
                                .get(*i + 1..*i + 5)
                                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                                .ok_or_else(|| format!("invalid \\u escape at {i}", i = *i))?;
                            let hex = std::str::from_utf8(hex).map_err(|e| e.to_string())?;
                            let n = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                            let ch = char::from_u32(n)
                                .ok_or_else(|| format!("lone surrogate at {i}", i = *i))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            *i += 4;
                        }
                        e => return Err(format!("unsupported escape 0x{e:02x} at {i}", i = *i)),
                    }
                    *i += 1;
                }
                c if c < 0x20 => {
                    return Err(format!(
                        "unescaped control character 0x{c:02x} at {i}",
                        i = *i
                    ));
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
        parse_flat_object(body).unwrap()
    }

    fn s(v: &str) -> V {
        V::Str(v.to_string())
    }

    /// 検証用パーサが不正な JSON を見逃さない（SUP-11・REPAIR-12）。
    ///
    /// 機械照合の根拠になるパーサ自体を具体値で確認する: 文字列内の未エスケープ制御文字（タブ・CR・LF・
    /// U+0001・U+001F）・未定義エスケープ・不正な `\u`・先頭ゼロの数値・末尾の余剰・途中終端を拒否する。
    #[test]
    fn sup11_task168_1_test_parser_rejects_malformed_json() {
        for (c, hex) in [
            ('\t', "09"),
            ('\r', "0d"),
            ('\n', "0a"),
            ('\u{1}', "01"),
            ('\u{1f}', "1f"),
        ] {
            assert_eq!(
                parse_flat_object(&format!("{{\"k\":\"a{c}b\"}}")),
                Err(format!("unescaped control character 0x{hex} at 7")),
            );
            assert_eq!(
                parse_flat_object(&format!("{{\"k{c}\":1}}")),
                Err(format!("unescaped control character 0x{hex} at 3")),
            );
        }
        let cases = [
            (r#"{"k":"\x"}"#, "unsupported escape 0x78 at 7"),
            (r#"{"k":"\u12"}"#, "invalid \\u escape at 7"),
            (r#"{"k":"\u+123"}"#, "invalid \\u escape at 7"),
            (r#"{"k":"\ud800"}"#, "lone surrogate at 7"),
            (r#"{"k":01}"#, "invalid number at 5"),
            (r#"{"k":-}"#, "invalid number at 5"),
            (r#"{"k":+1}"#, "invalid number at 5"),
            (r#"{"k":nul}"#, "invalid literal at 5"),
            (r#"{"k":1,"k":2}"#, "duplicate key k"),
            (r#"{"k": 1}"#, "invalid number at 5"),
            (r#"{"k":1}x"#, "trailing bytes at 7"),
            (r#"{"k":1"#, "unexpected end at 6"),
            (r#"{"k":"a"#, "unexpected end at 7"),
            (r#"["k"]"#, "unexpected byte 0x5b at 0"),
        ];
        for (input, want) in cases {
            assert_eq!(
                parse_flat_object(input),
                Err(want.to_string()),
                "input: {input}"
            );
        }
        // 正しくエスケープされた制御文字は元の文字へ復号される。
        let ok =
            parse_flat_object(r#"{"a":"x\ty\r\n\u0001\u001f\"\\\/\b\f","b":-12,"c":0,"d":null}"#)
                .unwrap();
        assert_eq!(ok["a"], s("x\ty\r\n\u{1}\u{1f}\"\\/\u{8}\u{c}"));
        assert_eq!(ok["b"], V::Num(-12));
        assert_eq!(ok["c"], V::Num(0));
        assert_eq!(ok["d"], V::Null);
    }

    /// bundle パスに制御文字・`"`・`\` が含まれても、出力は妥当な JSON 1 行で、パース結果が元のパスに戻る
    /// （SUP-11。untrusted 値のエスケープを実ストア経由で照合する）。
    #[test]
    fn sup11_task168_1_real_store_control_characters_in_bundle_are_escaped() {
        let t = TmpDir::new("ctrl");
        let store = open_default_store(Some(t.path().to_path_buf())).unwrap();
        let bundle = t.path().join("b\tu\rn\nd\u{1}l\u{1f}e\"q\\s");
        let req =
            CreateStateRequest::new(ContainerStatus::created(cid("c1"), None), bundle.clone())
                .unwrap();
        store.create(&req).unwrap();

        let mut buf = Vec::new();
        inspect(store.as_ref(), &cid("c1"))
            .unwrap()
            .write_json(&mut buf)
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains(r#"b\tu\rn\nd\u0001l\u001fe\"q\\s"#),
            "escaped bundle not found: {text}"
        );
        assert_eq!(
            text.bytes().filter(|c| *c < 0x20).collect::<Vec<_>>(),
            vec![b'\n'],
            "only the trailing LF may be a raw control byte"
        );
        let m = render(store.as_ref(), "c1");
        assert_eq!(m["bundle"], s(bundle.to_str().unwrap()));
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
