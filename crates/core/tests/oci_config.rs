//! `oci_runtime::load_config` / `parse_config_bytes` の結合試験（OCI-4・CORE-2・ERR-1・REPAIR-5・
//! TASK-29.1.1）。
//!
//! 公開 API だけを crate の外から呼び、bundle の `config.json` の読み込み・異常入力・非通常ファイルの
//! 拒否・未解釈プロパティの報告を具体値で確かめる。実機権限は不要で、3 OS の既定のテスト集合で動く
//! （`cfg(target_os)` を付けない。FIFO の拒否は Unix のみのユニットテストが担う）。

use std::path::{Path, PathBuf};

use fandhe_container_core::oci_runtime::{
    CONFIG_MAX_BYTES, NamespaceKind, OciConfigErrorKind, UnappliedField, load_config,
    parse_config_bytes,
};
use fandhe_container_core::traits::ErrorCode;

/// テストごとに専用の一時ディレクトリを作る（並列実行でも衝突しないよう名前とプロセス ID を含める）。
fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("fandhe-core-oci-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

const VALID: &str = r#"{
  "ociVersion": "1.2.0",
  "root": {"path": "rootfs", "readonly": true},
  "process": {
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "env": ["PATH=/usr/bin:/bin"],
    "cwd": "/"
  },
  "hostname": "it",
  "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "mount"}],
    "uidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
    "seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}
  }
}"#;

/// OCI-4: 通常ファイルの bundle 設定を読み、検証済みの値と未解釈プロパティを返す。
#[test]
fn oci4_load_config_reads_bundle_file() {
    let dir = temp_dir("valid");
    let path = dir.join("config.json");
    std::fs::write(&path, VALID).expect("write");

    let cfg = load_config(&path).expect("load");
    assert_eq!(cfg.oci_version().as_str(), "1.2.0");
    assert_eq!(cfg.root().path(), Path::new("rootfs"));
    assert!(cfg.root().readonly());
    let p = cfg.process().expect("process");
    assert_eq!(p.args(), ["/bin/sh"]);
    assert_eq!(p.env(), ["PATH=/usr/bin:/bin"]);
    assert_eq!(p.cwd(), Path::new("/"));
    assert_eq!(cfg.hostname(), Some("it"));
    assert_eq!(cfg.mounts()[0].destination(), Path::new("/proc"));
    let kinds: Vec<NamespaceKind> = cfg.namespaces().iter().map(|n| n.kind()).collect();
    assert_eq!(kinds, [NamespaceKind::Pid, NamespaceKind::Mount]);
    assert_eq!(cfg.uid_mappings()[0].size(), 65536);
    // SEC-1・CORE-5: 解釈しない seccomp は破棄せず報告される。
    assert_eq!(cfg.unapplied_fields(), [UnappliedField::LinuxSeccomp]);
    assert_eq!(cfg.unapplied_fields()[0].as_str(), "linux.seccomp");

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// OCI-4・ERR-1: 異常入力は機械可読な code / kind と位置で返り、入力値を含まない。
#[test]
fn oci4_load_config_reports_invalid_content() {
    let dir = temp_dir("invalid");

    let syntax = dir.join("syntax.json");
    std::fs::write(&syntax, "{\"ociVersion\": }").expect("write");
    let e = load_config(&syntax).expect_err("syntax");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(*e.kind(), OciConfigErrorKind::Syntax);
    assert_eq!((e.line(), e.column()), (Some(1), Some(16)));

    let null_linux = dir.join("null.json");
    std::fs::write(
        &null_linux,
        r#"{"ociVersion":"1.0.0","root":{"path":"r"},"linux":null}"#,
    )
    .expect("write");
    let e = load_config(&null_linux).expect_err("null");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(*e.kind(), OciConfigErrorKind::Data);

    let secret = dir.join("secret.json");
    std::fs::write(
        &secret,
        r#"{"ociVersion":"1.0.0","root":{"path":"r"},"process":{"user":{"uid":"dummy-secret","gid":0},"args":["a"],"cwd":"/"}}"#,
    )
    .expect("write");
    let e = load_config(&secret).expect_err("type mismatch");
    assert_eq!(*e.kind(), OciConfigErrorKind::Data);
    assert!(!e.to_string().contains("dummy-secret"), "{e}");

    let big = dir.join("big.json");
    std::fs::write(&big, vec![b' '; CONFIG_MAX_BYTES + 1]).expect("write");
    let e = load_config(&big).expect_err("too large");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(*e.kind(), OciConfigErrorKind::TooLarge);

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// ERR-1・REPAIR-5: 非通常ファイル・存在しないパスは 3 OS で同じ分類になる。
#[test]
fn err1_load_config_classifies_path_errors_on_all_os() {
    let dir = temp_dir("paths");

    let as_dir = dir.join("config.json");
    std::fs::create_dir_all(&as_dir).expect("mkdir");
    let e = load_config(&as_dir).expect_err("directory");
    assert_eq!(e.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        *e.kind(),
        OciConfigErrorKind::Invalid {
            field: "config.json"
        }
    );

    let missing = load_config(&dir.join("missing.json")).expect_err("missing");
    assert_eq!(missing.code(), ErrorCode::NotFound);
    assert_eq!(*missing.kind(), OciConfigErrorKind::Io);

    let file = dir.join("bundle");
    std::fs::write(&file, b"{}").expect("write");
    let e = load_config(&file.join("config.json")).expect_err("not a directory");
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert_eq!(*e.kind(), OciConfigErrorKind::Io);

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// OCI-4: メモリ上の入力でもファイル経由と同じ検証結果になる。
#[test]
fn oci4_parse_config_bytes_matches_load_config() {
    let cfg = parse_config_bytes(VALID.as_bytes()).expect("parse");
    assert_eq!(cfg.oci_version().as_str(), "1.2.0");
    assert_eq!(cfg.unapplied_fields(), [UnappliedField::LinuxSeccomp]);
}

/// mounts を差し替えた config を組み立てる。
fn config_with_mounts(mounts: &str) -> String {
    VALID.replacen(
        r#""mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}]"#,
        &format!(r#""mounts": {mounts}"#),
        1,
    )
}

/// OCI-4・CORE-2: トラバーサルを含む mounts destination は Err になる（3 OS 共通）。
#[test]
fn oci4_core2_mount_destination_traversal_rejected() {
    for dest in [r"/../../etc", r"/a/../b", r"a\\..\\x", "/"] {
        let json = config_with_mounts(&format!(r#"[{{"destination": "{dest}"}}]"#));
        let e = parse_config_bytes(json.as_bytes()).expect_err(dest);
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            *e.kind(),
            OciConfigErrorKind::Invalid {
                field: "mounts[].destination"
            }
        );
    }
}

/// OCI-4・CORE-2: 正規な destination は正規化され、rootfs 配下へ解決される。
#[test]
fn oci4_core2_mount_destination_normalized_and_resolved() {
    let json = config_with_mounts(
        r#"[{"destination": "/proc"}, {"destination": "/dev//shm/"}, {"destination": "sys"}, {"destination": "/etc"}]"#,
    );
    let cfg = parse_config_bytes(json.as_bytes()).expect("parse");
    let dests: Vec<&Path> = cfg.mounts().iter().map(|m| m.destination()).collect();
    assert_eq!(
        dests,
        [
            Path::new("/proc"),
            Path::new("/dev/shm"),
            Path::new("/sys"),
            Path::new("/etc")
        ]
    );
    let rootfs =
        std::env::temp_dir().join(format!("fandhe-core-oci-it-rootfs-{}", std::process::id()));
    assert_eq!(
        cfg.mounts()[1].destination_in(&rootfs).expect("resolve"),
        rootfs.join("dev").join("shm")
    );
    // 素朴な join だとホストの /etc に脱出する絶対パスも rootfs 配下に留まる。
    let etc = cfg.mounts()[3].destination_in(&rootfs).expect("resolve");
    assert!(etc.starts_with(&rootfs));
    assert_ne!(etc, Path::new("/etc"));
}
