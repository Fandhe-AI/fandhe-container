//! 合成フィクスチャでアンカー / エイリアス / マージキーの展開を具体値で照合する結合試験
//! （STACK-3・TASK-151.1・#595・REPAIR-12）。`docs/spec` は参照しない。

use fandhe_container_compose_convert::compose_convert::{ComposeValue, parse_compose_yaml};

const FIXTURE: &str = include_str!("fixtures/anchors_merge.yaml");

fn keys(v: &ComposeValue) -> Vec<&str> {
    v.as_mapping().unwrap().iter().map(|(k, _)| k).collect()
}

#[test]
fn anchors_and_merge_keys_expand() {
    let doc = parse_compose_yaml(FIXTURE).unwrap();
    let services = doc.get("services").unwrap();

    // web: 明示の restart がマージ由来に勝ち、`yes` は文字列。マージ分は明示キーの後ろ。
    let web = services.get("web").unwrap();
    assert_eq!(web.get("restart").unwrap().as_str(), Some("no"));
    assert_eq!(web.get("flag").unwrap().as_str(), Some("yes"));
    assert_eq!(keys(web), vec!["restart", "flag", "environment", "labels"]);
    assert_eq!(
        web.get("environment").unwrap().get("LOG").unwrap().as_str(),
        Some("info")
    );

    // api: 明示キーを先に書いても結果は同じ。
    let api = services.get("api").unwrap();
    assert_eq!(api.get("command").unwrap().as_str(), Some("serve"));
    assert_eq!(api.get("restart").unwrap().as_str(), Some("always"));

    // worker: 先のマッピング（a）が勝ち、b だけのキーは足される。
    let worker = services.get("worker").unwrap();
    assert_eq!(worker.get("image").unwrap().as_str(), Some("img-a"));
    assert_eq!(worker.get("user").unwrap().as_str(), Some("from-a"));
    assert_eq!(worker.get("tty").unwrap().as_bool(), Some(true));

    // db: アンカーの中のマージも展開される。
    let db = services.get("db").unwrap();
    assert_eq!(db.get("stop_signal").unwrap().as_str(), Some("SIGINT"));
    assert_eq!(db.get("restart").unwrap().as_str(), Some("always"));
    assert_eq!(
        db.get("labels").unwrap().get("tier").unwrap().as_str(),
        Some("base")
    );

    // cache: スカラー・シーケンスのエイリアスは複製される。
    let cache = services.get("cache").unwrap();
    assert_eq!(cache.get("image").unwrap().as_str(), Some("busybox:1.36"));
    let ports = cache.get("ports").unwrap().as_sequence().unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].as_str(), Some("8080:80"));

    // 展開後に `<<` は残らない。
    for name in ["web", "api", "worker", "db", "cache"] {
        assert!(services.get(name).unwrap().get("<<").is_none(), "{name}");
    }
    assert!(doc.get("x-nested").unwrap().get("<<").is_none());
}
