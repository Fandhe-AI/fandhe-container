//! スカラーと short syntax キーの変換を公開 API で通す結合試験（STACK-3・TASK-151.3.1・#864）。
//! YAML → `convert_top_level` → TOML 書き出し → 再パースで、stack の `deny_unknown_fields` を通ることを照合する。

use fandhe_container_compose_convert::compose_convert::parse_compose_yaml;
use fandhe_container_compose_convert::convert::{ValueDrops, convert_top_level};
use fandhe_container_stack::schema::ComposeToml;

/// STACK-3: 変換結果が TOML へ往復し、期待値と一致する。
#[test]
fn stack3_scalar_convert_roundtrips_through_toml() {
    let doc = parse_compose_yaml(
        "name: demo\nservices:\n  web:\n    image: nginx:1.27\n    command: nginx -g 'daemon off;'\n    environment:\n      A: \"1\"\n      B:\n    env_file: .env\n    labels: [k=v]\n    ports: ['8080:80']\n",
    )
    .unwrap();
    let mut drops = ValueDrops::new();
    let t = convert_top_level(&doc, &mut drops);
    let text = toml::to_string(&t).unwrap();
    let back: ComposeToml = toml::from_str(&text).unwrap();
    assert_eq!(back, t);
    let web = &back.services["web"];
    assert_eq!(
        web.command,
        Some(vec!["nginx".into(), "-g".into(), "daemon off;".into()])
    );
    assert_eq!(web.env.get("B").map(String::as_str), Some(""));
    assert_eq!(web.env_files, vec![".env".to_string()]);
    assert_eq!(web.ports, vec!["8080:80".to_string()]);
    assert!(drops.is_empty());
}
