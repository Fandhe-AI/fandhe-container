//! 実 YAML を読んで long syntax 6 キーの変換・drop を具体値で照合し、stack の `Service` へ載せた
//! TOML 往復も確かめる結合試験（STACK-3・TASK-151.3.2・#865・REPAIR-12）。`docs/spec` は参照しない。

use fandhe_container_compose_convert::compose_convert::{ComposeValue, parse_compose_yaml};
use fandhe_container_compose_convert::long_syntax::{
    LongSyntaxDropReason, LongSyntaxKey, convert_long_syntax_element,
};
use fandhe_container_stack::schema::Service;

const YAML: &str = "\
services:
  web:
    ports:
      - {target: 80, published: 8080, protocol: tcp}
      - {target: 53, published: 5353, protocol: udp, mode: host}
    volumes:
      - {type: volume, source: models, target: /models, read_only: true}
      - {type: bind, source: ./data, target: /data}
      - {type: tmpfs, target: /t}
    secrets:
      - {source: api_key}
      - {source: db_pass, target: /x}
    configs:
      - {source: app_conf}
    tmpfs:
      - {target: /run}
    devices:
      - {source: /dev/x, target: /dev/x}
";

fn run(
    web: &ComposeValue,
    name: &str,
    key: LongSyntaxKey,
) -> (Vec<String>, Vec<LongSyntaxDropReason>) {
    let mut out = Vec::new();
    let mut drops = Vec::new();
    for e in web.get(name).unwrap().as_sequence().unwrap() {
        match convert_long_syntax_element(key, e.as_mapping().unwrap()) {
            Ok(c) => out.push(c.short_syntax),
            Err(d) => drops.push(d.reason),
        }
    }
    (out, drops)
}

#[test]
fn six_keys_convert_or_drop() {
    let doc = parse_compose_yaml(YAML).unwrap();
    let web = doc.get("services").unwrap().get("web").unwrap();

    let (ports, pd) = run(web, "ports", LongSyntaxKey::Ports);
    assert_eq!(ports, vec!["8080:80/tcp"]);
    assert_eq!(pd, vec![LongSyntaxDropReason::PortModeNotIngress]);

    let (vols, vd) = run(web, "volumes", LongSyntaxKey::Volumes);
    assert_eq!(vols, vec!["models:/models:ro", "./data:/data"]);
    assert_eq!(vd, vec![LongSyntaxDropReason::VolumeTypeUnsupported]);

    let (secrets, sd) = run(web, "secrets", LongSyntaxKey::Secrets);
    assert_eq!(secrets, vec!["api_key"]);
    assert_eq!(sd, vec![LongSyntaxDropReason::UnsupportedField]);

    let (configs, cd) = run(web, "configs", LongSyntaxKey::Configs);
    assert_eq!(configs, vec!["app_conf"]);
    assert!(cd.is_empty());

    let (tmpfs, td) = run(web, "tmpfs", LongSyntaxKey::Tmpfs);
    assert!(tmpfs.is_empty());
    assert_eq!(td, vec![LongSyntaxDropReason::NoLongSyntax]);

    let (dev, dd) = run(web, "devices", LongSyntaxKey::Devices);
    assert!(dev.is_empty());
    assert_eq!(dd, vec![LongSyntaxDropReason::NoLongSyntax]);

    // stack の Service へ載せて TOML 往復しても値が保たれる。
    let toml_src = format!(
        "image = \"busybox\"\nports = {ports:?}\nvolumes = {vols:?}\nsecrets = {secrets:?}\nconfigs = {configs:?}\n"
    );
    let svc: Service = toml::from_str(&toml_src).unwrap();
    assert_eq!(svc.ports, ports);
    assert_eq!(svc.volumes, vols);
    assert_eq!(svc.secrets, secrets);
    assert_eq!(svc.configs, configs);
}
