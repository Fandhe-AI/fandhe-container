//! oci の `IdMap` と core の `IdMapSet`（#2009・本番 launcher の範囲写像）の検証規則が一致することの機械照合
//! （SEC-5・OCI-1・#2225・REPAIR-12）。oci は core に依存しない（core は dev-dependency だけ）ため型を共有せず、
//! 同じ入力の表で受理 / 拒否・拒否の code・受理した写像の結果が食い違わないことをここで確かめる。
// core の `exec`・`rootless` は Linux 限定のため、この照合も Linux でだけ行う。
#![cfg(target_os = "linux")]

use fandhe_container_core::exec::IdMapping;
use fandhe_container_core::rootless::IdMapSet;
use fandhe_container_oci::layer::idmap::{IdMap, IdRange};

fn r(c: u32, h: u32, n: u32) -> (u32, u32, u32) {
    (c, h, n)
}

fn table() -> Vec<Vec<(u32, u32, u32)>> {
    let mut t = vec![
        vec![],
        vec![r(0, 1000, 1)],
        vec![r(0, 100_000, 1), r(1, 100_001, 65_535)],
        vec![r(0, 1, 0)],
        vec![r(0, 0, 1)],
        vec![r(0, 100_000, 1), r(1, 0, 5)],
        vec![r(1, 1000, 5)],
        vec![r(0, 10, 5), r(1, 100, 1)],
        vec![r(0, 10, 5), r(100, 12, 1)],
        vec![r(0, 1, u32::MAX), r(u32::MAX, 5, 2)],
        vec![r(0, u32::MAX, 2)],
        vec![r(0, 5, 1), r(u32::MAX - 2, u32::MAX - 2, 2)],
        vec![r(0, 5, 1), r(10, 20, 5), r(20, 30, 5)],
    ];
    // 行数の上限の前後（340 行は受理、341 行は拒否）。
    for n in [340u32, 341] {
        t.push((0..n).map(|i| r(i, 1000 + i, 1)).collect());
    }
    t
}

/// 受理 / 拒否・拒否の code・受理した写像の `map_to_host` / `host_id_of` が core と一致する。
#[test]
fn sec5_idmap_matches_core_idmapset() {
    let probes = [
        0u32,
        1,
        2,
        4,
        5,
        33,
        99,
        100,
        339,
        340,
        1000,
        65_535,
        65_536,
        70_000,
        u32::MAX - 1,
        u32::MAX,
    ];
    let mut accepted = 0;
    let mut rejected = 0;
    for (i, lines) in table().into_iter().enumerate() {
        let core = IdMapSet::new(
            lines
                .iter()
                .map(|&(c, h, n)| IdMapping {
                    container_id: c,
                    host_id: h,
                    count: n,
                })
                .collect(),
        );
        let oci = IdMap::new(
            lines
                .iter()
                .map(|&(c, h, n)| IdRange {
                    container_id: c,
                    host_id: h,
                    count: n,
                })
                .collect(),
        );
        match (core, oci) {
            (Ok(c), Ok(o)) => {
                accepted += 1;
                for p in probes {
                    assert_eq!(o.map_to_host(p), c.host_id_of(p), "case {i} probe {p}");
                }
            }
            (Err(c), Err(o)) => {
                rejected += 1;
                assert_eq!(
                    format!("{:?}", c.code),
                    format!("{:?}", o.code()),
                    "case {i} error code"
                );
            }
            (c, o) => panic!("case {i}: core={c:?} oci={o:?}"),
        }
    }
    // 表が片側に偏っていないこと（受理と拒否の両方を照合している）。
    assert_eq!((accepted, rejected), (5, 10));
}

/// oci は chown の「変更なし」指定 u32::MAX をホスト範囲に含む写像を core より厳しく拒否する（意図した差。SEC-5・OCI-1）。
#[test]
fn sec5_idmap_oci_rejects_host_u32_max_unlike_core() {
    for lines in [
        vec![r(0, u32::MAX, 1)],
        vec![r(0, 1, u32::MAX)],
        vec![r(0, 5, 1), r(u32::MAX - 1, u32::MAX - 1, 2)],
    ] {
        let core = IdMapSet::new(
            lines
                .iter()
                .map(|&(c, h, n)| IdMapping {
                    container_id: c,
                    host_id: h,
                    count: n,
                })
                .collect(),
        );
        assert!(core.is_ok(), "core accepts {lines:?}");
        let oci = IdMap::new(
            lines
                .iter()
                .map(|&(c, h, n)| IdRange {
                    container_id: c,
                    host_id: h,
                    count: n,
                })
                .collect(),
        );
        assert_eq!(
            format!("{:?}", oci.unwrap_err().code()),
            "InvalidArgument",
            "{lines:?}"
        );
    }
}

/// `/proc/self/{uid,gid}_map` の解析（`parse_proc_id_map`）が core の `parse_id_map` と同じ入力で同じ受理 / 拒否・
/// 同じ行を返す（OCI-2・SEC-5・#2382・REPAIR-12）。
#[test]
fn oci2_parse_proc_id_map_matches_core() {
    use fandhe_container_core::rootless::parse_id_map;
    use fandhe_container_oci::layer::idmap::parse_proc_id_map;

    let many = |n: u32| -> String { (0..n).map(|i| format!("{i} {} 1\n", 1000 + i)).collect() };
    let inputs: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"         0       1000          1\n".to_vec(),
        b"0 1000 1\n1 100000 65536\n".to_vec(),
        b"0 1000 1".to_vec(),
        b"\n  \n0 1 1\n".to_vec(),
        b"0 1000\n".to_vec(),
        b"0 1000 1 9\n".to_vec(),
        b"a b c\n".to_vec(),
        b"0 1000 4294967296\n".to_vec(),
        b"-1 0 1\n".to_vec(),
        b"\xff\xfe\n".to_vec(),
        many(340).into_bytes(),
        many(341).into_bytes(),
    ];
    let (mut ok, mut ng) = (0, 0);
    for (i, input) in inputs.iter().enumerate() {
        match (parse_id_map(input), parse_proc_id_map(input)) {
            (Ok(c), Ok(o)) => {
                ok += 1;
                let c: Vec<(u32, u32, u32)> = c
                    .iter()
                    .map(|m| (m.container_id, m.host_id, m.count))
                    .collect();
                let o: Vec<(u32, u32, u32)> = o
                    .iter()
                    .map(|m| (m.container_id, m.host_id, m.count))
                    .collect();
                assert_eq!(c, o, "case {i}");
            }
            (Err(_), Err(_)) => ng += 1,
            (c, o) => panic!("case {i}: core={c:?} oci={o:?}"),
        }
    }
    assert_eq!((ok, ng), (6, 7));
}
