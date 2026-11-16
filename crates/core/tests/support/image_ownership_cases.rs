//! cli と plugin-cri の `image_ownership::extract_ownership_for` が、共有 fixture
//! `crates/core/testdata/image_ownership_cases.txt` の全ケースで同じ行・同じ拒否を返すことの照合ドライバ
//! （SEC-5・OCI-1・CORE-6・REPAIR-1・#4798。判断は #4777）。
//!
//! 取り込み元（2 か所。grep: `image_ownership_cases`）: `crates/cli/tests/image_ownership_fixture.rs`・
//! `crates/plugin-cri/tests/image_ownership_fixture.rs`。両者が同じ本ファイルと fixture を読むので、
//! 変換規則を片方だけ変えるとその crate の試験が落ちる。規則を変えるときは fixture と 2 か所の変換を同じ PR で直す。
//! 入力は本番と同じ `SubordinateIdSource::with_id_files` → `resolve_id_maps` の経路に通す（passwd・NSS は通さない）。
#[path = "scratch_root.rs"]
mod scratch_root;

use fandhe_container_core::oci_runtime::SubordinateIdSource;
use fandhe_container_core::traits::TraitError;
use fandhe_container_oci::layer::extract::OwnershipPolicy;
use fandhe_container_oci::layer::idmap::IdMap;
use fandhe_container_supervisor::id_model::RootlessIdResolution;

const CASES: &str = include_str!("../../testdata/image_ownership_cases.txt");

fn rows(m: &IdMap) -> String {
    m.lines()
        .iter()
        .map(|l| format!("{}:{}:{}", l.container_id, l.host_id, l.count))
        .collect::<Vec<_>>()
        .join(",")
}

fn lines_of(s: &str) -> String {
    if s == "-" {
        String::new()
    } else {
        s.split('|').map(|l| format!("{l}\n")).collect()
    }
}

/// 各 crate の `extract_ownership_for` を `convert(resolution, uid, gid, in_user_namespace)` として渡す。
pub fn run(
    convert: impl Fn(&RootlessIdResolution, u32, u32, bool) -> Result<OwnershipPolicy, TraitError>,
) {
    // 排他作成・一意名・drop（panic の unwind を含む）で削除する。
    let scratch = scratch_root::ScratchDir::new("fc-imgown-fx", std::time::Duration::from_secs(10));
    let dir = scratch.path().to_path_buf();
    let (mut singles, mut subs, mut oks, mut errs) = (0, 0, 0, 0);
    for (n, line) in CASES.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let (resolution, uid, gid, want) = match f[0] {
            "single" => {
                singles += 1;
                (RootlessIdResolution::SingleId, f[1], f[2], f[3])
            }
            "sub" => {
                subs += 1;
                let su = dir.join(format!("subuid{n}"));
                let sg = dir.join(format!("subgid{n}"));
                std::fs::write(&su, lines_of(f[4])).unwrap();
                std::fs::write(&sg, lines_of(f[5])).unwrap();
                let owner = (f[1] != "-").then(|| f[1].to_string());
                let src = SubordinateIdSource::with_id_files(owner, &su, &sg).unwrap();
                (RootlessIdResolution::SubordinateIds(src), f[2], f[3], f[6])
            }
            k => panic!("line {}: unknown kind {k}", n + 1),
        };
        let (uid, gid) = (uid.parse().unwrap(), gid.parse().unwrap());
        for in_ns in [false, true] {
            let got = convert(&resolution, uid, gid, in_ns);
            let ctx = format!("line {} in_ns={in_ns}: {line}", n + 1);
            if let Some(code) = want.strip_prefix("err:") {
                let e = got.expect_err(&ctx);
                assert_eq!(format!("{:?}", e.code()), code, "{ctx}");
                continue;
            }
            let (u, g) = want.strip_prefix("ok:").unwrap().split_once(';').unwrap();
            let p = got.expect(&ctx);
            let (pu, pg) = match (&p, in_ns) {
                (OwnershipPolicy::ChownMapped { uid, gid }, false)
                | (OwnershipPolicy::ChownInUserNamespace { uid, gid }, true) => (uid, gid),
                other => panic!("{ctx}: wrong policy kind {other:?}"),
            };
            assert_eq!(
                (rows(pu), rows(pg)),
                (u.to_string(), g.to_string()),
                "{ctx}"
            );
        }
        if want.starts_with("ok:") {
            oks += 1
        } else {
            errs += 1
        }
    }
    // 0 件・偏りで通ることを防ぐ。
    assert!(
        singles >= 3 && subs >= 10 && oks >= 5 && errs >= 6,
        "{singles} {subs} {oks} {errs}"
    );
}
