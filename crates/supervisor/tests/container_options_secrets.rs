//! secrets / configs の指定モデルの受け入れ基準照合（SUP-12・TASK-169.4.2・#1473・MS-9・REPAIR-12）。
//!
//! 公開 API だけで文字列入力・ホストファイルから `ContainerOptions` を組み立て、core の注入仕様型
//! （`InjectedFileSet`）への変換結果を具体値で確認する。内容がエラー message と `Debug` に出ないこと、
//! 注入ディレクトリが利用者 tmpfs と重なる指定の拒否も確かめる。root 不要で既定のテスト集合で動き、3 OS 共通。
//! 実カーネルでの専用 tmpfs への書き込み・read-only 化・書き込み拒否は core の実機前提テスト
//! （`crates/core/tests/inject_files.rs`）が担う。

use fandhe_container_core::injected_files::InjectedContent;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::container_options::{
    ContainerOptions, InjectedFileOption, InjectedFileOptions, InjectedKind, InjectedSource,
    MountOptions, ShmSize, TmpfsOption,
};

/// 内容のダミー値（実際の秘密情報ではない）。
const SENTINEL: &str = "SENTINEL-DUMMY-VALUE";

fn inline(body: &str) -> InjectedSource {
    InjectedSource::Inline(InjectedContent::from_bytes(body.as_bytes().to_vec()).unwrap())
}

fn options(secrets: Vec<InjectedFileOption>, configs: Vec<InjectedFileOption>) -> ContainerOptions {
    ContainerOptions::new().with_injected_files(
        InjectedFileOptions::default()
            .with_secrets(secrets)
            .unwrap()
            .with_configs(configs)
            .unwrap(),
    )
}

/// `(マウント先, 親ディレクトリ, モード, 内容長)` の一覧。
fn summary(o: &ContainerOptions) -> Vec<(String, String, u32, usize)> {
    o.injected_files()
        .unwrap()
        .files()
        .iter()
        .map(|f| {
            (
                f.destination().as_str().to_owned(),
                f.parent().to_owned(),
                f.mode().bits(),
                f.content().len(),
            )
        })
        .collect()
}

/// AC: 名前・出所・マウント先・モードの指定が core の注入仕様へ具体値で反映される（secrets → configs の順）。
#[test]
fn sup12_task169_4_2_options_reach_core_specs() {
    let o = options(
        vec![
            InjectedFileOption::parse(
                InjectedKind::Secret,
                "source=db_password,mode=0400",
                inline(SENTINEL),
            )
            .unwrap(),
            InjectedFileOption::parse(
                InjectedKind::Secret,
                "source=api_key,target=/run/keys/api",
                inline("k"),
            )
            .unwrap(),
        ],
        vec![
            InjectedFileOption::parse(
                InjectedKind::Config,
                "source=app.conf,target=/etc/app/app.conf",
                inline("a=b"),
            )
            .unwrap(),
        ],
    );
    assert_eq!(
        summary(&o),
        [
            (
                "/run/secrets/db_password".to_owned(),
                "/run/secrets".to_owned(),
                0o400,
                SENTINEL.len()
            ),
            ("/run/keys/api".to_owned(), "/run/keys".to_owned(), 0o444, 1),
            (
                "/etc/app/app.conf".to_owned(),
                "/etc/app".to_owned(),
                0o444,
                3
            ),
        ]
    );
    let set = o.injected_files().unwrap();
    // 親ディレクトリごとに専用 tmpfs（64 KiB 単位）が決まる。
    let groups: Vec<_> = set
        .groups()
        .iter()
        .map(|g| (g.directory.to_owned(), g.files.len(), g.tmpfs_size))
        .collect();
    assert_eq!(
        groups,
        [
            ("/run/secrets".to_owned(), 1, 65_536),
            ("/run/keys".to_owned(), 1, 65_536),
            ("/etc/app".to_owned(), 1, 65_536),
        ]
    );
    // 相対 target は既定ディレクトリ配下になり、注入ディレクトリ同士が入れ子になる指定は拒否される。
    let nested = options(
        vec![
            InjectedFileOption::new(InjectedKind::Secret, "a", inline("x")).unwrap(),
            InjectedFileOption::parse(InjectedKind::Secret, "source=b,target=keys/b", inline("y"))
                .unwrap(),
        ],
        vec![],
    );
    assert_eq!(
        nested.injected_files().unwrap_err().message(),
        "injected file directories must not overlap"
    );
}

/// AC: マウント先のパス検証は tmpfs と同じ強度（`..`・rootfs 直下・予約先・入れ子）で拒否する。
#[test]
fn sup12_task169_4_2_destination_is_validated_like_tmpfs() {
    let bad = |target: &str| {
        options(
            vec![
                InjectedFileOption::new(InjectedKind::Secret, "a", inline("x"))
                    .unwrap()
                    .with_target(target)
                    .unwrap(),
            ],
            vec![],
        )
        .injected_files()
        .unwrap_err()
    };
    for (target, msg) in [
        ("/x/../../etc/shadow", "invalid injected file destination"),
        (
            "/top",
            "injected file must be placed in a directory below the root",
        ),
        (
            "/proc/self/f",
            "injected files must not be placed on /proc or below",
        ),
        ("/dev/f", "injected files must not be placed on /dev itself"),
    ] {
        let e = bad(target);
        assert_eq!(
            (e.code(), e.message()),
            (ErrorCode::InvalidArgument, msg),
            "{target}"
        );
    }
    let deep = format!("/{}", "d/".repeat(33));
    assert_eq!(
        bad(&format!("{deep}f")).message(),
        "injected file destination is too deep"
    );
}

/// AC: 注入ディレクトリが `--tmpfs` / `--shm-size` の tmpfs と重なる指定は、builder の順序によらず拒否する。
#[test]
fn sup12_task169_4_2_rejects_overlap_with_user_tmpfs() {
    let secret = || InjectedFileOption::new(InjectedKind::Secret, "a", inline("x")).unwrap();
    let mounts = |dest: &str| {
        MountOptions::default()
            .with_tmpfs(TmpfsOption::parse(dest).unwrap())
            .unwrap()
    };
    for dest in ["/run", "/run/secrets", "/run/secrets/x"] {
        let injected = InjectedFileOptions::default()
            .with_secrets(vec![secret()])
            .unwrap();
        let a = ContainerOptions::new()
            .with_injected_files(injected.clone())
            .with_mounts(mounts(dest));
        let b = ContainerOptions::new()
            .with_mounts(mounts(dest))
            .with_injected_files(injected);
        for o in [a, b] {
            assert_eq!(
                o.injected_files().unwrap_err().message(),
                "injected file directory overlaps a tmpfs mount",
                "{dest}"
            );
        }
    }
    // 重ならない `--shm-size` と併用できる。
    let ok = options(vec![secret()], vec![])
        .with_mounts(MountOptions::default().with_shm_size(ShmSize::parse("64m").unwrap()));
    assert_eq!(ok.injected_files().unwrap().files().len(), 1);
}

/// AC: ホストファイルは消費時点で読まれ、上限・種別の検査に通らないものは拒否する。内容・パスはエラーに出ない。
#[test]
fn sup12_task169_4_2_host_file_source_and_no_leak() {
    let dir = std::env::temp_dir().join(format!("fandhe-secrets-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("db_password.txt");
    std::fs::write(&path, SENTINEL).unwrap();
    let o = options(
        vec![
            InjectedFileOption::new(
                InjectedKind::Secret,
                "db_password",
                InjectedSource::File(path.clone()),
            )
            .unwrap(),
        ],
        vec![],
    );
    assert_eq!(
        summary(&o),
        [(
            "/run/secrets/db_password".to_owned(),
            "/run/secrets".to_owned(),
            0o444,
            SENTINEL.len()
        )]
    );
    // 指定モデルは出所のパスだけを保持し、内容を持たない。Debug にも出ない。
    assert!(!format!("{o:?}").contains("SENTINEL-DUMMY"));
    // 読み取りは消費時点: 削除すると次の変換が失敗し、message はパス・内容を含まない。
    std::fs::remove_file(&path).unwrap();
    let e = o.injected_files().unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (
            ErrorCode::InvalidArgument,
            "cannot open secret or config source"
        )
    );
    assert!(!e.message().contains("db_password.txt"));
    let as_dir = options(
        vec![
            InjectedFileOption::new(InjectedKind::Secret, "d", InjectedSource::File(dir.clone()))
                .unwrap(),
        ],
        vec![],
    );
    assert_eq!(
        as_dir.injected_files().unwrap_err().message(),
        "secret or config source must be a regular file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// AC: 内容は `Debug` に出ず、不正な指定のエラーにも入力値・内容が含まれない。
#[test]
fn sup12_task169_4_2_content_never_in_debug_or_errors() {
    let o = options(
        vec![InjectedFileOption::new(InjectedKind::Secret, "a", inline(SENTINEL)).unwrap()],
        vec![],
    );
    assert!(!format!("{o:?}").contains("SENTINEL"));
    assert!(!format!("{:?}", o.injected_files().unwrap()).contains("SENTINEL"));
    for spec in ["source=SENTINEL/x", "source=a,mode=SENTINEL", "SENTINEL"] {
        let e =
            InjectedFileOption::parse(InjectedKind::Secret, spec, inline(SENTINEL)).unwrap_err();
        assert!(!e.message().contains("SENTINEL"), "{spec}: {}", e.message());
    }
}
