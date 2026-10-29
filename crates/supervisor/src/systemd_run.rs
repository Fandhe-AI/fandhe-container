//! `systemd-run` の探索と信頼判定、実行ユーザーの判定（CORE-3・CORE-4・PLUG-11・CLI-1・#2133）。
//!
//! [`crate::start_client`]（`start` の事前検査。CLI の `start` と plugin-cri の `start` が共有。#2434）と、CLI の `doctor`
//! （CORE-3 の前提の診断）から使われる Linux 専用の共通部で、どちらも同じ基準で `systemd-run` を判定するために
//! supervisor crate に置く（元は CLI の `user_scope`。移設は #2434・REPAIR-1）。user マネージャへの到達検査は
//! [`crate::user_scope`]（ベンチと共有）にある。
//!
//! # 探索と信頼の基準
//! - 探索先は固定候補だけで `PATH` は探さない。PLUG-11 は `PATH` 探索の opt-in に「発見ごとの警告」を求めるが、`start` の
//!   stderr は「失敗時に 1 行の JSON」という契約で成功時に警告を混ぜられない。supervisor へ渡す `PATH` も固定値であり、
//!   呼び出し元の `PATH` を信頼の根拠にしない方針と揃える。信頼の基準は場所に依らず同じなので、`PATH` を探しても
//!   通るものは増えない。
//! - 所有者・モードの判定は PLUG-11 と同じ関数（`plugin_trust::check_owner_and_mode`）を呼ぶ。所有者は root か実効 UID、
//!   group / other 書き込み不可、sticky でも例外にしない。symlink は `canonicalize` した実体で判定し、実体の祖先ディレクトリも
//!   同じ基準で確かめる。実体は実行ビットのある通常ファイルとする。
//! - 実効 UID 所有を許すが権限の境界は増えない: rootful は `start` が先に拒否するため euid は 0 でなく、CLI・supervisor・
//!   systemd-run は同じ uid で動き、同じ uid の書き手はもともと CLI 自身も差し替えられる。
//! - ハッシュの許可一覧は適用しない（systemd-run は配布物の一部でハッシュを固定できない）。
//! - 検証から exec までの TOCTOU は、信頼できる所有者だけが書ける場所に限ることで抑える。fd 経由の検証は
//!   特権ランチャー（#1719）の責務とする。
//!
//! # 既知の限界（NixOS）
//! マルチユーザー構成の Nix では `/run/current-system/sw/bin/systemd-run` の実体が `/nix/store/...` にあり、`/nix/store` は
//! 通常 `root:nixbld 1775`（group 書き込み可・sticky）である。上の基準では祖先の検査で拒否される。この点は実機で確かめて
//! いない。sticky 付きの祖先を例外にするかは PLUG-11 の文言に関わるオーナー判断であり、ここでは例外を作らない（安全側）。

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::privilege::{MAX_STATUS_BYTES, parse_proc_status};
use fandhe_container_core::plugin_trust::{PluginTrustErrorKind, check_owner_and_mode};

/// systemd-run の固定の探索先。先頭 4 つは supervisor へ渡す固定 `PATH` と同じ順序、末尾は NixOS の system profile。
pub const SYSTEMD_RUN_DIRS: [&str; 5] = [
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/run/current-system/sw/bin",
];

/// 固定候補に置く systemd-run の実行ファイル名。
pub const SYSTEMD_RUN_NAME: &str = "systemd-run";

/// 固定候補の絶対パス（本番）。
pub fn systemd_run_candidates() -> Vec<PathBuf> {
    SYSTEMD_RUN_DIRS
        .iter()
        .map(|d| Path::new(d).join(SYSTEMD_RUN_NAME))
        .collect()
}

/// systemd-run を採用できない理由（`ancestor` は実体ではなく祖先ディレクトリが原因であることを表す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdRunRejection {
    /// どの候補も存在しない（`canonicalize` できない）。
    NotFound,
    /// メタデータを読めない。
    Unreadable,
    /// 実体（祖先なら祖先）が通常ファイル（ディレクトリ）でない。
    NotRegularFile,
    /// 実体に実行ビットが無い。
    NoExecuteBit,
    /// 所有者が root でも実効 UID でもない。
    UntrustedOwner { ancestor: bool },
    /// group または other に書き込みビットがある。
    GroupOrOtherWritable { ancestor: bool },
}

fn map_trust(kind: PluginTrustErrorKind, ancestor: bool) -> SystemdRunRejection {
    match kind {
        PluginTrustErrorKind::UntrustedOwner => SystemdRunRejection::UntrustedOwner { ancestor },
        _ => SystemdRunRejection::GroupOrOtherWritable { ancestor },
    }
}

/// 固定候補から systemd-run の実体を決める（`PATH` 探索をしない）。
///
/// 最初に `canonicalize` できた候補（usrmerge の `/bin -> usr/bin` を解く）について、実体の種別・実行ビット・所有者・モードと、
/// `ancestor_floor` 以下の祖先ディレクトリの種別・所有者・モードを確かめる。本番は `ancestor_floor = "/"`。
/// 試験は一時ディレクトリを floor にして成功経路を確かめる。
pub fn resolve_systemd_run(
    candidates: &[&Path],
    euid: u32,
    ancestor_floor: &Path,
) -> Result<PathBuf, SystemdRunRejection> {
    let real = candidates
        .iter()
        .find_map(|c| std::fs::canonicalize(c).ok())
        .ok_or(SystemdRunRejection::NotFound)?;
    let meta = std::fs::metadata(&real).map_err(|_| SystemdRunRejection::Unreadable)?;
    if !meta.is_file() {
        return Err(SystemdRunRejection::NotRegularFile);
    }
    if meta.mode() & 0o111 == 0 {
        return Err(SystemdRunRejection::NoExecuteBit);
    }
    check_owner_and_mode(meta.uid(), meta.mode(), euid).map_err(|k| map_trust(k, false))?;
    for dir in real.ancestors().skip(1) {
        if !dir.starts_with(ancestor_floor) {
            break;
        }
        let m = std::fs::metadata(dir).map_err(|_| SystemdRunRejection::Unreadable)?;
        if !m.is_dir() {
            return Err(SystemdRunRejection::NotRegularFile);
        }
        check_owner_and_mode(m.uid(), m.mode(), euid).map_err(|k| map_trust(k, true))?;
    }
    Ok(real)
}

/// 実行ユーザーの判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// real / effective / saved / fs の uid がすべて 0 でない。値は実効 UID。
    Rootless { euid: u32 },
    /// uid のどれかが 0（SEC-5。rootful は未対応）。
    Rootful,
    /// `/proc/self/status` を解釈できない。
    Unreadable,
}

/// `/proc/self/status` の本文から実行ユーザーを判定する（純関数。supervisor の `privilege_for_status` と同じ基準）。
pub fn identity_from_status(status_text: &str) -> Identity {
    let Ok(snapshot) = parse_proc_status(status_text) else {
        return Identity::Unreadable;
    };
    let uid = snapshot.uid;
    if [uid.real, uid.effective, uid.saved, uid.fs].contains(&0) {
        Identity::Rootful
    } else {
        Identity::Rootless {
            euid: uid.effective,
        }
    }
}

/// `/proc/self/status` を上限つきで読む（読めなければ `None`）。
pub fn read_self_status() -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open("/proc/self/status").ok()?;
    let mut text = String::new();
    file.take(MAX_STATUS_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 第 2 要素は残骸を消して作った実体（Drop で後始末する。REPAIR-12・#3435）。
    struct TmpDir(PathBuf, #[allow(dead_code)] crate::test_root::TestRoot);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("fc-usc-{tag}-{}-{n}", std::process::id()));
            // 残骸・PID 再利用との衝突を避けるため作成前に削除する（0700。REPAIR-12・#3435）。
            let root = crate::test_root::test_root_at(p.clone());
            Self(std::fs::canonicalize(&p).expect("canon"), root)
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn self_uid() -> u32 {
        std::fs::metadata("/proc/self").expect("meta").uid()
    }

    /// CORE-3: 固定候補の並び。`PATH` 由来の要素は無く、末尾が NixOS の system profile。
    #[test]
    fn core3_candidates_are_fixed() {
        let got: Vec<String> = systemd_run_candidates()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(
            got,
            [
                "/usr/sbin/systemd-run",
                "/usr/bin/systemd-run",
                "/sbin/systemd-run",
                "/bin/systemd-run",
                "/run/current-system/sw/bin/systemd-run"
            ]
        );
    }

    /// CLI-1・PLUG-11: 解決の各分岐。実効 UID 所有は通り、他人所有・書き込み可・sticky 付き祖先・非通常ファイル・
    /// 実行ビット無しは理由つきで拒否し、symlink 経由なら実体のパスを返す。
    #[test]
    fn cli1_plug11_systemd_run_resolution() {
        let tmp = TmpDir::new("res");
        let me = self_uid();
        let floor = tmp.0.clone();
        let bin = floor.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        set_mode(&bin, 0o755);
        let exe = bin.join("systemd-run");

        let missing = bin.join("nope");
        assert_eq!(
            resolve_systemd_run(&[missing.as_path()], me, &floor),
            Err(SystemdRunRejection::NotFound)
        );

        std::fs::write(&exe, b"#!/bin/sh\n").expect("write");
        for (mode, want) in [
            (
                0o775,
                SystemdRunRejection::GroupOrOtherWritable { ancestor: false },
            ),
            (
                0o757,
                SystemdRunRejection::GroupOrOtherWritable { ancestor: false },
            ),
            (0o644, SystemdRunRejection::NoExecuteBit),
        ] {
            set_mode(&exe, mode);
            assert_eq!(
                resolve_systemd_run(&[exe.as_path()], me, &floor),
                Err(want),
                "mode {mode:o}"
            );
        }
        set_mode(&exe, 0o755);
        // 実効 UID 所有は通る。root でも実効 UID でもない所有者（me+1 が実効 UID だと見なした場合）は拒否する。
        assert_eq!(
            resolve_systemd_run(&[exe.as_path()], me, &floor).as_deref(),
            Ok(exe.as_path())
        );
        if me != 0 {
            assert_eq!(
                resolve_systemd_run(&[exe.as_path()], me.wrapping_add(1), &floor),
                Err(SystemdRunRejection::UntrustedOwner { ancestor: false })
            );
        }
        assert_eq!(
            resolve_systemd_run(&[bin.as_path()], me, &floor),
            Err(SystemdRunRejection::NotRegularFile)
        );
        assert_eq!(
            resolve_systemd_run(&[missing.as_path(), exe.as_path()], me, &floor).as_deref(),
            Ok(exe.as_path())
        );
        // 祖先ディレクトリが group 書き込み可なら ancestor 付きで拒否する。
        set_mode(&bin, 0o775);
        assert_eq!(
            resolve_systemd_run(&[exe.as_path()], me, &floor),
            Err(SystemdRunRejection::GroupOrOtherWritable { ancestor: true })
        );
        // sticky 付きでも例外にしない（PLUG-11）。
        set_mode(&bin, 0o1777);
        assert_eq!(
            resolve_systemd_run(&[exe.as_path()], me, &floor),
            Err(SystemdRunRejection::GroupOrOtherWritable { ancestor: true })
        );
        set_mode(&bin, 0o755);
        // symlink 経由の候補は実体のパスを返す。
        let link_dir = floor.join("link");
        std::os::unix::fs::symlink(&bin, &link_dir).expect("symlink");
        let via = link_dir.join("systemd-run");
        assert_eq!(
            resolve_systemd_run(&[via.as_path()], me, &floor).as_deref(),
            Ok(exe.as_path())
        );
    }

    /// SEC-5: uid のどれかが 0 なら Rootful、全部非 0 なら実効 UID、壊れた入力は Unreadable。
    #[test]
    fn sec5_identity_from_status() {
        let status = |uid: &str| {
            format!(
                "Name:\tx\nUid:\t{uid}\nGid:\t1000\t1000\t1000\t1000\nGroups:\t\nNoNewPrivs:\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"
            )
        };
        assert_eq!(
            identity_from_status(&status("1000\t1001\t1002\t1003")),
            Identity::Rootless { euid: 1001 }
        );
        assert_eq!(
            identity_from_status(&status("1000\t1000\t0\t1000")),
            Identity::Rootful
        );
        assert_eq!(identity_from_status("garbage"), Identity::Unreadable);
    }
}
