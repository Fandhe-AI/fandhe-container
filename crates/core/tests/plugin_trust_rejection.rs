//! plugin 信頼性検証の拒否ケース結合試験（TASK-122.6・PLUG-11・REPAIR-12）。
//!
//! 公開 API（探索 → `verify_candidate` → `PluginVerificationMethod::verify`）だけを通し、
//! 他ユーザー書き込み可能ディレクトリ・許可一覧に無いハッシュ・symlink 経由の信頼できない実体の
//! 3 種の拒否を具体値（kind・target・path・reason・ErrorCode）で照合する。
//!
//! - fixture は `/` からの全祖先検証を通すため `$HOME` 直下に作る（`/tmp` は sticky の
//!   world-writable で祖先として拒否される）。ディレクトリのモードは `set_permissions` で明示し
//!   umask に依存させない。`$HOME` 自体のモードは変更しない。
//! - 別 UID（非 root）所有の実体を使う試験だけは chown（root）が要るため `#[ignore]` の
//!   実機前提テストとして分離する（AGENTS.md「実機前提テスト」・`.claude/rules/ci.md`）。
//! - 検証本体は Linux のみ実装（非 Linux は fail-closed。`plugin_trust.rs` の結合試験が担保）。
//!   実ファイル系は `cfg(target_os = "linux")`。

use fandhe_container_core::plugin_trust::{AllowedPluginHashes, Sha256Digest};

/// 一覧に無いダイジェストは `contains` が false になること（3 OS 共通の純粋確認。TASK-122.6・PLUG-11）。
#[test]
fn plug11_task122_6_unlisted_digest_is_not_contained() {
    let listed = Sha256Digest::from_hex(&"a".repeat(64)).expect("hex");
    let other = Sha256Digest::from_hex(&"b".repeat(64)).expect("hex");
    let list = AllowedPluginHashes::from_digests([listed]);
    assert_eq!(list.len(), 1);
    assert!(!list.contains(&other));
}

#[cfg(target_os = "linux")]
mod rejection {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use fandhe_container_core::plugin_discovery::{
        PluginDirKind, PluginSearchDir, discover_candidates,
    };
    use fandhe_container_core::plugin_trust::{
        AllowedPluginHashes, PluginTrustError, PluginTrustErrorKind, PluginVerificationMethod,
        TrustTarget, VerifiedPluginFile, check_owner_and_mode, verify_candidate, verify_plugin_dir,
    };
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    const NAME: &str = "fandhe-container-plugin-x";
    /// `b"payload"` の sha256。
    const PAYLOAD_SHA: &str = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5";
    /// `PAYLOAD_SHA` と一致しない任意の sha256 値。
    const OTHER_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    /// `$HOME` 直下の一意なディレクトリ。Drop で（panic 時も）削除して残骸を残さない。
    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Self {
            let home = PathBuf::from(std::env::var_os("HOME").expect("HOME must be set"));
            // 既存ディレクトリを削除しない: 名前に時刻 ns・カウンタを混ぜ、`create_dir`
            // （既存なら AlreadyExists で失敗するアトミックな新規作成）に成功したものだけを
            // 自分の所有物として Drop で削除する。衝突時は別名で再試行する。
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            for _ in 0..100 {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir = home.join(format!(
                    "fandhe-plugin-trust-it-{}-{nanos:x}-{seq}-{tag}",
                    std::process::id()
                ));
                match fs::create_dir(&dir) {
                    Ok(()) => {
                        let fixture = Self(dir);
                        chmod(&fixture.0, 0o755);
                        return fixture;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create fixture dir: {e}"),
                }
            }
            panic!("could not create a unique fixture dir under HOME");
        }

        /// 0o755 のサブディレクトリを作る。
        fn subdir(&self, name: &str) -> PathBuf {
            let d = self.0.join(name);
            fs::create_dir(&d).expect("create subdir");
            chmod(&d, 0o755);
            d
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// `dir` に 0o755 の plugin ファイル（内容 `payload`）を作る。
    fn write_plugin(dir: &Path) -> PathBuf {
        let f = dir.join(NAME);
        fs::write(&f, b"payload").expect("write plugin");
        chmod(&f, 0o755);
        f
    }

    /// 探索 → 検証の実経路で `dir` 内の唯一の候補を検証する。
    fn discover_and_verify(dir: &Path) -> Result<VerifiedPluginFile, PluginTrustError> {
        let dirs = [PluginSearchDir::new(PluginDirKind::User, dir.to_path_buf())];
        let found = discover_candidates(&dirs).expect("discover");
        assert_eq!(found.len(), 1, "exactly one candidate in {}", dir.display());
        verify_candidate(found.first().expect("candidate"))
    }

    fn assert_rejected(
        err: &PluginTrustError,
        kind: PluginTrustErrorKind,
        target: TrustTarget,
        path: &Path,
        reason: &str,
    ) {
        assert_eq!(err.kind(), kind, "{err}");
        assert_eq!(err.target(), target, "{err}");
        assert_eq!(err.path(), path, "{err}");
        assert_eq!(err.reason(), reason);
        assert_eq!(
            TraitError::from(err.clone()).code(),
            ErrorCode::PermissionDenied
        );
    }

    /// 他ユーザー書き込み可能なディレクトリ配下の plugin が拒否される（TASK-122.6・PLUG-11）。
    #[test]
    fn plug11_task122_6_rejects_other_writable_dir() {
        let fx = Fixture::new("owd");
        let dir = fx.subdir("d");
        write_plugin(&dir);

        // 対照: 0o755 なら受理される（祖先連鎖が通る環境であり、後続の拒否は当該モード起因）。
        let ok = discover_and_verify(&dir).unwrap_or_else(|e| panic!("control must pass: {e}"));
        assert_eq!(ok.mode() & 0o022, 0);
        drop(ok);

        for mode in [0o757, 0o777, 0o1777] {
            chmod(&dir, mode);
            let err = discover_and_verify(&dir)
                .map(|_| ())
                .expect_err("must reject");
            assert_rejected(
                &err,
                PluginTrustErrorKind::GroupOrOtherWritable,
                TrustTarget::Directory,
                &dir,
                "group_or_other_writable",
            );
            let err = verify_plugin_dir(&dir)
                .map(|_| ())
                .expect_err("must reject");
            assert_rejected(
                &err,
                PluginTrustErrorKind::GroupOrOtherWritable,
                TrustTarget::Directory,
                &dir,
                "group_or_other_writable",
            );
        }
    }

    /// 許可済みハッシュ一覧に無いバイナリが拒否される（TASK-122.6・PLUG-11）。
    #[test]
    fn plug11_task122_6_rejects_unlisted_hash() {
        let fx = Fixture::new("hash");
        let dir = fx.subdir("d");
        let f = write_plugin(&dir);

        let file = discover_and_verify(&dir).expect("trusted dir/file");
        // 不一致が「計算失敗」ではなく「一覧に無い」ためだと確定させる。
        assert_eq!(file.sha256().expect("digest").to_string(), PAYLOAD_SHA);

        let other = AllowedPluginHashes::parse(format!("{OTHER_SHA}  plugin-x\n").as_bytes())
            .expect("parse");
        assert_eq!(other.len(), 1);
        let err = PluginVerificationMethod::Sha256Allowlist(other)
            .verify(file)
            .map(|_| ())
            .expect_err("must reject");
        assert_rejected(
            &err,
            PluginTrustErrorKind::HashMismatch,
            TrustTarget::File,
            &f,
            "hash_mismatch",
        );

        // 対照: 実ハッシュを含む一覧なら受理される。
        let file = discover_and_verify(&dir).expect("trusted dir/file");
        let allowed = AllowedPluginHashes::parse(format!("{PAYLOAD_SHA}  plugin-x\n").as_bytes())
            .expect("parse");
        let ok = PluginVerificationMethod::Sha256Allowlist(allowed)
            .verify(file)
            .unwrap_or_else(|e| panic!("control must pass: {e}"));
        assert_eq!(ok.digest().to_string(), PAYLOAD_SHA);
    }

    /// symlink 経由で信頼できない実体を指すケースが拒否される（同一 UID 部分。TASK-122.6・PLUG-11）。
    /// 判定は symlink 自体ではなく実体の inode と実体の親ディレクトリに対して行われる。
    #[test]
    fn plug11_task122_6_rejects_symlink_to_untrusted_real_file() {
        let fx = Fixture::new("lnk");
        let link_dir = fx.subdir("links");
        let real_dir = fx.subdir("real");
        let real = write_plugin(&real_dir);
        let link = link_dir.join(NAME);
        symlink(&real, &link).expect("symlink");

        // 対照: 実体が信頼できれば受理され、path は symlink・resolved_path は実体。
        let ok = discover_and_verify(&link_dir).unwrap_or_else(|e| panic!("control: {e}"));
        assert_eq!(ok.path(), link);
        assert_eq!(ok.resolved_path(), real);
        let uid = fs::metadata(&real).expect("stat").uid();
        drop(ok);

        // 実体が other 書き込み可能。
        chmod(&real, 0o757);
        let err = discover_and_verify(&link_dir)
            .map(|_| ())
            .expect_err("must reject");
        assert_rejected(
            &err,
            PluginTrustErrorKind::GroupOrOtherWritable,
            TrustTarget::File,
            &link,
            "group_or_other_writable",
        );
        chmod(&real, 0o755);

        // 実体の親ディレクトリが world-writable（symlink 経由で逃がせない）。
        chmod(&real_dir, 0o777);
        let err = discover_and_verify(&link_dir)
            .map(|_| ())
            .expect_err("must reject");
        assert_rejected(
            &err,
            PluginTrustErrorKind::GroupOrOtherWritable,
            TrustTarget::Directory,
            &real_dir,
            "group_or_other_writable",
        );

        // 所有者判定の論理部分: root でも実行 UID でもない所有者は拒否（実ファイルは chown 要のため純関数で）。
        let stranger = if uid == 4242 { 4243 } else { 4242 };
        assert_eq!(
            check_owner_and_mode(stranger, 0o755, uid),
            Err(PluginTrustErrorKind::UntrustedOwner)
        );
    }

    const OTHER_UID_ENV: &str = "FANDHE_CONTAINER_TEST_OTHER_UID_PLUGIN";

    /// symlink 経由で別 UID 所有の実体を指すケースが拒否される（実機前提。TASK-122.6・PLUG-11）。
    /// 別の非 root UID 所有のファイルは root の chown なしに作れないため、人間が事前に用意した
    /// 絶対パスを環境変数で受け取る（手順は AGENTS.md「実機前提テスト」）。前提不備は skip せず失敗させる。
    #[test]
    #[ignore = "requires a regular file owned by another non-root UID (prepared with chown as root); PLUG-11"]
    fn plug11_task122_6_rejects_symlink_to_other_uid_owned() {
        let target = PathBuf::from(
            std::env::var_os(OTHER_UID_ENV)
                .unwrap_or_else(|| panic!("{OTHER_UID_ENV} must be set")),
        );
        assert!(target.is_absolute(), "{OTHER_UID_ENV} must be absolute");
        let md = fs::metadata(&target).expect("stat target");
        assert!(md.is_file(), "target must be a regular file");
        let me = fs::metadata(std::env::var_os("HOME").expect("HOME")).expect("stat HOME");
        assert_ne!(md.uid(), 0, "target must not be root-owned");
        assert_ne!(md.uid(), me.uid(), "target must be owned by another UID");
        assert_eq!(
            md.mode() & 0o022,
            0,
            "target must not be group/other writable"
        );

        let fx = Fixture::new("otheruid");
        let link_dir = fx.subdir("links");
        let link = link_dir.join(NAME);
        symlink(&target, &link).expect("symlink");

        let err = discover_and_verify(&link_dir)
            .map(|_| ())
            .expect_err("must reject");
        assert_rejected(
            &err,
            PluginTrustErrorKind::UntrustedOwner,
            TrustTarget::File,
            &link,
            "untrusted_owner",
        );
    }
}
