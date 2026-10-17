//! 起動する外部実行ファイル（supervisor の bin・`systemd-run`）の事前検証（TASK-190・OWASP 不安全な設計）。
//!
//! ベンチは `--supervisor-bin` / `--systemd-run` で受けた絶対パスを起動する。他ユーザーが差し替えられる実行ファイルを
//! 起動しないよう、起動前に所有者・書き込み権限・symlink・全祖先ディレクトリを検証する。検証から exec までの TOCTOU は
//! 残る（開発者のローカル target ディレクトリを対象とする計測道具のため許容し、doc に記す）。
//! `std::os::unix::fs::MetadataExt` だけで行い、`unsafe` は使わない。

use super::StartupLatencyError;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

fn untrusted(message: &str) -> StartupLatencyError {
    StartupLatencyError::new("untrusted-binary", message)
}

/// 実行ファイルを検証する。絶対パス・symlink でない通常ファイル・実行ビットあり・group/other 書き込み不可・
/// 所有者が `euid` か root・全祖先ディレクトリ（字面上と実体の両方）が実効 UID か root 所有で other 書き込み不可・group 書き込み不可（sticky 付きは可）、をすべて満たさなければ拒否する。
///
/// 成功時は検証に使った実体パス（canonicalize 済み）を返す。呼び出し側は起動にこのパスだけを使うこと。
/// 元の字面のパスで起動すると、symlink 解決途中の経路（別 UID 所有のディレクトリ経由の redirect 等）が
/// 検証後に差し替えられ、検証していない実行ファイルを起動できてしまう。実体パスは symlink を含まず、
/// その全祖先を下で検証している。
pub fn verify_executable(path: &Path, euid: u32) -> Result<PathBuf, StartupLatencyError> {
    if !path.is_absolute() {
        return Err(StartupLatencyError::new(
            "invalid-args",
            "executable path must be absolute",
        ));
    }
    let meta =
        std::fs::symlink_metadata(path).map_err(|_| untrusted("executable is not accessible"))?;
    check_body(&meta, euid)?;
    // 字面上の祖先と、symlink を解決した実体の祖先の両方を検証する。symlink の差し替えにはそれを置く
    // ディレクトリの書き込み権が要るため、字面上の祖先の検証がそれも覆う。
    let real =
        std::fs::canonicalize(path).map_err(|_| untrusted("executable is not accessible"))?;
    for chain in [path, real.as_path()] {
        for dir in chain.ancestors().skip(1) {
            verify_ancestor(dir, euid)?;
        }
    }
    // 解決途中の symlink が検証した本体と別の実体を指す場合に備え、起動に使う実体パスの本体も再検証する。
    let real_meta =
        std::fs::symlink_metadata(&real).map_err(|_| untrusted("executable is not accessible"))?;
    check_body(&real_meta, euid)?;
    Ok(real)
}

/// 実行ファイル本体のメタデータ検証（通常ファイル・実行ビット・group/other 書き込み不可・所有者）。
fn check_body(meta: &std::fs::Metadata, euid: u32) -> Result<(), StartupLatencyError> {
    if !meta.file_type().is_file() {
        return Err(untrusted(
            "executable must be a regular file, not a symlink",
        ));
    }
    let mode = meta.mode();
    if mode & 0o111 == 0 {
        return Err(untrusted("executable has no execute bit"));
    }
    if mode & 0o022 != 0 {
        return Err(untrusted("executable is writable by group or others"));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(untrusted("executable owner is neither the caller nor root"));
    }
    Ok(())
}

/// 祖先ディレクトリ 1 つを検証する。ディレクトリで、所有者が `euid` か root で、group / other 書き込み不可であること。
/// 実効 GID はユーザー専用 group とは限らず、同じ group の別 UID が検証後に実行ファイルを差し替えられるため、
/// group 書き込み可は（自分の group でも）拒否する。umask 002 で `target/` が 0775 になる環境では
/// `chmod g-w` した場所へバイナリを置く。sticky ビット付きは `/tmp` のように他者が差し替えられないため許容する。
fn verify_ancestor(dir: &Path, euid: u32) -> Result<(), StartupLatencyError> {
    // symlink 自体の所有者を先に検証する。`metadata` は symlink を辿るため、別 UID 所有の symlink が
    // 信頼済みディレクトリを指す配置（sticky 共有ディレクトリ内で所有者が差し替えられる）を見逃す。
    let link_meta = std::fs::symlink_metadata(dir)
        .map_err(|_| untrusted("ancestor directory is not accessible"))?;
    if link_meta.file_type().is_symlink() && link_meta.uid() != euid && link_meta.uid() != 0 {
        return Err(untrusted(
            "ancestor symlink owner is neither the caller nor root",
        ));
    }
    let meta =
        std::fs::metadata(dir).map_err(|_| untrusted("ancestor directory is not accessible"))?;
    if !meta.is_dir() {
        return Err(untrusted("ancestor is not a directory"));
    }
    ancestor_verdict(meta.uid(), meta.mode(), euid).map_err(untrusted)
}

/// 祖先ディレクトリのメタデータ（所有者 UID・mode）だけで決まる判定。ファイルシステムに触れない純関数。
/// 所有者が `euid` か root でなければ拒否し、sticky なしで other / group 書き込み可なら拒否する。
fn ancestor_verdict(owner: u32, mode: u32, euid: u32) -> Result<(), &'static str> {
    if owner != euid && owner != 0 {
        return Err("ancestor directory owner is neither the caller nor root");
    }
    if mode & 0o1000 == 0 {
        if mode & 0o002 != 0 {
            return Err("ancestor directory is writable by others");
        }
        if mode & 0o020 != 0 {
            return Err("ancestor directory is writable by a group");
        }
    }
    Ok(())
}

/// 作業ディレクトリを作る親 `base` を検証し、実体パス（canonicalize 済み）を返す（TASK-190・OWASP 不安全な設計）。
///
/// `base` 自身と、字面上・実体の全祖先が `verify_executable` と同じ基準（所有者は `euid` か root・
/// group / other 書き込み不可、sticky 付きは可）を満たさなければ `untrusted-work-dir` で拒否する。
/// 祖先を別ユーザーが差し替えられると、作業ディレクトリを rename で別の場所へ向けられ、後続の
/// コピーが呼び出しユーザーの任意のファイルへ書いてしまうため。呼び出し側は返したパスだけを使う。
pub fn verify_work_base(base: &Path, euid: u32) -> Result<PathBuf, StartupLatencyError> {
    verify_dir_chain(base, euid, "untrusted-work-dir")
}

/// 結果の出力先 `path`（`--output`）を計測の開始前に検証する（TASK-190・REPAIR-5・OWASP 不安全な設計）。
///
/// 親ディレクトリを `verify_work_base` と同じ基準で検証し（コード `untrusted-output`）、出力先がすでに
/// 存在する（FIFO・symlink・通常ファイルを問わず）なら拒否する。計測後の書き込みが FIFO で無期限に停止したり、
/// symlink の参照先を上書きしたりするのを避ける。書き込みは `output::write_new` の `create_new` が担う。
/// 成功時は検証済みの実体の親とファイル名を結合したパスを返し、呼び出し側はそのパスだけを書き込みに使う
/// （解決途中の中間 symlink を検証後に差し替えられても別の場所へ作らせない）。
pub fn verify_output_target(path: &Path, euid: u32) -> Result<PathBuf, StartupLatencyError> {
    let deny = |m: &str| StartupLatencyError::new("untrusted-output", m);
    let parent = path
        .parent()
        .ok_or_else(|| deny("output path has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| deny("output path has no file name"))?;
    let real_parent = verify_dir_chain(parent, euid, "untrusted-output")?;
    let target = real_parent.join(name);
    match std::fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(target),
        Err(_) => Err(deny("output path is not accessible")),
        Ok(_) => Err(deny("output path already exists")),
    }
}

fn verify_dir_chain(
    base: &Path,
    euid: u32,
    code: &'static str,
) -> Result<PathBuf, StartupLatencyError> {
    let deny = |m: &str| StartupLatencyError::new(code, m);
    if !base.is_absolute() {
        return Err(StartupLatencyError::new(
            "invalid-args",
            "work directory must be absolute",
        ));
    }
    let real = std::fs::canonicalize(base).map_err(|_| deny("work directory is not accessible"))?;
    for chain in [base, real.as_path()] {
        for dir in chain.ancestors() {
            verify_ancestor(dir, euid).map_err(|e| deny(&e.message))?;
        }
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::super::probe_env::effective_uid;
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// 0700 の専用ディレクトリ（テスト後に削除）。
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir()
                .join(format!("fc-bincheck-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let f = self.0.join(name);
            std::fs::write(&f, b"x").expect("write");
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).expect("chmod");
            f
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn euid() -> u32 {
        effective_uid().expect("euid")
    }

    #[test]
    fn ancestor_verdict_matches_owner_and_mode_rules() {
        // 自分・root 所有で 0755 は可。
        assert_eq!(ancestor_verdict(1000, 0o755, 1000), Ok(()));
        assert_eq!(ancestor_verdict(0, 0o755, 1000), Ok(()));
        // 別ユーザー所有は拒否。
        assert!(ancestor_verdict(1001, 0o755, 1000).is_err());
        // other / group 書き込み可（sticky なし）は拒否。
        assert!(ancestor_verdict(0, 0o777, 1000).is_err());
        assert!(ancestor_verdict(1000, 0o775, 1000).is_err());
        // sticky 付き（/tmp 型）は許す。
        assert_eq!(ancestor_verdict(0, 0o1777, 1000), Ok(()));
    }

    #[test]
    fn output_target_must_be_new_in_a_trusted_parent() {
        let d = Dir::new("out");
        let got = verify_output_target(&d.0.join("r.json"), euid()).expect("ok");
        assert_eq!(
            got,
            std::fs::canonicalize(&d.0).expect("canon").join("r.json")
        );
        // 既存の通常ファイル・symlink・FIFO 相当の存在は拒否する（開かない）。
        let existing = d.file("exists.json", 0o600);
        let e = verify_output_target(&existing, euid()).unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            ("untrusted-output", "output path already exists")
        );
        let link = d.0.join("link.json");
        std::os::unix::fs::symlink(&existing, &link).expect("symlink");
        assert_eq!(
            verify_output_target(&link, euid()).unwrap_err().code,
            "untrusted-output"
        );
        let dangling = d.0.join("dangling.json");
        std::os::unix::fs::symlink(d.0.join("nowhere"), &dangling).expect("symlink");
        assert_eq!(
            verify_output_target(&dangling, euid()).unwrap_err().message,
            "output path already exists"
        );
    }

    #[test]
    fn output_target_with_untrusted_parent_is_rejected() {
        let d = Dir::new("outp");
        let sub = d.0.join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let e = verify_output_target(&sub.join("r.json"), euid()).unwrap_err();
        assert_eq!(e.code, "untrusted-output");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert_eq!(
            verify_output_target(&d.0.join("missing").join("r.json"), euid())
                .unwrap_err()
                .code,
            "untrusted-output"
        );
    }

    #[test]
    fn output_target_returns_the_resolved_parent_path() {
        let d = Dir::new("outres");
        let real = d.0.join("real");
        std::fs::create_dir(&real).expect("mkdir");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let got = verify_output_target(&link.join("r.json"), euid()).expect("ok");
        assert_eq!(
            got,
            std::fs::canonicalize(&real).expect("canon").join("r.json")
        );
    }

    #[test]
    fn work_base_accepts_private_dir_and_returns_real_path() {
        let d = Dir::new("wbok");
        let real = verify_work_base(&d.0, euid()).expect("ok");
        assert_eq!(real, std::fs::canonicalize(&d.0).expect("canon"));
    }

    #[test]
    fn work_base_rejects_relative_and_missing() {
        assert_eq!(
            verify_work_base(Path::new("rel"), euid()).unwrap_err().code,
            "invalid-args"
        );
        let d = Dir::new("wbmiss");
        assert_eq!(
            verify_work_base(&d.0.join("none"), euid())
                .unwrap_err()
                .code,
            "untrusted-work-dir"
        );
    }

    #[test]
    fn work_base_with_other_writable_ancestor_is_rejected() {
        let d = Dir::new("wbww");
        let sub = d.0.join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let e = verify_work_base(&sub, euid()).unwrap_err();
        assert_eq!(e.code, "untrusted-work-dir");
        assert_eq!(e.message, "ancestor directory is writable by others");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    #[test]
    fn work_base_with_foreign_owner_is_rejected_when_euid_differs() {
        // 自分所有のディレクトリを「別ユーザーの euid」で検証すると、所有者不一致で拒否される。
        let d = Dir::new("wbown");
        let other = euid().wrapping_add(12345);
        assert_eq!(
            verify_work_base(&d.0, other).unwrap_err().code,
            "untrusted-work-dir"
        );
    }

    #[test]
    fn work_base_through_symlink_is_resolved_and_ancestors_checked() {
        let d = Dir::new("wbsym");
        let target = d.0.join("t");
        std::fs::create_dir(&target).expect("mkdir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = d.0.join("l");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let real = verify_work_base(&link, euid()).expect("ok");
        assert_eq!(real, std::fs::canonicalize(&target).expect("canon"));
    }

    #[test]
    fn regular_0755_file_is_accepted() {
        let d = Dir::new("ok");
        let f = d.file("bin", 0o755);
        assert_eq!(
            verify_executable(&f, euid()),
            Ok(std::fs::canonicalize(&f).expect("canon"))
        );
    }

    #[test]
    fn symlink_is_rejected() {
        let d = Dir::new("sym");
        let target = d.file("real", 0o755);
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            verify_executable(&link, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    #[test]
    fn group_other_writable_is_rejected() {
        let d = Dir::new("w");
        assert_eq!(
            verify_executable(&d.file("bin", 0o777), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    /// 自分の group でも group 書き込み可の祖先は拒否する（同 group の別 UID による差し替えを防ぐ）。
    #[test]
    fn group_writable_ancestor_is_rejected_even_for_own_group() {
        let d = Dir::new("og");
        let sub = d.0.join("target");
        std::fs::create_dir(&sub).expect("mkdir");
        let f = sub.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        assert_eq!(
            verify_executable(&f, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    /// group 書き込み不可（0755）の祖先配下は受け入れる。
    #[test]
    fn non_group_writable_ancestor_is_accepted() {
        let d = Dir::new("ng");
        let f = d.file("bin", 0o755);
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(verify_executable(&f, euid()).is_ok());
    }

    /// 祖先が other 書き込み可（sticky なし）なら、実行ファイル自体が 0755 でも拒否する。
    #[test]
    fn other_writable_ancestor_is_rejected() {
        let d = Dir::new("gw");
        let sub = d.0.join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let f = sub.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        // 直近の親ではなく祖先（d.0）を group 書き込み可にする。
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o707)).expect("chmod");
        assert_eq!(
            verify_executable(&f, euid()).expect_err("reject").code,
            "untrusted-binary"
        );
    }

    /// 祖先の所有者が自分でも root でもなければ拒否する（euid を偽って照合する）。
    #[test]
    fn foreign_owned_ancestor_is_rejected() {
        let d = Dir::new("fa");
        let dir_owner = std::fs::metadata(&d.0).expect("meta").uid();
        if dir_owner != 0 {
            assert_eq!(
                verify_ancestor(&d.0, dir_owner.wrapping_add(1))
                    .expect_err("reject")
                    .code,
                "untrusted-binary"
            );
        }
    }

    /// symlink 経由で other 書き込み可の実体ディレクトリへ出る配置も拒否する。
    #[test]
    fn symlinked_ancestor_into_writable_dir_is_rejected() {
        let d = Dir::new("sl");
        let real = d.0.join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let f = real.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o757)).expect("chmod");
        let link = d.0.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert_eq!(
            verify_executable(&link.join("bin"), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    /// 別 UID 所有の祖先 symlink は、指す先が信頼済み（root 所有）でも拒否する（euid を偽って照合する）。
    #[test]
    fn foreign_owned_ancestor_symlink_is_rejected() {
        let d = Dir::new("fl");
        let link = d.0.join("link");
        std::os::unix::fs::symlink("/", &link).expect("symlink");
        let owner = std::fs::symlink_metadata(&link).expect("meta").uid();
        if owner != 0 {
            let err = verify_ancestor(&link, owner.wrapping_add(1)).expect_err("reject");
            assert_eq!(err.code, "untrusted-binary");
            assert!(err.message.contains("symlink"), "{}", err.message);
            assert_eq!(verify_ancestor(&link, owner), Ok(()));
        }
    }

    /// 解決途中の symlink（別 UID 所有の redirect 経由）で信頼済みの場所へ出る配置は、実体パスを返して
    /// 起動側が字面のパスを使わないようにする。さらに redirect 自体が別 UID 所有なら祖先として拒否する。
    #[test]
    fn redirect_through_foreign_owned_symlink_is_rejected_and_real_path_returned() {
        let d = Dir::new("rd");
        let real_dir = d.0.join("real");
        std::fs::create_dir(&real_dir).expect("mkdir");
        std::fs::set_permissions(&real_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let f = real_dir.join("bin");
        std::fs::write(&f, b"x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let redirect = d.0.join("redirect");
        std::os::unix::fs::symlink(&real_dir, &redirect).expect("symlink");
        let via = redirect.join("bin");
        // 返るのは symlink を含まない実体パス。
        assert_eq!(
            verify_executable(&via, euid()),
            Ok(std::fs::canonicalize(&f).expect("canon"))
        );
        // redirect の所有者が呼び出し元でも root でもない（euid を偽る）なら拒否する。
        let owner = std::fs::symlink_metadata(&redirect).expect("meta").uid();
        if owner != 0 {
            let err = verify_executable(&via, owner.wrapping_add(1)).expect_err("reject");
            assert_eq!(err.code, "untrusted-binary");
        }
    }

    #[test]
    fn relative_path_is_rejected() {
        assert_eq!(
            verify_executable(Path::new("rel/bin"), euid())
                .expect_err("reject")
                .code,
            "invalid-args"
        );
    }

    #[test]
    fn file_without_execute_bit_is_rejected() {
        let d = Dir::new("nx");
        assert_eq!(
            verify_executable(&d.file("bin", 0o644), euid())
                .expect_err("reject")
                .code,
            "untrusted-binary"
        );
    }

    #[test]
    fn foreign_owner_is_rejected() {
        let d = Dir::new("own");
        let f = d.file("bin", 0o755);
        // 所有者が自分でも root でもない UID を要求した場合は拒否される（euid を偽って照合する）。
        let other = euid().wrapping_add(12345);
        let file_owner = std::fs::metadata(&f).expect("meta").uid();
        if file_owner != 0 {
            assert_eq!(
                verify_executable(&f, other).expect_err("reject").code,
                "untrusted-binary"
            );
        }
    }
}
