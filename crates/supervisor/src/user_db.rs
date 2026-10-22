//! `/etc/passwd` に載らないユーザー（LDAP・sssd 等）の所有者名を NSS から得る（`getent passwd <uid>`。
//! CORE-6・SEC-5・REPAIR-5・#2390。判断記録は `docs/design/subid-owner-resolution.md`）。
//!
//! # 役割
//! `id_model::resolve_rootless_id_source`（`start` と pull 時の展開の所有者）と CLI の `doctor` が呼ぶ
//! 単一の入口 `resolve_owner_name`（Linux 限定）を提供する。`/etc/passwd` に行があればそれを使い（子プロセスを
//! 起動しない）、無いときだけ固定パスの `getent` を期限つきで実行する。`/etc/subuid` の第 1 欄の名前で書かれた
//! 自分の行を、`newuidmap` と同じく NSS 上の自分の名前で照合するために必要な情報を得るのが目的である。
//!
//! # 安全側の条件
//! - 実行ファイルは固定の絶対パス候補のみ（`PATH` を探索しない）。実体と全祖先ディレクトリが root 所有で
//!   group / other から書き込めないことを確かめる。満たさなければ「利用不可」（従来どおり数値 uid の行だけで照合）。
//! - 子は環境変数を持たず（`LD_*` を渡さない）、stdin / stderr は null、ambient capability は exec 直前に消す。
//! - 期限（既定 5 秒）を超えたら kill して回収する。期限は子の終了待ちだけでなく標準出力の読み取りにも適用する
//!   （バックグラウンドの孫が標準出力を継承して EOF が来なくても期限で打ち切る。REPAIR-5）。標準出力は
//!   `UnixStream` 対の読み取り側を読み取りタイムアウトつきで読む（読み取り用スレッドも `unsafe` も使わない。
//!   `start_entry` の手順 8 より前に常駐スレッドを作らない制約）。出力は 4 KiB まで。全体期限は読み取りのたびに
//!   確認し、少量ずつ出力され続けても超えて待たない。子は専用プロセスグループで起動し、期限切れ・出力超過時は
//!   グループごと kill して孫まで後始末する（`sys::kill_process_group`）。
//! - 終了コード 2（キー無し）は、`/etc/nsswitch.conf` の passwd 系が `files` 等のローカル源だけのときに限り
//!   「名前なし」とする。LDAP・sssd 等の遠隔源があるときは NSS の障害と区別できないため `Err`（起動拒否）。
//! - 参照の失敗・不正な出力・期限切れは `Err`（fail-closed）。名前の有無を判定できないまま 1 対 1 写像へ落とさない。
//!
//! エラー文言は固定の英語で、ユーザー名・パス・errno・出力内容を含めない。

#[cfg(any(target_os = "linux", test))]
use fandhe_container_core::traits::{ErrorCode, TraitError};

#[cfg(any(target_os = "linux", test))]
use crate::id_model::owner_name_from_passwd;

/// `getent` の出力の上限（バイト）。1 エントリは通常 1 KiB 未満。
pub const MAX_GETENT_OUTPUT_BYTES: usize = 4096;

#[cfg(any(target_os = "linux", test))]
fn precondition(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, message)
}

/// `getent passwd <uid>` の標準出力から名前を取り出す（純関数・全 OS で試験できる）。
///
/// 1 件目の `名前:…:uid:…` の uid 欄が要求した `uid` と一致するときだけ採用する。上限超過・UTF-8 不正・
/// 欄不足・空の名前・uid の不一致は `FailedPrecondition`。
#[cfg(any(target_os = "linux", test))]
pub fn owner_name_from_getent(stdout: &[u8], uid: u32) -> Result<String, TraitError> {
    let bad = || precondition("the user database returned an unusable entry");
    if stdout.len() > MAX_GETENT_OUTPUT_BYTES {
        return Err(bad());
    }
    owner_name_from_passwd(stdout, uid)
        .map_err(|_| bad())?
        .ok_or_else(bad)
}

/// 名前の出所。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerNameSource {
    /// `/etc/passwd`。
    Passwd,
    /// NSS（`getent`）。
    Nss,
}

/// 所有者名の解決結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerNameResolution {
    /// 名前を得た。
    Resolved {
        /// 名前（`SubIdOwner::new` の規則の検証は呼び出し側）。
        name: String,
        /// 出所。
        source: OwnerNameSource,
    },
    /// passwd にも NSS にも行が無い（数値 uid の行だけで照合する）。
    NotFound,
    /// passwd に行が無く、信頼できる `getent` も無い（NSS を引けない。数値 uid の行だけで照合する）。
    LookupUnavailable,
}

#[cfg(target_os = "linux")]
pub use linux::{DEFAULT_GETENT_TIMEOUT, GETENT_CANDIDATES, UserDbLookup, resolve_owner_name};

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::plugin_trust::check_owner_and_mode;
    use fandhe_container_core::traits::{ErrorCode, TraitError};

    use super::{
        MAX_GETENT_OUTPUT_BYTES, OwnerNameResolution, OwnerNameSource, owner_name_from_getent,
        precondition,
    };
    use crate::id_model::read_owner_name;

    /// `getent` の固定候補（`PATH` は探索しない）。
    pub const GETENT_CANDIDATES: [&str; 5] = [
        "/usr/bin/getent",
        "/bin/getent",
        "/usr/sbin/getent",
        "/sbin/getent",
        "/run/current-system/sw/bin/getent",
    ];
    /// `getent` の期限の既定（REPAIR-5。core の `DEFAULT_HELPER_TIMEOUT` と同値）。
    pub const DEFAULT_GETENT_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(10);

    /// NSS の参照の設定（候補・期限・信頼の基準）。本番は [`UserDbLookup::system`]。
    #[derive(Debug, Clone)]
    pub struct UserDbLookup {
        candidates: Vec<PathBuf>,
        timeout: Duration,
        /// root に加えて所有者として許す uid。本番は `None`（root のみ）。
        extra_trusted_uid: Option<u32>,
        /// この配下より上の祖先は検査しない。本番は `/`。
        ancestor_floor: PathBuf,
        /// passwd 系の NSS 源を調べる `nsswitch.conf`。`None` は「ローカル源のみ」とみなす（試験用）。
        nsswitch_conf: Option<PathBuf>,
    }

    /// 終了コード 2 を「名前なし」と断定してよい（NSS の障害と取り違えない）ローカル源。
    const LOCAL_NSS_SOURCES: [&str; 6] =
        ["files", "compat", "db", "altfiles", "systemd", "usrfiles"];
    /// `nsswitch.conf` の読み取り上限（バイト）。
    const MAX_NSSWITCH_BYTES: u64 = 64 * 1024;

    /// 角括弧の動作指定を除いた源の名前の一覧。閉じていない角括弧は不正として `None`。
    fn plain_sources(rest: &str) -> Option<Vec<String>> {
        let mut in_action = false;
        let mut plain = String::new();
        for c in rest.chars() {
            match c {
                '[' => in_action = true,
                ']' => {
                    in_action = false;
                    plain.push(' ');
                }
                _ if !in_action => plain.push(c),
                _ => {}
            }
        }
        if in_action {
            return None;
        }
        Some(plain.split_whitespace().map(str::to_owned).collect())
    }

    /// `nsswitch.conf` の passwd 系（`passwd`・`passwd_compat`）の源がローカルだけか。
    /// 角括弧の動作指定（`[NOTFOUND=return]` 等）は読み飛ばす。閉じていない角括弧は不正として `false`。
    /// `passwd` が `compat` を含むとき、glibc は `passwd_compat` の既定を `nis` とするため、
    /// `passwd_compat` の行が無ければローカルのみとは証明できず `false`（CORE-6・SEC-5）。
    fn passwd_sources_all_local(text: &str) -> bool {
        let mut passwd: Option<Vec<String>> = None;
        let mut compat: Option<Vec<String>> = None;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("");
            let Some((key, rest)) = line.split_once(':') else {
                continue;
            };
            let slot = match key.trim() {
                "passwd" => &mut passwd,
                "passwd_compat" => &mut compat,
                _ => continue,
            };
            let Some(srcs) = plain_sources(rest) else {
                return false;
            };
            // 同じ鍵が複数行あれば全部を検査対象にする。
            slot.get_or_insert_with(Vec::new).extend(srcs);
        }
        let all_local = |v: &Vec<String>| v.iter().all(|t| LOCAL_NSS_SOURCES.contains(&t.as_str()));
        if !passwd.as_ref().is_none_or(all_local) {
            return false;
        }
        let uses_compat = passwd
            .as_ref()
            .is_some_and(|v| v.iter().any(|t| t == "compat"));
        match &compat {
            Some(v) => all_local(v),
            None => !uses_compat,
        }
    }

    /// 期限後の子の回収の猶予。
    const REAP_GRACE: Duration = Duration::from_secs(2);

    /// 子とその子孫（専用プロセスグループ）を kill し、有限の猶予内で子を回収する。回収できなければ `Timeout` を
    /// 返す（無期限の `wait` はしない。割り込み不能な I/O 待ちの子が SIGKILL 後も残り得るため。REPAIR-5）。
    /// 孫が標準出力を持ったまま親が先に終了・回収済みでも、グループに孫が残る間は pgid は再利用されないため
    /// グループ宛ての kill は安全に届く。グループ kill の失敗（既に空）は無視し、回収の可否で判定する。
    fn kill_and_reap(child: &mut std::process::Child) -> Result<(), TraitError> {
        let _ = crate::sys::kill_process_group(child.id());
        let _ = child.kill();
        let until = Instant::now() + REAP_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(_) => break,
            }
            if Instant::now() >= until {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(TraitError::new(
            ErrorCode::Timeout,
            "the user database helper could not be reaped",
        ))
    }

    impl UserDbLookup {
        /// 本番の設定（固定候補・5 秒・root 所有のみ・祖先は `/` まで検査）。
        #[must_use]
        pub fn system() -> Self {
            Self {
                candidates: GETENT_CANDIDATES.iter().map(PathBuf::from).collect(),
                timeout: DEFAULT_GETENT_TIMEOUT,
                extra_trusted_uid: None,
                ancestor_floor: PathBuf::from("/"),
                nsswitch_conf: Some(PathBuf::from("/etc/nsswitch.conf")),
            }
        }

        /// 試験・別配置向け。root に加えて `extra_trusted_uid` 所有の実体を許し、祖先の検査を `ancestor_floor` で止める。
        /// 本番の入口（`start`・`doctor`・pull の展開）は [`Self::system`] だけを使う。期限は 1..=60 秒に丸める。
        #[must_use]
        pub fn custom(
            candidates: Vec<PathBuf>,
            timeout: Duration,
            extra_trusted_uid: Option<u32>,
            ancestor_floor: PathBuf,
        ) -> Self {
            Self {
                candidates,
                timeout: timeout.clamp(Duration::from_secs(1), MAX_TIMEOUT),
                extra_trusted_uid,
                ancestor_floor,
                nsswitch_conf: None,
            }
        }

        /// 試験向け。終了コード 2 の判定に使う `nsswitch.conf` を指定する。
        #[must_use]
        pub fn with_nsswitch_conf(mut self, path: PathBuf) -> Self {
            self.nsswitch_conf = Some(path);
            self
        }

        /// 終了コード 2 が「名前なし」だと確定できるか。遠隔源があるか読めないときは確定できない（`false`）。
        /// ファイルが存在しないときは glibc の既定（`files`）とみなす。
        fn exit2_means_absent(&self) -> bool {
            let Some(path) = &self.nsswitch_conf else {
                return true;
            };
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => return e.kind() == std::io::ErrorKind::NotFound,
            };
            let mut buf = Vec::new();
            if file
                .take(MAX_NSSWITCH_BYTES.saturating_add(1))
                .read_to_end(&mut buf)
                .is_err()
                || u64::try_from(buf.len()).map_or(true, |n| n > MAX_NSSWITCH_BYTES)
            {
                return false;
            }
            std::str::from_utf8(&buf).is_ok_and(passwd_sources_all_local)
        }

        /// 最初に実体を解決できた候補が信頼できれば、その実体のパスを返す。
        fn trusted_executable(&self) -> Option<PathBuf> {
            let runner = self.extra_trusted_uid.unwrap_or(0);
            let real = self
                .candidates
                .iter()
                .find_map(|c| std::fs::canonicalize(c).ok())?;
            let meta = std::fs::metadata(&real).ok()?;
            if !meta.is_file() || meta.mode() & 0o111 == 0 {
                return None;
            }
            check_owner_and_mode(meta.uid(), meta.mode(), runner).ok()?;
            for dir in real.ancestors().skip(1) {
                if !dir.starts_with(&self.ancestor_floor) {
                    break;
                }
                let m = std::fs::metadata(dir).ok()?;
                if !m.is_dir() {
                    return None;
                }
                check_owner_and_mode(m.uid(), m.mode(), runner).ok()?;
            }
            Some(real)
        }
    }

    /// `exe passwd <uid>` を期限つきで実行し、(終了コード, 標準出力) を返す。
    ///
    /// 期限は終了待ちと出力の読み取りの両方に掛かる。標準出力は `UnixStream` 対の片側を子へ渡し、親側を
    /// 短い読み取りタイムアウトで読む。孫が標準出力を持ち続けて EOF が来ない場合も期限で `Timeout` にする。
    fn run_getent(
        exe: &Path,
        uid: u32,
        timeout: Duration,
    ) -> Result<(Option<i32>, Vec<u8>), TraitError> {
        let failed = || precondition("the user database lookup failed");
        let (mut reader, writer) = UnixStream::pair().map_err(|_| failed())?;
        reader
            .set_read_timeout(Some(POLL_INTERVAL))
            .map_err(|_| failed())?;
        let mut cmd = Command::new(exe);
        cmd.arg("passwd")
            .arg(uid.to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)));
        // 専用プロセスグループで起動し、期限切れ・出力超過時に子孫まで kill する（pgid = 子の pid）。
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        crate::sys::clear_ambient_caps_on_exec(&mut cmd);
        let spawned = cmd.spawn();
        // Command が持つ親側の書き込み端を閉じる。残ると子の終了後も EOF が来ない。
        drop(cmd);
        let mut child =
            spawned.map_err(|_| precondition("the user database lookup could not start"))?;
        let deadline = Instant::now() + timeout;
        let mut out: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut eof = false;
        let mut status = None;
        let timed_out = |child: &mut std::process::Child| -> TraitError {
            match kill_and_reap(child) {
                Err(e) => e,
                Ok(()) => TraitError::new(ErrorCode::Timeout, "the user database lookup timed out"),
            }
        };
        loop {
            // 出力が少量ずつ届き続けても全体期限を超えて待たない（ループ先頭で毎回確認する）。
            let now = Instant::now();
            if now >= deadline {
                return Err(timed_out(&mut child));
            }
            if !eof {
                let slice = POLL_INTERVAL
                    .min(deadline - now)
                    .max(Duration::from_millis(1));
                reader.set_read_timeout(Some(slice)).map_err(|_| failed())?;
                match reader.read(&mut chunk) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        out.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                        if out.len() > MAX_GETENT_OUTPUT_BYTES {
                            kill_and_reap(&mut child)?;
                            return Err(precondition(
                                "the user database returned an unusable entry",
                            ));
                        }
                        continue;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        kill_and_reap(&mut child)?;
                        return Err(failed());
                    }
                }
            }
            if status.is_none() {
                match child.try_wait() {
                    Ok(s) => status = s,
                    Err(_) => {
                        kill_and_reap(&mut child)?;
                        return Err(failed());
                    }
                }
            }
            if let (Some(s), true) = (status, eof) {
                // 成功を返す直前にも期限を確認する（期限後に揃った結果は採らない）。
                if Instant::now() >= deadline {
                    return Err(timed_out(&mut child));
                }
                return Ok((s.code(), out));
            }
            if eof {
                // EOF 後は読み取りが即座に返るため、子の終了待ちの空回りを避ける。
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
    /// 実効 uid の所有者名を解決する（単一の入口。`start`・pull の展開・`doctor` が共用）。
    ///
    /// `passwd` に行があればそれを返し、`getent` は起動しない。行が無いときだけ NSS を引く。passwd が壊れている・
    /// 上限超過は `FailedPrecondition`。NSS の参照失敗・不正な出力は `FailedPrecondition`、期限切れは `Timeout`。
    pub fn resolve_owner_name(
        passwd: &Path,
        uid: u32,
        lookup: &UserDbLookup,
    ) -> Result<OwnerNameResolution, TraitError> {
        if let Some(name) = read_owner_name(passwd, uid)? {
            return Ok(OwnerNameResolution::Resolved {
                name,
                source: OwnerNameSource::Passwd,
            });
        }
        let Some(exe) = lookup.trusted_executable() else {
            return Ok(OwnerNameResolution::LookupUnavailable);
        };
        let (code, out) = run_getent(&exe, uid, lookup.timeout)?;
        match code {
            Some(0) => Ok(OwnerNameResolution::Resolved {
                name: owner_name_from_getent(&out, uid)?,
                source: OwnerNameSource::Nss,
            }),
            // getent(1): 2 はキーが見つからない。ただし NSS の障害でも 2 が返り得るため、遠隔源がある
            // （または nsswitch.conf を読めない）ときは「名前なし」と断定せず起動拒否にする。
            Some(2) if lookup.exit2_means_absent() => Ok(OwnerNameResolution::NotFound),
            Some(2) => Err(precondition(
                "the user database could not confirm that the entry is absent",
            )),
            _ => Err(precondition("the user database lookup failed")),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::PermissionsExt as _;

        use super::*;

        fn tmp(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!(
                "fc-userdb-{tag}-{}-{}",
                std::process::id(),
                // シェルスクリプトに埋め込むため、記号を含む `{:?}` 表記は使わない。
                std::thread::current()
                    .name()
                    .unwrap_or("t")
                    .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            // umask に依らず group / other 書き込み不可にする（信頼の検査を通すため）。
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            d
        }

        fn euid() -> u32 {
            std::fs::metadata("/proc/self").unwrap().uid()
        }

        fn stub(dir: &Path, body: &str) -> UserDbLookup {
            let p = dir.join("getent");
            let _ = std::fs::remove_file(&p);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            UserDbLookup::custom(
                vec![p],
                Duration::from_secs(5),
                Some(euid()),
                dir.to_path_buf(),
            )
        }

        fn resolve(d: &Path, lookup: &UserDbLookup) -> Result<OwnerNameResolution, TraitError> {
            resolve_owner_name(&d.join("passwd"), 4242, lookup)
        }

        /// CORE-6・SEC-5: passwd に行が無ければ NSS の答えを使う。
        #[test]
        fn core6_nss_name_used_when_passwd_misses() {
            let d = tmp("hit");
            let l = stub(&d, "echo 'ldapuser:*:4242:4242::/home/l:/bin/sh'");
            assert_eq!(
                resolve(&d, &l).unwrap(),
                OwnerNameResolution::Resolved {
                    name: "ldapuser".into(),
                    source: OwnerNameSource::Nss
                }
            );
            let _ = std::fs::remove_dir_all(&d);
        }

        /// 行があれば getent を起動しない（起動すると印を書く stub で照合）。
        #[test]
        fn core6_passwd_hit_does_not_spawn_getent() {
            let d = tmp("pw");
            std::fs::write(d.join("passwd"), "alice:x:4242:4242::/h:/bin/sh\n").unwrap();
            let mark = d.join("called");
            let l = stub(&d, &format!("touch {}; exit 1", mark.display()));
            assert_eq!(
                resolve(&d, &l).unwrap(),
                OwnerNameResolution::Resolved {
                    name: "alice".into(),
                    source: OwnerNameSource::Passwd
                }
            );
            assert!(!mark.exists());
            let _ = std::fs::remove_dir_all(&d);
        }

        /// 終了 2 は名前なし、その他の終了・不正出力は fail-closed。
        #[test]
        fn core6_exit_codes_and_bad_output() {
            let d = tmp("exit");
            assert_eq!(
                resolve(&d, &stub(&d, "exit 2")).unwrap(),
                OwnerNameResolution::NotFound
            );
            for body in [
                "exit 1",
                "exit 0",
                "echo 'x:*:1:1::/h:/s'",
                "echo ':*:4242:1::/h:/s'",
                "head -c 5000 /dev/zero | tr '\\0' a",
            ] {
                let e = resolve(&d, &stub(&d, body)).unwrap_err();
                assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{body}");
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        /// P1: 遠隔源（ldap・sss）があるとき終了 2 は名前なしと断定せず拒否。ローカル源だけなら名前なし。
        #[test]
        fn core6_exit2_with_remote_nss_source_is_refused() {
            let d = tmp("nsw");
            let conf = d.join("nsswitch.conf");
            let l = stub(&d, "exit 2");
            for (text, absent) in [
                ("passwd: files systemd\n", true),
                (
                    "# c\npasswd:   files [NOTFOUND=return] db\nhosts: dns ldap\n",
                    true,
                ),
                ("passwd: files sss\n", false),
                ("passwd: files ldap # x\n", false),
                ("passwd: compat\npasswd_compat: ldap\n", false),
                // passwd_compat の既定は nis のため、compat のみでは証明できない。
                ("passwd: compat\n", false),
                ("passwd: compat\npasswd_compat: files\n", true),
                ("passwd: files [SUCCESS=return\n", false),
            ] {
                std::fs::write(&conf, text).unwrap();
                let l = l.clone().with_nsswitch_conf(conf.clone());
                let r = resolve(&d, &l);
                if absent {
                    assert_eq!(r.unwrap(), OwnerNameResolution::NotFound, "{text}");
                } else {
                    assert_eq!(
                        r.unwrap_err().code(),
                        ErrorCode::FailedPrecondition,
                        "{text}"
                    );
                }
            }
            // 読めない（ディレクトリ）なら拒否、存在しないなら既定の files で名前なし。
            let l2 = l.clone().with_nsswitch_conf(d.clone());
            assert!(resolve(&d, &l2).is_err());
            let l3 = l.with_nsswitch_conf(d.join("absent"));
            assert_eq!(resolve(&d, &l3).unwrap(), OwnerNameResolution::NotFound);
            let _ = std::fs::remove_dir_all(&d);
        }

        /// REPAIR-5・P0: 孫が標準出力を持ち続けても、親の終了後の読み取りは期限で打ち切る。
        #[test]
        fn repair5_background_grandchild_holding_stdout_times_out() {
            let d = tmp("bg");
            let l = stub(&d, "sleep 30 &\nexit 2");
            let l = UserDbLookup {
                timeout: Duration::from_secs(1),
                ..l
            };
            let t = Instant::now();
            let e = resolve(&d, &l).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert!(t.elapsed() < Duration::from_secs(4));
            let _ = std::fs::remove_dir_all(&d);
        }

        /// REPAIR-5: 少量ずつ出力し続けるヘルパーでも全体期限で打ち切る（出力上限 4 KiB に達する前）。
        #[test]
        fn repair5_trickling_output_hits_overall_deadline() {
            let d = tmp("trickle");
            let l = stub(&d, "while true; do printf x; sleep 0.02; done");
            let l = UserDbLookup {
                timeout: Duration::from_secs(1),
                ..l
            };
            let t = Instant::now();
            let e = resolve(&d, &l).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert!(t.elapsed() < Duration::from_secs(3));
            let _ = std::fs::remove_dir_all(&d);
        }

        /// REPAIR-5: 期限切れでヘルパーの孫も kill する。
        #[test]
        fn repair5_timeout_kills_grandchild() {
            let d = tmp("gc");
            let pidfile = d.join("gpid");
            let l = stub(
                &d,
                &format!("sleep 30 &\necho $! > {}\nexit 2", pidfile.display()),
            );
            let l = UserDbLookup {
                timeout: Duration::from_secs(1),
                ..l
            };
            let e = resolve(&d, &l).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Timeout);
            let pid = std::fs::read_to_string(&pidfile).unwrap();
            let proc = format!("/proc/{}", pid.trim());
            let mut gone = false;
            for _ in 0..100 {
                // ゾンビ（init 回収待ち）も終了済みとみなす。
                let st = std::fs::read_to_string(format!("{proc}/stat")).unwrap_or_default();
                if st.is_empty() || st.contains(") Z ") {
                    gone = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(gone);
            let _ = std::fs::remove_dir_all(&d);
        }

        /// REPAIR-5: 期限を超えたら kill して Timeout。
        #[test]
        fn repair5_timeout_kills_child() {
            let d = tmp("slow");
            let pidfile = d.join("pid");
            let l = stub(&d, &format!("echo $$ > {}; sleep 30", pidfile.display()));
            let l = UserDbLookup {
                timeout: Duration::from_secs(1),
                ..l
            };
            let t = Instant::now();
            let e = resolve(&d, &l).unwrap_err();
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert!(t.elapsed() < Duration::from_secs(3));
            let pid = std::fs::read_to_string(&pidfile).unwrap();
            assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists());
            let _ = std::fs::remove_dir_all(&d);
        }

        /// 候補が無い・信頼できない実行ファイルは利用不可。
        #[test]
        fn sec5_untrusted_or_missing_getent_is_unavailable() {
            let d = tmp("trust");
            let none = UserDbLookup::custom(
                vec![d.join("absent")],
                Duration::from_secs(5),
                Some(euid()),
                d.clone(),
            );
            assert_eq!(
                resolve(&d, &none).unwrap(),
                OwnerNameResolution::LookupUnavailable
            );
            let l = stub(&d, "exit 2");
            let p = d.join("getent");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o775)).unwrap();
            assert_eq!(
                resolve(&d, &l).unwrap(),
                OwnerNameResolution::LookupUnavailable
            );
            // 本番の基準は root 所有のみ: euid 所有の stub は、euid が root でなければ拒否される。
            if euid() != 0 {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
                let strict = UserDbLookup::custom(vec![p], Duration::from_secs(5), None, d.clone());
                assert_eq!(
                    resolve(&d, &strict).unwrap(),
                    OwnerNameResolution::LookupUnavailable
                );
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        /// SUP-14: 子へ ambient capability を渡さない（`CapAmb` が 0）。CI では元から 0 のため配線の確認に留まる。
        #[test]
        fn sec5_child_has_no_ambient_caps() {
            let d = tmp("amb");
            let l = stub(
                &d,
                "grep -q '^CapAmb:[[:space:]]*0000000000000000$' /proc/self/status && exit 2; exit 1",
            );
            assert_eq!(resolve(&d, &l).unwrap(), OwnerNameResolution::NotFound);
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORE-6: 正常な行は名前、uid 不一致・欄不足・空の名前・上限超過・UTF-8 不正は拒否。
    #[test]
    fn core6_owner_name_from_getent_cases() {
        assert_eq!(
            owner_name_from_getent(b"alice@example.com:*:1000:1000::/h:/bin/sh\n", 1000).unwrap(),
            "alice@example.com"
        );
        for b in [
            &b"alice:*:1001:1::/h:/s\n"[..],
            b"alice:x\n",
            b":x:1000:1::/h:/s\n",
            b"",
            b"\xff:x:1000:1::/h:/s\n",
        ] {
            let e = owner_name_from_getent(b, 1000).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "the user database returned an unusable entry");
        }
        let big = format!(
            "alice:*:1000:1::/{}:/s\n",
            "a".repeat(MAX_GETENT_OUTPUT_BYTES)
        );
        assert!(owner_name_from_getent(big.as_bytes(), 1000).is_err());
    }
}
