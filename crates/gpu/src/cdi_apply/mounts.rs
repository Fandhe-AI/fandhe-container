//! CDI `mounts` を core が受理できる検証済みの bind mount 指定へ変換する（TASK-127.2・GPU-2・MS-10）。
//!
//! 呼び出し元: 適用層（TASK-127 の配線。#2774）が [`crate::cdi_edits::AggregatedEdits::mounts`] の結果を
//! [`cdi_bind_mounts`] に渡し、得た [`CdiBindMount`] を OCI `config.json` の `mounts[]`
//! （`destination`・`source`・`type`・`options`）へ合流させる。実際の bind mount は core の既存経路
//! （`BindMountSet::from_mounts` → `mount_binds`）が行い、symlink・疑似 FS・状態ルートとの重なりなど
//! 実体の検査もそちらが担う。本層は FS に触れない純粋関数で、3 OS でビルドできる（CLI-1）。
//!
//! 受理規則の SSOT は core の `parse_options`・`validate_source`（`crates/core/src/oci_runtime/bind_mounts.rs`）。
//! 本層はそれと同じ集合だけを通す fail-closed の前段検査で、規則を変えるときは双方を更新する。
//! - 受けるオプション: `bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・
//!   `rprivate`・`rslave`。`ro`/`rw`・`noexec`/`exec` は後勝ち。
//! - 拒否: `suid`・`dev`（制限を外す。SEC-1）、`shared` 系の伝播、未知のすべて。
//! - `nosuid`・`nodev` は指定の有無によらず常に付く（外した値を表現できない。REPAIR-2）。
//!
//! 出典（cncf-tags/container-device-interface v1.1.1 `cb98bcf66dc68530012483bd56e33e14d815e167`）:
//! `pkg/cdi/container-edits.go` の `Apply` は CDI の mount を OCI の `mounts[]` へ追加する。上流は同じ
//! `containerPath` の利用者 mount を置き換えるが、本実装は集計が重複を拒否し、core も重複を拒否する
//! （fail-closed の意図的な差）。
//!
//! 順序: 出力は集計順を保つ。上流は深さ順に並べ替えるが、core は bind 同士の入れ子を拒否するため
//! 順序による挙動差は出ない。
//!
//! エラーの `message` は固定文言で、パスもオプションの値も載せない（A09）。
//!
//! 既知の前提と残余（REPAIR-3。本層では解決しない）:
//! 1. `ro` の bind は書き込み可能な root では core に拒否される（#1917）。NVIDIA の mount は全件 `ro`。
//! 2. core の bind 経路は rootless の起動経路が対象。rootful との差は #2241 の範囲。
//! 3. 元が UNIX ソケット（PoC-14 の `/run/nvidia-persistenced/socket`）は core が種別で拒否する。本層は
//!    FS に触れないため検出しない。
//! 4. 宛先経路上の symlink の解決は TASK-127 の別の子の担当。usr-merge 正規化済みの宛先を受けるだけで、
//!    それ以外の symlink を含む宛先は core が拒否する。
//! 5. `mounts[]` への合流と実 namespace の mountinfo での確認は #2774・#552 の範囲。

use crate::cdi_edits::AggregatedEdits;
use crate::cdi_spec::{CdiSpecError, CdiSpecErrorCode, Mount};

/// 1 件の mount が持てる options の最大件数。実例は 4〜5 件で、確保の前に拒否する上限。
pub const CDI_APPLY_MAX_MOUNT_OPTIONS: usize = 32;

/// `hostPath`・`containerPath` の最大バイト数（core の `CONFIG_MAX_PATH_BYTES` と同値）。
pub const CDI_APPLY_MAX_PATH_BYTES: usize = 4096;

/// bind mount の伝播（core の `BindPropagation` と同じ 2 値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CdiBindPropagation {
    /// ホストへ伝播させない（既定）。
    Private,
    /// ホストの変更を受け取る（`rslave`）。
    HostSlave,
}

/// 検証済み・正規化済みの bind mount 指定。フィールドは非公開でアクセサから読む。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiBindMount {
    source: String,
    destination: String,
    recursive: bool,
    read_only: bool,
    noexec: bool,
    propagation: CdiBindPropagation,
}

impl CdiBindMount {
    /// ホスト側の絶対パス。
    pub fn source(&self) -> &str {
        &self.source
    }

    /// コンテナ内の絶対パス。
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// `rbind`（子マウントも含める）か。
    pub fn recursive(&self) -> bool {
        self.recursive
    }

    /// 読み取り専用か。
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// `noexec` か。
    pub fn noexec(&self) -> bool {
        self.noexec
    }

    /// 伝播。
    pub fn propagation(&self) -> CdiBindPropagation {
        self.propagation
    }

    /// 常に真（SEC-1）。
    pub fn nosuid(&self) -> bool {
        true
    }

    /// 常に真（SEC-1）。
    pub fn nodev(&self) -> bool {
        true
    }

    /// OCI の mount `type`。
    pub fn oci_type(&self) -> &'static str {
        "bind"
    }

    /// 正規形の OCI options。並びは `[bind|rbind, ro|rw, nosuid, nodev, noexec|exec, 伝播]` で固定。
    pub fn oci_options(&self) -> Vec<&'static str> {
        vec![
            if self.recursive { "rbind" } else { "bind" },
            if self.read_only { "ro" } else { "rw" },
            "nosuid",
            "nodev",
            if self.noexec { "noexec" } else { "exec" },
            match (self.propagation, self.recursive) {
                (CdiBindPropagation::HostSlave, _) => "rslave",
                (CdiBindPropagation::Private, true) => "rprivate",
                (CdiBindPropagation::Private, false) => "private",
            },
        ]
    }
}

fn err(code: CdiSpecErrorCode, message: &str) -> CdiSpecError {
    CdiSpecError::new(code, message)
}

/// 絶対・正規形（空要素・`.`・`..`・NUL・`\`・`/` 単独なし）で長さ内かを検査する。
fn check_path(path: &str, what: &str) -> Result<(), CdiSpecError> {
    if path.len() > CDI_APPLY_MAX_PATH_BYTES {
        return Err(err(
            CdiSpecErrorCode::ResourceExhausted,
            &format!("CDI mount {what} is too long"),
        ));
    }
    let invalid = || {
        err(
            CdiSpecErrorCode::InvalidArgument,
            &format!("CDI mount {what} must be a normalized absolute path"),
        )
    };
    if path.contains('\0') || path.contains('\\') {
        return Err(invalid());
    }
    let rest = path.strip_prefix('/').ok_or_else(invalid)?;
    if rest.is_empty() || rest.split('/').any(|e| matches!(e, "" | "." | "..")) {
        return Err(invalid());
    }
    Ok(())
}

/// 疑似 FS（`/proc`・`/sys`・`/dev`）とその配下か。要素の一致で判定し接頭辞一致にしない。
fn is_pseudo_fs_path(path: &str) -> bool {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    matches!(first, "proc" | "sys" | "dev")
}

/// CDI の `Mount` 1 件を検証して bind 指定へ変換する。
pub fn cdi_bind_mount(m: &Mount) -> Result<CdiBindMount, CdiSpecError> {
    if m.options.len() > CDI_APPLY_MAX_MOUNT_OPTIONS {
        return Err(err(
            CdiSpecErrorCode::ResourceExhausted,
            "CDI mount has too many options",
        ));
    }
    let opt = |name: &str| m.options.iter().any(|o| o == name);
    match m.r#type.as_deref() {
        None | Some("bind") => {}
        Some(_) => {
            return Err(err(
                CdiSpecErrorCode::Unimplemented,
                "CDI mount type is not supported",
            ));
        }
    }
    if !(m.r#type.as_deref() == Some("bind") || opt("bind") || opt("rbind")) {
        return Err(err(
            CdiSpecErrorCode::Unimplemented,
            "CDI mount is not a bind mount",
        ));
    }
    let (mut has_bind, mut has_rbind) = (false, false);
    let (mut read_only, mut noexec) = (false, false);
    let (mut has_slave, mut has_private) = (false, false);
    for o in &m.options {
        match o.as_str() {
            "bind" => has_bind = true,
            "rbind" => has_rbind = true,
            "ro" => read_only = true,
            "rw" => read_only = false,
            "noexec" => noexec = true,
            "exec" => noexec = false,
            "nosuid" | "nodev" => {}
            "private" | "rprivate" => has_private = true,
            "rslave" => has_slave = true,
            "suid" | "dev" => {
                return Err(err(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI mount option lifts a restriction",
                ));
            }
            "shared" | "rshared" | "slave" | "unbindable" | "runbindable" => {
                return Err(err(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI mount propagation option is not supported",
                ));
            }
            _ => {
                return Err(err(
                    CdiSpecErrorCode::InvalidArgument,
                    "CDI mount option is not supported",
                ));
            }
        }
    }
    if has_bind && has_rbind {
        return Err(err(
            CdiSpecErrorCode::InvalidArgument,
            "CDI mount has both bind and rbind",
        ));
    }
    if has_slave && has_private {
        return Err(err(
            CdiSpecErrorCode::InvalidArgument,
            "CDI mount has conflicting propagation options",
        ));
    }
    check_path(&m.host_path, "hostPath")?;
    check_path(&m.container_path, "containerPath")?;
    if is_pseudo_fs_path(&m.container_path) {
        return Err(err(
            CdiSpecErrorCode::InvalidArgument,
            "CDI mount containerPath must not be under /proc, /sys or /dev",
        ));
    }
    Ok(CdiBindMount {
        source: m.host_path.clone(),
        destination: m.container_path.clone(),
        recursive: has_rbind,
        read_only,
        noexec,
        propagation: if has_slave {
            CdiBindPropagation::HostSlave
        } else {
            CdiBindPropagation::Private
        },
    })
}

/// 集計済み edits の `mounts` を集計順のまま変換する。1 件でも拒否されれば全体を拒否する。
pub fn cdi_bind_mounts(edits: &AggregatedEdits) -> Result<Vec<CdiBindMount>, CdiSpecError> {
    edits.mounts().iter().map(cdi_bind_mount).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(opts: &[&str], ty: Option<&str>) -> Mount {
        Mount {
            host_path: "/usr/lib/libx.so".into(),
            container_path: "/usr/lib/libx.so".into(),
            options: opts.iter().map(|s| s.to_string()).collect(),
            r#type: ty.map(String::from),
        }
    }

    fn code(m: &Mount) -> CdiSpecErrorCode {
        cdi_bind_mount(m).unwrap_err().code()
    }

    type Case = (
        &'static [&'static str],
        bool,
        bool,
        bool,
        CdiBindPropagation,
        [&'static str; 6],
    );

    /// GPU-2: 受ける全 token が期待する写像と正規形になる。
    #[test]
    fn gpu2_task127_2_accepted_tokens_table() {
        use CdiBindPropagation::*;
        let cases: Vec<Case> = vec![
            (
                &["bind"],
                false,
                false,
                false,
                Private,
                ["bind", "rw", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["rbind"],
                true,
                false,
                false,
                Private,
                ["rbind", "rw", "nosuid", "nodev", "exec", "rprivate"],
            ),
            (
                &["bind", "ro"],
                false,
                true,
                false,
                Private,
                ["bind", "ro", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["bind", "rw"],
                false,
                false,
                false,
                Private,
                ["bind", "rw", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["bind", "nosuid", "nodev"],
                false,
                false,
                false,
                Private,
                ["bind", "rw", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["bind", "noexec"],
                false,
                false,
                true,
                Private,
                ["bind", "rw", "nosuid", "nodev", "noexec", "private"],
            ),
            (
                &["bind", "exec"],
                false,
                false,
                false,
                Private,
                ["bind", "rw", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["bind", "private"],
                false,
                false,
                false,
                Private,
                ["bind", "rw", "nosuid", "nodev", "exec", "private"],
            ),
            (
                &["rbind", "rprivate"],
                true,
                false,
                false,
                Private,
                ["rbind", "rw", "nosuid", "nodev", "exec", "rprivate"],
            ),
            (
                &["rbind", "rslave"],
                true,
                false,
                false,
                HostSlave,
                ["rbind", "rw", "nosuid", "nodev", "exec", "rslave"],
            ),
            (
                &["ro", "nosuid", "nodev", "bind"],
                false,
                true,
                false,
                Private,
                ["bind", "ro", "nosuid", "nodev", "exec", "private"],
            ),
        ];
        for (opts, rec, ro, nx, prop, canon) in cases {
            let b = cdi_bind_mount(&mount(opts, None)).unwrap();
            assert_eq!(b.recursive(), rec, "{opts:?}");
            assert_eq!(b.read_only(), ro, "{opts:?}");
            assert_eq!(b.noexec(), nx, "{opts:?}");
            assert_eq!(b.propagation(), prop, "{opts:?}");
            assert_eq!(b.oci_options(), canon, "{opts:?}");
            assert!(b.nosuid() && b.nodev());
            assert_eq!(b.oci_type(), "bind");
        }
    }

    /// GPU-2: ro/rw と noexec/exec は後勝ち（core と同じ）。
    #[test]
    fn gpu2_task127_2_last_one_wins() {
        let ro = |o: &[&str]| cdi_bind_mount(&mount(o, None)).unwrap().read_only();
        let nx = |o: &[&str]| cdi_bind_mount(&mount(o, None)).unwrap().noexec();
        assert!(!ro(&["bind", "ro", "rw"]));
        assert!(ro(&["bind", "rw", "ro"]));
        assert!(!nx(&["bind", "noexec", "exec"]));
        assert!(nx(&["bind", "exec", "noexec"]));
    }

    /// GPU-2: 拒否するオプションは期待するコードになる。
    #[test]
    fn gpu2_task127_2_rejected_tokens_table() {
        for t in [
            "suid",
            "dev",
            "shared",
            "rshared",
            "slave",
            "unbindable",
            "runbindable",
            "defaults",
            "rro",
            "idmap",
            "",
            "bogus",
            "RO",
        ] {
            assert_eq!(
                code(&mount(&["bind", t], None)),
                CdiSpecErrorCode::InvalidArgument,
                "{t:?}"
            );
        }
        assert_eq!(
            code(&mount(&["bind", "rbind"], None)),
            CdiSpecErrorCode::InvalidArgument
        );
        assert_eq!(
            code(&mount(&["rbind", "rslave", "private"], None)),
            CdiSpecErrorCode::InvalidArgument
        );
        assert_eq!(
            code(&mount(&["rbind", "rslave", "rprivate"], None)),
            CdiSpecErrorCode::InvalidArgument
        );
    }

    /// GPU-2: 種類の判定。
    #[test]
    fn gpu2_task127_2_type_handling() {
        assert_eq!(
            code(&mount(&["bind"], Some("tmpfs"))),
            CdiSpecErrorCode::Unimplemented
        );
        assert_eq!(code(&mount(&["ro"], None)), CdiSpecErrorCode::Unimplemented);
        assert_eq!(code(&mount(&[], None)), CdiSpecErrorCode::Unimplemented);
        let b = cdi_bind_mount(&mount(&[], Some("bind"))).unwrap();
        assert!(!b.recursive());
        assert_eq!(b.oci_options()[0], "bind");
    }

    /// GPU-2: パスの字句検査。
    #[test]
    fn gpu2_task127_2_path_validation() {
        let long = format!("/{}", "a".repeat(CDI_APPLY_MAX_PATH_BYTES));
        for p in [
            "usr/lib", "/", "//x", "/a//b", "/a/./b", "/a/../b", "/a/", "/a\0b", "/a\\b", "",
        ] {
            let mut m = mount(&["bind"], None);
            m.host_path = p.into();
            assert_eq!(code(&m), CdiSpecErrorCode::InvalidArgument, "host {p:?}");
            let mut m = mount(&["bind"], None);
            m.container_path = p.into();
            assert_eq!(
                code(&m),
                CdiSpecErrorCode::InvalidArgument,
                "container {p:?}"
            );
        }
        let mut m = mount(&["bind"], None);
        m.host_path = long.clone();
        assert_eq!(code(&m), CdiSpecErrorCode::ResourceExhausted);
        let mut m = mount(&["bind"], None);
        m.container_path = long;
        assert_eq!(code(&m), CdiSpecErrorCode::ResourceExhausted);
        // 上限ちょうどは受ける。
        let mut m = mount(&["bind"], None);
        m.host_path = format!("/{}", "a".repeat(CDI_APPLY_MAX_PATH_BYTES - 1));
        assert!(cdi_bind_mount(&m).is_ok());
    }

    /// GPU-2: containerPath の疑似 FS は要素の一致で拒否する。
    #[test]
    fn gpu2_task127_2_pseudo_fs_container_path() {
        for p in ["/dev/x", "/proc", "/sys/y", "/dev"] {
            let mut m = mount(&["bind"], None);
            m.container_path = p.into();
            assert_eq!(code(&m), CdiSpecErrorCode::InvalidArgument, "{p}");
        }
        for p in ["/devx", "/usr/dev/x", "/procfs"] {
            let mut m = mount(&["bind"], None);
            m.container_path = p.into();
            assert!(cdi_bind_mount(&m).is_ok(), "{p}");
        }
        // hostPath は疑似 FS でも字句上は受ける（実体の判断は core）。
        let mut m = mount(&["bind"], None);
        m.host_path = "/dev/x".into();
        assert!(cdi_bind_mount(&m).is_ok());
    }

    /// GPU-2: options 件数の上限。
    #[test]
    fn gpu2_task127_2_options_count_limit() {
        let mut opts = vec!["bind"];
        opts.extend(vec!["nosuid"; CDI_APPLY_MAX_MOUNT_OPTIONS - 1]);
        assert_eq!(opts.len(), CDI_APPLY_MAX_MOUNT_OPTIONS);
        assert!(cdi_bind_mount(&mount(&opts, None)).is_ok());
        opts.push("nosuid");
        assert_eq!(
            code(&mount(&opts, None)),
            CdiSpecErrorCode::ResourceExhausted
        );
    }

    /// GPU-2: エラーの message にパスもオプションの値も載らない。
    #[test]
    fn gpu2_task127_2_error_messages_do_not_leak() {
        let mut m = mount(&["bind", "secret-opt"], None);
        m.host_path = "/very/secret/host".into();
        let e = cdi_bind_mount(&m).unwrap_err();
        assert!(!e.message().contains("secret"));
        let mut m = mount(&["bind"], None);
        m.host_path = "/secret/../x".into();
        let e = cdi_bind_mount(&m).unwrap_err();
        assert!(!e.message().contains("secret"));
    }
}
