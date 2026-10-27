//! CDI の `createContainer` フックの検証・実行順序の強制・host 側プロセスとしての実行（TASK-127.3・GPU-2・MS-10）。
//!
//! # 責務境界
//! 本層は (a) フック定義の起動前検証、(b) 「rootfs の自己 bind → `<rootfs>/proc` のマウント → フック → `pivot_root`」
//! という実行順序の前提状態の検証、(c) フックの起動と結果の報告だけを担う。マウント・アンマウントは行わない
//! （自己 bind と `/proc` は core の `exec::prepare_rootfs` が既に行う）。順序の制約は PoC-14 の dev-box02 で判明した
//! もので、`nvidia-cdi-hook create-symlinks` は rootfs が自己 bind され `/proc` が見える状態でないと失敗する。
//!
//! # 呼び出し文脈（配線は #2774）
//! core の pre-pivot 段で `prepare_rootfs` の後・`pivot_root` の前に、`verify_hook_stage` で証跡
//! `CdiHookStage` を得て `run_create_container_hooks` を呼ぶ（いずれも Linux のみ）。失敗したら `pivot_root` へ
//! 進まない（fail-closed）。順序を呼び出し側の申告ではなく実際の mountinfo で検証し、通過時だけ証跡を発行するため、
//! 順序を逸脱した状態では実行 API を呼べない。コンテナプロセスの env は `cdi_apply::env`（フックの env とは別）、`create-symlinks` の全リンク網羅検証は #551 の範囲。
//!
//! # 上流 runc との差と残余
//! - フックの環境変数はフック指定分だけで、ホストの環境変数を継承しない（supervisor 側の秘密情報の漏えい防止。
//!   runc は未指定時に継承する）。
//! - スレッドを作らない（後続の Landlock・seccomp はスレッド単位で効くため）。stdout は捨て、stderr は bundle 内の
//!   ファイルへ向けて終了後に先頭だけ読む。
//! - タイムアウトは子プロセスの SIGKILL と回収まで。孫プロセスの残存、検証から exec までの TOCTOU は残余（REPAIR-3）。
//! - rootless: user namespace 内ではホスト root 所有のフックが overflow uid に見えて所有者検査が拒否する。
//!   namespace に入る前に `open_hook_executables` で検査して fd を保持し、`run_create_container_hooks_with_recorder`
//!   へ渡す契約とする（overflow uid を一律に信用しない）。
//! - 計測は `run_create_container_hooks_with_recorder` の `CdiHookRunRecorder`（結果コードと所要時間。REPAIR-4）。
//! - `createContainer` 以外の OCI フック名は `Unimplemented` で拒否する。
//! - CDI spec ファイル自体の信頼（置き場所・所有者）は読み込み側（TASK-126）の責務で、本層は前提とする。
//!
//! エラーの `message` は固定の英語で、パス・引数・env の値を載せない（A09）。

use super::{CdiApplyError, CdiApplyErrorCode as Code};
use crate::cdi_spec::Hook;

/// フックの最大件数（実例は 7 件）。
pub const CDI_APPLY_MAX_HOOKS: usize = 64;
/// 1 フックの `args` の最大件数（create-symlinks の `--link` 約 33 組を十分に包む）。
pub const CDI_APPLY_MAX_HOOK_ARGS: usize = 1024;
/// 1 フックの `args` の合計最大バイト数。
pub const CDI_APPLY_MAX_HOOK_ARGS_BYTES: usize = 256 * 1024;
/// 1 フックの `env` の最大件数。
pub const CDI_APPLY_MAX_HOOK_ENV: usize = 256;
/// path・args 要素・env 要素の最大バイト数。
pub const CDI_APPLY_MAX_HOOK_ITEM_BYTES: usize = 4096;
/// `timeout` 未指定時の既定秒数（PoC-14 の `HOOK_TIMEOUT`）。
pub const CDI_HOOK_DEFAULT_TIMEOUT_SECS: u64 = 30;
/// `timeout` の上限秒数。
pub const CDI_HOOK_MAX_TIMEOUT_SECS: u64 = 300;
/// mountinfo の読み取り上限バイト数。
pub const CDI_HOOK_MAX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;

const fn e(code: Code, message: &'static str) -> CdiApplyError {
    CdiApplyError::new(code, message)
}

/// 検証済みの `createContainer` フック。フィールドは非公開でアクセサから読む（REPAIR-2）。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiCreateContainerHook {
    path: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    timeout_secs: u64,
}

impl std::fmt::Debug for CdiCreateContainerHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // env の値は秘密を含みうるため件数だけ出す。
        f.debug_struct("CdiCreateContainerHook")
            .field("path", &self.path)
            .field("args", &self.args.len())
            .field("env", &self.env.len())
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl CdiCreateContainerHook {
    /// 実行ファイルの絶対パス。
    pub fn path(&self) -> &str {
        &self.path
    }
    /// argv 全体（先頭要素が argv 0 番になる。CDI の規約）。
    pub fn args(&self) -> &[String] {
        &self.args
    }
    /// 実効 timeout 秒。
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }
    /// env の件数（値は公開しない）。
    pub fn env_len(&self) -> usize {
        self.env.len()
    }
}

fn check_text(s: &str, nul_message: &'static str) -> Result<(), CdiApplyError> {
    if s.len() > CDI_APPLY_MAX_HOOK_ITEM_BYTES {
        return Err(e(Code::ResourceExhausted, "CDI hook item is too long"));
    }
    if s.contains('\0') {
        return Err(e(Code::InvalidArgument, nul_message));
    }
    Ok(())
}

fn validate_one(h: &Hook) -> Result<CdiCreateContainerHook, CdiApplyError> {
    match h.hook_name.as_str() {
        "createContainer" => {}
        "prestart" | "createRuntime" | "startContainer" | "poststart" | "poststop" => {
            return Err(e(
                Code::Unimplemented,
                "CDI hook name is not supported (only createContainer)",
            ));
        }
        _ => return Err(e(Code::InvalidArgument, "CDI hook name is unknown")),
    }
    check_text(&h.path, "CDI hook path contains NUL")?;
    let bad_path = h.path.contains('\\')
        || match h.path.strip_prefix('/') {
            None => true,
            Some(r) => r.is_empty() || r.split('/').any(|x| matches!(x, "" | "." | "..")),
        };
    if bad_path {
        return Err(e(
            Code::InvalidArgument,
            "CDI hook path must be a normalized absolute path",
        ));
    }
    if h.args.is_empty() {
        return Err(e(Code::InvalidArgument, "CDI hook args must not be empty"));
    }
    if h.args.len() > CDI_APPLY_MAX_HOOK_ARGS {
        return Err(e(Code::ResourceExhausted, "CDI hook has too many args"));
    }
    let mut total = 0usize;
    for a in &h.args {
        check_text(a, "CDI hook arg contains NUL")?;
        total = total.saturating_add(a.len());
    }
    if total > CDI_APPLY_MAX_HOOK_ARGS_BYTES {
        return Err(e(Code::ResourceExhausted, "CDI hook args are too large"));
    }
    if h.env.len() > CDI_APPLY_MAX_HOOK_ENV {
        return Err(e(
            Code::ResourceExhausted,
            "CDI hook has too many env entries",
        ));
    }
    let mut env = Vec::with_capacity(h.env.len());
    for kv in h.env.iter() {
        check_text(kv, "CDI hook env contains NUL")?;
        match kv.split_once('=') {
            Some((k, v)) if !k.is_empty() => env.push((k.to_string(), v.to_string())),
            _ => {
                return Err(e(
                    Code::InvalidArgument,
                    "CDI hook env entry must be KEY=VALUE",
                ));
            }
        }
    }
    let timeout_secs = match h.timeout {
        None => CDI_HOOK_DEFAULT_TIMEOUT_SECS,
        Some(t) => match u64::try_from(t) {
            Ok(t) if (1..=CDI_HOOK_MAX_TIMEOUT_SECS).contains(&t) => t,
            _ => return Err(e(Code::InvalidArgument, "CDI hook timeout is out of range")),
        },
    };
    Ok(CdiCreateContainerHook {
        path: h.path.clone(),
        args: h.args.clone(),
        env,
        timeout_secs,
    })
}

/// 集計済みのフックを全件検証する。1 件でも不正なら何も返さない（起動前に拒否。fail-closed）。
pub fn validate_create_container_hooks(
    hooks: &[Hook],
) -> Result<Vec<CdiCreateContainerHook>, CdiApplyError> {
    if hooks.len() > CDI_APPLY_MAX_HOOKS {
        return Err(e(Code::ResourceExhausted, "too many CDI hooks"));
    }
    hooks.iter().map(validate_one).collect()
}

/// mountinfo の 1 行（必要なフィールドだけ）。
struct MountEntry {
    id: u64,
    parent: u64,
    mount_point: String,
    fstype: String,
}

/// mountinfo の 8 進エスケープ（`\040` 等）を復号する。不正は `None`。
fn unescape_mount_point(s: &str) -> Option<String> {
    let mut it = s.bytes();
    let mut out = Vec::with_capacity(s.len());
    while let Some(c) = it.next() {
        if c == b'\\' {
            let mut v: u32 = 0;
            for _ in 0..3 {
                let d = it.next().filter(|d| (b'0'..=b'7').contains(d))?;
                v = v * 8 + u32::from(d - b'0');
            }
            out.push(u8::try_from(v).ok()?);
        } else {
            out.push(c);
        }
    }
    String::from_utf8(out).ok()
}

fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let sep = f.iter().position(|x| *x == "-")?;
    if sep < 6 {
        return None;
    }
    Some(MountEntry {
        id: f.first()?.parse().ok()?,
        parent: f.get(1)?.parse().ok()?,
        mount_point: unescape_mount_point(f.get(4)?)?,
        fstype: (*f.get(sep + 1)?).to_string(),
    })
}

/// 実行順序の前提（自己 bind 済み・`<rootfs>/proc` が proc で rootfs の直下に積まれている・pivot 前）を
/// mountinfo の文面から判定する純粋関数（GPU-2。3 OS でビルドし、単体試験で文面を注入する）。
/// 同一 mount point が重なる場合は最後の項目を採る。
pub fn check_hook_stage_mountinfo(rootfs: &str, mountinfo: &str) -> Result<(), CdiApplyError> {
    if mountinfo.len() > CDI_HOOK_MAX_MOUNTINFO_BYTES {
        return Err(e(Code::ResourceExhausted, "mountinfo is too large"));
    }
    let rootfs = rootfs.trim_end_matches('/');
    if rootfs.is_empty() {
        return Err(e(
            Code::FailedPrecondition,
            "rootfs is the host root (already pivoted or not separated)",
        ));
    }
    let mut entries = Vec::new();
    for line in mountinfo.lines().filter(|l| !l.trim().is_empty()) {
        entries.push(
            parse_mountinfo_line(line)
                .ok_or_else(|| e(Code::Internal, "mountinfo is malformed"))?,
        );
    }
    let proc_path = format!("{rootfs}/proc");
    let last = |p: &str| entries.iter().rev().find(|m| m.mount_point == p);
    let Some(root_entry) = last(rootfs) else {
        return Err(e(
            Code::FailedPrecondition,
            "rootfs is not self-bind mounted",
        ));
    };
    match last(&proc_path) {
        Some(p) if p.fstype == "proc" => {
            if p.parent != root_entry.id {
                return Err(e(
                    Code::FailedPrecondition,
                    "proc is not stacked directly on the rootfs bind mount",
                ));
            }
            Ok(())
        }
        _ => Err(e(
            Code::FailedPrecondition,
            "proc is not mounted under rootfs",
        )),
    }
}

#[cfg(target_os = "linux")]
mod run;
#[cfg(target_os = "linux")]
pub use run::{
    CdiHookError, CdiHookExecutables, CdiHookExit, CdiHookReport, CdiHookResult,
    CdiHookRunRecorder, CdiHookRunSample, CdiHookStage, CdiHookState, CdiHookWorkDir,
    open_hook_executables, open_hook_work_dir, run_create_container_hooks,
    run_create_container_hooks_with_recorder, verify_hook_stage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdi_spec::EnvList;

    fn hook(name: &str, path: &str, args: &[&str]) -> Hook {
        Hook {
            hook_name: name.into(),
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: EnvList::default(),
            timeout: None,
        }
    }
    fn code(h: Hook) -> Code {
        validate_create_container_hooks(&[h]).unwrap_err().code()
    }

    /// GPU-2: 正常系は既定 timeout 30 秒で argv をそのまま保つ。
    #[test]
    fn valid_hook_is_accepted() {
        let v = validate_create_container_hooks(&[hook(
            "createContainer",
            "/usr/bin/nvidia-cdi-hook",
            &["nvidia-cdi-hook", "create-symlinks"],
        )])
        .unwrap();
        assert_eq!(v[0].path(), "/usr/bin/nvidia-cdi-hook");
        assert_eq!(v[0].args(), ["nvidia-cdi-hook", "create-symlinks"]);
        assert_eq!(v[0].timeout_secs(), 30);
    }

    /// GPU-2: 他の OCI フック名は Unimplemented、未知は InvalidArgument。
    #[test]
    fn hook_names() {
        assert_eq!(
            code(hook("createRuntime", "/a", &["a"])),
            Code::Unimplemented
        );
        assert_eq!(code(hook("poststop", "/a", &["a"])), Code::Unimplemented);
        assert_eq!(code(hook("bogus", "/a", &["a"])), Code::InvalidArgument);
    }

    /// GPU-2: path・args・env・timeout の不正。
    #[test]
    fn invalid_fields() {
        for p in ["rel/x", "/a/../b", "/a//b", "/", "/a\\b", "/a\0b"] {
            assert_eq!(
                code(hook("createContainer", p, &["x"])),
                Code::InvalidArgument,
                "{p:?}"
            );
        }
        assert_eq!(
            code(hook("createContainer", "/a", &[])),
            Code::InvalidArgument
        );
        assert_eq!(
            code(hook("createContainer", "/a", &["x\0"])),
            Code::InvalidArgument
        );
        for bad in ["NOEQ", "=v"] {
            let mut h = hook("createContainer", "/a", &["x"]);
            h.env = EnvList::from_entries(vec![bad.into()]);
            assert_eq!(code(h), Code::InvalidArgument, "{bad}");
        }
        for t in [0i64, -1, 301] {
            let mut h = hook("createContainer", "/a", &["x"]);
            h.timeout = Some(t);
            assert_eq!(code(h), Code::InvalidArgument, "{t}");
        }
        let mut h = hook("createContainer", "/a", &["x"]);
        h.timeout = Some(300);
        assert_eq!(
            validate_create_container_hooks(&[h]).unwrap()[0].timeout_secs(),
            300
        );
    }

    /// GPU-2・REPAIR-5: 件数・長さの上限は確保前に拒否する。
    #[test]
    fn limits() {
        let many = vec![hook("createContainer", "/a", &["x"]); CDI_APPLY_MAX_HOOKS + 1];
        assert_eq!(
            validate_create_container_hooks(&many).unwrap_err().code(),
            Code::ResourceExhausted
        );
        let mut h = hook("createContainer", "/a", &["x"]);
        h.args = vec!["z".into(); CDI_APPLY_MAX_HOOK_ARGS + 1];
        assert_eq!(code(h), Code::ResourceExhausted);
        let mut h = hook("createContainer", "/a", &["x"]);
        h.args = vec!["z".repeat(CDI_APPLY_MAX_HOOK_ITEM_BYTES + 1)];
        assert_eq!(code(h), Code::ResourceExhausted);
        let mut h = hook("createContainer", "/a", &["x"]);
        h.args = vec!["z".repeat(4000); 100];
        assert_eq!(code(h), Code::ResourceExhausted);
    }

    /// env の値は Debug に出ない。
    #[test]
    fn debug_redacts_env() {
        let mut h = hook("createContainer", "/a", &["x"]);
        h.env = EnvList::from_entries(vec!["TOKEN=secret-value".into()]);
        let v = validate_create_container_hooks(&[h]).unwrap();
        assert!(!format!("{:?}", v[0]).contains("secret-value"));
    }

    const ROOT: &str = "/run/c/rootfs";
    const HOST: &str = "20 1 8:1 / / rw - ext4 /dev/sda1 rw";
    const BIND: &str = "30 20 8:1 /run/c/rootfs /run/c/rootfs rw - ext4 /dev/sda1 rw";
    const PROC: &str = "31 30 0:5 / /run/c/rootfs/proc rw - proc proc rw";

    /// GPU-2: 正しい順序は通る。
    #[test]
    fn stage_ok() {
        let mi = [HOST, BIND, PROC].join("\n");
        assert_eq!(check_hook_stage_mountinfo(ROOT, &mi), Ok(()));
    }

    /// GPU-2: 自己 bind 前は FailedPrecondition。
    #[test]
    fn stage_without_self_bind() {
        let err = check_hook_stage_mountinfo(ROOT, HOST).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "rootfs is not self-bind mounted");
    }

    /// GPU-2: `/proc` 前、または proc 以外は FailedPrecondition。
    #[test]
    fn stage_without_proc() {
        let err = check_hook_stage_mountinfo(ROOT, &[HOST, BIND].join("\n")).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "proc is not mounted under rootfs");
        let tmpfs = "31 30 0:5 / /run/c/rootfs/proc rw - tmpfs tmpfs rw";
        let err = check_hook_stage_mountinfo(ROOT, &[HOST, BIND, tmpfs].join("\n")).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    /// GPU-2: 自己 bind が `/proc` を覆った順序逆転は拒否する。
    #[test]
    fn stage_reversed_order() {
        let proc_first = "29 20 0:5 / /run/c/rootfs/proc rw - proc proc rw";
        let err =
            check_hook_stage_mountinfo(ROOT, &[HOST, proc_first, BIND].join("\n")).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "proc is not stacked directly on the rootfs bind mount"
        );
    }

    /// GPU-2: pivot 済み（rootfs が `/`）は拒否する。
    #[test]
    fn stage_pivoted() {
        for r in ["/", "//"] {
            assert_eq!(
                check_hook_stage_mountinfo(r, HOST).unwrap_err().code(),
                Code::FailedPrecondition
            );
        }
    }

    /// 重なった同一 mount point は最後の項目を採り、8 進エスケープを復号する。
    #[test]
    fn stage_last_entry_and_escape() {
        let old_bind = "25 20 8:1 /x /run/c/rootfs rw - ext4 /dev/sda1 rw";
        let stale_proc = "26 25 0:5 / /run/c/rootfs/proc rw - proc proc rw";
        let mi = [HOST, old_bind, stale_proc, BIND].join("\n");
        assert_eq!(
            check_hook_stage_mountinfo(ROOT, &mi).unwrap_err().code(),
            Code::FailedPrecondition
        );
        let b = "30 20 8:1 /r /run/my\\040c/rootfs rw - ext4 /dev/sda1 rw";
        let p = "31 30 0:5 / /run/my\\040c/rootfs/proc rw - proc proc rw";
        assert_eq!(
            check_hook_stage_mountinfo("/run/my c/rootfs", &[HOST, b, p].join("\n")),
            Ok(())
        );
    }

    /// 形式不正は Internal。
    #[test]
    fn stage_malformed() {
        assert_eq!(
            check_hook_stage_mountinfo(ROOT, "garbage line")
                .unwrap_err()
                .code(),
            Code::Internal
        );
    }
}
