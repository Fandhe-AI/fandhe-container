//! `containerd-shim-fandhe-container-v2` の入口（CRI-5・TASK-62.7.1・MS-7・#872）。
//!
//! containerd が exec する shim バイナリの薄い main。引数の解釈と start / delete / serve の本体は
//! `fandhe_container_cri::shim_v2::bootstrap` にあり、ここでは結果の出力と終了コードだけを扱う。
//! 登録するサービスは中身の無い Task サービス（v2・v3）だけで、本番の `ContainerRuntime` の結線は
//! 後続（cri は plugin-cri へ依存できないため。bootstrap の doc を参照。REPAIR-3）。
//! 失敗時は stdout へ何も書かず、stderr へ `{"code":"<CODE>","message":"<message>"}` の 1 行（JSON）を出して終了コード 1 にする（ERR 系）。
//! start の成功経路では stderr へ何も書かない（containerd が stdout と stderr をまとめて読むため）。

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::bootstrap::{parse_args, run};
use fandhe_container_cri::shim_v2::{EmptyTaskService, ServiceRegistry, TaskApiVersion};

fn registry() -> Result<ServiceRegistry, CriError> {
    let mut reg = ServiceRegistry::new();
    for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
        reg.register(Arc::new(EmptyTaskService::new(v)))
            .map_err(|_| CriError::internal("cannot register task service"))?;
    }
    Ok(reg)
}

fn main() -> ExitCode {
    let result = parse_args(std::env::args_os().skip(1)).and_then(|inv| run(inv, registry));
    match result {
        Ok(bytes) => {
            let mut out = std::io::stdout();
            if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            let line = serde_json::json!({
                "code": e.code().as_str(),
                "message": e.message(),
            });
            eprintln!("{line}");
            ExitCode::FAILURE
        }
    }
}
