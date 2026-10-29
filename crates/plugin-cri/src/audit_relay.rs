//! plugin-cri の監査 relay の組み立て（Linux。SEC-4・PLUG-12・REPAIR-5・#3300）。
//!
//! 呼び出し元: `main.rs` の `serve`（スレッドを作る前）と、本番と同じ組み立てを通す結合試験
//! `tests/shutdown_audit_helper.rs`。組み立てを 1 か所に置くのは、helper の止まり方の選択
//! （[`ControlAuditRelay::spawn_ignoring_stop_signals`]）を試験が固定できるようにするため。
//!
//! # 契約
//! - 呼び出しプロセスが単一スレッドのときだけ成功する（relay の fork の条件）。
//! - helper は SIGTERM・SIGINT を無視する。プロセスグループ宛て・systemd の cgroup 全体宛ての停止シグナルで本体より
//!   先に死ななければ、ドレイン中の peer 認証の拒否が `@audit.log` に届く（SEC-4）。終わるのは本体の終了
//!   （socketpair の EOF）か SIGKILL のとき。本体が死んだ後の残存は最悪 `RECORD_WAIT_LIMIT`（`shutdown::AUDIT_HELPER_LINGER_BOUND`）。

use std::path::PathBuf;
use std::sync::Arc;

use fandhe_container_core::audit_log::{ControlAuditRelay, FileAuditSink};

/// 監査専用の helper を fork して記録先を確かめる。`state_root` が `None` なら既定の状態ルート。
/// 失敗したら固定文言のエラーコードトークンを返す。
pub fn open_audit_relay_in(
    state_root: Option<PathBuf>,
) -> Result<Arc<ControlAuditRelay>, &'static str> {
    let relay = FileAuditSink::open_in_state_root(state_root)
        .and_then(ControlAuditRelay::spawn_ignoring_stop_signals)
        .and_then(|relay| relay.probe().map(|()| relay))
        .map_err(|e| e.code().as_str())?;
    Ok(Arc::new(relay))
}
