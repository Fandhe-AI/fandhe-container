//! supervisor の制御チャネル用の監査 relay の組み立て（Linux。SEC-4・REPAIR-5・#3415。#3300 の残り）。
//!
//! 呼び出し元: `start_entry::run_main_inner`（スレッドを作る前）と、本番と同じ組み立てを通す結合試験
//! `tests/control_audit_delivery.rs`。組み立てを 1 か所に置くのは、helper の止まり方の選択
//! （[`ControlAuditRelay::spawn_ignoring_stop_signals`]）を試験が固定できるようにするため。
//!
//! # 契約
//! - 呼び出しプロセスが単一スレッドのときだけ成功する（relay の fork の条件）。
//! - helper は SIGTERM・SIGINT を無視する。supervisor は `process_group(0)` のリーダーで、`systemd-run --user --scope`
//!   の中で動くため、グループ宛て・scope の停止（`KillMode=control-group`）の SIGTERM は helper にも届く。
//! - plugin-cri（#3300）と理由が異なる: supervisor 本体は SIGTERM・SIGINT のハンドラを持たず、停止シグナルでは本体も
//!   即座に死ぬ。ここで守れるのは、シグナル到着時に helper が書いている途中の 1 件だけである（`SIG_IGN` なら書き終えて
//!   から socketpair の EOF で終わる）。
//! - helper の終わりは本体の終了（EOF）か SIGKILL。本体が死んだ後の残存は最悪 `RECORD_WAIT_LIMIT`（REPAIR-5）で、
//!   scope の停止がその分だけ遅れ得る。SIGKILL は無視できないため最終の回収は妨げない。
//! - helper は exec しないので、`SIG_IGN` はコンテナ内のコマンドへ持ち込まれない（コンテナは本体から作る）。

use fandhe_container_core::audit_log::{ControlAuditRelay, FileAuditSink};
use fandhe_container_core::traits::TraitError;

/// 監査専用の helper を fork し、記録先を開けることまで確かめて返す。`root` が `None` なら既定の状態ルート。
/// 記録先を開けなければ型付きの `TraitError` を返す（呼び出し側は起動を拒否する。fail-closed。#2027）。
pub fn open_control_audit_relay(
    root: Option<std::path::PathBuf>,
) -> Result<ControlAuditRelay, TraitError> {
    FileAuditSink::open_in_state_root(root)
        .and_then(ControlAuditRelay::spawn_ignoring_stop_signals)
        // sink と helper を作れただけでは記録できるとは限らない（`@audit.log` がディレクトリ等だと記録時に初めて失敗する）。
        .and_then(|relay| relay.probe().map(|()| relay))
}
