//! stream-exec helper と plugin-cri の間の channel（CRI の Exec / Attach の本番 backend。CRI-6・SUP-6・REPAIR-2）。
//!
//! helper（supervisor の実行ファイルを `stream-exec` で起動した単一スレッドのプロセス。#3760）と plugin-cri
//! （#3761）は、パスを持たない socketpair（helper の fd 0）で次をやり取りする。方式の選定理由は
//! `docs/design/cri-streaming-server.md`「本番 backend の設計」（#3752。案 α: 制御チャネルの kind 6 / 7 を再利用し、
//! 新しい種別は足さない）を参照。
//!
//! - plugin-cri → helper: `StdioHandover`（要求された stdio の fd を `SCM_RIGHTS` で最大 3 本）
//! - helper → plugin-cri: `Started`・`PtyMaster`（tty のときだけ fd 1 本）・`Result`（終了の結果）
//!
//! 構成:
//! - [`wire`]: 固定長・big-endian の frame の型と codec（純粋関数。語彙の正は同モジュールの doc）
//! - [`channel`]: socketpair 上の期限つき送受信。fd の本数・向き・文字デバイスを検証して `OwnedFd` で返す
//!
//! # 未実装（REPAIR-3）
//!
//! 本モジュールは codec と fd の受け渡しだけを持つ。helper の入口（`main` の `stream-exec` 振り分け。#3760）と
//! plugin-cri 側の結線（#3761）は未実装で、現状どの経路からも呼ばれない。制御チャネル（`control`）には触れない。
//! Linux 限定（core の `exec::ExecChildStep` が Linux でしか使えないため。`exec` と同じ cfg）。

pub mod channel;
pub mod wire;
