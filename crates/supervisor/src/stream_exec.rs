//! stream-exec helper と plugin-cri の間の channel（CRI の Exec / Attach の本番 backend。CRI-6・SUP-6・REPAIR-2）。
//!
//! helper（supervisor の実行ファイルを `stream-exec` で起動した単一スレッドのプロセス。#3760）と plugin-cri
//! （#3761）は、パスを持たない socketpair（helper の fd 0）で次をやり取りする。方式の選定理由は
//! `docs/design/cri-streaming-server.md`「本番 backend の設計」（#3752。案 α: 制御チャネルの kind 6 / 7 を再利用し、
//! 新しい種別は足さない）を参照。
//!
//! - plugin-cri → helper: `StdioHandover`（要求された stdio の fd を `SCM_RIGHTS` で最大 3 本）
//! - plugin-cri → helper: `Signal`（exec のコマンドへ SIGKILL 以外の許可されたシグナルを送る要求。wire v3・#4282）
//! - helper → plugin-cri: `Started`（exec 子 cgroup の名前を運ぶ。#4221）・`PtyMaster`（tty のときだけ fd 1 本）・`Result`（終了の結果）・`SignalAck`（`Signal` の結果。#4282）
//!
//! 構成:
//! - [`wire`]: 固定長・big-endian の frame の型と codec（純粋関数。語彙の正は同モジュールの doc）
//! - [`channel`]: socketpair 上の期限つき送受信。fd の本数・向き・mask・pty master を検証して返す（受信失敗後は再利用しない契約。channel の doc）
//! - [`diag`]: helper の起動失敗の段名・errno を fd 2 へ出す診断行の語彙と組み立て（#4284）
//! - [`helper`]: helper の本体（`main` の `stream-exec` 振り分けの先。引数・処理順・結果の写像。#3760）
//!
//! # 未実装（REPAIR-3）
//!
//! helper は実装済み（#3760）で、plugin-cri 側の結線は #3761 で実装済み（受け取る stdio は socket か FIFO に限る）。
//! tty は helper 側（`--tty`・pty の割り当て・`PtyMaster` の `Started` の後・`Spawned` の前の送信）が #4416 で実装済みで、plugin-cri 側の有効化（`HelperCapabilities.tty`・`without_tty` の撤去）も #4417 で実装済み。helper は exec の待ちの刻みごとに fd 0 を見て `Signal` を受ける（#4282）が、plugin-cri が helper を kill
//! せずに死んだ場合は exec の期限（`--timeout-ms`）まで動く（詳細は [`helper`]）。制御チャネル（`control`）には触れない。
//! Linux 限定（core の `exec::ExecChildStep` が Linux でしか使えないため。`exec` と同じ cfg）。

pub mod channel;
pub mod diag;
pub mod helper;
pub mod wire;
