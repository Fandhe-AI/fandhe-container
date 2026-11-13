# 子の終了直後に pipe の EOF を即時に要求する判定の点検表

対象 issue: #4641（REPAIR-5・REPAIR-12・GPU-2・CORE-1）。前例: #2999・PR #4594（gpu の `ChildIo::finish` が `STDERR_EOF_GRACE`＝1 秒の猶予を設けた）。点検表の形は `flock-release-audit.md`・`channel-send-resource-audit.md` に倣う。

## 問題の形

「子が終わった直後に pipe の EOF が来なければ、子孫が書き込み端を握っている」と即時に判定してエラーにすると、誤検出になる。同じプロセスの別スレッドが並行して fork（`Command::spawn` 等）すると、fork から exec（close-on-exec）までの窓のあいだ、別の子が書き込み端の複製を持つためである。macOS では pipe の作成と close-on-exec の設定が別 syscall のため（#3139）、複製が exec を越えて残る余地もあり、猶予だけでは覆えない場合がある。

## 判定基準

1. EOF が来ないときの帰結: (E) エラーの判定、(T) 切り詰め・観測記録のみ、(B) 期限つきの待ち、(U) 期限なしの待ち。「該当」は (E) で、かつ 2 に当たるもの。
2. 書き込み端を持ちうる者: ファイル単位ではなくホストプロセス単位。同じプロセスの別スレッドが fork しうるか、`sys::fork_single_threaded*`（`Threads: 1` を強制）の経路か。
3. 作成と close-on-exec が原子的か（Linux の `pipe2(O_CLOEXEC)`・`SOCK_CLOEXEC` か、macOS の非原子的な経路か）。

「無害」とする条件: (T)(B) である／(U) である（別観点。下記）／書き込み端を持つのが `Threads: 1` を強制した fork の子だけである。判定できないものは安全側で「該当」とする。

## 点検の範囲と検索式

`crates/{core,supervisor,net,plugin}/src` の本番コードと `#[cfg(test)]`。次の式の全一致を確認した（gpu は修正済みの参照行のみ）。

- 作成: `rg -n 'Stdio::piped|io::pipe\(|pipe2|sys::pipe|UnixStream::pair|socketpair|NetnsHolderChannel::pair|create_fds|exec_status_pipe|result_pipe' crates/{core,supervisor,net,plugin}/src`
- 判定の形: `rg -n 'poll_readable\([^)]*, *0\)|Duration::ZERO|is_complete\(\)|wait_readable\(.*(ZERO|, *0)'` と、子の回収（`try_wait`・`wait_timeout`）の直後の待たない読み取り

## 点検結果（本番コード）

| 箇所 | EOF が来ないときの帰結 | 書き込み端を持ちうる者 | 判定 |
| ---- | ---------------------- | ---------------------- | ---- |
| gpu `cdi_apply/hooks/run.rs` `ChildIo::finish` | (E) だった | 並行 spawn の子 | 修正済み（#2999・#4594。猶予 `STDERR_EOF_GRACE`。`gpu2_repair5_2999_short_lived_descendant_within_grace_*`） |
| core `exec/process.rs` `read_exec_status`（`poll_readable(fd, 0)` が偽なら `the exec status pipe is still open after exit`）と、その呼び出し元 `exec_command.rs` `ExecChild::classify`・`process.rs` の `run_command_with_pidfd` | (E)。同じ形 | `exec_status_pipe()` の作成から親側の `drop(status_write)` までが 1 関数で、fork は `fork_single_threaded*`（`Threads: 1` を強制）。子（`run_exec_child`）は `execveat` の前に fork しない | 無害（書き込み端を持つのは `Threads: 1` の fork の子だけ。複製は作成と同時の close-on-exec で子の exec 後に残らず、`dup_fd_at_least` も `F_DUPFD_CLOEXEC`）。macOS でも作成と fork の間に別スレッドが無い前提は同じ |
| core `audit_log/file_sink.rs` `result_pipe`・`read_result`・`readable_now` | データの有無だけで判定し、EOF を要求しない（T） | 子（fd 3 以上を閉じる） | 無害。`std::io::pipe` は macOS で作成と close-on-exec が非原子的だが、判定がデータ有無なので誤検出にならない |
| core `exec/launch_status.rs`・`launch_intermediate.rs` の gate・report・status 読み取り | 期限つき（B） | - | 無害 |
| core `rootless.rs` `run_helper`（非 0 終了後の stderr を `recv_timeout(1s)`） | 切り詰め（T）。エラーは終了状態で確定済み | 子孫 | 無害 |
| core `rootless/holder_expiry_probe.rs`・`holder_memory_probe.rs`・`test_support.rs` | 期限つき（B）／試験用 | - | 無害 |
| supervisor `healthcheck/exec_probe.rs`（`DRAIN_GRACE` 100ms の後に `parse_result_stream`） | 結果はソケットに残ったデータで判定、EOF 未達は判定に使わない（T） | 子孫 | 無害 |
| supervisor `logs.rs`・`run.rs` の drain（`DEFAULT_DRAIN_TIMEOUT`） | 結果は保たれる（`sup1_task157_7_drain_timeout_keeps_outcome`）（T） | 孫 | 無害 |
| supervisor `user_db.rs` `run_getent` | 全体期限で `Timeout`（B） | 子孫 | 無害 |
| supervisor `start_client.rs`・`control/client.rs`・`attach_io.rs`・`stream_exec/*`・`log_pipeline.rs` | 1 行または期限で判定し、EOF を即時に要求しない | - | 無害 |
| supervisor `exec.rs` `collect_worker_result`（worker 終了後の `read_until(b'\n')`） | worker が結果を書いてから終了するので通常は行がある。行が無いと EOF まで待つ（U） | 並行 spawn の子 | 無害（別観点 A） |
| supervisor `netns_holder.rs` `drain_stderr`（回収後の `read_to_end`） | EOF まで待つ（U）。holder は fork しない前提 | 並行 spawn の子 | 無害（別観点 A） |
| net `dns_helper.rs`・`dns_helper/detach/os.rs`（`read_line_deadline` の期限 0 は次の行の有無の確認）・`netns.rs`・`netns_helper.rs`・`netns_dial/*`・`sys/holder.rs` | 行と期限で判定（B）。失敗経路の `REAP_TIMEOUT_DEFAULT` は回収の期限で EOF 判定ではない | - | 無害 |
| net `pasta/binary.rs` `collect` | 期限つきで EOF を待つ（B） | - | 無害 |
| net `pasta/process.rs` の `drain(..., Duration::ZERO)` | stderr 抜粋の切り詰め（T） | 子孫 | 無害 |
| plugin `lifecycle.rs`・`lifecycle/resident.rs` の `StderrCapture`（`PLUGIN_STDERR_DRAIN_TIMEOUT` 500ms） | `is_complete()=false` は観測記録にだけ出る（T）。猶予済み | 孫 | 無害。macOS は `spawn_gate` で作成と close-on-exec を排他済み（#3139） |
| plugin `spawn_gate.rs`・`sys.rs`・`transport.rs`・`uds_security.rs` | 期限つき（B） | - | 無害 |

## 試験コード

製品の判定がエラーにする形（E）は core の `read_exec_status` だけで、その試験は並行する libtest の fork の影響を受けるため、既に次の回避策を持つ。新たな修正は不要。

- `process.rs` の `sup6_2822_pre_step_failure_is_reported_with_its_step`・`sup6_2895_parent_lifetime_code_roundtrips`・`sup6_task163_read_exec_status_never_blocks`: pipe の作成からの 200 回再試行
- `exec_command.rs` の `sup6_task163_concurrent_waiters_share_one_exec_status`: 判定不能の回を許す assert（全員が同じ判定で揃うことを具体値で照合）
- `sup6_task163_unreadable_exec_status_is_not_reinterpreted`・`core2_start_gate_requires_release_and_fails_on_eof`: 書き込み端を自分で保持／EOF と `Err` の両方が失敗として等価で、複製の有無に結果が依存しない

## 別観点（本 issue の範囲外）

期限の無い読み取り（A）: `supervisor/exec.rs` `collect_worker_result` の結果行なしの場合と `netns_holder.rs` `drain_stderr` は、並行 spawn の子が書き込み端の複製を持つ窓のあいだだけ待つ。複製は exec で閉じるため有界だが、読み取り自体に期限は無い（REPAIR-5）。誤検出ではなく待ちの型なので本 issue では直さない。

## 結論

修正箇所なし。同型の即時判定（E）は gpu（修正済み）と core `read_exec_status` の 2 か所だけで、後者は `Threads: 1` を強制する fork の経路にだけ書き込み端が渡るため本番では起きない。受け入れ条件の「猶予の内側で終わる孫プロセスの試験」は対象なし。他 crate（cri・plugin-cri・oci・cli 等）は範囲外。
