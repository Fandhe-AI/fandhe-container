# user namespace の中で展開・削除する再 exec helper

plugin-cri が範囲写像（subuid / subgid）の user namespace の中でレイヤーを展開し、subuid 所有の木を削除するための
再 exec helper の設計記録。親 issue は #4777（オーナー承認済み。判断シート 11 の節 6・推奨一式）。本書は H1（#4795）の
入口の範囲と H3（#4800）の削除モードを扱う。ビヘイビア: SEC-5・OCI-1・OCI-2・OCI-7・CORE-6・REPAIR-5。

## 背景

マルチスレッドの plugin-cri プロセスは core の `isolate_rootless_subordinate`（単一スレッド必須。`MultiThreaded` で拒否）を
呼べないため、user namespace に入れない。このため `extract_identity` の `RootlessSubordinateIds` は暫定で `Keep` + `Strip`
のまま（[oci-layer-special-bits.md](./oci-layer-special-bits.md)）。plugin-cri 自身を固定の隠し引数で再 exec した単一スレッドの
helper を作り、参加後の処理を helper に任せる。

## 作業単位

| 単位 | 内容 | 状態 |
| ---- | ---- | ---- |
| H1（#4795） | 入口の振り分け・親側の起動部品・参加・結果の返却（Inspect・StatTarget） | 本書。実装済み |
| H2 | 展開の本体（Extract。tag 3） | 未 |
| H3（#4800） | 削除（Remove。tag 4）と plugin-cri の削除器・cri の注入点 | 本書。実装済み（有効化は H6） |
| H4 | `image_ownership` の複製と fixture | 未 |
| H5 | pull / start の subuid のずれの照合 | 未 |
| H6 | `extract_options_for` の対応表の切り替え | 未 |
| H7 | CI への組み込み・成功行の照合・所要時間の記録 | 未 |

## 構成

```text
plugin-cri（親。マルチスレッド）
  └─ UsernsHelperLauncher::run(mode, target_fd, work_budget)   同期のブロッキング API
       └─ /proc/self/exe を隠し引数 __extract-in-userns で再 exec（単一スレッドの helper）
            fd 0: 親との UnixStream（要求・応答 frame）
            fd 1: 対象ディレクトリの fd（パスは渡さない）
            fd 2: null
```

- 実装: `crates/plugin-cri/src/userns_helper/`（`wire.rs` は OS 非依存、`helper.rs`・`launcher.rs` は Linux のみ、`remover.rs` は Linux の x86_64 / aarch64 のみ）
- 入口: `main.rs` の先頭、引数解析より前に第 1 引数を見て振り分ける。tokio・thread・`LineSink` を作らない
- argv は `[__extract-in-userns]` の 1 個だけ。環境変数は空、cwd は `/`。余分な引数は応答なしで終了コード 2
  （パスや設定を引数で受けない）
- 実体は `/proc/self/exe` を 1 回開いて通常ファイルを確かめ、その fd を `/proc/self/fd/N` として exec する
  （検証した実体を起動し、パスを探し直さない。PLUG-11 の考え方。`pod_holder` と同じ手法）
- `pre_exec` と SCM_RIGHTS は使わない（`unsafe` の面を `sys` の 2 つ〔prctl・close_range〕に保つ）

## ワイヤー形式（REPAIR-2）

- 要求: 8 バイトの header `[version = 1, mode tag, 0, 0, payload_len(u32 BE)]` + payload。上限は 16 KiB で、`payload_len` の
  超過は payload を読む前・確保する前に `request_too_large`
- 応答: 固定 32 バイト `[version, status, mode または error tag, flags, u32 × 7]`。未使用のスロットが 0 でなければ拒否
- モード: Inspect（tag 1。`joined`・`threads`・`dumpable`・`euid`・`egid`・写像の行数）、StatTarget（tag 2。対象 fd の uid・gid・mode）。
  Remove（tag 4。H3）は固定 4 バイトの payload `[target tag, 0, 0, 0]`（target 1 = bundle の `rootfs`、2 = pull の `unpack`）。
  tag 3（Extract。H2）は予約で `unimplemented` を返す（実装済みを装わない。REPAIR-3）。helper は header を検査して期待の長さ
  （tag ごとに固定）が決まってから、その長さだけを固定長バッファへ読む（確保しない）。長さ違い・未知の target・予約バイト非 0 は
  `invalid_request`。応答は `Removed`（mode tag 4・スロット全 0）
- エラー語彙（固定。パス・errno・uid を含めない。REPAIR-4）: `invalid_request`・`request_too_large`・`unimplemented`・
  `multi_threaded`・`no_subordinate_ids`・`join_failed`・`not_non_dumpable`・`request_timeout`・`remove_refused`（マウント越え・種別違い等。`FailedPrecondition`）・`remove_failed`（それ以外。`Internal`）・`internal`。親側では core の
  `ErrorCode`（`InvalidArgument`・`Unimplemented`・`FailedPrecondition`・`Timeout`・`Internal`）へ写す

## helper の手順（順序は変えない）

1. argv の検査
2. `PR_SET_DUMPABLE` を 0 にして読み戻す（exec 直後は dumpable が 1 に戻るため最初に落とす。窓は exec からここまで）
3. `close_range(3, !0, 0)` で fd 3 以上を閉じる。失敗は `ENOSYS` を含め応答なしで終了コード 1
4. fd 0・1 を dup して所有する（`from_raw_fd` を使わない）。fd 0 は socket でなければ終了、fd 1 はディレクトリでなければ `invalid_request`
5. 権限モデルを start と同じ解決（`resolve_self_launch_privilege`）で得る。範囲写像の rootless でなければ `no_subordinate_ids`
6. `/proc/self/status` の `Threads:` が 1 であることを参加の直前に確かめ（解決が一時スレッドを使う場合に備える）、core の公開 API
   （`plan_rootless_subordinate`・`isolate_rootless_subordinate`）で user namespace へ参加する
7. 参加後に non-dumpable を再確認する（呼び出し元が non-dumpable ならその状態が保たれる。
   [rootless-id-map-holder.md](./rootless-id-map-holder.md) §3・§4・§4.1）
8. 要求 frame を読む（期限 2 秒）
9. モードを実行して応答を書く。成功は終了コード 0、応答できた失敗は 1

## 削除モード（H3。#4800・SEC-5・OCI-7・CORE-6・REPAIR-4・REPAIR-5）

範囲写像で展開した木はホストから見ると subuid 所有で、ホスト uid の `unlinkat`・`chmod` は `EPERM` で失敗しうる。
core の `remove_tree_in_userns` は単一スレッドの fork 前提で tokio の plugin-cri からは使えないため、同じ写像の user namespace に
入った helper が消す。

- 対象: fd 1 に**親ディレクトリ**を渡し（最上位自身が subuid 所有・0700 でもホスト側から開き直さずに済む）、消す子の名前は
  要求の target tag で固定の 2 種（`rootfs`・`unpack`）から選ぶ。任意のパス・名前は受けない
- 実行: fd 1 の複製を `/proc/self/fd/N` として oci の `ExtractRoot::open_proc_fd_link` で開き、`remove_child_tree_bounded`
  （symlink を辿らない・各エントリで mount ID を照合してマウントをまたがない・深さの上限・不在は成功）で消す。新しい再帰削除は書かない
- 木の外を消さない: 名前空間の中の能力は写像内の所有者の inode にしか効かず、他ユーザーの実体は構造的に消せない（多層防御）。
  `rootfs` / `unpack` が symlink に差し替えられても辿らず、リンク自体を unlink するだけでリンク先は残る。`remove_refused` は
  木の中のマウント越え等で返る
- helper 自身は期限を持たず、親の期限切れ（`JOIN_BUDGET` + `WorkBudget`）の kill・回収で止まる。削除は冪等で、途中で kill されても
  再実行が続きから消す
- cri の注入点: `fandhe-container-cri` の `SubordinateTreeRemover`（`bundle/tree_remover.rs`。plugin-cri → cri の依存方向のため
  cri 側にトレイトを置く）。`ImageRootfsSource`（`release_bounded`・展開失敗時の後始末）と `OciImagePuller`（pull の `unpack/` の
  後始末。親は oci の `PullSession::pull_dir_fd`）が、展開設定が `ChownInUserNamespace` のとき（`needs_userns_removal`）だけ
  注入された remover へ回す。それ以外（`Keep` 等）は従来のホスト側の削除のまま。真なのに remover が無ければホスト側へ縮退せず
  `FAILED_PRECONDITION`
- 本番の削除器: plugin-cri の `UsernsTreeRemover`（`userns_helper/remover.rs`。Linux x86_64 / aarch64）。プロセスで 1 つを pull 側と
  create 側が共有する。期限は呼び出し側の `ReleaseBudget` の残りから `JOIN_BUDGET` を引いて 1〜600 秒に丸める（期限なしは 120 秒）。
  同時実行は稼働中 + 回収できていない子の合計が 4 に達したら待たずに `UNAVAILABLE`。回収できなかった子は保持し、次の呼び出しの先頭で
  `try_wait` で掃く。失敗は固定文言の `CriError`（`Timeout`・`FailedPrecondition`・`Unavailable`・`Internal`）で返す
- 残余: 取り消しの旗は helper の実行中には見られない（開始前だけ）ため、全体の待ちは呼び出し側の期限を最大 `JOIN_BUDGET`（25 秒）
  超えうる。`PullSession::abort` と起動時の pull 回収 GC は oci 内のホスト側の削除のままで、subuid 所有の残骸（unpack の削除に
  失敗した `staging/<id>`）は消せない（H6 で実害が出る前に別 issue。起票は承認後）。公開済み rootfs の GC は TASK-183 が未実装
- 有効化: 対応表（`extract_options_for`）が `ChownInUserNamespace` を返すまで本番では通らない。切り替えは H6（#4801）。
  実機試験は `userns_helper_real`（CI への組み込みは H7・#4802）

要求を参加の後に読む理由: holder は exec しない fork で、呼び出し時点のメモリを複製する。dumpable な holder が要求の bytes を
持たないようにし、H2 が増やす fd・options が holder の窓に入らないようにする。H1 の要求に機密は無いが、順序は H2 のために固定する。

### holder の窓と fd 0・1・2 の扱い

holder（user namespace を作って保持する使い捨てプロセス）は fd 3 以上を閉じた後の複製で、fd 0・1・2 を保持する。
fd 0（制御 socket の片端）と fd 1（対象ディレクトリ）が残るが、fd は権限を持ち込まない。`openat` は呼び出し側の資格情報で検査され、
同じ uid は namespace の所有者として元々同じ権限を持つ。holder の生存は `release_wait` までで、参加後に release される。

## 親側の待ち（REPAIR-5）

- 全体期限は `JOIN_BUDGET`（3 × `DEFAULT_HELPER_TIMEOUT` + 5 秒 + slack 5 秒 = 25 秒）+ `WorkBudget`（1〜600 秒の newtype）
- 手順: spawn → 要求の書き込み（write timeout）→ 応答 32 バイトを残り時間で読む → 子の終了を最大 1 秒待つ
- 期限切れ・EOF・不正な応答・終了コードの不整合は kill → 最大 500 ms の回収。回収できなかった子は `UsernsHelperError::take_unreaped()` で
  呼び出し側へ返す
- `PDEATHSIG` は使わない（呼び出しスレッドに結びつくため、tokio の blocking thread で壊れる）。親が死ねば socket が EOF になり、
  helper は次の読み書きで終わる
- 1 呼び出し 1 プロセスで、同時実行数の上限は呼び出し側（H2・H3。H3 は `UsernsTreeRemover`）が持つ

## 試験専用の入口

feature `userns-helper-test-support`（既定オフ。release で有効にするとコンパイルが止まる）が有効なときだけ、helper が追加 argv
`--no-join` を受ける（参加を省いて `joined = false` で応答）。root・subuid の無い既定の集合で、実バイナリの `Threads: 1`・
non-dumpable・入口の検査を照合するため。本番のビルドには存在しない。参加経路の実機確認は `userns_helper_real`
（[real-machine-tests.md](../verification/real-machine-tests.md)）。

## 判断記録（Agent の判断・オーナー未承認の区別）

- 承認済み: 再 exec する helper 方式そのもの（#4777 の判断シート 11 の節 6）
- Agent が安全側に倒した判断（オーナー未承認）:
  - H1 で SCM_RIGHTS を足さない（`unsafe` の面を最小に保つため）。H2 は fd が対象ディレクトリ 1 本を超える場合に再検討する
  - helper の peer 認証を設けない。helper は同じ uid の誰でも手で起動できるが、得られるのは同じ uid が `newuidmap` で作れる
    namespace だけで新しい権限は無い（SO_PEERCRED の `unsafe` を増やさない）
  - 要求の読み取りを参加の後に置く（上記）

## unsafe（`sys` の外に足さない）

`crates/plugin-cri/src/sys.rs` の `hardening` に `prctl(PR_SET_DUMPABLE / PR_GET_DUMPABLE)` と
`syscall(SYS_close_range)` の薄いラッパーを足した（LP64 の x86_64・aarch64 の Linux のみ。他の組は `Unsupported` を返し helper は
fail-closed で終了）。値は定数の `const _` assert と `#[test]` で具体値として固定する（plugin-cri は libc の dev-dependency を
持たない。#3290）。
