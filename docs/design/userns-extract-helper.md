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
| H2（#4796） | 展開の記録の符号化 | 実装済み |
| 展開モード（#4847） | 展開モード（Extract・tag 3）の wire・helper 内の展開・親側の期限つき入口（`run_extract_bounded`）・blob の fd の `SCM_RIGHTS` の受け渡し | 本書。実装済み（cri の注入点と pull・create からの呼び出しは後続の issue） |
| H3（#4800） | 削除（Remove。tag 4）と plugin-cri の削除器・cri の注入点 | 本書。実装済み（有効化は H6） |
| H4（#4798） | `image_ownership` の複製と fixture | 実装済み |
| H5（#4799） | pull / start の subuid のずれの照合 | 実装済み |
| H6（#4801） | `extract_options_for` の対応表の切り替え | 未（着手前確認で `PreserveIfChowned` と create の rootfs 0755 化が両立せず、オーナー判断待ち。[oci-layer-special-bits.md](./oci-layer-special-bits.md)「`PreserveIfChowned` と rootfs の 0755 化の両立」） |
| H7（#4802） | CI への組み込み・成功行の照合・所要時間の記録 | 未 |

H 番号の注記: #4796（H2）の実体は符号化のみで、展開モード（Extract・tag 3）は #4847 で実装した。以降は展開モードを #4847 と書く。

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
- `pre_exec` は使わない。SCM_RIGHTS は展開モードの blob の fd だけに使う（`sys::fd_passing`。後述「展開モード」）

## ワイヤー形式（REPAIR-2）

- 要求: 8 バイトの header `[version = 1, mode tag, 0, 0, payload_len(u32 BE)]` + payload。上限は 16 KiB で、`payload_len` の
  超過は payload を読む前・確保する前に `request_too_large`
- 応答: 固定 32 バイト `[version, status, mode または error tag, flags, u32 × 7]`。未使用のスロットが 0 でなければ拒否
- モード: Inspect（tag 1。`joined`・`threads`・`dumpable`・`euid`・`egid`・写像の行数）、StatTarget（tag 2。対象 fd の uid・gid・mode）。
  Remove（tag 4。H3）は固定 4 バイトの payload `[target tag, 0, 0, 0]`（target 1 = bundle の `rootfs`、2 = pull の `unpack`）。
  tag 3（Extract。#4847）は固定部 48 バイト + レイヤー 1〜128 件 × 76 バイトの可変長（後述「展開モード」）。helper は header を
  検査して期待の長さ（tag ごとに固定、Extract は `48 + n × 76`）が決まってから、その長さだけを固定長バッファへ読む（確保しない）。長さ違い・未知の target・予約バイト非 0 は
  `invalid_request`。応答は `Removed`（mode tag 4・スロット全 0）
- エラー語彙（固定。パス・errno・uid を含めない。REPAIR-4）: `invalid_request`・`request_too_large`・`unimplemented`・
  `multi_threaded`・`no_subordinate_ids`・`join_failed`・`not_non_dumpable`・`request_timeout`・`remove_refused`（マウント越え・種別違い等。`FailedPrecondition`）・`remove_failed`（それ以外。`Internal`）・`extract_failed`
  （展開モード。error tag 12。応答のスロット 0 に oci の分類の固定表 tag〔1 = `InvalidArgument`・2 = `Unimplemented`・3 = `Unavailable`・
  4 = `Timeout`・5 = `PermissionDenied`・6 = `NotFound`・7 = `DataLoss`・8 = `ResourceExhausted`・9 = `FailedPrecondition`・
  10 = `AlreadyExists`・11 = `Internal`〕。他の失敗ではスロット 0 は 0 必須。core への写像は `DataLoss` と未知を `Internal`、他は同名）・`internal`。親側では core の
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
8. 要求 frame を読む（期限 2 秒）。展開要求なら続けて blob の fd を `SCM_RIGHTS` で 1 通受ける（同じ期限。token・本数が要求と
   合わなければ `invalid_request`）
9. モードを実行して応答を書く。成功は終了コード 0、応答できた失敗は 1

## 展開モード（#4847・SEC-5・OCI-1・OCI-2・CORE-6・REPAIR-2・REPAIR-5）

- 要求 payload（BE・固定長）: 固定部 48 バイト = `[ownership tag（1 = ChownInUserNamespace のみ）, special bits tag（1 = Strip・
  2 = PreserveIfChowned）, layer_count(u16), work_ms(u32, 1〜600000), u64 × 5（max_entries・max_total_bytes・max_input_bytes・
  max_tracked_paths・max_uncompressed_bytes）]`、レイヤー 76 バイト = `[media 添字, 0, 0, 0, size(u64), digest(32 バイト), diff_id(32 バイト)]`（media 添字は `LAYER_MEDIA_TYPES` の 1 起点で、
  文字列は送らない）。最大 48 + 128 × 76 = 9776 バイトで、16 KiB の上限に収まる。
  長さ・件数・版・予約欄・各値の範囲は確保の前に検査する。制限値は 1 以上かつ oci の既定値以下（親が上限を広げられない。
  既定値より大きい上限が要るときは wire の変更が要る）
- fd の割り当て: fd 0・1・2 は変えない。展開先は fd 1 を `/proc/self/fd/N` として開いた `ExtractRoot`（削除モードと同じ手法。パスは渡さない）。
  blob の fd だけを、要求 frame の後に 1 バイトの token（`0x58`）に添えて 1 通の `SCM_RIGHTS` で送る（上限 `MAX_EXTRACT_LAYERS` = 128。
  `SCM_MAX_FD` の 253 以下）。helper は参加の後に受けるため、dumpable な holder の窓に fd・要求は入らない
- 所有者の写像は wire で受けない。helper が参加に使った写像（`resolve_id_maps` の結果）から `OwnershipPolicy::ChownInUserNamespace` を作る
  （親が任意の写像を注入できない。変換は `image_ownership::to_oci_map` を再利用し、複製しない）。`--no-join`（試験専用）だけは写像が
  無いので `Keep`
- helper の展開: 各 fd を `VerifiedLayerBlob::from_file`（通常ファイル・所有者・nlink 1・g/o 書き込み不可と digest・サイズの再検証。
  所有者は名前空間の中から見た euid）に通し、`extract_image_layers_bounded_in` で展開する。期限は要求を受けた時点から `work_ms`
  （oci の `ExtractBudget`）。結果は `Extracted`（mode tag 3。スロット 0 = レイヤー数、1 = エントリ数の合計）か `extract_failed` + 分類
- 親側: `UsernsHelperLauncher::run_extract_bounded(request, blobs, dest, work_budget, hard_deadline, cancel)`。spawn の前に、件数の
  一致・blob が通常ファイル・展開先がディレクトリ・上限以下の件数（超過は `ResourceExhausted`）を検査する（副作用なし）。
  待ちは `run_bounded` と同じ（絶対期限・取り消しの旗・kill・回収）。helper へ渡す `work_ms` は作業予算と期限までの残りの小さい方（1 ms 以上）
- 契約: blob の fd は親と helper が open file description を共有するため、展開が終わるまで親は読まない・seek しない。`Err` のとき
  展開先は途中まで書かれているので、呼び出し側が破棄する。同時実行数の上限は呼び出し側が持つ
- 対象外・残余: 閉じ込めの祖先（`extract_image_layers_confined_in` の `ancestor`）は渡さない（根の 0700 化は #4801 のオーナー判断待ち。
  必要になったら wire の予約欄で足す）。cri の注入点と pull・create からの呼び出し・対応表の切り替え（#4801）・CI への組み込み（#4802）は後続。
  helper の中の oci 操作記録（`OciOpRecorder`）は捨てる（観測は親の呼び出し単位）

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
- 期限と取り消し: `UsernsTreeRemover` は呼び出し側の絶対期限と取り消しの旗を `run_bounded` へ渡す。launcher は絶対期限で待ちを
  制限し、応答待ちの間も 100 ms 間隔（`CANCEL_POLL`）で旗を確認する。どちらかが尽きたら helper を kill・回収して `Timeout` を返す。
  期限後の kill・回収に要する猶予（`JOIN_BUDGET` とは別）だけが呼び出し側の期限を超えうる。
- 残余: `PullSession::abort` と起動時の pull 回収 GC は oci 内のホスト側の削除のままで、subuid 所有の残骸（unpack の削除に
  失敗した `staging/<id>`）は消せない（H6 で実害が出る前に別 issue。起票は承認後）。公開済み rootfs の GC は TASK-183 が未実装
- 有効化: 対応表（`extract_options_for`）が `ChownInUserNamespace` を返すまで本番では通らない。切り替えは H6（#4801）。
  実機試験は `userns_helper_real`（CI への組み込みは H7・#4802）

要求を参加の後に読む理由: holder は exec しない fork で、呼び出し時点のメモリを複製する。dumpable な holder が要求の bytes を
持たないようにし、展開モードの fd・options が holder の窓に入らないようにする。H1 の要求に機密は無いが、順序は展開モードのために固定する。

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
- 1 呼び出し 1 プロセスで、同時実行数の上限は呼び出し側（削除は `UsernsTreeRemover`。展開は後続の issue）が持つ

## 試験専用の入口

feature `userns-helper-test-support`（既定オフ。release で有効にするとコンパイルが止まる）が有効なときだけ、helper が追加 argv
`--no-join` を受ける（参加を省いて `joined = false` で応答）。root・subuid の無い既定の集合で、実バイナリの `Threads: 1`・
non-dumpable・入口の検査を照合するため。本番のビルドには存在しない。参加経路の実機確認は `userns_helper_real`
（[real-machine-tests.md](../verification/real-machine-tests.md)）。

## 判断記録（Agent の判断・オーナー未承認の区別）

- 承認済み: 再 exec する helper 方式そのもの（#4777 の判断シート 11 の節 6）
- Agent が安全側に倒した判断（オーナー未承認）:
  - H1 では SCM_RIGHTS を足さなかった（`unsafe` の面を最小に保つため）。展開モード（#4847）は fd が対象ディレクトリ 1 本を超える
    （レイヤーの blob）ため再検討し、`sys::fd_passing` を足した（blob の fd だけに使い、1 通・上限 128 本・`MSG_CMSG_CLOEXEC`・
    制御長を期待本数に切り、超過・形式違反はすべて閉じて拒否する）
  - 展開モードの写像は wire で受けず helper が参加に使ったものを使う。`--no-join` は `Keep`（試験専用。本番のビルドに無い）
  - 件数の上限 128 は Docker / overlay 系の実用上の層数（約 127）を超える値で、`SCM_MAX_FD`（253）以下
  - mediaType は `LAYER_MEDIA_TYPES` の添字（表を単一の真実源にする）。表に無い値は親が spawn の前に `Unimplemented` で拒否する
  - blob は helper の中で `VerifiedLayerBlob::from_file` により再検証する（「検証したハンドルから展開する」の不変条件を保つ。
    読み直しの I/O が増える代償は受ける）
  - helper の peer 認証を設けない。helper は同じ uid の誰でも手で起動できるが、得られるのは同じ uid が `newuidmap` で作れる
    namespace だけで新しい権限は無い（SO_PEERCRED の `unsafe` を増やさない）
  - 要求の読み取りを参加の後に置く（上記）

## unsafe（`sys` の外に足さない）

`crates/plugin-cri/src/sys.rs` の `hardening` に `prctl(PR_SET_DUMPABLE / PR_GET_DUMPABLE)` と
`syscall(SYS_close_range)` の薄いラッパーを足した（LP64 の x86_64・aarch64 の Linux のみ。他の組は `Unsupported` を返し helper は
fail-closed で終了）。値は定数の `const _` assert と `#[test]` で具体値として固定する（plugin-cri は libc の dev-dependency を
持たない。#3290）。

展開モード（#4847）で `sys/fd_passing.rs`（`sendmsg` / `recvmsg` による `SCM_RIGHTS` の送受信）を足した。安全な `send_fds` /
`recv_fds` だけを公開し、`unsafe fn` を `sys` の外へ出さない。`msghdr` のレイアウト（56 バイト）・`SOL_SOCKET`・`SCM_RIGHTS`・
`MSG_*` は const assert と `#[test]` で具体値に固定し、制御データの解析は境界を checked で見て形式違反を拒否する。
LP64 の x86_64・aarch64 の Linux のみで、他の組は `Unsupported`（呼び出し側は fail-closed）。参考実装は net の `sys/holder.rs`
（`pub(crate)` のため流用できず同型を書いた）。
