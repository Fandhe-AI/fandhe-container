# コンテナ参照の照合とクラッシュ復旧 GC の起動点

OCI-7・OCI-5・CLI-1・CORE-1（常駐デーモンを置かない）・REPAIR-3/4/5。TASK-183.8 追補・TASK-183.8.2（#854）・TASK-183.11.2（#852）。Issue #2495。

## 背景

イメージつき `create` / `delete` は、コンテナ → manifest の参照（`@container-refs.json`）を登録・解除する（#2315）。
残った参照を照合して回収する oci の部品（`ImageStore::reconcile_container_refs`・`release_unbound_container_ref_if`）は、
本番の呼び出し元を持たなかった。残った参照は次の害を起こす。

- `register` 成功後・状態作成前のクラッシュや `bind` 失敗で、未確定の参照が残る。同じ ID の再 create が `ALREADY_EXISTS` になり続け、
  manifest が GC・`image rm` から守られ続ける
- 記録を持たない古いコンテナや、core 到達後に解除が失敗した delete は、確定済みの参照を残す（`delete` 自身は create 時のストア root の記録から解除する。#2499 で実装済み。下の「delete 自身の解除」）

## 根本の危険

oci の既存 doc は「進行中の create が無いこと」を前提に未確定参照の回収を認めるが、常駐デーモンの無い CLI（CORE-1）には
そう言える時点が無い。保証なしで回収すると、次の競合で稼働中のコンテナの参照を外す。

1. 照合が未確定参照 X（世代 g）を複製する
2. 並行する create がまだ状態を書いておらず、probe が `NotFound` を返す
3. 世代が一致するので X を外す
4. 並行する create が状態を作り、`bind` が `NotFound` で失敗する（create 自体は成功を返す）

結果、参照なしで動くコンテナの manifest が GC から無防備になる。`@lock`（`ImageStore`）は呼び出し単位、`BundleLock` は
bundle 単位で、`register` から `bind` までをまたぐロックは無いため、生存信号が必要になる。

## 決定 1: イメージストア単位の create ゲート

ストア root 直下の固定名ファイル `@create-gate`（0600・通常ファイル・symlink 拒否。`@lock` と同じ検査）への OS ロック。

| 役割 | 取得 | 使うもの |
| ---- | ---- | -------- |
| イメージつき create | 共有（`ImageStore::enter_container_create`。期限つき） | `create_with_image` の呼び出し全体を包む。cli では `create_container_with_image` が `&ContainerCreatePass` を要求し、型で強制する |
| 未確定参照の回収 | 排他（`ImageStore::quiesce_container_creates`。期限内に取れなければ `None`） | `release_unbound_container_ref_quiesced`・`reconcile_container_refs_quiesced` が `&CreateQuiescence` を要求する |

- 排他が取れた＝そのストアで進行中のイメージつき create が 0 件、なので oci の前提が成り立つ。プロセスが落ちればカーネルが
  ロックを外すため、クラッシュした create の参照は回収可能になる
- 排他が期限内に取れなければ未確定参照は回収しない（余分に残す側。OCI-7）
- 確定済み参照（`bound`）かつ状態 `Absent` の回収にゲートは要らない。確定済みの間は同じ ID の `register` が拒否されるので、
  状態の不在は削除済みを意味し、`release_container_ref_if` の世代比較が同じ ID の再作成を巻き込まない
- ロック順序: ゲート ＞ `ImageStore::lock`（`@lock`）＞ `StateStore` のロック。ゲートは常に最も外側で、ガードや状態ストアの
  ロックを保持したままゲートを取らない。同じスレッドが共有を持ったまま排他を取りに行かない。取得はすべて期限つき（REPAIR-5）

## 決定 2: 起動点（契機）

起動時の全件照合や新しいトップレベルコマンド（`system reconcile` 等）は採らない。デーモンの無い CLI に「起動時」は無く、
CLI の表面・3 OS の parity スクリプトへの波及を避けるため。

| 契機 | 対象 | 条件 |
| ---- | ---- | ---- |
| A: `create --image-root --image` の core 呼び出し前 | 同じ参照キー 1 件 | 状態 `Absent` のときだけ回収する。確定済みはゲート不要。未確定はゲート排他の下。`Present`・`Undetermined`・排他の期限切れは何もせず core に進む（core が `ALREADY_EXISTS` を返す。再試行で解ける） |
| B: `image rm` が使用中で拒否したとき | 拒否に載った参照のうち現在の状態ルートのもの（上限 256 件） | ガードを手放した状態でゲート排他 → `reconcile_container_refs_quiesced`。その後に同じ判定をやり直す。排他が取れない・状態ストアが開けないときは照合を飛ばし従来どおり拒否 |

契機 A が「同じ ID の恒久的な `ALREADY_EXISTS`」と「delete が解除できずに残した確定済み参照」を解く（照合は後追いの回収役）。
契機 B が「manifest が使用中のまま GC から守られ続ける」を解く。`image prune` の CLI は未配線（#2384）で、配線時に同じヘルパー
（`ref_reconcile::reconcile_in_use`）を呼ぶ。

## 決定 3: probe と状態ルートのスコープ

- 実装は cli の `commands/ref_reconcile.rs`（oci は core に依存できないため。`image_refs` と同じ理由）
- `StateStore::get` の結果の写し方: `Ok` は `Present`、`NotFound` は `Absent`、それ以外（`Timeout`・`Internal`・`PermissionDenied`・
  `Unimplemented`・`Unavailable` 等）は `Undetermined`。`Absent` は `NotFound` だけから作る
- 参照キー `<scope>.<id>` は、`scope` が現在の状態ルートのもので、`ContainerId` を通り、`ref_key` で往復して一致するものだけ状態を読む。
  他の状態ルートの scope・畳んだ形・不正なキーは状態を読まず `Undetermined`（別の状態ルートの参照を回収しない）
- 結果は計測（REPAIR-4）へ `image_ref_reclaim`・`image_ref_reconcile` として記録する。stderr へは出さない（OCI の create / delete 互換の無出力）

## 決定 4: `Present` かつ未確定の扱い（オーナー確認待ち）

状態があるのに参照が未確定のまま残る場合（`bind` 前のクラッシュや `bind` の失敗）の扱いは、実装者が決めない。選択肢:

1. 昇格しない（現状維持・**既定として実装**）: 状態がある間、同じ ID の再 create は `StateStore::create` の `AlreadyExists` で拒否される。
   `delete --image-root` は確定済みの登録しか外さないので参照を外さないが、状態の削除後は「未確定かつ `Absent`」となり契機 A・B で回収される。
   恒久的には塞がない（`oci7_present_unbound_does_not_block_forever` で確認）。代償は delete の時点で即時には外れないこと
2. 契機 B の照合（ゲート排他下）で `bind` して昇格する: delete が即時に解除できる。リスクは、イメージなし create（bundle 直指定）が同じ ID を再利用して
   作った状態に参照を結び付け、過剰保持という誤った帰属になること（安全側ではある）
3. core の `delete_releasing_image_ref` が状態削除後に未確定参照もゲート排他下で外す: core のトレイト契約の変更で、#2499 と範囲が重なる

推奨は 1。オーナーの判断は未取得。

## 決定 5: `reap_stale_unpacks`（#2379）は同じ契機で呼ばない

入力が bundle と `root.path` で、参照テーブルは bundle を持たないため、参照の回収と同じ契機では呼べない。同じ bundle への次の create
（`prepare_rootfs_target_with`）では既に呼ばれている。状態ルート全体の掃引は状態レコード・bundle の列挙が要るため本 issue の範囲外とする。
公開済みで状態の無い rootfs（孤児）も同じ bundle への次の create が回収する（#2540）。孤児は状態レコードを持たないので
`StateStore::list` でも参照テーブルでも bundle を列挙できず、状態ルート全体の掃引は行わない（決定 E は #2635 で確定）。
bundle の意図の記録（journal）を入れても、それを読んで掃引する契機が無い（候補は起動時の全件照合と新しいトップレベルコマンドだけで、
どちらも決定 2 で不採用）。展開途中の木（`.fandhe-unpack-*`）の契機も同じで、同じ bundle への次の create と、bundle を知る呼び出し元が呼ぶ
`reap_stale_unpacks` / `reap_stale_unpacks_with` に限る。根拠と運用者向けの手動回収の手順は
[image-rootfs-lifetime.md](image-rootfs-lifetime.md) の決定 E と「失敗後の手動回復」を参照。

## 制約・未実装（実装済みを装わない。REPAIR-3）

- 畳んだ参照キー（223 バイト以上の ID の `<scope>-<hash>`）は元の ID を復元できないため、契機 B では回収しない。契機 A は元の ID を知っているので回収できる（キー形式は #2500）
- 契機 B はゲート排他を取れない（進行中の create がある）間は何もしない。次の `image rm` の再実行で回収される
- ゲートを使わない `create_with_image` の呼び出し元（plugin 経由の配線等）を新設するときは、同じ規約（共有を保持して包む）を守る
- `image prune` の CLI 配線は #2384

## delete 自身の解除（#2499・OCI-7・OCI-5・CLI-1）

常駐デーモンの無い CLI（CORE-1）では、照合は後追いにしかならない。そこで create はイメージストア root（`ImageStore::root()` の正規パス）を
状態記録の annotations（予約キー `io.fandhe.container.image-root`。利用者の `--label` では書けない）へ残し、`--image-root` を省いた
`delete` もその記録のストアを開いて参照を解除する。`--image-root` を渡した場合は記録と一致を確かめ、食い違えば `FAILED_PRECONDITION` で
状態も参照も残す。記録の値は信頼せず、`ImageStore::open` の検査と開いた `root()` との一致を求める（開けなければ状態を消さずに失敗する）。
解除の結果は `DeleteResponse::image_ref` に載り、失敗は stderr の警告（`image reference release failed`）で伝える（終了コードは 0）。
参照キーの scope は開いた状態ストアの `host_state_root()`（正規パス）から求め、`--root` の表記ゆれで create と delete の scope がずれない。
記録の root を消したり移したりしたコンテナは delete できない（元のパスにストアを戻すか、空の 0700 ディレクトリを作れば通る）。

## 不採用案

- ref キーごとのリースファイル（flock）: ID ごとにファイルが増え続け、削除するとロックと unlink の競合（別の inode を掴む）の対策が要る。
  単一ファイルの共有 / 排他のほうが単純で、oci の前提と一致する
- oci の `register` 内で「未確定かつ `NotFound`」を置き換える: `container_ref.rs` の doc が挙げる理由（並行する同じ ID の create のロールバックが勝った側を外しうる）が残り、
  oci は `StateStore` を持たず `NotFound` を判断できない。同等の効果を、契機 A の「create 前の同一 ID の回収（ゲート排他下）」で得る
