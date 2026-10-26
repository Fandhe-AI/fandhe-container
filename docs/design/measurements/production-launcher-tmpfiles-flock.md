# production_launcher の create の間欠失敗（tmpfiles の aging 走査との flock 競合）

Issue #2840。ビヘイビア: CORE-1・CORE-2・CORE-5・CORE-6・SEC-1・REPAIR-4・REPAIR-5・REPAIR-12。

## 現象

main の CI（run 40298579586・commit 3ebc80ce）の `platform-ci (ubuntu-latest)`「production_launcher の実行」で、
シナリオ F の成功行の直後、シナリオ G の 1 周目（`bind`）の `do_create` が
`FailedPrecondition`・`container start is in progress in another process` で失敗した。次の run は通っており間欠失敗である。

## 否定した仮説

- ID の重なり: エラーは状態ストアではなく bundle の flock（`BundleLock::acquire`）から出る。全シナリオの ID は重ならない
- start のロックの解放漏れ・別 start の残り: G の bundle は直前に `create_dir` で排他作成した新しい inode で、
  前のシナリオのロックは別 inode に掛かる。F の start は fork 前の検査で拒否され `lock_owner` に届かない。
  本番 launcher は `LaunchMode::SelfBounded` で、残るスレッドも無い

したがって、新しい bundle の作成から create までの間に、試験プロセス以外が flock を掛けたことになる。

## 原因（有力。runner 上の直接観測は未取得）

- Ubuntu noble の `tmpfiles.d/tmp.conf` は `D /tmp 1777 root root 30d` で /tmp は aging 対象
- systemd の `dir_cleanup` は、サブディレクトリごとに `flock(LOCK_EX|LOCK_NB)` を取ってから再帰する（age に関係なく走査中は保持）
- `systemd-tmpfiles-clean.timer` は `OnBootSec=15min`
- 失敗した run だけが、ジョブ開始から production_launcher の実行までが約 14 分 37 秒で、起動後 15 分前後の走査に重なる
  （成功した 3 run は約 16 分 04 秒〜16 分 38 秒）。直近 40 件の失敗 run で同じ文言は 1 件のみ

## 修正

`crates/core/tests/production_launcher.rs` の一時領域を、`create_dir` で排他作成し 0700 にした親ディレクトリ
（`fandhe-prodlaunch-<pid>-<nanos>`）の下へまとめ、親に共有 flock を期限つきで取って試験の終わりまで保持する。
tmpfiles は LOCK_EX を取れないディレクトリを丸ごと飛ばす（tmpfiles.d(5)）。製品のロックは子の inode で親と干渉しない。
あわせて create の失敗時に `/proc/locks` から保持者を stderr に出す診断を足した（判定は変えない。REPAIR-4）。

採らなかった案: create の再試行（本物のロック漏れを隠す）、`target/tmp` への移動（祖先の権限への影響）、
ci.yml の `TMPDIR` 指定（CI でしか効かない）。

## 繰り返し実行の結果

未実施の項目を含む。この記録の作成環境（Unshare 段が `PermissionDenied` になる AppArmor 制限下）では本番試験を最後まで
回せなかったため、修正前後の繰り返し（注入あり・なし）の件数は未取得である。PR の CI（ubuntu）での通過を確認し、
再現頻度と修正後の失敗 0 の確認は人手で追記する。なお `make repeat-test` は #2886 で `USER_SCOPE=1`（委譲 scope での直接実行）・`TEST_ENV`
（`FANDHE_CONTAINER_TEST_ID_HELPER=1` 等）・512 文字までで `;` を含む成功行の完全一致に対応し、この試験に使えるようになった。
実行例は `AGENTS.md` の repeat-test の項を参照。dispatch（ubuntu・`repeat-user-scope=true`。1 回の上限は `repeat-run-timeout`〔既定 600 秒〕、ステップ全体は 55 分で打ち切られるため、遅ければ `repeat-count` を分けて複数回 dispatch する）での 300 回の結果
（run ID・commit・passed / failed・有効だった環境変数・tmpfiles の走査時刻との関係）は、PR の push 後に追記する（未実施）。
修正前の再現頻度は、boot から約 15 分の走査との重なりに依存するため繰り返しでは再測定できない。

## 残余（製品側）

`BundleLock` は待たない設計（#1316・#1854・#2378 で確定）のため、aging 対象の場所に bundle を置く利用者でも
create・start・delete が稀に同じ文言で失敗しうる。`launch.rs` の doc に既知の制約として記した。
待たない取得を期限つきの再試行にする案・文言の改善などはオーナー判断として追跡する。
