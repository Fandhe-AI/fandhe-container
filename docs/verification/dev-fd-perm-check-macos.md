# macOS での /dev/fd/N 経由の権限検査の観測手順と結果記録（MAC-1・#2088・TASK-64 追補）

`scripts/build-guest-initrd.sh` の `copy_input` は、入力を fd 9 で 1 度だけ開き、`/dev/fd/9` を `find -L` で辿って通常ファイルか・所有者・group / other の書き込み権限を検査する（検査後の差し替え対策）。macOS ではこの fd 経由の権限検査が効かないように見えたため、パス側の検査を重ねて回避している。パス側の検査は早期拒否であって差し替え対策の根拠ではないので、macOS では Linux より防御が弱い可能性がある。原因はまだ確定しておらず、本書の観測で絞る。

実機での実行と判断は人間担当（[#2088](https://github.com/Fandhe-AI/fandhe-container/issues/2088)）で、Agent は実行しない。Agent が用意したのは観測スクリプト `scripts/probe-dev-fd-perm.sh` までで、`build-guest-initrd.sh` の検査ロジックは本書の結果を受けた別 PR で扱う。

## 原因の候補

- (a): fdesc の `/dev/fd/N` に対する `stat` が、実パスと違う mode・所有者を返す / `obs=stat-L` の `target=path` と `target=fd9` の mode / uid が食い違う
- (b): `stat` は一致するが、BSD `find` の `-L` と `-perm` / `-user` の組み合わせだけが効かない / `obs=stat-L` は一致、`obs=find` の `target=fd9` が `target=path` と食い違う（`obs=find-ls-mode` も参照）
- (c): bash のコマンド置換の中と別プロセスで結果が違う / `obs=route` の `w-other-bash-subst` と `w-other-sh-child` が食い違う

## 前提

- macOS 実機。非 root の実行ユーザーで足りる
- 他者所有のケース（`--foreign`）だけは、操作者が自分で用意する。例: `sudo install -o root -g wheel -m 0644 <src> <自分の管理下の絶対パス>`（root 所有。スクリプトは所有者 0 を許すので、許可される側の観測になる）。可能なら別の一般ユーザー所有のファイルも用意する（拒否される側）。`sudo` はスクリプトの外で操作者が明示的に実行する。スクリプト自身は sudo を呼ばず、`--foreign` のファイルの中身も読まない
- 記録に書くのは OS・カーネルの版・アーキテクチャ・bash / find / stat の系統だけ。ホスト名・アドレス・接続先の名前・ユーザー名は書かない（スクリプトの出力にも含まれない）

## 実行

```bash
make dev-fd-perm-probe
scripts/probe-dev-fd-perm.sh --foreign <絶対パス>   # 所有者の違うファイルごとに 1 回
```

比較のため `/bin/bash`（3.2）と Homebrew の bash の両方で回す（任意）。`skip:` が出たケースは観測できていない扱いで、合格の根拠にしない。出力は 1 行 1 観測の `key=value` で、先頭は `probe=dev-fd-perm v=1`、末尾は `probe=dev-fd-perm done`。そのまま下の表に貼れる。

## 結果の読み方

- `obs=stat-L`: `path` と `fd9` の mode / uid / gid / type が一致
- `obs=stat-nolink target=fd9`: `/dev/fd/9` 自体はシンボリックリンク（Linux）
- `obs=find`: `fd9` と `path` の `w-other` / `w-group` / `own-me` / `is-file` が一致
- `obs=route`: 0666 で `w-other-*` が両方 `yes`

macOS の値は原因が未確定のためスクリプト側では判定しない。main への push で走る `platform-ci (macos-latest)` の自己テストのログにも同じ出力の形式が残るが、GitHub ホステッド runner の参考値で、実機の結果の代わりにはしない。

## 結果記録

記入先は #2088 のコメント。

- OS / カーネル / アーキテクチャ:
- bash の版・find の系統・stat の系統:
- 0644 / 0664 / 0666 の `stat-L` 一致:
- 0644 / 0664 / 0666 の `find` の `fd9` と `path` の差:
- `route` の差:
- foreign（root 所有）の結果:
- foreign（別の一般ユーザー所有）の結果:
- 原因の判定（a / b / c / 不明）:

## 判定を受けた後の対応（別 PR）

- (b) `stat -L /dev/fd/9` は一致するのに `find -L /dev/fd/9 -perm` だけが空: fd 側の検査を `stat` ベースに置き換える（Darwin は `stat -L -f '%Lp %u'`、GNU は `stat -L -c '%a %u'`）。`copy_input` の中のヘルパー 1 つにまとめ、パス側は早期拒否として残す。fd 側だけで拒否されることを確かめる回帰ケースを `build-guest-initrd-selftest.sh` に足す
- (a) `stat -L /dev/fd/9` 自体が下位の inode の mode・uid を返さない: macOS では fd 経由のメタデータ検査ができない。open の前後の `dev:inode` の同一性の照合に切り替えるか、限界として文書化するかはオーナーの判断事項として報告する（文書化する場合はスクリプト冒頭・`guest/kernel/README.md`・`AGENTS.md` に「macOS では検査の後の差し替えを防げない。`--init` には自分の管理下のパスを渡す」と書く）
- (c) bash の `$(...)` 内と別プロセスで違う: 検査を別プロセスで、fd を明示して継承させて行う形に直す
- 当てはまらない・結果が揺れる: #2088 に観測の追加を求めるコメントを書いて人間へ戻す

どの場合も、完了条件は `make guest-initrd-build-selftest` が main の `platform-ci` の 3 OS で通ること。

## 人間向けの依頼文（#2088 に貼る雛形）

macOS 実機で `docs/verification/dev-fd-perm-check-macos.md` の手順を実行し、出力の全行と原因の判定を #2088 にコメントしてください。記録には OS・カーネルの版だけを書き、ホスト名・アドレス・接続先は書かないでください。
