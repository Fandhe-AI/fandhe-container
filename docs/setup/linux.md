# Linux の配置手順

fandhe-container の実行ファイル（CLI・supervisor・特権ランチャー）を Linux に置く手順を定める。CLI の `start` は自分の実体と同じディレクトリの `fandhe-container-supervisor` を起動するため、CLI と supervisor は必ず同じディレクトリに置く。

- 対象ビヘイビア: SUP-14・CORE-6（関連: CLI-1・CLI-2・SEC-1・REPAIR-5）
- タスク: TASK-171 追補（#1721）・#2068。`start` の解決規則は TASK-79 追補（#1718）、`setup` が表示する手順は #1722
- 設計: [privilege-separation.md](../design/privilege-separation.md) の「インストールスクリプト」

> 未検証の注記（REPAIR-3）: rootful の手順は `scripts/install-privileged-launcher.sh` の自己テスト（スタブのみ・root 不要）で確かめたもので、root での実機実行と検証は未実施である（#538・#539）。rootless の手順は CLI の結合試験（symlink 経由の `start`）に基づくが、実機での手順全体の通し確認は未実施である。core の本番 launcher（#1715 の Phase B）が入るまで、`start` は supervisor の `UNIMPLEMENTED`（終了コード 8）で終わる。

## 配置の規則

| ファイル | 役割 | 付与する権限 |
| -------- | ---- | ------------ |
| `fandhe-container` | CLI | なし（capability も setuid も付けない） |
| `fandhe-container-supervisor` | コンテナごとの監視プロセス | なし |
| `fandhe-container-launcher` | rootful の特権ランチャー | file capability（xattr 非対応なら setuid root）。rootful のみ |

- CLI と supervisor は起動契約（`FCSUP1`）の版が揃っている必要がある。別々の版を混ぜない
- `PATH` 上に symlink を置いて起動してもよい。CLI は `/proc/self/exe` の解決結果（実体のパス）を見るため、symlink の置き場所ではなく実体のディレクトリの supervisor を使う。`PATH` 探索・環境変数・引数による上書きは無い

## rootful（インストールスクリプト）

root で次を実行する（スクリプト内で sudo は呼ばない）。入力元と許可済みの sha256 は 3 つとも必須で、入力元の symlink は不可。

```bash
scripts/install-privileged-launcher.sh \
  --launcher target/release/fandhe-container-launcher --launcher-sha256 <launcher の sha256> \
  --supervisor target/release/fandhe-container-supervisor --supervisor-sha256 <supervisor の sha256> \
  --cli target/release/fandhe-container --cli-sha256 <CLI の sha256>
```

- sha256 は 64 桁の 16 進で、配置するファイルの期待値を入力元とは別の経路で得る。リリース物ならば別の経路で配られた `SHA256SUMS`、手元でビルドしたならばビルド直後の信頼できる状態で `sha256sum target/release/...` を取って控えた値を使う。インストールの直前に入力元から計算し直した値では、差し替えを防げない
- 照合は配置先に複製した一時ファイルに対して行い、不一致なら `error: source-hash-mismatch`（終了コード 3）を出して何も置換しない。署名の検証は未実装

- 配置先は既定 `/usr/local/libexec/fandhe-container`。`--dest-dir <絶対パス>` で変えられる
- 配置先は根から全要素が root 所有・g/o 書き込み不可の通常ディレクトリでなければならない。満たさないときは補修せず終了コード 3 で止まる
- 3 ファイルは同じロックのもとで一組として置換し、途中で止まったら旧ファイルへ戻す。launcher にだけ file capability を付け、読み戻して照合する
- 成功すると stdout に `installed: method=file-capability dest-dir=<path>` の 1 行を出す

`PATH` 上から呼べるようにするには、root が symlink を手作業で作る。スクリプトは作らない。

```bash
ln -s /usr/local/libexec/fandhe-container/fandhe-container /usr/local/bin/fandhe-container
```

symlink はインストーラの信頼チェーンの外にある。CLI と supervisor の間に権限の境界は無く（同一ユーザーで起動する）、特権経路はランチャーが自分の実体の隣の supervisor を自前で検証するため、symlink が昇格の経路にはならない。

## rootless（root 不要）

rootless（CORE-6 の既定）では launcher は使わず、スクリプトも不要である。利用者所有のディレクトリに CLI と supervisor を同じ場所へ置く。

```bash
install -d -m 0755 ~/.local/libexec/fandhe-container ~/.local/bin
install -m 0755 target/release/fandhe-container ~/.local/libexec/fandhe-container/fandhe-container
install -m 0755 target/release/fandhe-container-supervisor ~/.local/libexec/fandhe-container/fandhe-container-supervisor
ln -sf ~/.local/libexec/fandhe-container/fandhe-container ~/.local/bin/fandhe-container
```

- どちらにも capability も setuid も付けない
- `~/.local/bin` が `PATH` に入っていなければ追加する
- 置き場所とその祖先は、他の利用者が書き込めないようにする（g/o 書き込み不可）。CLI と supervisor の間に権限の境界は無いが、他人が書ける場所に置くとファイルを差し替えられる
- 更新するときは CLI と supervisor を同じ版で置き直す

## 起動の前提（systemd の user マネージャ）

rootless の `start` は supervisor を `systemd-run --user --scope` で包んで起動する（CORE-3・CORE-4）。次を満たす環境が前提になる。

- `systemd-run` が固定の場所（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`・NixOS の `/run/current-system/sw/bin`）にある。`PATH` は探さない。実体が root か実行ユーザー所有の通常ファイルで、group / other から書き込めず、祖先ディレクトリも同じ条件であること（plugin の信頼の基準 PLUG-11 と同じ。sticky bit は例外にしない）。マルチユーザー構成の Nix の `/nix/store`（group 書き込み可・sticky）は祖先として拒否される可能性があり、実機では確かめていない
- `XDG_RUNTIME_DIR` が絶対パスで、`$XDG_RUNTIME_DIR/systemd/private` に自分のソケットがある（systemd のログインセッションまたは `loginctl enable-linger` で user マネージャが動いている）

満たしているかは読み取り専用の診断で確かめられる。

```bash
fandhe-container doctor
```

診断は stdout に JSON Lines で出る（`code` と対処 `remediation` つき）。終了コードは、前提が満たされない警告があれば 3、判定できなければ 4、問題がなければ 0 である。root で実行すると検査を省く。

`delete` は cgroup の配置を記録したコンテナを消すとき、実行中の cgroup が委譲されている必要がある。通常のログインセッション（SSH・TTY ログイン）の cgroup は委譲されていないため、そのまま実行すると失敗する。委譲されたスコープの中で実行する。

```bash
systemd-run --user --scope -p Delegate=yes -- fandhe-container delete <id>
```
