# Linux の配置手順

fandhe-container の実行ファイル（CLI・supervisor・特権ランチャー）を Linux に置く手順を定める。CLI の `start` は自分の実体と同じディレクトリの `fandhe-container-supervisor` を起動するため、CLI と supervisor は必ず同じディレクトリに置く。

- 対象ビヘイビア: SUP-14・CORE-6（関連: CLI-1・CLI-2・SEC-1・REPAIR-5）
- タスク: TASK-171 追補（#1721）・#2068。`start` の解決規則は TASK-79 追補（#1718）、`setup` が表示する手順は #1722
- 設計: [privilege-separation.md](../design/privilege-separation.md) の「インストールスクリプト」

> 未検証の注記（REPAIR-3）: rootful の手順は `scripts/install-privileged-launcher.sh` の自己テスト（スタブのみ・root 不要）で確かめたもので、root での実機実行と検証は未実施である（#538・#539）。rootless の手順は CLI の結合試験（symlink 経由の `start`）に基づくが、実機での手順全体の通し確認は未実施である。rootless の `start` は supervisor が core の本番 launcher で起動するが（#1819）、委譲 cgroup の準備を含む実機での確認は未実施である（#2062）。rootful の `start` は CLI からランチャーを選ぶ規則が未実装のため `UNIMPLEMENTED`（終了コード 8）で終わる（#1719・#1722）。

## 配置の規則

| ファイル | 役割 | 付与する権限 |
| -------- | ---- | ------------ |
| `fandhe-container` | CLI | なし（capability も setuid も付けない） |
| `fandhe-container-supervisor` | コンテナごとの監視プロセス | なし |
| `fandhe-container-launcher` | rootful の特権ランチャー | file capability（xattr 非対応なら setuid root）。rootful のみ |

- CLI と supervisor は起動契約（`FCSUP1`）の版が揃っている必要がある。別々の版を混ぜない
- `PATH` 上に symlink を置いて起動してもよい。CLI は `/proc/self/exe` の解決結果（実体のパス）を見るため、symlink の置き場所ではなく実体のディレクトリの supervisor を使う。`PATH` 探索・環境変数・引数による上書きは無い

## rootful（インストールスクリプト）

root で次を実行する（スクリプト内で sudo は呼ばない）。入力元は 3 つとも必須で、symlink は不可。

```bash
scripts/install-privileged-launcher.sh \
  --launcher target/release/fandhe-container-launcher \
  --supervisor target/release/fandhe-container-supervisor \
  --cli target/release/fandhe-container
```

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
