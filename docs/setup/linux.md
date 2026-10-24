# Linux の配置手順

fandhe-container の実行ファイル（CLI・supervisor・特権ランチャー）を Linux に置く手順を定める。CLI の `start` は自分の実体と同じディレクトリの `fandhe-container-supervisor` を起動するため、CLI と supervisor は必ず同じディレクトリに置く。

- 対象ビヘイビア: SUP-14・CORE-6（関連: CLI-1・CLI-2・SEC-1・REPAIR-5）
- タスク: TASK-171 追補（#1721）・#2068。`start` の解決規則は TASK-79 追補（#1718）、`fandhe-container setup` はステップ `privileged-launcher-install` として rootful の手順を表示する（実行はしない。#1722）
- 設計: [privilege-separation.md](../design/privilege-separation.md) の「インストールスクリプト」

> 未検証の注記（REPAIR-3）: rootful の手順は `scripts/install-privileged-launcher.sh` の自己テスト（スタブのみ・root 不要）で確かめたもので、root での実機実行と検証は未実施である（#538・#539）。rootless の手順は CLI の結合試験（symlink 経由の `start`）に基づくが、実機での手順全体の通し確認は未実施である。rootless の範囲写像（subuid / subgid）の実機確認も未実施である（#1621）。rootless の `start` は supervisor が core の本番 launcher で起動するが（#1819）、委譲 cgroup の準備を含む実機での確認は未実施である（#2062）。rootful の `start` は CLI の実体の隣にある `fandhe-container-launcher` を選んで起動するが（#2442）、ランチャー経由の本物の systemd-run・file capability・`setsid` を通す実機での確認は未実施である（#538・#539）。root（uid 0）での `start` は `UNIMPLEMENTED`（終了コード 8）で終わる（#2241 の判断待ち）。

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

配置後は非 root で `fandhe-container doctor` を実行し、`"check":"launcher"` の行でランチャーの信頼条件と file capability（または setuid root）が揃っていることを確かめる（#2599。hash / 署名は照合しない）。

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

## rootless の範囲写像（subuid / subgid）

rootless の `start` は、`/etc/subuid` と `/etc/subgid` の設定で ID 写像を選ぶ（CORE-6・SEC-5・#2243）。

| `/etc/subuid` | `/etc/subgid` | 結果 |
| ---- | ---- | ---- |
| 自分の行あり | 自分の行あり | 範囲写像（コンテナ 0 → 自分の uid / gid、1 以降 → 設定の範囲）。`uidmap` パッケージの `/usr/bin/newuidmap`・`/usr/bin/newgidmap` が要る |
| 無い（ファイル無し・自分の行無し） | 無い（同） | 1 対 1 写像（コンテナ 0 → 自分の uid / gid のみ） |
| 片方だけ | — | `FAILED_PRECONDITION` で起動しない（1 対 1 へ黙って縮退しない） |
| 読めない・書式不正 | — | `FAILED_PRECONDITION` で起動しない |

- 自分の行は、ユーザー名（`alice:100000:65536`。ダミーの値）か数値の uid で書く。名前は `/etc/passwd` から実効 uid で引き、行が無いときだけ NSS（固定パスの `getent passwd <uid>` を 5 秒の期限つきで実行）で引く。環境変数 `USER` は使わない（#2390・SEC-5・CORE-6。`docs/design/subid-owner-resolution.md`）
- `getent` は `/usr/bin/getent` などの固定候補だけを見る（`PATH` は探索しない）。実体と祖先ディレクトリが root 所有で group / other から書き込めないことが条件で、満たさないときは NSS を引かず、数値 uid の行だけで照合する（`doctor` が `SUBID_OWNER_LOOKUP_UNAVAILABLE` で通知する）
- LDAP・sssd の停止などで NSS の参照が失敗・期限切れになると、`start` は 1 対 1 へ縮退せず `FAILED_PRECONDITION` / `TIMEOUT` で止まる（`doctor` は `SUBID_OWNER_LOOKUP_FAILED`。警告）
- `getent` が使えず（`/etc/passwd` にも行が無い）、`/etc/subuid`・`/etc/subgid` に名前で書かれた行がある構成では、自分の行か判定できないため `start` は拒否する（`doctor` は `SUBID_OWNER_UNDETERMINED`。警告）。第 1 欄に数値の uid を書くか、信頼できる `getent` を入れる（#2545）
- `/etc/nsswitch.conf` の `subid:` で範囲を NSS から配る構成（libsubid・sssd・FreeIPA）は未対応で、`subid:` の最初の語が `files` 以外のとき（大文字小文字を区別しない。shadow 4.13 の `nss.c` と同じ判定）`start` は拒否する（`doctor` は `SUBID_NAME_SERVICE_UNSUPPORTED`。読めない・NUL などで判定できないのは `NSSWITCH_UNUSABLE`）。範囲は `/etc/subuid`・`/etc/subgid` のファイルに書く（#2545）
- 範囲があるのに `uidmap` が無い・検証に通らないときも起動に失敗する（1 対 1 へ縮退しない）
- これらの前提は `fandhe-container doctor` で `start` の前に確かめられる（読み取りのみ。`start` と同じ判定を使う。CORE-6・SEC-5・#2387）。主な `code` は、`SUBORDINATE_IDS_INCOMPLETE`（片方だけ）・`SUBUID_UNUSABLE` / `SUBGID_UNUSABLE`（読めない・書式不正）・`SUBORDINATE_ID_RANGE_INVALID`（範囲を写像にできない）・`ID_MAP_HELPER_NOT_FOUND` / `ID_MAP_HELPER_UNTRUSTED`（`newuidmap` / `newgidmap` が無い・信頼できない。欠けた側ごとに 1 件）で、いずれも警告（終了コード 3）。`SUBORDINATE_IDS_NOT_CONFIGURED`（1 対 1 写像になる）は通知のみで終了コードは 0 のまま
- 起動したコンテナにどの写像が効いているかは、`state.json` の `launchIsolation.id_mapping` と、supervisor の `inspect` 出力の `idMapping` で確かめられる（CORE-6・REPAIR-4・#2388）。`model` は `single`（1 対 1）か `subordinate`（範囲写像）で、`uid` / `gid` はコンテナ側先頭・ホスト側先頭・個数の配列である（`inspect` では `containerId`・`hostId`・`size`）。この記録を作る前の `state.json` では `null` になる（1 対 1 とは推測しない）。記録は観測用で、写像の選択には使わない

## 起動の前提（systemd の user マネージャ）

rootless の `start` は supervisor を `systemd-run --user --scope` で包んで起動する（CORE-3・CORE-4）。次を満たす環境が前提になる。

- `systemd-run` が固定の場所（`/usr/sbin`・`/usr/bin`・`/sbin`・`/bin`・NixOS の `/run/current-system/sw/bin`）にある。`PATH` は探さない。実体が root か実行ユーザー所有の通常ファイルで、group / other から書き込めず、祖先ディレクトリも同じ条件であること（plugin の信頼の基準 PLUG-11 と同じ。sticky bit は例外にしない）。マルチユーザー構成の Nix の `/nix/store`（group 書き込み可・sticky）は祖先として拒否される可能性があり、実機では確かめていない
- `XDG_RUNTIME_DIR` が絶対パスで、`$XDG_RUNTIME_DIR/systemd/private` に自分のソケットがあり、実際に接続できる（systemd のログインセッションまたは `loginctl enable-linger` で user マネージャが動いている）。ファイルだけ残って listener がいない死んだソケットは、doctor が `USER_MANAGER_SOCKET_REFUSED` で報告する

満たしているかは読み取り専用の診断で確かめられる。

```bash
fandhe-container doctor
```

診断は stdout に JSON Lines で出る（`code` と対処 `remediation` つき）。終了コードは、前提が満たされない警告があれば 3、判定できなければ 4、問題がなければ 0 である。root で実行すると検査を省く。rootless の ID 写像の前提（subuid・subgid・`newuidmap` / `newgidmap`）も検査する（上の節）。doctor は実行した CLI 自身の cgroup が委譲されているかも検査する（`delete` と同じ検出）。委譲されていないこと（`CGROUP_NOT_DELEGATED`）は `start` に影響しないため通知のみで、終了コードは 0 のままである。

`delete` は cgroup の配置を記録したコンテナを消すとき、実行中の cgroup が委譲されている必要がある。通常のログインセッション（SSH・TTY ログイン）の cgroup は委譲されていないため、そのまま実行すると失敗する（事前に doctor の `CGROUP_NOT_DELEGATED` で確かめられる）。委譲されたスコープの中で実行する。

## CRI plugin（`fandhe-container-plugin-cri`）を使う場合

CRI plugin の `start`・`kill`・`stop`・`delete` は CLI と同じ経路で supervisor を使う（#2434・CRI-2）。

- `fandhe-container-supervisor` を plugin の実体（`fandhe-container-plugin-cri`）と同じディレクトリにも置く。CLI の `start` と同じ規則で、`PATH` 探索・環境変数・引数による上書きは無い。見つからなければ `FAILED_PRECONDITION`
- plugin のプロセスの環境に `XDG_RUNTIME_DIR` が必要（user マネージャへの到達に使う）。上の「起動の前提」を同じく満たすこと
- cgroup の配置を記録したコンテナの `delete` は、plugin プロセス自身の cgroup が委譲されている必要がある（CLI の `delete` と同じ検出で、検出に失敗すると記録を残したまま失敗する）。plugin を委譲されたスコープの中（例: `systemd-run --user --scope -p Delegate=yes -- fandhe-container-plugin-cri ...`）で動かす
- `start` の権限モデルは CLI と同じ規則（plugin の実体の隣に信頼できるランチャーがあればランチャー経由。uid 0 は `UNIMPLEMENTED`。#2442）。インストールスクリプトは plugin を置かない。実機での通しは未確認（#850・#2062）

```bash
systemd-run --user --scope -p Delegate=yes -- fandhe-container delete <id>
```
