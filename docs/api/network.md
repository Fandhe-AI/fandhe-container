# create の network 指定（`--network`・`--add-host`・`--dns`）

`create` の network 関連フラグの書き方と現状の挙動(#1873・NET-6・NET-12・SEC-1・CLI-1。設計は [network-wiring.md](../design/network-wiring.md))。`-p` は [port-publish.md](port-publish.md)。

## 既定は `none`

Linux では `--network` を省略すると `none` になる(SEC-1「既定で閉じる」)。コンテナの network namespace には `lo` だけがあり、外部とは通信できない。従来は host 相当(ホストの network namespace を共有)だったため、省略時の挙動が変わる。host が必要なら `--network host` を明示する。

## `--network`

| 値 | 挙動 |
| -- | ---- |
| `none`(省略時) | 新しい network namespace を作り、`lo` だけを up にする |
| `host` | ホストの network namespace を共有する。分離を緩める指定で、start の成功後に supervisor が構造化ログ 1 行(`"event":"network_mode","network_mode":"host"`)を残す。supervisor は起動前に自分の netns と同一であることを確かめ、一致しなければ起動しない |
| ユーザー定義名 | rootless(Linux。隣に特権ランチャーが無い非 root)だけ受ける(#3329・NET-6・NET-9)。`network create` で作った定義(pasta 構成)が要り、`--pasta-path` か `--pasta-path-search` も要る。定義が無ければ `NOT_FOUND`(`network not found`)、定義が pasta 構成でなければ `FAILED_PRECONDITION`。いずれも状態ルート・イメージストアの作成より前に拒否する。`start` でも定義を照合し直し、`create` の後に `network rm` されていれば `FAILED_PRECONDITION`(`network definition no longer exists`)で起動しない。参照するコンテナ(作成済み・停止中・実行中)がある間の `network rm` は `FAILED_PRECONDITION`(`network is in use by a container; delete the containers that use it first`、終了コード 5)で拒否する(#3529・CLI-1)。参照を判定できないコンテナ(起動オプションの文書の欠落・破損等)があるときも拒否し(`network references could not be verified; inspect or delete broken containers first`)、回復は該当コンテナの `delete`。rootful は `UNIMPLEMENTED`(D13〔#3207・#3069・#3074〕の判断待ち)、非 Linux も `UNIMPLEMENTED` |
| `container:<id>` | `UNIMPLEMENTED`(将来仕様) |
| `bridge`・`default` | `INVALID_ARGUMENT`(予約名) |

非 Linux は `--network`・`--add-host`・`--dns` のどれかがあると `UNIMPLEMENTED`(MAC / WIN 系の結線の後続)。

## `--add-host <host>:<ip>`

`none` と `host` のどちらでも、コンテナの `/etc/hosts` に `<ip>\t<host>` の行を追記する(IPv4 / IPv6。最初の `:` で分割するので `name:::1` は `name` と `::1`)。最大 256 件。`/etc/hosts` の初期内容は localhost の行で、フラグ無しではイメージ(rootfs)側のファイルをそのまま使う。

## `--dns <ip>`

`/etc/resolv.conf` を `nameserver <ip>` の行で置き換える。`host` では任意の IP、`none` では loopback(`127.0.0.0/8`・`::1`)だけ(ほかは作成時に `INVALID_ARGUMENT`。省略時も `none` 扱いなので同じ)。最大 32 件。

## 生成されるファイル

指定があるときだけ start のたびに状態ルート配下の `@container-etc/<id>/` へ作り直し(ディレクトリ 0700・ファイル 0644)、rootfs の `/etc/hosts`・`/etc/resolv.conf` へ bind する。コンテナ内の宛先が symlink のとき、または tmpfs・注入・bind の宛先と重なるときは起動を拒否する。`delete` で消える。

## 制約

- 起動オプション文書の上限(`OPTIONS_DOC_MAX_BYTES` = `--env` の合計上限 + 256 KiB)があり、`--env` を上限近くまで使った上で `--add-host` を多数(最大 256 件 × 299 バイト、約 76 KiB)指定すると、`create` が `options document is too large` で拒否されることがある。
- 実機前提の結合試験 `network_modes_real`(`crates/cli/tests/network_modes_real.rs`。`--add-host` の名前解決・`lo` のみであること・host の resolv.conf・delete 後の残骸なし。#3345)を `platform-ci`(ubuntu)で実行する。手元の実機での実行と記録は #349(人間担当)。
