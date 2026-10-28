# create の network 指定（`--network`・`--add-host`・`--dns`）

`create` の network 関連フラグの書き方と現状の挙動(#1873・NET-6・NET-12・SEC-1・CLI-1。設計は [network-wiring.md](../design/network-wiring.md))。`-p` は [port-publish.md](port-publish.md)。

## 既定は `none`

Linux では `--network` を省略すると `none` になる(SEC-1「既定で閉じる」)。コンテナの network namespace には `lo` だけがあり、外部とは通信できない。従来は host 相当(ホストの network namespace を共有)だったため、省略時の挙動が変わる。host が必要なら `--network host` を明示する。

## `--network`

| 値 | 挙動 |
| -- | ---- |
| `none`(省略時) | 新しい network namespace を作り、`lo` だけを up にする |
| `host` | ホストの network namespace を共有する。分離を緩める指定で、start の成功後に supervisor が構造化ログ 1 行(`"event":"network_mode","network_mode":"host"`)を残す。supervisor は起動前に自分の netns と同一であることを確かめ、一致しなければ起動しない |
| ユーザー定義名・`container:<id>` | `UNIMPLEMENTED`(将来仕様。rootless は pasta〔NET-9・#1936〜#1940〕、rootful は D13〔#3207・#3069・#3074〕、定義の存在確認は #3066) |
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
- 実機での結合試験(`--add-host` の名前解決・`lo` のみであること・host の resolv.conf)は未整備で、#349 の実機確認は後続(PR 本文の対象外を参照)。
