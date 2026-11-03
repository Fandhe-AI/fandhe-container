# ポート公開（`create` の `-p` / `--publish`）

rootless のユーザー定義ネットワーク（pasta 構成）では、`create` の `-p` / `--publish` でホストのポートをコンテナへ公開する（NET-9・NET-3・CLI-1。#3200。設計は [rootless-network.md](../design/rootless-network.md) 12.6・12.14）。

## 現状（重要）

`-p` の解析と作成前の検証、起動オプション文書 `FCOPT1` の kind `publish`、supervisor 側の pasta の結線と `publish` の反映（#1940）に加え、CLI が rootless のユーザー定義名を受けて `network`・`pasta`・`publish` を文書へ記録する処理も #3329 で実装済み。定義の照合（`NOT_FOUND`）と pasta の解決は [network.md](network.md) を参照。実機での通し確認（pasta・ポート公開）は #3331 で人間が行う。

## 書き方

```text
-p [<ipv4>:]<host>:<container>[/tcp|udp]
```

- 繰り返せる（最大 64 件）。1 件は 64 バイト以下
- 待ち受けアドレスを省略すると `127.0.0.1`。全インターフェースは `0.0.0.0` を明示したときだけ
- プロトコルを省略すると TCP（`/tcp`・`/udp` は小文字のみ）
- IPv6 のリテラル・ポートの範囲・ポート 0・ポートの名前は受けない（`INVALID_ARGUMENT`）
- 重複（同じアドレス・プロトコル・ホストのポート）と、`0.0.0.0` との重なりは拒否する

## 組み合わせの規則

| 指定 | 結果 |
| ---- | ---- |
| ユーザー定義名の `--network` と rootless | 受理して文書へ記録する（#3329）。定義が無ければ `NOT_FOUND` |
| `--network` なし・`none`・`host`・`container:` | `INVALID_ARGUMENT`（モードによらず） |
| rootful（uid 0、または信頼できる特権ランチャーが CLI の隣にある） | `UNIMPLEMENTED`（v1 では対象外。D13 の判断待ち） |

エラーは固定の英文で、入力値を含めない。拒否は状態ルートの作成より前に行う。

## rootful の `PortPublish` との差

rootful の `PortPublish` は nftables の DNAT で公開し、loopback と未指定のホストアドレスを拒否する。rootless の pasta はホスト側の socket を bind するため、loopback も `0.0.0.0` も成り立ち、ホストのポートの衝突はカーネルの bind が拒否する。両者の指定構文と待ち受けの既定は同じではない。
