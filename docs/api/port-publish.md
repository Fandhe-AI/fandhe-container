# ポート公開（`create` の `-p` / `--publish`）

rootless のユーザー定義ネットワーク（pasta 構成）では、`create` の `-p` / `--publish` でホストのポートをコンテナへ公開する（NET-9・NET-3・CLI-1。#3200。設計は [rootless-network.md](../design/rootless-network.md) 12.6・12.14）。

## 現状（重要）

`-p` の解析と作成前の検証、起動オプション文書 `FCOPT1` の kind `publish` は実装済みで、supervisor 側の pasta の結線と `publish` の反映も #1940 で実装済みだが、CLI が rootless のユーザー定義名を受けて文書へ記録する #3329 が済むまで、検証を通った `-p` も `UNIMPLEMENTED` で拒否する（受理して黙って捨てない。REPAIR-3）。

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
| ユーザー定義名の `--network` と rootless | 検証後、結線まで `UNIMPLEMENTED` |
| `--network` なし・`none`・`host`・`container:` | `INVALID_ARGUMENT`（モードによらず） |
| rootful（uid 0、または信頼できる特権ランチャーが CLI の隣にある） | `UNIMPLEMENTED`（v1 では対象外。D13 の判断待ち） |

エラーは固定の英文で、入力値を含めない。拒否は状態ルートの作成より前に行う。

## rootful の `PortPublish` との差

rootful の `PortPublish` は nftables の DNAT で公開し、loopback と未指定のホストアドレスを拒否する。rootless の pasta はホスト側の socket を bind するため、loopback も `0.0.0.0` も成り立ち、ホストのポートの衝突はカーネルの bind が拒否する。両者の指定構文と待ち受けの既定は同じではない。
