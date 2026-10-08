# venus 試験治具（GPU-6・TASK-172.4・#888）

PoC 用の独立パッケージ（製品 crate ではない。ルート workspace の外）。既存 OSS の VMM が持つ
virtio-gpu 外部バックエンドの仕組みへ、自前の最小 venus デコーダ（`crates/plugin-macos` の `gpu::venus`）を
つなぐための治具。候補比較と選定は `docs/design/venus-decoder-poc.md` 10 章。製品 crate からは依存しない（一方向）。

## 現状（実装済みを装わない。REPAIR-3）

- 実装済み: virtio-gpu ctrl の `GET_CAPSET_INFO` / `GET_CAPSET` の復号・応答符号化・構造化ログ 1 行（`adapter`）と
  ログ照合器（`log`）。トランスポート（vhost-user 等）は未実装で、socket を開かない。
- 未達: 「Linux ゲストの Mesa venus の capset クエリが自前デコーダに届いたことをログで確認」は
  トランスポート（後続 F1）と実機実行（#725。人間担当）の完了まで満たせない。

## 実行

```bash
make poc-venus-jig-check   # CI は rust-ci-default-features ジョブが 3 OS で実行
# 実機前提テスト（既定の集合から分離。GPU 付き Linux・治具 VMM・Mesa venus ゲストが必要）
FANDHE_VENUS_JIG_LOG=<ログファイル> cargo test --manifest-path poc/venus-decoder/jig/Cargo.toml \
  --test real_machine_capset_log -- --ignored
```

## 後続

- F1: vhost-user トランスポート（メッセージ codec・fd 受け渡しと mmap の sys ラッパー・split virtqueue）
- F2: 残りの ctrl 応答（`GET_DISPLAY_INFO`・`CTX_CREATE` 等。未対応は `ERR_UNSPEC`）
- F3: 実機での疎通実行（#725）
