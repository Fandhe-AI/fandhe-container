# venus 試験治具（GPU-6・TASK-172.4・#888）

PoC 用の独立パッケージ（製品 crate ではない。ルート workspace の外）。既存 OSS の VMM が持つ
virtio-gpu 外部バックエンドの仕組みへ、自前の最小 venus デコーダ（`crates/plugin-macos` の `gpu::venus`）を
つなぐための治具。候補比較と選定は `docs/design/venus-decoder-poc.md` 10 章。製品 crate からは依存しない（一方向）。

## 現状（実装済みを装わない。REPAIR-3）

- 実装済み: virtio-gpu ctrl の `GET_CAPSET_INFO` / `GET_CAPSET` / `GET_DISPLAY_INFO` / `CTX_CREATE` / `CTX_DESTROY` の復号・応答符号化・構造化ログ 1 行（`adapter`）と
  ログ照合器（`log`）。トランスポート（vhost-user 等）のソケット I/O は未実装で、socket を開かない。
- 実装済み（F1.1・#1516）: vhost-user メッセージの codec（`vhost_user`。最小 16 要求種別の復号・符号化と応答 5 種。
  fd・socket・virtqueue には触れない）。出典と前提は `docs/design/venus-decoder-poc.md` 10.5。
- 実装済み（F1.2・#1517。Linux 限定）: `SCM_RIGHTS` による fd の送受信（上限・`MSG_CTRUNC` 検出・close-on-exec・タイムアウト）と、ゲストメモリ領域の mmap / munmap（境界検査つきの読み書き）。`unsafe` は `src/sys.rs` にだけ置く（根拠は #1517 の個別承認 U1〜U8 と、追加承認の U9 `fcntl`〔縮小封じ込めの seal 検査〕・U10 `ppoll`〔期限つき待機〕。`lib.rs` の crate 全体の `#![deny(unsafe_code)]` を `sys` でだけ `#[allow(unsafe_code)]` で外す）
- 未実装: virtqueue（F1.3）、セッションと応答ループ・UDS の bind と peer credential の検証（F1.4）。治具自身は socket を開かない。
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

- F1: vhost-user トランスポート（F1.1 メッセージ codec は実装済み／F1.2 fd 受け渡しと mmap のラッパーは実装済み〔#1517〕／F1.3 split virtqueue〔#1518〕／F1.4 セッション〔#1519〕）
- F2 の残り: `RESOURCE_CREATE_BLOB`・`SUBMIT_3D` 等の ctrl 応答（未対応は `ERR_UNSPEC`。設計書 10.4 節）
- F3: 実機での疎通実行（#725）
