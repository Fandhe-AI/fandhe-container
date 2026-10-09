# venus 試験治具（GPU-6・TASK-172.4・#888）

PoC 用の独立パッケージ（製品 crate ではない。ルート workspace の外）。既存 OSS の VMM が持つ
virtio-gpu 外部バックエンドの仕組みへ、自前の最小 venus デコーダ（`crates/plugin-macos` の `gpu::venus`）を
つなぐための治具。候補比較と選定は `docs/design/venus-decoder-poc.md` 10 章。製品 crate からは依存しない（一方向）。

## 現状（実装済みを装わない。REPAIR-3）

- 実装済み: virtio-gpu ctrl の `GET_CAPSET_INFO` / `GET_CAPSET` / `GET_DISPLAY_INFO` / `CTX_CREATE` / `CTX_DESTROY` の復号・応答符号化・構造化ログ 1 行（`adapter`）と
  ログ照合器（`log`）。トランスポート（vhost-user 等）のソケット I/O は未実装で、socket を開かない。
- 実装済み（F1.1・#1516）: vhost-user メッセージの codec（`vhost_user`。最小 16 要求種別の復号・符号化と応答 5 種。
  fd・socket・virtqueue には触れない）。出典と前提は `docs/design/venus-decoder-poc.md` 10.5。
- 実装済み（F1.2・#1517。Linux 限定）: `SCM_RIGHTS` による fd の送受信（上限・`MSG_CTRUNC` 検出・close-on-exec・タイムアウト）と、ゲストメモリ領域の mmap / munmap（backing の種類・seal・長さ・範囲の占有の検証と、境界検査つきの読み書き。x86_64 / aarch64 のみ、他アーキは `UNSUPPORTED`）。`unsafe` は `src/sys.rs` にだけ置く（根拠は #1517 の個別承認 U1〜U8 と、追加承認の U9 `fcntl`〔縮小封じ込めの seal 検査〕・U10 `ppoll`〔期限つき待機〕。`lib.rs` の crate 全体の `#![deny(unsafe_code)]` を `sys` でだけ `#[allow(unsafe_code)]` で外す）
- 実装済み（F1.3・#1518）: split virtqueue（`virtqueue`。記述子チェーンの走査・`INDIRECT` 拒否・循環と上限の検出・used への書き戻し・vring アドレスの検証と user アドレスから GPA への変換。全 OS で合成メモリのテストが動く）。出典と前提は `docs/design/venus-decoder-poc.md` 10.7。
- 実装済み（F1.4・#1519。Linux 限定）: vhost-user のセッションと ctrl キューの応答ループ（`session`。ネゴシエーションの状態遷移と順序違反の拒否・kick の待機・要求の取り出し・`adapter` への受け渡し・used への書き戻し・call での通知。待機はすべて期限つき）。設計は `docs/design/venus-decoder-poc.md` 10.8。
- 実装済み（F4・#1598。Linux 限定）: 起動入口（`launch` と bin `venus-jig`。UDS の bind・ソケットディレクトリの検証・期限つき accept・ログのファイル出力）。設計は `docs/design/venus-decoder-poc.md` 10.9。
- 未実装: peer credential（`SO_PEERCRED`）の検証（`unsafe` の承認範囲外。ソケットディレクトリを自 UID 所有・`0700` に限る代替。下記）・cursorq の処理・`observe` の定期出力。
- 未達: 「Linux ゲストの Mesa venus の capset クエリが自前デコーダに届いたことをログで確認」は
  実機実行（#725。人間担当）の完了まで満たせない。

## 起動（Linux 限定。1 接続を処理して終了する）

```bash
cargo run --manifest-path poc/venus-decoder/jig/Cargo.toml --bin venus-jig -- \
  --socket /run/user/1000/venus-jig/s.sock --log /home/me/venus-jig.log
```

- `--socket`・`--log` は絶対パス（必須）。ソケットの親ディレクトリは自分の UID 所有・モード `0700`・symlink でないこと（無ければ 1 段だけ `0700` で作る）。ソケットパスは 107 バイト以下。既存のソケット・ログは消さず上書きもせず、`SOCKET_PATH_EXISTS` / `LOG_PATH_EXISTS` で終わる（手で消す）。
- 任意: `--message-timeout-ms`（既定 5000）・`--idle-timeout-ms`（既定 60000）・`--poll-slice-ms`・`--accept-timeout-ms`（既定 60000）。
- VMM（vhost-user frontend）側から指定するのは `--socket` に渡した絶対パス。crosvm の `--vhost-user` の構文・最小カーネル版数・render server の要否は未確認（実機で確かめる。#725）。
- ログは `0600` で新規作成し、4 MiB・1 行 512 バイト・10 万行を超えたら `log_truncated` の行を残して止める。エラーは stderr に 1 行の JSON（`code` / `message`）。終了コードは 0 が正常、2 が引数・パス・ディレクトリの検証エラー、1 がそれ以外。
- peer credential の検証は未実装。接続できるのは同じ UID と root に限られる（同じ UID の別プロセスは接続できる）。検証は直接の親ディレクトリだけ。限界と承認事項は設計書 10.9。
- ログを読む側（`log::read_log_file`）は通常ファイル以外（FIFO・symlink）を open 前に拒否する。

## 実行

```bash
make poc-venus-jig-check   # CI は rust-ci-default-features ジョブが 3 OS で実行
# 実機前提テスト（既定の集合から分離。GPU 付き Linux・治具 VMM・Mesa venus ゲストが必要）
FANDHE_VENUS_JIG_LOG=<ログファイル> cargo test --manifest-path poc/venus-decoder/jig/Cargo.toml \
  --test real_machine_capset_log -- --ignored
```

## 後続

- F1: vhost-user トランスポート（F1.1 メッセージ codec は実装済み／F1.2 fd 受け渡しと mmap のラッパーは実装済み〔#1517〕／F1.3 split virtqueue は実装済み〔#1518〕／F1.4 セッションは実装済み〔#1519〕）
- F2 の残り: `RESOURCE_CREATE_BLOB`・`SUBMIT_3D` 等の ctrl 応答（未対応は `ERR_UNSPEC`。設計書 10.4 節）
- F4: 起動入口（実装済み。#1598）。記録ファイルのパス引数は #1602、capset より後の ctrl 応答は #1599
- F3: 実機での疎通実行（#725）
