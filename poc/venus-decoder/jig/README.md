# venus 試験治具（GPU-6・TASK-172.4・#888）

PoC 用の独立パッケージ（製品 crate ではない。ルート workspace の外）。既存 OSS の VMM が持つ
virtio-gpu 外部バックエンドの仕組みへ、自前の最小 venus デコーダ（`crates/plugin-macos` の `gpu::venus`）を
つなぐための治具。候補比較と選定は `docs/design/venus-decoder-poc.md` 10 章。製品 crate からは依存しない（一方向）。

## 現状（実装済みを装わない。REPAIR-3）

- 実装済み: virtio-gpu ctrl の `GET_CAPSET_INFO` / `GET_CAPSET` / `GET_DISPLAY_INFO` / `CTX_CREATE` / `CTX_DESTROY` / `RESOURCE_CREATE_BLOB` / `CTX_ATTACH_RESOURCE` / `CTX_DETACH_RESOURCE` / `RESOURCE_UNREF` / `SUBMIT_3D`（受理して受け渡し点へ渡すだけ。dispatch はしない）の復号・応答符号化・構造化ログ 1 行（`adapter`）と
  ログ照合器（`log`）。vhost-user のトランスポート（UDS の bind・accept とセッション）は下記 F1〜F4 で実装済み。
- 実装済み（F1.1・#1516。F5.2b.2・#1641 で 18 種）: vhost-user メッセージの codec（`vhost_user`。最小 18 要求種別の復号・符号化と応答 6 種。
  fd・socket・virtqueue には触れない）。出典と前提は `docs/design/venus-decoder-poc.md` 10.5。
- 実装済み（F1.2・#1517。Linux 限定）: `SCM_RIGHTS` による fd の送受信（上限・`MSG_CTRUNC` 検出・close-on-exec・タイムアウト）と、ゲストメモリ領域の mmap / munmap（backing の種類・seal・長さ・範囲の占有の検証と、境界検査つきの読み書き。x86_64 / aarch64 のみ、他アーキは `UNSUPPORTED`）。`unsafe` は `src/sys.rs` にだけ置く（根拠は #1517 の個別承認 U1〜U8 と、追加承認の U9 `fcntl`〔縮小封じ込めの seal 検査〕・U10 `ppoll`〔期限つき待機〕。`lib.rs` の crate 全体の `#![deny(unsafe_code)]` を `sys` でだけ `#[allow(unsafe_code)]` で外す）
- 実装済み（F1.3・#1518）: split virtqueue（`virtqueue`。記述子チェーンの走査・`INDIRECT` 拒否・循環と上限の検出・used への書き戻し・vring アドレスの検証と user アドレスから GPA への変換。全 OS で合成メモリのテストが動く）。出典と前提は `docs/design/venus-decoder-poc.md` 10.7。
- 実装済み（F1.4・#1519。Linux 限定）: vhost-user のセッションと ctrl キューの応答ループ（`session`。ネゴシエーションの状態遷移と順序違反の拒否・kick の待機・要求の取り出し・`adapter` への受け渡し・used への書き戻し・call での通知。待機はすべて期限つき）。設計は `docs/design/venus-decoder-poc.md` 10.8。
- 実装済み（F4・#1598。Linux 限定）: 起動入口（`launch` と bin `venus-jig`。UDS の bind・ソケットディレクトリの検証・期限つき accept・ログのファイル出力）。設計は `docs/design/venus-decoder-poc.md` 10.9。
- 実装済み: accept 直後の peer credential（`SO_PEERCRED`）による接続元 UID の照合（PLUG-12。不一致・取得失敗は拒否。`sys::peer_uid`＝U11）。
- 実装済み（F6・#1602。Linux 限定）: 受理した `SUBMIT_3D` の本体（32 バイトの ctrl 固定部より後ろ）を 1 提出 1 レコードで記録ファイル（FCVNSREC 形式。`replay::validate` で検証できる）へ書き出す `--record`（`recording`）。リングの中身（共有メモリ）は記録しない（F5.2b の後）。reply・期待出力も記録しない。
- 実装済み（F5.2b.3・#1642。Linux 限定）: backend 要求 `SHMEM_MAP` / `SHMEM_UNMAP` を NEED_REPLY つき・期限つきで送り、frontend の u64 応答を検査する部品（失敗後は channel を閉じる。10.4.4 節）
- 実装済み（F5.2b.1・#1639）: `REPLY_ACK` の確定と、NEED_REPLY つきの要求への ack。
- 実装済み（F5.2b.4a・#1643。Linux 限定）: ctrl の `RESOURCE_MAP_BLOB` / `RESOURCE_UNMAP_BLOB`。blob ごとに memfd を作り、`SHMEM_MAP` で frontend へ渡す（治具自身は mmap しない）。
- 実装済み（F5.2b.4b・#1645。Linux 限定）: map 中の資源の解放の確定。map 中の `RESOURCE_UNREF` は `ERR_INVALID_PARAMETER` で拒否、`CTX_DESTROY` は detach だけで map は残し、map が残ったままのセッション終了（正常・エラー）では期限つきで `SHMEM_UNMAP` を送ってから memfd を閉じる（終了時のログに `blob_release`）。ネゴシエーションから解放までの結合試験は `tests/shmem_lifecycle.rs`。設計は 10.4.3・10.4.4 節。
- 実装済み（F5.2b.2・#1641。Linux 限定）: protocol feature `SHMEM`・`BACKEND_REQ` の広告（`0x0040_0229`）と、`GET_SHMEM_CONFIG`（shmid 1 を 128 MiB で 1 個）・`SET_BACKEND_REQ_FD`（UDS を保持し、セッション終了で閉じる）の受け付け。確定の食い違いは終了時の `host_visible` 行で理由を残す。設計は 10.4.4 節。
- 未実装: cursorq の処理・`observe` の定期出力・`SUBMIT_3D` の dispatch（TASK-177.x）。
- 未達: 「Linux ゲストの Mesa venus の capset クエリが自前デコーダに届いたことをログで確認」は
  実機実行（#725。人間担当）の完了まで満たせない。

## 起動（Linux 限定。1 接続を処理して終了する）

```bash
cargo run --manifest-path poc/venus-decoder/jig/Cargo.toml --bin venus-jig -- \
  --socket /run/user/1000/venus-jig/s.sock --log /home/me/venus-jig.log \
  --record /home/me/venus-jig.fcvns   # 任意。省略時は記録しない
```

- `--socket`・`--log` は絶対パス（必須）。ソケットの親ディレクトリは自分の UID 所有・モード `0700`・symlink でないこと（無ければ 1 段だけ `0700` で作る）。ソケットパスは 107 バイト以下。既存のソケット・ログは消さず上書きもせず、`SOCKET_PATH_EXISTS` / `LOG_PATH_EXISTS` で終わる（手で消す）。
- `--record <絶対パス>`（任意）: 受理して ACK を返した `SUBMIT_3D` の本体を、`create_new` かつ `0600` のファイルへ書く。既存のパスは上書きせず `RECORD_PATH_EXISTS`（終了コード 2）で終わる。親から `/` までの祖先はログと同じ規則で検査し、違反は `RECORD_DIR_UNSAFE`。他の 2 つのパスと同一なら `PATH_INVALID`。ファイルを作れなければ `RECORD_OPEN_FAILED`、書き出し・同期に失敗すれば `RECORD_WRITE_FAILED`（どちらも 1）。
  - 上限は 1 レコード 16 MiB・65,536 件・全体 256 MiB。本体はメモリに溜めて終了時に書くため、ホストのメモリは最大 256 MiB まで増えうる。上限に達すると記録だけ止まり（以降は記録しない）、セッションは続く。ログに `venus_jig event=record_stopped reason=<理由> records=<件数>` を 1 回出す。
  - セッションが正常・エラーのどちらで終わっても記録をファイルへ書き、終了時に `venus_jig event=record_summary records=<n> skipped=<k> stopped=<理由|none> result=<ok|write_failed>` を出す。
  - **実機で採取したストリームにはワークロード由来のデータが含まれうるため、リポジトリにコミットしない。**
- 任意: `--message-timeout-ms`（既定 5000）・`--idle-timeout-ms`（既定 60000）・`--poll-slice-ms`・`--accept-timeout-ms`（既定 60000）。
- VMM（vhost-user frontend）側から指定するのは `--socket` に渡した絶対パス。crosvm の `--vhost-user` の構文・最小カーネル版数・render server の要否は未確認（実機で確かめる。#725）。
- ログは `0600` で新規作成し、4 MiB・1 行 512 バイト・10 万行を超えたら `log_truncated` の行を残して止める。エラーは stderr に 1 行の JSON（`code` / `message`）。終了コードは 0 が正常、2 が引数・パス・ディレクトリの検証エラー、1 がそれ以外。
- 接続元は accept 直後に `SO_PEERCRED` で取得した UID と実行ユーザーの effective UID を照合する（取得失敗は `PEER_CRED_UNAVAILABLE`、不一致は `PEER_UID_MISMATCH` で拒否。実行ユーザーの euid が overflowuid〔既定 65534〕ならマッピング外の接続元と区別できないので `PEER_UID_UNVERIFIABLE` で拒否）。受理するのは実行ユーザーと同じ UID のみ（同じ UID の別プロセスは接続できる）。終了時のソケット削除に失敗した場合は `SOCKET_REMOVE_FAILED` で失敗する。ソケットディレクトリは `/` までの祖先も検査する（存在しない祖先・symlink・他 UID 所有・sticky なしの書き込み可は `SOCKET_DIR_ANCESTOR_UNSAFE`。新規作成を許すのは検証済みの親の直下のソケットディレクトリ 1 段だけ）。限界と承認事項は設計書 10.9。
- ログを読む側（`log::read_log_file`）は通常ファイル以外（FIFO・symlink）を open 前に拒否し、Unix では open 後に `dev` / `ino` を open 前の値と比べて差し替えを拒否する（`Replaced`）。

## 共有メモリを使う起動の前提（Linux 限定）

ゲストの Mesa venus は host-visible な共有メモリ（virtio の共有メモリ領域 id 1）を必須にする。治具に共有メモリを使わせるには、frontend（VMM）が次を行う。

- protocol feature の `REPLY_ACK`・`BACKEND_REQ`・`SHMEM` を確定する（治具の広告は `0x0040_0229`）。
- ring の起動前に `GET_SHMEM_CONFIG`（shmid 1 を 128 MiB で 1 個）と `SET_BACKEND_REQ_FD`（backend 要求用の UDS。fd 1 本）を送る。
- 成立したかは、終了時のログの `host_visible status=` で読める（`ready` なら成立。それ以外は理由の語彙）。
- map が残ったままセッションが終わると、治具は残った map へ期限つき（`--message-timeout-ms` 1 つ分）で `SHMEM_UNMAP` を送ってから memfd を閉じ、`blob_release mapped=<n> unmapped=<n> memfds=<n>` を出す。
- crosvm 側の指定（`--vhost-user` の構文・共有メモリの有効化の指定・最小カーネル版数）、`SHMEM_MAP` と `GPU_MAP` のどちらを使うか、`BACKEND_SEND_FD` の扱いは**未確認**（実機で確かめる。#725）。

## 実行

```bash
make poc-venus-jig-check   # CI は platform-ci ジョブが実行（PR は ubuntu・main は 3 OS）
# 実機前提テスト（既定の集合から分離。GPU 付き Linux・治具 VMM・Mesa venus ゲストが必要）
FANDHE_VENUS_JIG_LOG=<ログファイル> cargo test --manifest-path poc/venus-decoder/jig/Cargo.toml \
  --test real_machine_capset_log -- --ignored
```

## 後続

- F1: vhost-user トランスポート（F1.1 メッセージ codec は実装済み／F1.2 fd 受け渡しと mmap のラッパーは実装済み〔#1517〕／F1.3 split virtqueue は実装済み〔#1518〕／F1.4 セッションは実装済み〔#1519〕）
- `RESOURCE_MAP_BLOB` / `UNMAP_BLOB` と解放の確定は実装済み（F5.2b.4a・F5.2b.4b。#1643・#1645）。残りは実機（#725）
- F4: 起動入口（実装済み。#1598）。記録ファイル（`--record`）は #1602 で実装済み。capset より後の ctrl 応答は #1599
- F3: 実機での疎通実行（#725）
