# 監視プロセス系の実機計測 実行手順書

人間担当の実機計測 #499（SUP-5）・#485（SUP-2）・#491（SUP-3）・#219（CORE-9・SUP-1）で、そのまま使える実行手順。計測スクリプトの起動行は supervisor の bin の契約に合わせ済み（#1820）。実行と合否判定は人間が行う。スクリプトは合否を出さない箇所があり、結果欄に Agent が実測値を埋めてはならない。

- 対応: TASK-158・TASK-160・TASK-162・TASK-50（追補）・MS-9（Phase 8）
- ビヘイビア: SUP-1・SUP-2・SUP-3・SUP-5・CORE-9・REPAIR-3（未実装を実装済みと装わない）・REPAIR-5（期限）・REPAIR-12
- 起動契約の根拠: `crates/supervisor/src/start_contract.rs`・`start_entry.rs`・`crates/cli/src/commands/supervisor_start.rs`（#1717・#1819）

## 現状の制約（必読）

| 項目 | 内容 |
| ---- | ---- |
| restart の再 launch（#491） | supervisor の再 launch は本番 launcher の単一スレッド要求で拒否される（#2043）。#2043 が入るまで `make restart-latency` は再起動未観測（終了コード 1）になり数値は出ない。`make supervisor-independence` の `--check-restart` も同じ |
| 計測の権限（#485・#219） | supervisor は入口で `PR_SET_DUMPABLE=0` にする（SUP-14）。同じ利用者の非 root からも `/proc/<pid>/exe`・`smaps_rollup` を読めない。一方 supervisor は rootful 起動を拒否する（SEC-5）。#485 は「root が計測し、supervisor は非 root で起動する」2 つのシェルで行う。#219 の own は 1 つのスクリプトが起動と PSS の読み取りを行うため両立せず、非 root では `unreadable-memory-value` で fail-closed になり、root では起動前に終了コード 3 になる。特権の橋渡しは未実装で、別途判断が要る（SUP-14 に関わる） |
| supervisor の停止 | SIGTERM のハンドラは無くコンテナを止めない。CLI の `stop` は未実装（#1544）。スクリプトは記録した pid・起動時刻の同一性を照合して子孫へ SIGKILL を送り、状態ルートごと削除する。CLI の `delete` は呼ばない |
| バックオフ（#491） | supervisor の bin にバックオフを指定する引数は無く、既定 100ms 固定（`crates/supervisor/src/restart.rs` の `DEFAULT_BACKOFF`）。計測値はバックオフを含むため、スクリプトは差し引いた値も出す |

## 共通の必要環境

- Linux 6.12 以上（Landlock ABI 6 以上）。bash 5・`jq`・`timeout`・`mkfifo`・`cp`・`setsid`・`systemd-run`
- 非 root の利用者で実行する（#485 の PSS 読み取りだけ root）
- 非特権 user namespace を許可する（例: `kernel.apparmor_restrict_unprivileged_userns=0`）
- `systemd-run --user` が使える（利用者の systemd と DBus セッション）。supervisor は親 cgroup に自分だけがいることを要求するため、スクリプトは supervisor ごとに `systemd-run --user --scope --quiet -p Delegate=yes --` で新しいスコープへ入れる
- cgroup v2 の委譲がある
- 参考: `crates/supervisor/tests/supervisor_bin_real.rs` の module doc に同じ前提がある

## ビルド

```bash
cargo build --release -p fandhe-container-cli -p fandhe-container-supervisor
chmod g-w target/release/fandhe-container target/release/fandhe-container-supervisor
export BIN_DIR="$PWD/target/release"
```

- `BIN_DIR` は `fandhe-container` と `fandhe-container-supervisor` を置いたディレクトリの絶対パス。スクリプトは固定名で解決し PATH 探索をしない
- スクリプトはバイナリが symlink でなく、所有者が実行ユーザーか root で、group / other に書き込み権が無く、祖先ディレクトリも安全であることを検査する。umask 002 のビルドで拒否されたら `chmod g-w` する
- `systemd-run` は既定 `/usr/bin/systemd-run`。違う場合は `SYSTEMD_RUN=<絶対パス>` を渡す

## bundle の用意

- 計測専用の使い捨てのテンプレートを作る。`TMPDIR` と同じファイルシステムに置く（コンテナごとの複製を `cp -al` のハードリンクで作るため。別ファイルシステムだと終了コード 2）
- ハードリンクで rootfs の inode を共有するため、コンテナ内の書き込みがテンプレートへ波及しうる。使い捨てにする理由はこれ
- `config.json` を置く。user namespace（UID マッピング）を入れる。`process.args` は長時間動き続けるものにする（restart 計測では即時終了しないもの）。静的リンクのバイナリか、共有ライブラリを rootfs へコピーしたものにする
- 並列起動するスクリプトは、コンテナごとに `config.json` を通常コピー・rootfs をハードリンク複製して使う（supervisor は start 中に bundle へ flock を取るため、同じ bundle を共有できない）

## #499 監視プロセス独立性（SUP-5・TASK-162）

```bash
make supervisor-independence BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> COUNT=50 OUTPUT=<新規ファイル>
```

- 非 root で実行する。N 個の supervisor を同時に起動し、1 個へ SIGKILL を送って次を判定する: (a) 対象の消滅・(b) 残り N-1 個の監視プロセスの生存・(c) 残りのコンテナ側プロセスの継続・(d) 対象のコンテナ側プロセスの稼働継続
- 出力の読み方: JSON の `result` が `pass` なら全判定成立。`supervisors_alive_after_kill`・`monitored_containers_alive` は期待値 N-1。`target_container_reparented_to` は孤児化後の親 pid（参考値）
- 終了コード: 0 = 全判定成立、1 = 判定不成立・起動数不足・期限切れ、2 = 引数・入力エラー、3 = 前提欠如（root 実行を含む）、4 = 後始末失敗
- `--check-restart` は #2043 の後に有効（既定 off）
- 実機でだけ確認できること: `systemd-run --scope` が pid・親子関係を変えずに supervisor を exec すること。実行後に `systemctl --user list-units --type=scope` へ残骸が無いこと

## #485 監視プロセスの常駐メモリ（SUP-2・TASK-158）

2 つのシェルで行う。

1. 非 root のシェルで、supervisor を N 個起動したまま保つ。コンテナごとに create し、結果チャネルは FIFO にする

   ```bash
   root=$(mktemp -d)
   for i in $(seq 1 50); do
     cp -al <テンプレート> "$root/b$i"
     "$BIN_DIR/fandhe-container" --root "$root/state" create --bundle "$root/b$i" "sup-$i"
     mkfifo "$root/f$i"
     exec {fd}<>"$root/f$i"
     systemd-run --user --scope --quiet -p Delegate=yes -- \
       "$BIN_DIR/fandhe-container-supervisor" start --root "$root/state" "sup-$i" >"$root/f$i" &
   done
   ```

   `FCSUP1 OK <pid>` が全員分出たら起動完了。後始末は起動したシェルで supervisor の pid を終了させ、`$root` を削除する
2. root のシェル（権限付きシェル）で計測する

   ```bash
   make supervisor-pss COUNT=50 EXPECTED_DIR="$BIN_DIR" SAMPLES=5 OUTPUT=<新規ファイル>
   ```

- 出力の読み方: `apportioned_pss_kb_median`（N 按分後の主指標）と `per_process_pss_kb_median`（単体の参考）。目標 2048KB は `target_pss_kb` に参考値として載るだけで、スクリプトは合否を出さない
- 読めないときは終了コード 3 で、メッセージに dumpable の旨が出る。root のシェルから実行する

## #491 restart レイテンシ（SUP-3・TASK-160）

前提: #2043 が入っていること。入っていなければ再起動未観測で終了コード 1 になる。

```bash
make restart-latency BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> TRIALS=20 WARMUP=1 OUTPUT=<新規ファイル>
```

- 非 root で実行する。supervisor を `--restart on-failure:<試行数>` で起動し、コンテナ側プロセスへ SIGKILL を送って、state.json が新 pid・`restartCount` + 1 を示すまでを計測する
- 出力の読み方（単位 ms）
  - `observed`: SIGKILL 送信から state.json の更新観測まで（主系列）。シグナル配送・終了検知・ポーリング粒度・**バックオフ**を含む
  - `supervisor_reported`: ログの `elapsed_us`（終了検知から Running 記録完了まで。バックオフを含む）。件数が合わなければ `null`
  - `observed_minus_backoff`・`supervisor_reported_minus_backoff`: 上の値から `backoff_ms_assumed`（100ms）を差し引いた値。supervisor はバックオフ以上眠るので「バックオフを除いた遅延の上側の推定」（寝過ごし分を含む保守側）。負になったら計測異常で終了コード 1
  - SUP-3 の目標（バックオフ 0 で中央値 100ms 以下）との比較と合否は #491 の担当。PoC-17 は区間が異なるため直接比較しない
- 終了コード: 0 = 成功、1 = 計測失敗、2 = 引数エラー、3 = 前提欠如、4 = 後始末失敗

## #219 50 コンテナ同時起動の集約メモリ（CORE-9・SUP-1・TASK-50）

```bash
make concurrent-memory BIN_DIR="$BIN_DIR" BUNDLE=<テンプレート> TARGET=own COUNT=50 TRIALS=3 OUTPUT=<新規ファイル>
make concurrent-memory-docker DOCKER=<docker の絶対パス> ...   # Docker 側の同一手法計測（#218）
make concurrent-memory-report OWN_RESULT=<own の出力> DOCKER_RESULT=<docker の出力>
```

- **未解決の前提**（上の表）: own は supervisor の PSS を読めないため、非 root の単独実行では成立しない。解決方針の選択肢は (A) スクリプトが root で動き起動行だけ非 root へ降格する、(B) 製品側で dumpable=0 を特権経路に限る（SUP-14 の判断が要る）。実測の前に判断を得る
- 集計の対象は supervisor を根とする子孫全体（コンテナ側プロセスを含む）。コンテナ側プロセスは環境変数を継承しないため、所有の証明は生存中に記録した pid・起動時刻の同一性で行う
- 出力の読み方・SUP-1（Docker の 80% 以下）の判定は #219 の担当。スクリプトは合否を出さない
- 終了コード: 0 = 全試行 N/N 起動、1 = 計測失敗、2 = 引数エラー（bundle の複製失敗を含む）、3 = 前提欠如（root 実行を含む）、4 = 後始末失敗

## 実行後の確認

- `systemctl --user list-units --type=scope` に `run-*.scope` の残骸が無いこと
- 一時ディレクトリ（`TMPDIR` 配下の `tmp.*`）が残っていないこと
- 残存プロセスが無いこと（終了コード 4 の場合はスクリプトの警告に従い手で回収する）
