# macOS の VM 利用方式（常駐 VM 共用）

macOS バックエンドの VM 利用方式（既定とオプション）を定める（MAC-4）。

> 方針自体は spec で確定済み（MAC-4 は確定）。本書はその文書化であり、「軽量プロセス分離」の解釈と TASK-64 / TASK-65 実装との対応の正確性は #370（TASK-66.h1。人間担当）で確認する。確認が済むまで、本書の実装対応の記述は確認待ちである。

- 対象ビヘイビア: MAC-4（関連: MAC-1・MAC-2・MVM-1・MVM-5・PLUG-1・PLUG-6・CORE-1）
- タスク: TASK-66（MS-5・G5。前提 TASK-65 は完了）
- 関連 issue: #369（本書）・#370（内容確認。人間担当）
- 出典: `docs/spec/04-behavior/api-platform-macos.md` の `MAC-4`、`api-microvm.md` の `MVM-1`・`MVM-5`、`05-tasks.md` の TASK-66（submodule リビジョン `984f8a2`）

## 2 方式の比較

| 項目 | 既定: 常駐 VM 共用 + 軽量プロセス分離 | オプション: 1 コンテナ = 1 VM |
| ---- | ------------------------------------ | ------------------------------ |
| 優先する性質 | 起動レイテンシ | 分離強度 |
| VM の寿命 | コンテナの起動・停止をまたいで保持し、複数コンテナで共用 | コンテナと同じ |
| コンテナ間の分離境界 | 共用ゲスト内のプロセス分離（ゲストカーネルは共有） | VM 境界（ゲストカーネルを共有しない） |
| 位置づけ | 既定 | 選択可能なオプション（MVM-1 と連携） |

根拠となる PoC（いずれも文献値・他ランタイムの実測であり、本実装の実測ではない）:

- PoC-5: コンテナごとに新規 VM を起動する Apple `container` 方式の cold start は 0.92 秒で、常駐 VM を使い回す Docker Desktop に及ばない trade-off がある
- PoC-11: Apple `container` 1.4.1 の cold start は 0.728 秒、Docker Desktop は 0.136 秒

本実装の VM 起動時間（MAC-2）の実測は TASK-70（人間担当）で行う。

## 既定方式（常駐 VM 共用 + 軽量プロセス分離）

- 常駐 VM: Virtualization.framework で起動した Linux ゲスト VM を、コンテナの起動・停止をまたいで保持し、複数コンテナで共用する
- 軽量プロセス分離: 共用ゲスト内のコンテナ間分離を、ゲスト Linux の namespaces / cgroups v2 / seccomp / Landlock（`crates/core` の機構。CORE 系・SEC 系）で行う、というのが本書の解釈である。MAC-4 本文は「軽量プロセス分離」としか書いていないため、この具体化は #370 での確認対象とする
- 分離強度の含意: コンテナ間はゲストカーネルを共有する。したがってカーネル脆弱性クラスへの耐性やマルチテナント分離が要る用途では、既定方式では足りない（次節のオプション方式を使う）。ホストとの境界は VM であり、virtiofs の共有範囲・アクセス権は Virtualization.framework のデバイス構成で強制される
- CORE-1 との関係: 「中央の常駐デーモンを持たない」（CORE-1・D-19）と「常駐 VM」は別の概念である。VM を保持する主体は本書では確定しない（未決事項）

## オプション方式（1 コンテナ = 1 VM）

- コンテナごとに専用 VM を割り当て、ゲストカーネルを共有しない。マルチテナント分離やカーネル脆弱性クラスへの耐性が要る用途向け（MVM-1 の前提）
- MVM-1 は microVM を選択可能なオプションとして提供するビヘイビア（Should・確定）。macOS への展開のバックエンド方針は MVM-5（Hypervisor.framework。文書化は TASK-78、Linux 側の実装は TASK-74 / TASK-75）
- 本書では断定しない事項: macOS でのオプション方式の実現経路（TASK-64 の Virtualization.framework `Vm` をコンテナごとに起動するか、MVM-5 系統の Hypervisor.framework 上の自前 VMM か）は MAC-4 からは定まらない。選択の UI（CLI フラグ・TOML キー）も未定義である。MVM-3（切り替えしきい値）は spec 上「検討中」のため確定扱いしない

## TASK-64 / TASK-65 実装との対応

どのコンポーネントが「常駐」側に属するかを示す。表の「既定方式での扱い」は本書の案であり、確認は #370 で行う。

| コンポーネント | 実装箇所（TASK） | 既定方式での扱い（案） |
| -------------- | ---------------- | ---------------------- |
| VM 設定・最小デバイス構成（`VmConfigSpec`・`build_vz_configuration`） | `crates/platform-macos/src/config.rs`（TASK-64.2・64.3） | 常駐（VM 生成時に 1 回） |
| VM ライフサイクル（`Vm`・`Vm::launch`・`start` / `stop`・`OpTimeouts`・状態イベント） | `crates/platform-macos/src/vm.rs`（TASK-64.4・64.5） | 常駐（VM 本体） |
| コンソールログの書き出し・ゲスト報告の走査 | `crates/platform-macos/src/console_log.rs`（TASK-64.3） | 常駐（VM に付随） |
| virtiofs 共有のデバイス構成（`VirtiofsSharesSpec`。最大 `MAX_VIRTIOFS_SHARES` = 8 件） | `crates/platform-macos/src/virtiofs.rs`（TASK-65.1） | 常駐（VM 構成の一部。構成構築時に固定） |
| ゲスト内 mount の指示・報告契約（カーネルコマンドライン経由の指示、hvc0 経由の報告） | `crates/platform-macos/src/guest_mount.rs`（TASK-65.3） | 常駐（起動時 1 回。`Vm::launch` 内で待機） |
| I/O 共有プロトコルクライアント（`VirtiofsIoClient`）と再接続（`ReconnectingVirtiofsIoClient`） | `crates/platform-macos/src/virtiofs/io_client.rs`・`reconnect.rs`（TASK-65.2・65.5） | 接続単位（寿命は VM に縛られない。常駐 VM への接続として使う想定。具象トランスポートは未実装） |
| ゲスト init（`crates/guest-init`。#1875。virtiofs の mount と報告・起動完了マーカー） | ソース実装済み（initrd への梱包 #1878・実機確認 #1628 は未実施） | VM 単位 |
| ゲスト内のコンテナ実行（軽量プロセス分離の本体） | 未存在 | コンテナ単位（未実装） |

### コンソールログの保持（回転・削除。#2138・MAC-1・REPAIR-4）

- 上限: 1 ファイル・1 回の起動あたり 1 MiB（`MAX_CONSOLE_LOG_BYTES`）、世代は現在を含め 3（`CONSOLE_LOG_GENERATIONS`。`<name>`・`<name>.1`・`<name>.2`）。supervisor のログ（#2067・SUP-7）と同じ値と番号規則（新しいほど小さい）で、パス 1 つあたりの総量は約 3 MiB。起動中は回転せず上限で切る（ブートログの先頭を残すため）。 回転・新規ファイルの open・書き出しへの引き渡し、および全世代の削除は、排他用ファイル `<name>.0`（世代と衝突しない番号。回転で変わらない）の lock を通して持ち、同じログパスの二重書き出しと使用中の削除を拒否する。回転と削除の結果・件数・所要時間は stderr の構造化ログ（`operation` が `rotate` / `remove`。パスは含めない）に残す（MAC-1・REPAIR-4）。
- 回転の時機: `VmConfigSpec::open_serial_console`（`Vm::launch` が呼ぶ）が書き出しの直前に行う。現在のログが無い・空なら世代を消費しない。使用中 lock を先に取り、世代ファイルに異常（symlink・他者所有・リンク数・モード・kernel / initrd / ディスクイメージとの同一性）があれば何も動かさず拒否する。
- 削除の時機: VM の stop・`Vm` の drop・起動失敗では残す（診断材料）。コンテナの delete で `VmConfigSpec::remove_console_logs` が現在のログと全世代を消す。この呼び出しの配線は plugin-macos の delete 実装（TASK-114）待ちで、現状は部品の提供までである。
- supervisor との違い: コードは共有しない（platform-macos は supervisor へ依存しない）。起動中の回転もしない。

### 現状の事実（実装済みを装わない。REPAIR-3）

- 現在の `Vm::launch` は「1 回の呼び出しで 1 VM を構成・起動する」API で、virtiofs 共有はカーネルコマンドラインの mount 指示とともに VM 構成の構築時に固定される。構造上は、既定方式よりオプション方式（1 コンテナ = 1 VM）に近い。複数コンテナで VM を使い回す仕組み（共用 VM の保持・コンテナ単位の追加 / 削除）は未実装である
- `Vm` の `Drop` は実行中の VM に停止を要求する。「常駐」させるには `Vm` を保持し続ける主体が要る
- 協調停止・pause / resume / save / restore は未実装である
- クライアント側の UDS `connect`・macOS ホスト側の VZ vsock トランスポートは未実装である。ゲスト init（指示を読んで mount し報告するもの）は `crates/guest-init` にソースがあるが（#1875）、initrd への梱包（#1878）と実機確認（#1628）までは、mount 指定つきの `Vm::launch` は報告が届かずタイムアウトしうる
- plugin 境界越しの配線は TASK-115（`fandhe-container-plugin-macos`）で行う

## plugin 境界との関係

- macOS バックエンドは core 外の plugin である（D-14・PLUG-1。[architecture.md](../architecture.md) の境界表）
- plugin プロセスの「常駐 / 都度起動」（PLUG-6・PoC-13 の上乗せ 5.032ms / 2.537ms）と、VM の「常駐 / コンテナごと」（MAC-4）は別の軸である。混同しない
- VM の寿命と plugin プロセスの寿命の関係（VM を保持する主体）は未決である

## 未決事項・後続

本書では解決しない。

- 共用 VM を保持する主体と寿命（plugin プロセス常駐との関係。CORE-1 との整合）
- VM 生成後にコンテナ単位の bind mount をどう届けるか（virtiofs 共有が構成時固定である制約）。共用 VM で複数コンテナの共有ディレクトリが同一ゲストに見える点のアクセス制御も含む
- 共用ゲスト内でコンテナを実行する機構（ゲスト init の拡張〔子プロセスの回収等〕・`crates/core` のゲスト内利用）
- オプション方式の macOS 実現経路と選択 UI、MVM-3 のしきい値（検討中）
- 関連タスク: TASK-70（MAC-2 / MAC-3 の実測・人間）、TASK-115（plugin 化）、TASK-74 / TASK-75（MVM-1 の Linux 実装）、TASK-78（MVM-5 の文書化）、TASK-49（CORE-8 の VM 経由リソース効率実測・人間）
- 共用 VM の実装タスクは spec のタスク定義に明示なし。要確認事項として報告する

## 見直し

MAC-4・MVM-1・MVM-5 の更新時、TASK-115 / TASK-78 の完了時、#370 の確認結果が出た時に本書を追従する。
