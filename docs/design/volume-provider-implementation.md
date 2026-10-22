# VolumeProvider の core 側実装（named volume の実体化）の担当 TASK と時期の判断記録

`VolumeProvider` の core 側実装を、どの TASK で・いつ行うかをオーナーが決めるための判断材料を整理する。

> 位置づけ: **オーナー承認待ち（#2451）**。本書は判断材料であり決定ではない。決まるまで core に実装は無く（REPAIR-3）、IO-7 の比較ベンチは named volume を「ランタイム管理ディレクトリに置く相当構成」で計測する。

- 対象ビヘイビア: CRI-7・PLUG-1・IO-7（関連: D-14・REPAIR-3・OCI-5・STACK-1・REPAIR-5・SEC-5）
- タスク: TASK-4（トレイト定義）・TASK-114（plugin 側。実装は core 側に残すと記載）・TASK-24.1 / 24.2（IO-7 比較）
- 関連 issue: #2451（本書）・#1886（ワイヤー経路の設計）・#110（TASK-24.2）・#107（TASK-23）・#19（TASK-4.h1。closed）・#1897（IO-7 の 2 構成の定義）・#1906（macos-shared-vm.md）
- 作成日: 2026-10-22

## 1. 現状

| 項目 | 事実 |
| ---- | ---- |
| トレイト | `crates/core/src/traits/volume_provider.rs`。create / remove / inspect / attach / detach。`VolumeSource::{Named, Bind}`・`VolumeName`・`GuestPath`・`HostBindPath` の検証型がある。データプレーンは持たない |
| core 側の実装 | 無い（同ファイルの module doc の REPAIR-3 節に明記） |
| core から io への依存 | `crates/core/Cargo.toml` に `fandhe-container-io` は無い。[architecture.md](../architecture.md) でも「想定」。結線は配管ではなく設計判断を含む |
| spec 上の担当 | 05-tasks のカバレッジ表で CRI-7 は TASK-4（トレイト定義）と TASK-114（plugin 実装）。TASK-114 は「実装は core 側に残す」とだけ書き、実装する TASK が無い |
| シグネチャのレビュー | #19（TASK-4.h1）は closed で、現時点のシグネチャを承認済み（後続の実装で必要になった変更は実装 issue で扱う）。一方、トレイトの doc は「レビュー前の暫定版」のままで食い違う |
| IO-7 の 2 構成 | 2026-10-12 のオーナー決定（#1897）で「書き込み先（共有ルート）の置き場所の違い」と定義済み。TASK-189 ハーネスの `--config` はラベルのみ（[small-files-bench.md](small-files-bench.md)） |
| 利用側 | `crates/stack` の `[volumes.<name>]`（STACK-1）→ `up`（TASK-155・STACK-8）。OCI `config.json` の `mounts[]`（OCI-4）・CRI の mounts |
| 前提となる未決 | #1886（ワイヤー上のファイル作成要求。io 結線の前提）。macOS / Windows でボリューム実体をゲスト内に置くか（OCI-5 (4) と同型。[macos-shared-vm.md](macos-shared-vm.md)・[windows-execution-layout.md](windows-execution-layout.md) が承認待ち） |

## 2. 論点 1: 担当 TASK

- **案 T1: 新しい TASK を spec に起こす**。トレーサビリティは最も明確だが、spec リポの変更（本リポでは決めない）を待つ
- **案 T2: 既存 TASK の追補として扱う**。候補は TASK-4（トレイト定義）・TASK-114（core 側に残すと記載）・TASK-29（mounts）の追補。本リポの「TASK-n 追補」運用（#1886・#1915 等と同じ）で、spec の改訂を待たずに起票できる
- **案 T3: MVP 外（将来）とする**。MVP では bind mount とランタイム管理ディレクトリで足りるとする。CRI-7・STACK-1 の `[volumes]` が未実装のまま残る

## 3. 論点 2: 時期

- **S1: MS-4（v0.1 Linux）内**。#1886 の設計確定後、TASK-155（MS-12）より前
- **S2: MS-12（複数コンテナ定義）に合わせる**。`[volumes.<name>]` の初の消費者が `up` のため
- **S3: MS-6 以降（v0.2 判断ゲート後）**

依存: #1886（io のワイヤー作成要求）・macOS / Windows のボリューム実体の置き場（ゲスト内か。#1906 等の承認待ち）・core から io への依存追加（既存の想定どおりの向きで循環なし）。

## 4. 論点 3: IO-7 評価（#110）での扱い

- 既存のオーナー決定（#1897）は 2 構成を「置き場所の違い」と定義している。素直に読めば #110 は相当構成のまま進み、実体の named volume を待たない
- 実体へ置き換える場合は、この既存決定を見直すことになる。本書はその見直しを推奨しない
- 置き換えない場合でも、実体ができた後に再計測するかを #110 に記録する選択肢がある

## 5. 実装の範囲の目安（オーナーの読み物。本書の PR では着手しない）

- core に既定実装: ランタイム管理ディレクトリ配下の named volume の作成・削除・照会、attach / detach の記録、rootless / rootful の置き場、`StateStore` との関係
- core から io への結線（#1886 の後）
- 安全性: 管理ディレクトリのパス要素には検証済みの `VolumeName`（`[A-Za-z0-9._-]`・`.` / `..` 拒否・255 バイト上限）だけを使う。管理ルートの所有者・モード・symlink 検査は `StateStore` の状態ルートと同水準にする（security.md「ボリュームの外へ書き込める経路を作らない」）
- 信頼性: 下位 I/O 待ちに REPAIR-5 のタイムアウト、attach 中の remove は `FailedPrecondition`、特権操作失敗時の後始末
- アクセス制御: rootless ではボリューム実体をホストの非特権 UID 所有に置く（SEC-5）。plugin 経由でデータパスに届く経路を作らない（D-14・PLUG-1）
- トレイト doc の「暫定版」表記を #19 の承認済みに合わせて更新する（決定後の実装 issue で扱う）
- 接続: STACK の `[volumes]`・CRI / OCI の mounts

## 6. 比較表

| 案 | spec 変更 | #1886 待ち | MS への影響 | #110 への影響 | macOS / Windows の未決 |
| -- | --------- | ---------- | ----------- | ------------- | ---------------------- |
| T1 | 要 | 要 | spec 改訂待ちで遅れうる | 変えない | 巻き込む |
| T2 | 不要 | 要 | S1 / S2 に合わせられる | 変えない | 巻き込む |
| T3 | 不要 | 不要 | `[volumes]` が MS-12 でも未実装 | 変えない | 巻き込まない |

## 7. 推奨（Agent の推奨。決定ではない）

案 T2（TASK-114 または TASK-4 の追補として本リポで起票）× S1 または S2（#1886 確定後）。#110 は既存決定どおり相当構成で進め、実体の実装後に再計測するかを #110 に記録する。最終判断はオーナー。

## 8. オーナーが決めること

- [ ] 担当 TASK（T1 / T2 / T3。T2 なら追補先）
- [ ] 時期（S1 / S2 / S3）
- [ ] #110 の扱い（相当構成のまま／実体へ置き換え／実装後に再計測）
- [ ] spec 追記の要否（要るなら spec リポで扱う）
- [ ] 決定後に起票する実装 issue の親（phase:7 の親の sub-issue 上限に注意）

## 9. spec 側で扱う事項

新 TASK 番号の付与・CRI-7 カバレッジ表の更新（案 T1 の場合）。spec 側の変更は本リポでは決めず、オーナーへ報告する（spec-reference.md）。
