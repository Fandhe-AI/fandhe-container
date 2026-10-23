# バックエンド plugin の検証後の起動と RPC の配線の設計案

非 Linux（macOS）の CLI は plugin の発見・レジストリ・信頼性検証・許可済みハッシュ照合までで止まり、全段階を通っても `BackendFailure::NotInvokable` を返す。本書は、検証済みの plugin を起動し、`ContainerRuntime` の呼び出しを長さ接頭辞フレームの RPC として転送する「配線」の設計案をまとめる。

> **位置づけ**: TASK-115・TASK-79 追補（#1869）の設計案。**オーナーの承認は未取得（承認待ち）**。本書の推奨は確定ではない。決定表（5 章）の状態はすべて「承認待ち」とし、承認後に 8 章の実装 issue を起票する。コードは変更しない。

- 対象ビヘイビア: PLUG-1・PLUG-2・PLUG-4・PLUG-7・PLUG-11・PLUG-12・SEC-4・REPAIR-3・REPAIR-4・REPAIR-5・CLI-1・MAC-1・CORE-1（関連: MAC-4・WIN-1・ERR-1・ERR-2・CRI-7）
- 対象タスク: TASK-115（#384）・TASK-79（#637。TASK-79.4〔#641〕の残り）追補。関連 TASK-110（#257）・TASK-122（#275）・TASK-114（#456）。MS-3・MS-5・MS-6、Phase 7（#58）
- 出典: spec の `04-behavior/plugin-system.md`・`api-cri.md`・`screen-cli.md`（ID のみ参照し、本文は写さない）
- 前提の決定済み issue: #1320（起動対象の型）・#1319（環境変数）・#1322（計装アダプタの配置）・#1415（Windows の実行構成）・#1539（macOS の信頼性検証）

## 1. 背景

doc は本配線を「TASK-114」と書いているが、TASK-114 の open issue（#456・#458〜#461・#849・#850）は CRI の gRPC 経路で、長さ接頭辞フレームのバックエンド plugin の起動と `HashVerifiedPluginFile` の受け渡しは扱っていない。#1539 のオーナー判断（2026-10-12）が「残っている別件」とした範囲が本 issue である。core / plugin 境界（PLUG-1）と拡張点トレイト `ContainerRuntime` に関わるため、実装の前に設計を決める。

## 2. 現状（main `8fe23c0d` 時点）

- `crates/cli/src/commands/plugin_backend.rs` の `backend_failure` は、発見 → `PluginRegistry::from_candidates` → `verify_candidate` → `PluginVerificationMethod::default().verify`（空の一覧で全件拒否）→ `NotInvokable` の順に進む。PATH 由来の候補もレジストリへ渡している
- `plugin_discovery`・`plugin_trust` は `plugin` feature で区切られていない（`crates/core/src/lib.rs`。区切られているのは `plugin` の再エクスポートだけ）。cli は core を既定 feature（`plugin` 有効）で使う
- 起動 API（`crates/plugin/src/lifecycle.rs` の `call_once`・`ResidentPlugin`・`PluginSession`）に本番の呼び出し元は無い
- 起動 API の期限の定数: `ONE_SHOT_TIMEOUT_DEFAULT` / `_MAX` 10 秒・`PLUGIN_EXIT_TIMEOUT` 5 秒・`PLUGIN_REAP_TIMEOUT` 2 秒・`RESIDENT_START_TIMEOUT_DEFAULT` / `_MAX` 10 秒・`UDS_RPC_TIMEOUT_DEFAULT` / `_MAX` 10 秒（`RpcTimeout` は 10 秒を超える値を作れない）
- plugin-macos の期限: `LAUNCH_TOTAL_TIMEOUT` 7 秒・`LAUNCH_START_TIMEOUT` 3 秒・`LAUNCH_STOP_TIMEOUT` 2 秒・`CREATE_VALIDATION_TIMEOUT` 3 秒・`SHUTDOWN_BUDGET` 4 秒・`FRAME_DEADLINE` = `UDS_RPC_TIMEOUT_DEFAULT`
- plugin-macos の暫定ワイヤー契約は `Vec<String>`（先頭要素が操作名）。create（id・kernel・initrd・cmdline・console_log・共有の組）・start・stop・ping だけを処理し、kill・delete・state は `UNIMPLEMENTED`。VM の登録は plugin プロセスのメモリ上にあり、終了時に `stop_all` で停止する。platform-macos の `Vm` は `Drop` で停止を要求する
- `ControlMessage<T>` のエンベロープは未知のフィールドと配列形を拒否する。「項目を足すときは `PROTOCOL_VERSION` を上げる」と doc にあり、現在は `PROTOCOL_VERSION = 1`
- `ContainerRuntime` は同期・`&self`・`Send + Sync`・dyn 互換。要求型（`CreateRequest { id, bundle }` 等）は serde を derive していない。契約 4 は「core にはこのトレイトの実装を置かない」
- `ResidentPlugin::call` は `&mut self`。Linux では起動したスレッドが終わると plugin が SIGKILL される（`PR_SET_PDEATHSIG`）
- `crates/cli/src/main.rs` は終了時に `take_pending_child_cleanup_failures` をすでに呼ぶ
- supervisor の bin と起動経路は Linux 限定（`systemd-run --user`）。CLI 全体の期限を表す定数は無い
- 兄弟の設計（いずれも未マージ・承認待ち）: #2198（#1868）は「許可済みハッシュ一覧の読み込み API を `plugin_trust` に置き、#1869 の共通入口が呼ぶ。呼び出しごとに読み、キャッシュしない」「PATH 由来の候補を登録前に除く」を推奨。#2197（#1862）は「Windows ホストでは plugin を発見も起動もしない」を推奨。#2195（#1856）は `PluginLaunchTarget::from_verified_file` を追加する

## 3. 前提と制約

- 決定済み: #1320・#1319・#1322・#1415・#1539、#280
- CORE-1: 中央の常駐デーモンを持たない。監視はコンテナごと
- 依存の向きは core → plugin。plugin crate は core に依存しない
- `make check-cli-backend-deps` を維持する（cli は `platform-*`・`plugin-macos`・`plugin-windows` へ依存しない）
- 依存の追加は前提にしない（serde は境界の crate にすでにある）

## 4. 決める項目

### 4.1 配線の置き場所（1 本の入口）

- 推奨: core に新モジュール `crates/core/src/plugin_backend.rs`（名前は仮。`#[cfg(feature = "plugin")]`）を置き、次を 1 つの公開入口（例: `open_backend_runtime(BackendKind, &BackendOpenOptions) -> Result<BackendRuntime, BackendOpenError>`）にまとめる: 発見 → PATH 由来の除外 → レジストリ → `verify_candidate_audited` → 許可済みハッシュ一覧の読み込み（#1868 の API）→ `verify_hash` → `PluginLaunchTarget` への変換 → `PluginSession::start` → 型つき proxy（`Box<dyn ContainerRuntime>`）
  - `BackendKind` は閉じた列挙（macOS だけ。将来 microvm）。外部入力から plugin 名を組み立てない
  - `BackendOpenError` は `kind()`（閉じた列挙）と固定文言だけを持ち、パス・plugin 名・plugin から来た文字列を含めない。詳細は監査の記録だけに載せる
- feature との関係: 入口全体が `plugin` feature の下にあるので、feature を切ると起動できる経路そのものが無くなる（検証だけが抜けて起動できる構成は作れない）。`plugin_discovery`・`plugin_trust` は feature で区切らないままにする（起動しないので fail-open にならず、Linux の検証の試験と #1868 の読み込みが feature に依らず使える）。cli は `cfg(feature)` を持たず core の既定 feature を使い続ける
- cli の責務: `plugin_backend.rs` は「`--root` の検証 → core の入口を呼ぶ → `BackendOpenError::kind()` を固定文言の表へ写す」だけにする
- 契約の修正: `container_runtime.rs` の契約 4 を「バックエンドの実装は置かない。plugin 境界へ転送する proxy だけは core に置く」に改める
- 採らない選択肢: cli に入口を置く（cli が起動 API と監査 sink の配線を持ち、CRI 経路〔TASK-114〕と共有できない）・plugin crate に置く（core の型を参照できず依存の向きが逆になる）

### 4.2 起動対象の受け渡し

- 推奨: #1320 のとおり、`HashVerifiedPluginFile` → `PluginLaunchTarget::from_verified_file`（#1856・PR #2195）の変換を 4.1 の入口の中の 1 か所でだけ行う（#1857 の機械判定の対象もこの 1 か所）。検証から起動まで保持した fd だけを使い、パスを開き直さない。`path()` / `resolved_path()` は表示と監査にだけ使う
- macOS は実体のパスで起動し、直前に dev / ino で同一性を確かめる（#1866）。同じ UID または root による差し替えは残余として書く
- `PluginLaunchTarget` は入口の外へ出さない

### 4.3 型つき proxy

**ワイヤー DTO の置き場所**

- A（推奨）: `fandhe-container-plugin` に新モジュール（例: `runtime_rpc`）を作り、`RuntimeRequest`（`Create`・`Start`・`Kill`・`Stop`・`Delete`・`State`・`Ping`）と `RuntimeResponse`（`Status { id, state, pid, exit_code }`・`Deleted`・`Pong`）を serde（externally tagged・snake_case・`deny_unknown_fields`）で定義する。core の proxy が core の型と DTO を相互に変換する（向きは core → plugin のまま）。plugin-macos / plugin-windows は core に依存しないまま DTO を使え、外部の plugin 作者がリンクするのはこの crate だけで済む。新しい依存は要らない
- B: DTO を core に置き、plugin-macos → core の辺を確定させる（`docs/architecture.md` の「想定」を確定にする）。外部の plugin 作者が core（Apache-2.0 単独・重い）にリンクすることになる
- **判断事項（ライセンス）**: A では新しいコードが `MIT OR Apache-2.0`（`fandhe-container-plugin` のライセンス）で公開される。境界の契約のコードなので crate の目的には合うが、ライセンスの判断なのでユーザーへ確認する

**ID の検証**: proxy は `MessageId` をセッションごとに 1 から単調に増やす。応答の id が要求と違う、または `Request` が返った場合はプロトコル違反として、セッションを閉じ（子を kill・回収）、`DataLoss` を返す（fail-closed。再利用しない）。この検証は core の proxy に置く。

**エラーの写像**: `PluginErrorCode` → core の `ErrorCode` の対応表を proxy の中の関数 1 つに置く。同名のコードは 1 対 1、表に無いものは `Internal`。plugin が返した `message` は信頼できないので `TraitError` の message へ流さず固定文言（例: `plugin backend returned <CODE>`）にする。元の message を切り詰めて監査・`OpRecorder` に入れるかは実装 issue で決める（推奨は入れない）。

**フレームの形**: PLUG-2 の長さ接頭辞フレームとエンベロープは変えず（IO-1 とは別物）、本体の型だけを `Vec<String>` から DTO へ替える。旧い本体は復号できないので `PROTOCOL_VERSION` を 1 から 2 へ上げ、組み合わせが合わないときはヘッダ検証で失敗させる（推奨）。影響範囲: `crates/plugin` の `frame`・`message` の試験、plugin-macos と plugin-windows の `frame_loop`・`adapter`・e2e の試験、plugin-mcp の uds（フレームを使うかを実装 issue で確かめる）、`core::plugin` の再エクスポートの試験（`PROTOCOL_VERSION == 1` を確かめている）。

**並行性**: トレイトは `&self + Send + Sync`、`ResidentPlugin::call` は `&mut self`。proxy はセッションを `Mutex` で包み、1 往復ずつ直列に実行する。Linux の常駐 plugin はセッションより長く生きるスレッドから起動する（pdeathsig の規則）。CLI は main スレッドから起動する。

**未決の問題（解かずに書き出す）**: core の `CreateRequest` は `{ id, bundle }` だけだが、plugin-macos の create は kernel・initrd・cmdline・console_log・共有の組を要求する。

- (a) plugin が bundle の `config.json`（`mounts[]`）と、固定の導入先にあるゲストのカーネル・initrd から組み立てる（推奨。core の型と CRI-7 を変えずに済む）。この場合 bundle の検証を plugin 側でもう一度行う（`SharedDirectoryPath::try_new` を使い続ける）
- (b) `CreateRequest` に OS 固有の拡張フィールドを足す（CLI-1 の「上位 crate へ OS 固有型を漏らさない」に反する）
- (c) proxy が bundle から組み立てて DTO の create に載せる（core が macOS の VM 構成を知ることになる）

kill・delete・state は plugin-macos では未実装（`UNIMPLEMENTED`）。proxy はそのまま `Unimplemented` として返し、実装済みのふりをしない（REPAIR-3）。

### 4.4 都度起動と常駐の選び方・常駐の寿命

- 事実: VM は plugin プロセスのメモリ上にあり、plugin が終了すると停止する。CLI の create・start・stop・delete は別プロセスなので、CLI が plugin を持つ形では、start で起動した VM がその CLI の終了とともに止まる
- A: CLI が都度起動・常駐のセッションを 1 コマンドのあいだだけ持つ。CORE-1 に合うが、コマンドをまたいで VM を保てない
- B: コンテナごとの保持役（CORE-1 に合う。Linux の supervisor と同じ考え方）が常駐 plugin を持ち、ほかの CLI コマンドは保持役と話す。supervisor は今 Linux 限定なので、macOS へ移すか macOS 専用の軽い保持役を作り、CLI と保持役の経路も新しく決める必要がある
- C: plugin-macos が自分でデタッチして待ち受け、CLI が再接続する。#395 の「plugin は connect 側だけ」と PLUG-12（接続後は socket を残さない）に反するので採らない
- 推奨:
  - 段階 1（本配線の範囲）: A。モードは `PluginMode` で操作ごとに決め、ping と create の検証は都度起動にする。start は「同じ CLI プロセス内で VM を保つ必要がある」ので、コマンドをまたいで保てないことを固定の `FailedPrecondition`（新しい `BackendFailure` の値）で正直に返す
  - 段階 2: B を正式な方式として別の設計 issue で決める。`macos-vm-strategy.md` の未決事項「VM を保持する主体と寿命」（#370）と同じ論点なのでそこで一緒に決める。本書では方向（コンテナごとの保持役・中央の常駐デーモンは持たない）だけを推奨する
- 常駐の寿命は起動したプロセス（段階 1 では CLI）のセッションと同じ。`PluginSession::shutdown` または `Drop` で kill・回収する

### 4.5 期限（REPAIR-5）

既存の定数で入れ子にする。新しい数値は決めない。

| 段階 | 期限 | 根拠 |
| ---- | ---- | ---- |
| 都度起動（spawn → 応答） | `OneShotTimeout`（既定 = 上限 10 秒） | lifecycle |
| 常駐の起動（spawn → accept） | `ResidentStartTimeout`（既定 = 上限 10 秒） | resident |
| 1 往復 | `RpcTimeout`（上限 10 秒） | transport |
| 応答後の終了待ち / 回収 | `PLUGIN_EXIT_TIMEOUT` 5 秒 / `PLUGIN_REAP_TIMEOUT` 2 秒 | lifecycle |
| plugin 側の start | `LAUNCH_TOTAL_TIMEOUT` 7 秒（< 1 往復の 10 秒） | plugin-macos |
| plugin 側の終了 | `SHUTDOWN_BUDGET` 4 秒（< 終了待ち 5 秒） | plugin-macos |

- stop: `StopRequest::grace` は 10 秒を超え得るが `RpcTimeout` は超えられない。推奨は、proxy が stop を「SIGTERM の kill RPC → 期限つきの state RPC でポーリング → 猶予が過ぎたら SIGKILL の kill RPC」に分け、どの往復も 10 秒以内に収めること。代案は DTO の stop に猶予を載せ plugin 側で待つ方式で、`grace` が 10 秒 − 余裕を超える指定を `InvalidArgument` で拒否する。どちらも承認待ち。plugin-macos の kill・state が未実装なので、段階 1 で代案の形にするかを実装 issue で決める
- CLI 全体の期限: 「1 コマンドの期限 = 起動の期限 + 各往復の期限の和 + 終了待ち + 回収待ち」という関係だけを書く。CLI 全体の上限を新設するかは未決（7 章）

### 4.6 環境変数

- #1319 の決定（既定は空で `FANDHE_CONTAINER_PLUGIN_SOCKET` だけを渡す。追加は呼び出し側が名前と値を明示し plugin crate が検証する。API は #1858）に従う
- plugin-macos: 推奨は「追加なし」から始めること。`HOME` / `TMPDIR` が要るかは**未確認**（#1628 の実機での実行で確かめる）。platform-macos・plugin-macos のコードは `HOME`・`TMPDIR` を `env::var` で読んでいないが、Virtualization.framework など OS の層が暗黙に使う可能性は確かめていない。要ると分かったら、値を検証（絶対パス・自 UID 所有・group / other 書き込み不可）して #1858 の API で渡す
- Windows のホスト用の変数は扱わない（#1415・#1319）

### 4.7 監査と計装

- peer 認証の拒否: core に `PeerAuthObserver` の実装（例: `AuditPeerAuthObserver`）を置き、拒否 1 件につき `AuditSink`（本番は `FileAuditSink`）へ 1 件記録する。フックはブロックする I/O をしない契約なので、拒否はメモリの有界バッファにため、呼び出しが戻った後に sink へ書く（`JsonLinesPeerAuthObserver` → `drain_lines` → sink の形）。socket のパスは監査の記録にだけ載せ、CLI の出力には出さない
- CRI の gRPC 経路の peer 拒否（#2484 で配線済み。本書の承認状態とは独立）: plugin-cri が受付側なので、plugin 境界をまたがず plugin-cri のプロセス内で core の `ControlAuditRelay` → `FileAuditSink`（同じ `@audit.log`）へ書く。層は `plugin_peer`（理由は `plugin_peer_uid_mismatch` 等の閉じた語彙。パスは socket、uid・pid の値は載せない）。フックは有界キューへ `try_send` するだけで I/O をせず、専用 thread が sink へ書く（文字列の `drain_lines` ではなく型つきの `AuditRecord` を渡す点が上の形との差）。あふれ・書き込み失敗は固定語彙の行で stderr に残す。記録経路を作れなければ（Linux）起動しない。非 Linux は #2430 の判断待ちで stderr のみ。長さ接頭辞フレームの経路（core が接続する側）は上のとおり W5
- 信頼性検証の拒否: 入口は `verify_candidate`（記録なし）ではなく `verify_candidate_audited` を使い、同じ sink へ書く
- 起動 API の observer（`call_observed` の `PluginCallRecord` / `OneShotRecord` / `ResidentCallRecord`）: #1322 のとおり、proxy を配線する場所（4.1 の core のモジュール）で `OpRecorder` へ渡す。CLI は今の `production_runtime` が持つ `OpRecorder` を入口へ渡す
- `Drop` 時に延期された後始末の記録: CLI の `main.rs` が終了時に `take_pending_child_cleanup_failures` を呼ぶので追加配線は要らない。段階 2 の保持役を作るときはそのホストでも取り出しを配線する
- sink の書き込み失敗: SEC-4 に従い黙って捨てず、`audit-delivery.md` の方針に合わせる

### 4.8 許可済みハッシュ一覧と PATH 由来の候補

- #1868（PR #2198。未マージ・承認待ち）の推奨に乗せる: 入口が `plugin_trust` の一覧の読み込み API を呼び、呼び出しごとに読み、キャッシュしない（CORE-1）。一覧が無いときは全件拒否、読めない・不正なときはエラーで止める
- PATH 由来の候補は #2198 の推奨（登録前に除外し、警告は残す）に合わせる。#2198 の推奨が変わったら本書も合わせて直す
- #2198 の I5（cli へ一覧の読み込みを配線する）は本書の入口に依存する。推奨は「I5 は本書の入口 issue に依存させる」（1 本にまとめる案もある）

### 4.9 対象の OS と plugin・TASK-114 との分担

- macOS（plugin-macos）: 主な対象
- Linux: plugin を介さず core を直接呼ぶ（今のまま）
- Windows: #1415 の決定と #1862（PR #2197）の推奨により、ホストでは plugin を発見も起動もしない。ゲスト内の core は Linux の経路を使う。plugin-windows の doc の「core 側 proxy が spawn する（TASK-114）」は #2197 の言い方（ホストの起動役の補助）に合わせて書き換え、「proxy が spawn する」とは書かない
- plugin-mcp: MCP クライアントが起動する前面のサーバーで core が起動するものではないため、この入口には乗せない。結線とフレーミングは別 issue で追う
- plugin-microvm: 将来この入口（`BackendKind` に値を足す）に乗せる候補。本書の範囲外
- TASK-114（CRI の gRPC 経路）との分担: 共有するのは入口のうち「発見 → 検証 → 起動対象」の部分だけ（関数として切り出す）。gRPC の接続と `ContainerRuntime` の proxy は別（plugin-cri は gRPC サーバーで、本書の長さ接頭辞フレームの proxy は使わない）。その peer 拒否の監査は、受付側の plugin-cri が自プロセス内で core の監査ログへ書く形で #2484 に配線済み（4.7）

### 4.10 CLI の失敗の分類

- `BackendFailure::NotInvokable` をやめ、`BackendOpenError::kind()` に対応する固定文言の値へ置き換える。案: `LaunchFailed`（`Unavailable`。spawn・接続・peer 認証の失敗）・`TimedOut`（`Timeout`）・`ProtocolViolation`（`DataLoss`。ID の不一致・不正なフレーム）・`DetachedLifecycleUnsupported`（`FailedPrecondition`。4.4 の段階 1）・`AllowlistUnavailable`（#2198 の I5 と調整）
- 方針は変えない: 文言は英語の定数だけ。パス・plugin 名・plugin 由来の文字列を出力へ出さない。`classify` で表との完全一致を確かめ、`ALL` が全値を走査する試験を残す。`PluginTrustError` を `?` で `TraitError` へ変えない
- 起動後の `ContainerRuntime` のエラー（4.3 の写像を通ったもの）は `OciRuntimeError` の今の経路（ERR-2 の終了コード）へそのまま流す

## 5. 決定事項の一覧

| 項目 | 推奨 | 状態 |
| ---- | ---- | ---- |
| 4.1 入口の置き場所 | core の `plugin_backend`（`plugin` feature の下）に 1 本。cli は写像だけ。契約 4 の文言を直す | 承認待ち |
| 4.2 起動対象 | 入口の 1 か所で `from_verified_file`。fd 保持・パスを開き直さない | 承認待ち |
| 4.3 DTO の置き場所 | A: `fandhe-container-plugin` に置く（`MIT OR Apache-2.0` の確認が必要） | 承認待ち |
| 4.3 ID 検証・エラー写像 | 不一致は `DataLoss` でセッションを閉じる。plugin の message は流さない | 承認待ち |
| 4.3 `PROTOCOL_VERSION` | 1 から 2 へ上げる | 承認待ち |
| 4.3 create の構成 | (a) plugin が bundle と固定の導入先から組み立てる | 承認待ち |
| 4.4 寿命 | 段階 1 は A（start は `FailedPrecondition`）、段階 2 は B を別 issue で | 承認待ち |
| 4.5 期限・stop | 既存定数で入れ子。stop は kill / state の往復に分ける | 承認待ち |
| 4.6 環境変数 | 追加なしから始める（`HOME` / `TMPDIR` は実機で確認） | 承認待ち |
| 4.7 監査 | `verify_candidate_audited`・peer 拒否 observer・`OpRecorder` を入口で配線 | 承認待ち |
| 4.8 一覧・PATH | #2198 の推奨に乗せる。I5 は本書の入口に依存 | 承認待ち |
| 4.9 OS 分担 | macOS のみ。Windows は #2197、mcp は対象外 | 承認待ち |
| 4.10 失敗の分類 | `NotInvokable` を固定文言の値に分割 | 承認待ち |

## 6. spec に入れる文言の案と担当 TASK の案

本リポからは spec を編集しない。spec リポ側の課題としてユーザーへ報告する。

- 暫定契約として spec 側で決めてほしいもの: `FANDHE_CONTAINER_PLUGIN_SOCKET`（PLUG-7。#1319 と合わせて）、要求・応答の本体の型（4.3 の DTO）、`PROTOCOL_VERSION` 2 への変更、ID の不一致を `DATA_LOSS` として扱うこと、`PluginErrorCode` → `ErrorCode` の写像、macOS でコマンドをまたいで VM を保つ主体（MAC-4。段階 2）
- 担当 TASK の案: (1) TASK-115 追補、(2) TASK-79 追補、(3) 新 TASK（G8 の「バックエンド plugin の proxy」。TASK-114 と並べる）。推奨は (3)。core の入口と proxy は CLI と CRI の両方が使い、TASK-114 とも TASK-115 とも範囲が違うため。ユーザーに確認する

## 7. 未確認事項・再検証条件

- macOS の `HOME` / `TMPDIR` の要否（#1628 の実機での実行で確認）
- CLI 全体の期限の上限を新設するか
- 4.3 の create の構成の組み立て方（(a)〜(c)）
- 4.4 段階 2 の保持役（supervisor を移すか、macOS 専用の保持役を作るか）
- 4.5 の stop の方式
- plugin-mcp の uds が長さ接頭辞フレームを使っているか（`PROTOCOL_VERSION` 変更の影響範囲）
- #2198・#2197 が承認で変わった場合の追従

## 8. 確定後の実装 issue（起票しない）

承認後に起票する。親は Phase 7（#58）。1 件は実装 2h 以下・1 PR・1 関心事。

| # | タイトル案 | 依存 | 受け入れ条件の骨子 |
| - | ---------- | ---- | ------------------ |
| W1 | feat(plugin)!: ランタイムの要求・応答の DTO を追加し `PROTOCOL_VERSION` を 2 に上げる | 本書の承認（4.3 A・ライセンス確認） | serde の往復・未知フィールド拒否・上限の試験を具体値で。`core::plugin` 再エクスポートの試験を更新 |
| W2 | feat(core): proxy の ID 検証と `PluginErrorCode` → `ErrorCode` の写像を追加 | W1 | 不一致は `DataLoss` でセッションを閉じる。全コードで写像を試験 |
| W3 | feat(core): `ContainerRuntime` の proxy（`Mutex` で直列化。`PluginSession` の上）を追加し契約 4 の文言を直す | W2・#1856 | 偽の plugin で create・start・state 等を往復。plugin の message を反射しない |
| W4 | feat(core): 発見 → 検証 → 起動の入口を `plugin` feature の下に追加 | W3・#1857・#1868 の I3 / I4 | `verify_candidate_audited` を使う。PATH 由来を除く。feature を切ると入口が無い |
| W5 | feat(core): peer 認証の拒否を `AuditSink` へ書く observer を追加 | W4 | 拒否 1 件につき記録 1 件。書き込み失敗を黙って捨てない |
| W6 | feat(core): 起動 API の observer を `OpRecorder` へ渡す | W4 | 操作ごとの記録の試験 |
| W7 | feat(plugin-macos): 型つきの本体へ切り替え、create の構成を bundle と固定の導入先から組み立てる | W1・4.3 未決の決定 | `Vec<String>` の契約を消す。bundle の検証を plugin 側でも行う |
| W8 | feat(cli): `plugin_backend` を core の入口へ置き換え、`NotInvokable` を固定文言の値へ分ける | W4・#2198 の I5 | `classify` の表の試験。パス・名前を出さない。`make check-cli-backend-deps` が通る |
| W9 | feat(core): stop を kill・state の往復に分ける（または猶予の上限を設ける） | W3・4.5 の決定 | どの往復も 10 秒以内。具体値の試験 |
| W10 | docs: 「TASK-114」と書かれた doc のうち本配線を指すものを本書・W1〜W9 へ書き換える | W8 | 8.1 の分類どおり。CRI の gRPC を指すものは変えない |
| W11 | docs(platform): `macos-vm-strategy.md` の未決事項に本書の 4.4 を参照として足す | 本書の承認 | 段階 1 と段階 2 の参照 |
| W12 | docs(core): macOS でコマンドをまたいで VM を保つ保持役の設計を決める（段階 2） | 本書の承認・#370 | CORE-1 との整合、CLI と保持役の経路、supervisor を移すか |
| W13 | test: macOS 実機で CLI → plugin-macos の create・start を確かめる（人間担当） | W8・#1628 | 実機の結果を PR に記録。`HOME` / `TMPDIR` の要否も確認 |

### 8.1 「TASK-114」表記の掃除対象（W10 の入力）

`git grep -c 'TASK-114' -- crates benches scripts`（`8fe23c0d`）で 46 ファイルが見つかった。下は分類案で、W10 で各行を読んで確定する。1 ファイルに両方の意味が混ざる場合（`transport.rs`・`uds_security.rs`・`message.rs` 等）は行ごとに分ける。

| 分類 | ファイル |
| ---- | -------- |
| 本配線（書き換え候補） | `crates/cli/src/commands.rs`・`commands/create_start.rs`・`commands/plugin_backend.rs`・`commands/stop_delete.rs`・`setup.rs` |
| 本配線 | `crates/core/src/plugin_discovery.rs`・`traits.rs`・`traits/container_runtime.rs` |
| 本配線 | `crates/plugin/src/audit.rs`・`error.rs`・`lib.rs`・`lifecycle.rs`・`lifecycle/drop_report.rs`・`lifecycle/mode.rs`・`lifecycle/resident.rs`・`message.rs`・`transport.rs`・`uds_security.rs` |
| 本配線 | `crates/plugin-macos/src/adapter.rs`・`frame_loop.rs`・`lib.rs`・`main.rs`・`tests/e2e.rs`、`crates/platform-macos/src/config.rs`・`console_log.rs` |
| 本配線（Windows は #2197 の言い方に合わせる） | `crates/plugin-windows/src/adapter.rs`・`frame_loop.rs`・`lib.rs`・`main.rs`・`tests/e2e.rs` |
| plugin-mcp の結線を追う別 issue を指すよう直す | `crates/plugin-mcp/src/lib.rs`・`main.rs`・`uds.rs`・`tests/integration.rs` |
| 本配線 | `scripts/cli-parity-check.sh` |
| CRI の gRPC 経路（変えない） | `crates/cri/src/adapter.rs`・`image_pull.rs`・`lib.rs`・`runtime_service.rs`・`tests/image_pull.rs`・`tests/runtime_service_namespaces.rs`、`crates/plugin-cri/Cargo.toml`・`src/lib.rs`、`crates/plugin/src/grpc.rs` |
| 判断が要る | `crates/core/src/traits/network_plugin.rs`（`NetworkPlugin` の proxy。本書の範囲外で別に追う）・`crates/net/src/network/delete.rs` |

## 9. セキュリティ上の考慮

- ソフトウェアとデータの完全性: 起動するのはハッシュで照合した fd の実体だけで、検証から起動までパスを開き直さない（TOCTOU。macOS は dev / ino の確認と残る余地を書く）。一覧が無い・読めないときは全件拒否またはエラーで止める（fail-closed）。PATH 由来は登録しない
- アクセス制御: UDS は 0700 のディレクトリと peer credential の照合（PLUG-12）。拒否はすべて監査に記録する（SEC-4）。常駐の接続は accept 後に socket を消す
- インジェクション・情報漏えい: CLI の出力は固定文言だけで、パス・plugin 名・plugin 由来の文字列を反射しない。plugin の応答は untrusted 入力として、型つき DTO（未知フィールドを拒否）で復号する
- 不安全な設計: すべての待ちに期限がある（4.5）。フレームには長さの上限とチェックサムがある。ID が合わなければセッションを閉じる。子は必ず kill・回収する
- 環境変数: 既定は空で資格情報を継承させない（#1319）

## 10. 関連文書

- [`docs/architecture.md`](../architecture.md): `plugin-*` → `core` の「想定」の辺と、`core` → `plugin` の辺の行（本書では変更しない）
- `plugin-hash-allowlist.md`（#2198。未マージ）・`windows-execution-layout.md`（#2197。未マージ）
- [`macos-vm-strategy.md`](./macos-vm-strategy.md)・[`privilege-separation.md`](./privilege-separation.md)・[`audit-delivery.md`](./audit-delivery.md)
