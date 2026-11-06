# MCP 2025-06-18 から 2026-07-28 への差分と plugin-mcp の対応方針

`fandhe-container-plugin-mcp` は MCP 2025-06-18 に準拠している。MCP-3 は 2026-07-28 版への追随を求める。本書は、2 段の仕様差分を一覧にし、項目ごとの実装の要否と担当 issue を整理して、`initialize` を廃した版にどう追随するかの判断材料をまとめる。

> **位置づけ**: TASK-119.1（#715）の設計。決定表（5 章）の D1〜D7 は 2026-11-05 にオーナーが推奨どおり承認した（#720・TASK-119.h1）。疎通確認の結果のレビューでは MCP-3 のステータスを確定のまま維持した（2026-11-06。#804・TASK-119.h2）。「要確認」と記した箇所は、決定後も精読が残っている。実装は #716・#717・#719 で行う。

- 対象ビヘイビア: MCP-3（関連: MCP-1・MCP-2・MCP-4・ERR-1・ERR-5・REPAIR-3・REPAIR-4・REPAIR-5・PLUG-12）
- 対象タスク: TASK-119（#715・#716〜#720）。前提 TASK-118（plugin-mcp 本体）・TASK-120。MS-7、Phase 13
- 出典: spec の `04-behavior/` は ID のみ参照し本文は写さない。外部仕様は下記（いずれも 2026-10-31 に取得）
  - <https://modelcontextprotocol.io/specification/2026-07-28/changelog>（比較元は 2025-11-25）
  - <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
  - <https://modelcontextprotocol.io/specification/2025-11-25/changelog>
  - 2026-07-28 の stdio 規定・`basic/index`（`_meta` の規則）・`server/discover`・`server/utilities/caching`・schema は、#716 の実装時（2026-11-06）に精読した（4.2。`specification/2026-07-28/basic/index`・`basic/transports/stdio`・`server/discover`・`server/utilities/caching`・`schema/2026-07-28/schema.ts`）。`basic/patterns/mrtr` と schema の `Result` は #717 の実装時（2026-11-06）に精読した（4.4）

## 1. 背景

- 2026-07-28 の changelog の比較元は 2025-11-25 であり、現行の 2025-06-18 からは **2 段**（2025-06-18 -> 2025-11-25 -> 2026-07-28）の差分を数える必要がある
- 2026-07-28 の中心は SEP-2575 によるステートレス化（`initialize` 廃止、要求ごとの `_meta`）である。仕様は legacy（`initialize` あり、2025-11-25 以前）と modern（2026-07-28 以降）を定義し、両方を受ける dual-era サーバーを許す（MAY）
- 本リポの plugin-mcp は stdio と UDS（改行区切りの暫定契約・PLUG-12）だけで、HTTP は持たない

## 2. 現状（main `cc03cf7c` 時点）

- `crates/plugin-mcp/src/server.rs`: `PROTOCOL_VERSION = "2025-06-18"`、`MAX_LINE_BYTES = 1 MiB`。`handle_message_with` は 1 行ごとの関数で接続状態を持たなかった（#716 で `handle_message_on` と接続ごとの 1 ビットの `ConnectionState` を足した。4.2）。扱うメソッドは `initialize`・`tools/list`・`ping`・`tools/call` の 4 つ。通知は黙殺し、バッチ配列は拒否し、クライアントからの応答は無視する（サーバーから要求を送らない）
- `initialize` は `initialize_params_valid` で `protocolVersion`・`capabilities`・`clientInfo` を検証し、要求された版にかかわらず常に `2025-06-18` を返す。capabilities は `tools.listChanged: false`
- `tools/list` は 2 ツールを固定順で返す。`nextCursor`・`ttlMs`・`cacheScope` は無い。`tools/call` は `structuredContent` と `content` を返し、業務エラーは `isError: true`
- `error.rs`: JSON-RPC コードは -32700・-32600・-32601・-32602・-32603。未知のツールと要求の形の不正は -32602（`data.code = INVALID_ARGUMENT`。ERR-5・MCP-4 に沿う）。引数の誤りは 2025-06-18 の経路が -32602、2026-07-28 の経路が `isError`（`ToolError::invalid_argument`。#4001・D8）
- 試験: `server.rs` 内の単体試験と `tests/startup.rs`・`tests/integration.rs`（#719 で `tests/protocol_2026_07_28.rs` を追加。11 章）が `2025-06-18`・`ping`・`initialize` を具体値で照合している
- ログは stderr に 1 行 JSON で、入力値を反射させない（REPAIR-4）

## 3. 差分一覧

「リビジョン」は変更が入った版（11-25 は 2025-11-25、07-28 は 2026-07-28）。判断待ちの項目は 5 章に対応する。

| 変更 | SEP・リビジョン | 破壊的か | plugin-mcp への影響 | 実装の要否 | 対応方針 | 担当 |
| ---- | -------------- | -------- | ------------------- | ---------- | -------- | ---- |
| `initialize`・`notifications/initialized` の廃止、要求ごとの `_meta`（`io.modelcontextprotocol/protocolVersion`・`clientCapabilities`・`clientInfo`） | SEP-2575・07-28 | 破壊的 | `handle_message_with` の分岐に modern 経路を足す | 要 | `_meta` を型検査して取り出し、dual-era なら legacy 経路を残す（4.1）。#716 で実装済み | #716 |
| `server/discover`（servers MUST） | SEP-2575・07-28 | 追加（MUST） | 新メソッド。対応版・capabilities・identity を返す | 要 | 対応版の一覧は定数で固定。結果の形は schema の `DiscoverResult` の必須 5 項目（`supportedVersions`・`capabilities`・`ttlMs`・`cacheScope`・`resultType`）と一致する（2026-11-06 に schema `38353251` で確認。identity は `_meta` の `serverInfo`） | #716 |
| `UnsupportedProtocolVersionError`（コード -32022、`data.supported`・`data.requested`） | SEP-2575・07-28 | 追加 | `error.rs` に variant と ERR-1 の `data.code` 対応を足す | 要 | `supported` は固定一覧。`requested` を返すなら長さ上限つき（4.2） | #716 |
| `ping` の廃止 | SEP-2575・07-28 | 破壊的 | `ping` 分岐 | 要（dual-era なら legacy 側に残す） | modern 経路では -32601 とする | #716 |
| `logging/setLevel`・`notifications/roots/list_changed` の廃止 | SEP-2575・07-28 | 破壊的 | 未実装のため影響なし | 不要（未実装） | なし | 対象外 |
| 全 result に必須の `resultType: "complete"` | SEP-2322・07-28 | 破壊的（必須化） | `server/discover`・`tools/list`・`tools/call`（`isError: true` を含む）の結果 | 実装済み | modern の全 result に `finish_modern` で付け、legacy には付けない（D3・4.3）。エラー応答は result ではないので付けない。クライアントは欠落を `complete` と扱う（MUST） | #717 |
| MRTR（`InputRequiredResult`・`inputRequests`・`requestState`） | SEP-2322・07-28 | 追加 | 追加入力を求めないため該当なし | 不要（追加入力を求めない。mrtr の精読で確定） | 4.4 | #717 の見直し |
| `tools/list` の `ttlMs`・`cacheScope` 必須化（`CacheableResult`） | SEP-2549・07-28 | 破壊的（必須化） | `ToolsListResult` | 要 | `ttlMs: 3600000`（1 時間。一覧は実行ファイルの差し替えでしか変わらない）・`cacheScope: "public"`（全利用者で同一）。modern の `tools/list` と `server/discover` に載せ、legacy には載せない（D6。#716 で実装済み） | #716 |
| `tools/list` を決まった順で返す（SHOULD） | 07-28 | なし | すでに固定順 | 不要（満たす） | 試験で固定済み（`tests/protocol_2026_07_28.rs`。経路をまたいでも `tools` 配列が同一。#719） | #719 |
| 結果の `_meta.io.modelcontextprotocol/serverInfo`（SHOULD） | SEP-2575・07-28 | なし | 結果の組み立て | 要（任意） | 名前と版を載せる | #716 |
| セッション・`Mcp-Session-Id`・SSE 再開の廃止 | SEP-2567・SEP-2575・07-28 | 破壊的（HTTP） | HTTP が無い | 不要（対象外） | HTTP を足すときに再評価 | 対象外 |
| `subscriptions/listen`（旧 `resources/subscribe` の置換） | SEP-2575・07-28 | 破壊的 | `listChanged: false` で購読を出さない | 不要（対象外） | なし | 対象外 |
| Streamable HTTP の `Mcp-Method`・`Mcp-Name` と `x-mcp-header` | SEP-2243・07-28 | 追加（HTTP のみ） | stdio / UDS に header layer が無い（stdio 側の規定は要確認） | 不要（現行トランスポートでは対象外） | 4.4 | #718 の見直し |
| tasks を拡張 `io.modelcontextprotocol/tasks` へ移動 | SEP-2663・07-28（導入は SEP-1686・11-25） | 破壊的 | tasks を実装していない | 不要（対象外） | なし | 対象外 |
| `ClientCapabilities`・`ServerCapabilities` の `extensions` | 07-28 | 追加 | 拡張を使わない | 不要 | なし | 対象外 |
| JSON Schema 2020-12 の既定化（11-25）と `inputSchema`・`outputSchema` の緩和（07-28） | SEP-1613・SEP-2106 | なし | 現スキーマが 2020-12 の範囲か | 確認済み（不要） | `$schema` は付けない。無ければ 2020-12 が既定で、現スキーマ（`type`・`properties`・`required`）はその範囲にある。完全一致で固定済み（#719） | #719 |
| 入力検証の誤りを Protocol Error ではなく Tool Execution Error（`isError`）で返す | SEP-1303・11-25 | 食い違い | 引数不正は現在 -32602 | 実装済み | 2026-07-28 の経路だけ `isError` で返す（D8・6 章）。#4001 で実装済み | #4001 |
| ツール名の指針 | SEP-986・11-25 | なし | 現在の 2 ツール名が適合するか | 確認済み（適合） | 1〜128 文字・`[A-Za-z0-9_.-]`・一意を試験で固定済み（#719） | #719 |
| `Implementation.description`・icons | 11-25 | 追加（任意） | `serverInfo` に載せられる | 不要（任意） | 載せない | 対象外 |
| エラーコードの割り当て方針（-32020〜-32099 は MCP 予約、-32000〜-32019 は実装定義） | 07-28 | なし | 独自に -32020 以降を使わない | 不要（遵守のみ） | `error.rs` の注記に残す | #716 |
| `notifications/cancelled` を受けたら処理を止める（SHOULD） | 07-28 stdio 規定 | なし | 現状は同期処理で黙殺 | 判断待ち | 要確認。同期処理のため実益が薄い | 判断待ち |
| サーバーは stdout に要求を書かない（MUST NOT） | 07-28 stdio 規定 | なし | すでに満たす | 不要（満たす） | 試験で固定済み（stdout の全行が応答で、`method` を持つ行が無い。#719） | #719 |
| Roots・Sampling・Logging の deprecation | SEP-2577・07-28 | 将来の削除 | 使っていない（ログはすでに stderr） | 不要（対象外） | なし | 対象外 |
| 認可系（DCR 非推奨・`iss`・`application_type`・資格情報のバインド） | SEP-2468・SEP-837・SEP-2352・07-28 | HTTP の認可のみ | 認可層が無い | 不要（対象外） | HTTP を足すときに再評価 | 対象外 |
| resource not found のコード変更（-32002 -> -32602） | 07-28 | 破壊的 | resources を実装していない | 不要（対象外） | なし | 対象外 |
| OpenTelemetry の `_meta` キー（`traceparent` 等） | SEP-414・07-28 | なし | 受けても無視してよい | 不要 | なし | 対象外 |

## 4. 主要な判断

### 4.1 dual-era か modern 単独か

仕様は dual-era サーバーを許す（`initialize` が来たら legacy 意味論、modern の `_meta` 付き要求はステートレスに処理）。

| 観点 | 案 A: dual-era | 案 B: modern 単独 |
| ---- | -------------- | ----------------- |
| 動作 | `initialize` は 2025-06-18 のまま、`_meta` 付きは 2026-07-28 | `initialize` は対応版を明記したエラーで拒否（SHOULD） |
| 利点 | MCP-1 の文言（`initialize` から始まる手順）と既存クライアントの互換を保てる。既存の試験を残せる | コードが単純。経路が 1 本 |
| 欠点 | 経路が 2 本。`ping`・`resultType` の差を版ごとに分ける必要 | legacy のクライアントが使えない。MCP-1 の文言を spec 側で変える必要。既存の試験の書き換え |

案 A を採る（根拠: MCP-1・MCP-2 の疎通を保ったまま追随でき、spec 側の変更が要らない。D1）。

### 4.2 `_meta` も版も無い要求の扱い

`initialize` を経ない要求で `_meta` に版が無い場合の扱い（MCP-3・D2。#716 で確定、2026-11-06 に一次情報を確認）。

- `basic/index` は `protocolVersion`・`clientCapabilities` の欠落を MUST で拒否（`-32602`）とし、`clientInfo` は任意とする。dual-era の例外は `initialize` が legacy を選んだ接続に限る。ERR-5 の注記も 2025-06-18 の経路を「`initialize` で始めた要求」と定義する
- 判定は `params._meta` の `io.modelcontextprotocol/protocolVersion` の有無。キーがあれば modern（文字列以外は `-32602`、`SUPPORTED_VERSIONS` に無ければ `-32022`、`clientCapabilities` が無い・オブジェクト以外は `-32602`。版の検査が先で、stdio の互換プローブが `-32022` を modern と認識できるようにする）
- キーが無い要求は、`initialize` か、`initialize` を成功させた接続（`ConnectionState` の 1 ビット）なら legacy、それ以外は `-32602`。「版が無ければ常に legacy」は `basic/index` の MUST に反するため採らない。modern の要求は接続状態を読まず書かない
- 対応版の一覧 `supported`・`supportedVersions` は `["2026-07-28"]` のみ。2025-06-18 は `initialize` からのみ到達できるので、`_meta` にその版を書いた要求は `-32022` になる（D11。2026-11-06 にオーナーが確認した）
- `data.requested` は 64 バイト（UTF-8 の文字境界）に切り詰め、`message` とログには入れない（REPAIR-4）。`clientInfo` は読まない
- `-32021` は必要なクライアント機能が無い場合のみ使う規定で、要求する機能が無いので返さない

### 4.3 legacy の応答にも `resultType` を付けるか

legacy の版の schema が知らないフィールドを足すと、厳格なクライアントが拒否しうる。一方 modern のクライアントは欠落を `complete` と扱う（MUST）ため、legacy 側は付けない案が安全。「legacy に付けない」を採る（D3）。

### 4.4 #717・#718 の受け入れ条件の見直し

- #717（マルチラウンドトリップ）: 本サーバーはクライアントへ追加入力を求めないので `InputRequiredResult` は対象外。必要なのは全 result への `resultType: "complete"` のみ。受け入れ条件（ハンドシェイクが仕様どおりに完了する）は対象が無くなるため、`resultType` のみに縮小した（D4）。`basic/patterns/mrtr` の精読の結果: `InputRequiredResult` は任意で `prompts/get`・`resources/read`・`tools/call` に限り、未宣言の `inputRequests` は送れない。本サーバーは `requestState` を発行せず読まないので検証の義務も生じない。実装済み（`finish_modern`）
- #718（ヘッダーベースルーティング）: SEP-2243 は Streamable HTTP の規定で、現行の stdio / UDS には header layer が無い。現行トランスポートでは対象外で、HTTP を足すときにだけ必要になる。対象外として閉じた（D5）

## 5. 決定表

| # | 項目 | 決定 | 状態 | 決定者 |
| - | ---- | ---- | ---- | ------ |
| D1 | dual-era か modern 単独か | 案 A（dual-era） | 承認済み | #720 |
| D2 | 版の無い要求の扱いと `data.requested` の上限 | 規定に従う。上限を設ける | 承認済み | #720 |
| D3 | legacy の応答への `resultType` | 付けない | 承認済み | #720 |
| D4 | #717 の受け入れ条件 | `resultType` のみに縮小 | 承認済み | #720 |
| D5 | #718 の扱い | 対象外として閉じる | 承認済み | #720 |
| D6 | `ttlMs`・`cacheScope` の担当 | #716 に含める | 承認済み | #720 |
| D7 | `notifications/cancelled` | 当面は黙殺のまま | 承認済み | #720 |
| D8 | SEP-1303 と ERR-5・MCP-4 の衝突 | 版で分ける。2026-07-28 の経路だけ `isError` | 承認済み | 2026-11-06 オーナー |
| D9 | `-32022` と全行の `data.code` | spec の ERR-5 の表に明記。`-32022` は `UNIMPLEMENTED` | 承認済み | 2026-11-06 オーナー |
| D10 | `tools/call` のレスポンス形の見直し | `content` の構造は変えない | 承認済み | 2026-11-06 オーナー |
| D11 | 対応版の一覧 `supported`・`supportedVersions` | `["2026-07-28"]` のみ。2025-06-18 は `initialize` からだけ到達する | 承認済み | 2026-11-06 オーナー（#804） |

## 6. spec 側へ報告した事項の結果

spec PR [#30](https://github.com/Fandhe-AI/fandhe-container-spec/pull/30) で反映した（2026-11-06）。ERR-5 の「引数スキーマ違反は `-32602`」は 2026-09-26 のユーザー決定で、これを D8 で改めた。

| 項目 | 結果 |
| ---- | ---- |
| (a) SEP-1303（引数不正を `isError` で返す）と ERR-5・MCP-4（-32602）の衝突 | D8。版で分ける。実装は #4001 |
| (b) ERR-5 の表に -32022 と予約範囲（-32020〜-32099）が無く、ERR-1 の `data.code` の対応も無い | D9。全行の値を表に明記し、予約範囲の注記を足した（#2217 もこれで解消） |
| (c) 案 B を採る場合の MCP-1 の文言の改訂 | 不要。D1 で案 A を採った |
| (d) api-mcp.md の「`tools/call` のレスポンス形は MCP-3 で見直す可能性」への回答 | D10。`content` の構造は変えず、`resultType` と `isError` の扱いだけを足した |

D8 で版を分けた理由: 2025-06-18 の仕様は "Invalid arguments" を Protocol Errors に挙げ、2025-11-25 以降は "Input validation errors" を Tool Execution Errors に挙げる。D1 は legacy を 2025-06-18 のまま保つ決定なので、legacy の応答は変えない。

`tools_call` の検査の分類:

| 検査 | 分類 |
| ---- | ---- |
| `params` がオブジェクトでない、`name` が無い、`arguments` がオブジェクトでない（`CallToolRequest` の違反） | どちらの経路も -32602 |
| 未知のツール | どちらの経路も -32602 |
| `container_id` の欠落・文字列以外・`ContainerId::new` の不合格（`arguments` の省略を含む） | 2025-06-18 の経路は -32602、2026-07-28 の経路は `isError`・`INVALID_ARGUMENT` |

`isError` の `message` にも入力値を入れない（REPAIR-4）。ツールのスキーマのフィールド名は入力値ではないので入れてよい。

`-32022` の `data.code` は `UNIMPLEMENTED` とした。仕様の文言が「要求の版を実装していない」で、`-32601` と同じ扱いになる。`schema.json` の `data` は `additionalProperties: false` を持たないので、`supported`・`requested` の横に `code` を足せる。

`-32021`（`MissingRequiredClientCapability`）は返さない。本サーバーはクライアントの機能を要求しないため。

## 7. 却下案

- 2025-06-18 のままにする: MCP-3 の要求に反する
- HTTP トランスポートを同時に足す: 範囲が広がり、認可・Origin 検査・ネットワーク公開の設計が要る。本追随には不要
- MCP の SDK crate を導入する: フルスクラッチ方針と依存方針（dependency-policy）に反し、不要

## 8. 実装 issue の対応表

| issue | 範囲 |
| ----- | ---- |
| #716 ステートレスコア | `_meta` の版検証、`server/discover`、-32022、`ping` の扱い、`serverInfo`、`ttlMs`・`cacheScope`（D6）。版の無い要求の扱いの精読（D2） |
| #717 マルチラウンドトリップ | `resultType: "complete"`（D4 で縮小） |
| #4001 引数の誤りの版の分岐 | 2026-07-28 の経路の入力検証の誤りを `isError` で返す（D8）。実装済み |
| #718 ヘッダーベースルーティング | 対象外として closed（D5） |
| #719 試験 | `tests/protocol_2026_07_28.rs`。順序の固定、スキーマ・ツール名の確認、MCP-1・MCP-2 の疎通の維持。実装済み（11 章） |
| 起票しない | `notifications/cancelled`（D7）。当面は黙殺のまま |

## 9. セキュリティの考慮

- `_meta` は新しい外部入力。`get()`・`as_*()` で型を検証して取り出し、未知の版は固定の `supported` つきの -32022 で返す。値をログやエラー文言へ反射させない（REPAIR-4）
- `_meta` を含めても既存の 1 行 1 MiB の上限（`MAX_LINE_BYTES`）の内側で処理し、新しい無制限の確保を作らない。MRTR の `requestState` は使わないので状態の増大も無い。期限（REPAIR-5）は既存の `Limits` を流用する
- トランスポートは stdio と peer 認証つきの UDS（PLUG-12）のままとし、HTTP は足さない。Origin 検査や `x-mcp-header` のヘッダーインジェクションは対象外で、HTTP を足すときに再評価する
- 新しい依存は不要

## 10. 再評価の条件

- HTTP トランスポートを足すとき
- 次の MCP リビジョンが出たとき
- Roots・Sampling・Logging が Removed になったとき
- core 側 proxy との結線でフレーミングが確定したとき（`uds.rs` の暫定契約）

## 11. 疎通確認の記録（TASK-119.5・#719）

追随後も MCP-1・MCP-2 の疎通が維持されることを、製品コードを変えずに試験で固定した（レビューは #804）。2026-07-28 版の `server/tools`・`basic/transports/stdio`（stdout の規定）を 2026-11-06 に精読して確認した。

| 試験 | 対応 | 内容 |
| ---- | ---- | ---- |
| `mcp1_mcp2_legacy_full_sequence_survives_over_stdio` | MCP-1・MCP-2 | 実バイナリで legacy の `initialize` → `tools/list` → `tools/call`（`list_containers` は一時の状態ルートで実呼び出し） |
| `mcp3_mcp2_modern_full_sequence_over_stdio` | MCP-3・MCP-2 | `initialize` なしの `server/discover` → `tools/list` → `tools/call` |
| `mcp3_tools_list_is_stable_across_routes_on_one_connection` | MCP-3 | 経路をまたいでも `tools/list` が同一・順序固定 |
| `mcp3_dual_era_probe_then_initialize_over_stdio` | MCP-3 | modern の要求が接続を legacy にしない |
| `mcp3_stdout_has_only_responses_and_logs_do_not_reflect_input` | MCP-1・REPAIR-4 | stdout は応答のみ・stderr は入力値を反射しない |
| `mcp2_both_tools_succeed_on_both_routes_with_fake_backend` | MCP-2 | 2 ツールの正常応答の形を両経路で固定 |
| `mcp3_tool_names_follow_the_naming_guidance`・`mcp3_input_schemas_are_fixed_and_2020_12_compatible` | MCP-3 | ツール名の指針・`inputSchema` の完全一致 |
| `uds::mcp3_modern_requests_over_uds_same_uid`（`tests/integration.rs`） | MCP-3・PLUG-12 | UDS 上の modern の 3 要求 |

実行: `cargo test -p fandhe-container-plugin-mcp`。ローカル（Linux・非 root）で `protocol_2026_07_28` 8 件・`integration` 5 件（`#[ignore]` 1 件）・`startup` 6 件・lib 90 件がすべて合格した。macOS・Windows のネイティブでは、main の 110ae71f の [run 42236524183](https://github.com/Fandhe-AI/fandhe-container/actions/runs/42236524183) の `platform-ci` で合格した（3 OS とも成功）。

残余（対象外）:

- `start_container` の本番起動（MCP-2 の実起動）は未実装で `UNIMPLEMENTED` を `isError` で返す。本試験はこの現行の契約を固定するだけで、実起動の達成は主張しない
- `list_containers` の `inputSchema` は仕様の推奨（`additionalProperties: false`）と異なるが許容される形で、変えない
- `notifications/cancelled` は D7 のまま黙殺する
