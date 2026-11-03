# MCP 2025-06-18 から 2026-07-28 への差分と plugin-mcp の対応方針のドラフト

`fandhe-container-plugin-mcp` は MCP 2025-06-18 に準拠している。MCP-3 は 2026-07-28 版への追随を求める。本書は、2 段の仕様差分を一覧にし、項目ごとの実装の要否と担当 issue を整理して、`initialize` を廃した版にどう追随するかの判断材料をまとめる。

> **位置づけ**: TASK-119.1（#715）の設計ドラフト。**オーナーの承認は未取得（承認待ち。承認は #720・TASK-119.h1）**。本書の推奨は確定ではない。決定表（5 章）の状態はすべて「承認待ち」。コードは変更しない。

- 対象ビヘイビア: MCP-3（関連: MCP-1・MCP-2・MCP-4・ERR-1・ERR-5・REPAIR-3・REPAIR-4・REPAIR-5・PLUG-12）
- 対象タスク: TASK-119（#715・#716〜#720）。前提 TASK-118（plugin-mcp 本体）・TASK-120。MS-7、Phase 13
- 出典: spec の `04-behavior/` は ID のみ参照し本文は写さない。外部仕様は下記（いずれも 2026-10-31 に取得）
  - <https://modelcontextprotocol.io/specification/2026-07-28/changelog>（比較元は 2025-11-25）
  - <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
  - <https://modelcontextprotocol.io/specification/2025-11-25/changelog>
  - 2026-07-28 の stdio 規定・`basic/index`（`_meta` の規則）・`server/discover`・`basic/patterns/mrtr`・schema の詳細ページは本ドラフトの作成時点では本文を精読しておらず、該当する箇所は「要確認」と記す

## 1. 背景

- 2026-07-28 の changelog の比較元は 2025-11-25 であり、現行の 2025-06-18 からは **2 段**（2025-06-18 -> 2025-11-25 -> 2026-07-28）の差分を数える必要がある
- 2026-07-28 の中心は SEP-2575 によるステートレス化（`initialize` 廃止、要求ごとの `_meta`）である。仕様は legacy（`initialize` あり、2025-11-25 以前）と modern（2026-07-28 以降）を定義し、両方を受ける dual-era サーバーを許す（MAY）
- 本リポの plugin-mcp は stdio と UDS（改行区切りの暫定契約・PLUG-12）だけで、HTTP は持たない

## 2. 現状（main `cc03cf7c` 時点）

- `crates/plugin-mcp/src/server.rs`: `PROTOCOL_VERSION = "2025-06-18"`、`MAX_LINE_BYTES = 1 MiB`。`handle_message_with` は 1 行ごとの関数で接続状態を持たない（すでに実質ステートレス）。扱うメソッドは `initialize`・`tools/list`・`ping`・`tools/call` の 4 つ。通知は黙殺し、バッチ配列は拒否し、クライアントからの応答は無視する（サーバーから要求を送らない）
- `initialize` は `initialize_params_valid` で `protocolVersion`・`capabilities`・`clientInfo` を検証し、要求された版にかかわらず常に `2025-06-18` を返す。capabilities は `tools.listChanged: false`
- `tools/list` は 2 ツールを固定順で返す。`nextCursor`・`ttlMs`・`cacheScope` は無い。`tools/call` は `structuredContent` と `content` を返し、業務エラーは `isError: true`
- `error.rs`: JSON-RPC コードは -32700・-32600・-32601・-32602・-32603。未知のツールと引数不正はどちらも -32602（`data.code = INVALID_ARGUMENT`。ERR-5・MCP-4 に沿う）
- 試験: `server.rs` 内の単体試験と `tests/startup.rs`・`tests/integration.rs` が `2025-06-18`・`ping`・`initialize` を具体値で照合している
- ログは stderr に 1 行 JSON で、入力値を反射させない（REPAIR-4）

## 3. 差分一覧

「リビジョン」は変更が入った版（11-25 は 2025-11-25、07-28 は 2026-07-28）。判断待ちの項目は 5 章に対応する。

| 変更 | SEP・リビジョン | 破壊的か | plugin-mcp への影響 | 実装の要否 | 対応方針 | 担当 |
| ---- | -------------- | -------- | ------------------- | ---------- | -------- | ---- |
| `initialize`・`notifications/initialized` の廃止、要求ごとの `_meta`（`io.modelcontextprotocol/protocolVersion`・`clientCapabilities`・`clientInfo`） | SEP-2575・07-28 | 破壊的 | `handle_message_with` の分岐に modern 経路を足す | 要 | `_meta` を型検査して取り出し、dual-era なら legacy 経路を残す（4.1） | #716 |
| `server/discover`（servers MUST） | SEP-2575・07-28 | 追加（MUST） | 新メソッド。対応版・capabilities・identity を返す | 要 | 対応版の一覧は定数で固定。結果の形は schema の `DiscoverResult` を要確認 | #716 |
| `UnsupportedProtocolVersionError`（コード -32022、`data.supported`・`data.requested`） | SEP-2575・07-28 | 追加 | `error.rs` に variant と ERR-1 の `data.code` 対応を足す | 要 | `supported` は固定一覧。`requested` を返すなら長さ上限つき（4.2） | #716 |
| `ping` の廃止 | SEP-2575・07-28 | 破壊的 | `ping` 分岐 | 要（dual-era なら legacy 側に残す） | modern 経路では -32601 とする | #716 |
| `logging/setLevel`・`notifications/roots/list_changed` の廃止 | SEP-2575・07-28 | 破壊的 | 未実装のため影響なし | 不要（未実装） | なし | 対象外 |
| 全 result に必須の `resultType: "complete"` | SEP-2322・07-28 | 破壊的（必須化） | `InitializeResult`・`ToolsListResult`・`tools/call` の結果 | 要 | modern の結果に付ける。legacy にも付けるか（4.3）。クライアントは欠落を `complete` と扱う（MUST） | #717 |
| MRTR（`InputRequiredResult`・`inputRequests`・`requestState`） | SEP-2322・07-28 | 追加 | 追加入力を求めないため該当なし | 不要（追加入力を求めない） | 4.4 | #717 の見直し |
| `tools/list` の `ttlMs`・`cacheScope` 必須化（`CacheableResult`） | SEP-2549・07-28 | 破壊的（必須化） | `ToolsListResult` | 要 | 固定値（例: 静的な一覧なので長い `ttlMs`・`cacheScope: "public"`）を決める。値は要確認 | 判断待ち（#716 に含めるか新規 issue） |
| `tools/list` を決まった順で返す（SHOULD） | 07-28 | なし | すでに固定順 | 不要（満たす） | 順序を固定する試験を足す | #719 |
| 結果の `_meta.io.modelcontextprotocol/serverInfo`（SHOULD） | SEP-2575・07-28 | なし | 結果の組み立て | 要（任意） | 名前と版を載せる | #716 |
| セッション・`Mcp-Session-Id`・SSE 再開の廃止 | SEP-2567・SEP-2575・07-28 | 破壊的（HTTP） | HTTP が無い | 不要（対象外） | HTTP を足すときに再評価 | 対象外 |
| `subscriptions/listen`（旧 `resources/subscribe` の置換） | SEP-2575・07-28 | 破壊的 | `listChanged: false` で購読を出さない | 不要（対象外） | なし | 対象外 |
| Streamable HTTP の `Mcp-Method`・`Mcp-Name` と `x-mcp-header` | SEP-2243・07-28 | 追加（HTTP のみ） | stdio / UDS に header layer が無い（stdio 側の規定は要確認） | 不要（現行トランスポートでは対象外） | 4.4 | #718 の見直し |
| tasks を拡張 `io.modelcontextprotocol/tasks` へ移動 | SEP-2663・07-28（導入は SEP-1686・11-25） | 破壊的 | tasks を実装していない | 不要（対象外） | なし | 対象外 |
| `ClientCapabilities`・`ServerCapabilities` の `extensions` | 07-28 | 追加 | 拡張を使わない | 不要 | なし | 対象外 |
| JSON Schema 2020-12 の既定化（11-25）と `inputSchema`・`outputSchema` の緩和（07-28） | SEP-1613・SEP-2106 | なし | 現スキーマが 2020-12 の範囲か | 要確認 | `$schema` を付けるか、現状で足りるかを確認 | #719 |
| 入力検証の誤りを Protocol Error ではなく Tool Execution Error（`isError`）で返す | SEP-1303・11-25 | 食い違い | 引数不正は現在 -32602 | 判断待ち | spec の ERR-5・MCP-4 と衝突するため spec 側へ報告（6 章） | spec 側 |
| ツール名の指針 | SEP-986・11-25 | なし | 現在の 2 ツール名が適合するか | 要確認 | 名前の文字種を確認 | #719 |
| `Implementation.description`・icons | 11-25 | 追加（任意） | `serverInfo` に載せられる | 不要（任意） | 載せない | 対象外 |
| エラーコードの割り当て方針（-32020〜-32099 は MCP 予約、-32000〜-32019 は実装定義） | 07-28 | なし | 独自に -32020 以降を使わない | 不要（遵守のみ） | `error.rs` の注記に残す | #716 |
| `notifications/cancelled` を受けたら処理を止める（SHOULD） | 07-28 stdio 規定 | なし | 現状は同期処理で黙殺 | 判断待ち | 要確認。同期処理のため実益が薄い | 判断待ち |
| サーバーは stdout に要求を書かない（MUST NOT） | 07-28 stdio 規定 | なし | すでに満たす | 不要（満たす） | 試験で固定してもよい | #719 |
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

推奨は案 A（根拠: MCP-1・MCP-2 の疎通を保ったまま追随でき、spec 側の変更が要らない）。状態は承認待ち。

### 4.2 `_meta` も版も無い要求の扱い

`initialize` を経ない要求で `_meta` に版が無い場合の扱いは、`basic/index` の規定を精読して決める（要確認）。対応版の一覧 `supported` は定数で固定する。`data.requested` に要求の文字列を返す場合は長さの上限を設ける。ログには要求された版や `clientInfo` を反射させない（REPAIR-4 を維持）。

### 4.3 legacy の応答にも `resultType` を付けるか

legacy の版の schema が知らないフィールドを足すと、厳格なクライアントが拒否しうる。一方 modern のクライアントは欠落を `complete` と扱う（MUST）ため、legacy 側は付けない案が安全。推奨は「legacy に付けない」。承認待ち。

### 4.4 #717・#718 の受け入れ条件の見直し

- #717（マルチラウンドトリップ）: 本サーバーはクライアントへ追加入力を求めないので `InputRequiredResult` は対象外。必要なのは全 result への `resultType: "complete"` のみ。受け入れ条件（ハンドシェイクが仕様どおりに完了する）は対象が無くなるため、#720 で見直しを諮る
- #718（ヘッダーベースルーティング）: SEP-2243 は Streamable HTTP の規定で、現行の stdio / UDS には header layer が無い。現行トランスポートでは対象外で、HTTP を足すときにだけ必要になる。「対象外として閉じる」か「メソッド名での振り分けに言い換える」かを #720 に諮る（本 issue では #718 を書き換えない）

## 5. 決定表

| # | 項目 | 推奨 | 状態 | 決定者 |
| - | ---- | ---- | ---- | ------ |
| D1 | dual-era か modern 単独か | 案 A（dual-era） | 承認待ち | #720 |
| D2 | 版の無い要求の扱いと `data.requested` の上限 | 規定に従う。上限を設ける | 承認待ち | #720 |
| D3 | legacy の応答への `resultType` | 付けない | 承認待ち | #720 |
| D4 | #717 の受け入れ条件 | `resultType` のみに縮小 | 承認待ち | #720 |
| D5 | #718 の扱い | 対象外として閉じる | 承認待ち | #720 |
| D6 | `ttlMs`・`cacheScope` の担当 | #716 に含める | 承認待ち | #720 |
| D7 | `notifications/cancelled` | 当面は黙殺のまま | 承認待ち | #720 |

## 6. spec 側へ報告する事項（本リポでは直さない）

- (a) SEP-1303（引数不正を `isError` で返す）と ERR-5・MCP-4（-32602）の規定の衝突
- (b) ERR-5 の表に -32022 と予約範囲（-32020〜-32099）が無く、ERR-1 の `data.code` の対応も無い
- (c) 案 B を採る場合の MCP-1 の文言の改訂
- (d) api-mcp.md の「`tools/call` のレスポンス形は MCP-3 で見直す可能性」への回答

## 7. 却下案

- 2025-06-18 のままにする: MCP-3 の要求に反する
- HTTP トランスポートを同時に足す: 範囲が広がり、認可・Origin 検査・ネットワーク公開の設計が要る。本追随には不要
- MCP の SDK crate を導入する: フルスクラッチ方針と依存方針（dependency-policy）に反し、不要

## 8. 実装 issue の対応表

| issue | 範囲 |
| ----- | ---- |
| #716 ステートレスコア | `_meta` の版検証、`server/discover`、-32022、`ping` の扱い、`serverInfo`、（D6 次第で）`ttlMs`・`cacheScope` |
| #717 マルチラウンドトリップ | `resultType: "complete"`（D4 次第で縮小） |
| #718 ヘッダーベースルーティング | 現行は対象外（D5） |
| #719 試験 | `tests/protocol_2026_07_28.rs`。順序の固定、スキーマ・ツール名の確認、MCP-1・MCP-2 の疎通の維持 |
| 新しい issue が要る | `notifications/cancelled`（D7）。起票の要否は #720 で判断 |

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
