# CRI ストリーミングサーバー基盤と URL 発行

CRI の `Exec`・`Attach`・`PortForward` は、RPC 自体ではデータを流さず「ストリーミングサーバーの URL」を返す。kubelet / apiserver はその URL へ HTTP（SPDY/3.1 の Upgrade）で接続して入出力をやり取りする。本書は、その土台（HTTP サーバーの起動・URL 発行・トークンの失効）の設計記録である（CRI-6・TASK-63.1・#679。依存の承認は #678）。

実装は `crates/cri/src/streaming.rs`。結合試験は `crates/cri/tests/streaming_server.rs`。

## スコープ

| 項目 | 本書の範囲 | 担当 |
| ---- | ---------- | ---- |
| HTTP/1.1 サーバーの起動・ルーティング・接続の上限と期限 | 実装済み | #679 |
| URL の発行（一意・単回使用・TTL つき） | 実装済み | #679 |
| 3 RPC の入力検証と存在照合 | 浅い検証まで実装済み | #679 |
| Exec の SPDY/3.1・Upgrade 後のストリーム | 未実装（501 を返す） | #680（TASK-63.2） |
| Attach | 未実装 | #681（TASK-63.3） |
| PortForward（Upgrade・SPDY/3.1・error / data の対・転送先との中継） | 実装済み（転送先への接続は `PortForwardDialer` の注入。本番 dialer と plugin-cri への注入は未実装） | #682（TASK-63.4）。本番 dialer は後続の issue |
| SPDY/3.1 の共通層（フレーム・辞書つきヘッダブロック） | 実装済み（`streaming/spdy.rs`。フロー制御なし） | #682 |
| plugin-cri からのサーバー起動と `with_streaming` での注入 | 未実装（注入が無い間は従来どおり `UNIMPLEMENTED`） | 後続の issue |

## バインドの方針

- 既定は `127.0.0.1:0`（loopback、OS が空きポートを選ぶ）。外部への公開は `StreamingConfig::allow_external` を明示したときだけで、`0.0.0.0`・`::` も外部として扱う。違反は起動時に `INVALID_ARGUMENT`（fail-closed）
- 発行 URL の host は `StreamingConfig::advertise_addr`（IP）を使い、ポートは実際の待ち受けポートにする。未指定なら bind したアドレスを使う。`0.0.0.0`・`::` で bind するときは kubelet から到達できない URL になるため広告アドレスを必須とし、無ければ（または広告アドレスが未指定アドレス・マルチキャストなら）起動時に `INVALID_ARGUMENT`（fail-closed）
- 外部へ公開するときは TLS も認証も無い。URL を知ることが唯一の認可なので、前段のネットワーク制御で守ること
- UDS での待ち受けは扱わない。kubelet は返された `http://` の URL へ接続するため、UDS の URL を kubelet が使える根拠の一次情報が無い（未確認・後続）

## トークン

| 項目 | 値 |
| ---- | -- |
| 乱数源 | unix は `/dev/urandom`（文字デバイスであることを確認）。非 unix は `UNAVAILABLE`（弱い代替を作らない） |
| 表現 | 32 バイトを小文字 hex 64 文字 |
| 有効期間 | 既定 60 秒（kubelet のトークンキャッシュの TTL に合わせる）。上限 600 秒、0 は拒否 |
| 使用回数 | 単回。種別違い・期限切れで照合に失敗しても取り除く |
| 保持件数 | 既定 1000（`RESOURCE_EXHAUSTED`）。発行時に期限切れを掃除する |
| 保存するもの | 発行時の要求そのもの。URL から要求を組み立て直さない（改ざんを受けない） |

トークンはログ・エラー・`Debug` に出さない。

## 期限と上限（REPAIR-5）

| 項目 | 既定 |
| ---- | ---- |
| HTTP ヘッダの読み取り | 10 秒 |
| Upgrade しない要求の接続全体 | ヘッダ読み取りの 3 倍 |
| 同時接続数 | 64（超えた接続は即座に閉じる） |
| 読み取りバッファ | 16 KiB |
| パスの長さ | 256 バイト |

Upgrade 後の idle の期限は #680〜#682 が決める。接続は 1 要求ごとに閉じる（keep-alive 無し）。

## ルーティング

- メソッドは GET / POST のみ（それ以外は 405）
- `/exec/{token}`・`/attach/{token}`・`/portforward/{token}` 以外は 404。トークンは小文字 hex の 64 文字以外を照合の前に 404 にする
- 未知・失効・使用済み・種別違いはすべて同じ 404 にする（区別すると探索の手がかりになる）
- 有効なトークンの要求は `StreamHandler` に渡す。既定の `NotImplementedHandler` は 501

## #680〜#682 に残るもの

- Exec・Attach の Upgrade 後のストリーム（SPDY/3.1 のフレーム層と zlib 辞書は #682 の `spdy` モジュールを使う）
- `container` が running か、tty と stderr の組み合わせ、ポートの到達性など深い意味検証
- WebSocket: kubelet / apiserver 側で WebSocket を SPDY に変換する仕組みの一次情報は #678 で未確認のまま。#680 の着手前に確かめる

## PortForward（#682・TASK-63.4・CRI-6）

- Upgrade 前の照合: `Connection: Upgrade`・`Upgrade: SPDY/3.1`・`X-Stream-Protocol-Version: portforward.k8s.io` のすべてが揃わなければ 400（Upgrade しない）。101 応答に同じ 3 ヘッダを載せる。WebSocket は未対応
- ストリームの対: クライアントが `streamtype`（error / data）・`port`・`requestid` のヘッダ付きで SYN_STREAM を送る。受けるたびに SYN_REPLY を返し、同じ `requestid` の error と data が揃ったら転送先へ接続する。クライアント起点の ID は奇数のみ
- 拒否（RST_STREAM の REFUSED_STREAM）: 不正な `streamtype`・`port`（10 進の数字のみ・1..=65535）・`requestid`（空・64 バイト超）、保存済み要求の `port` 一覧が非空でそれに無いポート、同時ストリーム数の超過、同じ対への重複
- 転送: data の DATA は TCP へ書き、FIN で TCP の書き込み側を shutdown する。TCP の EOF は DATA の FIN にし、両方向が閉じたら error ストリームも FIN で閉じる。接続失敗は error ストリームへ固定の英文（`error forwarding port <port>: connection failed`）を書いて両ストリームを FIN で閉じる
- PING は同じ ID で返す。SETTINGS・WINDOW_UPDATE・HEADERS は読み飛ばし、フロー制御は持たない（kubelet の SPDY 実装も窓を強制しない前提。実クライアントでの確認は #683）。GOAWAY・切断で終了する
- 転送先への接続は `PortForwardDialer`（`pod_sandbox_id` と `port` で `std::net::TcpStream` を返す）に切り出す。cri は名前空間の具象を知らず、既定でホストの loopback へつなぐ実装を置かない。本番の dialer（NODE ネットワークの pod と、pod の netns へ入って接続する POD ネットワークの pod）と plugin-cri でのサーバー起動・ハンドラ注入は後続の issue

| 項目 | 既定値 | 設定 |
| ---- | ------ | ---- |
| 転送先への接続の期限 | 10 秒 | `PortForwardConfig::dial_timeout` |
| 対が揃うまでの期限 | 30 秒（kubelet の stream creation timeout 相当） | `pair_timeout` |
| Upgrade 後の idle の期限 | 4 時間（kubelet の stream idle timeout 相当） | `idle_timeout` |
| 同時ストリーム数 | 128 | `max_streams` |
| 受けるフレーム本体の最大長 | 1 MiB | `max_frame_bytes` |
| 1 対の書き込み滞留・送信キューの上限 | 256 KiB（超えると読み取りを止める） | `max_pending_bytes` |

- ヘッダブロックの上限: 展開後 64 KiB・64 件・名前と値は各 8 KiB。超えたら GOAWAY(PROTOCOL_ERROR) で切断する
- SPDY/3 の zlib 辞書（1423 バイト）は SPDY Protocol Draft 3 の 2.6.10.1 節（<https://datatracker.ietf.org/doc/html/draft-mbelshe-httpbis-spdy-00#section-2.6.10.1>）を一次情報にして作り、実装コードからは写していない。長さと Adler-32（`0xe3c6a7c2`）を試験で固定している。帰属表示の要否は PR でユーザー確認に残す（licensing.md「非 Cargo 資産」）
- 観測: セッションの終了理由（`PortForwardEnd`）を `PortForwardObserver` に渡す。ポート・トークン・アドレスは載せない

## 依存

`hyper =1.12.0`（`server`/`http1`）・`hyper-util =0.1.21`（`tokio`）・`tokio` の `net`/`time` を crates/cri に追加した（承認 #678）。いずれも `Cargo.lock` に既存で、新しいパッケージは増えない。`http-body-util`・`bytes`・`http` は直接依存にせず、`hyper` の再 export と自前の小さな本体型（`StreamBody`）で足りる範囲に留めた。

`flate2`（`=1.1.10`・`zlib-rs`。承認 #678）を crates/cri から参照する（SPDY/3.1 のヘッダブロックの辞書つき zlib。#682）。workspace 既存の固定版で新しいパッケージは増えない。tokio の feature は追加していない（`sync`・`io-util`・`macros` が無いため、Upgrade 後の中継は 1 タスクの `poll_fn` 状態機械で書いた）。
