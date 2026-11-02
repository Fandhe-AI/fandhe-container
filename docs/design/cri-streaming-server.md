# CRI ストリーミングサーバー基盤と URL 発行

CRI の `Exec`・`Attach`・`PortForward` は、RPC 自体ではデータを流さず「ストリーミングサーバーの URL」を返す。kubelet / apiserver はその URL へ HTTP（SPDY/3.1 の Upgrade）で接続して入出力をやり取りする。本書は、その土台（HTTP サーバーの起動・URL 発行・トークンの失効）の設計記録である（CRI-6・TASK-63.1・#679。依存の承認は #678）。

実装は `crates/cri/src/streaming.rs`（Exec は `streaming/exec.rs`、SPDY/3.1 のコーデックは `streaming/spdy.rs`）。結合試験は `crates/cri/tests/streaming_server.rs`・`crates/cri/tests/streaming_exec.rs`。

## スコープ

| 項目 | 本書の範囲 | 担当 |
| ---- | ---------- | ---- |
| HTTP/1.1 サーバーの起動・ルーティング・接続の上限と期限 | 実装済み | #679 |
| URL の発行（一意・単回使用・TTL つき） | 実装済み | #679 |
| 3 RPC の入力検証と存在照合 | 浅い検証まで実装済み | #679 |
| Exec の SPDY/3.1・Upgrade 後のストリーム | 実装済み（`ExecStreamHandler`。起動役の本番の実装は未実装） | #680（TASK-63.2） |
| Attach | 未実装 | #681（TASK-63.3） |
| PortForward | 未実装 | #682（TASK-63.4） |
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

## Exec（#680・TASK-63.2・CRI-6）

`ExecStreamHandler`（`StreamHandler` の実装）を `StreamingServer::bind_with_handler` に渡す。`Exec` 以外の種別は `fallback`（既定 501）へ渡すので、#681・#682 は handler を連ねるだけで済む。

### プロトコル（kubernetes v1.34 の kubelet / apimachinery と moby/spdystream で確認。v1.37.1 での再確認は PR 本文）

- 交渉: `X-Stream-Protocol-Version` をクライアントの並び順に見て最初に `v4.channel.k8s.io` に一致した時点で採用し、応答ヘッダで返す。一致しなければ 403、`Connection: Upgrade` / `Upgrade: SPDY/3.1` が無ければ 400。サーバー側の SPDY に v5 は無い（v5 は WebSocket 用）。v1〜v3 は受けない
- ストリーム: SYN_STREAM のヘッダ `streamtype`（小文字で比較）で `error`・`stdin`・`stdout`・`stderr`・`resize` を見分ける。受け付ける組は発行時に保存した `ExecRequest` から決める（error ＋ 要求された stdio ＋ tty なら resize）。想定外・重複・偶数 ID・単調増加でない ID は RST_STREAM で拒否し、接続は閉じない
- 終了の通知: error ストリームへ `metav1.Status` の JSON を書く。成功は `{"metadata":{},"status":"Success"}`、非 0 は `reason: NonZeroExitCode` と `details.causes: [{"reason":"ExitCode","message":"<code>"}]`。起動失敗・待ち失敗は `reason: InternalError`・`code: 500` の固定文で、内部のパス・エラー文は載せない。続けて未 FIN の出力に FIN、GOAWAY を送り閉じる
- resize: `{"Width":u16,"Height":u16}` を改行区切りで解析する。1 行 1 KiB まで、不正・0・範囲外は捨てる

### フロー制御を採らない判断

moby/spdystream は WINDOW_UPDATE を送らず、受けても無視する（未処理のフレームは debug ログだけ）。窓に従うと Go のクライアントと 64 KiB で詰まるため、こちらも送信窓には従わない。代わりに送信キューの上限（1 MiB）と、stdin をプロセスへ書き終えるまで次のフレームを読まないことで背圧を TCP に任せる。受信した WINDOW_UPDATE・SETTINGS・HEADERS は読み捨てる。試験 `cri6_exec_large_stdin_roundtrip_beyond_window` が 256 KiB の往復で回帰を見る。

### 期限と上限（REPAIR-5）

| 項目 | 既定 | 備考 |
| ---- | ---- | ---- |
| `stream_creation_timeout` | 30 秒 | 揃わなければ launcher を呼ばずに GOAWAY で閉じる |
| `launch_timeout` | 30 秒 | |
| `idle_timeout` | 4 時間 | 上限 24 時間。DATA の送受信で延びる（PING では延びない） |
| `drain_timeout` | 10 秒 | 終了後に stdout / stderr を EOF まで送り切る期限 |
| 制御フレームの長さ | 16 KiB | 確保の前に検査 |
| DATA の長さ | 256 KiB | 同上 |
| ヘッダ | 32 個・名前と値は各 4 KiB・展開後 64 KiB | zlib bomb 対策。展開は途中で打ち切る |

### 注入トレイト `ExecStreamLauncher`

core の `ContainerRuntime` に exec は無く、shim v2 の `TaskExecLauncher` は stdio を持たない（containerd の FIFO 前提）。そこで stdio を持つ起動役を `crates/cri` の注入トレイトとして定義した（`ContainerRuntime` は変えない。PLUG-1）。`ExecLaunch` には発行時に保存した要求から作った値だけを入れ、通信路の内容から cmd を組み立てない。契約は、要求された stdio だけを返す・`ExecSession` の drop でプロセスを止める・コンテナの namespace / cgroup / seccomp / capability を継承して広げない（SEC-1）・panic しない。**本番の実装は無い（REPAIR-3）**。supervisor の exec 入口（pidfd 経由）へ stdio のパイプと pty を付ける橋渡しは後続の issue。

### zlib 辞書の出典

SPDY Protocol Draft 3（draft-mbelshe-httpbis-spdy-00）§2.6.10.1 の `SPDY_dictionary_txt`（1423 バイト）を IETF 掲載のテキストから機械的に起こした。長さと Adler-32（0xe3c6a7c2）は試験で照合する。定義元は IETF Internet-Draft（プロトコルの相互運用に必須の固定バイト列）で、出典は `crates/cri/src/streaming/spdy.rs` の先頭 doc に記載した。一次情報（<https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt>、2026-11-02 に取得）の確認結果: Copyright Notice は「Copyright (c) 2012 IETF Trust and the persons identified as the document authors」で IETF Trust の Legal Provisions（BCP 78）に従い、「Code Components extracted from this document must include Simplified BSD License text as described in Section 4.e of the Trust Legal Provisions」と記す。文書に NOTICE に当たるものは無く、ルート `NOTICE` は変更していない。辞書が Code Components に当たるか・Simplified BSD のライセンス文の同梱方法は Agent が決めず、オーナー判断が必要な事項として PR 本文で報告する（licensing.md）。判断が出るまで承認済みとは扱わない。

### 未確認

- WebSocket（`v5.channel.k8s.io`）: apiserver が WebSocket を SPDY に変換して CRI のストリーミングサーバーへ流すかは未確認。本 issue では実装しない
- 辞書のバイト列が実クライアント（kubectl / crictl）で通ることの最終確認は #683（TASK-63.5）

## #681・#682 に残るもの

- Attach（#681）: 握手・status JSON・resize の解析・ストリーム待ちを `exec.rs` から共通化する。`validate_attach_request` への tty と stderr の併用拒否もここ
- PortForward（#682）
- `container` が running か、ポートの到達性など深い意味検証
- `ExecStreamLauncher` の本番の実装と plugin-cri からの `StreamingServer` の起動・注入

## 依存

`flate2 =1.1.10`（`zlib-rs`。SPDY/3.1 ヘッダの zlib 辞書。承認 #678・#406。#680 で crates/cri に追加。新しいパッケージは増えない）。
`hyper =1.12.0`（`server`/`http1`）・`hyper-util =0.1.21`（`tokio`）・`tokio` の `net`/`time` を crates/cri に追加した（承認 #678）。いずれも `Cargo.lock` に既存で、新しいパッケージは増えない。`http-body-util`・`bytes`・`http` は直接依存にせず、`hyper` の再 export と自前の小さな本体型（`StreamBody`）で足りる範囲に留めた。
