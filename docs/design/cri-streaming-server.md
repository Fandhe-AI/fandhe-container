# CRI ストリーミングサーバー基盤と URL 発行

CRI の `Exec`・`Attach`・`PortForward` は、RPC 自体ではデータを流さず「ストリーミングサーバーの URL」を返す。kubelet / apiserver はその URL へ HTTP（SPDY/3.1 の Upgrade）で接続して入出力をやり取りする。本書は、その土台（HTTP サーバーの起動・URL 発行・トークンの失効）の設計記録である（CRI-6・TASK-63.1・#679。依存の承認は #678）。

実装は `crates/cri/src/streaming.rs`（SPDY は `streaming/spdy.rs`・`streaming/remotecommand.rs`、Attach は `streaming/attach.rs`、Exec は `streaming/exec.rs`）。結合試験は `crates/cri/tests/streaming_server.rs`・`streaming_attach.rs`・`streaming_exec.rs`。

## スコープ

| 項目 | 本書の範囲 | 担当 |
| ---- | ---------- | ---- |
| HTTP/1.1 サーバーの起動・ルーティング・接続の上限と期限 | 実装済み | #679 |
| URL の発行（一意・単回使用・TTL つき） | 実装済み | #679 |
| 3 RPC の入力検証と存在照合 | 浅い検証まで実装済み | #679 |
| Exec の SPDY/3.1・Upgrade 後のストリーム | 実装済み（`ExecStreamHandler`。#681 の codec・交渉・`SessionLimits` を再利用。起動役の本番の実装は未実装で、注入が無ければ 501） | #680（TASK-63.2） |
| Attach の SPDY/3.1・remotecommand・Upgrade 後のセッション | 実装済み（fake backend での結合試験）。本番の backend は未接続（注入が無ければ 501） | #681（TASK-63.3） |
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

Upgrade 後の期限（`StreamingConfig::stream_creation_timeout` 既定 30 秒・`stream_idle_timeout` 既定 4 時間。いずれも kubelet の既定。上限は 5 分・24 時間、0 は拒否）は下の「Attach」に記す。接続は 1 要求ごとに閉じる（keep-alive 無し）。

## ルーティング

- メソッドは GET / POST のみ（それ以外は 405）
- `/exec/{token}`・`/attach/{token}`・`/portforward/{token}` 以外は 404。トークンは小文字 hex の 64 文字以外を照合の前に 404 にする
- 未知・失効・使用済み・種別違いはすべて同じ 404 にする（区別すると探索の手がかりになる）
- 有効なトークンの要求は `StreamHandler` に渡す。既定の `NotImplementedHandler` は 501

## Attach（TASK-63.3・#681）

### 構成

| ファイル | 役割 |
| -------- | ---- |
| `streaming/spdy.rs` | SPDY/3.1 のフレーム codec。型付きの `Frame`・31 ビットの `StreamId`・辞書つき zlib のヘッダブロック。Exec（`exec.rs`）・PortForward も再利用する |
| `streaming/spdy_dictionary.rs` | SPDY/3 の辞書 1423 バイト。出典は `NOTICE`（moby/spdystream）。Adler-32 を draft の辞書 ID（`0xe3c6a7c2`）と照合する試験がある |
| `streaming/remotecommand.rs` | `*.channel.k8s.io` の交渉（v4・v3・v2）・`streamtype` の割り当て・`metav1.Status` の JSON・resize の JSON・`SessionLimits` |
| `streaming/attach.rs` | `AttachHandler`（`StreamHandler`）・`AttachBackend`（注入点）・1 接続 1 タスクのセッション |
| `streaming.rs` の `StreamDispatcher` | 種別ごとのハンドラの振り分け。未設定の種別は 501。#680・#682 は同じ型へ足す |

### 交渉と流れ

1. トークン照合の後、`X-Stream-Protocol-Version`（無ければ 400）から、クライアントの提示順で最初に対応する版を選ぶ（合う版が無ければ 403 と `X-Accepted-Stream-Protocol-Versions`）。次に `Connection: Upgrade` と `Upgrade: SPDY/3.1` を確認する（無ければ 400）。kubelet の `Handshake` → `UpgradeResponse` の順
2. 101 でエコーして Upgrade。IO を受けたタスクが `ConnectionPermit` を寿命まで持つ（接続数の上限を守る）
3. クライアントが SYN_STREAM で error・stdin・stdout・stderr（tty では resize）を `streamtype` つきで開く。サーバーは開いたものから SYN_REPLY を返す。重複は RST_STREAM(STREAM_IN_USE)、未知の種別・要求していない種別・ストリーム数超過は RST_STREAM(REFUSED_STREAM)、偶数または減少する ID は RST_STREAM(PROTOCOL_ERROR)
4. 要求した種別が揃ったら `AttachBackend::attach`（期限 10 秒）を呼ぶ。失敗は error ストリームの Failure Status
5. 中継。backend の stdout / stderr → DATA、DATA(stdin) → backend の stdin、FIN(stdin) → backend の stdin を shutdown、resize の JSON → backend の resize
6. コンテナの終了で残りの出力を最大 5 秒流し、error ストリームへ Status（v4 は JSON の Success。v3・v2 は成功時に何も書かない）、未送の FIN、GOAWAY を送る（最大 5 秒）。どの終了でも backend の stdio・終了通知を drop して資源を解放する

### 意図的な逸脱: flow control を強制しない

SPDY/3.1 は窓（既定 64 KiB）を超える DATA の送信を禁じる。しかし client-go が使う moby/spdystream は flow control を実装せず（`WINDOW_UPDATE` を送らず、受けても "unhandled frame type" として捨てる。commit c59e5d73 の `connection.go` で確認）、窓を強制すると 64 KiB を送った時点で永久に止まる。そのため WINDOW_UPDATE・SETTINGS は受理して無視し、送信を窓で止めない。滞留はセッションの出力バッファ（128 KiB で backend の読み取りを止める）と stdin の滞留（128 KiB でクライアントの読み取りを止める）で有界にする。試験 `cri6_attach_flow_control_large_output` が 256 KiB の出力が WINDOW_UPDATE 無しで届くことを固定している。flow control を守る SPDY/3.1 クライアントは対象外（kubelet / crictl / kubectl は対象）。

### 上限（外部入力）

| 項目 | 値 |
| ---- | -- |
| 受信フレームのペイロード | 256 KiB（確保の前に検査） |
| ヘッダブロックの展開後 | 16 KiB（zlib bomb は上限で拒否）。ヘッダ 64 組まで |
| ストリーム | 5 本まで。同一種別は 1 本 |
| 送信 DATA 1 フレーム | 32 KiB |
| resize の JSON の滞留 | 4 KiB |
| 期限 | ストリーム作成 30 秒・backend 接続 10 秒・idle 4 時間・終了後の流し切り 5 秒・最後の送出 5 秒 |

違反は GOAWAY(PROTOCOL_ERROR) で閉じ、部分的に解釈して続行しない。Status の message はコード別の固定の英語で、コンテナ ID・内部のパスを含めない。

### tty と stderr

CRI の定義は tty のとき stderr を false に固定する。RPC（`validate_attach_request`）は守らない要求を `INVALID_ARGUMENT` にする。接続時のハンドラは kubelet の `NewOptions` に合わせ、tty の stderr を要求していないものとして扱う。RPC はさらに running でないコンテナを `FAILED_PRECONDITION`、未知を `NOT_FOUND` にする。接続時にも backend が再確認する。

### Attach の本番 backend（未実装・REPAIR-3）

実行中コンテナの stdin / stdout / stderr と tty を渡す経路は、core の `ContainerRuntime` にも supervisor にも無い（CreateContainer の `stdin`・`stdin_once`・`tty` の bundle への反映もまだ）。`ContainerRuntime` トレイトの拡張か supervisor の新しい経路かは PLUG-1・SUP 系の設計判断（main の設計が要る）であり、本 issue では注入点（`AttachBackend`）までとした。判断材料として、supervisor のログの sink は stdout / stderr を読んでいるため読み側だけは供給できる可能性があるが、stdin の経路と tty は無く、断定していない。plugin-cri からの `StreamingServer` の起動と `StreamDispatcher` / `AttachHandler` の組み立てもこれと同じ後続の issue。

## Exec（#680・TASK-63.2・CRI-6）

`ExecStreamHandler`（`StreamHandler` の実装）を `StreamDispatcher::with_exec` で登録する（単独なら `bind_with_handler` に直接渡してもよい。Exec 以外の種別は 501）。SPDY の codec・交渉・status・resize の解析・期限（`SessionLimits`）は Attach と共通の `spdy.rs`・`remotecommand.rs` を使い、`exec.rs` に残るのは Exec 固有の部分（起動役 `ExecStreamLauncher`・プロセスの終了コードから Status への変換・stdin の stall 期限）だけである。

- 交渉・ストリーム割り当ては Attach と同じ（v4・v3・v2。resize は v3 以降）。受け付ける組は発行時に保存した `ExecRequest` から決める（`StreamOptions::expected`）
- 終了の通知: v4 は error ストリームに `metav1.Status` の JSON。成功は `{"metadata":{},"status":"Success"}`、非 0 は `reason: NonZeroExitCode` と `details.causes: [{"reason":"ExitCode","message":"<code>"}]`。v3・v2 は成功時に何も書かず、非 0 は `command terminated with exit code <code>` のテキスト（kubelet と同じ）。起動失敗・待ち失敗は `InternalError` の固定文で、内部のパス・エラー文は載せない。続けて未 FIN の出力に FIN、GOAWAY を送り閉じる
- フロー制御は Attach と同じく強制しない（「意図的な逸脱」）。送信キュー 1 MiB の上限と、stdin をプロセスへ書き終えるまで次のフレームを読まないことで背圧を TCP に任せる。試験 `cri6_exec_large_stdin_roundtrip_beyond_window` が 256 KiB の往復を固定する
- 期限（REPAIR-5）: `SessionLimits`（作成 30 秒・idle 4 時間・流し切り 5 秒・最後の送出 5 秒）に加え、Exec 固有の `launch_timeout`（既定 30 秒）と `stdin_stall_timeout`（既定 60 秒。溜めた stdin をプロセスが読まないとき、ソケットを読めず切断を検知できない時間の上限）
- 受信バッファが上限を超えた場合は EOF と区別して `ProtocolError`（GOAWAY）で閉じる

### 注入トレイト `ExecStreamLauncher`

core の `ContainerRuntime` に exec は無く、shim v2 の `TaskExecLauncher` は stdio を持たない（containerd の FIFO 前提）。そこで stdio を持つ起動役を `crates/cri` の注入トレイトとして定義した（`ContainerRuntime` は変えない。PLUG-1）。`ExecLaunch` には発行時に保存した要求から作った値だけを入れ、通信路の内容から cmd を組み立てない。契約は、要求された stdio だけを返す・`ExecSession` の drop でプロセスを止める・コンテナの namespace / cgroup / seccomp / capability を継承して広げない（SEC-1）・panic しない。**本番の実装は無い（REPAIR-3）**。supervisor の exec 入口（pidfd 経由）へ stdio のパイプと pty を付ける橋渡しは後続の issue。

## #682 ほかに残るもの

- PortForward のハンドラ本体（SPDY の codec・`StreamDispatcher` は再利用する）
- `ExecStreamLauncher` の本番の実装と plugin-cri からの `StreamingServer` の起動・注入
- ポートの到達性など深い意味検証
- WebSocket（`v5.channel.k8s.io` 等）: kubelet / apiserver 側で WebSocket を SPDY に変換する仕組みの一次情報は #678 で未確認のまま。必要になった時点で別途判断する
- kubelet / crictl の実クライアントでの照合（#683 の実機前提試験）

## 依存

`flate2`（zlib-rs backend。SPDY のヘッダブロックの辞書つき zlib。#681 で crates/cri の直接依存にした。承認は #678 のオーナー判断で、新しいパッケージは増えない）。`hyper =1.12.0`（`server`/`http1`）・`hyper-util =0.1.21`（`tokio`）・`tokio` の `net`/`time` を crates/cri に追加した（承認 #678）。いずれも `Cargo.lock` に既存で、新しいパッケージは増えない。`http-body-util`・`bytes`・`http` は直接依存にせず、`hyper` の再 export と自前の小さな本体型（`StreamBody`）で足りる範囲に留めた。
