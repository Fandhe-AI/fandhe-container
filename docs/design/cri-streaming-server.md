# CRI ストリーミングサーバー基盤と URL 発行

CRI の `Exec`・`Attach`・`PortForward` は、RPC 自体ではデータを流さず「ストリーミングサーバーの URL」を返す。kubelet / apiserver はその URL へ HTTP（SPDY/3.1 の Upgrade）で接続して入出力をやり取りする。本書は、その土台（HTTP サーバーの起動・URL 発行・トークンの失効）の設計記録である（CRI-6・TASK-63.1・#679。依存の承認は #678）。本番 backend の設計（#3752）も「本番 backend の設計」の節に含める。

実装は `crates/cri/src/streaming.rs`（SPDY は `streaming/spdy.rs`・`streaming/remotecommand.rs`、Attach は `streaming/attach.rs`、Exec は `streaming/exec.rs`）。結合試験は `crates/cri/tests/streaming_server.rs`・`streaming_attach.rs`・`streaming_exec.rs`。

## スコープ

| 項目 | 本書の範囲 | 担当 |
| ---- | ---------- | ---- |
| HTTP/1.1 サーバーの起動・ルーティング・接続の上限と期限 | 実装済み | #679 |
| URL の発行（一意・単回使用・TTL つき） | 実装済み | #679 |
| 3 RPC の入力検証と存在照合 | 浅い検証まで実装済み | #679 |
| Exec の SPDY/3.1・Upgrade 後のストリーム | 実装済み（`ExecStreamHandler`。#681 の codec・交渉・`SessionLimits` を再利用。本番の起動役は plugin-cri の `SupervisorExecLauncher` で結線済み〔Linux のみ。stdin・stdout・stderr のみで、tty と相対 argv[0] は RPC 時に `INVALID_ARGUMENT`、非 Linux は未結線の `UNIMPLEMENTED`〕。注入が無ければ Exec は結線済みと答えず、RPC は `UNIMPLEMENTED`） | #680（TASK-63.2）・#3761 |
| Attach の SPDY/3.1・remotecommand・Upgrade 後のセッション | 実装済み（fake backend での結合試験）。本番の backend は読み取り専用〔`LogFollowAttachBackend`。回転ログの follow〕で結線済み。非 Linux ではこの読み取り専用が本番で、stdin・tty は RPC 時と接続時に `INVALID_ARGUMENT`。Linux の本番は完全版（#4077・#4078）。backend が無ければ Attach は結線済みと答えず、RPC は `UNIMPLEMENTED`） | #681（TASK-63.3）・#3763 |
| PortForward | `PortForwardHandler` は実装済み。NODE の dialer で結線済み。POD は RPC 時と dialer の両方で `UNIMPLEMENTED` | #682（TASK-63.4）・#3755 |
| plugin-cri からのサーバー起動と `with_streaming` での注入 | 実装済み（loopback で起動し `StreamDispatcher` で注入。結線済みは PortForward〔NODE のみ。#3755〕・Attach〔読み取り専用。#3763〕・Exec〔Linux のみ。#3761〕。非 Linux の Exec は「not wired」の `UNIMPLEMENTED`） | #3754 |
| 本番 backend（Exec の helper・Attach・PortForward の dialer） | PortForward の NODE の dialer は実装済み（#3755）。Exec の stream-exec helper は実装済み（#3760）、plugin-cri 側の本番 launcher と結線も実装済み（#3761。tty は本番で fail-closed）。Attach は段階 1（読み取り専用）が実装済み（#3763）で、完全版も Linux で実装済み（#4077・#4078）で、実機前提試験 `production_binary_attach_real` も済み（#4079。往復・EOF・resize を照合。platform-ci の ubuntu）。POD の PortForward は未実装。設計は「本番 backend の設計」の節 | #3753〜#3766 |

## バインドの方針

- 既定は `127.0.0.1:0`（loopback、OS が空きポートを選ぶ）。外部への公開は `StreamingConfig::allow_external` を明示したときだけで、`0.0.0.0`・`::` も外部として扱う（`::ffff:127.0.0.1` など IPv4 射影の loopback も loopback とは扱わず外部とする。緩めない・plugin-cri の判定と揃える。#4238・SEC-1）。違反は起動時に `INVALID_ARGUMENT`（fail-closed）
- 発行 URL の host は `StreamingConfig::advertise_addr`（IP）を使い、ポートは実際の待ち受けポートにする。未指定なら bind したアドレスを使う。`0.0.0.0`・`::` で bind するときは kubelet から到達できない URL になるため広告アドレスを必須とし、無ければ（または広告アドレスが未指定アドレス・マルチキャストなら）起動時に `INVALID_ARGUMENT`（fail-closed）。ワイルドカード・未指定・マルチキャストの判定は IPv4 射影形を正規化してから行う（`::ffff:0.0.0.0` も拒否する。#4238）。広告アドレスは broadcast（`255.255.255.255`・射影形を含む）と IPv4 互換形 `::a.b.c.d`（`::` `::1` を除く）も拒否し、URL は射影形を IPv4 表記（`http://192.0.2.7:PORT`）で組み立てる（#4290）。残余: 240/4（broadcast 以外）・サブネット宛て broadcast・zone つき IPv6 は拒否せず、bind 側の互換形・broadcast は OS 任せ
- 外部へ公開するときは TLS も認証も無い。URL を知ることが唯一の認可なので、前段のネットワーク制御（ファイアウォール・リバースプロキシ等）で守ること
- plugin-cri の CLI は `--streaming-bind <ADDR>`・`--streaming-allow-external`・`--streaming-advertise <IP>` を `StreamingConfig` の `bind`・`allow_external`・`advertise_addr` へ 1:1 で写す（#4110・CRI-6・REPAIR-3）。`allow_external` は bind アドレスから推測せず別の明示フラグにする。cri の `validate()` に通し、さらに「opt-in だけ・広告だけが立つ指定」（非 loopback の bind なしの `--streaming-allow-external`、`--streaming-allow-external` なしの `--streaming-advertise`）も拒む。違反は起動前に `error: INVALID_ARGUMENT: invalid --streaming-* argument`（終了コード 2、値は含めない）。非 loopback で実際に待ち受けたときだけ、起動時に警告 1 行（`cri_streaming_external_exposure`、固定文言、アドレスなし）を stderr へ出す
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
- 有効なトークンの要求は `StreamHandler` に渡す。既定の `NotImplementedHandler` は結線済みの種別を持たず（URL は発行されない）、到達した要求には 501 を返す（多層防御）

## Attach（TASK-63.3・#681）

### 構成

| ファイル | 役割 |
| -------- | ---- |
| `streaming/spdy.rs` | SPDY/3.1 のフレーム codec。型付きの `Frame`・31 ビットの `StreamId`・辞書つき zlib のヘッダブロック。Exec（`exec.rs`）・PortForward も再利用する |
| `streaming/spdy_dictionary.rs` | SPDY/3 の辞書 1423 バイト。出典は `NOTICE`（moby/spdystream）。Adler-32 を draft の辞書 ID（`0xe3c6a7c2`）と照合する試験がある |
| `streaming/remotecommand.rs` | `*.channel.k8s.io` の交渉（v4・v3・v2）・`streamtype` の割り当て・`metav1.Status` の JSON・resize の JSON・`SessionLimits` |
| `streaming/attach.rs` | `AttachHandler`（`StreamHandler`）・`AttachBackend`（注入点）・1 接続 1 タスクのセッション |
| `streaming.rs` の `StreamDispatcher` | 種別ごとのハンドラの振り分け。未設定の種別は結線済みと答えず、URL は発行されない（到達した場合の 501 は多層防御）。#680・#682 は同じ型へ足す |

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

### Attach の本番 backend（段階 1 は実装済み・完全版は未実装・REPAIR-3）

実行中コンテナの stdin / stdout / stderr と tty を渡す経路は、core の `ContainerRuntime` にも supervisor にも無い（CreateContainer の `stdin`・`stdin_once`・`tty` の bundle への反映もまだ）。`ContainerRuntime` トレイトの拡張か supervisor の新しい経路かは PLUG-1・SUP 系の設計判断（main の設計が要る）であり、本 issue では注入点（`AttachBackend`）までとした。判断材料として、supervisor のログの sink は stdout / stderr を読んでいるため読み側だけは供給できる可能性があるが、stdin の経路と tty は無く、断定していない。plugin-cri からの `StreamingServer` の起動と `StreamDispatcher` / `AttachHandler` の組み立ては #3754。方式の設計は「本番 backend の設計」の「Attach」節。段階 1（読み取り専用）は #3763 で実装済み、完全版（stdin・tty・resize）は #3765 の設計に従い Linux で実装済み（#4077・#4078。実機の確認は #4079）。

## Exec（#680・TASK-63.2・CRI-6）

`ExecStreamHandler`（`StreamHandler` の実装）を `StreamDispatcher::with_exec` で登録する（単独なら `bind_with_handler` に直接渡してもよい。Exec 以外の種別は結線済みと答えず、URL は発行されない）。SPDY の codec・交渉・status・resize の解析・期限（`SessionLimits`）は Attach と共通の `spdy.rs`・`remotecommand.rs` を使い、`exec.rs` に残るのは Exec 固有の部分（起動役 `ExecStreamLauncher`・プロセスの終了コードから Status への変換・stdin の stall 期限）だけである。

- 交渉・ストリーム割り当ては Attach と同じ（v4・v3・v2。resize は v3 以降）。受け付ける組は発行時に保存した `ExecRequest` から決める（`StreamOptions::expected`）
- 終了の通知: v4 は error ストリームに `metav1.Status` の JSON。成功は `{"metadata":{},"status":"Success"}`、非 0 は `reason: NonZeroExitCode` と `details.causes: [{"reason":"ExitCode","message":"<code>"}]`。v3・v2 は成功時に何も書かず、非 0 は `command terminated with exit code <code>` のテキスト（kubelet と同じ）。起動失敗・待ち失敗は `InternalError` の固定文で、内部のパス・エラー文は載せない。続けて未 FIN の出力に FIN、GOAWAY を送り閉じる
- フロー制御は Attach と同じく強制しない（「意図的な逸脱」）。送信キュー 1 MiB の上限と、stdin をプロセスへ書き終えるまで次のフレームを読まないことで背圧を TCP に任せる。試験 `cri6_exec_large_stdin_roundtrip_beyond_window` が 256 KiB の往復を固定する
- 期限（REPAIR-5）: `SessionLimits`（作成 30 秒・idle 4 時間・流し切り 5 秒・最後の送出 5 秒）に加え、Exec 固有の `launch_timeout`（既定 30 秒）と `stdin_stall_timeout`（既定 60 秒。溜めた stdin をプロセスが読まないとき、ソケットを読めず切断を検知できない時間の上限）
- 受信バッファが上限を超えた場合は EOF と区別して `ProtocolError`（GOAWAY）で閉じる
- インスタンスの照合（#4286・CRI-5・SEC-1・CORE-1）: `Exec` RPC は URL の発行前に、実行層の `state` を `exit_observe_timeout`（有界）で 1 回読み、コンテナのインスタンス識別子を `StreamRequest::Exec { request, instance }` に保存する（実行層が無いスタブ経路は `None`。読めなければ RPC を失敗させ URL を発行しない）。起動役は対象のプロセスを決める状態読み取りと同じ読み取りで得た値と `adapter::instance_matches`（shim v2 の T5 と同じ規則。`None` 同士は通し、値違い・片側だけ `None` は不一致）で比べ、不一致なら helper を起動せず `FAILED_PRECONDITION` `"container was recreated after the exec request"`（`MSG_EXEC_INSTANCE_CHANGED`。ID・値を含めない）で拒否する。コードが shim の `NOT_FOUND "exec not found"` と違うのは、後者が登録簿から除去した結果の語彙で、ストリーミング経路には登録簿が無いため。kubelet には他の起動失敗と同じ `InternalError` の Status として見える

### 注入トレイト `ExecStreamLauncher`

core の `ContainerRuntime` に exec は無く、shim v2 の `TaskExecLauncher` は stdio を持たない（containerd の FIFO 前提）。そこで stdio を持つ起動役を `crates/cri` の注入トレイトとして定義した（`ContainerRuntime` は変えない。PLUG-1）。`ExecLaunch` には発行時に保存した要求から作った値だけを入れ、通信路の内容から cmd を組み立てない。契約は、要求された stdio だけを返す・`ExecSession` の drop でプロセスを止める・`ExecLaunch::instance` を起動時の状態読み取りと照合して不一致なら起動しない（#4286）・コンテナの namespace / cgroup / seccomp / capability を継承して広げない（SEC-1）・panic しない。**本番の実装は plugin-cri の `streaming::exec_launcher`（#3761）**。supervisor の exec 入口（pidfd 経由）へ stdio のパイプと pty を付ける橋渡しの設計は「本番 backend の設計」の「Exec」節（#3757〜#3762）。

## PortForward（#682・TASK-63.4・CRI-6）

- Upgrade 前の照合: `Connection: Upgrade`・`Upgrade: SPDY/3.1`・`X-Stream-Protocol-Version: portforward.k8s.io` のすべてが揃わなければ 400（Upgrade しない）。101 応答に同じ 3 ヘッダを載せる。WebSocket は未対応
- ストリームの対: クライアントが `streamtype`（error / data）・`port`・`requestid` のヘッダ付きで SYN_STREAM を送る。受けるたびに SYN_REPLY を返し、同じ `requestid` の error と data が揃ったら転送先へ接続する。クライアント起点の ID は奇数のみ
- 拒否（RST_STREAM の REFUSED_STREAM）: 不正な `streamtype`・`port`（10 進の数字のみ・1..=65535）・`requestid`（空・64 バイト超）、保存済み要求の `port` 一覧が非空でそれに無いポート、同時ストリーム数の超過、同じ対への重複
- 転送: data の DATA は TCP へ書き、FIN で TCP の書き込み側を shutdown する。TCP の EOF は DATA の FIN にし、両方向が閉じたら error ストリームも FIN で閉じる。接続失敗は error ストリームへ固定の英文（`error forwarding port <port>: connection failed`）を書いて両ストリームを FIN で閉じる
- 他の種別と同居させるときは `StreamDispatcher::with_port_forward` に登録する（`with_fallback` の連鎖は持たない）
- PING は同じ ID で返す。SETTINGS・WINDOW_UPDATE・HEADERS は読み飛ばし、フロー制御は持たない（kubelet の SPDY 実装も窓を強制しない前提。実クライアントでの確認は本番 backend の結線後）。GOAWAY・切断で終了する
- 転送先への接続は `PortForwardDialer`（`pod_sandbox_id` と `port` で `std::net::TcpStream` を返す）に切り出す。cri は名前空間の具象を知らず、既定でホストの loopback へつなぐ実装を置かない。本番の dialer（NODE ネットワークの pod と、pod の netns へ入って接続する POD ネットワークの pod）と plugin-cri でのサーバー起動・ハンドラ注入の設計は「本番 backend の設計」の「PortForward」節（NODE は #3755、POD は #3766）

| 項目 | 既定値 | 設定 |
| ---- | ------ | ---- |
| 転送先への接続の期限 | 10 秒 | `PortForwardConfig::dial_timeout` |
| 対が揃うまでの期限 | 30 秒（kubelet の stream creation timeout 相当） | `pair_timeout` |
| Upgrade 後の idle の期限 | 4 時間（kubelet の stream idle timeout 相当） | `idle_timeout` |
| 同時ストリーム数 | 128 | `max_streams` |
| 受ける DATA の 1 フレームの最大長 | 256 KiB（共通 codec の `MAX_INCOMING_PAYLOAD`。1024..=この値） | `max_frame_bytes` |
| 1 対の書き込み滞留・送信キューの上限 | 256 KiB（超えると読み取りを止める） | `max_pending_bytes` |
| 転送先への書き込みが進まないまま滞留してよい時間（対ごと） | 30 秒 | `write_stall_timeout` |
| blocking の dial の同時件数（ハンドラ全体） | 32（1..=256。取れなければ接続失敗） | `max_inflight_dials` |

- 転送先が TCP を読まない対は、滞留が上限に達すると SPDY 接続全体の読み取りが止まり、別の対の DATA・RST_STREAM も処理できなくなる。`write_stall_timeout` の間書き込みが 1 バイトも進まなければ、その対を RST_STREAM(CANCEL) で閉じて滞留分を捨て、受信を再開する（書き込みが進む遅い転送先は打ち切らない。REPAIR-5）。試験は `cri6_stalled_target_does_not_block_other_pairs_or_rst_stream`
- blocking の dial の枠は `PortForwardHandler` が持ち、全セッションで共有する。枠は `spawn_blocking` の処理が終わるまで返らないため、future の破棄・期限切れ・セッションの張り直しで上限を超えて積めない。残余: 起動済み・待機中の blocking 処理そのものは取り消せない（dialer の `timeout` に委ねる）

- ヘッダブロックの上限と SPDY/3 の zlib 辞書（出典と帰属表示）は共通 codec（`spdy`・`spdy_dictionary`）の記述に従う。超えたら GOAWAY(PROTOCOL_ERROR) で切断する
- 観測: セッションの終了理由（`PortForwardEnd`）を `PortForwardObserver` に渡す。ポート・トークン・アドレスは載せない

## 本番 backend の設計（#3752）

2026-11-03 に main が決めた要点（Attach は段階方式、Exec は制御チャネルの exec 要求と fd 渡しで孤児時に縮退しない、PortForward は NODE を先に入れ POD は #2877 の後、依存は plugin-cri から supervisor への一方向で cri に実装を入れない）を詳しくした設計記録である。後続の兄弟 issue（#3753〜#3766。親 #3726・TASK-63・MS-7）はこの記録を正として実装する。オーナーの確認が要る点は末尾の「未確認・オーナー確認事項」にまとめ、それ以外は確定扱いとする。**本節は設計記録であり、実装の状況は冒頭の表と各小節の「実装」の記述を正とする。Exec（#3761）・Attach（#3763 の読み取り専用と、Linux の完全版 #4077・#4078。実機前提試験は #4079 で実装済み）・NODE の PortForward（#3755）は実装済みで、Exec の tty・POD の PortForward は未実装である（REPAIR-3）**。

対象ビヘイビア: CRI-6・PLUG-1・SUP-4・SUP-6・SEC-1・REPAIR-2・REPAIR-3・REPAIR-5（関連: CORE-1・CORE-5・SUP-3・SUP-5・SUP-7・NET-3）。

### crate の担当と依存方向（PLUG-1）

| crate | 担当 | 入れないもの |
| ----- | ---- | ------------ |
| `crates/cri` | 注入トレイト・handler・URL 発行・RPC の検証。#3755 で PortForward の対象の型を足す | 本番の注入トレイトの実装、supervisor への依存 |
| `crates/plugin-cri` | 3 つの本番 backend（`ExecStreamLauncher`・`AttachBackend`・`PortForwardDialer`）、`StreamingServer` の起動と `with_streaming` の注入（#3754） | `run_command_with_pidfd` の直接の呼び出し（plugin-cri は多スレッドのため） |
| `crates/supervisor` | 制御チャネル（kind 6 / 7 は既存のまま。完全版 Attach の種別は #3765）、exec helper の入口 `stream-exec`、helper との channel の codec、fd 渡しの安全な公開 API、`ExecLaunchIo` の拡張、ログ reader の取り消しの口 | cri の型への依存 |
| `crates/core` | exec の stdio の付け替え（#3757）、pty の割り当てと `TIOCSWINSZ` の薄いラッパー（#3758） | — |

- 辺は plugin-cri から cri・supervisor・core と、supervisor から core だけで、新しい辺も外部依存も増えない。tokio の feature も増やさない（plugin-cri は `rt`・`net`・`time` の current_thread。`process`・`signal` は使わない）

### Exec（SUP-6・SEC-1・REPAIR-2・REPAIR-5）

**前提**:

- `run_command_with_pidfd` 系は setns と `fork_single_threaded` のため、呼び出し元が単一スレッドに限られる。supervisor 本体は多スレッドで直接呼べず、healthcheck は `/proc/self/exe` の 3 段で回避している（[healthcheck-exec-helper.md](healthcheck-exec-helper.md)）
- 制御チャネルは固定長で payload は 64 バイトまで（`MAX_PAYLOAD`）。kind 6 は pid と deadline、kind 7 は hold と cgroup 名
- 起動時の pidfd の出所は稼働中の supervisor だけで、記録 pid から `pidfd_open` しない（[exec-without-supervisor.md](exec-without-supervisor.md)）

**再利用の確認結果**: CLI の exec の経路（[exec-pidfd-handover.md](exec-pidfd-handover.md) の案 A。kind 6 `ExecHandoverRequest` と kind 7 `ExecCgroupNotify`、`ControlExecHandover`）は CRI の Exec にそのまま再利用できる。制御チャネルの codec は変更しない。

**方式比較**:

| 案 | 内容 | 評価 | 判断 |
| -- | ---- | ---- | ---- |
| α | plugin-cri が、同じディレクトリの supervisor の実行ファイルを第 1 引数 `stream-exec` で起動する。これが単一スレッドの helper になり、既存の `ControlExecHandover` で kind 6 の pidfd の複製を受け、kind 7 で exec 子 cgroup を通知し、拡張した stdio つきで `run_command_with_pidfd_*` を呼ぶ | 制御チャネルの新しい種別も可変長 frame も要らない。kind 7 のガードによる回収、uid の照合、同一性の照合（`identify_pid1_with_pidfd`）、監査 sink の作成順は CLI の exec と同じ経路を使う。argv は healthcheck helper と同じく `--` の後ろの配列で渡し、64 バイトの制約を受けない。新しい `unsafe` は sys の複数 fd 送信への一般化だけ | 採用 |
| β | supervisor が exec 要求（argv・stdio の fd）を受け、healthcheck と同じ reaper / helper を自分で起動する | argv が 64 バイトを超えるので可変長 frame（`VERSION` と互換方針の変更。REPAIR-2 の範囲が広がる）か別の文書が要る。helper へ 4 本以上の fd を渡すには `pre_exec`（sys の外の unsafe）か 2 段目の SCM_RIGHTS が要る。セッション中（最長 1 時間）の待ちのスレッドが supervisor に常駐し、再 launch の pause の対象が増える | 不採用 |
| γ | plugin-cri が自分のプロセスで `run_command_with_pidfd` を呼ぶ | plugin-cri は tokio と blocking pool で多スレッドのため成り立たない | 不採用 |

helper を supervisor の bin に置く理由は、exec の領域（healthcheck の `healthcheck-exec` の前例・`exec.rs`・試験の harness）が supervisor にまとまること、plugin-cri が start と同じ解決（`current_exe()` と同じディレクトリの固定名。PATH は探さない）で起動できること、plugin-cri の `main` の argv の振り分けを増やさないことの 3 点。plugin-cri の `/proc/self/exe` で振り分ける案は、plugin-cri 側に exec の領域が分散するため採らない。

「pidfd の保持者は supervisor だけ」は、出所が supervisor だけで helper は複製を一時的に持つだけ、という意味で読む（CLI の exec と同じ。案 A の承認範囲）。孤児時は kind 6 が `Unavailable` になり、記録 pid へ縮退せず失敗する。

**経路**:

1. plugin-cri が stdio の端と socketpair を作る。stdin・stdout・stderr は `UnixStream::pair` とし、親側は tokio の `UnixStream` にする。pipe にしない理由は healthcheck と同じ（nonblocking・子孫が端を持ち続けても止まらない・core の診断行は AF_UNIX にだけ出る）
2. helper を `env_clear`・cwd `/`・argv[0] 固定で起動する
3. helper は次の順で進む。`close_fds_from(3)` と `set_dumpable(false)`、引数の検証（`--root`・`--id`・`--expect-pid`・`--timeout-ms`・stdio のマスク・`--` 以降の argv。argv[0] は絶対パス）、状態記録の照合（Running・pid の一致）、`launch_env_for` の読み取り、`default_audit_sink` の作成（作れなければ exec しない）、kind 6 で pidfd を受ける（期限 5 秒）、stdio の fd を受ける、cgroup の作成直後に kind 7 で通知して ack を受ける（10 秒）、`Started` を返す、worker を fork する、結果を返す

| helper の fd | 中身 |
| ------------ | ---- |
| 0 | plugin-cri との channel（socketpair の子側、blocking） |
| 1 | `/dev/null` |
| 2 | 診断行（JSON 1 行。上限つきで plugin-cri の構造化ログへ転送する。healthcheck と同じ扱い） |

- channel の frame は固定長・big-endian で、壊れた値を表現できない型にする（REPAIR-2）。plugin-cri から helper へは `StdioHandover`（マスクと、そのビット数ちょうどの fd を SCM_RIGHTS で送る。最大 3 本）。helper から plugin-cri へは `Started`・`PtyMaster`（tty のときだけ fd 1 本）・`Spawned`（コマンドのホスト側 pid。fork の後に高々 1 回。届かないこともある。#4316）・`Result`（exited n / signaled s / not_started 段 コード / failed コード）。受け側は fd の本数・`MSG_CTRUNC`・マスクとの不一致をすべて拒否し、受け取った fd は drop で閉じる。magic・各 frame の長さ・語彙は #3759 で確定し、本書は構造と上限だけを定める
- pre_exec を使わず、子に渡す fd は `Stdio` の 3 本だけにする（新しい unsafe を sys の外に作らない）

**stdio と pty**:

- stdin / stdout / stderr を別々に付け替える処理は core（#3757）が持ち、`ExecLaunchIo` を拡張する。要求されない stdio は `/dev/null` のまま。既存の healthcheck の挙動は変えない
- pty は worker（コンテナの mount namespace に参加した後）が、コンテナの devpts（`/dev/ptmx` は `pts/ptmx` への symlink。[dev-default-mounts.md](dev-default-mounts.md)）で開く。runc と同じくコンテナ内で `ttyname` が成り立つ。slave は `setsid` と `TIOCSCTTY` で controlling terminal にして fd 0〜2 に付ける。master は core の既存の worker から親への SCM_RIGHTS で helper へ返し、helper が channel の `PtyMaster` で plugin-cri へ返す。受け側（`stream_exec::channel::recv_from_helper`）は core の `PtyMaster::from_received`（文字デバイス 5:2 かつ `TIOCGPTN` の成功）で検証し、不一致は fd を閉じて `NotPtyMaster`（`InvalidArgument`）で拒否する（#4100）。受信に失敗した channel からは再び受信しない（最後の失敗通知の送信だけ許す）。開く位置は、Landlock と seccomp の再適用の **後** に `ExecReady::allocate_pty` で、照合済みの `/` の fd から `dev` → `pts` → `ptmx` を 1 要素ずつ symlink 非追従で辿って開く（#3758 で確定。コマンドと同じ権利で開き、launch より広げない。暗黙の `/dev/pts` に `READ|WRITE|IOCTL_DEV` が付くため通る想定で、実コンテナでの確認は #3762。通らなければ再適用の前へ移す判断をオーナーに仰ぐ）。slave は `ChildStdio::from_pty_slave` が fd 0〜2 に付け、子が `setsid` の直後に `TIOCSCTTY` を発行する。master は worker がコマンドの fork の前に `spawn_exec_worker_with_listener_and_pty` の口で親へ送って閉じる（コマンドは master を持たない）。ホストの devpts で代わりに割り当てる方式は採らない
- resize は、plugin-cri が持つ master へ `TIOCSWINSZ` を発行する（core の安全なラッパー。supervisor への往復なし）

**SEC-1**:

- コマンドは既存の `run_command_with_pidfd` の段（namespace・cgroup・rlimit・launch と同じ capability 集合・NNP・Landlock・seccomp）だけを通り、launch より広げない
- env の基底は `config.json` の `process.env` と launch 時の env だけ。CRI は env を渡さないので `with_env` を使わない。argv はシェルを通さない
- argv[0] が相対パス（例: `sh`）の要求は、PATH の解決（#2439）が決まるまで `INVALID_ARGUMENT` で拒否する。URL の発行前（RPC 時）に断るのが望ましく、#3761 で `StreamWiring` の `exec_relative_command`（既定 false）と `StreamingUrlIssuer::require_exec_options` として実装した（`exec_impl` が URL の発行前に呼び、launch 時にも `StreamExecArgs::new` が拒否する）
- helper と plugin-cri の channel はパスを持たない socketpair で、第三者は接続できない。supervisor の実行ファイルは PATH を探さず固定名で解決し、受け取った pidfd は `identify_pid1_with_pidfd` で照合する。トークン・argv・パスはログやエラーに出さない

**終了コードの写像**: `Exited(n)` は n、`Signaled(s)` は 128 + s（`metav1.Status` の NonZeroExitCode）。`SetupFailed` は子の終了状態（通常 125 / 126 / 127）で、CLI の exec と同じ（exec-pidfd-handover.md §3.4）。拒否・期限・到達不能は launch の失敗にし、handler が `InternalError` の固定文にする。

**drop・restart・孤児**:

- `ExecSession` の drop で、plugin-cri は helper を `Child::kill` で止める（未回収の子なので pid は再利用されない）。channel と制御チャネルの接続が閉じると、kind 7 のガードが exec 子 cgroup を `cgroup.kill` で回収し、worker は PDEATHSIG で終わる
- helper の回収は blocking の待ちを期限つき（5 秒）で行う。回収できない helper は数の上限つきで保持し、超えたら新しい exec を `RESOURCE_EXHAUSTED` で断る（healthcheck の `MAX_HELD_HELPERS` の考え方）
- コンテナの restart（再 launch。[restart-relaunch-single-thread.md](restart-relaunch-single-thread.md)）では、`ExecGuardPool::shutdown_all` が旧世代の exec 子 cgroup を回収するので、CRI の exec のセッションも終わる
- supervisor が不在（孤児）なら `UNAVAILABLE` 相当で失敗し、縮退しない

**SCM_RIGHTS の再利用判断**: core（`sys/seccomp_notify.rs`）・net（`sys/holder.rs`）・supervisor（`sys/linux.rs` の `send_with_fd` / `recv_with_fds`）の自前ラッパーは、crate ごとの sys に置いたまま共有しない。いずれも `pub(crate)` で意味も違い（core は token と資格情報、net は holder の frame、supervisor は制御チャネル）、前例は [fdinfo-mnt-id-parsing.md](fdinfo-mnt-id-parsing.md) の「共有下位 crate を作らない」判断である。本設計で足りないのは supervisor の「複数 fd の送信」だけで、既存の `send_with_fd` を N 本（上限 3〜4。`recv_with_fds` の 4 本と揃える）へ一般化し、plugin-cri が使える安全な公開 API として出す。sys の事前承認の範囲内（coding-rust.md）。plugin-cri の sys には SCM_RIGHTS を新しく足さず、重複を作らない。

**上限**: 同時の exec は supervisor 側がコンテナごとに 16（`ExecGuardLimits::max_guards`）。plugin-cri 側にも全体の上限を設けた（#3761。同時セッション 64・回収できない helper の保持 8。いずれも暫定値で、#4116 のオーナー確認待ち）。channel の受信長は固定で、fd は最大 3 本受け、tty のときは master を 1 本返す。

**本番 launcher の実装（#3761・CRI-6・SEC-1・REPAIR-3・REPAIR-5）**:

- 置き場所は `crates/plugin-cri/src/streaming/exec_launcher.rs`（Linux のみ）。`SupervisorExecLauncher` が `ExecStreamLauncher` を実装し、`HelperSpawner`（本番は plugin-cri の実体と同じディレクトリの固定名の supervisor を `stream-exec` で起動。試験は偽の helper を差し込む）経由で helper を起動する。状態ストアで Running と pid を照合し、`StreamExecArgs::new` に渡す
- stdio は要求された分だけ `UnixStream::pair` を作り、片側を `send_stdio_handover` で渡す。`Started` を待ってから tokio 側の読み書き口に変換し、`Result` を待つ専用 std スレッドの結果を std の socketpair で tokio 側へ渡す（tokio の `sync`・`io-util`・`process` feature は使わない）。`ExecSession` の `exit` future を drop すると持ち主の `HelperGuard` が helper を SIGKILL して回収する
- **tty は本番で fail-closed**: helper に `--tty` が無く、supervisor の `ExecStdio` に pty が無い。`ExecStreamHandler::without_tty` で RPC 時に `INVALID_ARGUMENT`（「exec with tty is not supported」）とし、launcher も二重に断る。受け側（`PtyMaster::from_received` による検証・resize の `TIOCSWINSZ` 転送・pty と tokio の橋渡し）は偽の helper で試験済みで、supervisor 側の結線（後続 issue）が入れば能力フラグ `HelperCapabilities.tty` を true にするだけで有効にできる。`WindowSize` の 0 行・0 列はそのまま渡す
- **stdio の fd 種別（SUP-6・SEC-1）**: helper は受け取った stdin・stdout・stderr が AF_UNIX の socket か FIFO のときだけ受け、通常ファイル・ディレクトリ・文字デバイス（tty・pty・`/dev/null` を含む）・ブロックデバイスは exec も kind 7 の通知もせず `InvalidArgument`（`require_stdio_kinds`）。ホストの端末 fd をコンテナのコマンドへ渡して境界を越えさせないため
- 期限: helper の `--timeout-ms` は supervisor の上限 `MAX_EXEC_HOLD_SECS`（1 時間）なので、exec のセッションは最長 1 時間で止まる（kubelet の idle 4 時間より短い。#4116 の確認事項）。`Started` までは 25 秒（cri の `launch_timeout` 30 秒より短い）、stdio の受け渡しは 5 秒、kill 後の回収は 10 秒（`REAP_BUDGET`）で、回収できなければ保持一覧（上限 8）に入れる
- 停止: ドレインの期限（シグナルから 5 秒）で `stop_streaming_on` の `on_stop` が `shutdown_all` を呼び、追跡中の helper を kill する（「停止時のセッションの扱い」）。plugin-cri が SIGKILL された場合も、helper が fd 0 の切断を検知して通常 2 秒以内に終わる（下の「要求元の異常終了の検知」。実装は #4166、実機の照合は #4167 の `stream_exec_real` の `requester_killed` と `production_binary_exec_real` の段 4）。残る窓は listener の受け渡し前・通知処理中の最大 5 秒の遅れ・channel の端の漏れ
- helper の fd 1 は `/dev/null`。fd 2 は AF_UNIX の socketpair で受け、固定語彙の構造化ログへ転送する（下の「helper の fd 2 の診断の転送」。#4171）。結果は `Result` frame の固定語彙で返る
- 終了コード: `Exited(n)`→n、`Signaled(s)`→128+s、`NotStarted`→子の終了状態、`Failed(code)`→コード別の固定英文の `CriError`

#### helper の fd 2 の診断の転送（#4171・#4172・CRI-6・SUP-6・SEC-1・REPAIR-4・REPAIR-5）

- **転送先**: plugin-cri の構造化ログ（`telemetry::LineSink` の共有 stderr sink。`SupervisorExecLauncher::with_diagnostic_sink` で試験用に差し替えられる）。行は `{"event":"cri_exec_helper_diagnostic",…}` と、要約の `{"event":"cri_exec_helper_diagnostics","outcome":"error",…}`。読み手を作れないときは `"reason":"reader_unavailable"` の 1 行を出す（exec は失敗にしない。観測は最善努力）
- **pipe ではなく socketpair**: core の `emit_diagnostic_line_to` は AF_UNIX の socket にしか書かない（#1697）。helper 側の端は起動後に親で閉じ、helper の終了で読み手が EOF を観測できるようにする
- **上限**（`exec_launcher/diagnostics.rs` の定数と一致）: 1 行 512 バイト（`DIAG_MAX_LINE_BYTES`。改行を含む）、解析対象 32 行（`DIAG_MAX_LINES`）、総 8 KiB（`DIAG_MAX_TOTAL_BYTES`）、1 行あたりの要素数 12（`MAX_PAIRS`）。超えた分は読み捨てる（読むのをやめると helper の同期書き込みが止まるため）。メモリは入力量に比例しない
- **捨てた行の数え方**: 要約行の `forwarded`（転送した行）・`ignored`（語彙内だが失敗の欄が無い行。例 `entrypoint_mode`）・`unparsed`（解釈できない行。改行の無い末尾の断片を含む）・`dropped_lines` / `dropped_bytes`（上限を超えた分）。要約行は unparsed か dropped があるとき、または終わりが `deadline`・`read_error` のときだけ出す。終わりの語彙は `eof`・`stopped`・`deadline`・`read_error`
- **出さない項目**: 出力は閉じた語彙で引き直した `&'static str` と整数だけ。argv・トークン・コンテナ ID・パス・入出力の内容・`message` の値・helper の自由文は写さない（SEC-1）
- **停止**: 読み手は 100 ms 刻み（`DIAG_POLL`）で停止フラグと絶対期限を確かめる。helper の kill・セッションの drop・`shutdown_all` が停止フラグを立て、停止後は 50 ms（`DIAG_STOP_DRAIN`）だけ残りを読む。EOF には頼らない（fork した worker が書き込み端を継承しうるため）。終了時の待ちは 500 ms（`DIAG_JOIN_BUDGET`）。絶対期限は `Started` の予算 25 秒 + セッション 3600 秒 + 結果の余裕 30 秒
- **試験**: 単体試験（`diagnostics/tests.rs`・`exec_launcher/tests.rs` の偽 helper）、`exec_helper_diag_real.rs`（実の子プロセスの結線）、`exec_helper_failure_diag.rs`（#4172・#4284。自分自身を `stream-exec` helper として再実行し、supervisor の bin と同じ入口で動く実 helper のコードで場面 A〜D を照合する。既定の集合で動く）。A は fd 0 が socket でない helper で、ログは `{"event":"cri_exec_helper_diagnostic","component":"supervisor.stream_exec","code":"INVALID_ARGUMENT","stage":"helper_channel","errno":"none"}` の 1 行。B は存在しない pid のコンテナを本番の `SupervisorExecLauncher` で exec し、supervisor 不在で `UNAVAILABLE`（`exec helper is unavailable`）・`stage` が `helper_pidfd_handover`・errno が状態ディレクトリを開けない `ENOENT`（数値 2）の 1 行。C は不正な引数（予約済みの stdio ビット）で `helper_args`、D は記録の無い ID で `helper_state_get`（`NOT_FOUND`）。全場面で、既知のコンテナ ID・argv・トークン風の値・状態ルートの名前がログの全バイト列に現れないことを照合する。supervisor 側は `stream_exec_helper.rs` が偽の取得元・通知で各段（kind 6・kind 7・stdio の受信・状態の照合ほか）の段名と errno を具体値で固定する
- **生成側（#4284・SUP-6・REPAIR-4）**: helper は起動の失敗を `{"component":"supervisor.stream_exec","stage":"helper_*","code":…,"errno":N|"none"}` の 1 行にして、`Result` の送信より前に fd 2 へ書く（`Result` の送信が失敗したときは `helper_result_send` の行を足す。子の段の失敗 `NotStarted` は `Result` frame が段を運ぶので足さない。要求元の消滅の取り消しの行は従来の形のまま）。段の語彙は supervisor の `stream_exec::diag::HelperStage`（17 段。全トークンに `helper_` 接頭辞を付け、core の `ExecChildStep`・`IsolationStage` と衝突させない。試験で固定）で、fd 0 の確保・dumpable・引数・状態ストア（open・get・照合）・launch env・監査 sink・要求の検証・kind 6・stdio の受信・stdio の種別・期限・kind 7・`Started` の送信・exec・`Result` の送信。errno は OS の errno（1〜4095）があるときだけ数値で、無い段は固定語 `none`（0 は転送側が errno として受けないため使わない）、範囲外は `other`。errno を運べるのは helper 自身の syscall・制御クライアントの OS エラー（`ExecPidfdSource::obtain_with_errno`・`ExecCreatedNotifier::notify_created_with_errno`。既定は errno なしで包む加法的な拡張）・channel の入出力（`ChannelError::Io`）に限る。制御クライアントは失敗を作った地点で同じスレッドの受け渡し口（`control/os_errno.rs`）に errno を覚え、`obtain_with_errno` 等が呼び出しの前後で空にして取り出す。転送側は `component` が `supervisor.stream_exec` の行に限り、語彙外の `stage`・errno 名（helper と plugin-cri の版のずれ）を `other` として転送し、他の `component` の語彙外は従来どおり解釈できない行にする（fail-closed）。行は固定語彙と整数だけで組み、パス・ID・argv・自由文字列を型の上で入れない
- **残余（REPAIR-3）**: 状態ストア・launch env・監査 sink・要求の検証の失敗は、core の `TraitError` が errno を持たないため errno が `none` になる（`TraitError`・`ExecExit::SetupFailed` へ errno を持たせる案は別 issue）。`require_stdio_kinds`・mask の不一致を稼働中の supervisor と実コンテナで照合する実機前提の試験は #4327 で `stream_exec_real.rs` に追加済み（`mask_mismatch`・`stdio_kind`。ci.yml・real-machine-tests.md も同じ PR で整合）。対象外は `FdCountMismatch`（送信 API の型の上で作れない）と errno つき `Internal` の腕（決定的に起こせない）、`cri_exec_real.rs` 経由（本番の経路では不一致を作れない）。seccomp の集計行は supervisor の公開語彙（`SeccompReportEvent`）で引き、ignored に数える（#4233）。fd 1 は `/dev/null` のまま

#### 要求元の異常終了の検知（#4165・#4112・SUP-6・SEC-1・REPAIR-5）

plugin-cri が helper を kill せずに異常終了（SIGKILL 等）すると、単一スレッドの helper は exec の間 fd 0（plugin-cri との channel）を見ていないため、helper とコンテナ内のコマンドは exec の期限（`--timeout-ms`。上限 `MAX_EXEC_HOLD_SECS` 3600 秒）まで、kind 7 のガードは期限 + `hold_grace`（30 秒）まで残る。本節は検知の方式を選定する（設計。実装は #4166、実機の照合は #4167 で済み）。

**前提（origin/main で確認した事実）**:

- exec の間 helper が止まっている待ちのループは core ではなく supervisor にある。`crates/supervisor/src/exec.rs` の `respond_and_collect` が `ExecResponder::serve`（`seccomp_notify.rs`。反復ごとに `stop()` と期限を見て `SERVE_STEP` 20 ms の `wait`）を回し、続く `collect_worker_result` が core の `ContainerChild::wait_timeout`（期限 + `WORKER_GRACE` 7 秒）で待つ。core が出すのは `wait_timeout`・`wait_for_exit`・`kill_and_reap` だけで、取り消し口は core の API を変えずに supervisor 側で作れる
- 後始末は `run_in_worker_with` の cleanup（exec 子 cgroup の `cgroup.kill` と削除。`CHILD_CGROUP_CLEANUP_TIMEOUT` 5 秒）が既に通る。worker とコマンドは PDEATHSIG（SIGKILL）を持つ。helper の制御チャネルの接続が閉じると supervisor の `exec_guard` が通知済みの exec 子 cgroup を回収する
- plugin-cri は channel の自分の側を `watch_result` の専用スレッドが `Result` を受けるまで持ち、`shutdown` しない。受信失敗・セッションの drop・`shutdown_all` では helper を SIGKILL する。よって「channel が閉じた」ことは「要求元はもう exec を必要としていない」ことと等価である。channel はパスの無い socketpair（CLOEXEC）で、第三者は接続も切断もできない
- helper の送信は `MSG_NOSIGNAL` で、相手が消えていれば `Result` の送信は SIGPIPE なしに直ちに失敗する

**5 案（A・B・C1・C2・D）の比較**:

| 案 | 内容 | 長所 | 短所 | 判断 |
| -- | ---- | ---- | ---- | ---- |
| A | fd 0 を `poll`（タイムアウト 0）し、`POLLHUP`・`POLLERR`・`POLLRDHUP`・`POLLNVAL` を要求元の消滅とする | プロセスの死とセッションの破棄（channel の drop）を同じ事象で拾う。pid を扱わず再利用の窓が無い。非ブロッキングの 1 回の syscall で単一スレッドのまま。第三者が起こせない | supervisor の sys に `poll` の FFI 宣言と `libc_abi` の照合が要る（事前承認の範囲の sys ラッパー）。plugin-cri の end が他のプロセスへ漏れると検知できない | 検知の信号として採用 |
| B | 要求元の pid（`SO_PEERCRED`・`getppid`）を `pidfd_open` して終了を見る | channel の end の漏れに影響されない | 死から `pidfd_open` までに pid が再利用されうる。supervisor の sys に `pidfd_open` の宣言が要る。プロセスが生きたまま channel を捨てた場合を拾えない。「記録した pid から handle を導かない」方針（`exec-without-supervisor.md`）とずれる | 却下（A と同じ事象を競合と宣言を増やして拾うだけ。再評価条件に残す） |
| C1（core に取り消しトークン） | `ContainerChild::wait_timeout` 等に取り消しを足す | 汎用 | 実際のループは supervisor にあり、検知後は `kill_and_reap` へ切り替えれば待たずに済む。core の公開 API が増え healthcheck・CLI exec に波及する | 却下（core は変えない。PLUG-4・REPAIR-1） |
| C2（supervisor の serve ループに取り消し口） | `respond_and_collect` の `stop` を「worker の終了または取り消し」にし、取り消しなら `kill_and_reap` へ進む | 20 ms 刻みのループが既に `stop()` を呼ぶ。単一スレッドのまま。core は不変。他の呼び出し元は `None` で挙動不変 | `ExecLaunchIo` に任意項目が 1 つ増え、構築箇所 6 つの追従が要る | 取り消し口として採用（A の信号を受ける） |
| D | helper が `PR_SET_PDEATHSIG` を使う | 単純 | PDEATHSIG は親を fork した「スレッド」の終了で発火し、plugin-cri は多スレッド（tokio の blocking pool は idle で終わる）なので正常なセッションを誤って止める。子側の設定は `pre_exec`（sys 外の unsafe）が要る | 却下（誤検知が避けられない。`helper.rs` のモジュール doc の既存の却下理由と同じ） |

補足の却下: (1) core の `poll` ラッパーを公開して supervisor が使う案は、core の公開 API を増やし、crate ごとの sys に置いて共有下位 crate を作らない前例（`fdinfo-mnt-id-parsing.md`）に反する。(2) channel を非ブロッキングにして 1 バイト読む案は、データを消費し、O_NONBLOCK がオープンファイル記述で共有されて以後の送信の期限処理に影響する。

**採用: A（信号）+ supervisor 側の C2（取り消し口）**:

- 判定 `requester_gone`: fd 0 を `poll(timeout = 0)` し、`POLLHUP | POLLERR | POLLRDHUP | POLLNVAL` のいずれかで真。`POLLIN` だけ（想定外のデータ）は消滅とせず読みもしない。`poll` の失敗（`EINTR` 等）はその回は偽にし、既存の上限に任せる
- 契約（要求元側）: plugin-cri はセッションを続けたい間、channel の自分の側を閉じず `shutdown` もしない（現状の `watch_result` が満たす）。この end を他のプロセスへ渡さない（CLOEXEC を保つ）。#4166 で `exec_launcher.rs` の doc にも書く
- 取り消し口: `ExecLaunchIo` に取り消し判定の任意項目を足す（名前と型は #4166）。`ServeEnd::Lost` の後の待ちも `wait_for_exit` を短い刻みに分けて取り消しを見る。helper 以外（healthcheck・CLI exec 等）は `None`
- 検知後の順序:
  1. serve ループの `stop` が真 → `ServeEnd::Stopped`（取り消しの印つき）
  2. `collect_worker_result` を待たずに worker を `kill_and_reap`（上限 5 秒）。コマンドには PDEATHSIG が届く（多層防御）
  3. listener の保持を既存の順序どおり解放する
  4. `run_in_worker_with` の cleanup が exec 子 cgroup を `cgroup.kill` し、空になるのを待って削除する（上限 5 秒）。ここでコマンドと子孫が残らないことを保証する
  5. 結果は wire の `Failed(Unavailable)`（語彙を増やさず `Timeout` を流用しない）。監査の結果の記録と fd 2 の診断行で、期限切れと区別できる形にする
  6. `send_result` は相手が消えていて直ちに失敗し、終了コード 1
  7. helper の終了で制御チャネルの接続が閉じ、`exec_guard` が同じ cgroup をもう一度回収する（冪等。4 が失敗した場合の歯止めで、上限は既存の期限 + `hold_grace`）
- 適用範囲は `Started` を送った後の exec の通し。それ以前の待ちには既存の短い期限がある（kind 6 は 5 秒、kind 7 の ack は 10 秒）。worker が listener を渡す前に止まった窓は取り消しを見ず、既存の全体期限で終わる残余とする
- plugin-cri の本番 launcher（#3761・#4120）の経路: plugin-cri 側の変更は不要。plugin-cri の再起動をまたいで残った helper も、旧プロセスの死で channel が閉じるので同じ経路で止まる
- 他 OS: `stream_exec`・`exec` は Linux のみで、macOS・Windows に影響しない

**目標値（試験の合否に使う）**:

- 検知は `SERVE_STEP` 20 ms ごと。通知 1 件の処理中は最大 `MAX_RESPONSE_DEADLINE` 5 秒遅れうる
- **合否の値（通知処理のない通常ケース）: 要求元の消滅（SIGKILL、または偽の要求元が channel を閉じる）から helper の終了まで 2 秒以内**。この 2 秒は、消滅の時点で helper が通知の処理中でなく、worker・cgroup の後始末も遅れない場面の条件である。#4166 の単体試験と #4167 の実機前提試験はこの値で照合する。exec の期限は 60 秒以上にし、従来の上限（期限 + `hold_grace`）と区別する。通常は数十〜数百 ms の見込みで、2 秒は CI の揺れの余裕
- 遅延ケースの最大予算（REPAIR-5）: 通知処理中に消滅した場合は検知が最大 5 秒遅れる（2 秒の条件は適用しない。最大予算 5 秒 + 通常ケースの 2 秒）。worker の回収・cgroup の後始末が遅い場合や回収に失敗する場合の全体の最大予算は、判定 20 ms + 通知処理 5 秒 + worker の回収 5 秒 + cgroup の後始末 5 秒 ≒ 15 秒で、期限 + `hold_grace` より十分短い。回収できない helper は保持一覧（上限 8）へ入れる。試験は通常ケースを 2 秒で照合し、遅延・回収失敗の場面を試験する場合は 15 秒を上限として別に照合する

**期限と `hold_grace` を弱めない保証**:

- 取り消しは早く終わらせる短絡だけで、既存の期限の判定（serve の `deadline`、期限 + `WORKER_GRACE`、`--timeout-ms` の検証と `MAX_EXEC_HOLD_SECS`、kind 7 のガードの期限 + `hold_grace`）と定数は変えない
- 判定は非ブロッキングで待ちを足さない。判定の失敗は「取り消さない」に倒れ、従来の上限で終わる。取り消し口の既定は `None`
- 照合: 既存の期限・`hold_grace` の試験（`exec_timeout.rs`・`control_exec_handover.rs`・`control_exec_guard_relaunch.rs`・`exec_guard` の単体試験）を弱めずに通す。加えて #4166 で「判定が常に偽・常に失敗でも期限で従来どおり終わる」試験を足す

**セキュリティ（SEC-1）**: 第三者は取り消しを起こせない（パスの無い socketpair）。取り消しは「早く止める」だけで権限・分離は広がらない。検知後もコマンドと子孫は `cgroup.kill` で回収し、失敗しても `exec_guard` が既存の上限で回収する。新しい `unsafe` は supervisor の sys の `poll` ラッパーだけで、事前承認の範囲（`// SAFETY:`・`libc_abi` の照合・security-auditor 観点のレビューと PR 本文への記録が条件。#4166 の作業）。

**実装者が決める事項（#4166。決定済み）**:

- 取り消し判定の型は `crates/supervisor/src/exec.rs` の `ExecCancelHook<'a> = dyn Fn() -> bool + 'a`、`ExecLaunchIo` の項目名は `cancel: Option<&ExecCancelHook>`（既定の `None`）。core は変えない
- 判定の実体は `stream_exec::channel::requester_gone`（fd 0 の channel への `poll(timeout = 0)`。`POLLIN` だけは消滅としない・読まない。判定の失敗と非対応ターゲットは偽）
- `Lost` の後の刻みは `CANCEL_POLL_STEP` = 100 ms（`wait_for_exit` で待ち、kill しない）
- 取り消しの結果は `Unavailable`（固定メッセージ `exec cancelled: the requester went away; the exec worker was killed`）で、`Timeout` を流用しない。worker の終了を先に見て、終了済みの本当の結果を取り消しで上書きしない
- 監査レコードは足さない（`audit_worker_result` は分離違反だけを記録する SEC-4 の設計で、取り消しは違反ではないため）。期限切れとの区別は `Unavailable` / `Timeout` のコードとメッセージ、および helper が fd 2 に出す固定語彙の診断行（`{"code":"unavailable","message":"stream-exec requester went away; exec cancelled"}`）で行う

**再評価条件**: plugin-cri が channel の end を他のプロセスへ渡すようになったとき（B を足す）、Linux 以外へ同じ helper を広げるとき（AF_UNIX の `POLLHUP` の意味を確かめ直す）、`SERVE_STEP` を変えるとき。

**後続の作業単位**:

| issue | 内容 |
| ----- | ---- |
| #4166 | (a) supervisor の `sys/linux.rs` に `poll` の安全なラッパーと `libc_abi` の照合、具体値の単体試験 (b) `ExecLaunchIo` に取り消し判定の任意項目を足し、構築箇所 6 つ（cli の `commands/exec.rs` を含む）は `None` (c) `respond_and_collect` の `stop` と `Lost` の後の待ちに取り消しを足し、取り消しなら `kill_and_reap` → 既存の cleanup (d) helper の `serve` が fd 0 の判定を渡し、`Failed(Unavailable)` と区別できる診断・監査を出す (e) plugin-cri の `exec_launcher.rs` の doc に channel を閉じない契約を書く (f) 試験: channel を閉じて 2 秒以内に終わる・exec のプロセスが残らない・開いたまま長い期限で待つ間は止まらない・判定が失敗しても期限で終わる・既存の期限と `hold_grace` の試験が通る (g) `helper.rs` のモジュール doc の残余の更新。clippy は `--all-targets` と `--lib --bins`、`cargo check --workspace --all-targets` |
| #4167 | `stream_exec_real.rs` に要求元役を SIGKILL する場面、`cri_exec_real.rs` に plugin-cri を SIGKILL する場面を足し、2 秒以内とプロセスの不在を照合（期限は 60 秒以上）。成功行の変更に合わせ `ci.yml`・`real-machine-tests.md`・`AGENTS.md` を同じ PR で整合し、本書の「停止」の残余・「残るもの」の Exec の残余・期限の一覧の「未実装」を更新 |

### Attach（SUP-4・SUP-7・REPAIR-3・REPAIR-5）

**段階 1（#3763。読み取り専用）**:

- 出力は supervisor の回転ログ（`@container-logs`。CRI のコンテナも `TeeLogSink` で書く）を follow する。`tail 0` で現在の末尾から追い、スナップショットは出さない
- レコードのタグ（`stdout` / `stderr` の接頭辞とスペース 1 つ）で 2 本の `AsyncRead` に分け、タグを外して LF つきで流す。要求していない stderr は捨てる
- stdin・tty の要求は backend が `INVALID_ARGUMENT` で拒否する（必須）。URL の発行前（RPC 時）にも拒否するのが望ましく、#3753 の結線情報に「attach は読み取り専用」を載せる形で #3763 が判断する
- follow は blocking のポーリング（`FOLLOW_POLL_INTERVAL` 200 ms）なので、セッションごとに専用スレッド（または `spawn_blocking`）で回し、`exited` の future へ橋渡しする。終了は既存の終了条件（sink のロックの解放かつ Running でない）を `exited` に写す。期限は follow の上限 24 時間（`MAX_FOLLOW_DURATION`）とセッションの idle 4 時間
- follow には取り消しの口が無く、期限と書き込みの失敗でしか終わらない。drop の後も期限まで残らないよう、reader に取り消し（停止フラグ）を足す。これは supervisor の変更で、#3763 の範囲に含める
- 制限: 遅延は最大 200 ms とポーリングの読み取りの時間。LF の無い行は出ない（1 行の上限は 64 KiB）。restart の再 launch の間も追従が続く（完全版との違い）。世代数 1 の設定は拒否される（既定は 1 MiB × 3 世代）

**段階 1 の実装（#3763。実装済み）**:

- 置き場: plugin-cri の `streaming/log_attach.rs`（`LogFollowAttachBackend`）。`production_stream_dispatcher(attach)` が `AttachHandler::read_only()` に包んで結線し、`main.rs` が `CriPluginBackends::log_attach_backend()` で作って `bind_production_streaming` へ渡す（作れなければ起動しない）
- RPC 時の拒否（現在は非 Linux の読み取り専用の結線だけ。Linux は #4078 で対話可能になった）: `StreamWiring` に `attach_interactive`（既定 false）を足した。`AttachHandler::read_only()` の結線は宣言せず、`attach_impl` が `require_attach_options` で stdin・tty を URL の発行前に `INVALID_ARGUMENT`（`attach with stdin or tty is not supported`）で断る。`issue()` も同じ位置で断る（多層防御）。接続時は backend も同じ文言で断る
- follow の実行: セッションごとに専用の `std::thread`（blocking プールを使わない）で `read_container_log_with_cancel`（`tail 0`・stream 絞り込みなし）を回し、supervisor の `RecordDemux` がタグを外して stdout / stderr へ分ける。tokio への橋渡しは std の `UnixStream::pair` 3 組（stdout・stderr・終了通知）で、tokio の feature は増やしていない。背圧は socketpair のバッファ。同時数の上限は 64（超えたら `RESOURCE_EXHAUSTED`）
- 終わり方: supervisor が `FollowEnd`（`Stopped`・`LogRemoved`・`Deadline`・`Cancelled`）を報告する。`Stopped`・`LogRemoved`・`Cancelled` は読み口が EOF で終わり、`Deadline` と読み取りの失敗は EOF の後に読み口が `io::Error` を返す（セッションは Success にしない）。どの場合も終了通知を完了させる
- 取り消し: 読み口と終了通知の future が取り消しの旗を共有し、最後の 1 つが drop されたら旗が立つ（セッションの終了・切断・idle・停止）。follow は次のポーリング（200 ms）の前に旗を見て、書き込みが詰まっていても 200 ms 刻みで旗を見る
- 状態の問い合わせ: `AttachProbe`（本番は `StateStore` の `get`。不在は `NOT_FOUND`、Running でなければ `FAILED_PRECONDITION`、読めなければ `UNAVAILABLE`）。CLI の `container_activity` と同じ写像で、数行の重複は supervisor への集約を別 issue とする

**完全版の方式比較**（評価の核心は単一スレッド制約。[restart-relaunch-single-thread.md](restart-relaunch-single-thread.md)）:

| 案 | 内容 | 単一スレッド制約との干渉 | 判断 |
| -- | ---- | ------------------------ | ---- |
| A1 | 制御チャネルに固定長の種別を足し、supervisor がコンテナの init の stdin の書き込み端（tty なら pty master）の複製を SCM_RIGHTS で plugin-cri へ渡す。中継と resize（`TIOCSWINSZ`）は plugin-cri のプロセス内で行う。出力は捕捉からの tap（下の「完全版 Attach の設計（#3765）」D2。当初案の follow から変更） | 受け渡しは accept ループの 1 要求で、`PausableServer::pause` の既存の対象に入る。supervisor にセッションのスレッドが残らない。再 launch の後は新しい世代の stdin / pty になり、旧い複製は EPIPE で終わる | 採用（本命）。Exec の fd 渡しの部品（sys の複数 fd 送受信）と同じ形 |
| A2 | supervisor がコンテナごとに attach 用の UDS を listen し、接続ごとに中継スレッドを持つ | 2 本目の accept ループと最長 4 時間の中継スレッドが pause の対象になる。読まないクライアントが中継を詰まらせると pause が期限切れで失敗し、再 launch が `RelaunchFailed` から Stopped へ倒れる（attach のクライアントが restart を止められる）。peer の検証・ソケットの権限・PSS（SUP-2）も増える | 不採用 |
| A3 | core の `ContainerRuntime` に attach を足す | core に常駐プロセスが無く（CORE-1）、拡張点トレイトの変更になる（PLUG-1・PLUG-4） | 不採用 |

A1 の注意: 渡した pty master の複製を plugin-cri が読むと捕捉のデータを奪うので、書き込みと resize にだけ使う（契約）。`stdin_once` は最初の attach で所有を移し supervisor が自分の端を閉じる方向で検討する。同じ uid の範囲で増える能力は exec と同じ（rootful は対象外）。CreateContainer の `stdin`・`stdin_once`・`tty` の反映、init の stdin / pty の保持者、種別の frame、`stdin_once` は次の「完全版 Attach の設計（#3765）」で決めた。そこで出力は「段階 1 と同じログの follow」ではなく捕捉からの tap に改めた（LF 待ちでは tty のプロンプトが出ないため）。

### 完全版 Attach の設計（#3765・CRI-6・SUP-4・SUP-7・SEC-1・PLUG-1・REPAIR-2・REPAIR-3・REPAIR-5）

本節の内容は未実装で、設計の決定と子 issue への分解だけを書く（REPAIR-3）。方式は上の比較表の A1 を維持し、詳細を次のとおり決める。cri の注入トレイト（`AttachBackend` / `AttachSession`）は変えない。

**D1. 制御チャネルの種別（A1 の詳細）**

- kind 9 の `AttachRequest` を足す。固定長で、payload は期待する pid（u32）・要求のマスク（stdin・stdout・stderr）・tty の期待値・予算（ms）の 4 つに限り、64 バイト以内に収める。既存 frame と同じく big-endian で、壊れた値を表現できない型にする（REPAIR-2）。`VERSION` は上げない。古い supervisor は未知の kind を `Malformed` で拒否するので安全に失敗し、plugin-cri は `UNAVAILABLE` 相当として扱い縮退しない
- 応答は 1 回だけ: `Response(Ok)` と、マスクに対応する fd を SCM_RIGHTS で最大 3 本。非 tty は stdin の書き込み端・stdout の tap・stderr の tap、tty は master の複製・stdout の tap。送信は #3759 の複数 fd 送信を使う。拒否のときは fd を添えない
- `ControlReason` に `StdinNotOpen`（作成時に stdin を開いていない）・`TtyMismatch`・`StdinClosed`（`stdin_once` で消費済み）を足す。値の割り当ては子 issue で確定する
- （C6〔#4075〕で実装済み）payload は pid（u32）・mask（u8。bit0 = stdin・bit1 = stdout・bit2 = stderr）・tty（u8）・期限（u64）の 14 バイトで、全長 22 バイト。**予算（ms）は絶対期限（`CLOCK_MONOTONIC` の ns）に替えた**: 既存の frame はすべて絶対期限を載せており、相対値にすると受信の遅れの分だけ送信期限が延びて protocol.rs 冒頭の REPAIR-5 の根拠に反するため。サーバは残りが `ATTACH_ROUND_TRIP_BUDGET`（5 秒）を超える要求を `Malformed` で断り、クライアントは接続・Hello・要求・応答のすべてを呼び出し側の期限と 5 秒の早い方で打ち切る。tty = 1 と stderr の併用は `Malformed`。fd の並びは「入力 → stdout の tap → stderr の tap」のうち mask で指定したものだけ。`ControlReason` は `StdinNotOpen` = 15・`TtyMismatch` = 16・`StdinClosed` = 17。クライアントは `Malformed`・`TooLarge`・`UnsupportedVersion` を `Unavailable`（"the supervisor does not support attach"）として扱い、fd を受け取らない。受け取る側の境界（本数・`truncated`・種別。stdin は FIFO か socket、tap は socket、master は`PtyMaster::from_received`）は `ControlAttach` が検証し、1 つでも違えば全 fd を閉じて `Internal` を返す
- サーバの手順: 事前の照合（何も取り出さない）→ tap の購読（ロックの外。ハブは `SignalSlot::with_output_capture` で渡す）→ 確定（ロックの下で再照合して取り出す）→ 期限の確認 → 送信。tty の判定は、要求 tty が偽で master がある → `TtyMismatch`、真で master が無い → stdin の端があれば `TtyMismatch`・無ければ `NoHandle`。master の複製に失敗した tty のコンテナと `--stdin` の無い非 tty は区別できず、どちらも拒否する安全側で、tty の正式な照合は D7（C10）が担う
- 単一スレッド制約との関係: 要求は accept ループの中で 1 往復で終わり接続を保持しない（exec のガードとは違う）。このため `PausableServer::pause` に新しい参加者が増えず、supervisor にセッション用のスレッドも残らない。supervisor が持つのは世代ごとの fd だけである。このため [restart-relaunch-single-thread.md](restart-relaunch-single-thread.md) の表に行は足さない。常駐 listener（A2）を採らない理由は比較表のとおり

**D2. 出力は捕捉からの tap（A1 の「ログの follow」を改める）**

- ログの follow は LF までの完全な行しか出さず（`sup7_follow_waits_for_lf`）、ポーリングは 200 ms なので、LF の無い対話シェルのプロンプトが attach に届かない。そこで完全版の出力は、既存の捕捉のリーダーが sink へ書いた後に、購読者ごとの非ブロッキング socketpair へ生のバイト列を複製（tap）して渡す。tty と非 tty の両方に適用する
- tap は既存のリーダースレッドの中で動くので新しいスレッドが要らず、再 launch の前の `quiesce` の範囲に収まる
- 契約: sink への書き込みを常に優先する。`EAGAIN` や書き込み失敗の購読者はその場で切断し op ログに残し、背圧はかけない（SUP-7 のログを止めない）。購読者数にコンテナごとの上限を置く（初期案 8）。購読した時点より後の出力だけを流す。capture の EOF と世代交代で tap を閉じ、これが attach の終わりになる
- 却下: follow のまま部分行を出す案（レコード形式に部分行の印が要り CLI の logs にも波及し、遅延も残る）、非 tty だけ follow を残す案（出力の経路が 2 本になり終了の意味も揃わない）。段階 1（#3763）の follow は完全版の結線で置き換え、reader の取り消しの口は残す

**D3. init の stdin / pty を作り保持する主体**

- 作るのは core の本番 launcher で、supervisor が起動オプションで要求する。stdin は `LaunchOptions` で開く指定を足し、core が pipe を作って読み取り側を子の fd 0 にし、書き込み側を `LaunchedProcess` から取り出す。（stdin の段は C1〔#4069〕で実装済み。API は `LaunchOptions::with_stdin(LaunchStdinMode::Pipe)` と `LaunchedProcess::take_stdin`）tty（`process.terminal: true`）は、子がコンテナの mount namespace と devpts の中で `/dev/ptmx` を開き、slave を fd 0〜2 にして `setsid` と `TIOCSCTTY` で制御端末にし、`/dev/console` へ bind し、master は既存の子から親への SCM_RIGHTS（seccomp listener と同じ経路）で返す。pty の sys ラッパーと開く位置は、exec は #3758 の決定（Landlock / seccomp の再適用の後）を再利用する。launch の init だけは、`/dev/console` への bind（`open_tree`・`move_mount`）が seccomp の拒否集合にあり `CAP_SYS_ADMIN` も要るため、割り当てと bind を pivot 後・ステージ列の前（runc の `setupConsole`・`mountConsole` と同じ位置）へ置く（#4071。割り当てた slave は `process.user` へ所有者を補正する）。ホストの devpts では割り当てない
- core の `process.terminal` の拒否は、supervisor が端末対応を opt-in したとき（例: `with_terminal_support()`）だけ外す。master を捕捉しない呼び出し元は従来どおり拒否する（fail-closed）
- 保持するのは supervisor で、`control/target.rs` の `SignalSlot` と同じ置き場所に世代ごとのスロットを持つ。`Exited` と再 launch で落とし、新しい世代の fd に差し替える。tty では master を捕捉の stdout 1 本として `LogCapture` へ渡し、`EIO` は EOF とみなす（CRI のログは stdout のタグだけになる）
- 渡した master の複製を plugin-cri が読むと捕捉のデータを奪うので、書き込みと `TIOCSWINSZ` にだけ使う（契約）
- （C4〔#4074〕で実装済み）保持の置き場所は `SignalSlot` の `SlotState::Active` の中の `GenerationIo`（stdin の書き込み端・master の複製・`stdin_consumed`。`ControlledProcess::new` がスロットへ移す）。`Exited`・`clear`・世代交代の `register` で必ず落ちる。tty の master を捕捉の stdout 1 本にする振り分けは、`take_output` と `ControlledProcess::new` の順が起動と再起動で逆になるため、構築の時点で分ける `attach_io::AttachIoProcess::wrap` に置く（起動は `launch_prepared`、再起動は `LauncherRelauncher::relaunch` が launch の直後に適用）。端末対応の opt-in は start と再 launch の launcher だけ（`with_terminal_support`）で、`SpecCapturingLauncher` が `supports_terminal` を転送する。tty では core の stdout / stderr の pipe を閉じる（init が pty の slave で fd 1 / 2 を置き換えた後に `launch` が戻るため、書き込み端は残らない）。master の複製に失敗したときはログの捕捉を優先し、attach の口だけを閉じる（C6 は `NoHandle`）
- 入口は argv の `--stdin <open|once>`（`StdinOption`）。指定があれば常に core へ `LaunchStdinMode::Pipe` を渡す。tty と `Pipe` の併用は core が launch の fork 前に `InvalidArgument` で拒否する（#4069）ため、**C8 は tty のコンテナに `--stdin` を渡さない**（tty の入力は master が担う。tty の stdin の可否は cri の D7 が RPC の時点で判断する）。supervisor は config.json を先に読んで分岐しない（TOCTOU になるため）。再評価の候補: core に tty なら `Pipe` を無視する `LaunchStdinMode` を足す案（core の API 変更になるため C8 / C10 で判断する）
- fail-closed（D8）: 端末または `--stdin` を期待したのに master・書き込み端が届かない起動・再起動は、報告で ERR にしてプロセスを回収する（弱いコンテナを動かさない）

**D4. CRI から supervisor への運び方**

- tty: cri の `bundle/spec.rs` が `process.terminal: true` を config.json に出す（OCI の標準の欄）
- stdin・stdin_once: OCI の config.json に欄が無いので、cri が CreateContainer で値を記録（再採用用の永続記録を含む。[cri-record-readoption.md](cri-record-readoption.md)）に保存し、StartContainer で core の `StartRequest` に 3 値の enum（例: `StdinMode::{Closed, Open, Once}`）として載せる。`with_log_path` と同じ builder の形にする。plugin-cri の `supervised.rs` が supervisor の argv に `--stdin <open|once>` を付ける（plugin-cri 専用。`start_contract` の契約に足す）。plugin-cri は起動オプション文書（FCOPT1）を書かないので使わない
- 対応づけの位置（C8・#4076）: tty の有無と `stdin` / `stdin_once` から `StdinMode` を導くのは cri（`ContainerRecord::start_stdin_mode`。tty なら常に `Closed`、D3 のため）。`StdinMode` から `--stdin` の値への写しは plugin-cri（cri は supervisor に依存しない）。未知の `StdinMode` は起動前に `Unimplemented` で断る
- 依存の向きは plugin-cri から cri / supervisor / core、supervisor から core のままで、新しい辺も外部依存も増えない（PLUG-1）

**D5. `stdin_once`**

- 非 tty で `stdin_once` のとき、最初に stdin を要求した attach へ複製ではなく元の書き込み端を渡し、supervisor は自分の端を閉じる（所有の移転）。セッションの stdin が終端になると plugin-cri が drop し、コンテナは EOF を受ける。その後の stdin の要求は `StdinClosed` で断る
- tty の `stdin_once` は閉じない。containerd の `container_io.go` の `Attach` は `StdinOnce && !Tty` のときだけ stdin を閉じ、コードの上のコメントは tty も閉じると読めるが挙動はコードに従っているため、本設計もコードに従う
- （C6〔#4075〕で実装済み）`Once` の元の端は、送信に成功したら supervisor が drop する。**送れなかったときは、同じ世代がまだ `Active` で`stdin` が空のときだけ端をスロットへ戻し、消費済みを取り消す**（戻さないと失敗した attach がコンテナの stdin を閉じてしまう）。fd がカーネルに受理された後の失敗は戻さない（端は相手にある）。残る問題: `sendmsg` が成功した直後にクライアントが期限切れで接続を閉じると、`Once` の端は渡った後にカーネルが閉じ、コンテナは EOF を受ける。絶対期限とクライアントの余裕で窓を小さくするが、なくせない
- `stdin_once` でないときは毎回複製を渡し、supervisor が自分の端を持ち続けるのでセッションが終わってもコンテナは EOF を受けない。再 launch で世代が変わると新しい pipe を作り、消費済みの状態も初期化する

**D6. resize・終了・複数の attach**

- resize: plugin-cri が持つ master の複製へ core の安全なラッパー（#3758）で `TIOCSWINSZ` を発行する。supervisor との往復は無い。初期の寸法は既定値のままで、kubelet の最初の resize で決まる
- 終了: tap の EOF と既存の kind 8 の `ExitWatch` から `exited` を作る。ポーリングはしない（主経路の話。実装〔#4077〕は ExitWatch の枠の上限 8 により `Transient`〔`Busy`〕になりうるため、`Transient` と `NoSupervisor` のときだけ状態ストアの照会〔1 秒刻み〕へ退避する逸脱を持つ）
- 複数の attach: 同時に attach してよい（containerd と同じ）。stdin は各セッションの複製から並行して書かれ、混ざりうる。出力は各セッションが自分の tap を持つ

**D7. RPC 時の整合検査（cri）**

- stdin を開いていないコンテナへの stdin の要求、およびコンテナの tty の実体と要求の tty が違う場合は `FAILED_PRECONDITION`（固定の英語文）で断る（fail-closed）。containerd は stdin を黙って無視するので差がある

**D8. 拒否を外す順序（fail-closed の段階）**

- `bundle/spec.rs` の `unsupported("tty/stdin")` を外すのは最後の実装 issue（C10）だけにする（**#4078 で解除済み**。tty は `process.terminal` へ写り、stdin / stdin_once は記録と StartContainer で運ぶ）。それまでの途中の状態では拒否を残し、要求より弱い挙動のコンテナ（stdin が `/dev/null`、端末が無い）を作らせない。core の `process.terminal` の拒否は D3 の opt-in で段階的に外す。shim v2 の terminal の拒否（`task_service.rs`）は本件の範囲外でそのまま残す

**D9. SEC-1 と OWASP の観点**

- 受け取った fd を plugin-cri 側で検証する: stdin の端は FIFO か socket、tap は socket、master は devpts の ptmx の文字デバイス。ディレクトリの fd は拒否する（`ChildStdio::from_fds` と同じ理由）。本数・`MSG_CTRUNC`・マスクとの不一致はすべて拒否し、受け取った fd は drop で閉じる
- 信頼境界は既存のまま（同じ uid・0600 のソケット・`SO_PEERCRED` の照合）。master の複製で増えるのは PID 1 の入力を注入する能力で、exec と同じ範囲に収まる。rootful は対象外
- コンテナへ渡るのは pipe の読み取り側と slave だけ。書き込み端・master・tap の fd は close-on-exec で `close_inherited_fds` の対象とし、fd 漏れ（CVE-2024-21626 型）の対策を維持する
- 新しい `unsafe` は各 crate の `sys` の事前承認の範囲に限り、`sys` の外には作らない。トークン・コンテナ ID・入出力の内容はログやエラーに出さない
- 無制限確保をしない（payload は固定長、購読者数に上限、tap は溢れたら切断）。kind 9 の往復は 5 秒（REPAIR-5）。セッションの期限は既存の attach のものを使う

**D10. オーナー確認事項（決定扱いにしない）**

1. D7 の containerd との差（黙って無視せず断る）
2. tap の購読者の上限の値
3. tty の `stdin_once` で閉じないこと（containerd のコードとコメントの食い違い）
4. tty の CRI ログで LF の無い出力が遅れて出ること（CRI ログの部分行 `P` は範囲外）

**範囲外**: CLI の `create -i -t`（CLI-1）、shim v2 の terminal、CRI ログの部分行 `P`。追跡の issue が要るかは C11 の時点で判断する。

**子 issue（いずれも #3765 の sub-issue、2h 以下）**

| 子 | issue | 内容 | 依存 |
| -- | ----- | ---- | ---- |
| C1 | #4069 | core: init の stdin パイプ（実装済み: `LaunchOptions::with_stdin(LaunchStdinMode::Pipe)` と `LaunchedProcess::take_stdin`。書き込み端は close-on-exec かつ fd 3 以上。supervisor のラッパーの `take_stdin` の転送は C4） | なし |
| C2 | #4070 | core: init の pty と master の返却（実装済み。受信は exec 前の 2 行目の判定の後。stdout / stderr の pipe は起動前の診断のため残す。supervisor の opt-in は C4） | #3758 |
| C3 | #4071 | core: slave を `/dev/console` へ bind（実装済み。割り当てと bind は bind の特権要件から pivot 後・ステージ列の前。D3 の補足） | C2 |
| C4 | #4074 | supervisor: stdin 端・master の保持、tty 捕捉、`--stdin`（実装済み: `attach_io::AttachIoProcess`・`SlotState::Active` の `GenerationIo`・`SignalSlot::with_stdin_option` / `with_generation_io`・argv `--stdin <open\|once>`。kind 9 は C6） | C1・C2 |
| C5 | #4072 | supervisor: 捕捉からの出力の tap（実装済み。sink 優先・背圧なし・溢れたら切断・購読者数の上限 8 は初期案。購読 API は `CaptureHub::subscribe_output`、kind 9 での受け渡しは C6） | なし |
| C6 | #4075 | supervisor: kind 9 `AttachRequest` と fd 応答（実装済み: `control::protocol` の `AttachRequestFrame`・`control::server` の `handle_attach`・クライアント入口 `AttachIoSource` / `ControlAttach`。結線は C9） | C4・C5・#3759 |
| C7 | #4073 | core: `StartRequest` の `StdinMode`（実装済み。`StartRequest::with_stdin` / `stdin`、既定 `Closed`。値の参照は C4・C8） | なし |
| C8 | #4076 | cri: 記録への保存と StartContainer での運搬（実装済み: 記録の config〔永続記録 v1 のまま〕から `start_stdin_mode` で導き、`RuntimeAdapter::start_with_options` が `StartRequest::with_stdin` に載せる。plugin-cri の `supervised.rs` が `StartOptions::with_stdin` で argv `--stdin <open\|once>` へ写す。`bundle/spec.rs` の `tty/stdin` の拒否は C8 の時点では C10 まで残していたが、#4078 で解除済み） | C7・C4 |
| C9 | #4077 | plugin-cri: 完全版 `AttachBackend`（実装済み: Linux の `streaming::supervisor_attach::SupervisorAttachBackend`。状態確認 → kind 9 の `AttachIoSource::obtain` → `validate_attach_io` で形を再照合 → 入力は専用スレッド＋socketpair、tap は tokio 化、resize は `PtyMaster::resize`、`exited` は tap の EOF と kind 8 の購読。`CriPluginBackends::supervisor_attach_backend` が組み `main.rs` が Linux で使う。C10 の前の状態の記述。現在は #4078 で `ProductionAttach::interactive` により `read_only` を外し、Linux の本番で届く） | C6・C8・#3763・#3754・#3761 |
| C10 | #4078 | cri: 拒否の解除と整合検査（実装済み: `bundle/spec.rs` の拒否を外し tty を `process.terminal` へ写す。`attach_impl` が URL の発行前に記録から 1 回のロックで状態・`config.tty`・`config.stdin` を読み、未知 ID は `NOT_FOUND`、running でない・tty の不一致〔どちらの向きも〕・stdin 未開への stdin 要求は `FAILED_PRECONDITION`〔固定文 `MSG_ATTACH_*`〕。stdin は `start_stdin_mode` でなく `config.stdin` を直接見る〔tty のコンテナでは常に `Closed` で、supervisor は tty に master を渡すため、stdin なしの tty コンテナへの入力の注入を断れるのはここだけ〕。plugin-cri の `ProductionAttach::interactive` で `read_only` を外す。containerd との差は設計の既定のままで D10-1 はオーナー確認事項） | C3・C9 |
| C11 | #4079 | 実機前提試験・手順・CI の追記 | C10。実装済み: `crates/plugin-cri/tests/cri_attach_real.rs` の `production_binary_attach_real`（非 tty・stdin_once の往復と EOF、tty の往復と resize の `stty size`、tty 不一致の拒否）。platform-ci の ubuntu に 2 ステップ。実 crictl・kubectl での確認は人間担当（#3730 の子） |

### PortForward（NET-3・SEC-1）

**NODE（#3755）**:

- host netns の `127.0.0.1:<port>` だけへ `dial_timeout`（10 秒）で接続する。接続先は要求から組み立てず loopback に固定する（SEC-1）。`::1` は試さない（fail-closed）
- NODE が先に成り立つ理由: NODE ネットワークでは network namespace の要素を作らず（host netns）、本番の `NetworkReady` は false なので、現状 kubelet が受ける Pod は hostNetwork だけである
- NODE か POD かは、cri が RPC の時点で sandbox の記録（保存済みの `config` の `namespace_options.network`）から決め、発行時の要求に保存して dialer へ渡す。#3755 で `PortForwardDialer` の引数に対象の型（例: `PortForwardTarget { pod_sandbox_id, network: Node | Pod }`）を足す。URL やヘッダから組み立て直さず、plugin-cri に記録の解析を複製しない（REPAIR-1）
- hostNetwork の Pod の port-forward はホストの loopback 上の任意のサービスへ届く。これは hostNetwork の性質で、認可は単回トークンの URL と kubelet / apiserver 側が担う
- 実装（#3755）: `runtime_service::port_forward_network` が `namespace_options.network` がちょうど `NODE` のときだけ `Node` とし、未指定・POD・CONTAINER・TARGET・未知の値は `Pod`（fail-closed。`wants_pod_network` は CONTAINER・TARGET を「POD でない」と扱うので流用しない）。`port_forward_impl` の順序は 結線 → 入力検証 → sandbox の照合（`NOT_FOUND`）→ POD の拒否（`UNIMPLEMENTED "port-forward for pod network is not implemented"`。トークン枠を消費しない）→ 発行。dialer は port 0・期限 0 を `INVALID_ARGUMENT`、期限切れを `TIMEOUT`、その他を `UNAVAILABLE` の固定文で返し、成功後に `peer_addr` が loopback であることを確かめる。`PortForwardDialer::supports_pod_network`（既定は偽）を真にした dialer を注入すると結線情報の POD 対応が立ち、RPC 時の拒否が外れる（#3766 が使う）
- 残余: URL 発行後に sandbox が消えても dialer は記録を照合しない（トークン TTL 60 秒とセッションの idle の期限で有界）。停止時の Upgrade 後のセッションはドレインの期限の後に強制クローズする（「停止時のセッションの扱い」）。実行中の blocking の dial（最長 10 秒）は abort できず、ランタイムの `shutdown_timeout`（1 秒）が打ち切り、待ちは増えない

**POD（#3766）**: #2877（pod の namespace 保持役）が入るまで `UNIMPLEMENTED` とする。URL の発行前に断るのが望ましく、#3753 の結線情報で扱う。dialer 側でも `CriError::unimplemented` を返す（多層防御）。候補は、単一スレッドの helper が保持役の fd で pod の userns・netns へ入って connect し接続済みの fd を SCM_RIGHTS で返す案と、保持役に connect を頼む案（保持役の攻撃面が広がるので劣後）で、最終判断は #3766 に置く。

### 期限の一覧（REPAIR-5）

| 待ち | 値 |
| ---- | -- |
| 制御チャネルの connect と Hello | 既存 |
| kind 6 の pidfd の受け渡し | 5 秒（全体の内側） |
| kind 7 の ack | 10 秒 |
| `launch_timeout`（helper の起動から `Started` まで） | 30 秒 |
| exec の全体の上限 | 3600 秒（`MAX_EXEC_HOLD_SECS`。CLI の `--timeout` の上限。確認事項 1） |
| ガードの保持 | 期限 + 30 秒 |
| helper の回収 | 5 秒 |
| stdin の stall | 60 秒 |
| 流し切り / 最後の送出 | 各 5 秒 |
| ストリームの作成 | 30 秒 |
| idle | 4 時間 |
| attach の `backend_timeout` | 10 秒 |
| kind 9 の attach の fd の受け渡し（往復） | 5 秒 |
| follow のポーリング / 上限 | 200 ms / 24 時間 |
| attach の follow スレッドの書き込みの刻み（取り消しの確認） | 200 ms |
| PortForward の dial / 対の揃い / 書き込みの stall | 10 秒 / 30 秒 / 30 秒 |
| `StreamingServer` の SIGTERM での停止 | 受信の検知（100 ms 周期）で待ち受けを閉じる（待ちなし。#3754）。受け付け済みのセッションはシグナルから 5 秒（`STREAMING_DRAIN_WAIT`）ドレインし、期限で exec を止めて 1 秒（`STREAMING_CLOSE_WAIT`）待ち、残りを強制クローズする。gRPC の猶予 10 秒以内に収まり、streaming は全体の上限を延ばさない（全体は #4340 で op-stats の最後の書き出し 1 秒が別に足されて 14.7 秒）（#4164。暫定値で #4116 の対象） |
| helper の fd 2 の読み手（#4171） | 読み取りの刻み 100 ms / 停止後の drain 50 ms / 終了時の待ち 500 ms / 絶対期限 25 秒 + 3600 秒 + 30 秒 |
| 要求元の切断の検知（helper の serve の刻み）/ 検知から helper の終了まで | 20 ms / 合否値 2 秒（通知処理のない通常ケース。遅延・回収失敗ケースは検知最大 5 秒・回収込み 約 15 秒。期限と `hold_grace` は不変）。#4165。実装済み（#4166）。実機前提試験は `stream_exec_real` の `requester_killed` と `production_binary_exec_real` の段 4（#4167） |

### 実装単位と兄弟 issue の対応

| issue | 内容 | 範囲の変更（issue 本文の想定との差） |
| ----- | ---- | ------------------------------------ |
| #3753 | 結線済みの種別だけ URL を発行する | 実装済み（種別単位の結線情報 `StreamWiring` のみ。下の「結線情報（#3753・REPAIR-3）」）。attach の読み取り専用（#3763。`attach_interactive` として実装済み）・POD 未対応（#3766）・exec の相対 argv[0]（#3761）を RPC 時に断る情報は、`StreamWiring` に項目を足して各 issue が入れる |
| #3754 | `StreamingServer` の起動・注入 | 実装済み（plugin-cri の `streaming`。下の「plugin-cri での起動と停止（#3754）」） |
| #3755 | NODE の dialer | 実装済み。cri の `PortForwardDialer::dial` の引数を `PortForwardTarget { pod_sandbox_id, network: PortForwardNetwork }` にし、`StreamRequest::PortForward { request, network }` と `StreamWiring::port_forward_pod_network`（既定は偽）を足した。plugin-cri の `NodeLoopbackDialer`（`streaming/node_dialer.rs`）が `127.0.0.1:<port>` へ接続する |
| #3756 | 試験 | — |
| #3757 | `ExecLaunchIo` と core の stdio 拡張 | — |
| #3758 | core の pty | コンテナの devpts で worker が開き、master は core の既存の worker から親への SCM_RIGHTS で返す |
| #3759 | supervisor: helper と plugin-cri の channel の frame codec、sys の複数 fd 送信の一般化（安全な公開 API） | 制御チャネルの新しい種別は足さない（kind 6 / 7 を再利用） |
| #3760 | supervisor: bin の `stream-exec` 入口（単一スレッドの helper）が kind 6 / 7 と `run_command_with_pidfd_*` を呼び、結果を返す | 常駐の supervisor 側の受け口ではなく helper |
| #3761 | plugin-cri の本番 launcher | 実装済み（tty は本番で fail-closed。supervisor 側の pty 結線は後続。上の「本番 launcher の実装」）。helper の起動・fd の送信・tokio の橋渡し・drop で kill・ローカルの resize・全体の上限 |
| #3762 | 実機前提試験 | — |
| #3763 | plugin-cri の読み取り専用 attach | 実装済み（supervisor の reader の取り消しの口・`FollowEnd`・`RecordDemux` を含む） |
| #3764 | docs の更新 | 実装済み（冒頭の表と「残るもの」） |
| #3765 | 完全版 attach（A1 を本命として設計と分解） | 設計済み。子 issue は「完全版 Attach の設計（#3765）」を参照 |
| #3766 | POD の port-forward の設計と分解 | — |
| #4165 | 要求元の異常終了の検知方式の選定 | 設計済み（Exec 節の「要求元の異常終了の検知」） |
| #4166 | 検知の実装（sys の `poll`・`ExecLaunchIo` の取り消し口・helper） | 実装済み |
| #4167 | 検知の実機前提試験 | 実装済み（`stream_exec_real` の `requester_killed`・`production_binary_exec_real` の段 4） |

### 未確認・オーナー確認事項

決定扱いにしない。

1. CRI のストリーミング exec の全体の上限を、当面 3600 秒（kind 7 の保持の上限）とする。kubelet の idle 4 時間より短く、長い対話セッションは 1 時間で止まる。代案は保持の更新（heartbeat）や上限の分離で、オーナー判断
2. `::1` を接続先に足すか（containerd の挙動は一次情報で未確認）
3. pty をホストの devpts で代わりに割り当てる方式は採らない（変えるならオーナー判断）
4. argv[0] の PATH の解決（#2439）が出るまでは、相対パスを拒否する
5. 観測名の語彙（exec-pidfd-handover.md §6 の未決事項が CRI の exec にも及ぶ）
6. `SetupFailed` の終了コードの扱いと containerd との比較（未確認）

CRI の `ExecSync`（現状 `UNIMPLEMENTED`）も本設計の helper を再利用できる見込みだが、本件の対象外である。

## 残るもの

実装済みは Exec の本番 launcher（#3761。Linux のみ）、読み取り専用の Attach（#3763）、NODE の PortForward（#3755）。未実装の組は次のとおり（REPAIR-3）。

- 完全な Attach（stdin・stdin_once・tty・resize）: 実装済み（#4077・#4078。dispatcher の `read_only` と bundle の拒否は解除済み）。実機前提試験・手順・CI も済み（#4079）。残るのは実 crictl・kubectl での確認（人間担当）。#3765（設計のみ・closed）の子 issue で追う。個別の状態は「完全版 Attach の設計（#3765）」の子 issue 表を正とする
- POD ネットワークの PortForward: 設計と分解は #3766、前提は保持役 provider の #2877。RPC 時と dialer の両方で `UNIMPLEMENTED`
- Exec の tty（supervisor 側の pty 結線と helper の `--tty`。受け側は実装・試験済み）: 追跡 issue 未起票（親 #3726 の残り）。本番は RPC 時に `INVALID_ARGUMENT`
- Exec の相対 argv[0]（PATH 解決）: #2439 の判断待ち。RPC 時に `INVALID_ARGUMENT`
- Exec の実機前提試験: #3762。完全版 Attach の実機前提試験は #4079（`production_binary_attach_real`）で実装済み
- Exec の残余: plugin-cri の異常終了時の helper の早期停止は #4112（#4166・#4167）で解消。残る窓は listener の受け渡し前・通知処理中の最大 5 秒の遅れ・channel の端の漏れだけ（`PtyMaster` の fd 検証は #4100 で解消）
- Exec の残余（診断）: 生成側は #4284 で入った。状態ストア等 core の `TraitError` 起因の段は errno が `none`（`TraitError` へ errno を持たせる案と、`require_stdio_kinds`・mask の不一致の実機前提の照合は #4327 で `stream_exec_real` に追加済み）
- Attach の残余: 入力の書き込みは、書き込み先の記述（`fstat` の `st_dev`・`st_ino`）ごとの排他で調停する。表は backend が持ち、生きた項目は入力スレッド数以下（上限 `MAX_ATTACH_SESSIONS`。満杯は共有へ縮退せず `RESOURCE_EXHAUSTED`）。pipe・socket は記述ごとに固有の inode、pty master は本番ではコンテナごとの devpts の inode のため、衝突は同じコンテナ内に限る。plugin 外の書き手が空きを使い切ると保持者は `write` で止まり、その間は同じ記述（同じコンテナ）の入力だけが進まない（別コンテナは進む）。同じ記述の他セッションの排他の待ちは取り消しで抜け、スレッド・fd・枠を返す（#4134・#4232・CRI-6・REPAIR-5）
- Attach の保持者本人の blocking write の取り消し（#4232 の残余を #4287 で pipe について解消。CRI-6・REPAIR-5・REPAIR-3）。比較: (A) スレッド宛てシグナルで `EINTR` にする案は、`sys::signal(3)` が BSD セマンティクス（`SA_RESTART`）で `write` が再開されるため `sigaction`（アーキごとの `struct sigaction`）・`pthread_self`・`pthread_kill` の新しい FFI 宣言とプロセス全体のシグナル配置の変更・`libc` の機械照合が要り、承認待ちで未実装。(B) `/proc/self/fd/N` を `O_WRONLY|O_NONBLOCK` で開き直して plugin-cri 専用の open file description にする案は pipe（FIFO）だけに採用した（`reopen_pipe_nonblocking`）: 記述が自分専用なので supervisor 側へ `O_NONBLOCK` が漏れず、`write` は `EAGAIN` で即戻って保持が有限になる。開く前に FIFO であることを `fstat` で確かめ、開いた後も FIFO と (dev, ino) の一致を照合し、元の記述はすぐ閉じる（唯一の書き込み端が閉じたときの EOF を保つ）。失敗・非対応のアーキ（`O_NONBLOCK` の定数は Linux の x86_64・aarch64 のみ）は従来の共有記述の経路へ戻る。pty master は開くと新しい pty が割り当てられて入力が別の端末へ流れ、socket は `ENXIO` のため開き直さない。(C) `send(MSG_DONTWAIT)`・`pwritev2(RWF_NOWAIT)` は pty に効かず版数依存。(D) fd の close・dup2 は blocking 中の `write` を戻さない。残余: pty・socket は共有記述のままで、plugin 外の書き手に空きを使い切られると保持者は `write` の中で止まる。ただし本番の stdin は pipe で、pty master へ書くのは plugin-cri の attach だけ（同じ排他で直列化され、supervisor の捕捉は読むだけ）のため、`poll` が Ready を返した後の書き込みは止まらず、この残余は本番では起きない見込み。同じ devpts instance の複数の pty master は同じキー（ptmx の dev/ino）に畳まれ、将来 attach がコンテナ内の別 pty を対象にするときは pty 番号をキーに足す必要がある（core の `PtyMaster` に番号の取得口が要る）。コンテナの終了で読み手が閉じれば pipe は `EPIPE`、pty は `EIO` で保持者は抜ける。再評価条件: plugin-cri への `libc` の dev-dependency 追加の承認（#3290・#1837 の子）・plugin 外の書き手が同じ stdin・pty master へ実際に書く経路の追加・止まった保持者による枠の枯渇の観測・attach が別の pty を対象にするとき
- 暫定値・設計の確認事項（exec の全体上限・同時セッション数・`::1`・終了コード・観測名など）: 上の「未確認・オーナー確認事項」と #4116（オーナー判断）
- rootful: plugin-cri の start が uid 0 を `UNIMPLEMENTED` にするため、rootful のコンテナは無く 3 RPC とも使えない（uid 0 の拒否は #2442、rootful を許すかは #2241 の判断待ち）
- 非 Linux: Exec は未結線の `UNIMPLEMENTED`。コンテナの start 自体も未実装（macOS の状態ルートは #2431）
- `ExecSync`: `UNIMPLEMENTED` のまま。追跡 issue 未起票。実装するときは Exec と同じインスタンスの記録と起動時の照合を入れる義務がある（#4286）
- Exec のインスタンス照合の残余（#4286）: (1) 識別子を報告しない実装・記録の無い旧い `state.json` は両側 `None` で保護されない（試験で固定）。(2) CRI の記録（`ContainerRecord`）は create 時のインスタンスを持たないため、`Exec` RPC より前に外で作り直されたコンテナには新しいインスタンスで URL が発行される（塞ぐには記録ファイルと再採用へインスタンスを持たせる必要があり、本件の範囲外）。(3) 照合の違反の観測は `ExecStreamOutcome::InstanceChanged`（コードと文 `MSG_EXEC_INSTANCE_CHANGED` の両方で判定）として他の起動失敗と区別され、操作別計装 `cri.exec.session`（`FAILED_PRECONDITION`）に加えて `cri.exec.instance_changed` の失敗として別の行にも出る（二重計上。60 秒周期の `op_stats` 行。#4324・CRI-6・REPAIR-4）。クライアントへの Status は `InternalError` のままで観測だけが分かれる。即時の構造化行は未実装
- 外部公開の TLS・認証（無い。opt-in の口は #4110 で plugin-cri の CLI に出した。前段の守りが前提）
- Upgrade 後のセッションの停止時のドレイン方針の再評価（REPAIR-5）: #4111。`ConnectionObserver` の telemetry への接続（REPAIR-4）は #4163 で実装済み（下の「plugin-cri での起動と停止」）
- ポートの到達性など深い意味検証
- WebSocket（`v5.channel.k8s.io` 等）: kubelet / apiserver 側で WebSocket を SPDY に変換する仕組みの一次情報は #678 で未確認のまま。必要になった時点で別途判断する
- kubelet / crictl の実クライアントでの照合（人間担当の #3730・#3777・#3779。本番の backend と plugin-cri の結線は済みで実施待ち。プロセス内の偽 backend と crictl 相当の SPDY クライアントによる疎通は `crates/cri/tests/streaming.rs`〔#683・TASK-63.5・CRI-6〕で済み。実 crictl は WebSocket が既定の版がありうるため、照合時に既定を一次情報で確かめる）

## plugin-cri での起動と停止（#3754）

- 置き場は plugin-cri の `streaming`（`production_streaming_config`・`production_stream_dispatcher`・`bind_production_streaming`・`stop_streaming_on`）。`main.rs` が runtime の構築直後、UDS の bind より前に呼ぶ
- 設定は `StreamingConfig::default()`（`127.0.0.1:0`・外部公開なし・TTL 60 秒）。外部公開は `--streaming-*` を明示したときだけ（`production_streaming_config_with`。#4110）。TLS・認証は無く、URL のトークンが唯一の認可
- dispatcher は Attach（Linux は対話可能な完全版、非 Linux は `AttachHandler::read_only()`。`ProductionAttach` で宣言する。#3763・#4078）・PortForward（NODE の `NodeLoopbackDialer`。#3755）・Exec（Linux で `exec_stream_launcher` があるとき。`without_tty`・`absolute_command_only`。#3761）を結線して注入する（`production_stream_dispatcher(attach: ProductionAttach, exec, recorder)`。`PortForwardHandler::new` の失敗を `INTERNAL` に写すため `Result`）。非 Linux の Exec は未結線で「not wired」の `UNIMPLEMENTED`。兄弟 issue は `with_*` を足す（`wiring` は bind 時に取られるため bind より前）
- 接続の観測（#4163・CRI-6・REPAIR-4）: `bind_production_streaming` は `ConnectionObserver` を受け取り `bind_with_observer` へ渡す。本番は `streaming::connection_observer::TelemetryConnectionObserver`（共有 `OpRecorder` と `stderr_sink()`。作れなければ起動しない）。件数は共有記録器の `cri.streaming.connection`（受理の成功・HTTP 失敗）・`cri.streaming.connection_deadline`・`cri.streaming.connection_rejected`・`cri.streaming.accept_failed` で、既存の 60 秒周期の `op_stats` 行に出る（正の件数）。異常の構造化行 `{"event":"cri_streaming_connection","op":…,"outcome":"error","reason":…,"count":…}` の reason は固定語彙 `max_connections`・`deadline_exceeded`・`accept_failed` の 3 種で、理由ごとの累計が 2 のべき乗に達した時だけ出す（接続の洪水で、監査行と共用の stderr sink を埋めないため。HTTP 失敗は件数のみ）。`observe` は I/O をせず `try_send` のみでブロックしない。トークン・コンテナ ID・入出力・パス・相手アドレスは出さない（イベント型が文字列を持たない）
- bind の失敗は fail-closed（`error: UNAVAILABLE: failed to start the streaming server`、設定検証の失敗は `INTERNAL`）。縮退すると「未結線」と区別できないため。UDS より先に判定するので socket を残さない
- 停止は SIGTERM・SIGINT の検知と同時に TCP の待ち受けを閉じる（shutdown future は待たない）。その後のセッションの扱いは次節。`SHUTDOWN_TOTAL_BOUND`（14.7 秒。#4340 で op-stats の最後の書き出し 1 秒が別に足された）は本件で延ばさない

## 停止時のセッションの扱い（#4164・CRI-6・REPAIR-5）

### 判断材料

- kubelet の期限はストリーム作成 30 秒・idle 4 時間（`SessionLimits::default()`）で、停止の予算よりずっと長い。「自然に終わるまで待つ」は採れない
- 本体の停止の上限は `SHUTDOWN_TOTAL_BOUND` 14.7 秒（検知 100 ms + gRPC の猶予 10 秒 + 強制回収 2 秒 + 書き出し 3 × 200 ms + ランタイム 1 秒 + op-stats の最後の書き出し 1 秒〔#4340。streaming の分ではない〕）で、`shutdown.rs` の試験が固定している。本件はこの値を延ばさない
- 変更前は、シグナルで exec の helper を即座に kill し（停止間際に終わるはずだった応答も欠ける）、Upgrade 後の Attach・PortForward のセッションは追跡も期限も記録も無いまま、gRPC の猶予の後にランタイムの停止が切っていた
- 受け入れた各セッションのタスクは handler が捨てハンドルで `tokio::spawn` しており、停止の経路だけでは強制クローズも件数の把握もできなかった。このため cri に `ConnectionPermit::spawn_session`（タスクの寿命 = 枠の寿命を型で結ぶ）と `StreamingSessions`（件数・`close_all`・`wait_idle_until`）を足し、3 つの handler の起動をそれに置き換えた（挙動は変えない）。Upgrade 前の接続のタスクも同じ追跡簿に登録する

### 方針

期限つきでドレインし、期限を過ぎたら exec を止めてから強制的に閉じる。基準はシグナルの受信時刻 T の絶対時刻で、シグナル受信時に shutdown future が別タスクとして起動し、`serve_with_audit` の戻り（RPC が残ると gRPC の猶予 10 秒を使う）を待たずに期限どおり進む。`StreamingStop::finish` はその結果を受け取る。shutdown future 自体は待ちを持たない（TCP の待ち受けを閉じる契約〔#3226〕を遅らせないため）。

| 段 | 時刻 | 内容 |
| -- | ---- | ---- |
| 1 | T | 待ち受けを閉じ、開いていた件数 `open_at_stop` を記録 |
| 2 | T..T+5 秒（`STREAMING_DRAIN_WAIT`） | セッションが自分で終わるのを待つ。全部閉じたら早く抜ける |
| 3 | T+5 秒 | `on_stop`（`shutdown_all`。helper を kill し、以後の launch を拒否）。exec は終了を観測して Status を送り閉じる |
| 4 | 〜T+6 秒（`STREAMING_CLOSE_WAIT`） | exec が閉じるのを待つ。全部閉じたら早く抜ける |
| 5 | T+6 秒 | 残りを abort する（強制クローズ）。破棄で枠が返るのを最大 100 ms 確かめる |
| 6 | 最後 | 構造化ログを 1 行出す（`event=cri_streaming_stop`。`open_at_stop`・`drained`・`exceeded`・`forced`・`remaining`・`elapsed_ms`。期限を超えたか残ったときは `warn`） |

- 順序の理由: exec のプロセスを先に止めてから接続を閉じる。クライアントに「切れた」と見えた後もコマンドが動き続ける窓をなくし、終了コード（Status）をできるだけ届けるため。強制クローズでも `ExecSession` の drop が helper を kill する（二重の経路）
- 上限の不変性: 5 秒 + 1 秒 = 6 秒 ≤ `PLUGIN_SHUTDOWN_GRACE` 10 秒。期限は T からの絶対時刻なので、serve が期限より後に戻ったときは待たずに段 3 へ進み、停止全体は serve の戻りと 6 秒 + 100 ms の大きい方で終わる。streaming 由来では延びない（`repair5_4164_stop_waits_fit_within_grpc_grace_and_total_bound` で固定）
- シグナルが記録されないまま `finish` したとき（serve が先にエラーで戻った）、`finish` を呼ばず drop したときも、待たずに `on_stop` と強制クローズを行う
- 暫定値: 5 秒は cri の `SessionLimits` の `drain_timeout`（終了後の流し切りの予算）と同じ、1 秒は `RUNTIME_SHUTDOWN_WAIT` と同じ。どちらも暫定値で、オーナー確認は #4116 の対象。承認は得ていない

### 残余

- シグナルの受信からドレインの期限までは、受け付け済みで launch 前の exec が launch できる。期限の `shutdown_all` で止まり、停止直前に始めた exec と同じ扱いになる
- abort されたセッションは `record_session` や observer の記録を通らない。件数は停止の 1 行に出る
- plugin-cri が SIGKILL された場合は、helper が channel の切断を検知して通常 2 秒以内に終わる（#4112。実機照合は #4167）。残る窓は上記の Exec の残余
- 実行中の blocking の dial は abort できず、ランタイムの `shutdown_timeout` が打ち切る

### 試験

- cri `tests/streaming_server.rs`: 3 セッションのうち自然に終わる 1 件の応答が欠けず、残り 2 件が `close_all` で閉じる（`cri6_repair5_4164_drain_keeps_natural_response_and_force_closes_rest`）、強制クローズ後の接続の即時 abort、Upgrade 前の接続の強制クローズ
- plugin-cri `streaming.rs`: 3 件を開いたままの停止が期限内に終わり全件閉じること、`on_stop` が 1 回で強制クローズより前に呼ばれること、期限内に終わった応答が欠けないこと、`finish` を呼ばなくても期限どおりに `on_stop` と強制クローズが行われること、期限後の `finish` が待たないこと、ログ行の形

## 依存

`flate2`（zlib-rs backend。SPDY のヘッダブロックの辞書つき zlib。#681 で crates/cri の直接依存にした。承認は #678 のオーナー判断で、新しいパッケージは増えない）。`hyper =1.12.0`（`server`/`http1`）・`hyper-util =0.1.21`（`tokio`）・`tokio` の `net`/`time` を crates/cri に追加した（承認 #678）。いずれも `Cargo.lock` に既存で、新しいパッケージは増えない。`http-body-util`・`bytes`・`http` は直接依存にせず、`hyper` の再 export と自前の小さな本体型（`StreamBody`）で足りる範囲に留めた。

## 結線情報（#3753・REPAIR-3）

- `StreamHandler::wiring()`（既定実装なしの必須メソッド）が、そのハンドラが処理する種別を `StreamWiring` で返す。`StreamingServer` は起動時に 1 回だけ読み、`StreamingUrlIssuer` に持たせる（スナップショット。ハンドラは寿命の間、値を変えない）
- `StreamDispatcher::wiring()` は、登録済みの slot のうち子ハンドラが同じ種別を結線済みと答えるものだけを返す。`StreamingServer::bind`（`NotImplementedHandler`）はどの種別も結線しない
- `CriRuntimeService` の `exec`・`attach`・`port_forward` は、入力検証と存在照合より前に `StreamingUrlIssuer::require_wired` を通し、未結線の種別は URL を返さず `UNIMPLEMENTED`（英語の固定文。トークン・要求の中身を含めない）にする。未注入のときと同じ順序で、未知のコンテナでも `NOT_FOUND` より先に `UNIMPLEMENTED` になる
- `StreamingUrlIssuer::issue` も未結線の種別を乱数源とトークン枠の消費より前に断る（多層防御）。未結線の RPC を繰り返しても、結線済みの種別の発行枠（`max_in_flight`）は埋まらない
- 未結線の種別の HTTP 側の 501 は、issuer を経ない到達に対する多層防御として残す
- `StreamWiring` は後から項目を足せる構造体で、種別ごとの結線の有無と、attach が stdin・tty を扱えるか（`attach_interactive`。#3763）を持つ。既定は全未結線かつ非対話（fail-closed）。`StreamDispatcher::wiring()` は Attach の子の `attach_interactive` を伝える
- `StreamWiring::port_forward_pod_network`（#3755）は PortForward が POD ネットワークの pod にも対応するかを表し、既定は偽（fail-closed）。`only`・`with` では立たず、`all()`（試験用の全機能）と `with_port_forward_pod_network` で立つ。`StreamDispatcher` は子ハンドラの宣言を引き継ぐ
