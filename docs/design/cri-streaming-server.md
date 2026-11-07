# CRI ストリーミングサーバー基盤と URL 発行

CRI の `Exec`・`Attach`・`PortForward` は、RPC 自体ではデータを流さず「ストリーミングサーバーの URL」を返す。kubelet / apiserver はその URL へ HTTP（SPDY/3.1 の Upgrade）で接続して入出力をやり取りする。本書は、その土台（HTTP サーバーの起動・URL 発行・トークンの失効）の設計記録である（CRI-6・TASK-63.1・#679。依存の承認は #678）。本番 backend の設計（#3752）も「本番 backend の設計」の節に含める。

実装は `crates/cri/src/streaming.rs`（SPDY は `streaming/spdy.rs`・`streaming/remotecommand.rs`、Attach は `streaming/attach.rs`、Exec は `streaming/exec.rs`）。結合試験は `crates/cri/tests/streaming_server.rs`・`streaming_attach.rs`・`streaming_exec.rs`。

## スコープ

| 項目 | 本書の範囲 | 担当 |
| ---- | ---------- | ---- |
| HTTP/1.1 サーバーの起動・ルーティング・接続の上限と期限 | 実装済み | #679 |
| URL の発行（一意・単回使用・TTL つき） | 実装済み | #679 |
| 3 RPC の入力検証と存在照合 | 浅い検証まで実装済み | #679 |
| Exec の SPDY/3.1・Upgrade 後のストリーム | 実装済み（`ExecStreamHandler`。#681 の codec・交渉・`SessionLimits` を再利用。起動役の本番の実装は未実装。注入が無ければ Exec は結線済みと答えず、RPC は `UNIMPLEMENTED`） | #680（TASK-63.2） |
| Attach の SPDY/3.1・remotecommand・Upgrade 後のセッション | 実装済み（fake backend での結合試験）。本番の backend は未接続。backend が無ければ Attach は結線済みと答えず、RPC は `UNIMPLEMENTED`） | #681（TASK-63.3） |
| PortForward | 未実装 | #682（TASK-63.4） |
| plugin-cri からのサーバー起動と `with_streaming` での注入 | 実装済み（loopback で起動し `StreamDispatcher` で注入。結線済みは #3755 の PortForward〔NODE のみ〕で、Exec・Attach は「not wired」の `UNIMPLEMENTED`） | #3754 |
| 本番 backend（Exec の helper・Attach・PortForward の dialer） | PortForward の NODE の dialer は実装済み（#3755）。Exec の stream-exec helper は実装済み（#3760。plugin-cri 側の起動は #3761）。Attach・POD の PortForward は未実装。設計は「本番 backend の設計」の節 | #3753〜#3766 |

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

実行中コンテナの stdin / stdout / stderr と tty を渡す経路は、core の `ContainerRuntime` にも supervisor にも無い（CreateContainer の `stdin`・`stdin_once`・`tty` の bundle への反映もまだ）。`ContainerRuntime` トレイトの拡張か supervisor の新しい経路かは PLUG-1・SUP 系の設計判断（main の設計が要る）であり、本 issue では注入点（`AttachBackend`）までとした。判断材料として、supervisor のログの sink は stdout / stderr を読んでいるため読み側だけは供給できる可能性があるが、stdin の経路と tty は無く、断定していない。plugin-cri からの `StreamingServer` の起動と `StreamDispatcher` / `AttachHandler` の組み立ては #3754。方式の設計は「本番 backend の設計」の「Attach」節。段階 1（読み取り専用）は #3763 で実装済み、完全版（stdin・tty・resize）は #3765 の設計に従う未実装。

## Exec（#680・TASK-63.2・CRI-6）

`ExecStreamHandler`（`StreamHandler` の実装）を `StreamDispatcher::with_exec` で登録する（単独なら `bind_with_handler` に直接渡してもよい。Exec 以外の種別は結線済みと答えず、URL は発行されない）。SPDY の codec・交渉・status・resize の解析・期限（`SessionLimits`）は Attach と共通の `spdy.rs`・`remotecommand.rs` を使い、`exec.rs` に残るのは Exec 固有の部分（起動役 `ExecStreamLauncher`・プロセスの終了コードから Status への変換・stdin の stall 期限）だけである。

- 交渉・ストリーム割り当ては Attach と同じ（v4・v3・v2。resize は v3 以降）。受け付ける組は発行時に保存した `ExecRequest` から決める（`StreamOptions::expected`）
- 終了の通知: v4 は error ストリームに `metav1.Status` の JSON。成功は `{"metadata":{},"status":"Success"}`、非 0 は `reason: NonZeroExitCode` と `details.causes: [{"reason":"ExitCode","message":"<code>"}]`。v3・v2 は成功時に何も書かず、非 0 は `command terminated with exit code <code>` のテキスト（kubelet と同じ）。起動失敗・待ち失敗は `InternalError` の固定文で、内部のパス・エラー文は載せない。続けて未 FIN の出力に FIN、GOAWAY を送り閉じる
- フロー制御は Attach と同じく強制しない（「意図的な逸脱」）。送信キュー 1 MiB の上限と、stdin をプロセスへ書き終えるまで次のフレームを読まないことで背圧を TCP に任せる。試験 `cri6_exec_large_stdin_roundtrip_beyond_window` が 256 KiB の往復を固定する
- 期限（REPAIR-5）: `SessionLimits`（作成 30 秒・idle 4 時間・流し切り 5 秒・最後の送出 5 秒）に加え、Exec 固有の `launch_timeout`（既定 30 秒）と `stdin_stall_timeout`（既定 60 秒。溜めた stdin をプロセスが読まないとき、ソケットを読めず切断を検知できない時間の上限）
- 受信バッファが上限を超えた場合は EOF と区別して `ProtocolError`（GOAWAY）で閉じる

### 注入トレイト `ExecStreamLauncher`

core の `ContainerRuntime` に exec は無く、shim v2 の `TaskExecLauncher` は stdio を持たない（containerd の FIFO 前提）。そこで stdio を持つ起動役を `crates/cri` の注入トレイトとして定義した（`ContainerRuntime` は変えない。PLUG-1）。`ExecLaunch` には発行時に保存した要求から作った値だけを入れ、通信路の内容から cmd を組み立てない。契約は、要求された stdio だけを返す・`ExecSession` の drop でプロセスを止める・コンテナの namespace / cgroup / seccomp / capability を継承して広げない（SEC-1）・panic しない。**本番の実装は無い（REPAIR-3）**。supervisor の exec 入口（pidfd 経由）へ stdio のパイプと pty を付ける橋渡しの設計は「本番 backend の設計」の「Exec」節（#3757〜#3762）。

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

2026-11-03 に main が決めた要点（Attach は段階方式、Exec は制御チャネルの exec 要求と fd 渡しで孤児時に縮退しない、PortForward は NODE を先に入れ POD は #2877 の後、依存は plugin-cri から supervisor への一方向で cri に実装を入れない）を詳しくした設計記録である。後続の兄弟 issue（#3753〜#3766。親 #3726・TASK-63・MS-7）はこの記録を正として実装する。オーナーの確認が要る点は末尾の「未確認・オーナー確認事項」にまとめ、それ以外は確定扱いとする。**本節の内容はいずれも未実装である（REPAIR-3）**。

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

- channel の frame は固定長・big-endian で、壊れた値を表現できない型にする（REPAIR-2）。plugin-cri から helper へは `StdioHandover`（マスクと、そのビット数ちょうどの fd を SCM_RIGHTS で送る。最大 3 本）。helper から plugin-cri へは `Started`・`PtyMaster`（tty のときだけ fd 1 本）・`Result`（exited n / signaled s / not_started 段 コード / failed コード）。受け側は fd の本数・`MSG_CTRUNC`・マスクとの不一致をすべて拒否し、受け取った fd は drop で閉じる。magic・各 frame の長さ・語彙は #3759 で確定し、本書は構造と上限だけを定める
- pre_exec を使わず、子に渡す fd は `Stdio` の 3 本だけにする（新しい unsafe を sys の外に作らない）

**stdio と pty**:

- stdin / stdout / stderr を別々に付け替える処理は core（#3757）が持ち、`ExecLaunchIo` を拡張する。要求されない stdio は `/dev/null` のまま。既存の healthcheck の挙動は変えない
- pty は worker（コンテナの mount namespace に参加した後）が、コンテナの devpts（`/dev/ptmx` は `pts/ptmx` への symlink。[dev-default-mounts.md](dev-default-mounts.md)）で開く。runc と同じくコンテナ内で `ttyname` が成り立つ。slave は `setsid` と `TIOCSCTTY` で controlling terminal にして fd 0〜2 に付ける。master は core の既存の worker から親への SCM_RIGHTS で helper へ返し、helper が channel の `PtyMaster` で plugin-cri へ返す。受け側は master が文字デバイスであることを fstat で確かめる。開く位置は、Landlock と seccomp の再適用の **後** に `ExecReady::allocate_pty` で、照合済みの `/` の fd から `dev` → `pts` → `ptmx` を 1 要素ずつ symlink 非追従で辿って開く（#3758 で確定。コマンドと同じ権利で開き、launch より広げない。暗黙の `/dev/pts` に `READ|WRITE|IOCTL_DEV` が付くため通る想定で、実コンテナでの確認は #3762。通らなければ再適用の前へ移す判断をオーナーに仰ぐ）。slave は `ChildStdio::from_pty_slave` が fd 0〜2 に付け、子が `setsid` の直後に `TIOCSCTTY` を発行する。master は worker がコマンドの fork の前に `spawn_exec_worker_with_listener_and_pty` の口で親へ送って閉じる（コマンドは master を持たない）。ホストの devpts で代わりに割り当てる方式は採らない
- resize は、plugin-cri が持つ master へ `TIOCSWINSZ` を発行する（core の安全なラッパー。supervisor への往復なし）

**SEC-1**:

- コマンドは既存の `run_command_with_pidfd` の段（namespace・cgroup・rlimit・launch と同じ capability 集合・NNP・Landlock・seccomp）だけを通り、launch より広げない
- env の基底は `config.json` の `process.env` と launch 時の env だけ。CRI は env を渡さないので `with_env` を使わない。argv はシェルを通さない
- argv[0] が相対パス（例: `sh`）の要求は、PATH の解決（#2439）が決まるまで `INVALID_ARGUMENT` で拒否する。URL の発行前（RPC 時）に断るのが望ましく、置き場所は #3753・#3761 で決める
- helper と plugin-cri の channel はパスを持たない socketpair で、第三者は接続できない。supervisor の実行ファイルは PATH を探さず固定名で解決し、受け取った pidfd は `identify_pid1_with_pidfd` で照合する。トークン・argv・パスはログやエラーに出さない

**終了コードの写像**: `Exited(n)` は n、`Signaled(s)` は 128 + s（`metav1.Status` の NonZeroExitCode）。`SetupFailed` は子の終了状態（通常 125 / 126 / 127）で、CLI の exec と同じ（exec-pidfd-handover.md §3.4）。拒否・期限・到達不能は launch の失敗にし、handler が `InternalError` の固定文にする。

**drop・restart・孤児**:

- `ExecSession` の drop で、plugin-cri は helper を `Child::kill` で止める（未回収の子なので pid は再利用されない）。channel と制御チャネルの接続が閉じると、kind 7 のガードが exec 子 cgroup を `cgroup.kill` で回収し、worker は PDEATHSIG で終わる
- helper の回収は blocking の待ちを期限つき（5 秒）で行う。回収できない helper は数の上限つきで保持し、超えたら新しい exec を `RESOURCE_EXHAUSTED` で断る（healthcheck の `MAX_HELD_HELPERS` の考え方）
- コンテナの restart（再 launch。[restart-relaunch-single-thread.md](restart-relaunch-single-thread.md)）では、`ExecGuardPool::shutdown_all` が旧世代の exec 子 cgroup を回収するので、CRI の exec のセッションも終わる
- supervisor が不在（孤児）なら `UNAVAILABLE` 相当で失敗し、縮退しない

**SCM_RIGHTS の再利用判断**: core（`sys/seccomp_notify.rs`）・net（`sys/holder.rs`）・supervisor（`sys/linux.rs` の `send_with_fd` / `recv_with_fds`）の自前ラッパーは、crate ごとの sys に置いたまま共有しない。いずれも `pub(crate)` で意味も違い（core は token と資格情報、net は holder の frame、supervisor は制御チャネル）、前例は [fdinfo-mnt-id-parsing.md](fdinfo-mnt-id-parsing.md) の「共有下位 crate を作らない」判断である。本設計で足りないのは supervisor の「複数 fd の送信」だけで、既存の `send_with_fd` を N 本（上限 3〜4。`recv_with_fds` の 4 本と揃える）へ一般化し、plugin-cri が使える安全な公開 API として出す。sys の事前承認の範囲内（coding-rust.md）。plugin-cri の sys には SCM_RIGHTS を新しく足さず、重複を作らない。

**上限**: 同時の exec は supervisor 側がコンテナごとに 16（`ExecGuardLimits::max_guards`）。plugin-cri 側にも全体の上限を設け、値は #3761 で決める。channel の受信長は固定で、fd は最大 3 本受け、tty のときは master を 1 本返す。

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
- RPC 時の拒否: `StreamWiring` に `attach_interactive`（既定 false）を足した。`AttachHandler::read_only()` の結線は宣言せず、`attach_impl` が `require_attach_options` で stdin・tty を URL の発行前に `INVALID_ARGUMENT`（`attach with stdin or tty is not supported`）で断る。`issue()` も同じ位置で断る（多層防御）。接続時は backend も同じ文言で断る
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
- 単一スレッド制約との関係: 要求は accept ループの中で 1 往復で終わり接続を保持しない（exec のガードとは違う）。このため `PausableServer::pause` に新しい参加者が増えず、supervisor にセッション用のスレッドも残らない。supervisor が持つのは世代ごとの fd だけである。このため [restart-relaunch-single-thread.md](restart-relaunch-single-thread.md) の表に行は足さない。常駐 listener（A2）を採らない理由は比較表のとおり

**D2. 出力は捕捉からの tap（A1 の「ログの follow」を改める）**

- ログの follow は LF までの完全な行しか出さず（`sup7_follow_waits_for_lf`）、ポーリングは 200 ms なので、LF の無い対話シェルのプロンプトが attach に届かない。そこで完全版の出力は、既存の捕捉のリーダーが sink へ書いた後に、購読者ごとの非ブロッキング socketpair へ生のバイト列を複製（tap）して渡す。tty と非 tty の両方に適用する
- tap は既存のリーダースレッドの中で動くので新しいスレッドが要らず、再 launch の前の `quiesce` の範囲に収まる
- 契約: sink への書き込みを常に優先する。`EAGAIN` や書き込み失敗の購読者はその場で切断し op ログに残し、背圧はかけない（SUP-7 のログを止めない）。購読者数にコンテナごとの上限を置く（初期案 8）。購読した時点より後の出力だけを流す。capture の EOF と世代交代で tap を閉じ、これが attach の終わりになる
- 却下: follow のまま部分行を出す案（レコード形式に部分行の印が要り CLI の logs にも波及し、遅延も残る）、非 tty だけ follow を残す案（出力の経路が 2 本になり終了の意味も揃わない）。段階 1（#3763）の follow は完全版の結線で置き換え、reader の取り消しの口は残す

**D3. init の stdin / pty を作り保持する主体**

- 作るのは core の本番 launcher で、supervisor が起動オプションで要求する。stdin は `LaunchOptions` で開く指定を足し、core が pipe を作って読み取り側を子の fd 0 にし、書き込み側を `LaunchedProcess` から取り出す。（stdin の段は C1〔#4069〕で実装済み。API は `LaunchOptions::with_stdin(LaunchStdinMode::Pipe)` と `LaunchedProcess::take_stdin`）tty（`process.terminal: true`）は、子がコンテナの mount namespace と devpts の中で `/dev/ptmx` を開き、slave を fd 0〜2 にして `setsid` と `TIOCSCTTY` で制御端末にし、`/dev/console` へ bind し、master は既存の子から親への SCM_RIGHTS（seccomp listener と同じ経路）で返す。pty の sys ラッパーと開く位置（Landlock / seccomp の再適用との順序）は #3758 の決定を再利用し、ここで決め直さない。ホストの devpts では割り当てない
- core の `process.terminal` の拒否は、supervisor が端末対応を opt-in したとき（例: `with_terminal_support()`）だけ外す。master を捕捉しない呼び出し元は従来どおり拒否する（fail-closed）
- 保持するのは supervisor で、`control/target.rs` の `SignalSlot` と同じ置き場所に世代ごとのスロットを持つ。`Exited` と再 launch で落とし、新しい世代の fd に差し替える。tty では master を捕捉の stdout 1 本として `LogCapture` へ渡し、`EIO` は EOF とみなす（CRI のログは stdout のタグだけになる）
- 渡した master の複製を plugin-cri が読むと捕捉のデータを奪うので、書き込みと `TIOCSWINSZ` にだけ使う（契約）

**D4. CRI から supervisor への運び方**

- tty: cri の `bundle/spec.rs` が `process.terminal: true` を config.json に出す（OCI の標準の欄）
- stdin・stdin_once: OCI の config.json に欄が無いので、cri が CreateContainer で値を記録（再採用用の永続記録を含む。[cri-record-readoption.md](cri-record-readoption.md)）に保存し、StartContainer で core の `StartRequest` に 3 値の enum（例: `StdinMode::{Closed, Open, Once}`）として載せる。`with_log_path` と同じ builder の形にする。plugin-cri の `supervised.rs` が supervisor の argv に `--stdin <open|once>` を付ける（plugin-cri 専用。`start_contract` の契約に足す）。plugin-cri は起動オプション文書（FCOPT1）を書かないので使わない
- 依存の向きは plugin-cri から cri / supervisor / core、supervisor から core のままで、新しい辺も外部依存も増えない（PLUG-1）

**D5. `stdin_once`**

- 非 tty で `stdin_once` のとき、最初に stdin を要求した attach へ複製ではなく元の書き込み端を渡し、supervisor は自分の端を閉じる（所有の移転）。セッションの stdin が終端になると plugin-cri が drop し、コンテナは EOF を受ける。その後の stdin の要求は `StdinClosed` で断る
- tty の `stdin_once` は閉じない。containerd の `container_io.go` の `Attach` は `StdinOnce && !Tty` のときだけ stdin を閉じ、コードの上のコメントは tty も閉じると読めるが挙動はコードに従っているため、本設計もコードに従う
- `stdin_once` でないときは毎回複製を渡し、supervisor が自分の端を持ち続けるのでセッションが終わってもコンテナは EOF を受けない。再 launch で世代が変わると新しい pipe を作り、消費済みの状態も初期化する

**D6. resize・終了・複数の attach**

- resize: plugin-cri が持つ master の複製へ core の安全なラッパー（#3758）で `TIOCSWINSZ` を発行する。supervisor との往復は無い。初期の寸法は既定値のままで、kubelet の最初の resize で決まる
- 終了: tap の EOF と既存の kind 8 の `ExitWatch` から `exited` を作る。ポーリングはしない
- 複数の attach: 同時に attach してよい（containerd と同じ）。stdin は各セッションの複製から並行して書かれ、混ざりうる。出力は各セッションが自分の tap を持つ

**D7. RPC 時の整合検査（cri）**

- stdin を開いていないコンテナへの stdin の要求、およびコンテナの tty の実体と要求の tty が違う場合は `FAILED_PRECONDITION`（固定の英語文）で断る（fail-closed）。containerd は stdin を黙って無視するので差がある

**D8. 拒否を外す順序（fail-closed の段階）**

- `bundle/spec.rs` の `unsupported("tty/stdin")` を外すのは最後の実装 issue（C10）だけにする。それまでの途中の状態では拒否を残し、要求より弱い挙動のコンテナ（stdin が `/dev/null`、端末が無い）を作らせない。core の `process.terminal` の拒否は D3 の opt-in で段階的に外す。shim v2 の terminal の拒否（`task_service.rs`）は本件の範囲外でそのまま残す

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
| C3 | #4071 | core: slave を `/dev/console` へ bind | C2 |
| C4 | #4074 | supervisor: stdin 端・master の保持、tty 捕捉、`--stdin` | C1・C2 |
| C5 | #4072 | supervisor: 捕捉からの出力の tap（実装済み。sink 優先・背圧なし・溢れたら切断・購読者数の上限 8 は初期案。購読 API は `CaptureHub::subscribe_output`、kind 9 での受け渡しは C6） | なし |
| C6 | #4075 | supervisor: kind 9 `AttachRequest` と fd 応答 | C4・C5・#3759 |
| C7 | #4073 | core: `StartRequest` の `StdinMode` | なし |
| C8 | #4076 | cri: 記録への保存と StartContainer での運搬 | C7・C4 |
| C9 | #4077 | plugin-cri: 完全版 `AttachBackend` | C6・C8・#3763・#3754・#3761 |
| C10 | #4078 | cri: 拒否の解除と整合検査 | C3・C9 |
| C11 | #4079 | 実機前提試験・手順・CI の追記 | C10 |

### PortForward（NET-3・SEC-1）

**NODE（#3755）**:

- host netns の `127.0.0.1:<port>` だけへ `dial_timeout`（10 秒）で接続する。接続先は要求から組み立てず loopback に固定する（SEC-1）。`::1` は試さない（fail-closed）
- NODE が先に成り立つ理由: NODE ネットワークでは network namespace の要素を作らず（host netns）、本番の `NetworkReady` は false なので、現状 kubelet が受ける Pod は hostNetwork だけである
- NODE か POD かは、cri が RPC の時点で sandbox の記録（保存済みの `config` の `namespace_options.network`）から決め、発行時の要求に保存して dialer へ渡す。#3755 で `PortForwardDialer` の引数に対象の型（例: `PortForwardTarget { pod_sandbox_id, network: Node | Pod }`）を足す。URL やヘッダから組み立て直さず、plugin-cri に記録の解析を複製しない（REPAIR-1）
- hostNetwork の Pod の port-forward はホストの loopback 上の任意のサービスへ届く。これは hostNetwork の性質で、認可は単回トークンの URL と kubelet / apiserver 側が担う
- 実装（#3755）: `runtime_service::port_forward_network` が `namespace_options.network` がちょうど `NODE` のときだけ `Node` とし、未指定・POD・CONTAINER・TARGET・未知の値は `Pod`（fail-closed。`wants_pod_network` は CONTAINER・TARGET を「POD でない」と扱うので流用しない）。`port_forward_impl` の順序は 結線 → 入力検証 → sandbox の照合（`NOT_FOUND`）→ POD の拒否（`UNIMPLEMENTED "port-forward for pod network is not implemented"`。トークン枠を消費しない）→ 発行。dialer は port 0・期限 0 を `INVALID_ARGUMENT`、期限切れを `TIMEOUT`、その他を `UNAVAILABLE` の固定文で返し、成功後に `peer_addr` が loopback であることを確かめる。`PortForwardDialer::supports_pod_network`（既定は偽）を真にした dialer を注入すると結線情報の POD 対応が立ち、RPC 時の拒否が外れる（#3766 が使う）
- 残余: URL 発行後に sandbox が消えても dialer は記録を照合しない（トークン TTL 60 秒とセッションの idle の期限で有界）。停止時は Upgrade 後のセッションと blocking の dial（最長 10 秒）をランタイムの `shutdown_timeout`（1 秒）が打ち切り、待ちは増えない

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
| `StreamingServer` の SIGTERM での停止 | 受信の検知（100 ms 周期）で待ち受けを閉じ、待ちを足さない。受け付け済みの接続はランタイム停止の 1 秒で打ち切る。全体の上限 13.7 秒は不変（#3754） |

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
| #3761 | plugin-cri の本番 launcher | helper の起動・fd の送信・tokio の橋渡し・drop で kill・ローカルの resize・全体の上限 |
| #3762 | 実機前提試験 | — |
| #3763 | plugin-cri の読み取り専用 attach | 実装済み（supervisor の reader の取り消しの口・`FollowEnd`・`RecordDemux` を含む） |
| #3764 | docs の更新 | — |
| #3765 | 完全版 attach（A1 を本命として設計と分解） | 設計済み。子 issue は「完全版 Attach の設計（#3765）」を参照 |
| #3766 | POD の port-forward の設計と分解 | — |

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

- Exec と Attach の本番 backend の実装と結線（設計は「本番 backend の設計」の節、実装は #3761・#3763 ほか。PortForward の NODE は #3755 で実装済み、POD は #3766）
- 外部公開の opt-in を plugin-cri の CLI へ出すこと（現状は loopback 固定。REPAIR-3）
- `ConnectionObserver` の telemetry への接続（現状は `NoopObserver`。REPAIR-4）
- Upgrade 後のセッションの停止時のドレイン方針の再評価（backend が入った時点。REPAIR-5）
- ポートの到達性など深い意味検証
- WebSocket（`v5.channel.k8s.io` 等）: kubelet / apiserver 側で WebSocket を SPDY に変換する仕組みの一次情報は #678 で未確認のまま。必要になった時点で別途判断する
- kubelet / crictl の実クライアントでの照合（本番の backend と plugin-cri の結線の後。プロセス内の偽 backend と crictl 相当の SPDY クライアントによる疎通は `crates/cri/tests/streaming.rs`〔#683・TASK-63.5・CRI-6〕で済み。実 crictl は WebSocket が既定の版がありうるため、照合時に既定を一次情報で確かめる）

## plugin-cri での起動と停止（#3754）

- 置き場は plugin-cri の `streaming`（`production_streaming_config`・`production_stream_dispatcher`・`bind_production_streaming`・`stop_streaming_on`）。`main.rs` が runtime の構築直後、UDS の bind より前に呼ぶ
- 設定は `StreamingConfig::default()`（`127.0.0.1:0`・外部公開なし・TTL 60 秒）。外部公開の口は plugin-cri から出さない。TLS・認証は無く、URL のトークンが唯一の認可
- dispatcher は PortForward（NODE の `NodeLoopbackDialer`）だけ結線して注入する（#3755。`production_stream_dispatcher` は `PortForwardHandler::new` の失敗を `INTERNAL` に写すため `Result`）。Exec・Attach は「not wired」の `UNIMPLEMENTED` のまま。兄弟 issue は `with_*` を足す（`wiring` は bind 時に取られるため bind より前）
- bind の失敗は fail-closed（`error: UNAVAILABLE: failed to start the streaming server`、設定検証の失敗は `INTERNAL`）。縮退すると「未結線」と区別できないため。UDS より先に判定するので socket を残さない
- 停止は SIGTERM・SIGINT の検知と同時に TCP の待ち受けを閉じ、待ちを足さない。受け付け済みで Upgrade しない接続は既存の `RUNTIME_SHUTDOWN_WAIT`（1 秒）が打ち切り、`SHUTDOWN_TOTAL_BOUND`（13.7 秒）は変わらない

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
