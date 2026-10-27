# トポロジー保持入口と 1 バイト TCP 往復計測プログラム（TASK-140 準備・#1881）

TASK-140（#319。人間担当）の条件 2（スループットの Docker 比。NET-2）と条件 3（1 バイト TCP 往復の p50・p99。NET-3）を測るための、Rust 側の 2 つの道具の契約を定める。iperf3・Docker 側・集計スクリプトは #1882 の範囲。

- 保持入口: `crates/net/tests/network_paths_privileged.rs` の `--hold --max-secs N`（root・実機前提。CI では実行しない）
- 往復計測プログラム: `crates/net/tests/tcp_rtt_probe.rs`（root 不要・std のみ・3 OS の既定のテスト集合で自己試験が走る）

対応 ID: NET-2・NET-3・NET-11・REPAIR-3・REPAIR-5・REPAIR-12、TASK-140（#319）、MS-8。

## 値の位置づけ（暫定値）

Issue #319 の 2026-10-12 のコメント（推奨案での仮確定。オーナーの判断で変わり得る）に従い、この方法で得た値は暫定値であり、NET-2・NET-3 の判定には使わない。判定は製品の起動経路（#1812〜#1819・#1873）がつながってから測り直した値で行う。出力はすべて `provisional: true` と `method` を持つ。#1882 の比・倍率の出力も同じ `provisional` フィールド名を引き継ぐ。

制約（`method` にも書く）:

- コンテナ役は `nsenter --net=<pin>` で入った任意のプロセスで、製品の起動経路（namespace 隔離・cgroup・seccomp）を通らない
- masquerade 本体は未実装（`crates/net/src/network.rs`「未実装範囲」。REPAIR-3）
- ホスト役は実ホストではなく、隔離 netns。経路 (c) の宛先 `10.214.1.1` は veth `fcox0` のローカルアドレスで、物理 NIC を通らない。隔離 netns の nft ルールセットは自前のテーブルだけで、ホストの Docker・firewall のルールを通らない

## 隔離の判断

保持は、既存の `--measure` と同じ `unshare --net --mount` の新規 netns の中で行う。

- bridge・veth・nft テーブルは新規 netns の中、pin は private な mount namespace の tmpfs の上にある
- 保持時間の期限、シグナル、ランチャや親スクリプトの死亡のどの場合も、プロセスの終了で netns ごとカーネルが回収し、ホストの link・nft・mount に何も残らない（REPAIR-5）。シグナルハンドラを持たないので `sys` 外の unsafe も作らない
- スクリプトが起動した `nsenter` 越しのプロセス（iperf3 サーバー等）がコンテナの netns に残ると、その netns は当該プロセスが終わるまで残る。ホストには何も残らないが、起動したプロセスの回収はスクリプト側（#1882）の責任

## 保持入口の契約

起動: `sudo <network_paths_privileged の実行ファイル> --hold --max-secs <N>`

- `--max-secs` は必須で 1..=3600。欠落・範囲外・非数値は root の確認より前に終了コード 2
- ランチャの期限は `max_secs + 期限 x 60`（既定 600 秒）。`--ignored` / `--measure` の挙動は変えない
- stdout は JSON 行専用、診断は stderr。途中の失敗は stderr に診断を出して終了コード 1（後始末は上記のとおり namespace の消滅で担保）

手順: `prepare_isolation` -> `lo` と外側アドレス `10.214.1.1/24`（veth `fcox0`/`fcox1`）-> `create_network`（名前 `hld`、gateway `10.214.0.1/24`）-> `attach_container` c1（TCP 公開 `10.214.1.1:18080 -> 9080` と `:15201 -> 5201`、アドレス `10.214.0.2`）と c2（公開なし、`10.214.0.3`）-> ready 行 -> 保持 -> `delete_network`・取り残し確認 -> released 行。

### ready 行（1 行の JSON）

| フィールド | 内容 |
| ---------- | ---- |
| `schema` / `event` | `fandhe-container.net-hold/v1` / `ready` |
| `provisional` / `method` | `true` / 上記制約の英文 |
| `isolation` | `unshare --net --mount (fresh netns)` |
| `max_secs` | 保持の期限 |
| `inner_pid` | 保持プロセスの PID |
| `host_netns` | `/proc/<inner_pid>/ns/net`。経路 (b)(c) のクライアントを置く netns |
| `mount_ns` | `/proc/<inner_pid>/ns/mnt` |
| `host` | `bridge_addr`（`10.214.0.1`）・`outer_addr`（`10.214.1.1`） |
| `containers[]` | `id`・`addr`・`pin`（inner の mount ns から見た pin）・`netns`（`/proc/<inner_pid>/root<pin>`）・`publishes[]`（`proto`・`host_addr`・`host_port`・`container_port`） |

`pin` と `netns` は文字種 `[A-Za-z0-9/._-]` だけからなることを出力前に確かめ、外れたら出力せず失敗する（`TMPDIR` 由来の文字による JSON の破損・注入の防止）。

### 解放

stdin の `release` 行、stdin の EOF、`max_secs` 経過のいずれか。スクリプトの異常終了は stdin のパイプの EOF で検出する。解放後に `delete_network`（`leftover` 空・bridge と host 側 veth が `NotFound`・pin が無いこと）を確かめ、次の行を出して終了コード 0。

```json
{"schema":"fandhe-container.net-hold/v1","event":"released","reason":"eof|release|deadline","cleanup":"ok","provisional":true}
```

### pin への入り方

pin はホストの mount namespace から見えない。計測プロセスはホストの mount namespace のまま `nsenter --net=/proc/<inner_pid>/root<pin>`（ready 行の `netns`）で入る。代替は `nsenter --mount=<mount_ns> -- nsenter --net=<pin> -- ...` の 2 段（`nsenter` は名前空間ファイルを先に全部開くため、`--mount` と `--net=<pin>` を 1 段で並べる形は使えない）。

### 契約の照合（REPAIR-12）

- 既定の実行（引数なし。root 不要）: `--max-secs` の境界値（1・3600 は受理、0・3601・負数・非数値・欠落は拒否）、解放の理由（`release` 行・EOF）、ready / released 行の具体値、`pin` の文字種検査を自己試験する。成功行 `network_paths_privileged: hold contract self-test passed (NET-3)`
- 実機前提 `sudo <実行ファイル> --hold-check`: 保持を `release` 行・stdin EOF・期限（`--max-secs 1`）の 3 通りで開始から解放まで通し、ready 行の内容・`netns` パスの実在・released 行の完全一致（`cleanup:ok`）・終了コード 0 を照合する。成功行 `network_paths_privileged: hold verified release/eof/deadline (NET-3)`。CI では実行しない

## 往復計測プログラムの契約

`tcp_rtt_probe`（引数なしは loopback の自己試験）。

- `--serve <ip:port>`: bind 後に `{"tcp_rtt_probe":"listening","addr":"..."}` を出し、接続を 1 本だけ期限つきで受けて 1 バイトを返し続ける。EOF で `{"tcp_rtt_probe":"served","rounds":K}` を出して終了
- `--client <ip:port> [--rounds N] [--warmup W]`: 接続して W 回のウォームアップ（計測しない）の後 N 回を計り、1 行 JSON を出す
- 両端 `TCP_NODELAY`。1 往復 = 1 バイト送信から同じ 1 バイト受信まで。バイトは往復ごとに変え、不一致は `DESYNC`
- `--rounds` は 1..=100000（既定 10000。PoC-15 と同じ）、`--warmup` は 0..=10000（既定 100）。上限検証してから確保する。試行の繰り返し（PoC-15 は 5 試行）はスクリプト側（#1882）
- 百分位は nearest-rank（`rank = ceil(p x n / 100)`、整数演算）。単位は us、小数 3 桁
- 期限: 接続・accept・各往復は `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）、クライアントの全体は期限 x 30
- 結果: `schema` = `fandhe-container.tcp-rtt/v1`、`unit` = `us`、`target`、`rounds`、`warmup`、`p50`、`p99`、`min`、`max`、`mean`、`nodelay`、`provisional`、`method`
- 失敗: stderr に `{"tcp_rtt_probe":"error","code":"ARGS|TIMEOUT|CONNECT|DESYNC|IO","message":"..."}`。引数誤りは終了コード 2、他は 1

## 3 経路の置き方（実行は #1882・人間）

ready 行の `containers[].netns` を `<c1>`・`<c2>`、`host_netns` を `<host>` とする。

| 経路 | サーバー | クライアント |
| ---- | -------- | ------------ |
| (a) コンテナ間 | `nsenter --net=<c2> tcp_rtt_probe --serve 10.214.0.3:9101` | `nsenter --net=<c1> tcp_rtt_probe --client 10.214.0.3:9101 --rounds 10000` |
| (b) ホスト -> コンテナ | `nsenter --net=<c1> tcp_rtt_probe --serve 10.214.0.2:9102` | `nsenter --net=<host> tcp_rtt_probe --client 10.214.0.2:9102` |
| (c) ポート公開（DNAT） | `nsenter --net=<c1> tcp_rtt_probe --serve 0.0.0.0:9080` | `nsenter --net=<host> tcp_rtt_probe --client 10.214.1.1:18080` |

iperf3 は (c) で `9080` の代わりに `5201`（公開は `10.214.1.1:15201`）を使う。

## PoC-15 との差

PoC-15 の自作ツールは spec 側にあり、本リポの製品側には無かった。本プログラムは同じ方法（1 バイト、TCP_NODELAY、既定 10000 往復）を std のみで再現するが、計測の場所が隔離 netns でコンテナ役が起動経路を通らない点が異なる。
