# CLI・起動経路への network 結線の設計

`crates/net` に実装済みの `--add-host`・`--dns`・host / none モード・ユーザー定義ネットワーク・DNS ヘルパーを、統一 CLI と supervisor の起動経路から呼べるようにするための結線を設計として確定する。呼び出し主体・順序・後始末・netns への参加方法・hosts / resolv.conf・プロセスをまたぐ状態・排他と期限を決め、残りの実装 issue を起票する。

> **位置づけ**: 本書は #1870 の設計確定である。D1〜D12・D14〜D16 は main（opus）が確定した設計で、実装 issue の入力になる。**D13（rootful のユーザー定義ネットワークの実行主体）だけはオーナー承認待ち**で、決定扱いにしない（人間担当の判断 issue は #3207。判断シートを足した #3057 は PR #3186 で close 済み）。D13 に依存する実装は #3207 の判断が出るまで着手しない。判断シートは D13 節の末尾「D13 の承認事項（判断シート）」にある。

- 対象ビヘイビア: NET-6・NET-12（関連: NET-1〜NET-5・NET-7・NET-9・NET-11・CLI-1・CORE-1・CORE-6・SEC-1・SEC-4・SEC-5・SUP-12・SUP-14・PLUG-1・PLUG-12・REPAIR-2〜REPAIR-5・ERR-1）
- タスク: TASK-185・TASK-143 の追補（MS-6・MS-8）
- 関連 issue: #1870（本設計）・#1871・#1872・#1873・#1935・#1939・#1940・#349（実機実測 TASK-186）・#319（実機実測 TASK-140）・#617
- 出典: `docs/spec` の `04-behavior/api-network.md` の `NET-6`・`NET-12` ほか。本書は spec 本文を貼らず ID で参照する

## 前提となる既決事項（再決定しない）

| 出典 | 内容 |
| ---- | ---- |
| NET-6・CLI-1（spec#14・#340） | `--network` の値は `none` / `host` / 名前の 3 種（`container:<id>` は将来）。既定は `none`（NET-9 確定後も変えない）。ユーザー定義ネットワークの入口は stack の `[networks.<name>]` と CLI の `network create/rm/ls` |
| 2026-10-12 オーナー決定（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6129145225)） | pasta は core 側（コンテナごとの supervisor が起動・回収）。DNS ヘルパーは plugin 側（`NetworkPlugin` の実装）。`crates/net` は core 側のライブラリ |
| 2026-10-15 オーナー決定（[#4 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-6200154873)・spec#22） | rootful のネットワーク設定（veth・bridge・nftables）は plugin 側（`NetworkPlugin` の実装が net を使う）。core は network namespace を用意してその参照を渡すだけ（CNI 型） |
| NET-9 | rootless の `--network <名前>` は pasta の構成として読む。同名コンテナ同士の通信と名前解決は約束しない。IPv6 は作成前に拒否。pasta の細目は #1935（`rootless-network.md`）が確定し、本書は重複して決めず参照する |

## 現状（main `cd1eab83`）

- `crates/net` には `--add-host`・`--dns` の検証と反映、host / none モード、bridge ネットワーク（作成・接続・公開・削除）、DNS ヘルパーが実装済み。製品コードから呼んでいるのは plugin-cri の `netsetup` だけで、本番には注入されていない。CLI と supervisor の起動経路からは届かない
- 本番の CLI 経路は rootless（`RootlessSingleId` / `RootlessSubordinateIds`）。uid 0 は `UNIMPLEMENTED`（#2241）
- 特権ランチャー（SUP-14）を CLI の隣に置いた rootful のインストールでは、supervisor が `CAP_NET_ADMIN`・`CAP_SYS_ADMIN` を ambient で持つ。コンテナは引き続き user namespace の中で動く
- core の start は config の network namespace を `Unimplemented` で拒否し、指定が無ければホストの netns を共有する。CRI の bundle は `POD` / `CONTAINER` で `{"type":"network"}` を出し、`NODE` では出さない
- そのため人間担当の実機実測 #349（TASK-186・NET-12）と #319（TASK-140・NET-2〜NET-4）を製品の経路で確かめられない

## 決定

### D1 フラグの形と受けるサブコマンド

- **決定**: `create` だけが受ける（`start` は受けない）。
  - `--network <値>`: 1 回まで。最大 64 バイト（net の `NetworkName` の上限）
  - `--add-host <hostname>:<ip>`: 繰り返し可。最大 `MAX_ADD_HOST_ENTRIES`=256 件、1 件 299 バイト（253 + 1 + 45）
  - `--dns <ip>`: 繰り返し可。最大 `MAX_DNS_SERVERS`=32 件、1 件 45 バイト
  - 上限は確保の前に検証し、超過は使い方エラー
  - ユーザー定義ネットワーク（bridge）では `--dns` の転送先が DNS ヘルパーの上流転送（D11）に渡るため、上記の件数上限とは別に、上流転送の制約（最大 3 件・loopback・link-local・ヘルパー自身の gateway アドレスの拒否。net の `DnsUpstreamMap::set` と同じ検証）を D2 の検証で作成前に適用する。`ResolvConfPlan::for_mode` が bridge の非空指定を `Unimplemented` にする経路は、この検証を通った値を記録経由で渡す形に結線の側で置き換える（bridge で `--dns` を受けて start 時に初めて失敗する形にしない。NET-12）
  - `--network` の解釈: `none` / `host` は完全一致。`container:` で始まる値は `UNIMPLEMENTED`（spec で将来扱い）。それ以外は net の `NetworkName::new`（`crates/net/src/network.rs`）で検証する。予約名 `none`・`host`・`bridge`・`default` は名前として使えず `InvalidArgument`（net の `NetworkMode::parse` は `bridge` を受けるが、spec の値は 3 種で `bridge` モードは無いため CLI は使わない）
  - `network create <name>`・`network rm <name>`・`network ls` は位置引数のみでオプションを持たない（spec に無い。subnet 等を足すなら spec 側の課題）
  - 3 OS で構文は同じ（CLI-1）。Linux 以外は検証を通した後に `UNIMPLEMENTED`（platform の結線は MAC / WIN 系の後続）
- **理由**: NET-12 は「コンテナ作成前に拒否」を求める。作成時の指定は状態として残り、start が使う（D4）。
- **却下した案**: `start` で受ける（作成前の拒否にならない）。`NetworkMode::parse` の流用（`bridge` を受けてしまう）。

### D2 検証の順序と副作用の前の拒否

- **決定**: CLI `create` の順序は、(1) argv の解析、(2) net の検証関数（`parse_add_hosts`・`parse_ip_addr`・`ResolvConfPlan::for_mode`。none は loopback 限定）、(3) ユーザー定義名なら定義ストア（D10）での存在確認（読み取りのみ）と、その定義が bridge である場合の `--dns` の上流転送用検証（3 件以下・アドレス種別。D1。gateway との一致は定義の subnet から算出して照合する）、(4) OS の判定、(5) 起動オプション文書の書き込み、(6) core の create。状態ディレクトリの作成を含むどの副作用より前に ERR-1 形式で拒否し、メッセージに入力値を含めない。
- **理由**: 規則を CLI 側に二重実装しない（#1871 の受け入れ条件と一致）。

### D3 段階的な導入

- **決定**: #1871 の段階では、検証で不正な値を先に拒否する（#349 の条件 5 を CLI で確かめられる）。正しい値でも `--network`・`--add-host`・`--dns` のどれかがあれば `UNIMPLEMENTED` で拒否し、文書には書かない。#1873 の段階で文書へ書いて反映し、同時に既定の `none` を入れる。
- **理由**: 受理して記録しても反映しない状態を作らない（REPAIR-3）。既定を変える段を 1 つにする。従来は host 相当だった作成の既定が `none` に変わるのは #1873 の 1 段だけで、help と doc にそう書く。
- **却下した案**: #1871 の時点で文書へ記録し、start で無視する。

### D4 CLI から supervisor への受け渡し

- **決定**: 既存の起動オプション文書 `FCOPT1`（`<state_root>/@container-options/<id>`。[container-options-delivery.md](container-options-delivery.md)）に、閉じた語彙の kind を 3 つ足す。
  - `network`: 1 レコード、64 バイト以下
  - `add-host`: 256 件以下、299 バイト以下
  - `dns`: 32 件以下、45 バイト以下
  - CLI は `--network` を省略しても `network none` を必ず書く（NET-6 の既定は CLI が適用する）。supervisor は復号のたびに net のパーサで再検証する（未信頼の入力）。文書に `network` kind が無い（plugin-cri・従来のコンテナ）ときは「config に従う」＝現行の挙動のまま
- 追記（#1935）: rootless のユーザー定義名（pasta 構成）では kind `pasta` と `publish` を足す。詳細は [rootless-network.md](rootless-network.md) 12.4・12.6。`publish` の kind と CLI の `-p` の解析・検証は #3200 で実装済み。CLI が `network` とともに文書へ書くのは #1873 の後。
- **理由**: argv・特権ランチャー・`start_client` を変えずに済む。serde / toml を supervisor へ足さない（依存の承認が要る。既存文書でも却下済み）。
- **却下した案**: argv / env で渡す（既存文書の却下理由と同じ）。core の `StateRecord` に同梱する（plugin 境界の型が変わる）。

### D5 呼び出し主体と依存の向き

| 経路 | 呼ぶプロセス | 呼び先 |
| ---- | ------------ | ------ |
| 入力検証（純粋関数） | CLI `create` | net（既存の依存 `cli` → `net`） |
| 再検証・hosts / resolv.conf への書き込み・host / none の照合 | supervisor の start | net（**`supervisor` → `net` を新設**） |
| netns の作成（none）・参加（rootful bridge） | core の launch（supervisor の同一プロセス内） | core 自身 |
| pasta（rootless のユーザー定義名） | supervisor | net（#1936〜#1940） |
| bridge・veth・nft・DNS ヘルパー（rootful） | `NetworkPlugin` の実装（plugin プロセス） | net（D13。置き場所は承認待ち） |

- **決定**: `supervisor` → `net` は feature を切らない通常の依存にする。net は workspace 内の依存を持たず 3 OS でコンパイルでき（Linux 専用部分は net 側の cfg で閉じている）、循環しない。依存辺を足したときの supervisor の release バイナリのサイズ差分を記録する（CORE-7・SUP-2）。#3065 の PR #3194 では記録が漏れたため、#3212 で記録した（下記「計測（#3212）」）。`core` → `net` は足さない。core は netns を用意するだけ（2026-10-15）で、`lo` の up は D6 で core が自前で行う。
- **却下した案**: supervisor に feature `network` を切る（cfg の組み合わせが増え、`check-standalone-clippy` の行列が増える）。`core` → `net`（core の rlib に netlink / nft の codec が入り、PLUG-4 の不変性判定の対象も広がる）。
- **計測（#3212）**: `supervisor` → `net` の辺（PR #3194・`38a96dcb`）の前後で、supervisor の release バイナリのサイズを測った（CORE-7・SUP-2）。
  - 条件: `cargo build --release --locked -p fandhe-container-supervisor --bins`、x86_64-unknown-linux-gnu、rustc 1.99.0（`b940084d7` 2026-09-28、LLVM 23.1.1）・cargo 1.99.0、GNU binutils 2.46、リンカは GNU ld 2.46（`cc` 経由）。ルートの `Cargo.toml` に `[profile.release]` は無く Cargo の既定（LTO なし・codegen-units 既定）。「strip 前」は Cargo の既定の出力（`strip = "debuginfo"`。シンボル表は残る）、「strip 後」は複製に `strip --strip-all` をかけたもの。3 点とも同じソースパスの 1 つの git worktree を切り替えてビルドし（パス文字列の差が混ざらないようにするため）、target はリポ外で計測後に削除した。計測日 2026-10-28。`38a96dcb` は別の target で作り直して sha256 まで一致した（再現する）
  - 3 点: A = `7b6251b5`（辺の前。issue #3212 の指定）、P = `2df55658`（`38a96dcb` の親）、B = `38a96dcb`（辺を足した commit）。A と B の間には 34 commit があり、その大半は core・supervisor・net に触れる辺と無関係の変更（hosts / resolv.conf 生成・LaunchOptions の network モード・`CLONE_NEWNET` など）を含む。辺の影響として読むのは P → B（ただし #3194 が足した supervisor 側のコード〔`container_options/network.rs`・`document.rs` など〕も含む）

  | 成果物 | 点 | strip 前 | strip 後 |
  | ------ | -- | -------- | -------- |
  | supervisor | A `7b6251b5` | 4,263,656 B（4.07 MiB） | 3,177,184 B（3.03 MiB） |
  | supervisor | P `2df55658` | 4,323,136 B | 3,222,544 B |
  | supervisor | B `38a96dcb` | 4,409,792 B（4.21 MiB） | 3,276,552 B（3.12 MiB） |
  | supervisor の差 | A → B | +146,136 B（+3.43%） | +99,368 B（+3.13%） |
  | supervisor の差 | P → B | +86,656 B（+2.00%） | +54,008 B（+1.68%） |
  | launcher | A | 999,152 B | 677,208 B |
  | launcher | P | 1,000,368 B | 677,768 B |
  | launcher | B | 1,044,784 B | 700,856 B |
  | launcher の差 | A → B | +45,632 B（+4.57%） | +23,648 B（+3.49%） |
  | launcher の差 | P → B | +44,416 B（+4.44%） | +23,088 B（+3.41%） |

  - 内訳（supervisor、strip 前の `size -A`。A / P / B）: `.text` 2,436,534 / 2,471,158 / 2,495,366 B、`.rodata` 153,108 / 157,652 / 158,996 B、`.gcc_except_table` 157,752 / 159,116 / 181,316 B、`.eh_frame` 254,644 / 257,280 / 260,960 B。P → B の増加の大半は `.text`（+24,208 B）と `.gcc_except_table`（+22,200 B）。定義シンボルの総数は 8,938 / 9,063 / 9,595
  - net のシンボル（`nm -C` で `fandhe_container_net` を含む定義シンボル）は A・P で 0 件、B の supervisor で 16 件・合計 5,673 B、launcher で 2 件・合計 200 B。中身は `add_host_dns`（`AddHostEntry::parse`・`HostName::parse`・`parse_add_hosts`・`parse_ip_addr`）、`resolv_conf`（`ResolvConfPlan::for_mode`・`validate_nameservers`）、`network::NetworkName::new` と、これらの `Vec` / `drop_glue` / `RawVec::grow_one` などの単相化だけである。netlink の codec（`netlink*`）と nftables の codec（`nftables_batch` などの組み立て・直列化の関数）は入っていない（`nftables_batch::table_chain::NftName` は `RawVec::grow_one` の型引数に現れるだけ）。supervisor が呼ぶのは net の入力検証と hosts / resolv.conf の純粋関数に限られ、未使用の codec はリンク時に落ちている
  - 所見: net のシンボル自体は 5.7 KB で、P → B の増加（supervisor +86,656 B）の大半は net ではなく #3194 が足した supervisor 側のコードと、それに伴う `.gcc_except_table`・`.eh_frame` である。net の辺そのもののサイズへの寄与は小さい。supervisor が codec を呼ぶ変更（#1936〜#1940 の pasta、D13 の rootful bridge を supervisor に置く場合など）を入れると、codec が入って増加幅が変わるため、その時点で同じ手順で測り直す
  - CORE-7・SUP-2 との関係: バイナリのサイズは PSS ではない。text はページキャッシュで複数の supervisor に共有され、PSS に乗るのは触れたページの按分だけである。SUP-2（supervisor 1 つあたりの PSS 中央値 2MB 以下）の合否はバイト数から推さず、PSS の計測（TASK-158・`scripts/bench/supervisor_pss.sh`。実機は `docs/verification/supervisor-measurement-runbook.md`）で判定する。増加は strip 後で約 3%（net の辺だけでは P → B で約 1.7%）で、現時点で問題とする根拠はない。後続の案: 以後 net の codec を supervisor から呼ぶ PR は、同じ手順の前後差と PSS の再計測を記録する
  - 測っていないもの: PSS・RSS、aarch64・macOS・Windows のサイズ、現在の main のサイズ（#3194 より後に増えた net の利用分は対象外）

### D6 none モード（rootless・CLI 経路）

- **決定**: core の rootless 経路で、中間プロセスが user namespace と同時に `CLONE_NEWNET` を unshare する（netns は user namespace が所有する）。同じプロセスが entrypoint の exec より前に `lo` を up にする。手段は core の `sys` に置く `SIOCGIFFLAGS` / `SIOCSIFFLAGS` の ioctl の薄いラッパー（AF_INET の SOCK_DGRAM）で、事前承認の範囲の新しい unsafe になる（PR 本文に unsafe の一覧と監査の記録を書く。core の libc 照合〔#1847〕が入っていれば `ifreq` の照合も同じ PR で足す）。pin はしない。netns はコンテナのプロセスと一緒に消えるので stop / delete の後始末は不要。
- **理由**: net の `create_none_netns` は `CAP_SYS_ADMIN` を要し、init user namespace 所有の netns を作るため rootless では使えない。supervisor から外の netns へ `setns` するにも init user namespace での `CAP_SYS_ADMIN` が要る。`lo` が down のままだと自己宛て配送が落ちる（#1927・#2077）。
- **却下した案**: supervisor が子の user namespace と netns へ入る補助プロセスで `lo` を up にする（#1939 の同期点が none の起動にも必要になり、fork も増える）。`core` → `net` の依存（D5）。
- **#1939 との関係**: netns の作成と `lo` の up は本項の実装（#3064）が入れる。#1939 はその上に pasta 用の同期点だけを足す。

### D7 config.json との突き合わせ

- **決定**: core の `LaunchOptions` に network モード（`FromConfig`〔既定〕・`Loopback`〔none〕・`Host`）を足す。supervisor は文書の kind から変換する（`none` → `Loopback`、`host` → `Host`、ユーザー定義名 → rootless なら pasta〔#1940〕・rootful なら D12 の参加指定、文書なし → `FromConfig`）。規則は fork・予約より前に判定する。

| モード | config の network namespace | 結果 |
| ------ | ---------------------------- | ---- |
| FromConfig | 無し / 有り | 現行どおり（無しはホスト共有、有りは `Unimplemented`。CRI の `POD` の意味論を壊さない） |
| Loopback | 無し、または path の無い `{"type":"network"}` | 新しい netns と `lo` の up（D6） |
| Loopback | path 付き | `InvalidArgument`（指定の衝突） |
| Host | 無し、または path の無い `{"type":"network"}` | ホスト共有。config のエントリより起動オプションを優先する（`--ipc host` の前例と同じ。`runc spec` の既定 bundle でも使えるように） |
| Host | path 付き | `InvalidArgument` |

- 追記（#1935）: ユーザー定義名かつ rootless の場合、core のモードは「外から付ける netns」（Loopback と同じ中身で、同期点で fd を渡す）になる。[rootless-network.md](rootless-network.md) 12.2・12.3。
- `net.*` の sysctl は、実効のモードが Host なら拒否する（既存の `reject_net_sysctls_without_network_namespace` を実効の名前空間で判定する）。
- **理由**: CLI の既定を変えても CRI の経路（文書なし）の挙動を変えない。
- **却下した案**: core で path の無い network エントリを常に受ける（CRI の `POD` が pod 内で共有されない netns で黙って動く）。Host で config の network エントリを `InvalidArgument` にする（`runc spec` の bundle がそのまま使えず、`--ipc host` と扱いが揃わない）。

### D8 host モード

- **決定**: supervisor は start の入口で自分の netns の (dev, ino) を基準として取る（基準は「supervisor の netns」と定義する）。launch の中の「entrypoint の exec 直前の同期点」（子が exec 前に pipe で待ち、supervisor の検証が済むまで進まない。#3206 で足す。#3058〔PR #3187〕は受け入れ条件に無く `sys` の新しい `unsafe` を伴うため実装しなかった。pasta の同期点〔#1939〕は #3206 の上に fd 2 本への拡張として作る）で、次の方式で確かめる（本番の supervisor は `start_entry.rs` で `PR_SET_DUMPABLE=0` にしており、中間プロセスと exec 前の子もこれを継承する。non-dumpable のプロセスの `/proc/<pid>/ns/*` と `/proc/<pid>/task/<tid>/ns/net` は ptrace アクセス検査で非特権の親から `PermissionDenied` になるため、親が procfs で子の netns を参照する `HostNetns::verify_process(pid)` は本番経路では使わない。既存の non-dumpable 防御〔SEC-1〕は緩めず、`PR_SET_DUMPABLE` を 1 に戻さず、`CAP_SYS_PTRACE` も足さない）。子は同期点で、自分の `/proc/self/ns/net` を `O_RDONLY|O_CLOEXEC` で開き（自分自身の参照は dumpable に依らず許される）、その fd を同期用の `socketpair(AF_UNIX, SOCK_SEQPACKET)` で `SCM_RIGHTS` により親へ渡す。親は受け取った fd を `fstat` し、(dev, ino) を基準と比較する。netns の fd は inode が netns を一意に表すため、procfs の参照と同じ判定になる。fd は 1 本だけを受け、control メッセージ長・fd 数・種別を検証し（余分な fd は閉じて `FailedPrecondition`）、受信には期限を付ける（REPAIR-5）。net 側の判定（Host / Loopback / Other の分類）は pid ではなく (dev, ino) を取る関数 `HostNetns::verify_ns_identity` として切り出し、`verify_process` はその薄い呼び出し元に保つ（実装は #3206 で足す。net 側の切り出しも #3206 の照合に含める。host モードの結線と構造化ログ `network_mode=host` は #1873）。子は同期点で生存が保証されるため、`/bin/true` のように検証前に終了するコンテナでも `NotFound` にならない（verify_process はゾンビを含め生存スレッドが 0 件なら `NotFound` を返す契約で、既定の none にも適用される）。検証後に同期点を解放して exec する。照合は資格情報を落とす前に行う（fd 渡しなので、資格情報の前後に依らず成立するが、順序は変えない）: 同期点は子が `process.user` の setuid / setgid / `setgroups` を行う前（子がまだ supervisor と同じ実 UID の間）に置き、照合の完了を pipe で親子同期してから子が資格情報を切り替えて exec する。これにより RootlessSubordinateIds で `process.user` が非 root（子のホスト UID が supervisor と異なる）でも、`/proc/<pid>/task/<tid>/ns/net` の stat に要る ptrace 相当の権限を増やさずに照合でき、非特権の supervisor が `PermissionDenied` で正常な起動を拒否する（既定の none でも起きる）ことがない。資格情報を落とした後の再照合はしない（netns は setns / unshare 済みで、以後 exec までに変わる経路が無い。エラーの意味は SEC-5 の `FailedPrecondition` に統一し、`PermissionDenied` を照合の失敗として黙って握りつぶさない）。Host は子の全スレッドが基準の netns にいること、Loopback は子が基準と別の netns にいること（`Other`）。違えば子を止めて（同期点で待っているので exec 前に確実に止まる）fail-closed（`FailedPrecondition`）。分離を緩める指定なので、start 時に構造化ログ（REPAIR-4）で `network_mode=host` を 1 行出す。監査ログ（SEC-4）には書かない（分離違反の試行ではないため）。
- 実装（#3206）: core の `crates/core/src/exec/netns_sync.rs`（C 側の `receive_and_verify`・子側の `NetnsSyncSender`）と `launch_intermediate.rs` の配線。決定の本文は変えず、実装で決めた細部は次のとおり（自動運転で安全側に選んだ。オーナーの承認は未取得）。
  - **同期点の位置**: PID 1 の開始ゲート通過後・`child_main`（pivot・stdio・StagePipeline の `CapabilityDrop` 段）の前。PID 1 はこの時点で単一スレッドで、fd 1 本で全スレッドが基準の netns にいることを表せる。C は PID 1 の pidfd を開き、ゲートを開放し、中間プロセスを回収した後、状態 pipe の `P` を読む前に受信する。
  - **範囲**: `LaunchNetworkMode::Host`（期待は基準と同じ）と `Loopback`（基準と異なる）の起動だけが通る。`FromConfig`（既定・CRI の経路）は通さない（D7 の「CRI の経路の挙動を変えない」と整合。pod の netns への join〔#2838〕が入るときに広げるかを見直す）。モードと実効の組が不整合なら fork の前に `Internal` で拒否する。
  - **基準の取り方**: launch の入口（fork の前）で C が自分の `/proc/thread-self/ns/net` を開いて取る。launch を呼ぶ C は `Threads: 1` の supervisor そのもので、start の入口から launch までの間に `setns` / `unshare(CLONE_NEWNET)` をしないため、D8 の「start の入口で取る基準」と同じ値になる。restart の再 launch でも同じプロセスの netns を取り直す。取れなければ子を作らずに `FailedPrecondition`（段 `netns_verify`）。レビューで決定との食い違いと判断された場合は、`LaunchOptions` に基準を渡す入口を足して supervisor の `start_entry` で取る形へ切り替える。
  - **ワイヤー**: listener 用とは別の `SOCK_SEQPACKET` の socketpair。子 → C は本文 `N` ＋ `SCM_RIGHTS` の fd 1 本（C の端は `SO_PASSCRED`）、C → 子は本文 `A`。受信側は期待する fd の種別の列（`[Net]` か `[Net, User]`）を取り、#1939 の `Attachable` は netns・user namespace の 2 本を渡す（実装済み。`rootless-network.md` 12.2「実装（#1939）」）。検証は切り詰め・本文・本数・送信元 pid・close-on-exec・nsfs（`fstatfs`）・`readlink` が `net:[<ino>]` であること、そのうえで (dev, ino) を期待と照合する。
  - **期限と fail-closed**: 子の ACK 待ちは 60 秒（開始ゲートと同じ）、C の受信は launch の単一期限の残りまで。EOF・期限切れ・`A` 以外では子は exec せずに終了し、C は PID 1 を kill して回収する。C の端は中間プロセスで閉じ（PID 1 へ継承させない）、親の死は EOF で子に届く。
  - **監査（SEC-4）**: 不一致（理由 `netns_identity_mismatch`）と形式違反（`netns_handoff_invalid`）は、段 `netns_verify`・層 `mount`・パスなしで 1 件記録する（`FailedPrecondition`）。EOF・期限切れ・errno・子の `E` 通知は系のエラーで記録しない。message は固定の英文で、inode の値を含めない。
  - **範囲外**: `network_mode=host` の構造化ログ 1 行と、net の `HostNetns::verify_ns_identity` の切り出し・結線は #1873、pasta 構成の fd 2 本と合図は #1939 で実装済み（フックの実装は #1940）。
- 追記（#1935）: pasta 構成の同期点では netns と user namespace の fd を 2 本、この順で受ける（[rootless-network.md](rootless-network.md) 12.2）。Loopback・Host は 1 本のまま。
- **却下した案**: 照合を省く（設定誤りを検出できず、#1873 の受け入れ条件にも合わない）。

### D9 hosts / resolv.conf

- **決定**:
  - 生成場所は `<state_root>/@container-etc/<id>/`（ディレクトリ 0700）の `hosts` / `resolv.conf`（通常ファイル 0644・所有者は supervisor の euid）。core の新 API（`etc_files`。型は OS 非依存、実体は Linux）が排他作成（`O_CREAT|O_EXCL|O_NOFOLLOW`・fd 起点）で作る。`@container-options` と同じく `--root` と `<id>` だけから導く
  - `hosts` は core が固定の初期内容（`127.0.0.1 localhost` と `::1 localhost ip6-localhost ip6-loopback`）を書き、supervisor が net の `apply_add_hosts` で `--add-host` を追記する。`resolv.conf` は supervisor が net の `apply_dns` で書く（host / none。`--dns` があるときのみ。rename 置換）。rootful のユーザー定義ネットワーク（bridge）では指定の有無に依らず supervisor が `resolv.conf` を生成する: `nameserver` は DNS ヘルパーの待ち受けアドレス（ネットワークの gateway アドレス。attach 後に確定するため、D14 の順序で attach の結果を受けてから書く）だけにし、`--dns` はコンテナの記録（`members/<id>`）経由でヘルパーの上流（D11 の `--dns` の上流転送）に渡す。この場合 `--dns` の値は `resolv.conf` に直接は書かない。イメージの `/etc/hosts` は読まない（未信頼の rootfs のファイルを読む経路を作らない）
  - 生成条件の限定は host / none にだけ適用する（`--add-host` があれば `hosts`、`--dns` があれば `resolv.conf`）。rootful の bridge は上記のとおり `--dns` の有無に依らず `resolv.conf` を生成する。限定に当たらず生成しないものはイメージのファイルをそのまま使い、従来の挙動を変えない
  - 段は supervisor の start の手順 3〜7（作業スレッド・期限つき）で、launcher を作る前に作成と書き込みを終える。`apply_dns` は rename で inode が替わるため bind mount より前に済ませる。start のたびに作り直し（前回の残りを消してから排他作成）、supervisor 内の restart は同じファイルを使い回す
  - bind mount は launcher のオプションで core に渡し、pivot の前、検証済みの bind（#1915）と同じ段で適用する。ただし利用者の bind（`mounts[]`）の検証〔元が状態ルートの同一・祖先・子孫なら `BindSourceReachesStateRoot` で拒否。SEC-1〕には通さず、core 内部の専用の種別（`EtcFileMount`）として扱う。この種別の元は呼び出し側のパスではなく core が `state_root` と `<id>` から固定の形（`<state_root>/@container-etc/<id>/{hosts,resolv.conf}` の 2 つだけ）で導く（任意のパスを受けない。`@container-options` と同じ流儀）。利用者の bind の元が `@container-etc` を指す場合は従来どおり `BindSourceReachesStateRoot` で拒否し、緩めない。元のファイルは launch の時点で状態ルートから 1 要素ずつ fd 起点（`O_PATH|O_NOFOLLOW`）で開き直し、`@container-etc/<id>` が 0700・所有者 euid であること、ファイルが通常ファイル・所有者 euid・nlink 1 であることを確かめる（不適合は `FailedPrecondition`）。先は rootfs の fd から 1 要素ずつ辿る（`mount_destination` の検証）。rw で mount する（Docker と同等。書き換えても自分の生成ファイルにしか及ばない）
  - 先が symlink: 解決せず `InvalidArgument` で拒否を続ける（#3210 の決定。理由と利用者向けの文言は下の「先が symlink の扱い（#3210）」）。`/etc` が無い、または symlink: `InvalidArgument`。先のファイルが無い: `/etc` の fd の下に 0644 の空ファイルを排他作成してから mount する。`root.readonly` で先が無い: `FailedPrecondition`。利用者の `mounts[]`・tmpfs・注入ファイルと先が重なる: `InvalidArgument`
  - rootless は `SingleId`・`SubordinateIds` のどちらでも、元のファイルの所有者はコンテナの root に当たる uid で 0644 なので読める。mount はコンテナの user namespace が所有する mount namespace の中で行う
  - 後始末: start の失敗時は supervisor が自分で作ったものを消す。CLI の `delete` が成功した後に `@container-etc/<id>` を消す（`@container-options` と同じ条件）。plugin-cri は作らない
- **実装の補足（#1872。core 側の実装済みの範囲）**:
  - core の公開 API は `etc_files`（`create_etc_files`・`remove_etc_files`・`check_etc_overlaps`）と、launcher の起動オプション `LaunchOptions::with_etc_files`、pivot 前段の `exec::mount_etc_files`（`inject_files` の後・`mount_binds` の前。`PrePivotStep::EtcFiles`・`IsolationStage::MountEtcFiles`）。`CreateRequest`・`StateRecord` には何も足さない
  - `create_etc_files` は `<id>` が既にあれば `ALREADY_EXISTS` で拒否する。「start のたびに作り直す」は呼び出し側（supervisor。#1873・#3065）が `remove_etc_files` の後に `create_etc_files` を呼んで実現する
  - mount のモード: 既定は rw（D9 のとおり）。実効の `root.readonly=true` では ro で載せる（containerd の `containerMounts` が `readonly_rootfs` を hosts / resolv.conf の `Readonly` に写す挙動に揃えた、閉じた側の選択。一次情報の確認は #2859 に残し、違えば緩める）。ro のときに先が無いなら rootfs へ書かず `FailedPrecondition`
  - 元の検証は 2 段: launcher が fork 前に所有者・権限・nlink を検査して `(st_dev, st_ino)` を記録し、子（新しい mount namespace）が同じ正規化済みパスを辿り直して `(st_dev, st_ino)` と nlink 1 の一致を要求する（user namespace の中では uid が写像後の値になるため）
  - 未実装: supervisor の start からの呼び出し・start 失敗時の巻き戻し（#1873・#3065）、rootful bridge の resolv.conf（D13・#3074）、`RootfulHostRoot`（launcher が拒否。#2241）
- **先が symlink の扱い（#3210。NET-12・SEC-1）**: 解決せず拒否を続ける。理由:
  1. systemd-resolved 形（`/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf`）は、解決しても救えない。`/run` は実行時の tmpfs でイメージの tarball では空のため、解決先の親ディレクトリを作らない制約の下では結局拒否になる。救えるのは rootfs 内にある通常ファイルを指す symlink だけで、まれな場面と見込む（実イメージでの確認はしていない）
  2. 利用者の bind（`mounts[]`）は先の symlink を解決せずに拒否する（`bind_mounts.rs`）。etc の bind だけ解決すると方針が混ざる
  3. 影響は狭い。host / none では `--add-host` / `--dns` を指定したときだけ生成するため、フラグなしの起動は当たらない
  4. pivot 前の段に新しいパス解決の面を足さない。解決する方式は core の `sys` に `openat2(RESOLVE_IN_ROOT)` の新しい `unsafe` ラッパー（`EAGAIN` の再試行・`RESOLVE_NO_XDEV`・親と葉を分ける 2 段の解決・`check_etc_overlaps` の解決後パス対応）を要する
  - 利用者向けの文言（`InvalidArgument`・固定の英語。rootfs の値は含めない）: hosts は `/etc/hosts in the rootfs is a symbolic link; the container etc mount does not follow symbolic links (replace it with a regular file in the image)`。resolv.conf は同じ文頭で `(replace it with a regular file in the image, or remove it when the rootfs is writable)`。`/etc` 自体が symlink・非ディレクトリ・無い場合の拒否は変えない
  - 見直し条件は「残余・見直し条件」を参照
- **却下した案**: SUP-12 の `injected_files` の流用（親ディレクトリ単位の tmpfs で `/etc` 全体を覆い隠し、単一ファイルの bind は未対応）。CLI の create で生成する（restart と start のたびの再生成を同じ経路にできない）。イメージの hosts を写してから追記する。symlink の先の inode の上に mount する案、rw の rootfs で symlink を消して通常ファイルに置き換える案（rootfs の意味を未検討の形で変える）。解決先の親ディレクトリを作る案（オーナー判断が出たら見直す）。

### D10 ネットワーク定義の状態ストア（CORE-1）

- **決定**: 置き場所は net の新モジュールで、CLI・supervisor・`NetworkPlugin` の実装のどれからも使える。常駐デーモンを置かず、ファイルとロックだけで持つ。

```text
<state_root>/@networks/            0700・所有者 euid
├── @lock                          全体のロック
└── <name>/
    ├── definition                 FCNET1（FCOPT1 と同じ長さ接頭辞のテキスト・閉じた語彙。符号化と復号を同じ型に置く。REPAIR-2）
    ├── @lock
    ├── members/<container-id>
    ├── realized
    ├── pending-reclaim/           既存の ReclaimStore の形を流用
    └── dns-helper
```

- 検証: 開くたびに fd 起点・`O_NOFOLLOW`。ディレクトリ 0700・ファイル 0600・所有者 euid・通常ファイル・nlink 1。違反は fail-closed（`PermissionDenied` / `FailedPrecondition`）。読み込みは上限（1 レコード 4 KiB）を検証してから確保する
- 排他: `flock` を `LOCK_NB` で取り直し、期限つきの backoff で待つ（既定 5 秒、超えたら `Timeout`。[state-lock-contention.md](measurements/state-lock-contention.md) の飢えの対策に倣う）。順序は全体のロック → ネットワークのロック（デッドロック回避）。`ls` は共有ロック
- 上限: ネットワーク数 256（D13 の subnet の pool と一致）。メンバー数は subnet の割り当て可能数（/24 で 253）。超過は作成前に `ResourceExhausted`
- 定義の中身: 名前、作成モード（`pasta` = rootless のインストール / `bridge` = rootful のインストール）、bridge なら subnet
- `network create`: 全体のロックの下で、名前の検証 → 予約名の拒否 → 存在の確認 → 定義の書き込み。カーネル資源は作らない。`network rm`: メンバーも孤児の記録も無いときだけ定義を消し、あれば `FailedPrecondition`。`network ls`: 定義の一覧（形式は既存の `list` に揃える）。`create --network <名前>`: 定義が無ければ `NotFound`。start でも再照合する（作成から起動までの削除を許さない）
- **理由**: CLI に特権が無くても動き、CORE-1・D-19 と整合する。
- **却下した案**: 常駐デーモン。core の StateStore への同梱（core の型が変わり、net の状態は plugin 側も使う）。serde / toml（依存の承認が要る）。

### D11 プロセスをまたぐ各状態の持ち方

| 項目 | 持ち方（決定） |
| ---- | -------------- |
| ネットワーク定義 | D10 の `definition` |
| `CreatedNetwork`（作成済みのカーネル資源） | `realized` に bridge 名・ifindex・所有トークン・nft テーブル名・テーブル handle・gateway・subnet を記録する。`create_network` の成功後に書き、`delete_network` の成功後に消す。カーネル操作の前に意図記録（`realized.intent`。操作の種類・bridge 名・所有トークン・予約した subnet）を fsync して書き、成功後に `realized` へ置き換える。操作後・記録前に SIGKILL されても意図記録が残るため、次の特権操作の先頭が所有トークンでカーネルを照合し、実在し、かつ全構成の完成（アドレス設定・up・nft テーブルの作成と、記録する handle の取得）を確認できたときだけ `realized` に昇格する。所有トークンが一致しても未完成（トークン設定の後、アドレス設定・up・nft テーブル作成の途中で SIGKILL された部分状態）の場合は、昇格せず意図記録を残したまま、不足している操作を冪等に完了させるか、完了できなければ所有トークンで照合できた資源だけを逆順に巻き戻して意図記録を捨てる（巻き戻しの失敗は `FailedCreateClaim` 相当の回収待ちとして残す。特権操作の後始末・REPAIR-3）。実体が無ければ意図記録を捨てる。`FailedCreateClaim` は失敗を受け取れる経路でしか生成できないので、クラッシュの回収はこの意図記録が担う |
| 静的 IPAM | 独立したカウンタを持たない。全メンバーのアドレスと隔離（結果不明で保持した）アドレスから、ネットワークのロックの下で操作のたびに `StaticIpam` を組み立て直す（数え違いが起きない） |
| メンバー（attach） | `members/<id>` に endpoint・アドレス・公開（受け口と nft の rule handle）・`--dns` の上流を記録する。attach の前に意図記録（別ディレクトリ `members-intent/<id>`。割り当てるアドレス・endpoint 名・所有トークン）を fsync して書き、成功後に `members/<id>` を作って意図記録を消し、detach の成功後に `members/<id>` を消す。ContainerId はドットを許すため、確定記録（`members/`）と意図記録（`members-intent/`）はディレクトリで名前空間を分け、拡張子による判別は行わない。IPAM の再構成は `members/*` に加えて `members-intent/*` のアドレスも使用中として数えるため、クラッシュで未記録になった endpoint のアドレスを再割り当てしない。意図記録が残っていて実体が無いものは次の特権操作が掃除する。取り残しは既存の `FailedAttachClaim` と `.owned/<endpoint>` |
| DNS ヘルパーの参照カウント | カウンタを持たず、メンバーの記録の件数を正とする（ロックの下で数える）。0→1 で起動、1→0 で停止（NET-7） |
| 親からの切り離し | ヘルパーを `setsid` と二重 fork で親から切り離して起動し、`dns-helper` に pid・`/proc/<pid>/stat` の開始時刻・boot id を記録する。停止時は記録の pid から `pidfd_open` で pidfd を先に取得し、その pidfd が指すプロセスの開始時刻（`/proc/<pid>/stat`）と boot id を記録と照合して同一性を確かめる（取得後に照合するため、照合と操作の間の pid の再利用で別プロセスを対象にしない）。同一でなければ何も送らず記録を古いものとして扱う。以降の期限つきの待機（pidfd の可読化）と強制停止（`pidfd_send_signal` の SIGKILL）はすべてその pidfd に対して行い、pid 番号へのシグナル送信はしない（制御 UDS の停止要求 → pidfd で期限つきで待つ → 超えたら pidfd へ SIGKILL）。pidfd_open が使えないカーネルでは停止を行わず `Unimplemented` で報告する。`Drop` で止める今の形は試験専用に残す |
| 名前の登録経路 | ヘルパーはメンバーの記録を正として読み込む。登録側は記録を書いた後に制御 UDS（`<name>/dns.ctl`・0600・`SO_PEERCRED` で uid を照合。PLUG-12）へ `Reload{generation}` を送り、`Loaded{generation}` の ack を期限つき（既定 2 秒）で待つ。フレームは型付きの長さ接頭辞（REPAIR-2）。ack が無ければ attach を失敗にする |
| `--dns` の上流転送 | メンバーの記録の `--dns` から、ヘルパーが読み込みのたびに `ForwardingHandler` をコンテナのアドレス単位で組む（製品の経路）。upstream の検証は net の既存関数 |
| ポート予約（`PortRegistry`） | 同じ状態ルート内では、全ネットワークのメンバーの公開を全体のロックの下で集めて照合する。状態ルートをまたぐ衝突（CLI と plugin-cri の `.cri`、別の `--root`）はファイルを共有しても保証できないので、カーネルを正とし、公開の前に全 `fandhe_net_*` テーブルの DNAT を GETRULE で dump して照合する。nft は同一の受け口の重複を拒否しない（`publish.rs` の契約）ため、照会と投入の間に別の `--root` が割り込むと両方が「競合なし」と判定して二重に投入できる。これを避けるため、dump の照合から DNAT の投入までを、状態ルートに依らない共有ロック（`/run/fandhe-container/net-publish.lock` 相当。D15）。このロックは許可した実行主体だけが取得できるようにする: Linux の `flock` は読み取り用 fd でも排他ロックを取れるため、0644 の共有ファイルでは無関係なホストユーザーがロックを保持し続けて全状態ルートのポート公開を `Timeout` に追い込める（5 秒の期限は各呼び出しを終わらせるだけで妨害を防げない）。そこで、ロックファイルは親ディレクトリ `/run/fandhe-container/`（root 所有 0755）の下の root 所有・グループ `fandhe-net`（専用グループ。公開を行う実行主体だけが属す）・モード 0660 とし、ディレクトリを fd 起点で検証した上で `O_NOFOLLOW` で開く（所有者・モード・nlink 1 を fstat で確認し、不適合は `FailedPrecondition`）。他ユーザーには open 自体が `EACCES` になるので取得も保持もできない。rootful の DNAT 公開では、ロックの利用を公開の必須条件とする（nft の DNAT はソケットを bind せず、kernel の bind 衝突では二重投入を防げないため）。グループを作れない・属せない・ロックを開けない・期限内に取れない場合は、公開を fail-closed で拒否する（公開の指定が無いコンテナの attach・起動は影響を受けない。rootful で `-p` を指定した場合はエラーを返す。ロック無しで投入する経路を持たず、0644 や 0666 へ緩めて代替しない）。kernel の bind 衝突への委譲は pasta（rootless。pasta 自身がホスト側のソケットを bind するため、衝突は kernel が拒否する）に限る。特権ランチャーが root で開いた fd を `SCM_RIGHTS` で渡す案は、ランチャーの面を広げるため採らず、残余とする。`flock` は `LOCK_NB` の取り直しと期限 5 秒で取るの下で行う。rootless の pasta はこのロックの対象外で、上記のとおり kernel の bind 衝突に任せる（rootful の代替ではない）。ロックの外から投入する経路（手動の nft 操作）は検出のみで、投入後にもう一度 dump して自分の受け口が複数ある場合は自分のルールを削除して `AlreadyExists` で失敗する（世代を条件にした事後確認と再試行は 1 回まで） |
| 公開ハンドルの再起動後の復元 | dump ではなく永続化で復元する。メンバーの記録の rule handle とテーブル handle を照合し、テーブルが作り直されていた（handle が違う）ら、その rule handle は古いので削除に使わず報告する |
| attach 済みコンテナの detach | net に、コンテナ単体の切り離し（`unpublish_container_port` で公開を個別に解除 → veth → pin → IPAM の記録）を足す。`NetworkPlugin::detach` の attach 済みの `Unimplemented` をこれで埋める |
| masquerade と `ip_forward` | net に `bitwise` / `meta` の expr と、postrouting の masquerade（出口が bridge 以外）を足す。host の `ip_forward` は net が変更しない方針のまま（NET-10 の診断で案内する） |
| `eth0` へのリネーム | attach で peer を netns へ移した後、`IFLA_IFNAME` で `eth0` に変える（`LinkSet` に足す） |

### D12 netns への参加方法（rootful bridge）

- **決定**: `NetworkPlugin::create_netns` が返す pin のパス（netns の置き場の配下）と (dev, ino) を、supervisor が launcher のオプション（参加指定）で core へ渡す。core は `NamespaceJoin` を network に広げて検証する（#2872・#2776 と同じ流儀）。
  - パスを 1 回だけ開いて fd に固定する
  - nsfs であること、`NS_GET_NSTYPE` が net であること
  - (dev, ino) が渡された値と一致すること
  - 所有 user namespace が init であること（rootful の参加先）
  - パスが置き場の配下で `..` を含まないこと
  - user namespace を作る前に `setns` する（init user namespace での `CAP_SYS_ADMIN` は特権ランチャー経由の supervisor から引き継ぐ）。拒否と受理は監査に残す（SEC-4）
- fd の受け渡し（SCM_RIGHTS）は採らない。#460 で未決だった方式をここで決める。**理由**: plugin 境界のフレームを広げる必要があり、パスと (dev, ino) の照合で TOCTOU を閉じられる。
- CRI の pod の join（#2872。user・ipc・net の組）とは別の入口で、init user namespace 所有の net は #2872 では従来どおり `Unimplemented`。実装は #3069（D13 の承認が前提）。

### D13 rootful のユーザー定義ネットワークの実行主体（オーナー承認待ち）

**決定扱いにしない。推奨と案を並べ、判断は #3207（人間担当。判断シートは #3057）で行う。**

- 前提: CLI は特権を持たない。特権を持つのはランチャー経由の supervisor だけ。2026-10-15 の決定で、設定は `NetworkPlugin` の実装（plugin 側）が行う。
- 推奨の流れ:
  1. `network create` は定義（D10）と subnet の予約だけ行う。subnet は pool `10.89.0.0/16` の /24 から、全体のロックの下で空きの先頭を取る
  2. 最初の attach で supervisor が `NetworkPlugin` の plugin を一回起動し（必要な capability だけを ambient に残す）、`create_network` を呼ぶ。続けて DNS ヘルパーを起動し、`create_netns`・`attach` を行う
  3. 最後の detach（コンテナの最終終了・stop）で `detach` を呼び、0 件なら `delete_network` を呼んでヘルパーを停止する
  4. CLI の `delete` は特権が無いので、supervisor が異常終了して残った記録を孤児として印を付けるだけにする。回収は次の特権操作（同じネットワークの start）が先頭で行う。`network rm` は孤児があれば拒否し、手動の手順（[network-reclaim-recovery.md](../setup/network-reclaim-recovery.md)）を示す
- plugin プロセスの置き場所の案:
  - (A) **推奨**: 新 crate `fandhe-container-plugin-net`（bin）を作り、plugin-cri の `NetsetupNetwork` などをこの crate の lib へ移して plugin-cri と共有する。crate の追加なので [crate-naming.md](crate-naming.md) の改定とオーナー承認が要る
  - (B) plugin-cri のバイナリに `NetworkPlugin` の RPC を足す（CRI と CLI の結合が増える）
  - (C) supervisor の中で net を直接呼ぶ（2026-10-15 の決定に反する）
- 関連する承認待ち: RootfulHostRoot（#2241）。plugin の起動の配線（#1869）は closed で、[plugin-backend-wiring.md](plugin-backend-wiring.md) の設計案に従う。
- spec 側への確認事項: 作成・削除を最初の attach / 最後の detach へ遅らせると、NET-4 の「ネットワーク作成・削除」の時間の意味が変わる。

#### D13 の承認事項（判断シート）

すべて未決である（2026-10-27 時点）。窓口は #3207（#3057 は判断シートを足した PR #3186 で close 済み）。返答は「D13-1: A / D13-2: 推奨どおり / D13-3: (a)、spec へ持ち込む / D13-4: 推奨どおり」の形で受ける。回答を受けたら #3207 にコメントで記録して（#3057 にも参照を残し）close し、下の棚卸しに沿って設計文書を更新する。

| 番号 | 判断事項 | 選択肢 | 推奨 | 影響 | 判断 |
| ---- | -------- | ------ | ---- | ---- | ---- |
| D13-1 | rootful の `NetworkPlugin` 実装（plugin プロセス）の置き場所 | (A) 新 crate `fandhe-container-plugin-net`（bin） / (B) plugin-cri のバイナリに `NetworkPlugin` の RPC を足す / (C) supervisor の中で net を直接呼ぶ | (A) | 下の補足を参照 | 未決 |
| D13-2 | カーネル資源（bridge・nft のテーブル・DNS ヘルパー）を作る・消す時点 | (i) 遅延: `network create` は定義と subnet の予約だけ。最初の attach で `create_network`、最後の detach で `delete_network` / (ii) 即時: `network create` の時点で作る | (i) | (i) は特権を持たない CLI の前提を崩さない。NET-4 の「作成・削除」の時間の意味が変わる（D13-3）。(ii) は CLI の `network create/rm` にも特権の経路（ランチャー経由の一時プロセス）が要り、SUP-14 の特権の面が広がる | 未決 |
| D13-3 | D13-2 が (i) のときの NET-4 の計測区間（spec リポ側の事項。本リポでは決めない） | (a) plugin の `create_network` / `delete_network` の RPC 単体を「作成・削除」とする / (b) 最初の attach（作成と接続）・最後の detach（切り離しと削除）をまとめて計測する / (c) CLI の `network create/rm` を計測する | (a)（PoC-15 の計測区間に最も近い。(b) は補助の値として残す） | NET-4 の期待値の読み方と #319 条件 2〜4 の計測手順が決まる。(c) は記録だけの時間のため Docker との比較に意味が無い。spec の文言を改めるかはオーナーが spec リポで判断する | 未決（spec 側） |
| D13-4 | #2241（RootfulHostRoot）と合わせて判断する必要があるか | 独立に判断する / #2241 の回答を待つ | 独立に判断する | D13 の rootful は、ランチャー経由で ambient capability を持つ非 root の supervisor が、user namespace の中のコンテナのために init user namespace 所有の netns を用意する構成（[privilege-separation.md](privilege-separation.md)）。#2241 は uid 0 のまま user namespace を作らない権限モデルの採否で、どの答えでも D13 の前提は崩れない。D13-1 の推奨は #2241 の結論に依存しない | 未決 |

D13-1 の補足（選択肢ごとの影響）:

- (A) 新 crate `fandhe-container-plugin-net`
  - [crate-naming.md](crate-naming.md) の確定一覧への追加（plugin 系 6 個目）とオーナー承認が要る。PLUG-11 の発見はバイナリ名 `fandhe-container-plugin-*` で行うので、命名規約に合う
  - plugin-cri の `crates/plugin-cri/src/netsetup.rs`（`NetsetupNetwork`・`LinuxNetsetup`）と `netsetup/reclaim_store.rs` を新 crate の lib へ移し、plugin-cri がそれに依存する形にする（ワークスペース内の依存辺が 1 本増える。外部依存が増えるなら別途承認が要る）
  - 許可済みハッシュ一覧（[plugin-hash-allowlist.md](plugin-hash-allowlist.md)）の対象と、`scripts/install-privileged-launcher.sh`・`docs/setup/linux.md` の配置対象に加わる。PLUG-11 の検証対象のバイナリが 1 つ増える
  - PLUG-4 の判定（core の rlib の sha256）では core が変わらない
- (B) plugin-cri に RPC を足す: crate は増えない。一方で CRI（kubelet 向け）と CLI 経路が 1 つのバイナリを共有し、plugin-cri の更新と信頼性検証の単位に CLI の rootful 経路が巻き込まれる（REPAIR-1）。plugin-cri の常駐起動と、CLI 経路の一時起動を両立させる設計が別に要る
- (C) supervisor から net を直接呼ぶ: 2026-10-15 のオーナー決定（rootful のネットワーク設定は plugin 側）に反する。選ぶならその決定の変更が先に要り、D5 の表と crate-naming.md の net 行も改める
- どの案でも変わらないもの: D14 の `net-helpers` cgroup・`CLONE_INTO_CGROUP` での起動、init user namespace 所有の netns への参加（D12）は承認まで実装しない

#### D13 の決定後の変更の棚卸し

本節の時点では何も変えていない。D13-1 の回答ごとに触れる箇所は次のとおり。

| 区分 | (A) のとき | (B) のとき | 共通 |
| ---- | ---------- | ---------- | ---- |
| 設計文書 | `crate-naming.md` の確定一覧・plugin 系の数・決定の追記、本書 D5 の表の「置き場所は承認待ち」と D13 の「承認待ち」の解除、冒頭の位置づけ注記 | 本書の D5・D13、[plugin-backend-wiring.md](plugin-backend-wiring.md) の plugin-cri の役割 | `docs/architecture.md` の設計ドラフト行を確定済み設計判断の表へ移す。crate を足すときは `CLAUDE.md` のリポジトリ構造も更新する |
| 実装 issue | 新 crate の雛形と netsetup の移設の issue を親 #3056 の配下に起票する（承認後） | plugin-cri への RPC 追加の issue | #3069・#3074・#3075 の依存欄から #3057 を外す。#3074 の本文に選んだ置き場所を書く |
| 試験 | 新 crate の既定のテスト集合で、`create_network` / `attach` / `detach` / `delete_network` の順序と参照カウント（0→1・1→0）を具体値で照合する | plugin-cri 側で同じ照合 | 実機前提（`CAP_NET_ADMIN`・init user namespace の netns）の試験は `#[ignore]` で分離し、`AGENTS.md`「実機前提テスト」に実行方法を書く（#3074・#3069 で行う） |
| spec 側 | — | — | D13-3 の回答に応じた NET-4 の文言の見直し（spec リポ側の課題。本リポからは編集しない） |

### D14 失敗時のロールバック・stop / delete の後始末

- **決定**: supervisor の start の順序は、(1) 文書の復号、(2) hosts の作成と、host / none の resolv.conf の書き込み（D9）、(3) rootful のみ plugin の `attach`（D13）と、bridge の resolv.conf の生成（D9。ヘルパーのアドレスは attach の結果から得る）、(4) cgroup、(5) launch（netns の作成 / 参加）、(6) host / none の照合（D8）、(7) 報告。k 段目で失敗したら k−1 段目から逆順に戻す（detach → 生成ファイルの削除）。none / host ではカーネル資源の巻き戻しは無い（netns はプロセスと一緒に消える）。
- cgroup 配置（NET-7。(3) の plugin と DNS ヘルパーは (4) の cgroup 準備より前に起動するため、ここで決める）: `DelegatedCgroup::prepare` は委譲親に supervisor と登録済み companion 以外のプロセスがあると拒否し、companion は評価時にコンテナの cgroup 側へ退避（移動）される。`setsid` と二重 fork は cgroup の所属を変えないので、何もしないと plugin とヘルパーが supervisor の scope を継承して最初の bridge 起動が失敗する。また共有ヘルパーはコンテナより長生きするため、コンテナの cgroup や supervisor の scope に置いてはならない（コンテナの終了や scope の削除で巻き添えになる）。そこで次のとおり決める。
  - 配置先: **supervisor の scope（コンテナごとの systemd scope）とは独立した cgroup** `net-helpers` に置く。委譲された cgroup の根（コンテナごとの scope 配下）には置かない（最初の supervisor が終了して scope が破棄されると、配下のヘルパーも道連れになり、同じネットワークの他コンテナの DNS が失われるため）。`net-helpers` は特権ランチャーが rootful の起動時に作成する、ランチャー管理の恒久的な unit（例: `fandhe-container-net-helpers.slice` 配下の独立 scope / service。名前は #3074 で確定）で、どのコンテナの scope・cgroup の祖先でも子孫でもない。寿命は「ネットワークの最後の detach（D11 の 1→0）まで」で、個々の supervisor の寿命には依存しない。plugin（`attach` / `detach` の間だけ生きる一時プロセス）と DNS ヘルパー（参照カウントが 0 になるまで生きる共有プロセス）の両方をここに置く。
  - 移動する時点: 起動の瞬間から入れる。`clone3` の `CLONE_INTO_CGROUP`（`net-helpers` の fd）で起動し、fork から移動までの間に委譲親へ残る窓を作らない。`CLONE_INTO_CGROUP` が使えない環境では、起動の直後・(4) の前に、`pidfd` で同一性を確かめた上で `cgroup.procs` へ書いて移し、移し終えるまで (4) へ進まない（移せなければ起動を失敗にして D14 の逆順に戻す）。
  - companion の範囲: plugin とヘルパーは companion に登録しない（登録すると prepare がコンテナ側へ退避して寿命が壊れるため）。companion は従来どおり、supervisor 自身に付随してコンテナと運命を共にするプロセスに限る。`prepare` の委譲親の検査はそのまま（supervisor と companion 以外のプロセスがいれば拒否）で、plugin とヘルパーは `net-helpers` にいるため検査に掛からない。
  - 順序の整合: (3) の起動時に配置が済んでいることを (4) の前提条件とし、(4) は委譲親に `net-helpers` 由来のプロセスが残っていないことを（記録の pid の cgroup を読んで）確かめてから進む。0→1 で起動したヘルパーは、最後の detach（1→0）の停止（D11）まで `net-helpers` に居続ける。最初の supervisor が先に終了・異常終了しても、`net-helpers` は supervisor の scope と独立しているのでヘルパーは生き残り、他のコンテナの DNS は途切れない。回収は次の特権操作が先頭で行う（D13）。
  - DNS ヘルパーの起動窓（意図記録）: 二重 fork で切り離した後、`dns-helper` の記録（pid・開始時刻・boot id）を書く前に起動元が SIGKILL されると、`net-helpers` に居る生存ヘルパーが記録に残らず、親の終了でも回収されず、次の起動で gateway:53 の bind が競合する。これを CreatedNetwork の意図記録と同じ扱いで閉じる。(i) 起動の前に意図記録（`dns-helper.intent`。ネットワーク名・起動 nonce・gateway:53）を fsync して書く。(ii) 子は起動直後に自身の識別情報（pid・開始時刻・boot id・nonce）を起動元との同期用 pipe へ送り、起動元が `dns-helper` の記録を fsync して書き終え ack を返すまで、期限つき（既定 2 秒。D15）で待つ。bind と応答の開始は ack の後で、期限内に ack が無ければ子は bind せず自ら終了する（起動元が記録前に死んだ場合もこの経路で子が残らない）。(iii) 記録の確定後に意図記録を消す。(iv) 次の特権操作の先頭は、意図記録が残っていれば `net-helpers` の cgroup の中から nonce を持つプロセス（起動引数の nonce を `/proc/<pid>/cmdline` で照合し、pidfd 取得後に開始時刻を再確認）を探して pidfd 経由で停止し、意図記録を捨ててから起動し直す。この手順は記録ベースの停止が使えない窓の専用回収である。
  - 実装: ランチャーの `net-helpers` の作成と supervisor の配置を #3074 に、DNS ヘルパーの同期手順（ack 待ち・意図記録・先頭での回収）を #3070 の設計と受け入れ条件に、`DelegatedCgroup` 側の変更が要れば（`net-helpers` を検査の対象外とする指定）core の cgroups に、受け入れ条件として入れる。
- stop / delete の後始末: none / host は delete で `@container-etc` を消すだけ。pasta は #1940。rootful bridge は D13（supervisor が最終終了で detach、CLI の delete は孤児の印を付ける）。netns の pin・veth・公開・DNS からの離脱は `detach` が逆順で行う。

### D15 期限（REPAIR-5）

| 操作 | 期限 |
| ---- | ---- |
| ストアのロック待ち | 5 秒 |
| DNS の ack | 2 秒 |
| plugin の RPC | 既存の `RpcTimeout`（最大 10 秒） |
| host / none の照合 | 既存の `MAX_PASSES` で有界（fd 方式〔D8。#3206〕では、子の ACK 待ちが 60 秒、C の受信が launch の単一期限の残り） |
| supervisor の手順 3〜7 | 既存の `result_deadline` |

launch の前に `launch_step_budget` が残っていることを確かめる（既存）。

pasta 構成の期限（`--version` 2 秒・holder の READY 2 秒・準備完了 5 秒・停止の各段）は [rootless-network.md](rootless-network.md) 12.9 で決めた。起動側の合計は上の `result_deadline` と `launch_step_budget` に収める。

### D16 実装単位

下の「実装 issue」を正とする。2h 以下の粒度で、親 #3056 の配下に起票した。

## 未実装範囲の棚卸し

| 項目 | 該当ファイル | 待っている人間担当の条件 | 完了させる issue |
| ---- | ------------ | ------------------------ | ---------------- |
| CLI のフラグと作成前の検証 | `crates/cli/src/commands/args.rs` | #349 条件 4（拒否側）・5 | #1871 |
| hosts / resolv.conf の生成と bind | core（新規 `etc_files`）・`exec/rootfs.rs` | #349 条件 1（host / none）・3 | #1872 |
| none の netns と `lo` の up | `crates/core/src/exec.rs`・`oci_runtime/start.rs` | #349 条件 1（none）・4（loopback の反映） | #3058・#3064 |
| 文書の kind と `supervisor` → `net` | `crates/supervisor/src/container_options/document.rs` | #349 条件 1・3 | #3065 |
| host / none の結線と既定の none | cli・supervisor | #349 条件 1（host / none）・3・4 | #1873 |
| ネットワーク定義・`CreatedNetwork` の永続化 | `crates/net/src/network.rs` | #349 条件 1（ユーザー定義）・2、#319 条件 2〜4 | #3059・#3067 |
| `network create/rm/ls` | cli | #319 条件 4 | #3066 |
| 静的 IPAM の永続化 | `crates/net/src/network/ipam.rs` | #349 条件 2、#319 条件 2〜4 | #3067 |
| 公開ハンドルの復元 | `crates/net/src/network/unpublish.rs` | なし（NET-3 の残余） | #3068 |
| rootful の実行主体（承認） | — | #349 条件 1（rootful）・2、#319 条件 2〜4 | #3207（判断シートは #3057〔close 済み〕） |
| init user namespace 所有の netns への参加 | `crates/core/src/oci_runtime/namespace_join.rs` | 同上 | #3069 |
| plugin の起動と attach / detach の結線 | supervisor | 同上 | #3074 |
| DNS の参照カウントと切り離し | `crates/net/src/dns_helper/refcount.rs`・`dns_helper.rs` | #349 条件 2 | #3070 |
| 名前の登録経路 | `crates/net/src/dns_helper.rs` | #349 条件 2 | #3071 |
| `--dns` の上流転送（製品の経路） | `crates/net/src/dns_helper/upstream.rs` | #349 条件 2 | #3072 |
| masquerade 本体 | `crates/net/src/network.rs`・`nftables_rules` | なし（NET-1 の期待の一部。#349 の上流 DNS はヘルパーが host の netns から送るため不要。#319 の 3 経路の (c) も DNAT のみ） | #3060・#3073（実装済み。postrouting の masquerade を `create_network` のバッチへ投入。外向きの実トラフィックは未検証） |
| `eth0` へのリネーム | `netlink_route/link.rs` | なし | #3061 |
| コンテナ単体の detach | `crates/net/src/network/delete.rs` | #319 条件 4（削除）・CLI の stop | #3062 |
| 状態ルートをまたぐ受け口の衝突 | `crates/net/src/network/listener_dump.rs`・`publish.rs` | なし | #3063（公開前の DNAT の dump と照合は実装済み。共有ロックと投入後の事後確認は未実装で、#3191 で追跡する） |
| plugin-cri の netsetup の永続化 | `crates/plugin-cri/src/netsetup.rs` | なし | #3075 |
| rootless のユーザー定義名（pasta） | net・supervisor | #349 条件 1（rootless）。条件 2 は NET-9 で約束しないため対象外 | #1936〜#1940 |
| stack の `[networks]` の up / down | stack・cli | なし | #617（D10 の定義ストアを使う） |

### #349・#319 の条件ごとの対応

「すべて完了すると製品の経路で確かめられる」issue の集合。

| 条件 | issue |
| ---- | ----- |
| #349 条件 1（host / none） | #1871・#1872・#1873・#3058・#3064・#3065 |
| #349 条件 1（ユーザー定義） | #3059〜#3074・#1936〜#1940 |
| #349 条件 2 | #3059・#3067・#3057〜#3072・#3066 |
| #349 条件 3 | #1871・#1872・#1873・#3065 |
| #349 条件 4 | #1871（拒否）、#1873・#3064（loopback の反映） |
| #349 条件 5 | #1871 |
| #319 条件 2〜4 | #3059・#3066・#3067・#3057・#3069・#3074・#3062（条件 4 の作成・削除の意味は D13 の確認事項） |

## 実装 issue

親: #3056（#3206 の親は #3032）。依存欄は各 issue の本文を正とする。状態は 2026-10-28 時点で、正は各 issue の状態。

| issue | 内容 | 担当 | 依存 | 状態 |
| ----- | ---- | ---- | ---- | ---- |
| #3058 | core: `LaunchOptions` の network モードと config との突き合わせ（D7） | runtime-builder | なし | 実装済み（PR #3187） |
| #3206 | core: entrypoint の exec 直前の同期点と netns の素性の照合（D8。親 #3032） | runtime-builder | #3058・#3064 | 未実装 |
| #3064 | core: rootless の `CLONE_NEWNET` と `lo` の up（D6） | runtime-builder | #3058 | 実装済み（PR #3195） |
| #3065 | supervisor: 起動オプション文書の kind 追加と net での再検証（D4・D5） | runtime-builder | #3058 | 実装済み（PR #3194） |
| #3059 | net: ネットワーク定義の状態ストア（D10） | net-builder | なし | 実装済み（PR #3188） |
| #3066 | cli: `network create/rm/ls`（D10） | cli-stack-builder | #3059 | 実装済み（rootful の create は D13 待ちで `UNIMPLEMENTED`） |
| #3067 | net: メンバー記録・IPAM の再構成・`realized`（D11） | net-builder | #3059 | 未実装 |
| #3068 | net: 公開ハンドルとテーブル handle の記録と照合（D11） | net-builder | #3067 | 未実装 |
| #3057 | 人間担当: rootful の実行主体の判断シート（D13） | 人間 | なし | 判断シートあり（PR #3186）・判断は #3207 |
| #3069 | core: init user namespace 所有の netns への参加（D12） | runtime-builder | #3057・#3058 | 未実装 |
| #3074 | supervisor: rootful の plugin 起動と attach / detach の結線（D13・D14） | runtime-builder | #3057・#3059・#3067・#3069・#3065 | 未実装 |
| #3070 | net: DNS ヘルパーの切り離し起動と停止（D11） | net-builder | #3059 | 実装済み（切り離し起動・記録・pidfd 経由の停止・起動窓の回収の判定。停止要求の UDS は #3071、`members/*` の件数による起動・停止の配線は #3067・#3074、回収の候補 pid を出す `net-helpers` の cgroup の列挙は #3074 が残る） |
| #3071 | net: DNS ヘルパーの制御 UDS と記録からの名前の読み込み（D11） | net-builder | #3067・#3070 | 未実装 |
| #3072 | net: `--dns` の上流転送を製品のヘルパーで有効化（D11） | net-builder | #3071 | 未実装 |
| #3060 | net: nftables の `bitwise`・`meta` expr（D11） | net-builder | なし | 実装済み（PR #3189） |
| #3073 | net: postrouting の masquerade（D11） | net-builder | #3060 | 実装済み |
| #3061 | net: attach で peer を `eth0` へリネーム（D11） | net-builder | なし | 実装済み（PR #3190） |
| #3062 | net: attach 済みコンテナ単体の切り離し（D11） | net-builder | なし | 実装済み（PR #3192） |
| #3063 | net: 公開前に `fandhe_net_*` の DNAT を dump して衝突検出（D11） | net-builder | なし | 実装済み（PR #3193。共有ロックと投入後の事後確認は #3191） |
| #3075 | cri: netsetup の `CreatedNetwork`・IPAM の永続化 | oci-cri-builder | #3059・#3067・#3057 | 未実装 |

既存の #1871（D1〜D3）・#1872（D9）・#1873（D4・D6〜D9・D14）・#1939（D6）・#1940（D5・D10）・#1935（D1・D10）は、本書の該当項を参照する。コード内のドキュメントコメントの陳腐化（`crates/net/src/lib.rs` の「PLUG-1 区分は検討中」、`network_plugin.rs` の「host / none は #19 で確定」）は本 PR では直さず、#3059 と #3058 の受け入れ条件に入れた。

## セキュリティ上の確認

- インジェクション: `--add-host` / `--dns` / `--network` は net の検証を通してから使う。生の文字列をファイル・パス・コマンドへ連結しない。resolv.conf には `IpAddr` の表記だけを書く。エラーメッセージに入力値を含めない
- アクセス制御: 状態ストアと生成ファイルは 0700 / 0600（hosts / resolv.conf は 0644）・所有者 euid・fd 起点・`O_NOFOLLOW`・nlink 1。DNS の制御 UDS は 0600 で `SO_PEERCRED` が別 uid なら切断する（PLUG-12）。host モードは明示した場合だけ使い、ログに残す
- 不安全な設計の防止: 件数・長さは確保の前に検証する。ロック・ack・RPC・照合はすべて期限つき（REPAIR-5）。失敗時は逆順に巻き戻す。既定は `none`（閉じた側）。指定の衝突は `InvalidArgument`
- 完全性: netns への参加はパスを 1 回だけ開いて fd に固定し、nsfs・種別・(dev, ino)・所有 user namespace・配下性を照合する（SEC-1）。pid の再利用は、pidfd を先に取得してから開始時刻と boot id を照合し、待機と強制停止をその pidfd に対して行うことで除く。公開の rule handle はテーブル handle と照合し、古い handle で他者のルールを消さない
- コンテナ分離: bind mount の先は rootfs の fd から辿り、symlink・`..`・外への脱出を拒否する。init user namespace 所有の netns への参加は承認（#3207）まで実装しない。コンテナ内の root は init user namespace 所有の netns に対して `CAP_NET_ADMIN` を持たない
- 依存: 新規依存なし。serde / toml を supervisor へ足さない。`lo` の up の ioctl は core の `sys` の事前承認の範囲で、PR 記録の条件は #3064 の受け入れ条件に入れた

## spec 側への報告事項（本リポで決めない）

- CLI のポート公開フラグ（`-p` / `--publish`）が CLI-1・NET-6 に無い。pasta（NET-9）と rootful のどちらでも入口が要る
- `network create` のオプション（subnet 等）が spec に無い。本設計では持たず、subnet は pool から自動で予約する（D13 の推奨）
- rootless で `--network <名前>` に事前の `network create` を要するか。本設計は「要る」と読む（NET-6 の入口の定義から）。確認を求める
- rootful で作成・削除を最初の attach / 最後の detach に遅らせると、NET-4 の作成・削除時間の意味が変わる（D13 と #3207 で判断する）。判断シートの D13-3 を参照

## 残余・見直し条件

- /etc/hosts・/etc/resolv.conf の先が symlink の場合は解決しない（D9・#3210）。次のいずれかが起きたら見直す: (1) オーナーが解決先の親ディレクトリの作成（runc の securejoin + MkdirAll と同等）を認めた、(2) rootful bridge の resolv.conf（D13・#3074）で `--dns` の有無に関わらず resolv.conf を作るようになり、この拒否に当たる場面が増えた、(3) 実イメージの調査で、rootfs 内の既存の通常ファイルを指す symlink の resolv.conf が多いと分かった
- #1935（pasta の設計。[rootless-network.md](rootless-network.md) 12 章）は予約名と名前の照合を変えなかった。D1・D10 の見直しは不要。今後変わったら見直す
- #3207 の判断が出たら D13 を確定し、本書の位置づけの注記と `docs/architecture.md` の設計ドラフトの行を更新する
