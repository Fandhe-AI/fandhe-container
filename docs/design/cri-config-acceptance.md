# CRI の未受理項目の受け入れ順序とイメージ User の解決方式

`crates/cri` の bundle 生成（`crates/cri/src/bundle/spec.rs`）は、実行層が受けない CRI 項目を黙って落とさず `UNIMPLEMENTED` で拒否している（fail-closed。CRI-2・CRI-7）。本書は、その受け入れ順序と担当、およびイメージ `User` の名前解決の方式を記す（#2606。TASK-114 追補・TASK-56）。

## 未受理項目の受け入れ順序と担当

| 順 | 項目 | 塞いでいる箇所 | 担当 | issue |
| -- | ---- | -------------- | ---- | ----- |
| 1 | イメージ User の名前解決 | cri＋oci の fd 起点の読み取り（本変更で実装済み） | cri・oci | #2606 |
| 2 | run_as_username | cri（`RootfsSource::prepare` へ解決要求 `UserResolveRequest` を渡す口の変更。順 1 の読み口を再利用。本変更で実装済み） | cri | #2664 |
| 3 | dns_config | cri（bundle に resolv.conf を生成して `/etc/resolv.conf` へ ro で bind。変換の段は本変更で実装済み。start は core の制約〔#1917・状態ルート配下の source の拒否〕で現状は拒否される。下記「dns_config の受け入れ方式」） | cri（end-to-end は core の解消待ち） | #2665 |
| 4 | capabilities（drop を先行。add / ambient はオーナー判断。SEC-1） | core の `process.capabilities`（UnappliedField）の適用 → cri。drop は本変更で実装済み。add / ambient は `UNIMPLEMENTED` のまま | core → cri | #2666 |
| 5 | supplemental_groups（とイメージ User の補助グループ） | core の `additionalGids`（start.rs で拒否。SEC-5） → cri | core → cri | #2667 |
| 6 | stop_signal | core の `StopRequest` に `signal` を足し（PLUG-1 の境界変更）、cri が受け入れる。本変更で実装済み | core → cri | #2668 |
| 7 | mount の propagation（rslave / rshared） | core の `bind_mounts.rs` が拒否・`linux.rootfsPropagation` | core → cri | #2669 |
| 8 | sysctls（namespaced のみ） | core の `linux.sysctl`（UnappliedField） | core → cri | #2670 |
| 9 | log_path / log_directory | core / supervisor の CRI ログ形式の書き出し | core・supervisor → cri | #2671 |
| 10 | cgroup_parent | core の `linux.cgroupsPath`（#2010 の方針で拒否。再判断が要る。判断材料は [cri-cgroup-parent.md](cri-cgroup-parent.md)。オーナー承認待ちで、それまで `UNIMPLEMENTED`） | core → cri | #2672 |
| 11 | devices・CDI | core の `linux.devices`（UnappliedField）・gpu の CDI 適用（判断材料は [cri-devices-cdi.md](cri-devices-cdi.md)。gpu の TASK-127・128・129 の完了とオーナー判断まで `UNIMPLEMENTED`。一般デバイスは GPU-9 が検討中） | gpu・core → cri | #2673 |
| 12 | pod の pid / ipc の共有（join） | core の `linux.namespaces[].path` の拒否 | core → cri | #2674 |
| 13 | pod netns の作成・結線 | core の network namespace の拒否・plugin-cri `netsetup` の `create_netns` | net・core・cri | #2675 |
| 14 | port_mappings | plugin-cri `netsetup` の `publish_port`。順 13 が前提 | net・cri | #2676 |
| 15 | userns の uids / gids の写像 | オーナー判断待ち | core → cri | #2240 |

本表の外の項目（tty / stdin・readonly_rootfs・SELinux・AppArmor・privileged・resources の一部）は #2606 の列挙の対象外である。受け入れない項目の `UNIMPLEMENTED` の照合は `crates/cri/tests/bundle_spec.rs` に残している。

## イメージ User の解決方式（SEC-1・SEC-5・REPAIR-5）

イメージ config の `User` が名前・uid のみ・名前を含む組のとき、`ImageRootfsSource` は展開後（bundle 配下の私有の 0700 の木）の rootfs の `/etc/passwd`・`/etc/group` で解決する。

- 読み取りは `fandhe_container_oci::layer::read_rootfs_file`。rootfs を `openat2` で 1 回だけ開き、以後は fd 起点で `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` を付けて開く。途中・最終要素が symlink でもホストの内容は読めない
- FIFO・デバイス・ディレクトリは `O_PATH` の fstat で読み取りの open より前に除外し、読み取りの open は `O_NONBLOCK` を付けて同じ実体（dev・ino）を照合する
- 上限は 1 ファイル 1 MiB・65,536 行・名前 256 バイト。超過・不正は未解決
- `openat2` が使えない環境・Linux の x86_64 / aarch64 以外はパス起点へ縮退せず未解決（fail-closed）
- 解決に失敗しても prepare は失敗させない。`user_unresolved = true` で返し、CRI の `run_as_user` が無ければ `UNIMPLEMENTED`（root へ黙って落とさない）

| イメージ User | 結果 |
| ------------- | ---- |
| 空 | 既定（root）。従来どおり |
| `1000:2000` | `(1000, 2000)`。rootfs を読まない |
| `app`（passwd に `app:x:1000:1001`） | `(1000, 1001)` |
| `app:staff`（group に `staff:x:50`） | `(1000, 50)` |
| `app:60` | `(1000, 60)` |
| `1000:staff` | `(1000, 50)` |
| `1000`（passwd に uid 1000 の行） | `(1000, その行の gid)` |
| `1000`（passwd に該当なし、または passwd が無い） | `(1000, 0)`（uid は root にしない。`run_as_user` だけの指定が gid 0 になる既存挙動と同じ） |
| 名前が passwd に無い・`staff` が group に無い | 未解決 |
| `etc` / `etc/passwd` が symlink・FIFO・上限超過 | 未解決（uid のみの指定も未解決） |

形式が崩れた行（フィールド不足・数値不正）・空行・コメント・NIS（`+` `-`）の行は読み飛ばし、名前は完全一致で最初の一致を採る。

## run_as_username の解決方式（CRI-2・SEC-5。#2664）

CRI の `LinuxContainerSecurityContext.run_as_username` は、`ImageRootfsSource` が同じ読み口で展開後の rootfs の `/etc/passwd` を読み、名前の完全一致で `(uid, gid)` を `ImageDefaults::resolved_run_as_username` へ返して受け入れる。`validate_config` は rootfs に触れる前に形式（256 バイト以下・NUL / `:` / `/` / 改行なし・数字だけは不可）と `run_as_user` との同時指定を検査する。

| 要求 | 結果 |
| ---- | ---- |
| `app`（passwd に `app:x:1000:1001`） | `(1000, 1001)`。イメージ User より優先 |
| `app` + `run_as_group=44` | `(1000, 44)` |
| `run_as_group` のみ | `INVALID_ARGUMENT`（従来どおり） |
| `run_as_user` と `run_as_username` の同時指定 | `INVALID_ARGUMENT` |
| 数字だけ・`:` `/` NUL 改行を含む・257 バイト以上 | `INVALID_ARGUMENT` |
| passwd に名前が無い・passwd が無い | `INVALID_ARGUMENT` |
| `etc` / `etc/passwd` が symlink・FIFO・上限超過 | `FAILED_PRECONDITION` |
| `openat2` 不可・対象外の OS / アーキ | `UNIMPLEMENTED` |
| 解決要求を無視する `RootfsSource`（結果が無い） | `UNIMPLEMENTED`（root へ黙って落とさない） |

エラーメッセージは固定文言で、利用者の指定した名前を含めない。

既知の差:

- 数字だけの `run_as_username` は拒否する（containerd は uid 扱いだが、CRI の「passwd に存在すること」を満たさない。数値は `run_as_user` を使う）
- `/etc/group` の所属から補助グループは作らない（core が `additionalGids` を未受理のため。権限は弱い側に倒れる。順 5）
- uid のみで gid 0 に落とす挙動は runc / containerd の `GetExecUser` に合わせたもので、実装時に一次情報との再照合は行っていない（食い違いが見つかれば未解決へ倒す）

## dns_config の受け入れ方式（CRI-2・NET-5。#2665）

`PodSandboxConfig.dns_config` は、cri の変換（`config.json` の生成）で受け入れる。内容は `crates/cri/src/bundle/resolv_conf.rs` が検証して resolv.conf を作り、`SpecBundleProvider::prepare` が `<bundle>/resolv.conf` に mode 0644 で排他作成する。`config.json` には次の bind を `mounts[]` の末尾へ出す。

```json
{"destination":"/etc/resolv.conf","type":"bind","source":"<bundle>/resolv.conf","options":["bind","private","nosuid","nodev","noexec","ro"]}
```

### 形式と上限

- 出力は固定順: 見出しコメント → `nameserver <IP>`（servers の順に 1 行ずつ）→ `search ...`（空なら省く）→ `options ...`（空なら省く）。重複は畳まず、改行は LF
- servers は `IpAddr` に parse できたものの表記だけを書く。search は英数字・`-`・`_`・`.`（ラベルは 1〜63 バイト、末尾の `.` は不可）、option は英数字・`-`・`_`・`.`・`:` に限る。空白・改行・NUL・`#` は届かない（行の注入の防止）
- 上限: servers 32 件・searches 32 件（1 件 253 バイト、合計 2048 バイト）・options 32 件（1 件 64 バイト）・生成物 8 KiB。超過・不正は `INVALID_ARGUMENT`（all-or-nothing。エラー文言に値を含めない）。glibc が使う先頭 3 件への切り詰めはしない

### 結果表

| 要求 | 結果 |
| ---- | ---- |
| `dns_config` なし、または 3 リストがすべて空 | ファイルも mount も作らない（イメージの `/etc/resolv.conf` が見える） |
| 有効な指定 | resolv.conf を生成して ro で bind |
| 不正な IP・zone つきの IPv6・不正な search / option・上限超過 | `INVALID_ARGUMENT`（bundle を作る前の検証段で拒否） |
| 利用者の `mounts[].container_path` が `/etc/resolv.conf` または `/etc` と重なる、または `readonly_paths` / `masked_paths` と重なる | `INVALID_ARGUMENT` |
| 生成ファイルのパスを渡さない入口（`build_runtime_config`）に空でない指定 | `UNIMPLEMENTED`（黙って落とさない） |

### 既知の差（containerd 等との違い）

- 空の指定で、ホストの `/etc/resolv.conf` を写す縮退はしない（ホストの設定の露出を避ける。network 未結線のため）
- 利用者の mount が `/etc/resolv.conf` と重なるとき、containerd は利用者を優先して自分の mount を省くが、本実装は拒否する（fail-closed）
- zone つきの IPv6 は受けない

### 残る制約（REPAIR-3）

`/etc/resolv.conf` の ro の bind は、本番の start では次の 2 点で現状は拒否される。cri は受け入れて mount を出し、start は構造化エラーで止まる（network namespace と同じ形）。

1. Landlock のルール生成は、書き込み可能な root 配下の `ro` の mount を拒否する（#1917）
2. plugin-cri の bundle は `<state_root>/.cri/bundles` にあり、core の `validate_bind_mounts` は状態ルートと重なる source を拒否する（管理ルートに生成して bind する core の処理は #1872〔NET-12〕が近い）

## stop_signal の受け入れ方式（CRI-2・PLUG-1。#2668）

- core の `StopRequest` に `signal`（既定 SIGTERM）を足した（`with_signal` / `signal()`）。実装は `signal()` を停止の意図つきで 1 回送り、`grace` を過ぎても止まらなければ、シグナルが何であっても無条件に SIGKILL へ切り替える。全体の待ちは有界のまま（REPAIR-5）。wire の形式は変わらない
- CRI の enum `Signal` の値は Linux の番号ではない（例: `SIGTERM = 23`、`SIGKILL = 13`）。`crates/cri/src/stop_signal.rs` の表で Linux の番号へ写す。`RUNTIME_DEFAULT`（0）は SIGTERM。実時間シグナルは glibc / moby の慣習（`SIGRTMIN` = 34、`SIGRTMAX` = 64）
- 未知の値は CreateContainer の検証で `INVALID_ARGUMENT`。StopContainer は記録した config から、StopPodSandbox はコンテナごとに値を求めて渡す（写像に失敗したら SIGTERM へ落とさず `INTERNAL`）
- 既知の差: イメージ config の `StopSignal` は読まないため、`RUNTIME_DEFAULT` は常に SIGTERM になる。ContainerStatus の `stop_signal` は config の値をそのまま返す（後続で扱う）

## capabilities の受け入れ方式（CRI-2・SEC-1。#2666）

CRI の `LinuxContainerSecurityContext.capabilities` のうち `drop_capabilities` だけを受け入れる。`add_capabilities` / `add_ambient_capabilities` が空でなければ従来どおり `UNIMPLEMENTED`（オーナー判断まで）。

- core は `config.json` の `process.capabilities` を解釈する。bounding / effective / permitted の 3 集合が互いに等しく、かつ OCI 既定 14 個の部分集合（drop だけ）のときに限り解釈済みとし、launch の `CapabilityDrop` 段へ渡す。型 `ContainerCapabilities` は OCI 既定集合の部分集合しか作れないため、設定から capability を足す経路は無い
- `inheritable` / `ambient` が空でない指定、集合ごとに違う指定、既定外を含む指定（add）は `UnappliedField::ProcessCapabilities` として create / start が `UNIMPLEMENTED` で拒否する。未知名・`CAP_` 接頭辞なし・小文字は `INVALID_ARGUMENT`
- exec は launch 時の分離の記録（`state.json` の `launchIsolation.capabilities`）の集合で再適用し、launch より広い集合を与えない。記録のキーが無い旧記録は、導入前の launch が必ず OCI 既定集合で起動したため OCI 既定集合として扱う。読み込み時は `restrict` で組み直し、未知名・既定外・件数超過は破損（`Internal`）
- cri は drop の指定があるときだけ「OCI 既定 − drop」を 3 集合へ書く。指定が無ければ `process.capabilities` を書かない

| CRI の要求 | 結果 |
| ---------- | ---- |
| drop `NET_RAW` | 既定 13 個（`CAP_NET_RAW` が無い） |
| drop `cap_net_raw`・`CAP_MKNOD` | 既定 12 個（大文字小文字・`CAP_` 接頭辞は区別しない） |
| drop `ALL` | 空集合 |
| drop `SYS_ADMIN`（既定に無い） | 既定 14 個のまま（no-op） |
| 未知名・空・33 バイト以上・非 ASCII | `INVALID_ARGUMENT`（固定文言。名前は載せない） |
| add / ambient | `UNIMPLEMENTED` |

既知の差:

- 名前の正規化（大文字化・`CAP_` 接頭辞の補完・`ALL`）は containerd に合わせた想定で、実装時に一次情報（commit 指定）との再照合は行っていない。食い違いが見つかれば厳しい側（拒否）へ倒す
- 集合ごとに別の値を指定する細かい制御は未対応（未適用として拒否）
