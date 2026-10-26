# CRI の未受理項目の受け入れ順序とイメージ User の解決方式

`crates/cri` の bundle 生成（`crates/cri/src/bundle/spec.rs`）は、実行層が受けない CRI 項目を黙って落とさず `UNIMPLEMENTED` で拒否している（fail-closed。CRI-2・CRI-7）。本書は、その受け入れ順序と担当、およびイメージ `User` の名前解決の方式を記す（#2606。TASK-114 追補・TASK-56）。

## 未受理項目の受け入れ順序と担当

| 順 | 項目 | 塞いでいる箇所 | 担当 | issue |
| -- | ---- | -------------- | ---- | ----- |
| 1 | イメージ User の名前解決 | cri＋oci の fd 起点の読み取り（本変更で実装済み） | cri・oci | #2606 |
| 2 | run_as_username | cri（`RootfsSource::prepare` へ解決要求 `UserResolveRequest` を渡す口の変更。順 1 の読み口を再利用。本変更で実装済み） | cri | #2664 |
| 3 | dns_config | cri（bundle に resolv.conf を生成して `/etc/resolv.conf` へ ro で bind。変換の段は本変更で実装済み。start は core の制約〔#1917・状態ルート配下の source の拒否〕で現状は拒否される。下記「dns_config の受け入れ方式」） | cri（end-to-end は core の解消待ち） | #2665 |
| 4 | capabilities（drop を先行。add / ambient はオーナー判断。SEC-1） | core の `process.capabilities`（UnappliedField）の適用 → cri。drop は本変更で実装済み。add / ambient は `UNIMPLEMENTED` のまま | core → cri | #2666 |
| 5 | supplemental_groups（とイメージ User の補助グループ） | core の `additionalGids`（launcher が gid 写像と照合して `setgroups` で適用） → cri。本変更で実装済み。`ContainerStatus.user` の報告と機能フラグは #2771 で追加 | core → cri | #2667・#2771 |
| 6 | stop_signal | core の `StopRequest` に `signal` を足し（PLUG-1 の境界変更）、cri が受け入れる。本変更で実装済み。イメージ config の `StopSignal` と ContainerStatus の報告は #2771 で追加 | core → cri | #2668・#2771 |
| 7 | mount の propagation（HostToContainer は受け入れ済み。Bidirectional はオーナー判断待ち） | core が `rslave` の bind をホストの slave として載せる（本変更で実装済み）→ cri が HostToContainer を `rslave` へ変換（実装済み）。`rshared`（Bidirectional）は user namespace の中でコンテナからホストへ伝播できないため受けず `UNIMPLEMENTED` のまま。`linux.rootfsPropagation` は使わない。理由と緩和点は `docs/design/mount-propagation.md` | core → cri | #2669 |
| 8 | sysctls（namespaced のみ） | core の `linux.sysctl` の適用 → cri。IPC 系は本変更で実装済み。`net.*` は順 13 まで `UNIMPLEMENTED` | core → cri | #2670 |
| 9 | log_path / log_directory | core / supervisor の CRI ログ形式の書き出し | core・supervisor → cri | #2671（実装済み。下の節。ランチャー経由と ReopenContainerLog は未対応。総量は上限つき） |
| 10 | cgroup_parent | core の `linux.cgroupsPath`（#2010 の方針で拒否。再判断が要る。判断材料は [cri-cgroup-parent.md](cri-cgroup-parent.md)。オーナー承認待ちで、それまで `UNIMPLEMENTED`） | core → cri | #2672 |
| 11 | devices・CDI | core の `linux.devices`（UnappliedField）・gpu の CDI 適用（判断材料は [cri-devices-cdi.md](cri-devices-cdi.md)。gpu の TASK-127・128・129 の完了とオーナー判断まで `UNIMPLEMENTED`。一般デバイスは GPU-9 が検討中） | gpu・core → cri | #2673 |
| 12 | pod の pid / ipc の共有（join） | core は user＋ipc の path の組だけ受理済み（#2674）。cri は変換まで実装済みで、供給元（pod の保持役）は未実装のため本番では常に新しい namespace。構築口は #2776 で保持役の pid からの `PodNamespacePaths::for_holder_pid`（`/proc/<pid>/ns/{user,ipc}`）に限った。保持役の設計は [pod-namespace-holder.md](pod-namespace-holder.md)（#2838）で、実装は #2870〜#2880（保持役の配線は #2871・#2876・#2877）。pid の共有は未対応 | core → cri | #2674・#2776・#2838 |
| 13 | pod netns の作成・結線 | core の network namespace の拒否（netns への join）。net・plugin-cri・cri の結線と注入点は本変更で実装済み。core の join と本番への注入は後続（設計は [pod-namespace-holder.md](pod-namespace-holder.md)・#2838。実装は #2872・#2878・#2879） | net・core・cri | #2675・#2838 |
| 14 | port_mappings | plugin-cri `netsetup` の `publish_port`（本変更で実装済み。provider を注入した構成の `POD` だけ。本番は順 13 と同じく未注入のため `UNIMPLEMENTED`。下記「port_mappings の受け入れ方式」） | net・plugin-cri・cri | #2676 |
| 15 | userns の uids / gids の写像 | オーナー判断待ち | core → cri | #2240 |
| 16 | readonly_rootfs | core の `root.readonly`（#2767 で実装済み）→ cri が写す（実装済み。下記「readonly_rootfs の受け入れ方式」） | core → cri | #2827 |

受け入れない項目（順 7 の Bidirectional を含む）の `UNIMPLEMENTED` の照合は `crates/cri/tests/bundle_spec.rs` に残し、受け入れた HostToContainer は同じ試験で `config.json` の `mounts[].options`（`rslave`）を具体値で照合する（#2669・CRI-2・OCI-4）。

本表の外の項目（tty / stdin・SELinux・AppArmor・privileged・resources の一部）は #2606 の列挙の対象外である。受け入れない項目の `UNIMPLEMENTED` の照合は `crates/cri/tests/bundle_spec.rs` に残している。

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
- 実効 uid が 0 のコンテナにはイメージの `/etc/group` 由来の補助グループを付けない。主 gid を `additionalGids` へ足さない（containerd の `ensureAdditionalGids` との差。いずれも権限が弱い側に倒れる。#2667）
- passwd を安全に読めず実効ユーザーの名前を決められないときも、イメージ由来のグループは付けない（権限が弱い側。明示した `run_as_user` の起動を passwd の不備で止めない）
- uid のみで gid 0 に落とす挙動は runc / containerd の `GetExecUser` に合わせたもので、実装時に一次情報との再照合は行っていない（食い違いが見つかれば未解決へ倒す）

## supplemental_groups の受け入れ方式（CRI-2・SEC-5・CORE-6。#2667）

コンテナ側の `supplemental_groups` と `supplemental_groups_policy` を受け入れ、`process.user.additionalGids` へ写す。core の launcher が fork の前に user namespace の gid 写像と照合し、子の capability 削減段が `setgroups(list)` で適用して `getgroups` で読み戻す。

| 要求 | 結果 |
| ---- | ---- |
| 値が負・`4294967295`（`u32::MAX`）・範囲外 | `INVALID_ARGUMENT`（`validate_config` でも拒否） |
| ポリシーが `Merge`(0)・`Strict`(1) 以外 | `INVALID_ARGUMENT` |
| `Merge`（既定） | イメージの `/etc/group` 由来 → CRI の一覧の順。重複は最初のものを残す |
| `Strict` | CRI の一覧だけ |
| 実効 uid が 0 | イメージ由来は付けない。CRI の明示した一覧は付ける |
| 合計が 65,536 超 | `FAILED_PRECONDITION` |
| sandbox 側の `supplemental_groups` | 値を検証して受け入れ、適用先が無いため出力しない |
| 範囲写像で gid が写像外 | start で `FAILED_PRECONDITION`（fork 前） |
| 単一 ID 写像で非空 | start で `FAILED_PRECONDITION`（`setgroups` が `deny` のため。黙って落とさない） |
| `/etc/group` が symlink・FIFO・上限超過（uid 非 0 で名前が決まったとき） | `FAILED_PRECONDITION`。不在は空 |

exec は `process.user` の非 root と `additionalGids` を引き続き `UNIMPLEMENTED` で拒否する。

### ContainerStatus.user の報告と機能フラグ（#2771。KEP-3619）

- `ContainerStatus.user.linux` に、起動時に適用する uid・gid・補助グループを返す。値は `SpecBundleProvider` が書いた `config.json` の `process.user` と同じもの（`RuntimeConfigJson::process_user()`）で、推測や既定値で補わない。補助グループは重複除去後の最終の集合で、順序は `additionalGids` と同じ
- 主 gid は補助グループへ自動では足さない（core の launcher が `setgroups(list)` でそのまま適用するため）。containerd は `additionalGids` に主 gid を含めることがあり、ここが既知の差
- 報告は `BundleProvider::prepare` の戻り値 `PreparedBundle`（`user()`）で `CriRuntimeService` へ届き、`ContainerRecord.applied_user` に保持する。置き場所はプロセス内メモリのレジストリで、寿命は `exit_code`・`resolved_log_path` と同じ（plugin-cri の再起動で消える）。config の annotations には書かず（CRI は書き換えを禁じる）、core の `StateStore` にも書かない（PLUG-1 の境界）。報告の無い経路（スタブ・報告しない provider）は `user` が `None` のまま（root を作り出さない）
- 補助グループの保持量（最大 65,536 件）は `container_retained_bytes` の累積上限に入れ、超えたら `FAILED_PRECONDITION`（黙って切り詰めない）
- 機能フラグ: `runtime_service::runtime_features()` が `RuntimeFeatures.supplemental_groups_policy = true` を返す（cri-api v0.37.1 では `RuntimeHandlerFeatures` ではなく `StatusResponse.features` の `RuntimeFeatures`）。`Status` RPC の応答の `features` にそのまま乗る（#2830。[cri-status-rpc.md](cri-status-rpc.md)）

## readonly_rootfs の受け入れ方式（CRI-2・CORE-5・SEC-1。#2827）

コンテナの `LinuxContainerSecurityContext.readonly_rootfs=true` は、`config.json` の `root.readonly=true` へ写す（`crates/cri/src/bundle/spec.rs`）。`false`・security context なしは `readonly` キーを出さず、従来の出力とバイト単位で同じである。core の start は pivot_root の直後に rootfs の mount top へ `MOUNT_ATTR_RDONLY` を非再帰で足し、Landlock の root 権利も同じ値から決める（#2767）。変換は Build 段と Validate 段で同じ関数を通る。

sandbox 側（`LinuxSandboxSecurityContext.readonly_rootfs`）は出力しない。適用先のプロセス（pause コンテナ）が無く、無視しても分離が弱くなる方向ではないため（`supplemental_groups` の sandbox 側と同じ扱い）。

### 書き込み可否の整理（本実装の挙動。`docs/api/bind-mounts.md`・`production_launcher` のシナリオ Y）

| 対象 | readonly_rootfs=true のときの本実装 |
| ---- | ---- |
| rootfs | 読み取り専用（`EROFS`） |
| `/dev/shm`・tmpfs・rw の bind | 書き込める（自分の mount 属性のまま） |
| `/etc/resolv.conf`（`dns_config`） | 常に ro の bind（readonly_rootfs に依らない） |
| `/etc/hosts`・`/etc/hostname` | bind を供給しない（イメージ内のファイルが root とともに ro になる） |
| 利用者の `mounts[]` | `Mount.readonly` に従う。`ro` の bind は readonly root のときだけ core が受理する（#1917） |
| `/proc` | Landlock が書き込みを落とす（`EACCES`） |

### 既知の差（containerd との比較。未検証）

containerd の `containerMounts` は sandbox のファイル（`/etc/hostname`・`/etc/hosts`・`/etc/resolv.conf`）の bind を readonly_rootfs に従わせ、`/dev/shm` は rw と記憶しているが、本変更では一次情報（commit 指定）を再確認していない。以下は未検証の見込みとして扱う。

- `/etc/resolv.conf` は readonly_rootfs=false でも本実装は常に ro（containerd は rw の見込み）。既存の差
- `/proc` は readonly root で本実装は書き込めない（containerd は readonlyPaths を除き書ける見込み）。追跡 issue は [#2859](https://github.com/Fandhe-AI/fandhe-container/issues/2859)
- `/etc/hosts`・`/etc/hostname` の供給を足すときは readonly_rootfs に従わせる
- `process.cwd` が rootfs に無いとき、runc は作るが core は作らず失敗する（readonly とは独立した既存の差）

照合は `crates/cri/tests/bundle_spec.rs` の `cri2_core5_readonly_rootfs_maps_to_root_readonly`・`cri2_readonly_rootfs_false_keeps_output_unchanged`。

### カーネルの事実（EROFS と Landlock の順序。CORE-5・SEC-1。#2837）

`production_launcher` のシナリオ Y（#2767）は、読み取り専用 rootfs への書き込みが Landlock の `EACCES`（13）ではなく VFS の `EROFS`（30）で返ることを条件にしている。Landlock は個別の `security_*` フックで拒否するため、フックより前に VFS が「mount が読み取り専用」で止めることが前提になる。この順序を Linux `v6.12`（commit `adc218676eef25575469234709c2d87185ca223a`。リポの参照版。tag と commit は [exec-without-supervisor.md](exec-without-supervisor.md) の版表と同じ）のソースで確かめた。確認日は 2026-10-26。

| 操作（シナリオ Y のプローブ） | 出典（v6.12） | 結果 |
| ----------------------------- | ------------- | ---- |
| 新規作成（`open(O_WRONLY\|O_CREAT\|O_EXCL)`。`RO_CREATE`） | [`fs/namei.c` L3683](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L3683)（`open_last_lookups` が `got_write = !mnt_want_write(...)`）、[L3550-L3558](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L3550-L3558)（`lookup_open` は `got_write` が偽なら `create_error = -EROFS` とし、`may_o_create` を呼ばない）、[L3600-L3603](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L3600-L3603)（負の dentry なら `create_error` を返す）。Landlock の `security_path_mknod` は `may_o_create` の中（[L3414](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L3414)）にあり、`got_write` が真のときだけ呼ばれる | 一致。mount が ro なら Landlock のフックに到達する前に `EROFS`。条件: 対象の dentry がまだ無いこと（あれば `EEXIST` 等の別の結果になりうる。プローブは `/ro-probe-new` で存在しない名前を使う） |
| 既存ファイルへの書き込み open（`open(O_WRONLY)`。`RO_WRITE`） | [`fs/open.c` L929](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/open.c#L929)（`do_dentry_open` が `file_get_write_access`）→ [L883-L895](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/open.c#L883-L895)（`mnt_get_write_access`）→ [`fs/namespace.c` L492-L494](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namespace.c#L492-L494)（`mnt_is_readonly` で `-EROFS`）が、[`fs/open.c` L945](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/open.c#L945) の `security_file_open`（Landlock の `hook_file_open`）より先 | 一致。書き込み open は `EROFS`。その前の `may_open`（`fs/namei.c` L3328）の `inode_permission` は Landlock にフックが無い（下の行）。`sb_permission`（L486）が見るのは superblock の ro で、per-mount の `MOUNT_ATTR_RDONLY` は上の `mnt_get_write_access` が見る |
| mkdir（`create_dir`。`RO_MKDIR`） | [`fs/namei.c` L4019](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L4019)（`filename_create` が `err2 = mnt_want_write`）、[L4044-L4047](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L4044-L4047)（`err2` を返して失敗）が、[L4277](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/fs/namei.c#L4277) の `do_mkdirat` の `security_path_mkdir` より先 | 一致。mkdir は `EROFS`。条件: 同名が無いこと（あれば L4033 の `EEXIST` が先） |
| Landlock の登録フック | [`security/landlock/fs.c` L1660-L1675](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/security/landlock/fs.c#L1660-L1675)（`path_mkdir`・`path_mknod`・`file_open` 等。`inode_permission` 相当のフックは無い） | 一致。Landlock は上の 3 操作の `security_*` の位置でだけ拒否し、それらは `EROFS` の判定より後ろ |

結論: シナリオ Y の「`EACCES`（13）なら Landlock だけが止めていて VFS の読み取り専用化が効いていない」という判別は、v6.12 のソースの順序に裏付けられた（食い違いなし）。`production_launcher.rs` のドキュメントコメントが挙げる `lookup_open`・`filename_create`・`do_dentry_open` の順序とも一致する。範囲: 上の 3 操作に限る。`truncate`・`unlink`・`rename` など他の書き込み系の操作の順序は確かめていない。カーネル版は 6.12 のみで、他の版での順序の変化は確かめていない。

## dns_config の受け入れ方式（CRI-2・NET-5。#2665）

`PodSandboxConfig.dns_config` は、cri の変換（`config.json` の生成）で受け入れる。内容は `crates/cri/src/bundle/resolv_conf.rs` が検証して resolv.conf を作り、`SpecBundleProvider::prepare` が `<bundle>/resolv.conf` に mode 0644 で排他作成する。`config.json` には次の bind を `mounts[]` の末尾へ出す。

```json
{"destination":"/etc/resolv.conf","type":"bind","source":"<bundle>/resolv.conf","options":["bind","private","nosuid","nodev","noexec","ro"]}
```

### 形式と上限

- 出力は固定順: 見出しコメント → `nameserver <IP>`（servers の順に 1 行ずつ）→ `search ...`（空なら省く）→ `options ...`（空なら省く）。重複は畳まず、改行は LF
- servers は `IpAddr` に parse できたものの表記だけを書く。search は英数字・`-`・`_`・`.`（ラベルは 1〜63 バイト、末尾の `.` は不可）、option は英数字・`-`・`_`・`.`・`:` に限る。空白・改行・NUL・`#` は届かない（行の注入の防止）
- 上限: servers 32 件・searches 32 件（1 件 253 バイト、空白区切りで連結した長さが 2048 バイト）・options 32 件（1 件 64 バイト）・生成物 8 KiB。超過・不正は `INVALID_ARGUMENT`（all-or-nothing。エラー文言に値を含めない）。glibc が使う先頭 3 件への切り詰めはしない
- 値の出どころ（kubernetes `v1.37.1` で照合済み。下記「外部の事実の照合」）: searches の 32 件・2048 バイト・1 件 253 バイトは kubelet と同じ値。servers の 32 件、options の 32 件・64 バイト、生成物の 8 KiB は本実装独自の上限で、kubelet の値ではない（kubelet の servers は 3 件）

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
- kubelet は CRI へ渡す前に nameserver を 3 件へ、search を 32 件・2048 バイト・1 件 253 バイト以下へ切り詰める（超えた分を黙って落とし、イベントを出す）。options には件数・長さの上限が無く、名前が空でないことだけを検査する。本実装は servers 32 件まで受け、超過は切り詰めずに拒否する。kubelet 経由の要求は 3 件以下に収まって届くため、実際には差が出ない

### 残る制約（REPAIR-3）

`/etc/resolv.conf` の ro の bind は、本番の start では次の 2 点で現状は拒否される。cri は受け入れて mount を出し、start は構造化エラーで止まる（network namespace と同じ形）。

1. Landlock のルール生成は、書き込み可能な root 配下の `ro` の mount を拒否する（#1917）
2. plugin-cri の bundle は `<state_root>/.cri/bundles` にあり、core の `validate_bind_mounts` は状態ルートと重なる source を拒否する（管理ルートに生成して bind する core の処理は #1872〔NET-12〕が近い）

## stop_signal の受け入れ方式（CRI-2・PLUG-1。#2668）

- core の `StopRequest` に `signal`（既定 SIGTERM）を足した（`with_signal` / `signal()`）。実装は `signal()` を停止の意図つきで 1 回送り、`grace` を過ぎても止まらなければ、シグナルが何であっても無条件に SIGKILL へ切り替える。全体の待ちは有界のまま（REPAIR-5）。wire の形式は変わらない
- CRI の enum `Signal` の値は Linux の番号ではない（例: `SIGTERM = 23`、`SIGKILL = 13`）。`crates/cri/src/stop_signal.rs` の表で Linux の番号へ写す。`RUNTIME_DEFAULT`（0）は SIGTERM。実時間シグナルは glibc / moby の慣習（`SIGRTMIN` = 34、`SIGRTMAX` = 64。containerd・moby の表と一致することを照合済み。下記「外部の事実の照合」）
- 未知の値は CreateContainer の検証で `INVALID_ARGUMENT`。StopContainer は記録した config から、StopPodSandbox はコンテナごとに値を求めて渡す（写像に失敗したら SIGTERM へ落とさず `INTERNAL`）
- イメージ config の `StopSignal` を読む（#2771・OCI-1）。`ImageDefaults.stop_signal` へ解釈し、CRI の `stop_signal` が `RUNTIME_DEFAULT` のときだけ使う（無ければ SIGTERM）。CRI の明示値が優先される。解釈できない値は、CRI 側が既定以外でも CreateContainer を `INVALID_ARGUMENT` で拒否する（fail-closed。レイヤー展開の前に判定）
- StopSignal で受ける形式（`parse_image_stop_signal`。語彙の解釈は core の `Signal::parse_notation` に委ね、CLI の `stop --signal` と同じ部品を使う。#2832・CLI-1）:

  | 入力 | 結果 |
  | ---- | ---- |
  | 空・欠落 | 未指定 |
  | 数字だけ（1〜64。32・33 を除く） | その Linux 番号 |
  | `SIGTERM`・`TERM`・`sigterm`（`SIG` 接頭辞は任意・ASCII の大文字小文字を区別しない） | 名前の表との照合 |
  | `SIGRTMIN`・`SIGRTMIN+1`〜`+15`・`SIGRTMAX`・`SIGRTMAX-1`〜`-14`（オフセットは先頭 0 なしの 1〜2 桁） | 実時間シグナル。`RTMIN+01`・`RTMINPLUS3` 等の綴りは受けない |
  | 別名 `IOT`・`CLD`・`POLL` | 番号経由で正規の名前（`SIGABRT`・`SIGCHLD`・`SIGIO`）へ寄る。送る番号は同じで、`ContainerStatus.stop_signal` は正規名で報告される |
  | 上記以外（空白・非 ASCII・範囲外・未知の名前・64 バイト超） | `INVALID_ARGUMENT`（固定文言。値は含めない） |

- `ContainerStatus.stop_signal` は実際に stop で使う解決済みの値を返す（`ContainerRecord.stop_signal`。`RUNTIME_DEFAULT` は入れない）。`RUNTIME_DEFAULT` の config は SIGTERM（23）と報告され、別名の明示値（例: 15 = SIGPOLL）はそのまま返る（CRI の明示値の話。イメージ由来の値は上表のとおり正規名に寄る）。StopContainer・StopPodSandbox も同じ値を使う。置き場所と寿命は `applied_user` と同じ

## capabilities の受け入れ方式（CRI-2・SEC-1。#2666）

CRI の `LinuxContainerSecurityContext.capabilities` のうち `drop_capabilities` だけを受け入れる。`add_capabilities` / `add_ambient_capabilities` が空でなければ従来どおり `UNIMPLEMENTED`（オーナー判断まで）。

- core は `config.json` の `process.capabilities` を解釈する。bounding / effective / permitted の 3 集合が互いに等しく、かつ OCI 既定 14 個の部分集合（drop だけ）のときに限り解釈済みとし、launch の `CapabilityDrop` 段へ渡す。型 `ContainerCapabilities` は OCI 既定集合の部分集合しか作れないため、設定から capability を足す経路は無い
- `inheritable` / `ambient` が空でない指定、集合ごとに違う指定、既定外を含む指定（add）は `UnappliedField::ProcessCapabilities` として create / start が `UNIMPLEMENTED` で拒否する。未知名・`CAP_` 接頭辞なし・小文字は `INVALID_ARGUMENT`
- exec は launch 時の分離の記録（`state.json` の `launchIsolation.capabilities`）の集合で再適用し、launch より広い集合を与えない。記録のキーが無い旧記録は、導入前の launch が必ず OCI 既定集合で起動したため OCI 既定集合として扱う。読み込み時は `restrict` で組み直し、未知名・既定外・件数超過は破損（`Internal`）
- cri は drop の指定があるときだけ「OCI 既定 − drop」を 3 集合へ書く。指定が無ければ `process.capabilities` を書かない

| CRI の要求 | 結果 |
| ---------- | ---- |
| drop `NET_RAW` | 既定 13 個（`CAP_NET_RAW` が無い） |
| drop `cap_net_raw`・`CAP_MKNOD` | 既定 12 個（大文字小文字・`CAP_` 接頭辞は区別しない。containerd では `CAP_MKNOD` は無効になる。下の既知の差） |
| drop `ALL` | 空集合 |
| drop `SYS_ADMIN`（既定に無い） | 既定 14 個のまま（no-op） |
| 未知名・空・33 バイト以上・非 ASCII | `INVALID_ARGUMENT`（固定文言。名前は載せない） |
| add / ambient | `UNIMPLEMENTED` |

既知の差:

- 名前の正規化は containerd と**一部食い違う**（containerd `v2.4.2` で照合済み。下記「外部の事実の照合」）。大文字小文字を区別しない点と `ALL` は一致する。食い違いは 2 点で、(1) containerd は名前へ無条件に `CAP_` を前置するため、`CAP_MKNOD` のように接頭辞つきで渡すと `CAP_CAP_MKNOD` になり何も drop されない（エラーにもならない）が、本実装は接頭辞を受けて drop する。(2) containerd は未知の名前を拒否せず無視するが、本実装は `INVALID_ARGUMENT` にする。どちらも本実装のほうが drop する範囲は狭くならない（厳しい側）。挙動を containerd に合わせるか、接頭辞つきを拒否するかは判断事項で、コードは変えていない（追跡: 末尾の表）
- 集合ごとに別の値を指定する細かい制御は未対応（未適用として拒否）

## sysctls の受け入れ方式（CRI-2・CORE-3・SEC-1。#2670）

- 分類・文法は core の `sysctl` モジュール（`SysctlKey::parse`）が唯一の定義で、cri はそれを再利用する。
- 許可集合の出典: runc `libcontainer/configs/validate/validator.go` の `sysctl`（tag v1.3.0、commit `4ca628d1d4c974f92d24daccb901aa078aad748e`、Apache-2.0）。写したのはキー名と接頭辞だけ。runc の NOTICE（Docker, Inc. の帰属行と輸出規制の注記）を一次情報で確認し、帰属行をルート `NOTICE` に追記した。輸出規制の注記も、省略の可否がオーナー判断待ちのため（licensing 規約）、判断が出るまでルート `NOTICE` に原文のまま保持する。
- 判定:

| 種別 | キー | CRI の結果 | core（config.json 直指定）の結果 |
| ---- | ---- | ---------- | ------------------------------- |
| IPC | `kernel.msgmax`・`msgmnb`・`msgmni`・`sem`・`shmall`・`shmmax`・`shmmni`・`shm_rmid_forced`、`fs.mqueue.*` | 受け入れ | 受け入れ。IPC namespace が要る（`--ipc=host` と併用は fork 前に `InvalidArgument`） |
| net | `net.*` | `UNIMPLEMENTED`（pod の netns の結線 #2675 が前提） | network namespace なしは `InvalidArgument`、ありは未実装の名前空間として `Unimplemented` |
| UTS | `kernel.hostname`・`kernel.domainname` | `UNIMPLEMENTED` | `Unimplemented` |
| その他 | 名前空間を持たないキー、文法違反（`/` 区切り・空要素・非 ASCII 等） | `INVALID_ARGUMENT` | `InvalidArgument` |

- 適用は pivot 前段 `apply_sysctls`（`verify_pinned` の直後。`readonly_paths` が `/proc/sys` を ro にする前）で、`rootfs/proc/sys` へ fd 起点・`O_NOFOLLOW`・procfs の `f_type` 照合つきで 1 回の `write` で書く。存在しないキー・不正な値は起動を止める。
- 既知の差: runc は `/` 区切りのキーも受けるが、許可リストのすり抜けを防ぐため本実装は `.` 区切りだけ。
- pod の ipc 共有（下記「pod の ipc 共有の受け入れ方式」。#2674）で join する起動では、共有された pod の IPC namespace へ書く（同じ pod の各コンテナが同じ pod の値を書く）。cri の供給元（保持役）がまだ無い間は、pod 単位の値を各コンテナ自身の IPC namespace へ適用する近似になる。
- rootless で IPC 系 sysctl に書けるかは、その IPC namespace を所有する user namespace を、書き込む側のプロセスが持っているかに依存する。新しい namespace を作る起動では user namespace と IPC namespace を同時に作るため、コンテナの root が所有者となり書ける。pod の user・ipc namespace へ join する起動でも、join 先の IPC namespace を所有するのは同時に join する pod の user namespace（core が照合する）のため同じ条件になるが、join と sysctl を併用した実機確認は未実施。書けない環境では `PermissionDenied` で起動が失敗する(fail-closed。黙って無視しない)。確認済み: `production_launcher` のシナリオ V(`kernel.shmmax`)が `platform-ci` の ubuntu-latest(非 root・委譲 cgroup)で成功行を出す(PR #2733 の CI で合格)。他のカーネル・配布物・LSM(AppArmor 等)の構成での確認は未実施で、そうした環境で `PermissionDenied` となる場合は、シナリオ V と `ci.yml` の成功行の照合が失敗する(環境の前提不足として扱い、照合は緩めない)。

## log_path / log_directory の受け入れ方式（CRI-2・SUP-4。#2671）

CRI の `log_path`（コンテナ）と `log_directory`（サンドボックス）を受け入れ、supervisor がコンテナ出力を CRI のログ形式で `log_directory/log_path` へ書く。

流れ: cri（`resolve_log_path` が検証して結合）→ `StartRequest::with_log_path`（core の検証済み型 `ContainerLogPath`）→ plugin-cri → supervisor の argv `--cri-log-path <絶対パス>` → supervisor が再検証して開く。config.json の `annotations` は使わない（annotations は挙動を変えない契約のため）。

| 指定 | 結果 |
| ---- | ---- |
| 両方とも空 | CRI ログなし（従来どおり） |
| `log_directory` だけ | 受け入れる。そのコンテナは CRI ログなし（containerd と同じ） |
| `log_path` だけ | `INVALID_ARGUMENT`（相対パスの基点が無い。黙ってログを無効化しない） |
| 両方 | `log_directory` は絶対パス、`log_path` は相対パス。どちらも `.`・`..`・空要素・制御文字を含まない。結合後 4096 バイト以下。`..` を禁じるので結合結果は必ず `log_directory` の配下 |

- `ContainerStatus.log_path` は結合済みの絶対パスを返す（containerd と同じ。kubelet の GetContainerLogs と crictl logs が直接開く）。実行層未接続（スタブ）の経路は従来どおり指定値を無改変で返す
- 形式は `<RFC3339Nano UTC 固定 9 桁> <stdout|stderr> <F|P> <内容>\n`。1 行は 16 KiB（containerd の `max_container_log_line_size` の既定）ごとに分け、最後を `F`、それ以前を `P` にする。空行は `<ts> stdout F \n`。捕捉側が 64 KiB で切り詰めた分は残らない（既知の制限）
- `@container-logs`（`fandhe logs`・delete のログ削除の対象）にも従来どおり書く（二重書き）。出力先ごとに失敗状態を持ち、片方（CRI ログ等）が失敗しても正常な側への書き込みは続ける（`Err` を返すのは両方失敗のときだけ）。CRI ログは kubelet の所有物で、`RemoveContainer`・delete は消さない
- 開き方: 追記・`O_NOFOLLOW`・通常ファイルのみ。`log_directory` は作らない（kubelet が作る）が、標準の `<containerName>/<N>.log` の `containerName/` は、検査済みの祖先の直下に限り 1 階層だけ 0o750 で作る（kubelet は `log_directory` しか作らず、containerd・CRI-O は親を作るため。2 階層以上欠けていれば拒否）。親は絶対パス・`..` なし・root 以外が所有する祖先の symlink なし・group / other 書き込み不可。検査と open の間の差し替え（TOCTOU）は残る既知の制限（`@container-logs` の sink と同じ）
- 特権ランチャー経由（ambient capability あり）は `UNIMPLEMENTED` で拒否する。`CAP_DAC_OVERRIDE` のまま利用者指定のパスを開くと任意のファイルへ追記できてしまうため（`CapEff` / `CapPrm` が 0 でなければ拒否）。cri は `UNIMPLEMENTED` を確定失敗として created へ戻す
- 既知の制約: rootless の supervisor は root 所有 0755 の `/var/log/pods` に書けず、標準配置の kubelet では start が失敗する。動くのは rootless の kubelet や、利用者が所有する `log_directory` の場合。`log_directory` に `/tmp`（1777）は使えない（group / other 書き込み可のため拒否）
- 総量の上限: CRI ログ1本は 50 MiB（`CRI_LOG_MAX_BYTES`。既存サイズも数える）。超えると CRI ログへの書き出しを止め（`RESOURCE_EXHAUSTED`）、`@container-logs` は続ける。出力先ごとの最初の失敗は構造化ログ 1 行（`component=supervisor.logs`・`result=destination_failed`・`destination`・`code`。パス・行の内容は含めない。REPAIR-4）で stderr に出す
- 書き手は 1 ファイルにつき 1 つ: 上限を書き手ごとに数えるため、開いたファイルに排他ロック（`flock(2)`）を supervisor の生存中保持し、同じ書き先を別の supervisor が開こうとすると start を `FAILED_PRECONDITION` で拒否する（kubelet は `<containerName>/<restartCount>.log` を使い回さない。ロックは協調的で、ロックを取らない別プロセスの追記は防げない）
- 未対応（後続 issue）: `ReopenContainerLog`（kubelet のログ回転。未実装のため上限到達後は CRI ログが止まる）、ランチャー経由での CRI ログ（open の間だけ DAC 系 capability を落とす等）、64 KiB を超える行の P 断片化

## pod の ipc 共有の受け入れ方式（CRI-2・CORE-3。#2674）

### core の検査（`oci_runtime::NamespaceJoin`。すべて fork・予約の前）

`linux.namespaces[].path` は `user` と `ipc` を組で指す場合だけ受ける。非特権では ipc namespace への `setns` が、参加先を所有する user namespace と現在の user namespace の両方で `CAP_SYS_ADMIN` を要するため、pod の user namespace に先に参加する形でしか成立しない（k8s の pod 単位の userns と同じ形）。

| 検査 | 不合格 |
| ---- | ------ |
| 絶対パス・`..` なし・4096 バイト以内 | `InvalidArgument` |
| 開けない | `FailedPrecondition`（権限不足は `PermissionDenied`） |
| nsfs でない・`NS_GET_NSTYPE` が宣言と違う | `InvalidArgument` |
| user: 自身の namespace・親が自身の namespace でない・作成者 uid が euid と違う | `PermissionDenied` |
| ipc: 所有する user namespace が join 先と違う | `PermissionDenied` |
| pid / mount / uts 等の path、片方だけの path | `Unimplemented` |

path は 1 回だけ開いて fd に固定する（pid の再利用で別 pod へ入る TOCTOU を閉じる）。中間プロセスは `setns(user)` → `setns(ipc)` → `/proc/self/{uid,gid}_map` を権限モデルの期待値と完全一致で照合（SEC-5）→ pid・mount・uts を `unshare` する。`--ipc=host` との併用は `InvalidArgument`。

### cri の出力

| 要求 | 供給元 | 出力 |
| ---- | ------ | ---- |
| ipc `POD` | あり | ipc と user を `path` つき（join） |
| ipc `POD` | 無し | 新しい namespace |
| ipc `CONTAINER` | 問わない | 新しい namespace |
| ipc `POD` ＋ userns `CONTAINER` | あり | `UNIMPLEMENTED` |
| pid（全モード） | 問わない | 新しい namespace（`NODE` / `TARGET` は `UNIMPLEMENTED`） |

`/proc/<pid>` を Create の時点で書く方式は pid の再利用で別 pod の namespace に入り得るため採らない。

### 既知の差と残り

- `/dev/shm`（POSIX shm）は共有されない（コンテナごとの tmpfs）。SysV IPC と POSIX mqueue は共有される。userns が pod 単位になり、共有者は同じ userns の root になる（capability は既定の 14 個、seccomp が `setns`・`unshare` を禁じ、pid namespace は別）。
- 残り（後続 issue）: pod の保持役（#2675 の netns と共有する設計。[pod-namespace-holder.md](pod-namespace-holder.md)・#2838。実装は #2870・#2871・#2874・#2876・#2877）と cri へのパスの供給、pid の共有（PID 1 の証跡・`Pid1Target` の見直しが要る）、pod 内の `/dev/shm` の共有、`NamespaceMode::TARGET`。

## pod netns の作成・結線（CRI-2・NET-1・PLUG-1。#2675）

CRI の `namespace_options.network` は既定が `POD` で、netns は sandbox 単位で配下のコンテナが共有する。`RunPodSandbox` が `NetworkPlugin` 経由で netns を作って結線し、`CreateContainer` の bundle がその netns を指す経路のうち、core の外側（net・plugin-cri・cri）を実装した。**コンテナが netns へ入る側（core）と本番への注入は未実装**で、本番の挙動は変わらない。

| 層 | 実装 |
| -- | ---- |
| net | `create_container_netns`（作成と pin だけを切り出した入口。安全性の検査は `attach_container` と同じ関数）・`attach_prepared_container`（事前作成の netns へ接続。失敗時は veth・IPAM・受け口を戻すが netns は unpin せず返す）・`release_container_netns` |
| plugin-cri `netsetup` | `LinuxNetsetup::create_netns` が事前作成してハンドルを保持し、`attach` が使う。`detach`（未 attach）・`delete_network` が未 attach の netns を解放する。解放に失敗したら記録を残す |
| plugin-cri `pod_network` | `set_up_sandbox`（`create_network` → `create_netns` → `attach`。失敗は逆順に戻す）・`NetsetupPodNetwork`（cri の `PodNetworkProvider` の実装）・`PodSubnetPool`（pod ごとのサブネットの払い出し。上限つき） |
| cri | `PodNetworkProvider`（注入点）。`RunPodSandbox`（`POD`）が `set_up`、`StopPodSandbox`・`RemovePodSandbox` が `tear_down`、`CreateContainer` が `BundleRequest::pod_netns_path` で bundle へ渡す。`POD` でパスがあるときだけ `{"type":"network","path":…}` を出す |

| CRI の要求 | 結果 |
| ---------- | ---- |
| `POD`・provider 注入あり | `set_up` を sandbox ID で 1 回。以後の `CreateContainer` の `linux.namespaces` の network に `path` |
| `POD`・provider なし（本番） | 従来どおり `{"type":"network"}`（path なし）。core の start が `UNIMPLEMENTED` |
| `NODE` | ネットワークに触れない。network namespace を出さない |
| `CONTAINER`・`TARGET` | 従来どおり（`CONTAINER` は path なし、`TARGET` は `UNIMPLEMENTED`） |
| `set_up` 失敗 | `tear_down` で回収を試み、回収できたら sandbox を登録しない。できない・期限超過は notready で残し、Stop・Remove が回収する |
| `tear_down` 失敗 | Stop・Remove が `INTERNAL` で失敗し、記録を残して再試行できる |

既知の差:

- **コンテナが pod netns へ入る側（core）は未実装**: core は `linux.namespaces[].path` のうち `user` と `ipc` の組（順 12。#2674）だけを受け、`network` の path は `UNIMPLEMENTED` で拒否する。network の join は user namespace より前に `setns(CLONE_NEWNET)` する順序と、netns の検証（`O_NOFOLLOW`・`NSFS_MAGIC`・`NS_GET_NSTYPE`・置き場の配下性・所有者）を要し、方式は #1870 の設計事項で、保持役の userns が所有する netns への join は [pod-namespace-holder.md](pod-namespace-holder.md)（#2838。実装は #2872）。順 12（pid / ipc の join。#2674）と共通の土台にする。それまで provider を差した構成の start は `UNIMPLEMENTED` で失敗する
- **本番へは注入しない**: 差すと `RunPodSandbox` が bridge・netns・veth を作るのに start が失敗する。pod 用サブネットの出どころ（起動引数・固定値・設定）も未決
- 本番の plugin-cri は rootless で、bridge・veth の pin は初期 user namespace の `CAP_NET_ADMIN`・`CAP_SYS_ADMIN` を要するため作れない。rootless の pod netns は pasta 構成（NET-9。#1935 系）の領域で、rootful は #2241 のオーナー承認待ち
- net にコンテナ単位の切り離しが無いため、pod ごとにネットワーク（bridge と nft テーブル）を作って `delete_network` で一括解放する。共有ネットワークと per-container の detach への移行は後続（CORE-9 の資源効率）
- 未 attach の事前作成 netns は route ソケットの fd を 1 本保持する（件数は `MAX_NETWORKS` × `MAX_CONTAINERS_PER_NETWORK` で有界）。状態はプロセスのメモリだけで、plugin の再起動で失われる
- `port_mappings` は下記「port_mappings の受け入れ方式」（#2676）。`PodSandboxStatus` の `network`（IP の報告）は空のスタブのまま（実装は #2873）
- 実機（root）の試験は `crates/net/tests/network_attach_privileged.rs` に準備したが、本変更では未実行

## port_mappings の受け入れ方式（CRI-2・NET-3・NET-4・PLUG-1。#2676）

pod の netns の結線（順 13）の最後で、`port_mappings` を `NetworkPlugin::publish_port`（nft の DNAT）で公開する。

流れ: cri の `parse_port_mappings`（`crates/cri/src/port_mapping.rs`。検証と型への変換）→ `PodNetworkRequest::port_publishes` → plugin-cri `set_up_sandbox`（`attach` の後に公開指定ごとに `publish_port`）→ `NetsetupNetwork::publish_port`（契約 11 の判定）→ net の `publish_container_ports`（受け口の予約 → 専用テーブルの `prerouting` / `output` へ 1 バッチで DNAT）。core の `PublishPortRequest` / `PortMapping` には後方互換の任意欄 `host_ip` を足した（判定キーは従来どおり `(host_port, protocol)`）。

### 結果表

| port_mappings の要素 | 結果 |
| -------------------- | ---- |
| protocol が TCP・UDP・SCTP 以外、container_port が 1..=65535 の外、host_port が 0..=65535 の外、host_ip が 64 バイト超・IP でない・multicast・`240/4`・`0/8`（`0.0.0.0` を除く）、完全に同じ受け口の重複、公開する要素が 64 件超 | `INVALID_ARGUMENT` |
| `host_port == 0` | 公開しない（どのモードでも受ける） |
| `host_port > 0` で SCTP、host_ip が空・`0.0.0.0`・`127.0.0.0/8`・IPv6、host_ip だけ違う同じ `(protocol, host_port)` | `UNIMPLEMENTED` |
| 公開する要素があり、provider なし（本番）・`NODE`・`CONTAINER`・`TARGET` | `UNIMPLEMENTED`（RunPodSandbox で資源を作る前に返す。bundle も最終の防壁として同じ判定） |
| 公開する要素があり、provider ありの `POD` | `set_up` の中で公開。失敗は `delete_network` で一括して戻す |

エラーメッセージは固定文言で、入力値を含めない（REPAIR-4）。

### 既知の差と残る制約（REPAIR-3）

- **空の host_ip は `UNIMPLEMENTED`**: kubelet の既定は空（全アドレス）で、containerd・CNI portmap も空と `0.0.0.0` を「全アドレス」として扱う（下記で照合済み）。一方、net は意図しない全アドレス公開を避けるため明示した非 loopback の unicast を必須にしており、黙って特定アドレスに置き換えない。このため実際の hostPort の大半はまだ通らない（net の拒否を見直すかはオーナー判断の候補）
- `host_port == 0` を読み飛ばす扱いは kubelet・containerd と一致する（下記「外部の事実の照合（port_mappings）」で 2026-10-26 に照合済み。kubelet は `host_port == 0` の要素もそのまま CRI へ送り、containerd が `HostPort <= 0` を読み飛ばす）。hostNetwork の扱いは**挙動が食い違う**: kubelet は hostNetwork の pod の ports に `host_port = container_port` を入れて送り、containerd は `NODE` でネットワークの setup を行わず port_mappings を使わない（黙って無視する）。本実装は公開する要素がある `NODE` を `UNIMPLEMENTED` にするため、ports を宣言した hostNetwork の pod は本実装では起動できない（厳しい側の差）。無視に合わせるかはオーナー判断の事項で、コードは変えていない
- masquerade 未実装と host の `ip_forward` が前提で、外部からの到達は保証しない
- 他プロセスとの受け口の衝突は検出しない（`LinuxNetwork` が共有ファイルなしの `PortRegistry` をネットワークごとに持つ。ネットワークをまたぐ契約 11 は `NetsetupNetwork` のプロセス内の記録で担保する）
- 公開の個別解除は net の `unpublish_container_port` と `NetsetupBackend::unpublish_port`（#2839・NET-3）で可能だが、CRI の経路は呼ばない（`port_mappings` は sandbox 単位で、`delete_network` が一括で解放する。`NetworkPlugin` への追加は後続事項）。結果不明のバッチは受け口の記録を保持し、`delete_network` まで再公開を拒む
- `NODE`（hostNetwork）の hostPort・IPv6・SCTP・loopback への公開は `UNIMPLEMENTED`
- 実機（root）での DNAT 到達確認は本変更では未実行

### 外部の事実の照合（port_mappings。kubelet・containerd・CNI portmap。CRI-2・NET-3。#2837）

確認日は 2026-10-26。版は下記「外部の事実の照合」の版表の kubernetes `v1.37.1`（`f78e722310e50bcaca9276be22276d9e91d91308`）と containerd `v2.4.2`（`b7a25261e029d68978bbf290df0a62fc819b3c51`）。CNI portmap は containerd `v2.4.2` の `go.mod`（L34）が固定する `github.com/containernetworking/plugins v1.9.1`（commit `adc3e6b5b581638afbd194cf2e9319ecbb0151a1`）。コードは変えていない。

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| kubelet は `host_port == 0` の要素を読み飛ばさず CRI へ送る | [kubernetes `kuberuntime_sandbox.go` L119-L139](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go#L119-L139)（`generatePodSandboxConfig` が全コンテナの `MakePortMappings` の結果をそのまま積む）、[`container/helpers.go` L449-L484](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/container/helpers.go#L449-L484)（`HostPort`・`HostIP` を無加工で写し、`HostPort` で絞らない）。検証側も [`validation.go` L2818](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/apis/core/validation/validation.go#L2818) で `HostPort != 0` のときだけ範囲を見る（0 は未指定として許す） | 確認。宣言した ports は `host_port == 0` のまま届くので、読み飛ばす側（runtime）の責務になる |
| containerd は `HostPort <= 0` を読み飛ばす | [containerd `sandbox_run.go` L601-L615](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/sandbox_run.go#L601-L615)（`toCNIPortMappings` の `if mapping.HostPort <= 0 { continue }`。呼び出しは L536） | 一致。本実装の「`host_port == 0` は公開しない（どのモードでも受ける）」と同じ。負の値は CRI の型（int32）では来うるが、本実装は `host_port` を 0..=65535 に限り範囲外を `INVALID_ARGUMENT` にする（containerd は負も黙って読み飛ばす。厳しい側の差） |
| 空の `host_ip` は「全アドレス」 | kubelet は `HostIP` を空のまま渡す（[`helpers.go` L456](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/container/helpers.go#L456)）。containerd は `HostIP: mapping.HostIp` を無加工で CNI へ渡す（`sandbox_run.go` L611）。portmap は `HostIP` が空のときは宛先指定（`-d`）を付けず、指定があっても `IsUnspecified()` なら付けない（[iptables 実装 L221-L246](https://github.com/containernetworking/plugins/blob/adc3e6b5b581638afbd194cf2e9319ecbb0151a1/plugins/meta/portmap/portmap_iptables.go#L221-L246)、[nftables 実装 L189-L200](https://github.com/containernetworking/plugins/blob/adc3e6b5b581638afbd194cf2e9319ecbb0151a1/plugins/meta/portmap/portmap_nftables.go#L189-L200)） | 確認。空と `0.0.0.0`（・`::`）はどちらも全アドレス。本実装は空・`0.0.0.0` を `UNIMPLEMENTED` にしているため、kubelet が既定で送る空の `host_ip` の hostPort は通らない（既知の差の 1 点目。net の拒否を見直すかはオーナー判断の候補） |
| containerd は hostNetwork（`NamespaceMode_NODE`）でネットワークの setup を行わず、port_mappings を使わない | [`sandbox_run.go` L196](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/sandbox_run.go#L196)（`if !hostNetwork(config)` の中で netns を作り、`setupPodNetwork` を呼ぶ L266。CNI の port map の組み立て `cniNamespaceOpts` は `setupPodNetwork` 内の L492）、[`helpers.go` L428-L443](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/helpers.go#L428-L443)（Linux は `NetworkNamespace == NODE` を hostNetwork とする） | 確認。hostNetwork では公開の処理そのものが走らず、エラーにもならない（無視）。本実装の `NODE` を `UNIMPLEMENTED` にする扱いとは**食い違う**（containerd は受けて無視、本実装は拒否） |
| kubelet は hostNetwork の pod でも ports を送り、`host_port` を `container_port` へ既定化する | [`kuberuntime_sandbox.go` L119-L139](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go#L119-L139)（`HostNetwork` による分岐なし）、[`defaults.go` L214-L216・L440-L448](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/apis/core/v1/defaults.go#L214-L216)（`defaultHostNetworkPorts`）、[`validation.go` L4328-L4353](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/apis/core/validation/validation.go#L4328-L4353)（hostNetwork の Pod は `hostPort == containerPort` を要求） | 確認。ports を宣言した hostNetwork の pod は `NODE` かつ `host_port > 0` で届く。これは本実装では `UNIMPLEMENTED` になるため、kubelet から見るとその pod の起動が失敗する（挙動の差。上の「既知の差」で扱う） |

食い違いの扱い:

- `host_port == 0`・空の `host_ip` の意味は、本実装の記述と一致した（空の `host_ip` の拒否は、意味は合っていて、安全側に倒した差である）
- hostNetwork（`NODE`）は食い違った。containerd は受けて無視し、本実装は `UNIMPLEMENTED` で拒否する。「無視」に合わせると、公開されないのに成功を返すため、利用者が到達できると誤解する余地がある。現状の拒否のまま保つか、containerd に合わせて無視するか、明示のエラー文言を整えるかは**オーナー判断**の事項とする（コードは変えない。追跡: 起票の承認待ちとして PR 本文に記載）

## 外部の事実の照合（CRI-2・SEC-1・NET-5・CORE-4。#2772）

上の「既知の差」が containerd・kubelet・moby の挙動を前提にしている箇所を、版・commit を固定した一次情報で確かめた。確認日は 2026-10-26。コードは変えていない。

照合に使った版（取得時点の最新の安定版）:

| 対象 | tag | commit |
| ---- | --- | ------ |
| kubernetes | `v1.37.1`（`crates/cri/proto` の cri-api `v0.37.1` と同期した版） | `f78e722310e50bcaca9276be22276d9e91d91308` |
| containerd | `v2.4.2`（`go.mod` が `k8s.io/cri-api v0.37.0`・`github.com/moby/sys/signal v0.7.1` を使う） | `b7a25261e029d68978bbf290df0a62fc819b3c51` |
| moby/sys | `signal/v0.7.1`（containerd `v2.4.2` が参照する版） | `cafbe42351600ca9b363e220722f66d96f6e71f4` |
| OCI image-spec | `v1.1.1`（tag object `de7a13cc5ce022e0486d22211e80eb36f9d4a218`。2026-10-26 確認） | `147f9c13cedb47a0c4d9a11a222961073d585877` |

### dns_config の上限（kubelet）

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| nameserver・search の上限値 | [`pkg/apis/core/validation/validation.go`](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/apis/core/validation/validation.go#L4244-L4253)（`MaxDNSNameservers = 3`・`MaxDNSSearchPaths = 32`・`MaxDNSSearchListChars = 2048`。コメントは glibc の制限に由来すると述べる）と、`validatePodDNSConfig`（L4290-L4312。search を空白区切りで連結した長さを検査し、1 件ごとに DNS サブドメインとして検証する） | 一致（search）。**食い違い（nameserver）**: 文書の servers 32 件は kubelet の 3 件と違う。本実装独自の上限と明記した |
| options の上限 | 同 L4313-L4318。名前が空でないことだけを検査し、件数・長さの上限は無い | 文書の options 32 件・64 バイトは kubelet に無い独自の上限。明記した |
| 超過時の扱い | [`pkg/kubelet/network/dns/dns.go`](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/network/dns/dns.go#L102-L157)（`formDNSSearchFitsLimits`・`formDNSNameserversFitsLimits`）。nameserver は 3 件へ、search は 32 件・1 件 253 バイト以下・合計 2048 バイト以下へ切り詰めて CRI へ渡す | 本実装は拒否（`INVALID_ARGUMENT`）。差を「既知の差」に追記した。kubelet 経由では上限内で届くため実害は無い |
| 1 件 253 バイト | 同 L114-L122（`DNS1123SubdomainMaxLength` を超える search を除く。コメントは glibc 2.28 が abort する例を挙げる） | 一致 |

### 実時間シグナル（containerd・moby）

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| `SIGRTMIN` = 34・`SIGRTMAX` = 64 | [moby/sys `signal/signal_linux.go`](https://github.com/moby/sys/blob/cafbe42351600ca9b363e220722f66d96f6e71f4/signal/signal_linux.go#L13-L14)（`sigrtmin = 34`・`sigrtmax = 64`）と、`RTMIN`・`RTMIN+1..15`・`RTMAX-14..-1`・`RTMAX` の表（L53-L83。`+0`・`-0`・先頭 0 のキーは無い）。カーネルは 32〜64 の 33 個を持ち、glibc の NPTL が 2 個を使って `SIGRTMIN` を 34 にする（[man-pages `signal(7)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man/man7/signal.7?h=man-pages-6.20)。tag `man-pages-6.20`） | 一致。本実装の表（`stop_signal.rs`）の 34〜64 と同じ |
| containerd が CRI の enum から名前・番号へ写す方法 | [`internal/cri/server/container_stop_signal.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/container_stop_signal.go#L27-L43)（enum 名から `SIGNAL_` を外し、`PLUS`・`MINUS` を `+`・`-` へ置換）→ [`container_stop.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/container_stop.go#L167-L199) が `signal.ParseSignal`（moby/sys の `signal.go` L38-L51。`SIG` を外して `SignalMap` を引く）で番号にする | 一致。`SIGRTMINPLUS1` は `RTMIN+1` = 35、`SIGRTMAXMINUS1` は `RTMAX-1` = 63。containerd は stop_signal を消費している（未対応ではない） |
| イメージ config の `StopSignal` の扱い | [`container_create.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/container_create.go#L332-L339)（要求が `RUNTIME_DEFAULT` ならイメージの `StopSignal` を記録に使う） | 一致する差（本実装は読まない）。「既知の差」はそのまま |
| イメージ `StopSignal` の語彙（moby `ParseSignal` と OCI image-spec。#2832） | moby/sys [`signal/signal.go`](https://github.com/moby/sys/blob/cafbe42351600ca9b363e220722f66d96f6e71f4/signal/signal.go) の `ParseSignal`: `Atoi` で数に読めれば 0 だけを拒否し範囲検査なしで受理（負数・`+15`・32・33・65 以上・先頭 0 も通る）。数でなければ Unicode の大文字化 → `SIG` 除去 → `SignalMap`。長さ上限なし。OCI image-spec [`config.md`](https://github.com/opencontainers/image-spec/blob/147f9c13cedb47a0c4d9a11a222961073d585877/config.md) の `StopSignal` は「`SIGNAME` 形式のシグナル名（例 `SIGKILL`・`SIGRTMIN+3`）を取りうる」とだけ書く | 名前の集合（別名 `IOT`・`CLD`・`POLL` を含む）は moby と同じ。本実装（core の `Signal::parse_notation`）は moby より厳しい: 符号つき数字・0・32・33・65 以上・非 ASCII・64 バイト超・空（cri は空を未指定とする）を拒否し、先頭 0 のオフセットも moby と同じく拒否する。番号・接頭辞なし・小文字は仕様の文面外で、moby の慣習に合わせた受理。別名は正規名へ寄せる |

### cgroup_parent（containerd・kubelet）

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| containerd の変換 | [`getCgroupsPath`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/server/helpers.go#L447-L455)（`podsandbox/helpers_linux.go` L62-L70 にも同じ実装）。親の末尾要素が `.slice` なら `<末尾要素>:cri-containerd:<id>`、そうでなければ `<親>/<id>`。`container_create.go` L836-L838 と `podsandbox/sandbox_run_linux.go` L63-L66 が使う | 照合済み。詳細は `cri-cgroup-parent.md` |
| kubelet が送る値 | [`kuberuntime_sandbox.go`](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go#L167-L170)（`CgroupParent` を常に設定）→ [`kubelet_pods.go`](https://github.com/kubernetes/kubernetes/blob/f78e722310e50bcaca9276be22276d9e91d91308/pkg/kubelet/kubelet_pods.go#L636-L641)（`GetPodCgroupParent`）→ `pkg/kubelet/cm/pod_container_manager_linux.go`（QoS 別の pod の cgroup 名。systemd ドライバなら `*.slice` 形式、cgroupfs なら `/` 始まりのパス。L123-L144）。cgroupsPerQOS を無効にした構成は空文字（L343-L349） | 一致。`cri-cgroup-parent.md` の「kubelet は既定で送る」は正しい |

### drop_capabilities（containerd）

| 事実 | 出典 | 結果 |
| ---- | ---- | ---- |
| `ALL` の判定 | [`internal/cri/opts/spec_opts.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/internal/cri/opts/spec_opts.go#L198-L235)（`WithCapabilities`。L212 で `util.InStringSlice(drop, "ALL")`、`internal/cri/util/strings.go` L27-L34 は `strings.EqualFold`） | 一致（大文字小文字を区別しない） |
| 名前の正規化 | 同 L227-L231。`"CAP_" + strings.ToUpper(c)` を無条件に前置する | 一致（大文字化）。**食い違い（接頭辞）**: `CAP_` つきの名前は `CAP_CAP_...` になる |
| 未知名の扱い | [`pkg/oci/spec_opts.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/pkg/oci/spec_opts.go#L1124-L1139)（`WithDroppedCapabilities`）と `removeCap`（L1083-L1092）。完全一致で取り除くだけで、名前の検証をしない。対象は bounding・effective・permitted・inheritable | **食い違い**: containerd は未知名・接頭辞つきを黙って無視する。本実装は `INVALID_ARGUMENT`（未知名）と drop（接頭辞つき）にする |

食い違い（drop_capabilities の 2 点）は #2812 で追跡する。`spec.rs` のドキュメントコメントは訂正済み。挙動を containerd に合わせるかはオーナー判断待ち（コードは変えていない）。

### ContainerStatus・ListContainers の image_ref・image_id（CRI-2・OCI-1。#2831）

CreateContainer の時点で `ImageRootfsSource` が在庫（`ImageStore`）で解決した結果を記録へ残し、両 RPC で返す。経路は `ImageRootfsSource::prepare`（`ImageDefaults::resolved_image`）→ `SpecBundleProvider::prepare`（`PreparedBundle::with_image`）→ `CriRuntimeService::attach_prepared` → `ContainerRecord::resolved_image`。置き場所はプロセス内メモリのレジストリで、寿命は `applied_user`・`stop_signal` と同じ（annotations にも `StateStore` にも書かない）。保持量は `container_retained_bytes` の上限に計上する。

| 経路 | ContainerStatus.image_ref | ContainerStatus.image_id | ListContainers の image_ref・image_id |
| ---- | ---- | ---- | ---- |
| 在庫の記録に `repo_digests` がある | `repo_digests[0]` | image ID（`sha256:<config digest>`） | image ID |
| 記録に digest が無い・在庫なしで image ID 指定 | image ID | image ID | image ID |
| 報告の無い経路（スタブ・外部 bundle・報告しない provider） | 空 | 空 | 空 |

- 報告が無いときに digest を推測しない（`config.image.image` を流用しない。REPAIR-3）。containerd は空を返さないので、空は本リポ固有の挙動
- `image_id` は `PullImageResponse.image_ref`（= image ID）と一致させる（`crates/cri/proto/api.proto` の `ContainerStatus.image_id`・`Container.image_id` の MUST）。`image_ref` は同 proto の「Digested reference to the image in use」
- containerd との照合（一次情報。#2901 で `b7a2526` を確認し同内容）: main `cfb18c48f865669d497115c1734e94fedc338153` の `internal/cri/server/container_status.go` は `imageID = container.ImageRef`（create 時の config digest）、`imageRef` は在庫の `repoDigests[0]`（無ければ config digest）。`container_list.go` の `toCRIContainer` は `ImageRef`・`ImageId` とも config digest で在庫を引かない。v2.1.4（`75cb2b7193e4e490e9fbdc236c0e811ccaba3376`）は `ImageId` を設定しない
- 既知の差の詳細は次の小節（#2901）に移した

### ContainerStatus の image・message・info と在庫の扱い（CRI-2・OCI-1・REPAIR-3。#2901）

確認日 2026-10-26。containerd `v2.4.2`（`b7a25261e029d68978bbf290df0a62fc819b3c51`）の `internal/cri/server/container_status.go`・`container_start.go`・`internal/cri/store/image/image.go` と、kubelet v1.37.1 の `kuberuntime_container.go` を照合した。

| 主張 | 一次情報 | 本実装との関係 |
| ---- | ---- | ---- |
| Status の `image` は、在庫に `repoTags` があれば `&ImageSpec{Image: repoTags[0]}` へ置き換える（新しい ImageSpec。annotations・`user_specified_image`・`runtime_handler` は落ちる） | `container_status.go` L42-L43（コメント）・L61-L65 | **一致**: create 時に在庫から得た `repo_tags[0]` があれば同じ形で返す。タグが無い・報告の無い経路は `config.image` のまま（containerd も在庫に無ければ config の値） |
| `ListContainers` の `image` は置き換えない | `container_list.go` の `toCRIContainer`（`container.Config.GetImage()`） | 一致（`to_summary` は `config.image`） |
| kubelet は create に image ID を渡し、Status の `Image.Image` を Pod status の `image` に使う。`user_specified_image` は読まない | kubelet `kuberuntime_container.go` L373・L716-L747 | 置き換えないと image ID が表示されるため寄せる。`runtime_handler` は create 時に拒否するので常に空で、落としても失うものは無い |
| `message` を書くのは start 失敗（`status.Message = retErr.Error()`）だけ。start 失敗は `StartError`・`errorStartExitCode` の exited にする | `container_start.go` L73-L75 | **方針として空**: 実行層のエラー文字列を外へ出さない方針に合わない。本実装は確定した start 失敗で created に戻すため、message を付ける exited の記録も無い |
| verbose の `info` は `{"info": <JSON 文字列>}` の 1 キー。JSON は sandboxID・pid・snapshotKey・snapshotter・runtimeType・config（envs を含む CRI の ContainerConfig）・runtimeSpec（OCI spec。ホストパスを含む） | `container_status.go` L219 ほか | **方針として空**: envs（秘密値）・ホストパス・snapshot のキーは「内部のパス・構成を出さない」方針に合わない。pid は cri が持たない。将来値を入れる場合もキーは `"info"` の 1 つで値は crictl が解釈する JSON 文字列にする |
| 在庫の references は `docker.Sort(MergeStringSlices(...))` で整列する。pull 時に記録する digest 参照は top-level の digest 1 件（multi-arch では index） | `image.go` L258 | **差として残す**（下記） |

本実装の残る差（コードは変えない）。

- タグはスナップショット: containerd は Status のたびに在庫を引き直し、create 後の retag・タグ削除・イメージ削除が `image`・`image_ref` に反映される。本実装は create 時の値を返し続ける（`to_status` はレジストリのロック下で呼ばれ、在庫への参照を持たない。引き直しには構造の変更が要る）
- `repo_digests` の並び: 本実装は検証済みのプラットフォーム manifest digest を先頭、index digest を 2 番目に入れる（`image_ref` はタグ pull でプラットフォームの manifest digest になる。containerd は multi-arch で index digest）。並びを変えると ImageStatus・ListImages・`image_ref` が変わり、`merged_with` の和集合や永続在庫との整合にも手が要るため、本 issue では変えない。追跡が要る場合は別 issue で扱う
- start 失敗の記録: containerd は `StartError`・非 0 の exit code・message つきの exited にし、restart 復旧時の不明は reason `Unknown` にする。本実装は created に戻すか、reason 空の exited
- `message`・`info` は上記のとおり方針として空（スタブではない）
