//! exec プロセスへの制限の再適用（rlimit・capability 削減・`NO_NEW_PRIVS`・Landlock・seccomp。
//! SUP-6・TASK-163.3・TASK-163.4・#502・#503・CORE-5・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! SUP-6 の exec は「pid1 の namespace へ `setns` → cgroup join → 制限の再適用 → コマンド実行」。
//! `setns` と cgroup join だけを済ませたプロセスは、コンテナ本体（launch 経路のステージ列
//! `Rlimits → CapabilityDrop → NoNewPrivs → Landlock → Seccomp`。`exec/stages.rs`）より弱い制限で動いてしまう。
//! 本モジュールは 3 段目の再適用を担い、`fandhe-container-supervisor` の `exec`（`prepare_restrictions` /
//! `reapply_restrictions` / `run_command`）が薄く配線する。結果から作る [`ExecReady`] が、`exec/exec_command.rs` の
//! `spawn_exec_command`（fork → `close_range` → execve）の唯一の入口になる。
//!
//! # 契約
//!
//! - 二段階 API（`exec/cgroup_join.rs` の `prepare_cgroup_join` / `join_cgroup` と同型）:
//!   [`prepare_exec_restrictions`] は **`join_namespaces` の前**、[`reapply_restrictions`] は
//!   `join_namespaces` と `join_cgroup` の **後** に呼ぶ。seccomp の既定フィルタは `setns` を拒否するため、
//!   再適用を `setns` の前に置くと namespace 参加が失敗する（cgroup join を seccomp の前に置く既存の順序と一致）。
//!   [`reapply_restrictions`] の内部は「準備したプロセスの確認 → 参加後の user namespace・mount namespace・子が入る PID namespace・所属 cgroup が準備時の対象のもの
//!   であることの照合 → 参加後の `/` の照合 → 適用」の順で、確認・照合で拒否したときは何も適用していない
//! - 全体の順序（exec 専用プロセス内。supervisor の `run_command` が固定する）: `identify_pid1` →
//!   `prepare_cgroup_join` → [`prepare_exec_restrictions`] → `join_namespaces` → `join_cgroup` →
//!   [`reapply_restrictions`] → [`ExecRestrictionReport::into_complete`] → `spawn_exec_command`（fork →
//!   `close_range` → execve）。制限は fork / execve を越えて継承されるため「適用 → fork → execve」の順にする。
//!   namespace 参加を cgroup 参加より先に置くのは launch 経路と同じ相対順である（launch は namespace 分離と
//!   `pivot_root` の後にステージ列の先頭で cgroup へ参加する。`StageKind::ORDER`）。cgroup 参加は事前に開いた
//!   fd だけで完結するため `setns` の後でも成立し、どちらも制限の適用より前に終わる
//! - 内部の適用順は rlimit → capability 削減 → `PR_SET_NO_NEW_PRIVS` → Landlock → seccomp で固定
//!   （`StageKind::ORDER` の相対順と同じ。rlimit は capability 削減の後だと hard の引き上げができず、seccomp の
//!   後だと `prlimit64` を許す必要が生じるため前に置く）。最初の失敗で打ち切り、後続は呼ばない。エラーの
//!   `stage` は `Rlimits` / `CapabilityDrop` / `NoNewPrivs` / `Landlock` / `Seccomp`
//!   （適用前の拒否は、準備したプロセスの不一致が `Validate`、参加後の namespace・`/` の不一致が `SetNs`）
//! - **rlimit は launch 時の記録を適用する**（SUP-12・SUP-6・TASK-169 追補・#1467）: コンテナの rlimit
//!   （`--ulimit`）は launch 時に全 16 種（指定のある種別は指定値、無い種別は launch 時点の実効値）を
//!   `state.json` へ記録する（`StateRecord::rlimits`。トレイト契約 11）。supervisor の特定が記録から取り出した
//!   集合を [`prepare_exec_restrictions`] へ渡し、全 16 種の (soft, hard) を exec プロセスへ適用して読み戻す
//!   （launch の `StagePipeline::with_rlimits` と同じ `apply_rlimits`。黙ってクランプしない）。記録が無い・全 16 種
//!   そろっていない場合は、適用を省かず `FailedPrecondition`（段 `Rlimits`）で拒否する（準備・再適用の両方で
//!   確かめる。#1460。適用を省いても未適用の一覧へ載らない経路を塞ぐ）。pid1 の現在値への縮退はしない。
//!   他プロセスへの `prlimit` 経路は作らない
//! - **記録の値は pid1 の後からの変更に影響されない**: pid1 が soft を上げ下げしても、exec は記録の値で動く
//!   （再現性があり、コンテナ側から exec の値を操作できない）。記録の hard が exec を起動したプロセスの hard を
//!   超える場合は `EPERM` で拒否する（rlimit は対象の user namespace へ参加した後に適用するため、hard の引き上げには
//!   初期 user namespace の `CAP_SYS_RESOURCE` が要る。rootless では fail-closed になる）
//! - **capability は launch と同じ許可集合へ削減する**（SEC-1・CRI-2・#2666）: launch と同じ関数・同じ集合で、
//!   bounding set を許可集合まで落とし、ambient を空にし、effective = permitted = 許可集合 ∩ 現在の permitted、
//!   inheritable = 空にして読み戻す。許可集合は launch 時の分離の記録（`LaunchIsolationRecord::capabilities`）の
//!   値で、`process.capabilities` の drop で絞った集合も launch と一致する。記録が無い旧記録は OCI 既定集合
//!   （導入前の launch は必ず OCI 既定集合で起動した）。許可集合の型は OCI 既定の部分集合だけを表すため、
//!   exec が launch より広い集合を与えることはない。pid1 が起動後に自分の
//!   capability をさらに落としていても、exec は launch がコンテナへ与えた集合で動く。uid / gid・
//!   securebits は launch・exec とも変更しない（呼び出しプロセスの値を引き継ぐ）。ただし user namespace へ参加した
//!   場合（下記）は、補助グループの消去の後・bounding set の削減の前に、gid → uid の順で `process.user` の値へ揃える。spec（SUP-6）が
//!   exec での capability 削減に言及しない点は確認事項で、「launch より弱くしない」側に倒している
//! - **補助グループは既定で空にし、`process.user.additionalGids` があればそれだけを持たせる**（SEC-1・SEC-5・
//!   CORE-6・TASK-163 追補・#1457・#2667・#2770）: capability 削減の関数が先頭で、指定が空なら `setgroups(0)` で
//!   消去して読み戻し、非空なら `setgroups(list)` で置き換えて読み戻す（`exec/capabilities.rs` の
//!   `SupplementaryGroups`）。launch の子は supervisor の、exec の子は exec を起動したプロセス（`sudo` 経由なら
//!   呼び出しユーザー）のホスト側の補助グループを持ち越していたため、消去が要る。**exec は namespace へ参加する
//!   前にも消去する**（[`prepare_exec_restrictions`] の最後。対象の user namespace へ `setns` した後は `deny` で
//!   消せなくなり、起動者のグループを持ち込むため。参加前に消せば参加後の削減は「元から空」になり、結果には
//!   参加前の消去を残す。非空の指定を参加後に適用したときの結果は `Applied`）。`additionalGids` は exec でも対象の
//!   user namespace の実際の写像（`/proc/<pid1>/gid_map`・`setgroups`）と **`setns` の前** に照合する
//!   （`exec_user_from_config`）。写像の外は `InvalidArgument`、`setgroups` が `deny` の単一 ID 写像で非空なら
//!   `FailedPrecondition` で、補助グループの消去（不可逆）より前に拒否する。確保（正規化）は
//!   [`prepare_exec_restrictions`] で済み、参加後の段は読み戻し以外で確保しない。user
//!   namespace が `setgroups` を `deny` にしている場合（rootless。`setns` の前に開いた自分の procfs の `setgroups` で
//!   確認する。`EPERM` という errno だけでは判断しない）は消去できないため現状のまま残し、結果
//!   （[`ExecRestrictionReport::supplementary_groups`]）へ記録する。それ以外の理由で消去できなければ拒否する
//! - **user namespace は対象のものへ参加する（SUP-6・SEC-5・TASK-163.h2・#1462）**: capability は user namespace に
//!   対する相対的な権限なので、同じ集合でも exec プロセスが対象より外側の user namespace にいれば launch より
//!   強い。対象が呼び出し側と別の user namespace にいる（既定の rootless）ときは、`join_namespaces` が他の
//!   namespace より先に user namespace へ参加する（`exec/setns.rs`）。参加で参加先の全 capability を得るため、
//!   参加後の処理は launch と同じ関数・同じ順序「補助グループ → gid・uid → capability 削減（bounding set・ambient・
//!   permitted/effective/inheritable）→ `NO_NEW_PRIVS` → Landlock → seccomp」で省かない（SEC-5）。gid・uid は
//!   `process.user`（`config.json`。uid・gid は対象の写像の内側に限る。#2770）の値へ補助グループ → `setresgid` →
//!   `setresuid` の順で揃えて読み戻す。非 root の uid で `execve` すると ambient が空のため permitted・effective も
//!   空になり（launch の非 root と同じ。Docker と同等）、エントリポイントの解決も対象 user の権限で行われる。
//!   非特権ユーザーが自分で作ったコンテナへの exec では名前空間内の
//!   値が変わらないが、ホストの root から rootless のコンテナへ入ると名前空間内では写像されていない uid のまま
//!   全 capability を持つため、コンテナの所有者の uid・gid へ揃えることが権限境界になる。同じ user namespace
//!   （rootful 相当）では参加せず、uid / gid は呼び出しプロセスの値を引き継ぐ
//! - **参加前の補助グループの消去の順序（#1457・#1462）**: 参加の前、初期 user namespace で `CAP_SETGID` を持つ間に消去
//!   する（root・`sudo` 経由の起動者のグループをコンテナへ持ち込まない）。補助グループを持つ非特権ユーザーは
//!   `CAP_SETGID` を持たず `EPERM` かつ `setgroups` が `allow` になるが、別の user namespace へ入り、呼び出し側の
//!   実効 uid が対象の実効 uid と一致する（= コンテナの所有者自身の exec）場合に限り、消去を参加の **後** に回す
//!   （参加先の全 capability で消去し、`deny` なら現状維持として記録する）。それ以外は従来どおり拒否する
//!   （コンテナの所有者と別の uid の補助グループを持ち込まない。fail-closed）
//! - **制限を exec の対象へ束縛する**: [`prepare_exec_restrictions`] が対象の user namespace・mount namespace の
//!   識別子（nsfs の `st_dev`・`st_ino`）と自プロセスの procfs ディレクトリの fd（`setns` 後は `/proc/self` を
//!   解決できないため）を保持し、[`reapply_restrictions`] が参加後の自プロセスの識別子と照合する（user namespace を
//!   先に照合する。rootful で参加しない場合も「呼び出し側 = 対象」の一致を確かめる）。不一致は違反記録
//!   `exec_joined_namespace_mismatch`（何も適用しない）。同じ rootfs を共有する別コンテナへ参加した場合は `/` の
//!   照合だけでは検出できないため、`/` の照合より先に行う。[`ExecReady`] の作成後に対象が変わらないのは、
//!   seccomp が `setns`・`unshare` を拒否するため
//! - **準備したプロセス自身が適用する**: 保持する `/proc/self/status` の fd は開いたプロセスの情報を返す。
//!   `setns(CLONE_NEWNS)` の後は `/proc` がコンテナ側の procfs になり自プロセスを `/proc/self` で解決できない
//!   ため、事前に開いた fd で適用前後の `Threads: 1` 検査（seccomp・Landlock の既存検査）を行う。fork した
//!   子から使うと親のスレッド数を読むため、準備時の pid を記録し、不一致なら何も適用せず
//!   `FailedPrecondition` にする（best-effort の誤用検知。PID namespace をまたぐ数値衝突は検知できない）
//! - **単一スレッド専用・不可逆**: logs 捕捉スレッドを持つ supervisor 本体からは呼ばない。失敗時は制限が
//!   部分的に載った不定状態のため、呼び出し側は続行せず終了する（巻き戻し不可。`join_cgroup` と同じ）
//! - **fail-closed**: Landlock 未対応カーネル・ルール生成失敗は準備段階で `stage = Landlock` として拒否し、
//!   Landlock 無しで続行する経路を作らない（CORE-5）。値を消費するため二重適用・fd の残留を型で防ぐ
//! - **参加後の `/` を launch 時に記録したコンテナの `/` と照合してから適用する（SEC-1・#1468）**: `setns(CLONE_NEWNS)` は呼び出し
//!   プロセスの root と cwd を **参加先 mount namespace のルート**（`mnt_ns->root` に積まれた最上位のマウント）へ
//!   付け替える（カーネルの `fs/namespace.c` `mntns_install` が `set_fs_root` / `set_fs_pwd` を呼ぶ。pidfd で複数
//!   namespace を一括指定した場合も `kernel/nsproxy.c` の `commit_nsset` が同じ root / cwd を反映する。`setns(2)` の
//!   man page には記載が無いカーネルの挙動）。したがって参加後の `/` はホストの `/` ではないが、それが
//!   「コンテナの rootfs」であることは launcher が `pivot_root` 済み（`exec/rootfs.rs`）で、以後 `/` へ別の
//!   マウントが重ねられていないという前提に依存する。この前提を仮定で済ませず、launch 時に `state.json` へ記録した
//!   pivot 後の `/` の識別子（`LaunchIsolationRecord::root`。[`prepare_exec_restrictions`] が受け取る）と、
//!   [`reapply_restrictions`] が参加後に開いた `/` が **同じディレクトリ（`st_dev`・`st_ino` の一致）** であることを、
//!   何も適用する前に確かめる。不一致は違反記録 `exec_root_not_container_rootfs` つきの `FailedPrecondition` で
//!   拒否する（pivot していない対象・`/` へマウントを重ねた対象・restart で記録し直していない対象では、ルールが
//!   別の木に付くうえコマンドも rootfs の外で動くため）。基準はホスト側の bundle ディレクトリではなく記録した
//!   pivot 後の `/` なので、rootfs を mount namespace の中で組み立てる構成（overlay 等）でも照合が成り立つ
//!   （bundle の rootfs はホスト側の固定と監査と「自分の `/` でないこと」の検査にだけ使う）。記録は fd を持たず
//!   inode 番号の再利用を型では防げないが、照合は mount namespace の束縛の後に行い、生きている pid1 の mount
//!   namespace が `/` のマウントを固定していること・`CAP_SYS_ADMIN` を持たないコンテナは `/` を付け替えられない
//!   （SEC-1）こと・seccomp が `setns`・`unshare` を拒否することで、束縛後の `/` が別物にすり替わらない。
//!   記録した `/` が自プロセスの `/`（ホスト）と一致する場合も、準備が違反 `rootfs_is_host_root` で拒否する
//! - **照合の基準に pid1 の root（`/proc/<pid>/root`）を使わない**: pid1 の root はコンテナ側が変えられる
//!   （OCI 既定の capability には `CAP_SYS_CHROOT` が含まれ、pid1 は自分を `chroot` できる）。基準は launch 時に
//!   記録した `/` の識別子にする。pid1 が自分を `chroot` していても、exec は mount namespace のルート = rootfs へ入る
//! - **ルールパスは照合済みの `/` の fd を起点に、`setns` の後に解決する**: 準備段階の ruleset が持つのは
//!   記録した mount destination（コンテナ内パス。`RulePath`。`..` を含まない正規化済み）の文字列だけで、
//!   準備ではルールのパスを開かない（`setns` 前に開くとホスト側の木を指すため）。`landlock_add_rule` 用の
//!   `O_PATH` fd は [`reapply_restrictions`] の中で、照合に使ったのと同じ `/` の fd から 1 要素ずつ
//!   `O_NOFOLLOW` で開く。symlink はまたがず、解決できないパスは拒否し、ルールを黙って落とさない。launch 経路
//!   （`StagePipeline::with_landlock`。pivot 後の `/` 起点）と同じ関数・同じ規則で辿る
//! - **ルールは launch 時に記録した ruleset をそのまま使う**（#1468）: handled access もパスごとの許可も
//!   `LaunchIsolationRecord`（`state.json`。トレイト契約 12）から組み直し、`config.json` から導き直さない
//!   （launch の後に bundle の config が変わっても、launch と同じ対象に同じ権限が付く）。ABI は launch と同じ
//!   fail-closed（6 未満は拒否）で検出するだけで、handled は今のカーネルの ABI から計算し直さない（launch の
//!   handled に無かった権利が無制限になるため）。記録の handled が今のカーネルの扱える範囲を超える場合は縮退せず
//!   拒否する。Landlock の適用は存在しない・開けないルールパスを拒否するため、記録した mount destination が
//!   稼働中の rootfs に無ければ [`reapply_restrictions`] は失敗し exec は拒否される（fail-closed として正しい挙動）。
//!   記録が無い場合の拒否は supervisor の `identify_pid1` が行う。ルールの対象ごとの `(st_dev, st_ino)` は記録しない
//!   （未実装）。「同じ対象」は、照合済みの `/` の fd を起点に `O_NOFOLLOW` で 1 要素ずつ辿ることと、対象が
//!   すべてマウントポイントであること（`CAP_SYS_ADMIN` が無いと動かせない）で担保する
//! - **完了は型で表す**: 成功結果 [`ExecRestrictionReport`] のフィールドは非公開で、未適用の制限は
//!   [`ExecRestrictionReport::unapplied`] で読むだけ（crate の外から書き換え・構築できない）。TASK-163.4 で
//!   rlimit と capability 削減を実装したため通常の一覧は空で、「launch 経路と同じ制限がすべて載った」ことの
//!   証跡は [`ExecReady`]（[`ExecRestrictionReport::into_complete`] だけが作る。未適用が残る間は `Err`）。
//!   launch の段が増えて exec 側が追従しない場合は、一覧への追加（機械照合する単体テストが失敗する）で exec を
//!   拒否に倒す。**fork / execve の入口（`spawn_exec_command`）は [`ExecReady`] を値で受け取る**。
//!   `ExecRestrictionReport` や真偽値を受け取る入口、[`ExecReady`] を経由しない入口はない
//! - エラーメッセージ・`Debug` 出力にホスト側パス・ルール内容を載せない
//!
//! # `execve` を結線する前の 5 条件（TASK-163.3 が残し、TASK-163.4・#503 で満たした）
//!
//! 1. **完了を型で強制する**: 入口 `spawn_exec_command` は [`ExecReady`] だけを値で受け取る。[`ExecReady`] を
//!    作る別経路・`Clone`・公開コンストラクタはない（単体テスト専用の作成は `cfg(test)` のみ）
//! 2. **capability 削減と rlimit 適用**: 上記の順序で適用し、未適用の一覧は空
//! 3. **制限を exec の対象へ束縛する**: mount namespace の識別子の照合（上記）
//! 4. **`setns` を伴う通し試験**: supervisor の `tests/exec.rs`（実機前提。root を要し、CI ではビルドのみで
//!    実行していない）が、実コンテナへ参加した後の `/` と rootfs の一致・保持 status fd からのスレッド数の
//!    読み取り・pivot していない対象の拒否・別コンテナへの参加の拒否を具体値で照合する。このうち
//!    「launcher と同じ手順で `pivot_root` した対象へ参加した後の `/` が、固定した rootfs と同じディレクトリに
//!    なる」ことだけは、非特権の user namespace で動く `tests/exec_setns_join.rs`（CI で実行）が本番の
//!    `join_namespaces` を通して具体値で照合する（rootfs を mount namespace の中で組み立てた場合の、記録した
//!    `/` との一致とホスト側ディレクトリとの不一致も同じ試験が照合する。#1468）。ルールパスの解決の起点が照合済みの fd であること（プロセスの `/` を引き直して
//!    いないこと）は、`open_verified_root` が返した fd を Landlock の適用と cwd の設定の両方へ渡す実装で担保し、
//!    プロセスの `/` と起点が食い違う状況を作る専用の試験は未実装（下記）
//! 5. **全体のタイムアウトと fd の後始末**: supervisor の `run_command` が準備から実行までを worker プロセスへ
//!    隔離して全体の上限時間を課し（REPAIR-5）、子は `execve` の前に `close_range` でホスト側の fd を閉じる
//!    （`exec/process.rs`）。fork から `close_range` までの間に子がコンテナ側から見える窓は、worker を
//!    non-dumpable にして閉じる（`exec/exec_command.rs`）
//!
//! 準備時の pid との照合は best-effort で、`setns` で PID namespace に参加した後に fork した子の pid は数値が
//! 衝突し得る。「適用 → fork → execve」の順を守り、子で適用しないことで避ける。
//!
//! # 未実装（REPAIR-3）
//!
//! - Mount 由来のルールの対象がマウントのルートであることのマウント ID での照合は、#3201 で実装済み: 再適用は
//!   `state.json` に残した launch 時の識別子（`mnt_id`・`st_dev`・`st_ino`・`read_only`）を `MountCheck::Recorded` で照合し、
//!   `mnt_id` は `setns` の後に `/proc/thread-self` が使えないため `TargetBinding.proc_dir` の `fdinfo/N` から読む。
//!   識別子の無い旧記録（Mount 由来のルールがあるもの）は、`setns` と補助グループの消去より前に `FailedPrecondition`
//!   （段 `Landlock`）で拒否する（作り直しの手順は `docs/setup/exec-mount-identity-recovery.md`）。
//!   restart の再 launch は Running(新 pid) の更新で識別子を置き換える（契約 12）が、本番 launcher の再 launch は #2043 まで
//!   拒否される。記録を持たない偽の launcher が前の記録を引き継ぐと識別子が古くなり、照合で拒否される（fail-closed）
//! - 同じ user namespace（`Shared`。rootful 相当で本番では到達しない）での root 以外の `process.user` と
//!   `additionalGids`（`Unimplemented` で拒否。`RootfulHostRoot` の判断待ち。#2241）。別の user namespace
//!   （既定の rootless）では写像と照合して適用する（#2770）
//! - ルールパスの解決の起点とプロセスの `/` が食い違う状況での照合専用の試験（上記 4）
//! - launch 時の分離の記録は、本番 launcher が適用する ruleset そのものから作り、start の Running 更新と restart の
//!   Running(新 pid) 更新で `state.json` へ書く（結線済み・#2007）。記録を持たない launcher（偽の実装）では
//!   supervisor の `identify_pid1` が記録なしで exec を拒否する。本番 launcher による restart の再 launch は #2043 まで
//!   拒否される。exec と launch の一致は「launch が適用した ruleset を記録し、同じ規則で辿る」ことで担保する
//! - 拒否の違反記録（種別 `exec_target`）の監査ログへの保存のうち、本番の sink の実体の生成と CLI からの
//!   受け渡し（SEC-4）。層 `AuditLayer::ExecTarget` と supervisor `run_command`（親プロセス側）の 1 拒否 1 件の
//!   記録は実装済み（#1465）。この段関数単体は記録せず、`ExecError::violation` に載せて返す
//! - 実機前提の通し試験 `tests/exec.rs` の実行結果の記録（CI ではビルドのみ）

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use super::capabilities::{NormalizedGroups, PreJoinGroups, ProcessIds};
use super::entrypoint_mode::EntrypointExecMode;
use super::landlock::landlock_ruleset_from_record;
#[cfg(feature = "exec-test-support")]
use super::landlock::{LandlockAccessProbe, run_probe};
use super::rlimits::{apply_rlimits, widen_fsize_for_copy};
use super::sealed_copy::SealPolicy;
use super::setns::{
    NsIdentity, TargetIdMaps, UserNsRelation, cgroup_path_matches, read_bounded_from,
    status_effective_uid,
};
use super::{
    ExecError, ExecWorkerProof, IsolationStage, Pid1Target, StageKind, SupplementaryGroups,
    ThreadCountSource, ViolationReason, no_new_privs,
};
use crate::capabilities::ContainerCapabilities;
use crate::landlock::{LandlockRuleset, MountedTargets};
use crate::launch_isolation::{LaunchIsolationRecord, RecordedMountIdentities, RootIdentity};
use crate::oci_runtime::{OciConfig, RootfsDir};
use crate::rlimits::{Rlimit, RlimitKind, Rlimits};
use crate::sys;
use crate::traits::types::ErrorCode;

// テストでは本物（`Threads: 1` と実 syscall を要する）の代わりに偽物へ差し替える（`stages.rs` と同じ）。
#[cfg(test)]
use super::capabilities::testing::{
    apply_default_capabilities_with, clear_supplementary_groups_before_join,
};
#[cfg(not(test))]
use super::capabilities::{
    apply_default_capabilities_with, clear_supplementary_groups_before_join,
};
#[cfg(not(test))]
use super::landlock::apply_landlock_stage_with;
#[cfg(test)]
use super::landlock::testing::apply_landlock_stage_with;
#[cfg(test)]
use super::seccomp::testing::{
    apply_default_seccomp_with, apply_default_seccomp_with_listener_threads,
};
#[cfg(not(test))]
use super::seccomp::{apply_default_seccomp_with, apply_default_seccomp_with_listener_threads};
use super::seccomp_listener::ExecListenerSender;

/// [`prepare_exec_restrictions`] が `setns` の前に確保した再適用の材料一式。[`reapply_restrictions`] が消費する。
#[must_use = "prepared restrictions do nothing until passed to reapply_restrictions"]
pub struct ExecRestrictions {
    landlock: LandlockRuleset,
    threads: ThreadCountSource,
    owner_pid: u32,
    /// launch 時に記録したコンテナの `/` の同一性（`state.json`。トレイト契約 12）。参加後の `/` と照合する基準。
    /// ホスト側の bundle ディレクトリではなく launch の pivot 後の `/` の識別子なので、rootfs を mount namespace の
    /// 中で組み立てる構成（overlay 等）でも成り立つ。
    root: RootIdentity,
    /// launch 時の rlimit の記録（`state.json`。全 16 種）。exec プロセスへ同じ値を載せる。
    rlimits: Rlimits,
    /// 制限を準備した対象への束縛（参加後に別の対象へ適用させない）。
    binding: TargetBinding,
    /// namespace へ参加する前に補助グループを空にした結果（[`prepare_exec_restrictions`] が行う。#1457）。
    /// 観測用の経路・単体テストが直接組み立てた値では `None`（参加前の消去をしていない）。
    groups_before_join: Option<SupplementaryGroups>,
    /// 参加後に呼び出しスレッドを揃える uid・gid（`process.user`）。対象が別の user namespace にいて参加する
    /// ときだけ `Some`（SUP-6・SEC-5・TASK-163.h2・#1462）。同じ user namespace・観測用の経路は `None`。
    ids: Option<ProcessIds>,
    /// 参加後に適用する補助グループ（`process.user.additionalGids`。正規化済み。空なら消去。SEC-5・CORE-6・#2770）。
    /// 確保は `prepare_exec_restrictions` で済ませ、再適用の段（fork 子ではない worker の中）では確保しない。
    groups: NormalizedGroups,
    /// 封印した複製が元のファイルの実行時ポリシー（複製では維持できない LSM・`AT_EXECVE_CHECK` の要否）を
    /// 迂回しないかの判定材料。`setns` の前（ホスト側の securityfs が見えるうち）に作る（#1531）。
    seal_policy: SealPolicy,
    /// seccomp の段で listener を exec の親へ渡す送信口（SEC-4・SUP-6・#2385）。本番の再適用（`Complete`）では必須
    /// （[`Self::with_seccomp_listener`] で付ける。無ければ何も適用せず拒否する）。観測用の経路では任意。
    seccomp_listener: Option<ExecListenerSender>,
    /// 再適用する capability の許可集合。launch 時の分離の記録から取る（`process.capabilities` の drop を
    /// launch と同じにする。SEC-1・CRI-2・#2666）。記録が無い旧記録・観測用の経路は OCI 既定集合
    /// （導入前の launch は必ず OCI 既定集合で起動したため、これが旧記録の正しい値）。
    capabilities: ContainerCapabilities,
    /// launch 時に記録した Mount 由来のルールの識別子（`state.json`。SEC-1・SEC-4・#3201）。Landlock の適用時に
    /// 開いた fd の識別子と照合する。`prepare_exec_restrictions`（本番の入口）が必ず `Some` にし、`None` は
    /// 識別子を持たない結合試験用の観測関数だけ（`Complete` の再適用は `None` を何も適用する前に拒否する）。
    mounts: Option<MountedTargets>,
}

/// 制限を exec の対象（pid1）へ束縛する材料（SUP-6・SEC-1・TASK-163.4）。
///
/// `setns(CLONE_NEWNS)` の後はホスト側の procfs が見えず自プロセスを `/proc/self` で解決できないため、
/// `setns` の前に開いた自プロセスの procfs ディレクトリの fd（`proc_dir`）から `ns/mnt` を引き、参加後の
/// 自プロセスの mount namespace の識別子を読む。これが準備時に記録した対象の識別子と一致しなければ、
/// 同じ rootfs を共有する別コンテナへ参加していても何も適用しない。
struct TargetBinding {
    proc_dir: OwnedFd,
    /// 対象の user namespace の識別子（`Pid1Target::open` が記録し、`join_namespaces` が参加の直前に再照合した
    /// もの）。参加後の自プロセスの `ns/user` と照合する（別の user namespace へ参加する場合も、参加しない
    /// 場合も。#1462）。
    target_user_ns: NsIdentity,
    target_mnt_ns: NsIdentity,
    /// 対象の PID namespace の識別子。参加後に子が入る PID namespace（`ns/pid_for_children`）と照合する。
    target_pid_ns: NsIdentity,
    /// 対象のコンテナ cgroup（`Pid1Target::open` が記録から組み立てた期待パス）。cgroup 参加後の自プロセスの
    /// 所属と完全一致を照合する。
    expected_cgroup: String,
}

impl ExecRestrictions {
    /// seccomp の listener を exec の親へ渡す送信口を付ける（SEC-4・SUP-6・#2385）。
    ///
    /// `spawn_exec_worker_with_listener` が worker へ渡す [`ExecListenerSender`] を、`reapply_restrictions` の前に
    /// 付ける。seccomp の段は `NEW_LISTENER` 付きで filter を載せ、listener を親へ渡して ACK を待つ（届け方は
    /// 送信口が持つ値に従う。`USER_NOTIF` なら応答者は exec の親。#2544）。付けずに本番の再適用を呼ぶと、何も適用せず `FailedPrecondition`
    /// （段 `Validate`）で拒否する（listener の受け渡しを省く経路を本番に残さない。fail-closed）。
    pub fn with_seccomp_listener(mut self, sender: ExecListenerSender) -> Self {
        self.seccomp_listener = Some(sender);
        self
    }

    /// エントリポイントの実行方式の判定結果（`setns` の前に判定済み。封印した複製か現行方式と、その理由。
    /// オーナー判断 2026-10-09「条件付き切り替え」・#1531・REPAIR-4）。supervisor が構造化ログと `ExecOutcome` に
    /// 残すために読む。
    pub fn entrypoint_mode(&self) -> EntrypointExecMode {
        self.seal_policy.mode()
    }
}

impl std::fmt::Debug for ExecRestrictions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // fd・ルール内容は出さない。
        f.debug_struct("ExecRestrictions")
            .field("owner_pid", &self.owner_pid)
            .finish_non_exhaustive()
    }
}

/// launch 経路は適用するが、exec の再適用（本モジュール）は **適用しない** 制限（SUP-6・SEC-1・REPAIR-3）。
///
/// [`ExecRestrictionReport::unapplied`] に載る。TASK-163.4（#503）で rlimit 適用と capability 削減を実装した
/// ため、現在の [`ExecRestrictionReport::UNAPPLIED`] は空。launch 経路に段が増えて exec 側が追従しない場合に
/// 備え、列挙自体は残す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnappliedExecRestriction {
    /// rlimit 適用（launch 経路の `StageKind::Rlimits`。SUP-12）。
    Rlimits,
    /// capability 削減（launch 経路の `StageKind::CapabilityDrop`。SEC-1）。`setns` は資格情報を変えないため、
    /// 適用しなければ rootful の exec プロセスは全 capability を持つ。
    CapabilityDrop,
}

impl UnappliedExecRestriction {
    /// 機械可読な名前（エラーメッセージ・ログ用）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rlimits => "rlimits",
            Self::CapabilityDrop => "capability_drop",
        }
    }

    /// launch 経路でこの制限を適用する段。
    pub fn launch_stage(self) -> StageKind {
        match self {
            Self::Rlimits => StageKind::Rlimits,
            Self::CapabilityDrop => StageKind::CapabilityDrop,
        }
    }
}

/// 適用を終えたプロセスが exec の入口へ持ち越す材料（非公開。[`ExecReady`] だけが保持する）。
struct ExecCarry {
    /// 参加後に照合した `/`（`O_PATH`）。コマンドの cwd を照合済みの root へ置く起点。
    root: OwnedFd,
    /// fork 前の `Threads: 1` 確認に使う、`setns` 前に開いた status fd。
    threads: ThreadCountSource,
    /// 適用したプロセス。別プロセス（fork した子等）が exec の入口を呼べないようにする。
    owner_pid: u32,
    /// 子へ持ち越す `RLIMIT_FSIZE`（#1531）。封印した複製の書き込みが `RLIMIT_FSIZE`（0 や小さい値）で失敗
    /// しないよう、exec プロセスには載せず、子が複製を完成させた後・`execveat` の前に適用する。
    deferred_fsize: Option<Rlimit>,
    /// 子が封印した複製を作る前に参照する判定材料（[`ExecRestrictions`] から持ち越す。#1531）。
    seal_policy: SealPolicy,
}

impl std::fmt::Debug for ExecCarry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // fd は出さない。
        f.debug_struct("ExecCarry")
            .field("owner_pid", &self.owner_pid)
            .finish_non_exhaustive()
    }
}

/// [`reapply_restrictions`] の成功結果（将来拡張できる構造。制限適用の証跡ではない。REPAIR-3）。
///
/// 成功は「rlimit・capability 削減・`NO_NEW_PRIVS`・Landlock・seccomp を載せた」ことを表す。ただし `RLIMIT_FSIZE` だけは
/// この exec プロセスには載せず子へ持ち越す（[`rlimits_deferred`](Self::rlimits_deferred)。#1531）。持ち越した値は
/// exec の子が `execveat` の前に必ず適用して読み戻し、失敗すればコマンドを起動しない（`SetupFailed`）。exec してよい
/// ことの証跡は [`ExecReady`] で、[`into_complete`](Self::into_complete) だけが作る（未適用の一覧
/// [`unapplied`](Self::unapplied) が空のときのみ）。
///
/// フィールドは非公開で、crate の外からは構築も書き換えもできない（未適用の一覧を空に書き換えて完了を
/// 装えない。SEC-1）。読み取りは getter で行う。`Clone` ではない（照合済みの root の fd を持ち越すため）。
///
/// ```
/// # #[cfg(target_os = "linux")]
/// fn inspect(report: &fandhe_container_core::exec::ExecRestrictionReport) -> bool {
///     report.unapplied().is_empty() && report.is_complete()
/// }
/// ```
///
/// 未適用の一覧は書き換えられない（非公開フィールド）:
///
/// ```compile_fail,E0616
/// fn tamper(mut report: fandhe_container_core::exec::ExecRestrictionReport) {
///     report.unapplied = &[];
/// }
/// ```
///
/// crate の外では構築できない:
///
/// ```compile_fail,E0451
/// let _ = fandhe_container_core::exec::ExecRestrictionReport {
///     landlock_rules: 0,
///     seccomp_instructions: 0,
///     rlimits_applied: 0,
///     capability_bounding_dropped: 0,
///     supplementary_groups: None,
///     unapplied: &[],
///     carry: todo!(),
/// };
/// ```
#[derive(Debug)]
#[must_use = "a successful reapply does not make the process ready to exec; call `into_complete`"]
pub struct ExecRestrictionReport {
    landlock_rules: usize,
    seccomp_instructions: usize,
    rlimits_applied: usize,
    rlimits_deferred: usize,
    capability_bounding_dropped: usize,
    supplementary_groups: Option<SupplementaryGroups>,
    unapplied: &'static [UnappliedExecRestriction],
    carry: ExecCarry,
}

impl ExecRestrictionReport {
    /// 現在の実装が適用しない制限の一覧（唯一の定義元。launch 経路の段の順）。TASK-163.4 で空になった。
    pub const UNAPPLIED: &'static [UnappliedExecRestriction] = &[];

    /// 追加した Landlock ルール数。
    pub fn landlock_rules(&self) -> usize {
        self.landlock_rules
    }

    /// exec の子が使うエントリポイントの実行方式（[`ExecRestrictions::entrypoint_mode`] と同じ判定。#1531）。
    pub fn entrypoint_mode(&self) -> EntrypointExecMode {
        self.carry.seal_policy.mode()
    }

    /// 適用した seccomp の BPF 命令数。
    pub fn seccomp_instructions(&self) -> usize {
        self.seccomp_instructions
    }

    /// この exec プロセスへ適用した rlimit の種別数（記録の全 16 種のうち、子へ持ち越した
    /// `RLIMIT_FSIZE` を除いたもの。通常は 15）。
    pub fn rlimits_applied(&self) -> usize {
        self.rlimits_applied
    }

    /// 子へ持ち越した rlimit の種別数（`RLIMIT_FSIZE`。0 か 1。#1531）。exec プロセスには載せず（封印した複製の書き込みを
    /// 妨げないため。複製の期間だけ soft・hard を広げる）、exec の子が `execveat` の前（封印した複製を使うときはその
    /// 完成後）に適用して読み戻す。子での適用に失敗すればコマンドは起動せず `SetupFailed` になる。
    /// [`rlimits_applied`](Self::rlimits_applied) との和が対象の rlimit の種別数。
    pub fn rlimits_deferred(&self) -> usize {
        self.rlimits_deferred
    }

    /// capability 削減で bounding set から落とした capability の数。
    pub fn capability_bounding_dropped(&self) -> usize {
        self.capability_bounding_dropped
    }

    /// 補助グループの扱いの結果（capability 削減の中で、launch 経路と同じ関数が行う。TASK-163 追補・#1457）。
    /// capability 削減を適用していない場合（未適用の一覧に `CapabilityDrop` が載る）は `None`。
    pub fn supplementary_groups(&self) -> Option<SupplementaryGroups> {
        self.supplementary_groups
    }

    /// launch 経路は適用するが、この再適用では適用していない制限（[`ExecRestrictionReport::UNAPPLIED`]）。
    pub fn unapplied(&self) -> &'static [UnappliedExecRestriction] {
        self.unapplied
    }

    /// launch 経路と同じ制限がすべて載ったか（未適用が残る間は `false`）。持ち越した `RLIMIT_FSIZE`
    /// （[`rlimits_deferred`](Self::rlimits_deferred)）は、exec の子が `execveat` の前に必ず適用する前提で完了に含める。
    /// 判定を見るだけの補助で、exec の許可には [`into_complete`](Self::into_complete) の証跡を使うこと。
    pub fn is_complete(&self) -> bool {
        self.unapplied.is_empty()
    }

    /// 未適用の制限が無ければ、exec へ進んでよいことの証跡 [`ExecReady`] に変える（SEC-1）。
    ///
    /// 未適用が 1 つでも残っていれば `FailedPrecondition`（段 `Exec`。メッセージに未適用の名前を並べる）。
    pub fn into_complete(self) -> Result<ExecReady, ExecError> {
        if self.unapplied.is_empty() {
            return Ok(ExecReady { carry: self.carry });
        }
        let names: Vec<&str> = self.unapplied.iter().map(|u| u.as_str()).collect();
        Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Exec,
            format!(
                "exec restrictions are incomplete; not applied: {}",
                names.join(", ")
            ),
        ))
    }
}

/// 「launch 経路と同じ制限がすべて exec プロセスへ載った」ことの証跡（SUP-6・SEC-1）。`RLIMIT_FSIZE` だけは子へ持ち越して
/// おり（[`ExecRestrictionReport::rlimits_deferred`]）、この証跡を受け取った exec の子が `execveat` の前に適用する。
///
/// [`ExecRestrictionReport::into_complete`] だけが作る。フィールドは非公開で、公開コンストラクタ・`Clone`・
/// `Default` を持たないため、crate の外では構築も複製もできない。照合済みの `/` の fd と、`setns` 前に
/// 開いた status fd を持ち、exec の入口（`spawn_exec_command`）が cwd の設定と fork 前の単一スレッド確認に使う。
///
/// # 契約（TASK-163.4）
///
/// exec 専用プロセスの fork / execve の入口（`spawn_exec_command`）は、この型を **値で** 受け取る（消費して
/// 二重実行を防ぐ）。`ExecRestrictionReport`・真偽値・`is_complete()` の結果を受け取る入口や、この型を
/// 経由しない入口はない。この型を作る別経路（テスト用を含む公開コンストラクタ・feature による抜け道）を
/// 足さない。対象（どのコンテナへの exec か）への束縛は [`reapply_restrictions`] が適用の前に行い、
/// その後は seccomp が `setns`・`unshare` を拒否するため、証跡が作られた後に対象が変わることはない。
///
/// ```compile_fail,E0451
/// let _ = fandhe_container_core::exec::ExecReady { carry: todo!() };
/// ```
#[derive(Debug)]
#[must_use = "ExecReady is the only evidence that permits exec; pass it to the exec entry point"]
pub struct ExecReady {
    carry: ExecCarry,
}

impl ExecReady {
    /// 持ち越した材料を取り出す（exec の入口だけが呼ぶ。`ExecReady` を消費する）。
    pub(super) fn into_parts(self) -> ExecReadyParts {
        let ExecCarry {
            root,
            threads,
            owner_pid,
            deferred_fsize,
            seal_policy,
        } = self.carry;
        ExecReadyParts {
            root,
            threads,
            owner_pid,
            deferred_fsize,
            seal_policy,
        }
    }

    /// 単体テスト専用: 任意の材料から証跡を作る。本番ビルドには存在しない（crate 内の `cfg(test)` のみ）。
    #[cfg(test)]
    pub(super) fn for_test(root: OwnedFd, threads: ThreadCountSource, owner_pid: u32) -> Self {
        Self {
            carry: ExecCarry {
                root,
                threads,
                owner_pid,
                deferred_fsize: None,
                seal_policy: SealPolicy::unrestricted(),
            },
        }
    }
}

/// [`ExecReady::into_parts`] が返す持ち越し材料（exec の入口が使う）。
pub(super) struct ExecReadyParts {
    pub(super) root: OwnedFd,
    pub(super) threads: ThreadCountSource,
    pub(super) owner_pid: u32,
    /// 子が複製の完成後に適用する `RLIMIT_FSIZE`（[`ExecCarry::deferred_fsize`]）。
    pub(super) deferred_fsize: Option<Rlimit>,
    /// 子が封印した複製を作る前に参照する判定材料（[`ExecCarry::seal_policy`]）。
    pub(super) seal_policy: SealPolicy,
}

/// launch 時の分離の記録（`launch`）から Landlock ruleset を組み直し、参加後の `/` と照合する識別子・
/// 対象への束縛の材料・自プロセスの status fd を確保する。`config.json` から Landlock を導き直さない（#1468）。
///
/// `join_namespaces` の **前** に、再適用を行うプロセス自身が呼ぶ。`rootfs` は稼働中コンテナの bundle から
/// `oci_runtime::pin_bundle_rootfs` で固定したもの（`config` と同じ bundle のもの）で、自プロセスの `/` と別の
/// ディレクトリであることの検査と監査にだけ使う（`/` の照合の基準は `launch` の記録）。`config` は
/// `process.user` の解釈に使う。`target` は
/// `join_namespaces` へ渡すのと同じ対象で、その mount namespace の識別子をここで記録する（参加後に別の対象へ
/// 適用させない）。`rlimits` は launch 時に `state.json` へ記録した全 16 種（`StateRecord::rlimits`）で、
/// launch と同じ値を exec プロセスへ載せる。全 16 種そろっていなければ `FailedPrecondition`（段 `Rlimits`）で拒否する。
/// **準備の最後に、呼び出しプロセスの補助グループを空にする**（不可逆。参加の前に消去するため。#1457）。消去
/// できず、user namespace の `setgroups` = `deny` も確認できなければ `PermissionDenied`（段 `CapabilityDrop`）で、
/// 参加へ進ませない。
/// ABI 検出・ルール生成の失敗（Landlock 未対応カーネルを含む）は `stage = Landlock` で拒否する
/// （fail-closed。CORE-5）。`rootfs` が呼び出しプロセス自身の `/` と同じディレクトリなら、参加後の照合が
/// 意味を持たないため違反記録 `rootfs_is_host_root` つきで拒否する（SEC-1）。
///
/// `worker` は [`spawn_exec_worker`](super::spawn_exec_worker) の worker の中でしか得られない証跡で、補助グループの
/// 不可逆な消去を常駐プロセスで起こさないために要求する（#1532）。`reapply_restrictions` の capability 削減の中の
/// 消去も、[`ExecRestrictions`] がこの関数からしか作れないため同じ証跡で間接的に守られる。
///
/// ```compile_fail,E0061
/// use fandhe_container_core::exec::{Pid1Target, prepare_exec_restrictions};
/// use fandhe_container_core::oci_runtime::{OciConfig, RootfsDir};
/// use fandhe_container_core::rlimits::Rlimits;
/// use fandhe_container_core::launch_isolation::LaunchIsolationRecord;
/// fn without_proof(
///     t: &Pid1Target,
///     c: &OciConfig,
///     r: &RootfsDir,
///     l: &Rlimits,
///     i: &LaunchIsolationRecord,
/// ) {
///     let _ = prepare_exec_restrictions(t, c, r, l, i);
/// }
/// ```
pub fn prepare_exec_restrictions(
    worker: &ExecWorkerProof,
    target: &Pid1Target,
    config: &OciConfig,
    rootfs: &RootfsDir,
    rlimits: &Rlimits,
    launch: &LaunchIsolationRecord,
) -> Result<ExecRestrictions, ExecError> {
    // 証跡は型で呼び出し元を絞るためだけに要求する（値は使わない）。
    let _ = worker;
    let own_root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Validate, "open own root"))?;
    reject_own_root(rootfs.as_fd(), own_root.as_fd())?;
    reject_recorded_own_root(launch.root(), own_root.as_fd())?;
    let relation = target.user_ns_relation();
    let target_mnt_ns = target.mnt_ns_identity()?;
    let target_pid_ns = target.pid_ns_identity()?;
    // 記録が欠けている・不完全だと、緩い rlimit のまま exec することになるため拒否する（#1460・#1467）。
    require_rlimits(rlimits)?;
    let rlimits = rlimits.clone();
    let binding = TargetBinding {
        proc_dir: open_own_proc_dir()?,
        target_user_ns: relation.target_identity(),
        target_mnt_ns,
        target_pid_ns,
        expected_cgroup: target.expected_cgroup_path().to_owned(),
    };
    // 別の user namespace へ参加するときだけ、参加後に揃える uid・gid と補助グループ（`process.user`）を決める。
    // 対象の user namespace の実際の写像（`uid_map`・`gid_map`・`setgroups`）と副作用の前に照合し、写像の外・
    // `setgroups` が `deny` の追加グループは補助グループの消去（不可逆）より前に拒否する（SEC-5・CORE-6・#2770）。
    let maps = match relation {
        UserNsRelation::Shared { .. } => None,
        UserNsRelation::Distinct { .. } => Some(target.user_id_maps()?),
    };
    let user = exec_user_from_config(config, &relation, maps.as_ref())?;
    // 旧記録（識別子なし）の拒否は、不可逆な補助グループの消去より前に行う（#3201）。
    let mounts = recorded_mounts_for_exec(launch)?;
    let mut restrictions = prepare_with_launch(launch, launch.root(), rlimits, binding)?;
    restrictions.mounts = Some(mounts);
    restrictions.ids = user.ids;
    restrictions.groups = user.groups;
    // 準備の最後（ここまでの失敗では何も変えない）に、補助グループを参加の **前** に空にする。対象の user
    // namespace へ入った後では `setgroups` が `deny` で消せず、exec を起動したプロセスのホスト側の補助グループを
    // 持ち込んでしまうため（#1457）。不可逆で、以後このプロセスは exec 専用として使い捨てる。
    // 補助グループを持つ非特権の呼び出し側は初期 user namespace で消去できないが、コンテナの所有者自身の exec
    // （別の user namespace で、呼び出し側の実効 uid が対象の実効 uid と一致）に限り参加後へ回す（#1462）。
    let defer = defer_group_clearing(&relation, own_effective_uid());
    restrictions.groups_before_join = match clear_supplementary_groups_before_join(
        &mut restrictions.threads,
        restrictions.binding.proc_dir.as_fd(),
        defer,
    )? {
        PreJoinGroups::Done(groups) => Some(groups),
        PreJoinGroups::DeferredUntilJoin => None,
    };
    Ok(restrictions)
}

/// 参加前の補助グループの消去を参加後へ回してよいか（副作用の前に判定するテスト可能な純関数。SUP-6・SEC-1・
/// SEC-5・TASK-163.h2・#1462）。
///
/// 別の user namespace へ参加し（`Distinct`）、かつ呼び出し側の実効 uid（`own_euid`。読めなければ `None`）が対象の
/// user namespace の所有者 uid と一致する場合だけ真。pid1 の実効 uid とは比べない（`process.user` が非 root だと
/// pid1 の uid は所有者と別の値になるため。#2770）。一致しない呼び出し側（コンテナの所有者と別の uid、たとえば別ユーザーの
/// 補助グループを持つプロセス）は、参加後の消去が `deny` で現状維持になるとそのグループをコンテナへ持ち込むため、
/// 従来どおり参加前の消去の失敗として拒否させる。
fn defer_group_clearing(relation: &UserNsRelation, own_euid: Option<u32>) -> bool {
    match *relation {
        UserNsRelation::Shared { .. } => false,
        UserNsRelation::Distinct { owner_uid, .. } => own_euid == Some(owner_uid),
    }
}

/// 呼び出しプロセスの実効 uid（`/proc/self/status` の `Uid:`。呼び出し側の user namespace から見た値）。
/// 読めない・解釈できない場合は `None`。
fn own_effective_uid() -> Option<u32> {
    let file = std::fs::File::open("/proc/self/status").ok()?;
    let text = read_bounded_from(file, OWN_STATUS_READ_LIMIT).ok()?;
    status_effective_uid(&text)
}

/// 自プロセスの `status` の読み取り上限（バイト）。
const OWN_STATUS_READ_LIMIT: u64 = 64 * 1024;

/// exec が参加後に適用する資格情報（uid・gid と補助グループ。SUP-6・SEC-5・CORE-6・#2770）。
///
/// `config.json` の `process.user` を対象 user namespace の写像と照合した結果。将来 exec 要求ごとの user の上書き
/// （CLI の `--user`・CRI の Exec。#2712・#680）を足すときは、同じ照合を通した値をここへ渡す拡張点になる
/// （上書き自体は未実装）。
#[derive(Debug, PartialEq, Eq)]
struct ExecUser {
    /// 参加後に揃える uid・gid。同じ user namespace（`Shared`）では `None`（呼び出し側の値を引き継ぐ）。
    ids: Option<ProcessIds>,
    /// 参加後に適用する補助グループ（空なら消去）。
    groups: NormalizedGroups,
}

/// `config.json` の `process.user` から、参加後に適用する資格情報を導く（SUP-6・SEC-5・CORE-6・TASK-163.h2・
/// #1462・#2770。副作用なしの純関数）。
///
/// - `Distinct`（別の user namespace。既定の rootless。本番はこちらだけ）: uid・gid・`additionalGids` を対象の
///   写像（`maps`）と照合する。写像の外は `InvalidArgument`、`additionalGids` が非空で `setgroups` が `deny`
///   （単一 ID 写像）なら `FailedPrecondition`（黙って落とさない）。通れば ids と正規化した補助グループを返す
///   （launch と同じ順序 setgroups → setgid → setuid で適用される）。メッセージは固定文言で値を含めない（ERR-1）
/// - `Shared`（同じ user namespace。rootful 相当。本番では到達しない）: root（0/0・追加グループなし）だけを従来
///   どおり受け、それ以外は `Unimplemented`（`RootfulHostRoot` の判断待ち。#2241）
///
/// `process` が無い config は `InvalidArgument`。launch 側の写像外は `FailedPrecondition` のままで、exec は
/// 要求の誤りとして `InvalidArgument` にする（#2770）。
fn exec_user_from_config(
    config: &OciConfig,
    relation: &UserNsRelation,
    maps: Option<&TargetIdMaps>,
) -> Result<ExecUser, ExecError> {
    let stage = IsolationStage::Validate;
    let process = config.process().ok_or_else(|| {
        ExecError::new(
            ErrorCode::InvalidArgument,
            stage,
            "config.json: process is required",
        )
    })?;
    let user = process.user();
    let (uid, gid) = (user.uid(), user.gid());
    let additional = user.additional_gids();
    let maps = match (relation, maps) {
        (UserNsRelation::Distinct { .. }, Some(maps)) => maps,
        (UserNsRelation::Distinct { .. }, None) => {
            return Err(ExecError::new(
                ErrorCode::Internal,
                stage,
                "target id maps are missing for a distinct user namespace",
            ));
        }
        (UserNsRelation::Shared { .. }, _) => {
            if uid != 0 || gid != 0 || !additional.is_empty() {
                return Err(ExecError::new(
                    ErrorCode::Unimplemented,
                    stage,
                    "process.user other than root is not supported",
                ));
            }
            return Ok(ExecUser {
                ids: None,
                groups: NormalizedGroups::empty(),
            });
        }
    };
    if maps.uid.host_id_of(uid).is_none() || maps.gid.host_id_of(gid).is_none() {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            stage,
            "process.user is not mapped in the container user namespace (SEC-5)",
        ));
    }
    if additional.iter().any(|g| maps.gid.host_id_of(*g).is_none()) {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            stage,
            "process.user.additionalGids is not mapped in the container user namespace (SEC-5)",
        ));
    }
    if !additional.is_empty() && !maps.setgroups_allowed {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "process.user.additionalGids requires setgroups to be allowed in the container user namespace (SEC-5)",
        ));
    }
    Ok(ExecUser {
        ids: Some(ProcessIds { uid, gid }),
        groups: NormalizedGroups::new(additional)?,
    })
}

/// 結合試験専用: 対象 pid1 の実際の写像に対する `process.user` の照合だけを通す（SEC-5・CORE-6・#2770）。
///
/// 本番の `prepare_exec_restrictions` と同じ関数（`Pid1Target::user_id_maps` と `exec_user_from_config`）を呼び、
/// 受け入れ時は `(uid, gid, 正規化した補助グループ)`（同じ user namespace では `None`）を返す。副作用なし。
/// `exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn exec_user_check_for_test(
    target: &Pid1Target,
    config: &OciConfig,
) -> Result<Option<(u32, u32, Vec<u32>)>, ExecError> {
    let relation = target.user_ns_relation();
    let maps = match relation {
        UserNsRelation::Shared { .. } => None,
        UserNsRelation::Distinct { .. } => Some(target.user_id_maps()?),
    };
    let user = exec_user_from_config(config, &relation, maps.as_ref())?;
    Ok(user
        .ids
        .map(|ids| (ids.uid, ids.gid, user.groups.as_slice().to_vec())))
}

/// 参加前の消去の結果 `before` と、参加後の capability 削減の中での結果 `after` から、報告する値を決める。
///
/// 参加前に消去していれば、参加後は「元から空」になる。その場合は「消去した」ことと件数を残す。それ以外は
/// 参加後の結果（最終的な状態）をそのまま使う。
fn combine_group_outcomes(
    before: Option<SupplementaryGroups>,
    after: Option<SupplementaryGroups>,
) -> Option<SupplementaryGroups> {
    match (before, after) {
        (
            Some(cleared @ SupplementaryGroups::Cleared { .. }),
            Some(SupplementaryGroups::AlreadyEmpty),
        ) => Some(cleared),
        (_, after) => after,
    }
}

/// `rootfs` が呼び出しプロセス自身の `/` と別のディレクトリであることを確かめる
/// （Landlock の検出より先に判定する）。
///
/// 拒否は違反 `rootfs_is_host_root`（種別 `rootfs_pivot`）で、supervisor の worker から `err` 行で親へ運ばれ、
/// 親が層 `mount`（パスなし）に 1 件記録する（`ViolationReason::EXEC_WORKER_REASONS`・`record_exec_worker_rejection`。
/// SEC-4・SEC-1）。
fn reject_own_root(rootfs: BorrowedFd<'_>, own_root: BorrowedFd<'_>) -> Result<(), ExecError> {
    if same_directory(rootfs, own_root).map_err(|e| e.at_stage(IsolationStage::Validate))? {
        return Err(ExecError::from_violation_at(
            ViolationReason::RootfsIsHostRoot,
            None,
            IsolationStage::Validate,
        ));
    }
    Ok(())
}

/// 記録した launch 時の `/` が呼び出しプロセス自身の `/` と別であることを確かめる（SEC-1・#1468）。
///
/// 記録が自分の `/`（ホストの `/`）と一致するなら、参加後の照合は「ホストの `/` を拒否する」意味を失う
/// （壊れた記録・ホストの `/` を指す記録）ため、[`reject_own_root`] と同じ違反 `rootfs_is_host_root` で拒否する。
fn reject_recorded_own_root(
    recorded: RootIdentity,
    own_root: BorrowedFd<'_>,
) -> Result<(), ExecError> {
    let own = RootIdentity::of_dir_fd(own_root).ok_or_else(|| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Validate,
            "failed to inspect the root directory",
        )
    })?;
    if own == recorded {
        return Err(ExecError::from_violation_at(
            ViolationReason::RootfsIsHostRoot,
            None,
            IsolationStage::Validate,
        ));
    }
    Ok(())
}

/// 結合試験 `tests/exec_audit.rs`（supervisor）専用の入口: `rootfs` を symlink 非追従で開き、
/// [`prepare_exec_restrictions`] と同じ `reject_own_root` の判定だけを行う（SEC-4・SEC-1・#1614 の事後監査）。
///
/// 本番の経路で `rootfs_is_host_root` に届くには対象の特定（入れ子の PID 1・cgroup の一致）を通る必要があり、
/// 非特権の結合試験では起こせない。そこで判定の関数そのものを worker の中から呼べるようにし、実際の拒否が
/// worker の結果行を経て親の監査記録になることを確かめる。通常の利用者は呼ばない。`exec-test-support`
/// feature を付けたビルドにだけ存在する（リリースビルドでは `compile_error!` で止まる）。
#[cfg(feature = "exec-test-support")]
pub fn reject_own_root_for_test(rootfs: &Path) -> Result<(), ExecError> {
    use std::os::unix::ffi::OsStrExt as _;
    let stage = IsolationStage::Validate;
    let path = std::ffi::CString::new(rootfs.as_os_str().as_bytes())
        .map_err(|_| ExecError::new(ErrorCode::InvalidArgument, stage, "invalid rootfs path"))?;
    let dir = sys::open_dir_path_nofollow(None, &path)
        .map_err(|e| ExecError::from_sys(e, stage, "open rootfs"))?;
    let own_root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, stage, "open own root"))?;
    reject_own_root(dir.as_fd(), own_root.as_fd())
}

/// 結合試験 `tests/exec_setns_join.rs`（supervisor）専用の入口: 参加後の呼び出しプロセスの `/` が、記録した
/// 識別子 `expected` と一致するかを本番と同じ `open_verified_root` で照合する（SEC-1・#1468）。一致すれば `Ok`、
/// 不一致は違反 `exec_root_not_container_rootfs` つきの `Err`。overlay のように rootfs を mount namespace の中で
/// 組み立てる構成の代わりの検証に使う。`exec-test-support` feature を付けたビルドにだけ存在する。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn verify_joined_root_for_test(expected: RootIdentity) -> Result<(), ExecError> {
    open_verified_root(expected).map(|_| ())
}

/// 自プロセスの procfs ディレクトリ（pid 指定。`O_PATH`）を開き、本物の procfs であることを確かめる。
///
/// `setns` の後は `/proc` がコンテナ側の procfs になるため、参加前に開いた fd を保持して `ns/mnt` を引く
/// 起点にする（`/proc/self` は symlink で `O_NOFOLLOW` では開けないため pid で開く）。
fn open_own_proc_dir() -> Result<OwnedFd, ExecError> {
    let stage = IsolationStage::SetNs;
    let path = std::ffi::CString::new(format!("/proc/{}", std::process::id()))
        .map_err(|_| ExecError::new(ErrorCode::Internal, stage, "invalid own procfs path"))?;
    let dir = sys::open_dir_path_nofollow(None, &path)
        .map_err(|e| ExecError::from_sys(e, stage, "open own procfs directory"))?;
    if sys::fs_type(dir.as_fd()) != Ok(sys::PROC_MAGIC) {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "own procfs directory is not on procfs",
        ));
    }
    Ok(dir)
}

/// 保持した procfs ディレクトリ `proc_dir` から、呼び出しプロセスの現在の mount namespace の識別子を読む。
///
/// `ns/mnt` は参照のたびにタスクの現在の namespace へ解決されるため、`setns` の後は参加先を返す。
fn current_mnt_ns_identity(proc_dir: BorrowedFd<'_>) -> Result<NsIdentity, ExecError> {
    own_ns_identity(proc_dir, c"ns/mnt", "mount")
}

/// 保持した procfs ディレクトリ `proc_dir` から、呼び出しプロセスの現在の user namespace の識別子を読む。
///
/// `ns/user` は参照のたびにタスクの現在の資格情報の user namespace へ解決されるため、`setns` の後は参加先を返す。
fn current_user_ns_identity(proc_dir: BorrowedFd<'_>) -> Result<NsIdentity, ExecError> {
    own_ns_identity(proc_dir, c"ns/user", "user")
}

/// 保持した procfs ディレクトリ `proc_dir` から、呼び出しプロセスの子が入る PID namespace の識別子を読む。
///
/// `setns(CLONE_NEWPID)` は呼び出しプロセス自身の PID namespace を変えず、以後の子だけを移す。コマンドは
/// fork した子で実行するため、`ns/pid`（自分自身）ではなく `ns/pid_for_children` を照合する。
fn current_pid_ns_for_children_identity(proc_dir: BorrowedFd<'_>) -> Result<NsIdentity, ExecError> {
    own_ns_identity(proc_dir, c"ns/pid_for_children", "PID")
}

/// `proc_dir` 配下の namespace エントリ `entry` の識別子（nsfs の `st_dev`・`st_ino`）。
fn own_ns_identity(
    proc_dir: BorrowedFd<'_>,
    entry: &std::ffi::CStr,
    what: &'static str,
) -> Result<NsIdentity, ExecError> {
    let stage = IsolationStage::SetNs;
    let ns = sys::open_path_follow_at(proc_dir, entry)
        .map_err(|e| ExecError::from_sys(e, stage, &format!("open own {what} namespace")))?;
    // `O_PATH` の fd への fstat（パスを再解決しない）。
    let meta = std::fs::File::from(ns)
        .metadata()
        .map_err(|e| ExecError::from_io(&e, stage, &format!("inspect own {what} namespace")))?;
    Ok((meta.dev(), meta.ino()))
}

/// 保持した procfs ディレクトリ `proc_dir` から、呼び出しプロセスの所属 cgroup が `expected`（cgroup v2 の
/// 絶対パス）と完全一致するかを返す。`/proc` は参加後にコンテナ側の procfs になるため、参加前に開いた fd から読む。
fn own_cgroup_matches(proc_dir: BorrowedFd<'_>, expected: &str) -> Result<bool, ExecError> {
    let stage = IsolationStage::CgroupJoin;
    let fd = sys::open_read_at(proc_dir, c"cgroup")
        .map_err(|e| ExecError::from_sys(e, stage, "open own cgroup"))?;
    let text = read_bounded_from(std::fs::File::from(fd), OWN_CGROUP_READ_LIMIT)
        .map_err(|e| ExecError::from_io(&e, stage, "read own cgroup"))?;
    Ok(cgroup_path_matches(&text, expected))
}

/// 自プロセスの cgroup v2 パス（`0::<path>`）。観測関数・単体テストが「対象は自分自身」の束縛を作るために使う。
#[cfg(any(test, feature = "exec-test-support"))]
fn own_cgroup_path(proc_dir: BorrowedFd<'_>) -> Result<String, ExecError> {
    let stage = IsolationStage::CgroupJoin;
    let fd = sys::open_read_at(proc_dir, c"cgroup")
        .map_err(|e| ExecError::from_sys(e, stage, "open own cgroup"))?;
    let text = read_bounded_from(std::fs::File::from(fd), OWN_CGROUP_READ_LIMIT)
        .map_err(|e| ExecError::from_io(&e, stage, "read own cgroup"))?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or_else(|| ExecError::new(ErrorCode::Internal, stage, "own cgroup v2 entry missing"))
}

/// 自プロセスの `cgroup` の読み取り上限（バイト）。
const OWN_CGROUP_READ_LIMIT: u64 = 64 * 1024;

/// 参加後の user namespace・mount namespace・子が入る PID namespace・所属 cgroup が、準備時に記録した対象の
/// ものと一致することをこの順で確かめる（SEC-1・SEC-5）。不一致は違反記録（user / mount は
/// `exec_joined_namespace_mismatch`、他は `exec_joined_pid_namespace_mismatch` / `exec_joined_cgroup_mismatch`。
/// 何も適用しない）。user namespace は別の user namespace へ参加した場合も参加しない場合も照合する（#1462。
/// 参加しない場合は「呼び出し側 = 対象」の一致の確認になる）。
fn verify_target_binding(binding: &TargetBinding) -> Result<(), ExecError> {
    let proc_dir = binding.proc_dir.as_fd();
    if current_user_ns_identity(proc_dir)? != binding.target_user_ns {
        return Err(ExecError::from_violation(
            ViolationReason::ExecJoinedNamespaceMismatch,
            None,
        ));
    }
    if current_mnt_ns_identity(proc_dir)? != binding.target_mnt_ns {
        return Err(ExecError::from_violation(
            ViolationReason::ExecJoinedNamespaceMismatch,
            None,
        ));
    }
    if current_pid_ns_for_children_identity(proc_dir)? != binding.target_pid_ns {
        return Err(ExecError::from_violation(
            ViolationReason::ExecJoinedPidNamespaceMismatch,
            None,
        ));
    }
    if !own_cgroup_matches(proc_dir, &binding.expected_cgroup)? {
        return Err(ExecError::from_violation_at(
            ViolationReason::ExecJoinedCgroupMismatch,
            Some(Path::new(&binding.expected_cgroup)),
            IsolationStage::SetNs,
        ));
    }
    Ok(())
}

/// [`prepare_exec_restrictions`] の本体（`/` が自分の `/` でないことの検査を除く）。
/// 結合試験用の観測関数は `setns` をしないため、自分の `/`・自分の namespace を基準にしてここから入る。
/// Landlock は記録（`launch`）のルールからだけ作り、`config.json` は読まない（#1468）。
fn prepare_with_launch(
    launch: &LaunchIsolationRecord,
    root: RootIdentity,
    rlimits: Rlimits,
    binding: TargetBinding,
) -> Result<ExecRestrictions, ExecError> {
    let landlock = landlock_ruleset_from_record(launch)?;
    let seal_policy = SealPolicy::probe();
    let status_error =
        |what: &'static str| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, what);
    let file = std::fs::File::open("/proc/self/status")
        .map_err(|_| status_error("failed to open /proc/self/status"))?;
    // スレッド数の取得元が本物の procfs であることを確かめる（`/proc` に別の FS が載った環境で、
    // 固定の内容を読んで単一スレッドと誤認しない。fail-closed）。
    if sys::fs_type(file.as_fd()) != Ok(sys::PROC_MAGIC) {
        return Err(status_error("/proc/self/status is not on procfs"));
    }
    Ok(ExecRestrictions {
        landlock,
        threads: ThreadCountSource::PreOpened(file),
        owner_pid: std::process::id(),
        root,
        rlimits,
        binding,
        groups_before_join: None,
        ids: None,
        groups: NormalizedGroups::empty(),
        seal_policy,
        seccomp_listener: None,
        capabilities: launch
            .capabilities()
            .unwrap_or_else(ContainerCapabilities::oci_default),
        mounts: None,
    })
}

/// launch 時のマウントの識別子を記録から取り出す（本番の入口 [`prepare_exec_restrictions`] 専用。SEC-1・SEC-4・#3201）。
///
/// Mount 由来のルールがあるのに識別子が無い旧記録（この版より前に作ったコンテナ）は、重ねられたマウントを検出できない
/// ため `FailedPrecondition`（段 `Landlock`）で拒否する（`NotRecorded` へ縮退して続けない。fail-closed）。違反の試行では
/// ないので監査には記録しない。作り直しの手順は `docs/setup/exec-mount-identity-recovery.md`。
/// Mount 由来のルールが無い記録（rootfs だけ）は空の記録で通す。
/// `setns` と補助グループの消去（不可逆）より前に呼ぶ。
fn recorded_mounts_for_exec(launch: &LaunchIsolationRecord) -> Result<MountedTargets, ExecError> {
    if launch.landlock().mount_identities() == RecordedMountIdentities::Absent {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Landlock,
            "launch isolation record has no mount identities; recreate the container",
        ));
    }
    MountedTargets::from_recorded(launch.landlock()).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Landlock,
            "too many recorded mount identities",
        )
    })
}

/// 再適用する rlimit の集合が全 16 種そろっていることを確かめる（SUP-6・SEC-1・REPAIR-3・TASK-163 追補・#1460・#1467）。
///
/// 空集合や一部の種別だけの集合は「適用する値が無い種別」を残し、launch より緩い rlimit のまま exec へ進めてしまう
/// （結果の件数が減るだけで未適用の一覧には載らない）。本番の入口（[`prepare_exec_restrictions`]・
/// [`reapply_restrictions`]）は、全 16 種そろっていない集合を `FailedPrecondition`（段 `Rlimits`）で拒否する。
/// 通常は launch 時の記録（`state.json`）から全 16 種が入る。
fn require_rlimits(rlimits: &Rlimits) -> Result<(), ExecError> {
    if !rlimits.is_complete() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Rlimits,
            "the rlimits of the exec target are incomplete; refusing to exec without all rlimits",
        ));
    }
    Ok(())
}

/// 2 つの fd が同じディレクトリ（`st_dev`・`st_ino` が一致）を指すか。どちらかがディレクトリでない・
/// 調べられない場合はエラー（段 `SetNs`。一致とも不一致とも扱わない）。
fn same_directory(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> Result<bool, ExecError> {
    let identity = |fd: BorrowedFd<'_>| -> Option<(u64, u64)> {
        // `O_PATH` の fd への fstat（パスを再解決しない）。複製は同じ open file description を指す。
        let meta = std::fs::File::from(fd.try_clone_to_owned().ok()?)
            .metadata()
            .ok()?;
        meta.is_dir().then(|| (meta.dev(), meta.ino()))
    };
    match (identity(a), identity(b)) {
        (Some(a), Some(b)) => Ok(a == b),
        _ => Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::SetNs,
            "failed to inspect the root directory",
        )),
    }
}

/// 参加後の呼び出しプロセスの `/` を開き、launch 時に記録したコンテナの `/`（`expected`）と同じ
/// ディレクトリ（`st_dev`・`st_ino` の一致）であることを確かめて返す（SEC-1）。不一致は違反記録
/// `exec_root_not_container_rootfs`。
///
/// 返す fd は Landlock のルールパスを辿る起点と、コマンドの cwd の起点に使う（照合した実体と起点を
/// 同じ fd にする）。
///
/// inode 番号の再利用への備え: 記録は識別子だけで fd を持ち続けないが、呼び出し側が先に mount namespace の
/// 束縛（`verify_target_binding`）を済ませており、生きている pid1 の mount namespace が `/` のマウントを固定
/// している。SEC-1 で `CAP_SYS_ADMIN` を持たないコンテナは `/` を付け替えられず、seccomp が `setns`・`unshare` を
/// 拒否する。したがって束縛の後の `/` の識別子は launch のものと一致するか、記録が古い（restart で記録し直して
/// いない）かのどちらかで、後者は不一致として拒否される。
fn open_verified_root(expected: RootIdentity) -> Result<OwnedFd, ExecError> {
    let root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, IsolationStage::SetNs, "open / after joining"))?;
    let actual = RootIdentity::of_dir_fd(root.as_fd()).ok_or_else(|| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::SetNs,
            "failed to inspect the root directory",
        )
    })?;
    if actual != expected {
        return Err(ExecError::from_violation(
            ViolationReason::ExecRootNotContainerRootfs,
            None,
        ));
    }
    Ok(root)
}

/// rlimit → capability 削減 → `NO_NEW_PRIVS` → Landlock → seccomp を呼び出しプロセスへ不可逆に適用する。
///
/// `join_namespaces` と `join_cgroup` の **後**、準備したプロセス自身から単一スレッドで呼ぶ。
/// 適用の前に、参加後の mount namespace が準備時に記録した対象のものであること、参加後の `/` が準備時に
/// 固定したコンテナの rootfs であることをこの順で照合し、不一致なら何も適用せず拒否する（違反記録つき。
/// SEC-1）。適用順は launch 経路（`StageKind::ORDER`）の相対順と同じで、rlimit は capability 削減（hard の
/// 引き上げができなくなる）と seccomp（`prlimit64` を許す必要が生じない）の前に置く。Landlock のルールパスは
/// 照合済みの `/` を起点に辿る。最初の失敗で打ち切る。失敗後の制限は部分的に載った不定状態のため、
/// 呼び出し側は続行せず終了すること。
///
/// 成功した結果から [`ExecRestrictionReport::into_complete`] が返す [`ExecReady`] が、`execve` へ進んでよい
/// ことの唯一の証跡。
pub fn reapply_restrictions(
    restrictions: ExecRestrictions,
) -> Result<ExecRestrictionReport, ExecError> {
    reapply_inner(restrictions, ReapplyMode::Complete)
}

/// [`reapply_inner`] が適用する範囲。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapplyMode {
    /// 本番: すべての制限を適用する。rlimit の空集合は拒否する（#1460）。
    Complete,
    /// 結合試験用の観測関数専用: capability 削減を省き、rlimit の空集合を許す。省いたものは結果の未適用の
    /// 一覧へ載るため、完了（`ExecReady`）にはならない。
    #[cfg_attr(not(feature = "exec-test-support"), allow(dead_code))]
    ObservationWithoutCapabilityDrop,
}

/// [`reapply_restrictions`] の本体。`mode` が観測用のときだけ capability 削減を省き（`CAP_SETPCAP` を持たない
/// 非特権の使い捨て子で seccomp / Landlock の遮断だけを観測するため）、rlimit の空集合を許す。省いた制限は
/// 結果の未適用の一覧（`CapabilityDrop`・空集合のときは `Rlimits`）へ載せる（完了を装わない）。本番の入口は
/// 常に [`ReapplyMode::Complete`] で、rlimit の空集合を何も適用する前に拒否する。
fn reapply_inner(
    restrictions: ExecRestrictions,
    mode: ReapplyMode,
) -> Result<ExecRestrictionReport, ExecError> {
    let drop_capabilities = mode == ReapplyMode::Complete;
    let ExecRestrictions {
        landlock,
        mut threads,
        owner_pid,
        root: expected_root,
        rlimits,
        binding,
        groups_before_join,
        ids,
        groups,
        seal_policy,
        seccomp_listener,
        capabilities: allowed_capabilities,
        mounts,
    } = restrictions;
    if owner_pid != std::process::id() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "restrictions must be reapplied by the process that prepared them",
        ));
    }
    // 本番は rlimit の空集合を、何も適用する前に拒否する（未適用の一覧へ載らないまま省かれる経路を塞ぐ。#1460）。
    if mode == ReapplyMode::Complete {
        require_rlimits(&rlimits)?;
    }
    // 本番は launch 時の識別子の無い再適用を、何も適用する前に拒否する（照合を省く経路を残さない。SEC-1・SEC-4・#3201）。
    if mode == ReapplyMode::Complete && mounts.is_none() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Landlock,
            "exec restrictions have no recorded mount identities; refusing to reapply",
        ));
    }
    verify_target_binding(&binding)?;
    let root = open_verified_root(expected_root)?;
    // 本番は listener の送信口が無い再適用を、何も適用する前に拒否する（受け渡しを省く経路を残さない。SEC-4・#2385）。
    // 束縛・`/` の照合より後に置き、それらの違反の検出（違反記録つきの拒否）を先取りしない。
    if mode == ReapplyMode::Complete && seccomp_listener.is_none() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "exec restrictions have no seccomp listener channel; refusing to reapply",
        ));
    }
    // 観測用の空集合では syscall を呼ばず、下で未適用の一覧へ `Rlimits` を載せる。通常は全 16 種が入る。
    let rlimits_skipped = rlimits.is_empty();
    // `RLIMIT_FSIZE` だけは子へ持ち越す（封印した複製の書き込みを妨げない。#1531）。実効値は子が複製の完成後・
    // `execveat` の前に適用し、読み戻して確認する。件数は適用済み（`rlimits_applied`）と持ち越し
    // （`rlimits_deferred`）に分けて報告する。
    let (immediate, deferred_fsize) = split_deferred_fsize(&rlimits)?;
    if !rlimits_skipped {
        apply_rlimits(&immediate).map_err(|e| e.at_stage(IsolationStage::Rlimits))?;
        // 複製の期間に必要な soft・hard を、`CAP_SYS_RESOURCE` を落とす前の今ここで確保する。子が複製の後に
        // 適用する値は引き下げだけになり、特権を要さない（#1531）。
        if let Some(fsize) = &deferred_fsize {
            widen_fsize_for_copy(fsize).map_err(|e| e.at_stage(IsolationStage::Rlimits))?;
        }
    }
    // capability 削減は、先頭で補助グループも空にする（launch 経路と同じ関数。#1457）。
    let capabilities = if drop_capabilities {
        Some(
            apply_default_capabilities_with(
                &mut threads,
                Some(binding.proc_dir.as_fd()),
                ids,
                &groups,
                allowed_capabilities,
            )
            .map_err(|e| e.at_stage(IsolationStage::CapabilityDrop))?,
        )
    } else {
        None
    };
    let capability_bounding_dropped = capabilities
        .as_ref()
        .map_or(0, |report| report.bounding_dropped.len());
    let supplementary_groups = combine_group_outcomes(
        groups_before_join,
        capabilities
            .as_ref()
            .map(|report| report.supplementary_groups),
    );
    no_new_privs::apply_no_new_privs()?;
    let landlock = apply_landlock_stage_with(
        &landlock,
        &mut threads,
        root.as_fd(),
        binding.proc_dir.as_fd(),
        mounts.as_ref(),
    )
    .map_err(|e| e.at_stage(IsolationStage::Landlock))?;
    let seccomp = match seccomp_listener {
        Some(sender) => {
            let (sender, ack_timeout) = sender.into_parts();
            apply_default_seccomp_with_listener_threads(sender, ack_timeout, &mut threads)
        }
        None => apply_default_seccomp_with(&mut threads),
    }
    .map_err(|e| e.at_stage(IsolationStage::Seccomp))?;
    Ok(ExecRestrictionReport {
        landlock_rules: landlock.rules_added,
        seccomp_instructions: seccomp.instructions,
        rlimits_applied: if rlimits_skipped { 0 } else { immediate.len() },
        rlimits_deferred: usize::from(deferred_fsize.is_some()),
        capability_bounding_dropped,
        supplementary_groups,
        // launch 経路の段の順（`Rlimits` → `CapabilityDrop`）で並べる。
        unapplied: match (rlimits_skipped, drop_capabilities) {
            (false, true) => ExecRestrictionReport::UNAPPLIED,
            (false, false) => &[UnappliedExecRestriction::CapabilityDrop],
            (true, true) => &[UnappliedExecRestriction::Rlimits],
            (true, false) => &[
                UnappliedExecRestriction::Rlimits,
                UnappliedExecRestriction::CapabilityDrop,
            ],
        },
        carry: ExecCarry {
            root,
            threads,
            owner_pid,
            deferred_fsize,
            seal_policy,
        },
    })
}

/// `rlimits` を「いま適用する集合」と「子へ持ち越す `RLIMIT_FSIZE`」に分ける（#1531）。
fn split_deferred_fsize(rlimits: &Rlimits) -> Result<(Rlimits, Option<Rlimit>), ExecError> {
    let deferred = rlimits
        .iter()
        .find(|r| r.kind() == RlimitKind::Fsize)
        .copied();
    let rest = rlimits
        .iter()
        .filter(|r| r.kind() != RlimitKind::Fsize)
        .copied()
        .collect();
    let rest = Rlimits::new(rest).map_err(|_| {
        ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Rlimits,
            "failed to split the rlimits",
        )
    })?;
    Ok((rest, deferred))
}

/// [`observe_exec_restriction_reapply`] の観測結果。errno は成功を `None`、失敗を `Some(errno)`（不明は `-1`）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
#[derive(Debug)]
#[non_exhaustive]
pub struct ExecReapplyObservation {
    /// 準備（ABI 検出・ルール生成）の失敗。`Some` なら適用もプローブもしていない（fail-closed）。
    pub prepare_error: Option<ExecError>,
    /// 再適用の失敗。`Some` ならプローブはしていない（exec 拒否に相当）。
    pub reapply_error: Option<ExecError>,
    /// 再適用の成功結果。
    pub report: Option<ExecRestrictionReport>,
    /// 適用前の `/proc/thread-self/status` の `Seccomp:` 値（無制限は `0`）。
    pub seccomp_before: String,
    /// 適用前の `NoNewPrivs:` 値（準備失敗時に「変わっていない」ことを照合する基準）。
    pub no_new_privs_before: String,
    /// 試行後の `Seccomp:` 値（適用に成功すれば filter モードの `2`）。
    pub seccomp_after: String,
    /// 試行後の `NoNewPrivs:` 値（適用に成功すれば `1`）。
    pub no_new_privs_after: String,
    /// 適用前の `kcmp(自 pid, 自 pid, KCMP_VM)`（対照。通常は成功し `None`。外側の seccomp が `kcmp` を拒否する環境では `EPERM` になり対照として働かないため、試験は前提欠如として失敗させる。ESC-06・#2006）。
    pub kcmp_before: Option<i32>,
    /// 適用後の `kcmp`（`ERRNO(EPERM)` の禁止 syscall のため `EPERM`）。適用に失敗した場合は `None`。
    ///
    /// `unshare` は `KILL_PROCESS` で戻らず errno を観測できないため、識別には `kcmp` を使う（#1834）。
    pub kcmp_after: Option<i32>,
    /// Landlock プローブ結果（入力順）。再適用に成功した場合のみ入る。
    pub results: Vec<(LandlockAccessProbe, Option<i32>)>,
}

/// 観測 1 回で試せるプローブ数の上限（`exec/landlock.rs` と同じ固定リスト前提の防御）。
#[cfg(feature = "exec-test-support")]
const MAX_REAPPLY_PROBES: usize = 32;

/// 本番の準備・再適用の経路をそのまま通し、seccomp と Landlock の遮断を観測する
/// （SUP-6・TASK-163.3・#502・CORE-5。結合試験専用）。
///
/// 結合試験 `tests/exec_restrictions_reapply.rs` の使い捨て子プロセス（単一スレッドの `main`）専用で、
/// 通常の利用者は呼ばない。`setns` は行わないため、「コンテナの rootfs」の代わりに呼び出し側が渡す
/// `expected_root`（ディレクトリ）を照合の基準にする: `/` を渡せば照合が通り、Landlock のルールパスは
/// 呼び出しプロセスの `/` に対して解決される。`/` 以外を渡せば、参加後の `/` が rootfs でない場合と同じ
/// 拒否（違反記録 `exec_root_not_container_rootfs`。何も適用しない）を観測できる。本番の入口
/// [`prepare_exec_restrictions`] が行う「rootfs が自分の `/` でないこと」の検査だけは通さない。
/// 準備・再適用のいずれかが失敗したらプローブは実行しない。`unsafe` は追加せず、syscall は既存の
/// `crate::sys` ラッパーに限る。対象への束縛は自プロセスの mount namespace に対して行うため常に一致し、
/// rlimit は変更しない（空集合）。`CAP_SETPCAP` を持たない非特権の子でも観測できるよう capability 削減は
/// 省き、結果の未適用の一覧に `Rlimits` と `CapabilityDrop` が残る（省いたものを適用済みと装わない。本番の
/// 入口は rlimit の空集合を拒否する。#1460。capability 削減の実機確認は supervisor の
/// `tests/exec.rs`）。
///
/// `setns` を伴う通し確認は `fandhe-container-supervisor` の `tests/exec.rs`（TASK-163.4・#503）が行う。
///
/// `exec-test-support` feature を付けたビルドにだけ存在し、既定のビルド（リリース成果物を含む）の公開 API には
/// 含まれない（TASK-163 追補・#1460。core 自身のテストでは dev-dependency の自己参照で有効になる）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn observe_exec_restriction_reapply(
    config: &OciConfig,
    expected_root: &Path,
    probes: &[LandlockAccessProbe],
) -> Result<ExecReapplyObservation, ExecError> {
    observe_reapply_inner(config, expected_root, probes, None)
}

/// 観測用の launch 時の識別子の記録の作り方（SEC-1・SEC-4・#3201。結合試験専用）。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedMountRecording {
    /// 適用の直前に開いた対象の実際の識別子をそのまま記録する（launch が記録した値を読み戻した正常系）。
    Faithful,
    /// 記録した `mnt_id` を 1 ずらす（マウントの差し替え・overmount で `mnt_id` が変わった状態の再現）。
    MountIdShifted,
}

/// [`observe_exec_restriction_reapply`] に、Mount 由来のルールの識別子つきの記録で `MountCheck::Recorded` の
/// 照合を通させる版（SEC-1・SEC-4・#3201。結合試験専用）。
///
/// 記録は launch の代わりに、`config` から導いた ruleset の Mount 由来のルール（暗黙の `/dev` 系）の対象を
/// 自プロセスの `/` から開いて読んだ `(mnt_id, st_dev, st_ino)` で作り、`state.json` と同じ
/// [`LaunchIsolationRecord`] へ添えて本番の `recorded_mounts_for_exec` を通す。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn observe_exec_restriction_reapply_recorded(
    config: &OciConfig,
    expected_root: &Path,
    probes: &[LandlockAccessProbe],
    recording: ObservedMountRecording,
) -> Result<ExecReapplyObservation, ExecError> {
    observe_reapply_inner(config, expected_root, probes, Some(recording))
}

/// Mount 由来のルールの識別子を、対象を開いて読んだ値で作る（観測用）。
#[cfg(feature = "exec-test-support")]
fn observed_mount_identities(
    ruleset: &LandlockRuleset,
    launch: LaunchIsolationRecord,
    recording: ObservedMountRecording,
) -> Result<LaunchIsolationRecord, ExecError> {
    use crate::launch_isolation::RecordedMountIdentity;
    use std::os::unix::fs::MetadataExt as _;
    let internal = |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, m);
    let mut entries = Vec::new();
    for i in launch.landlock().mount_rule_positions() {
        let rule = ruleset
            .rules()
            .get(i)
            .ok_or_else(|| internal("mount rule position out of range"))?;
        let file = std::fs::File::open(rule.path.as_str())
            .map_err(|_| internal("cannot open mount rule target"))?;
        let meta = file
            .metadata()
            .map_err(|_| internal("cannot stat mount rule target"))?;
        let fd = OwnedFd::from(file);
        let mnt_id = crate::oci_runtime::mountinfo_identity::read_fd_mnt_id(fd.as_fd())
            .map_err(|_| internal("cannot read mount id"))?;
        let mnt_id = match recording {
            ObservedMountRecording::Faithful => mnt_id,
            ObservedMountRecording::MountIdShifted => mnt_id.saturating_add(1),
        };
        let id = RecordedMountIdentity::new(mnt_id, meta.dev(), meta.ino(), false)
            .map_err(|_| internal("invalid mount identity"))?;
        entries.push((i, id));
    }
    launch
        .with_mount_identities(entries)
        .map_err(|e| internal(e.message()))
}

#[cfg(feature = "exec-test-support")]
fn observe_reapply_inner(
    config: &OciConfig,
    expected_root: &Path,
    probes: &[LandlockAccessProbe],
    recording: Option<ObservedMountRecording>,
) -> Result<ExecReapplyObservation, ExecError> {
    let internal = |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Validate, m);
    if probes.len() > MAX_REAPPLY_PROBES {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Landlock,
            "too many access probes",
        ));
    }
    let seccomp_before = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    let no_new_privs_before =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    let kcmp_before = errno_of(sys::kcmp_self_probe());
    let mut obs = ExecReapplyObservation {
        prepare_error: None,
        reapply_error: None,
        report: None,
        seccomp_before,
        no_new_privs_before,
        seccomp_after: String::new(),
        no_new_privs_after: String::new(),
        kcmp_before,
        kcmp_after: None,
        results: Vec::new(),
    };
    let expected = OwnedFd::from(
        std::fs::File::open(expected_root).map_err(|_| internal("cannot open expected root"))?,
    );
    let expected_identity = RootIdentity::of_dir_fd(expected.as_fd())
        .ok_or_else(|| internal("expected root is not a directory"))?;
    // `setns` をしないため、対象の mount namespace は自分自身（束縛は常に一致する）。rlimit は変えない。
    let proc_dir = open_own_proc_dir().map_err(|_| internal("cannot open own procfs directory"))?;
    let target_user_ns = current_user_ns_identity(proc_dir.as_fd())
        .map_err(|_| internal("cannot read own user namespace"))?;
    let target_mnt_ns = current_mnt_ns_identity(proc_dir.as_fd())
        .map_err(|_| internal("cannot read own mount namespace"))?;
    let target_pid_ns = current_pid_ns_for_children_identity(proc_dir.as_fd())
        .map_err(|_| internal("cannot read own PID namespace"))?;
    let expected_cgroup =
        own_cgroup_path(proc_dir.as_fd()).map_err(|_| internal("cannot read own cgroup"))?;
    let binding = TargetBinding {
        proc_dir,
        target_user_ns,
        target_mnt_ns,
        target_pid_ns,
        expected_cgroup,
    };
    // 観測では `config` から導いた ruleset と `expected_root` の識別子で記録を作る（launch の代わり）。
    let prepared = super::landlock::landlock_ruleset_from_config(config).and_then(|ruleset| {
        let launch = LaunchIsolationRecord::new(expected_identity, &ruleset).map_err(|e| {
            ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, e.message())
        })?;
        let launch = match recording {
            Some(r) => observed_mount_identities(&ruleset, launch, r)?,
            None => launch,
        };
        let mut restrictions =
            prepare_with_launch(&launch, expected_identity, Rlimits::default(), binding)?;
        if recording.is_some() {
            restrictions.mounts = Some(recorded_mounts_for_exec(&launch)?);
        }
        Ok(restrictions)
    });
    match prepared {
        Err(e) => obs.prepare_error = Some(e),
        Ok(prepared) => {
            match reapply_inner(prepared, ReapplyMode::ObservationWithoutCapabilityDrop) {
                Ok(report) => obs.report = Some(report),
                Err(e) => obs.reapply_error = Some(e),
            }
        }
    }
    obs.seccomp_after = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    obs.no_new_privs_after =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    if obs.report.is_some() {
        obs.kcmp_after = errno_of(sys::kcmp_self_probe());
        for p in probes {
            obs.results.push((p.clone(), run_probe(p)));
        }
    }
    Ok(obs)
}

#[cfg(feature = "exec-test-support")]
fn errno_of(r: Result<(), sys::SysError>) -> Option<i32> {
    match r {
        Ok(()) => None,
        Err(sys::SysError::Os(n)) => Some(n),
        Err(_) => Some(-1),
    }
}

/// `/proc/thread-self/status` の指定フィールド値（前後の空白は除く）。
#[cfg(feature = "exec-test-support")]
fn status_field(name: &str) -> Option<String> {
    let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(|v| v.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::no_new_privs::testing::{fake, take};
    use crate::sys::SysError;

    fn dir_fd(path: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(path).expect("open dir"))
    }

    /// 照合の基準を自プロセスの `/` にした材料（単体テストは `setns` をしないため照合が通る）。
    fn restrictions(owner_pid: u32) -> ExecRestrictions {
        restrictions_rooted_at(owner_pid, Path::new("/"))
    }

    fn identity_of(path: &Path) -> RootIdentity {
        RootIdentity::of_dir_fd(dir_fd(path).as_fd()).expect("directory identity")
    }

    fn restrictions_rooted_at(owner_pid: u32, rootfs: &Path) -> ExecRestrictions {
        ExecRestrictions {
            landlock: LandlockRuleset::for_observation(6, Vec::new()),
            threads: ThreadCountSource::ProcSelf,
            owner_pid,
            root: identity_of(rootfs),
            rlimits: full_rlimits(),
            binding: own_binding(),
            groups_before_join: None,
            ids: None,
            groups: NormalizedGroups::empty(),
            seal_policy: SealPolicy::unrestricted(),
            seccomp_listener: Some(test_listener_sender()),
            capabilities: ContainerCapabilities::oci_default(),
            mounts: Some(MountedTargets::new()),
        }
    }

    /// 単体テスト用の送り手（親の端は直ちに閉じる。偽の seccomp は送り手を使わない）。
    fn test_listener_sender() -> ExecListenerSender {
        let (_receiver, child_end) = crate::exec::seccomp_listener::exec_listener_pair().unwrap();
        crate::exec::seccomp_listener::exec_sender_from(
            child_end,
            crate::seccomp::ErrnoDelivery::Errno,
        )
    }

    /// 対象の mount namespace を自分自身にした束縛（単体テストは `setns` をしないため照合が通る）。
    fn own_binding() -> TargetBinding {
        let proc_dir = open_own_proc_dir().expect("own procfs dir");
        let target_user_ns = current_user_ns_identity(proc_dir.as_fd()).expect("own user ns");
        let target_mnt_ns = current_mnt_ns_identity(proc_dir.as_fd()).expect("own mnt ns");
        let target_pid_ns =
            current_pid_ns_for_children_identity(proc_dir.as_fd()).expect("own pid ns");
        let expected_cgroup = own_cgroup_path(proc_dir.as_fd()).expect("own cgroup");
        TargetBinding {
            proc_dir,
            target_user_ns,
            target_mnt_ns,
            target_pid_ns,
            expected_cgroup,
        }
    }

    /// 偽の呼び出し記録を取り出し、連続する `rlimits`（種別ごとに 1 回ずつ記録される）を 1 つにまとめる。
    /// 段の順序の照合用（rlimit の個別の値は `take_sets` で照合する）。
    fn taken() -> Vec<&'static str> {
        let mut v = take();
        v.dedup();
        v
    }

    /// 適用の呼び出し順を確かめるための全 16 種の rlimit 集合（偽の `prlimit` が記録する）。
    /// 値は種別の添字から決める具体値で、`Nofile` だけ (256, 512)、`Fsize` は (4096, 4096)。
    fn full_rlimits() -> Rlimits {
        Rlimits::new(
            RlimitKind::ALL
                .into_iter()
                .enumerate()
                .map(|(i, k)| {
                    let (soft, hard) = match k {
                        RlimitKind::Nofile => (256, 512),
                        RlimitKind::Fsize => (4096, 4096),
                        _ => (i as u64, 100 + i as u64),
                    };
                    Rlimit::new(k, soft, hard).expect("rlimit")
                })
                .collect(),
        )
        .expect("set")
    }

    /// 持ち越し材料つきの結果（`unapplied` を差し替えて `into_complete` の分岐を試す）。
    fn report_with(unapplied: &'static [UnappliedExecRestriction]) -> ExecRestrictionReport {
        ExecRestrictionReport {
            landlock_rules: 1,
            seccomp_instructions: 2,
            rlimits_applied: 3,
            rlimits_deferred: 0,
            capability_bounding_dropped: 4,
            supplementary_groups: Some(SupplementaryGroups::AlreadyEmpty),
            unapplied,
            carry: ExecCarry {
                root: dir_fd(Path::new("/")),
                threads: ThreadCountSource::ProcSelf,
                owner_pid: std::process::id(),
                deferred_fsize: None,
                seal_policy: SealPolicy::unrestricted(),
            },
        }
    }

    /// 使い捨ての空ディレクトリ（`/` とは別の inode）。
    fn temp_dir(label: &str) -> (crate::scratch_root::ScratchDir, std::path::PathBuf) {
        // pid＋nanos の名前を create_dir_all せず、排他作成の ScratchDir の子を使う（#3478・REPAIR-12）。
        crate::test_support::scratch_child(&format!("fandhe-reapply-{label}"), "d")
    }

    fn err(code: ErrorCode, stage: IsolationStage) -> ExecError {
        ExecError::new(code, stage, "fake")
    }

    /// SUP-12・SEC-1・#1531: `RLIMIT_FSIZE` は exec プロセスには対象の値を載せず子へ持ち越し、報告では適用済み
    /// （`rlimits_applied`）と持ち越し（`rlimits_deferred`）を分ける。持ち越しを含めて完了扱いで `ExecReady` になり、
    /// 持ち越した値は `ExecReady` の持ち越し材料に載る。
    #[test]
    fn sup12_deferred_fsize_is_reported_separately_from_applied_rlimits() {
        let _ = take();
        let r = restrictions(std::process::id());
        let report = reapply_restrictions(r).expect("ok");
        assert_eq!(
            (report.rlimits_applied(), report.rlimits_deferred()),
            (15, 1)
        );
        assert!(report.is_complete());
        let carry = report.into_complete().expect("ready").into_parts();
        assert_eq!(
            carry.deferred_fsize,
            Some(Rlimit::new(RlimitKind::Fsize, 4096, 4096).expect("fsize"))
        );
    }

    /// SUP-6・TASK-163.4: 適用順は rlimit → capability 削減 → NO_NEW_PRIVS → Landlock → seccomp で固定
    /// （launch 経路の `StageKind::ORDER` の相対順）。成功すれば未適用は空で `ExecReady` に変えられる。
    #[test]
    fn sup6_task163_4_reapply_order_is_rlimits_caps_nnp_landlock_seccomp() {
        let _ = take();
        let report = reapply_restrictions(restrictions(std::process::id())).expect("ok");
        assert_eq!(
            taken(),
            vec![
                "rlimits",
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp"
            ]
        );
        assert_eq!(report.landlock_rules(), 0);
        assert_eq!(report.seccomp_instructions(), 0);
        assert_eq!(report.rlimits_applied(), 15);
        assert_eq!(report.rlimits_deferred(), 1);
        // #1467: 偽の `prlimit` へは記録の全 16 種が、値・件数とも記録どおりに渡る（Fsize は持ち越し）。
        let sets = crate::exec::rlimits::testing::take_sets();
        let (fsize, others): (Vec<_>, Vec<_>) = sets
            .into_iter()
            .partition(|(k, _, _)| *k == RlimitKind::Fsize);
        let want: Vec<_> = full_rlimits()
            .iter()
            .filter(|r| r.kind() != RlimitKind::Fsize)
            .map(|r| (r.kind(), r.soft(), r.hard()))
            .collect();
        assert_eq!(others.len(), 15);
        assert_eq!(others, want);
        // 持ち越した Fsize は exec プロセスでは広げるだけ（封印した複製の書き込みのため。#1531）で、記録の値は載せない。
        assert_eq!(
            fsize,
            [(
                RlimitKind::Fsize,
                crate::rlimits::RLIMIT_INFINITY,
                crate::rlimits::RLIMIT_INFINITY
            )]
        );
        // TASK-163 追補（#1457）: capability 削減が補助グループの扱いも済ませ、結果に載る（偽のカーネルは空）。
        assert_eq!(
            report.supplementary_groups(),
            Some(SupplementaryGroups::AlreadyEmpty)
        );
        // SEC-1: TASK-163.4 で capability 削減・rlimit を実装し、未適用の一覧は空になった。
        assert_eq!(report.unapplied(), ExecRestrictionReport::UNAPPLIED);
        assert!(report.unapplied().is_empty());
        assert!(report.is_complete());
        let ready = report.into_complete().expect("ready to exec");
        // `Debug` は fd を出さず、適用したプロセスの pid だけを示す。
        assert_eq!(
            format!("{ready:?}"),
            format!(
                "ExecReady {{ carry: ExecCarry {{ owner_pid: {}, .. }} }}",
                std::process::id()
            )
        );
    }

    /// SUP-6・SEC-1・TASK-163.4: 再適用の適用順は、launch 経路の順序表（`StageKind::ORDER`）から cgroup 参加
    /// （exec では `join_cgroup` が再適用の前に済ませる）を除いた並びと一致する。launch 側で段の追加・順序の
    /// 変更があれば、網羅 `match` のコンパイルエラーかこのテストの失敗として検出する（exec だけ別の順序・
    /// 別の内容で動く状態を作らない）。
    #[test]
    fn sup6_task163_4_reapply_order_follows_launch_stage_order() {
        let recorded_name = |kind: StageKind| match kind {
            StageKind::CgroupJoin => None,
            StageKind::Rlimits => Some("rlimits"),
            StageKind::CapabilityDrop => Some("capability_drop"),
            StageKind::NoNewPrivs => Some("no_new_privs"),
            StageKind::Landlock => Some("landlock"),
            StageKind::Seccomp => Some("seccomp"),
        };
        let expected: Vec<&str> = StageKind::ORDER
            .into_iter()
            .filter_map(recorded_name)
            .collect();
        assert_eq!(StageKind::ORDER.first(), Some(&StageKind::CgroupJoin));
        let _ = take();
        let report = reapply_restrictions(restrictions(std::process::id())).expect("ok");
        assert_eq!(taken(), expected);
        assert!(report.into_complete().is_ok());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・SEC-5・TASK-163 追補（#1457）: 参加前に補助グループを消去していれば、参加後の capability 削減が
    /// 「元から空」でも結果は「消去した」と件数を残す。それ以外は参加後の最終状態を報告する（参加前に消せず
    /// 参加後も残った場合は「残した」、参加前の消去をしていない経路は参加後の結果そのまま）。
    #[test]
    fn sup6_sec1_task163_group_outcomes_before_and_after_join_are_combined() {
        use SupplementaryGroups::{AlreadyEmpty, Cleared, KeptSetgroupsDenied};
        let cleared = Cleared { cleared: 3 };
        let kept = KeptSetgroupsDenied { kept: 3 };
        for (before, after, want) in [
            (Some(cleared), Some(AlreadyEmpty), Some(cleared)),
            (Some(AlreadyEmpty), Some(AlreadyEmpty), Some(AlreadyEmpty)),
            (Some(kept), Some(kept), Some(kept)),
            (Some(kept), Some(Cleared { cleared: 3 }), Some(cleared)),
            (None, Some(cleared), Some(cleared)),
            (None, Some(AlreadyEmpty), Some(AlreadyEmpty)),
            (Some(cleared), None, None),
            (None, None, None),
        ] {
            assert_eq!(
                combine_group_outcomes(before, after),
                want,
                "{before:?} {after:?}"
            );
        }

        // 通しでも、参加前に消去した結果が報告へ残る（偽のカーネル。参加後は元から空）。
        let _ = take();
        let mut r = restrictions(std::process::id());
        crate::exec::capabilities::testing::fake_groups_before_join(4);
        r.groups_before_join = match clear_supplementary_groups_before_join(
            &mut r.threads,
            r.binding.proc_dir.as_fd(),
            false,
        )
        .expect("clear before join")
        {
            PreJoinGroups::Done(groups) => Some(groups),
            PreJoinGroups::DeferredUntilJoin => None,
        };
        assert_eq!(r.groups_before_join, Some(Cleared { cleared: 4 }));
        let report = reapply_restrictions(r).expect("ok");
        assert_eq!(report.supplementary_groups(), Some(Cleared { cleared: 4 }));
        assert_eq!(
            taken(),
            vec![
                "setgroups_before_join",
                "rlimits",
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp"
            ]
        );
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・REPAIR-3・TASK-163 追補（#1460）: 本番の入口は rlimit の空集合を、何も適用する前に
    /// `FailedPrecondition`（段 `Rlimits`）で拒否する（適用を省いたまま未適用の一覧へ載らない経路を塞ぐ）。
    #[test]
    fn sup6_sec1_task163_empty_rlimits_are_rejected_before_applying_anything() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        r.rlimits = Rlimits::default();
        let e = reapply_restrictions(r).unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Rlimits)
        );
        assert_eq!(
            e.message,
            "the rlimits of the exec target are incomplete; refusing to exec without all rlimits"
        );
        assert_eq!(e.violation, None);
        assert_eq!(taken(), Vec::<&str>::new());
        assert_eq!(
            require_rlimits(&Rlimits::default()).unwrap_err().stage,
            IsolationStage::Rlimits
        );
        // 15 種（1 種欠け）も、何も適用する前に拒否する（#1467）。
        let fifteen = Rlimits::new(full_rlimits().iter().skip(1).copied().collect()).expect("set");
        assert_eq!(fifteen.len(), 15);
        let mut r = restrictions(std::process::id());
        r.rlimits = fifteen.clone();
        let e = reapply_restrictions(r).unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Rlimits)
        );
        assert_eq!(taken(), Vec::<&str>::new());
        assert!(require_rlimits(&fifteen).is_err());
        require_rlimits(&full_rlimits()).unwrap();
    }

    /// SUP-6・SEC-1・REPAIR-3・TASK-163 追補（#1460）: 観測用の経路は rlimit の空集合と capability 削減の省略を
    /// 許すが、省いた制限を launch の段の順で未適用の一覧へ載せ、`ExecReady` を作らせない（完了を装わない）。
    #[test]
    fn sup6_sec1_task163_observation_lists_every_skipped_restriction() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        r.rlimits = Rlimits::default();
        let report =
            reapply_inner(r, ReapplyMode::ObservationWithoutCapabilityDrop).expect("observation");
        assert_eq!(taken(), vec!["no_new_privs", "landlock", "seccomp"]);
        assert_eq!(report.rlimits_applied(), 0);
        assert_eq!(report.supplementary_groups(), None);
        assert_eq!(
            report.unapplied(),
            [
                UnappliedExecRestriction::Rlimits,
                UnappliedExecRestriction::CapabilityDrop
            ]
        );
        assert!(!report.is_complete());
        let e = report.into_complete().unwrap_err();
        assert_eq!(
            e.message,
            "exec restrictions are incomplete; not applied: rlimits, capability_drop"
        );

        // rlimit を持つ観測は、capability 削減だけが未適用として残る。
        let report = reapply_inner(
            restrictions(std::process::id()),
            ReapplyMode::ObservationWithoutCapabilityDrop,
        )
        .expect("observation");
        assert_eq!(
            taken(),
            vec!["rlimits", "no_new_privs", "landlock", "seccomp"]
        );
        let _ = crate::exec::rlimits::testing::take_sets();
        assert_eq!(
            report.unapplied(),
            [UnappliedExecRestriction::CapabilityDrop]
        );
    }

    /// SUP-6・SEC-1・TASK-163.4: rlimit の適用失敗（hard の引き上げ不可等）で、以降の段を呼ばない（段は
    /// `Rlimits`）。黙って緩い制限のまま進まない。
    #[test]
    fn sup6_task163_4_rlimit_failure_stops_before_capability_drop() {
        let _ = take();
        crate::exec::rlimits::testing::fake(Err(SysError::Os(crate::sys::EPERM)), None);
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("rlimit");
        assert_eq!(e.stage, IsolationStage::Rlimits);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(taken(), vec!["rlimits"]);
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・TASK-163.4: capability 削減の失敗で、NO_NEW_PRIVS 以降を呼ばない（段は `CapabilityDrop`）。
    #[test]
    fn sup6_task163_4_capability_failure_stops_before_nnp() {
        let _ = take();
        crate::exec::capabilities::testing::fake_capability_drop_err(SysError::Os(
            crate::sys::EPERM,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("capability");
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(taken(), vec!["rlimits", "capability_drop"]);
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SEC-4・SUP-6（#2385）: 本番の再適用で listener の送信口が無ければ、何も適用せず `FailedPrecondition`
    /// （段 `Validate`）で拒否する（受け渡しを省く経路を残さない）。
    #[test]
    fn sec4_sup6_2385_complete_reapply_without_listener_channel_applies_nothing() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        r.seccomp_listener = None;
        let e = reapply_restrictions(r).expect_err("no channel");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Validate);
        assert_eq!(
            e.message,
            "exec restrictions have no seccomp listener channel; refusing to reapply"
        );
        assert!(e.violation.is_none());
        assert_eq!(taken(), Vec::<&str>::new());
    }

    /// SEC-4・SUP-6（#2385）: 送り手が無くても、束縛の不一致は従来どおりの違反として拒否される
    /// （送り手の検査が束縛・`/` の照合を先取りしない）。
    #[test]
    fn sec4_sup6_2385_binding_violation_is_not_masked_by_missing_listener_channel() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        r.seccomp_listener = None;
        let (dev, ino) = r.binding.target_mnt_ns;
        r.binding.target_mnt_ns = (dev, ino.wrapping_add(1));
        let e = reapply_restrictions(r).expect_err("other target");
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.violation.expect("violation").reason,
            ViolationReason::ExecJoinedNamespaceMismatch
        );
        assert_eq!(taken(), Vec::<&str>::new());
    }

    /// SEC-4・SUP-6（#2385）: 送り手を付けても段の順は変わらない。seccomp の失敗は段 `Seccomp`・code を保つ。
    #[test]
    fn sec4_sup6_2385_listener_channel_keeps_stage_order_and_seccomp_failure_code() {
        let _ = take();
        let _report = reapply_restrictions(restrictions(std::process::id())).expect("ok");
        assert_eq!(
            taken(),
            vec![
                "rlimits",
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp"
            ]
        );
        let _ = crate::exec::rlimits::testing::take_sets();
        let _ = take();
        crate::exec::seccomp::testing::fake_seccomp_err(err(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("seccomp");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Seccomp);
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.4: 参加後の mount namespace が準備時に記録した対象のものと違えば、何も
    /// 適用せず違反記録つきの `FailedPrecondition`（理由 `exec_joined_namespace_mismatch`・段 `SetNs`）。
    /// 同じ rootfs を共有する別コンテナへ参加した場合を想定し、`/` の照合には到達しない（束縛が先）。
    #[test]
    fn sup6_task163_4_other_target_namespace_applies_nothing() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        let (dev, ino) = r.binding.target_mnt_ns;
        r.binding.target_mnt_ns = (dev, ino.wrapping_add(1));
        let e = reapply_restrictions(r).expect_err("other target");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the user or mount namespace after joining is not the one of the prepared exec target"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecJoinedNamespaceMismatch);
        assert_eq!(v.reason.as_str(), "exec_joined_namespace_mismatch");
        assert_eq!(v.kind.as_str(), "exec_target");
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(taken(), Vec::<&str>::new());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.4: mount namespace が同じでも、参加後に子が入る PID namespace が準備時の
    /// 対象のものと違えば、何も適用せず違反記録つきで拒否する（`exec_joined_pid_namespace_mismatch`）。
    #[test]
    fn sup6_task163_4_other_pid_namespace_applies_nothing() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        let (dev, ino) = r.binding.target_pid_ns;
        r.binding.target_pid_ns = (dev, ino.wrapping_add(1));
        let e = reapply_restrictions(r).expect_err("other pid ns");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the PID namespace after joining is not the one of the prepared exec target"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecJoinedPidNamespaceMismatch);
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(taken(), Vec::<&str>::new());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-5・SEC-4・TASK-163.h2・#1462: 参加後の user namespace が準備時に記録した対象のものと違えば
    /// （別の user namespace へ参加し損ねた・rootful が user namespace に入らずに参加した場合を想定）、何も適用せず
    /// 違反記録つきの `FailedPrecondition`（理由 `exec_joined_namespace_mismatch`・段 `SetNs`）。mount namespace の
    /// 照合より先に判定する（mount namespace も食い違わせて、user namespace の方で止まることを確かめる）。
    #[test]
    fn sup6_task163_h2_other_user_namespace_applies_nothing() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        let (dev, ino) = r.binding.target_user_ns;
        r.binding.target_user_ns = (dev, ino.wrapping_add(1));
        let (dev, ino) = r.binding.target_mnt_ns;
        r.binding.target_mnt_ns = (dev, ino.wrapping_add(1));
        let e = reapply_restrictions(r).expect_err("other user ns");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the user or mount namespace after joining is not the one of the prepared exec target"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecJoinedNamespaceMismatch);
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(taken(), Vec::<&str>::new());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: 参加前の補助グループの消去を参加後へ回してよいのは、別の user namespace
    /// （`Distinct`）で、呼び出し側の実効 uid が対象の実効 uid と一致するときだけ。同じ user namespace・uid 不一致・
    /// uid を読めない場合は回さない（fail-closed）。
    #[test]
    fn sup6_task163_h2_defer_group_clearing_truth_table() {
        let own: NsIdentity = (4, 10);
        let shared = UserNsRelation::Shared { identity: own };
        let distinct = UserNsRelation::Distinct {
            target: (4, 11),
            own,
            owner_uid: 1000,
        };
        assert!(!defer_group_clearing(&shared, Some(1000)));
        assert!(!defer_group_clearing(&shared, None));
        assert!(defer_group_clearing(&distinct, Some(1000)));
        assert!(!defer_group_clearing(&distinct, Some(0)));
        assert!(!defer_group_clearing(&distinct, Some(1001)));
        assert!(!defer_group_clearing(&distinct, None));
    }

    /// `process.user` を指定した最小の config（`exec_user_from_config` の入力）。
    fn config_with_user(user: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"mounts":[],
            "process":{{"terminal":false,"user":{user},"args":["/bin/true"],"cwd":"/"}}}}"#
        );
        crate::oci_runtime::parse_config_bytes(json.as_bytes()).expect("config")
    }

    /// 試験用: コンテナ内 0..65536 と 1000..1000+65536 を持つ（subuid 型の）対象の写像。
    fn range_maps(setgroups: &str) -> TargetIdMaps {
        TargetIdMaps::parse("0 100000 65536\n", "0 200000 65536\n", setgroups).expect("maps")
    }

    fn distinct() -> UserNsRelation {
        UserNsRelation::Distinct {
            target: (4, 11),
            own: (4, 10),
            owner_uid: 1000,
        }
    }

    fn shared() -> UserNsRelation {
        UserNsRelation::Shared { identity: (4, 10) }
    }

    /// SUP-6・SEC-5・CORE-6・#2770: `Shared`（本番では到達しない）は従来どおり root だけを受け、それ以外は
    /// `Unimplemented`。`process` の無い config は `InvalidArgument`。
    #[test]
    fn sup6_sec5_exec_user_shared_accepts_only_root() {
        let ok = exec_user_from_config(&config_with_user(r#"{"uid":0,"gid":0}"#), &shared(), None)
            .expect("root");
        assert_eq!(
            ok,
            ExecUser {
                ids: None,
                groups: NormalizedGroups::empty()
            }
        );
        for user in [
            r#"{"uid":1000,"gid":0}"#,
            r#"{"uid":0,"gid":100}"#,
            r#"{"uid":0,"gid":0,"additionalGids":[5]}"#,
        ] {
            let e = exec_user_from_config(&config_with_user(user), &shared(), None).unwrap_err();
            assert_eq!(
                (e.code, e.stage),
                (ErrorCode::Unimplemented, IsolationStage::Validate),
                "{user}"
            );
            assert_eq!(e.message, "process.user other than root is not supported");
            assert_eq!(e.violation, None);
        }
        let e = exec_user_from_config(&config(false, "[]"), &shared(), None).unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::InvalidArgument, IsolationStage::Validate)
        );
    }

    /// SUP-6・SEC-5・CORE-6・#2770: `Distinct` は写像の内側の非 root と `additionalGids` を受け、補助グループは
    /// 正規化（昇順・重複除去）して返す。範囲の端（先頭・末尾）も通る。root（0/0）は従来どおり ids=0/0・空。
    #[test]
    fn sup6_sec5_exec_user_distinct_accepts_mapped_ids_and_groups() {
        let maps = range_maps("allow\n");
        let u = exec_user_from_config(
            &config_with_user(r#"{"uid":1000,"gid":1000,"additionalGids":[3000,2000,3000]}"#),
            &distinct(),
            Some(&maps),
        )
        .expect("mapped");
        assert_eq!(
            u.ids,
            Some(ProcessIds {
                uid: 1000,
                gid: 1000
            })
        );
        assert_eq!(u.groups.as_slice(), &[2000, 3000]);
        let edge = exec_user_from_config(
            &config_with_user(r#"{"uid":65535,"gid":0,"additionalGids":[0,65535]}"#),
            &distinct(),
            Some(&maps),
        )
        .expect("edge");
        assert_eq!(edge.ids, Some(ProcessIds { uid: 65535, gid: 0 }));
        assert_eq!(edge.groups.as_slice(), &[0, 65535]);
        let root = exec_user_from_config(
            &config_with_user(r#"{"uid":0,"gid":0}"#),
            &distinct(),
            Some(&maps),
        )
        .expect("root");
        assert_eq!(root.ids, Some(ProcessIds { uid: 0, gid: 0 }));
        assert!(root.groups.is_empty());
    }

    /// SUP-6・SEC-5・CORE-6・#2770: 写像の外（末尾 + 1）の uid・gid・追加 gid は `InvalidArgument`（段 `Validate`）。
    /// `setgroups` が `deny` で追加グループが非空なら `FailedPrecondition`、空なら通る。値はメッセージに含めない。
    #[test]
    fn sup6_sec5_exec_user_distinct_rejects_unmapped_and_setgroups_deny() {
        let maps = range_maps("allow\n");
        for (user, msg) in [
            (
                r#"{"uid":65536,"gid":0}"#,
                "process.user is not mapped in the container user namespace (SEC-5)",
            ),
            (
                r#"{"uid":0,"gid":65536}"#,
                "process.user is not mapped in the container user namespace (SEC-5)",
            ),
            (
                r#"{"uid":0,"gid":0,"additionalGids":[5,65536]}"#,
                "process.user.additionalGids is not mapped in the container user namespace (SEC-5)",
            ),
        ] {
            let e = exec_user_from_config(&config_with_user(user), &distinct(), Some(&maps))
                .unwrap_err();
            assert_eq!(
                (e.code, e.stage),
                (ErrorCode::InvalidArgument, IsolationStage::Validate),
                "{user}"
            );
            assert_eq!(e.message, msg);
            assert_eq!(e.violation, None);
        }
        let denied = range_maps("deny\n");
        let e = exec_user_from_config(
            &config_with_user(r#"{"uid":1000,"gid":1000,"additionalGids":[5]}"#),
            &distinct(),
            Some(&denied),
        )
        .unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::FailedPrecondition, IsolationStage::Validate)
        );
        assert_eq!(
            e.message,
            "process.user.additionalGids requires setgroups to be allowed in the container user namespace (SEC-5)"
        );
        // 追加グループが空なら `deny` でも通る（補助グループは消去のまま。`KeptSetgroupsDenied` に逃がす指定ではない）。
        let ok = exec_user_from_config(
            &config_with_user(r#"{"uid":1000,"gid":1000}"#),
            &distinct(),
            Some(&denied),
        )
        .expect("deny + empty groups");
        assert!(ok.groups.is_empty());
        // 単一 ID 写像（"0 1000 1"）では 0 以外は写像の外。
        let single = TargetIdMaps::parse("0 1000 1\n", "0 1000 1\n", "deny\n").unwrap();
        let e = exec_user_from_config(
            &config_with_user(r#"{"uid":1000,"gid":1000}"#),
            &distinct(),
            Some(&single),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        // 写像が無い `Distinct` は内部エラー（fail-closed）。
        let e = exec_user_from_config(&config_with_user(r#"{"uid":0,"gid":0}"#), &distinct(), None)
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
    }

    /// SUP-6・SEC-5・#2770: 参加前の消去の結果が `Cleared`、参加後が `Applied` なら `Applied` を報告する。
    #[test]
    fn sup6_sec5_combine_group_outcomes_prefers_applied() {
        assert_eq!(
            combine_group_outcomes(
                Some(SupplementaryGroups::Cleared { cleared: 2 }),
                Some(SupplementaryGroups::Applied { count: 2 })
            ),
            Some(SupplementaryGroups::Applied { count: 2 })
        );
        assert_eq!(
            combine_group_outcomes(
                Some(SupplementaryGroups::Cleared { cleared: 2 }),
                Some(SupplementaryGroups::AlreadyEmpty)
            ),
            Some(SupplementaryGroups::Cleared { cleared: 2 })
        );
    }

    /// SUP-6・SEC-5・CORE-6・#2770: 準備で決めた補助グループは再適用で capability 段へ届き、結果は `Applied`。
    #[test]
    fn sup6_sec5_exec_groups_reach_capability_stage() {
        use crate::exec::capabilities::testing::take_groups_seen;
        let _ = take();
        let _ = take_groups_seen();
        let mut r = restrictions(std::process::id());
        r.ids = Some(ProcessIds {
            uid: 1000,
            gid: 1000,
        });
        r.groups = NormalizedGroups::new(&[3000, 2000]).unwrap();
        let report = reapply_restrictions(r).expect("ok");
        assert_eq!(take_groups_seen(), Some(vec![2000, 3000]));
        assert_eq!(
            report.supplementary_groups,
            Some(SupplementaryGroups::Applied { count: 2 })
        );
        let _ = take();
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-5・TASK-163.h2・#1462: 再適用は準備で決めた `ids` を capability 段へ渡す。別の user namespace へ
    /// 参加した場合（`Some`）は gid・uid の切り替えが載り、同じ user namespace（`None`）では渡さない。
    #[test]
    fn sup6_task163_h2_ids_reach_capability_stage_only_when_set() {
        use crate::exec::capabilities::testing::take_ids_seen;
        let _ = take();
        let _ = take_ids_seen();
        let mut r = restrictions(std::process::id());
        r.ids = Some(ProcessIds { uid: 0, gid: 0 });
        let _ = reapply_restrictions(r).expect("ok with ids");
        assert_eq!(take_ids_seen(), Some(Some(ProcessIds { uid: 0, gid: 0 })));
        let _ = take();
        let _ = reapply_restrictions(restrictions(std::process::id())).expect("ok without ids");
        assert_eq!(take_ids_seen(), Some(None));
        let _ = take();
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・SEC-5・TASK-163.h2・#1462: 参加前の消去を延期してよい場合（`EPERM` かつ `allow`）は、延期の
    /// 可否が下位の関数へ渡り、延期可なら `DeferredUntilJoin`（`groups_before_join` は `None` になり、参加後の結果が
    /// 報告に使われる）。延期不可なら従来どおり `PermissionDenied` で準備が失敗する。
    #[test]
    fn sup6_task163_h2_pre_join_group_clearing_can_be_deferred() {
        use crate::exec::capabilities::testing::{
            fake_groups_before_join, fake_groups_before_join_eperm_allow, take_defer_requested,
        };
        let _ = take();
        let mut r = restrictions(std::process::id());
        fake_groups_before_join(3);
        fake_groups_before_join_eperm_allow();
        let out = clear_supplementary_groups_before_join(
            &mut r.threads,
            r.binding.proc_dir.as_fd(),
            true,
        )
        .expect("deferred");
        assert_eq!(out, PreJoinGroups::DeferredUntilJoin);
        assert_eq!(take_defer_requested(), Some(true));
        fake_groups_before_join(3);
        fake_groups_before_join_eperm_allow();
        let e = clear_supplementary_groups_before_join(
            &mut r.threads,
            r.binding.proc_dir.as_fd(),
            false,
        )
        .unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::PermissionDenied, IsolationStage::CapabilityDrop)
        );
        assert_eq!(take_defer_requested(), Some(false));
        // 延期した場合、参加後の結果が報告に使われる。
        assert_eq!(
            combine_group_outcomes(
                None,
                Some(SupplementaryGroups::KeptSetgroupsDenied { kept: 3 })
            ),
            Some(SupplementaryGroups::KeptSetgroupsDenied { kept: 3 })
        );
        let _ = take();
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.4: mount・PID namespace が同じでも、参加後の所属 cgroup が準備時の対象の
    /// ものと違えば、何も適用せず違反記録つきで拒否する（`exec_joined_cgroup_mismatch`）。
    #[test]
    fn sup6_task163_4_other_cgroup_applies_nothing() {
        let _ = take();
        let mut r = restrictions(std::process::id());
        r.binding.expected_cgroup = "/other/container-cgroup".to_owned();
        let e = reapply_restrictions(r).expect_err("other cgroup");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the cgroup after joining is not the one of the prepared exec target"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecJoinedCgroupMismatch);
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(taken(), Vec::<&str>::new());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・TASK-163.4: 束縛の照合は `/` の照合より先（両方不一致なら束縛の違反を返す）。
    #[test]
    fn sup6_task163_4_binding_check_precedes_root_check() {
        let _ = take();
        let (_scratch, dir) = temp_dir("binding-first");
        let mut r = restrictions_rooted_at(std::process::id(), &dir);
        let (dev, ino) = r.binding.target_mnt_ns;
        r.binding.target_mnt_ns = (dev, ino.wrapping_add(1));
        let e = reapply_restrictions(r).expect_err("both mismatch");
        assert_eq!(
            e.violation.expect("violation").reason,
            ViolationReason::ExecJoinedNamespaceMismatch
        );
        assert_eq!(taken(), Vec::<&str>::new());
    }

    /// SUP-6・TASK-163.4: 自プロセスの mount namespace の識別子は、`/proc/self/ns/mnt` の `stat` と一致する
    /// （保持した procfs ディレクトリ経由の読み取りが、パス経由と同じ nsfs の inode を返す）。
    #[test]
    fn sup6_task163_4_current_mnt_ns_identity_matches_stat() {
        use std::os::unix::fs::MetadataExt as _;
        let proc_dir = open_own_proc_dir().expect("own procfs dir");
        let via_fd = current_mnt_ns_identity(proc_dir.as_fd()).expect("identity");
        let meta = std::fs::metadata("/proc/self/ns/mnt").expect("stat");
        assert_eq!(via_fd, (meta.dev(), meta.ino()));
    }

    /// SUP-6・SEC-1・TASK-163.3: `ExecReady` は未適用が空のときだけ作れる（空の一覧は crate 内でしか
    /// 組み立てられない。外部 crate から構築・書き換えできないことは型の doc の `compile_fail` で照合する）。
    /// 未適用が 1 つでも残れば `Err` で、名前を launch 経路の段の順に並べる。
    #[test]
    fn sup6_task163_3_exec_ready_requires_empty_unapplied() {
        assert!(report_with(&[]).is_complete());
        assert!(report_with(&[]).into_complete().is_ok());
        const RLIMITS: &[UnappliedExecRestriction] = &[UnappliedExecRestriction::Rlimits];
        const CAPS: &[UnappliedExecRestriction] = &[UnappliedExecRestriction::CapabilityDrop];
        for (unapplied, message) in [
            (
                RLIMITS,
                "exec restrictions are incomplete; not applied: rlimits",
            ),
            (
                CAPS,
                "exec restrictions are incomplete; not applied: capability_drop",
            ),
        ] {
            assert!(!report_with(unapplied).is_complete());
            let e = report_with(unapplied)
                .into_complete()
                .expect_err("incomplete");
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.message, message);
        }
        // TASK-163.4: 現在の実装が返す一覧は空（capability 削減・rlimit を適用するため）。
        assert!(
            report_with(ExecRestrictionReport::UNAPPLIED)
                .into_complete()
                .is_ok()
        );
    }

    /// SUP-6・SEC-1・TASK-163.3: 未適用の一覧は、launch 経路の段（`StageKind::ORDER`）から「exec 経路で
    /// 適用済みのもの」（cgroup 参加は `join_cgroup`、`NoNewPrivs`・`Landlock`・`Seccomp` は本モジュール）を
    /// 除いた残りと、順序を含めて一致する。launch 経路に段が増えたのに exec 側で適用も列挙もしていない
    /// 状態（黙って弱い制限で動く）を、このテストの失敗として検出する。
    #[test]
    fn sup6_task163_3_unapplied_matches_launch_stages_not_reapplied() {
        const APPLIED_ON_EXEC: [StageKind; 6] = [
            StageKind::CgroupJoin,
            StageKind::Rlimits,
            StageKind::CapabilityDrop,
            StageKind::NoNewPrivs,
            StageKind::Landlock,
            StageKind::Seccomp,
        ];
        let remaining: Vec<StageKind> = StageKind::ORDER
            .into_iter()
            .filter(|s| !APPLIED_ON_EXEC.contains(s))
            .collect();
        let unapplied: Vec<StageKind> = ExecRestrictionReport::UNAPPLIED
            .iter()
            .map(|u| u.launch_stage())
            .collect();
        assert_eq!(unapplied, remaining);
        // TASK-163.4: launch 経路の全段（cgroup 参加を含む）を exec 経路が適用するため、残りは空。
        assert_eq!(unapplied, Vec::<StageKind>::new());
        assert_eq!(UnappliedExecRestriction::Rlimits.as_str(), "rlimits");
        assert_eq!(
            UnappliedExecRestriction::CapabilityDrop.as_str(),
            "capability_drop"
        );
        assert_eq!(
            UnappliedExecRestriction::CapabilityDrop.launch_stage(),
            StageKind::CapabilityDrop
        );
    }

    /// SUP-6・TASK-163.3・REPAIR-5: 事前に開いた status が読み取り上限を超える場合は、切り詰めて解釈せず
    /// `None`（適用は拒否される）。先頭に `Threads: 1` があっても採用しない。上限ちょうどは読める。
    #[test]
    fn sup6_task163_3_pre_opened_source_rejects_oversized_status() {
        let limit = usize::try_from(crate::exec::STATUS_READ_LIMIT).expect("limit fits");
        let head = b"Threads:\t1\n";
        let mut exact = head.to_vec();
        exact.resize(limit, b'\n');
        let mut over = exact.clone();
        over.push(b'\n');
        assert_eq!(
            ThreadCountSource::PreOpened(tmp_file(&exact)).count(),
            Some(1)
        );
        assert_eq!(ThreadCountSource::PreOpened(tmp_file(&over)).count(), None);
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.3・#1468: 参加後の `/` が launch 時に記録した `/` と別のディレクトリなら、
    /// 何も適用せず違反記録つきの `FailedPrecondition`（理由 `exec_root_not_container_rootfs`・段 `SetNs`）。
    #[test]
    fn sup6_task163_3_root_mismatch_applies_nothing_and_records_violation() {
        let _ = take();
        let (_scratch, dir) = temp_dir("mismatch");
        let e = reapply_restrictions(restrictions_rooted_at(std::process::id(), &dir))
            .expect_err("root mismatch");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the root directory after joining is not the recorded container rootfs"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecRootNotContainerRootfs);
        assert_eq!(v.reason.as_str(), "exec_root_not_container_rootfs");
        assert_eq!(v.kind.as_str(), "exec_target");
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(taken(), Vec::<&str>::new());
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・TASK-163.3: 準備したプロセスの確認は root の照合より先（別プロセスからは root が
    /// 一致しなくても違反記録を付けず `Validate` 段で拒否する）。
    #[test]
    fn sup6_task163_3_owner_check_precedes_root_check() {
        let _ = take();
        let (_scratch, dir) = temp_dir("owner-first");
        let other = std::process::id().wrapping_add(1);
        let e = reapply_restrictions(restrictions_rooted_at(other, &dir)).expect_err("mismatch");
        assert_eq!(e.stage, IsolationStage::Validate);
        assert!(e.violation.is_none());
        assert_eq!(taken(), Vec::<&str>::new());
    }

    /// SUP-6・SEC-1・TASK-163.3: ディレクトリの同一性は `st_dev`・`st_ino` で決まる。同じディレクトリを別々に
    /// 開いた fd は一致し、別のディレクトリ・親子は一致しない。ディレクトリでない fd は判定せずエラー。
    #[test]
    fn sup6_task163_3_same_directory_compares_dev_and_ino() {
        let (_scratch, dir) = temp_dir("same");
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).expect("sub");
        std::fs::write(dir.join("file"), b"x").expect("file");
        let (a, b, c) = (dir_fd(&dir), dir_fd(&dir), dir_fd(&sub));
        let file = dir_fd(&dir.join("file"));
        assert_eq!(same_directory(a.as_fd(), b.as_fd()).ok(), Some(true));
        assert_eq!(same_directory(a.as_fd(), c.as_fd()).ok(), Some(false));
        assert_eq!(same_directory(c.as_fd(), a.as_fd()).ok(), Some(false));
        let e = same_directory(a.as_fd(), file.as_fd()).expect_err("not a directory");
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::SetNs);
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.3: 固定した rootfs が自プロセスの `/` と同じディレクトリなら、準備が
    /// 違反記録 `rootfs_is_host_root` つきの `InvalidArgument`（段 `Validate`）で拒否する（参加後の照合が
    /// 意味を持たないため）。Landlock の検出より先に判定するので、カーネル版数に依存しない。
    #[test]
    fn sup6_task163_3_prepare_rejects_rootfs_equal_to_own_root() {
        let root = dir_fd(Path::new("/"));
        let e = reject_own_root(root.as_fd(), root.as_fd()).expect_err("own root");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Validate);
        assert_eq!(e.message, "rootfs must not be the host root '/'");
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason.as_str(), "rootfs_is_host_root");
    }

    /// SUP-6・TASK-163.3: NO_NEW_PRIVS の失敗で Landlock・seccomp を呼ばない（段は NoNewPrivs）。
    #[test]
    fn sup6_task163_3_nnp_failure_stops_before_landlock() {
        let _ = take();
        fake(Err(SysError::Os(1)), Ok(true));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("nnp fails");
        assert_eq!(e.stage, IsolationStage::NoNewPrivs);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(taken(), vec!["rlimits", "capability_drop", "no_new_privs"]);
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・TASK-163.3: Landlock の失敗で seccomp を呼ばない（段と code を保つ）。
    #[test]
    fn sup6_task163_3_landlock_failure_stops_before_seccomp() {
        let _ = take();
        crate::exec::landlock::testing::fake_landlock_err(err(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("landlock");
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            taken(),
            vec!["rlimits", "capability_drop", "no_new_privs", "landlock"]
        );
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・TASK-163.3: seccomp の失敗は段 Seccomp・code を保って返る（Landlock までは適用済み）。
    #[test]
    fn sup6_task163_3_seccomp_failure_reports_seccomp_stage() {
        let _ = take();
        crate::exec::seccomp::testing::fake_seccomp_err(err(
            ErrorCode::Internal,
            IsolationStage::Landlock,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("seccomp");
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(
            taken(),
            vec![
                "rlimits",
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp"
            ]
        );
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・TASK-163.3: 準備したのと別のプロセスからは何も適用せず FailedPrecondition。
    #[test]
    fn sup6_task163_3_owner_pid_mismatch_applies_nothing() {
        let _ = take();
        let other = std::process::id().wrapping_add(1);
        let e = reapply_restrictions(restrictions(other)).expect_err("mismatch");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message,
            "restrictions must be reapplied by the process that prepared them"
        );
        assert_eq!(taken(), Vec::<&str>::new());
    }

    /// 記録（`config.json` に無いルールを含む手組みの値）。rootfs と `/data`、`/only-in-record` を持つ。
    fn hand_made_record(root: RootIdentity, handled: u64) -> LaunchIsolationRecord {
        use crate::launch_isolation::{RecordedLandlock, RecordedRule, RecordedTarget};
        use crate::oci_runtime::MountDestination;
        let dest = |p: &str| MountDestination::parse(p).expect("destination");
        let rules = vec![
            RecordedRule::new(RecordedTarget::Root, 0x7),
            RecordedRule::new(
                RecordedTarget::Mount {
                    destination: dest("/only-in-record"),
                    index: 4,
                },
                0x1,
            ),
        ];
        LaunchIsolationRecord::from_parts(
            root,
            RecordedLandlock::new(handled, rules).expect("recorded landlock"),
        )
    }

    /// SUP-6・CORE-5・SEC-1・TASK-163 追補・#1468: exec の Landlock は記録のルールだけから作る。
    /// `config.json` に無いルールでも記録にあればそのまま載り（launch の後に config が変わっても影響しない）、
    /// 記録の handled も変えない。準備は `config` を引数に取らない。
    #[test]
    fn sup6_task163_1468_landlock_is_built_from_the_record_not_from_config() {
        let launch = hand_made_record(identity_of(Path::new("/")), 0xFFFF);
        match prepare_with_launch(&launch, launch.root(), Rlimits::default(), own_binding()) {
            Ok(r) => {
                let rules: Vec<(&str, u64)> = r
                    .landlock
                    .rules()
                    .iter()
                    .map(|rule| (rule.path.as_str(), rule.allowed.bits()))
                    .collect();
                assert_eq!(rules, vec![("/", 0x7), ("/only-in-record", 0x1)]);
                assert_eq!(r.landlock.handled_access_fs().bits(), 0xFFFF);
                assert_eq!(r.root, launch.root());
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    /// SEC-1・CRI-2・#2666: exec の許可集合は launch 時の記録の値で、記録が無い旧記録は OCI 既定集合になり、
    /// 再適用は準備で決めた集合を capability 段へ渡す（launch より広い集合では動かさない）。
    #[test]
    fn sec1_cri2_exec_capabilities_follow_the_launch_record() {
        use crate::capabilities::{Capability, CapabilitySet};
        use crate::exec::capabilities::testing::take_allowed_seen;
        let narrowed = ContainerCapabilities::restrict(
            CapabilitySet::empty()
                .with(Capability::Kill)
                .with(Capability::Chown),
        )
        .expect("subset of the default");
        let legacy = hand_made_record(identity_of(Path::new("/")), 0xFFFF);
        let recorded = legacy.clone().with_capabilities(narrowed);
        for (launch, want) in [
            (&legacy, ContainerCapabilities::oci_default()),
            (&recorded, narrowed),
        ] {
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）ため、通った場合だけ照合する。
            if let Ok(r) =
                prepare_with_launch(launch, launch.root(), Rlimits::default(), own_binding())
            {
                assert_eq!(r.capabilities, want);
            }
        }
        let _ = take();
        let _ = take_allowed_seen();
        let mut r = restrictions(std::process::id());
        r.capabilities = narrowed;
        let report = reapply_restrictions(r).expect("reapply");
        assert_eq!(take_allowed_seen(), Some(narrowed));
        assert_eq!(report.capability_bounding_dropped, 39);
        let _ = take();
        let _ = crate::exec::rlimits::testing::take_sets();
    }

    /// SUP-6・SEC-1・SEC-4・#1468: 記録した `/` が自プロセスの `/` と同じ（壊れた記録・ホストの `/` を指す記録）なら、
    /// 違反 `rootfs_is_host_root` で拒否する。
    #[test]
    fn sup6_task163_1468_recorded_root_equal_to_own_root_is_rejected() {
        let own = dir_fd(Path::new("/"));
        let e = reject_recorded_own_root(identity_of(Path::new("/")), own.as_fd())
            .expect_err("own root");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Validate);
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason.as_str(), "rootfs_is_host_root");
        let (_scratch, dir) = temp_dir("recorded-own");
        reject_recorded_own_root(identity_of(&dir), own.as_fd()).expect("different directory");
    }

    /// SUP-6・SEC-1・#1468: 参加後の `/` の照合は記録した識別子との `st_dev`・`st_ino` の一致で決まる。
    /// ホスト側の bundle ディレクトリ（`/` と別のディレクトリ）の識別子とは一致しない。
    #[test]
    fn sup6_task163_1468_open_verified_root_compares_recorded_identity() {
        let root = identity_of(Path::new("/"));
        assert!(open_verified_root(root).is_ok());
        let other = RootIdentity::new(root.dev(), root.ino().wrapping_add(1));
        let e = open_verified_root(other).expect_err("different inode");
        assert_eq!(e.stage, IsolationStage::SetNs);
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecRootNotContainerRootfs);
        let (_scratch, dir) = temp_dir("verified-root");
        let e = open_verified_root(identity_of(&dir)).expect_err("host directory");
        assert_eq!(
            e.message,
            "the root directory after joining is not the recorded container rootfs"
        );
    }

    /// SUP-6・TASK-163.3: `Debug` は fd・ルール内容を出さず、pid だけを示す。
    #[test]
    fn sup6_task163_3_debug_hides_internals() {
        let text = format!("{:?}", restrictions(42));
        assert_eq!(text, "ExecRestrictions { owner_pid: 42, .. }");
    }

    /// `config` の `root.path`（`rootfs`）を持つ使い捨ての bundle を作り、start と同じ経路で rootfs を固定する。
    fn pinned_rootfs(
        label: &str,
        config: &OciConfig,
    ) -> (
        crate::scratch_root::ScratchDir,
        std::path::PathBuf,
        RootfsDir,
    ) {
        // 親は Linux で canonicalize 済み。bundle は親の子にする（親の共有 flock と bundle のロックを干渉させない）。
        let (scratch, bundle) =
            crate::test_support::scratch_child(&format!("fandhe-reapply-{label}"), "bundle");
        std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
        let rootfs = crate::oci_runtime::pin_bundle_rootfs(&bundle, config).expect("pin rootfs");
        (scratch, bundle, rootfs)
    }

    /// launch の代わりに、`config` から導いた ruleset と固定済み rootfs の識別子で記録を作る
    /// （`launch_isolation_from_bundle` と同じ。Landlock 未対応のカーネルでは `Err`）。
    fn launch_record(
        config: &OciConfig,
        rootfs: &RootfsDir,
    ) -> Result<LaunchIsolationRecord, ExecError> {
        crate::exec::launch_isolation_from_bundle(config, rootfs)
    }

    fn config(readonly: bool, mounts: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":{readonly}}},"mounts":{mounts}}}"#
        );
        crate::oci_runtime::parse_config_bytes(json.as_bytes()).expect("config")
    }

    /// SEC-1・SEC-4・#3201: Mount 由来のルールがあるのに識別子の無い旧記録は `FailedPrecondition`(段 `Landlock`)で
    /// 拒否し、Mount 由来のルールが無い記録(rootfs だけ)は通す。
    #[test]
    fn sec1_3201_old_record_without_mount_identities_is_rejected() {
        use crate::launch_isolation::{RecordedLandlock, RecordedRule, RecordedTarget};
        use crate::oci_runtime::MountDestination;
        let old = LaunchIsolationRecord::from_parts(
            RootIdentity::new(1, 2),
            RecordedLandlock::new(
                0xFFFF,
                vec![
                    RecordedRule::new(RecordedTarget::Root, 0x7),
                    RecordedRule::new(
                        RecordedTarget::Mount {
                            destination: MountDestination::parse("/data").expect("destination"),
                            index: 0,
                        },
                        0x7,
                    ),
                ],
            )
            .expect("landlock"),
        );
        let e = recorded_mounts_for_exec(&old).expect_err("must be rejected");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert_eq!(
            e.message,
            "launch isolation record has no mount identities; recreate the container"
        );

        let root_only = LaunchIsolationRecord::from_parts(
            RootIdentity::new(1, 2),
            RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)])
                .expect("landlock"),
        );
        assert!(recorded_mounts_for_exec(&root_only).is_ok());
    }

    /// SUP-6・TASK-163.3・CORE-5・#1468: 書き込み制限が祖先ルールで無効になる構成は、launch の記録の作成が
    /// `stage = Landlock` で拒否する（記録を作れないので exec の準備まで進まない）。ABI 検出が通らない環境では検出失敗で拒否される（どちらも fail-closed で成功しない）。
    #[test]
    fn sup6_task163_3_prepare_rejects_shadowed_write_restriction() {
        let c = config(false, r#"[{"destination":"/etc","options":["ro"]}]"#);
        let (_scratch, _bundle, rootfs) = pinned_rootfs("shadowed", &c);
        let e = launch_record(&c, &rootfs).expect_err("must be rejected");
        assert_eq!(e.stage, IsolationStage::Landlock);
        const DETECT: [&str; 6] = [
            "kernel_lacks_landlock",
            "landlock_disabled_at_boot",
            "landlock_abi_too_old",
            "invalid_kernel_response",
            "unsupported_architecture",
            "landlock_probe_failed",
        ];
        if e.message.starts_with("write_restriction_shadowed:") {
            assert_eq!(e.code, ErrorCode::InvalidArgument);
        } else {
            assert!(
                DETECT.iter().any(|r| e.message.starts_with(r)),
                "{}",
                e.message
            );
        }
    }

    /// SUP-6・TASK-163.3: 準備が通れば自 pid を記録し、status fd からスレッド数を読める。
    #[test]
    fn sup6_task163_3_prepare_records_pid_and_reads_threads() {
        let c = config(true, "[]");
        let (_scratch, _bundle, rootfs) = pinned_rootfs("records", &c);
        let prepared = launch_record(&c, &rootfs).and_then(|launch| {
            prepare_with_launch(&launch, launch.root(), Rlimits::default(), own_binding())
        });
        match prepared {
            Ok(mut r) => {
                assert_eq!(r.owner_pid, std::process::id());
                let n = r.threads.count().expect("threads readable");
                assert!(n >= 1, "{n}");
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    /// SUP-6・TASK-163.3・CORE-5: 準備はルールパスを開かず解決もしない。実在しないパスを destination に
    /// 持つ config でも準備は成功し、ruleset はコンテナ内パスの文字列をそのまま保持する
    /// （開く処理は `setns` 後の `reapply_restrictions` 側。fail-closed の拒否もそこで起きる）。
    #[test]
    fn sup6_task163_3_prepare_keeps_container_paths_unresolved() {
        let dest = "/fandhe-nonexistent-reapply-dest/data";
        let c = config(
            true,
            &format!(r#"[{{"destination":"{dest}","options":["ro"]}}]"#),
        );
        let (_scratch, _bundle, rootfs) = pinned_rootfs("unresolved", &c);
        let prepared = launch_record(&c, &rootfs).and_then(|launch| {
            prepare_with_launch(&launch, launch.root(), Rlimits::default(), own_binding())
        });
        match prepared {
            Ok(r) => {
                let paths: Vec<&str> = r
                    .landlock
                    .rules()
                    .iter()
                    .map(|rule| rule.path.as_str())
                    .collect();
                // 暗黙の /dev 系（#1657）は root の次に入る。
                assert_eq!(paths, vec!["/", "/dev", "/dev/pts", "/dev/shm", dest]);
                // 準備（`join_namespaces` 前）でホストへ解決されていないこと: destination は実在しない。
                assert!(!std::path::Path::new(dest).exists());
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    fn tmp_file(content: &[u8]) -> std::fs::File {
        use std::io::{Seek as _, Write as _};
        let mut f = tempfile_in_target();
        f.write_all(content).expect("write");
        f.seek(std::io::SeekFrom::Start(0)).expect("seek");
        f
    }

    /// 使い捨ての無名ファイル（名前を残さない）。`O_TMPFILE` 相当を std だけで作れないため、
    /// 一意名で作成して直ちに unlink する。
    fn tempfile_in_target() -> std::fs::File {
        use std::io::Read as _;
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("urandom");
        let path = std::env::temp_dir().join(format!(
            "fandhe-reapply-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(buf)
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create");
        std::fs::remove_file(&path).expect("unlink");
        f
    }

    /// SUP-6・TASK-163.3: 事前に開いた fd から `Threads:` を読め、同じ fd を再読込しても同じ値になる。
    #[test]
    fn sup6_task163_3_pre_opened_source_parses_and_rereads() {
        let mut src =
            ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\nThreads:\t1\nVmRSS:\t5 kB\n"));
        assert_eq!(src.count(), Some(1));
        assert_eq!(src.count(), Some(1));
    }

    /// SUP-6・TASK-163.3: `Threads:` 行が無い・空の fd は `None`（適用は拒否される。fail-closed）。
    #[test]
    fn sup6_task163_3_pre_opened_source_rejects_unreadable_status() {
        let mut no_line = ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\n"));
        assert_eq!(no_line.count(), None);
        let mut empty = ThreadCountSource::PreOpened(tmp_file(b""));
        assert_eq!(empty.count(), None);
        let mut multi = ThreadCountSource::PreOpened(tmp_file(b"Threads:\t3\n"));
        assert_eq!(multi.count(), Some(3));
    }
}
