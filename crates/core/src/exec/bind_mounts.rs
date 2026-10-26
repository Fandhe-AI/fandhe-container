//! 検証済みの bind mount を pivot 前の rootfs へ fd 起点で適用する段（CORE-1・CORE-2・OCI-4・SEC-1・SEC-4・
//! SEC-5・TASK-29 追補・#1913。方針は #1910 のオーナー決定 2026-10-12・#1907 案 (a)）。
//!
//! # 役割と呼び出し文脈
//!
//! `config.json` の `mounts[]` のうち bind の指定は、[`BindMountSet::from_mounts`](crate::oci_runtime::BindMountSet)
//! （#1911）が字句検証済みの型へ変換する。本段はその型を、ホストのディレクトリ／ファイルをコンテナへ見せる
//! 分離の境界として、rootfs へ実際に載せる。tmpfs の段（`exec/tmpfs.rs`）・注入の段（`exec/inject.rs`）と同じ流儀で、
//! fd で固定し、shared の上には載せず、移動を検査し、`move_mount(2)` を fd で指定し、マウント ID で事後照合し、
//! 失敗時は自分が作ったものだけを戻す。`MountDestination::resolve_in` の文字列結合や `mount(2)` へのパス渡しは使わない。
//!
//! ```text
//! prepare_rootfs（と create_default_devices -> mount_tmpfs -> inject_files）-> mount_binds(&isolation, &prepared, &set)
//!   -> readonly_paths -> masked_paths -> pivot_root
//!                                                  ^ 同じスレッド・seccomp の適用前
//! ```
//!
//! 入口は検証済みの型（[`MountIsolation`]・[`PreparedRootfs`]・`BindMountSet`）だけを受け、生の `OciMount` や
//! パス文字列を受ける入口は持たない。`run_pre_pivot` へは組み込み済み（#1914。`inject_files` の後・`readonly_paths` の前に固定）。
//! `start` と本番 launcher への結線・`check_against_*` の呼び出しは #1915 で済み（`start` が host_paths・保護パス、launcher が tmpfs を検査する）。`/dev` の tmpfs を覆い隠す宛先は
//! `BindMountSet` が `/proc`・`/sys`・`/dev` とその配下を拒否するため型の上で作れず、`DeviceReport` の証跡は受けない。
//!
//! # マウント元をどのプロセスがどの権限で開くか
//!
//! 起動の連鎖は次のとおり。supervisor（C）は init user namespace で特権ランチャー由来の ambient capability を持つ。
//! 中間プロセス（I）が `isolate` で `unshare(CLONE_NEWUSER)` する。以後 I が持つ capability は子の user namespace の中
//! だけで、親（init）の namespace には効かない。I が fork した PID 1 は、その user namespace を引き継ぎ、
//! `establish` → `prepare_rootfs` → …… → 本段 → `pivot_root` と進む。
//!
//! **マウント元は PID 1 が本段の中で開く**。C と I は元を開かず、fd も渡さない（unshare 前に開いた fd は、`open_tree` が
//! 同じ mount namespace の fd を要求する〔`check_mnt`〕ため `EINVAL` になり、そもそも使えない）。user namespace の中の
//! `CAP_DAC_OVERRIDE`・`CAP_DAC_READ_SEARCH` は、所有者と group がその namespace へ写像されている inode にしか効かない
//! （`user_namespaces(7)` の "Effect of capabilities within a user namespace"）。写像されていない所有者の inode は、
//! ホスト側の fsuid（コンテナ root は起動した利用者の UID に写る）で通常の DAC 判定を受ける。したがって、
//! 特権ランチャー由来の capability で利用者の権限外の場所へは届かない。上書きが効くのは、利用者本人の UID が所有する
//! inode（本人は chmod できる）と、subordinate 写像のときの subuid／subgid が所有する inode（利用者に委譲済みの ID）に限る。
//!
//! `O_PATH` の open は祖先の search 権限しか見ず、末端の read 権限を確かめない（`open_tree` も見ない）。そのため種別の確認の後、
//! 固定した fd を `/proc/thread-self/fd/N` 経由で `O_RDONLY|O_NONBLOCK` に開き直し（パスを再 walk しない）、同じ inode に
//! 読み取り権限の判定を掛ける。`EACCES`・`EPERM` は `bind_source_not_accessible`。user namespace なしの経路
//! （init user namespace、またはホストの ID 0 を写像した経路）では適用せず `user_namespace_required`・
//! `host_root_identity_mapping` で拒否する。
//!
//! # 契約（1 件ごとの順序）
//!
//! 1. **元の固定**: 新しい mount namespace の中で `/` から全要素を `O_NOFOLLOW` で辿って fd に固定する。symlink は
//!    `bind_source_symlink`、種別がディレクトリ・通常ファイル以外は `bind_source_unsupported_type`、存在しなければ
//!    `NOT_FOUND`（違反ではない。何も作らない）。固定した fd から複製し、パス文字列で再解決しない
//!    **元の FS の種類**: 固定した fd に `fstatfs(2)` を掛け、`f_type` が `PSEUDO_FS_DENYLIST` にあれば `bind_source_pseudo_fs`
//!    で拒否する（#2098・#2065 案 B。SEC-1。字句の段では判定しない。`fstatfs` の失敗は fail-closed、対応外アーキテクチャは
//!    `UNIMPLEMENTED`）。ホストの `/proc` を bind すると、コンテナ自身の `/proc` に掛ける `maskedPaths`・`readonlyPaths` が
//!    効かない別の宛先からホストのプロセス情報が見えるため。拒否リストの根拠は `PSEUDO_FS_DENYLIST` の doc を参照
//! 2. **rootfs との同一性**: rootfs の `(st_dev, st_ino)` とその祖先（`..` を `O_NOFOLLOW` で辿る。4096 段が上限）に元が
//!    含まれれば `bind_source_contains_rootfs` で拒否する。rootfs の祖先には bundle が入るため、bundle の bind 別名（同じ inode）も
//!    ここで拒否する。bundle・rootfs の配下は受ける（#2063 案 B）。あわせて状態ルートの inode の鎖
//!    （start の段が fd で固定し `BindMountSet` の `ProtectedFsRoot` で渡す。自身から `/` まで）に元が含まれるか、元の祖先に状態ルートが
//!    あれば `bind_source_reaches_state_root` で拒否する（同一・祖先・子孫。`judge_source_inodes`。SEC-1・SEC-4・#2066）。
//!    固定していない集合は `FAILED_PRECONDITION`（fail-closed）
//! 3. **先の固定**: [`PreparedRootfs`] の fd から 1 要素ずつ辿る（symlink・非ディレクトリは `path_symlink_or_not_directory`）。
//!    無い要素は 0755 で作り、元が通常ファイルなら末尾は空の通常ファイル（0644。umask の影響を受ける）にする。既存の
//!    マウント先の種別が元と違えば `bind_target_kind_mismatch`
//! 4. **検査**: マウント先が shared の上なら `target_on_shared_mount`
//! 5. **複製と属性**: 固定した元から `open_tree(OPEN_TREE_CLONE)` で複製し（`rbind` のときだけ `AT_RECURSIVE`）、切り離したまま
//!    `mount_setattr` で `nosuid`・`nodev`（常時）と `ro`・`noexec`（指定どおり）を足す。属性を付け終えてから付け替える
//! 6. **付け替え前の属性確認**: 切り離したマウントの `mount_flags` が要求どおりか確かめる。`attr_clr` を持たないため、ロックされた
//!    属性や読み取り専用の FS の元は要求より強い制限が残る。黙って別の属性で載せず、`FAILED_PRECONDITION`（`specify ro` 等）にする
//! 7. **移動検査**: 付け替えの直前にマウント先が改名・移動・削除されていないことを fd の現在位置で確かめる（`target_moved`）
//! 8. **付け替え**: `move_mount(2)` の空パス + fd 指定。直後に自分のマウントの fd を保持する
//! 9. **事後検証**: マウント前と別のマウントであること・自分のマウントの ID であること・`mount_flags` が要求どおりであること・
//!    元と同じ `(st_dev, st_ino)` であること・mountinfo で自分のマウント（`rbind` は配下全体）に `shared:`・`master:` が無く（`rslave` は
//!    `shared:` が無く、最上位に `master:` か `propagate_from:` があること）
//!    per-mount options が要求を満たすこと。満たさなければ fail-closed で失敗にする。続けて同じ mountinfo で、自分のマウント
//!    （`rbind` は配下全体）の fstype を拒否リストの名前と照合し、疑似 FS が 1 つでもあれば `bind_source_pseudo_fs` で拒否する
//!    （配下だけ除いて載せることはしない。付け替えた木そのものを見るため、検査から複製までの間に元の下へマウントが足される
//!    TOCTOU が無い。拒否は付け替えの後だが `pivot_root`・exec の前で、後始末が自分のマウントを外す）
//!
//! **`rslave` の例外（#2669・OCI-4・CRI-2・SEC-1）**: `BindMountSpec::propagation()` が `HostSlave` の bind だけは、下の「`/` が
//! private である前提」の例外になる。`/` の再帰 private 化は接続済みの木の `master` 関係をすべて消すため、`MountIsolation::
//! establish_with` が `unshare(CLONE_NEWNS)` の直後・private 化の前に、その元を固定して `clone_host_slave_sources` で複製する
//! （ホスト側の元が shared か slave でなければ、rootfs に触れる前に `FAILED_PRECONDITION`）。複製は匿名 namespace にあり、
//! private 化の対象にならないため `master` を保つ。本段（`apply_one`）は手順 1 の固定と手順 5 の `open_tree` の代わりにその固定と
//! 複製を使い、他の手順（疑似 FS・rootfs・状態ルートの照合、属性、移動検査、付け替え）は private の bind と同じ。手順 9 は、
//! `shared:` を全メンバーで禁止したまま、最上位に `master:`・`propagate_from:` のどちらかを必須にする（配下の `master:` は許す）。
//! 付け替え先は手順 4 で非 shared と確認済みで、slave の複製はコンテナからホストへ伝播しない。
//!
//! 残余（REPAIR-3）: ホストから `rslave` の bind へ伝播してきたマウントは、ホスト側のマウントの属性とカーネルのロックを持ち、
//! こちらの `nosuid`・`nodev`・`ro`・`noexec` が付かない。疑似 FS と状態ルートの検査も付け替え時点の 1 回だけである。これは
//! HostToContainer の意味に内在し、引き起こせるのはホスト側の特権主体だけ。Landlock は経路で判定するため、bind 先の規則は
//! 伝播したマウントにも効く。`rshared`（コンテナからホストへの伝播）は、user namespace の中では原理的に成り立たないため受けない
//! （`docs/design/mount-propagation.md`）。
//!
//! **伝播（private の bind）**: 明示の private 化はしない。`MountIsolation::establish` が `/` を `MS_REC|MS_PRIVATE` にしており、この
//! namespace のマウントは shared でも slave でもない。shared でも slave でもないマウントの複製はやはりそうなる。付け替え先は
//! 手順 4 で非 shared と確認済みで、手順 9 が `shared:`・`master:` の不在を確かめる。`establish` の private 化は計画の
//! namespace 集合に依らず無条件で、`mount_binds` は `&MountIsolation`（`establish` の証跡）を引数に取るため、型の上で
//! `establish` の後にしか呼べない。`isolate*` 側の private 化は `Mount` を含む計画のときだけ走り、本段の前提はそれに依存しない（#2131）。
//!
//! 切り離したマウントへの伝播変更は、カーネルのソースで許されると確認済み（#2064・SEC-1。`mount_setattr(2)` の man page
//! 〔man-pages 6.17〕は可否を明記せず、決め手はソース）。`mount_setattr_commit` はマウントごとに `change_mnt_propagation` を呼び、
//! 対象の判定は v5.12 の `mount_setattr_prepare` が「親なしなら匿名 mount namespace であること」、v6.12 の `do_mount_setattr` が
//! 「親を持つか匿名でないなら `check_mnt`」、v7.0 の `do_mount_setattr` が `!anon_ns_root(mnt) && !check_mnt(mnt)` で `EINVAL` とする。
//! `open_tree(OPEN_TREE_CLONE)` の fd は匿名 namespace の root なのでいずれも通る。それでも使わないのは、複製（`clone_mnt`）が元の
//! 伝播（`mnt_group_id`・`mnt_master`）を引き継ぐためで、**複製が private であることは `establish` の `MS_REC|MS_PRIVATE`
//! に依存する**（これを外す改修は手順 4・9 の照合で検出されるが、前提として維持すること）。`MS_PRIVATE` を同じ呼び出しで設定する
//! 変更は #2165 で検討し、見送った（伝播の前提は `establish` の無条件の private 化・手順 4 の shared 拒否・手順 9 の照合の 3 段で
//! 守られ、いずれも fail-closed のため）。再検討するのは、`establish` の private 化を条件付き・順序替え・除去する改修や、
//! 手順 4・9 が伝播の不備を検出したとき（SEC-1・OCI-4）。
//!
//! **属性とロックの一次情報**（#2064 で版つきに確認。Linux v5.12・v6.12・v7.0 の `fs/namespace.c`・`fs/pnode.c`、man-pages 6.17）:
//!
//! - ロックが付く条件: `copy_mnt_ns` は user namespace が異なるとき `lock_mnt_tree` を呼び、`MNT_LOCK_ATIME` と、立っている
//!   `ro`・`nodev`・`nosuid`・`noexec` に対応する `MNT_LOCK_*` を立てる（`mount_namespaces(7)` は nodev に触れないがソースは立てる）。
//!   本経路は user namespace の後に PID 1 が `unshare(CLONE_NEWNS)` するため、ホストから引き継いだマウントはすべてロックされる。
//! - 非再帰の `EINVAL`: `__do_loopback` は `!recurse` で、元の直接の子に配下で `MNT_LOCKED` のものがあると `EINVAL`
//!   （`has_locked_children`。v7.0 は `__has_locked_children`。`mount(2)` の ERRORS にも同旨）。ホスト側で配下にマウントを持つ
//!   ディレクトリは典型的にこれに当たり、`rbind` を促す `FAILED_PRECONDITION` にする。`__do_loopback` の `EINVAL` は他に
//!   元が unbindable のときと `check_mnt` 不成立のときがあるが、前者は `establish` の `MS_PRIVATE`（`change_mnt_propagation` が
//!   unbindable を外す）、後者は同じ mount namespace の中で開くことで起きない。この写像はその前提の下で成り立つ。
//! - 属性の引き継ぎ: `clone_mnt` は `MNT_LOCK_*` を含む `mnt_flags` を複製に残す（落とすのは内部用フラグだけ）。`rbind`
//!   （`copy_tree`）の unbindable 配下の `EPERM` も、unbindable が残らないため起きない。
//! - 足すだけの `mount_setattr`: `can_change_locked_flags` が false になるのは、ロックされた属性が結果から消えるとき
//!   （と `MNT_LOCK_ATIME` で atime が変わるとき）だけで、いずれも `EPERM`。`attr_clr` = 0・atime なしの本段は常に成功し、
//!   ロックされた ro は外れないまま要求との差が手順 6・9 の構造化エラーになる（`mount_setattr(2)` の EPERM の記述は
//!   「ロックされた属性が立っている」と読めるが、ソースは外そうとしたときだけ）。
//!
//! `rbind` の配下の付け替え前の属性確認は行わず（mount top だけを見る）、配下は手順 9 の mountinfo で確かめる。実機
//! （user namespace・実マウント）での確認は #1916。
//!
//! # エラーと監査
//!
//! 失敗は段 `MountBinds` の [`ExecError`]。分離違反（symlink・配下でない・種別違い・移動・読めない元・shared・疑似 FS）は
//! [`ViolationReason`] を持ち、[`audit_mount_violation`](super::audit_mount_violation) で `Mount` 監査レコードにできる。違反記録の対象と
//! message のパスは**コンテナ内の宛先**で、ホスト側のマウント元・rootfs の実パスは載せない。宛先は [`display_destination`]
//! のエスケープと切り詰めを通す。新マウント API の無いカーネルでは `mount(2)` へ縮退せず `UNIMPLEMENTED` で拒否する。
//!
//! 失敗時は、載せたマウントを新しい順に `umount2(MNT_DETACH)` で外し、自分が作った空ファイル・ディレクトリを、作成時に記録した
//! `(dev, ino)` と一致するときだけ消す（自分専用の隔離ディレクトリへ `renameat2(RENAME_NOREPLACE)` してから照合して消し、照合と削除の間の
//! 差し替えを防ぐ）。後始末の失敗（umount・開き直し・照合不一致・削除）は元のエラーの message に `; cleanup failed: ...` として併記する
//! （REPAIR-4）。呼び出し後もプロセスは破棄する（`pivot_root`・exec へ進まない）。
//!
//! 隔離ディレクトリの 0700・実効 uid 所有の照合が排除するのは別の uid のプロセスだけである。同じ実効 uid のプロセス
//! （または `CAP_DAC_OVERRIDE` を持つプロセス）は隔離ディレクトリに入れ、差し替えもできるため、同じ uid のプロセスは隔離
//! しない。これは残余として受け入れている（同じ uid のプロセスはランチャー自体を ptrace・kill でき、脅威モデルの外にある。
//! SEC-1・#2131）。以降の「他者」「他者は入れない」は、別の uid のプロセスを指す。
//!
//! # 未対応・残余（REPAIR-3: 実装済みを装わない）
//!
//! - 状態ルートとの重なりは `start` が一次検査し（字句・`canonicalize`・fd の `mnt_id` によるマウントの特定と mountinfo の実体照合）、
//!   適用の段も固定した元に対して毎回再検証する（`ProtectedFsRoot`・`check_source_not_protected`。restart を含む。
//!   元の属するマウントは固定した fd の `mnt_id` で特定し、`rbind` のときだけ配下のマウントを照合する。保護対象と同じ FS 上で
//!   リンク数 2 以上の通常ファイルは状態ファイルへのハードリンクかもしれないため拒否する。状態ルート配下の状態ファイルが
//!   別名を持つ場合は、同じ FS 上のディレクトリ元も拒否する）。残余は検査から `open_tree` までの間の差し替え（固定した fd への複製のため元の差し替えは効かない）。
//!   実機前提の結合試験の段ごとの観測（#1916。通しの確認は `tests/production_launcher.rs` のシナリオ D〔#1915〕）。
//!   `ro` と Landlock の衝突解消（#1917）
//! - 状態ルートの inode の照合（#2066）は start の段で鎖を固定した実体に対するもので、start の後に状態ルートが祖先ごと改名されても
//!   効く（inode は変わらない）。start の後に状態ルートを**別の親ディレクトリへ付け替えた**場合は、
//!   適用の段が start の記録したホスト側パスを `/` から辿り直し（`O_NOFOLLOW`。`resolve_fresh_state_chains`）、固定した実体と
//!   一致しなければ `FAILED_PRECONDITION` で拒否する（#2129。restart を含む）。一致した新しい鎖でも元を照合する。
//!   残余は、祖先の bind mount を別の経路から改名するなど、パスが同じ inode に解決したまま FS 内パスだけが変わる場合で、
//!   mountinfo の `(dev, path)` は、適用の段が毎回作り直す（#2166。`check_source_not_protected`。記録した `chain_path` を開き直し、
//!   fd の `mnt_id` で行を引いて `fs_identity` を作る。本番は `fresh_state_identity`、単体テストは `BindDeps::state_identity`）。
//!   記録した値と作り直した値の**両方**と、`chain_path` 配下の子マウントを現在の mountinfo から取り直したものを照合し、作り直せない・dev が
//!   記録と食い違う場合は `FAILED_PRECONDITION`。判定が厳しくなる方向だけの変更で、記録した値での判定は残す。必要な理由は、
//!   start の後に下層の実パス（マウントポイントを通らない経路）で状態ルートが改名されると、`chain_path` は同じ inode に解決し続けて
//!   辿り直しを通る一方、記録した FS 内パスだけが古くなり、改名後の親を元にした bind が inode の鎖にも mountinfo にも映らないため。
//!   start の後に子マウントが増えた場合も、取り直した結果で元との重なりを見る（ハードリンクの走査対象〔`scan_root`〕は start の記録のまま）。
//!   PID 1 と start（CLI）が同じ資格情報でパスを辿れるという前提（subordinate 写像を含む）は実機の結合試験（#1916）で確かめる。
//!   別の superblock を通して同じデータを見せるもののうち、overlayfs の層は付け替えた木の mountinfo の super_options から照合する
//!   （手順 9 の直後。`check_overlay_layers`・`overlay_layers`。#2166）。FUSE 系の中身は検出しない。bundle の実体は rootfs の鎖と
//!   mountinfo の `contained` で照合済み（ホスト側の bind による別名を含む）。実機での別名の確認は #1916
//! - overlayfs の層の照合（#2166）は、付け替えた自分のマウント（`rbind` なら配下全体）のうち fstype が `overlay` のものの
//!   `lowerdir`・`lowerdir+`・`datadir+`・`upperdir`・`workdir` を `/` から `O_NOFOLLOW` で辿り、rootfs・状態ルートの鎖と inode で照合する。
//!   相対パス・現在の namespace で解決できない層（Docker のように `/` が overlay で下層が見えない環境を含む）・symlink・解析できない
//!   super_options・上限（層 500・1 層 4096 バイト・1 件の bind で合計 4096 層）超過・層が別の overlay の上にある入れ子は、
//!   `FAILED_PRECONDITION` で拒否する。残余は、入れ子の overlay の再帰的な照合（拒否で代える）と、照合から `pivot_root` までの間の
//!   層の差し替え
//!   （overlay の層は開き直しが実際の backing directory と同一とは限らない〔lowerdir のパスを後から別の bind で覆う等〕ため、
//!   層の属するマウントの `(dev, path)` による照合〔#2166 の再指摘〕の後も、overlayfs を含む元は同一性を保証できず fail-closed で拒否する）
//! - 保護対象（状態ルート・rootfs・bundle）の側が overlayfs の上にある場合の逆方向の別名（#2317）は、適用の時点の mountinfo で
//!   保護対象の dev の行が `overlay` なら、その層を `resolve_overlay_layers` で解決して保護対象に加え（`protected_overlay_layers`）、
//!   宛先を作る前に inode（`judge_source_against_layers`）と mountinfo の `(dev, path)` で照合する。rootfs・bundle 由来の層は同一・
//!   祖先・子孫のすべてを `bind_source_contains_rootfs` で拒否する。層を解決できない場合（Docker のように `/` が overlay で下層が
//!   見えない環境を含む）、および保護対象の dev の行が mountinfo に無い場合は `FAILED_PRECONDITION`（#2536。fail-closed）。
//!   fstype が `overlay` の完全一致でない積層 FS（`fuse.fuse-overlayfs` 等。super_options に層のパスが載らない）は検出対象外の残余。
//!   開き直した層の同一性の残余を許可に倒す点はオーナー判断待ち（#2536）。残余は順方向と同じく、開き直した層が実際の backing directory と同一とは限らない点で、
//!   逆方向では一律拒否にしない（一律拒否にすると保護対象が overlay 上にある限りどの bind も拒否になるため）。入れ子の overlay は拒否で代える。
//!   `start` の fork 前の一次検査（`MountRow` が fstype を持たない）には足さず、restart を含めて毎回走る適用の段が権威である
//! - 疑似 FS の元は `f_type`（と配下の mountinfo の fstype）の**拒否リスト**で拒否する（#2098・#2065 案 B）。リストにない未知の
//!   疑似 FS は受ける。devtmpfs（ホストの `/dev`）は `f_type` が tmpfs と同じで区別できないため、付け替えた自分のマウントの
//!   mountinfo の fstype 名 `devtmpfs` で拒否する（#2129。手順 9）。FUSE（lxcfs のように `/proc` に似た内容を作るもの）・
//!   別の superblock 経由の別名のうち FUSE の中身は検出しない（overlayfs の層は #2166 で照合する）。見直しの手順は
//!   `docs/api/bind-mounts.md`。実機（user namespace と実際のマウント）での確認は #1916
//!
//! # 単体テストの安全策
//!
//! 新マウント API・属性の観測・mountinfo は [`BindDeps`] の差し込み点で差し替える（本番は `mount_binds`、単体テストは
//! 記録つきの dry-run）。元の固定・種別・読めるかは実ファイルで照合する。実機の挙動は #1916 の結合試験で確認する。

use std::cell::RefCell;
use std::ffi::{CString, OsStr};
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::oci_runtime::ProtectedFsRoot;
use crate::oci_runtime::mountinfo_identity::{
    FsIdentity, MOUNTINFO_MAX_LINES, MountRow, dir_identity_chain, dir_identity_chain_with_mnt_id,
    exposed_devs, fs_identity, mounts_under, parse_fdinfo_mnt_id, parse_mountinfo, path_mount_id,
    source_contains, source_reaches,
};
use crate::oci_runtime::{BindMountSet, BindMountSpec, BindPropagation};
use crate::rootless::parse_id_map;
use crate::sys::{
    self, BindMountAttrs, BindSourceError, BindSourceKind, MountFlags, MountTreeScope, SysError,
    VerifiedBindSourceFd,
};
use crate::traits::types::ErrorCode;

use super::overlay_layers::overlay_layer_paths;
use super::tmpfs::{DIR_MODE, display_destination, open_chain, root_display};
use super::{
    ExecError, IdMapping, IsolationStage, MountIsolation, PreparedRootfs, USER_NS_INIT_INO,
    ViolationReason, fd_mount_id, fd_still_at, mount_is_shared, read_thread_mountinfo,
    thread_ns_link,
};

/// 結合試験専用の入口 [`mount_binds_with_attach_hook`] が、検査後・付け替え前に呼ぶ処理の型。
#[cfg(feature = "exec-test-support")]
type AttachHook<'a> = &'a dyn Fn();

const STAGE: IsolationStage = IsolationStage::MountBinds;

/// 通常ファイルの元に対して作る空ファイルのモード（umask の影響を受ける。bind で覆われるため見えるのは元の inode）。
const FILE_MODE: u32 = 0o644;

/// rootfs の祖先を辿る段数の上限（超えたら fail-closed。無制限の走査を防ぐ）。
const MAX_ANCESTORS: usize = 4096;

/// `/proc/thread-self/{uid,gid}_map` の読み取り上限（バイト）。
const MAX_ID_MAP_BYTES: u64 = 64 * 1024;

/// 適用した bind mount の元の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindSourceType {
    /// ディレクトリ。
    Directory,
    /// 通常ファイル。
    RegularFile,
}

impl From<BindSourceKind> for BindSourceType {
    fn from(kind: BindSourceKind) -> Self {
        match kind {
            BindSourceKind::Directory => Self::Directory,
            BindSourceKind::RegularFile => Self::RegularFile,
        }
    }
}

/// 適用した bind mount 1 件の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BindMountOutcome {
    /// `mounts[]` 内の位置。
    pub index: usize,
    /// コンテナ内のマウント先（正規化済み）。ホスト側のマウント元は載せない。
    pub destination: String,
    /// 元の種別。
    pub source_kind: BindSourceType,
    /// 読み取り専用で載せたか。
    pub read_only: bool,
    /// `noexec` で載せたか。
    pub noexec: bool,
    /// 再帰 bind（`rbind`）か。
    pub recursive: bool,
    /// マウント先（末尾の要素）をこの呼び出しが作ったか。
    pub created_target: bool,
}

/// [`mount_binds`] の成功結果（将来の拡張に備えた非網羅の構造体）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BindMountReport {
    /// 指定順に適用した結果。
    pub mounts: Vec<BindMountOutcome>,
}

/// `set` の bind mount を rootfs（`prepared` の新しい mount top）配下へ指定順に載せる。
///
/// [`MountIsolation`] の証跡が現在の状態と一致しなければ副作用なしに拒否する（fail-closed）。空の集合は何もしない。
/// user namespace なしの経路では適用しない。詳細な契約はモジュール doc を参照。
pub fn mount_binds(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
) -> Result<BindMountReport, ExecError> {
    mount_binds_checked(isolation, prepared, set, &|| {})
}

/// 結合試験専用: [`mount_binds`] と同じ検査・マウントを行い、各件の「移動検査の後・付け替えの直前」で `hook` を呼ぶ
/// （#1916 用。検査後にマウント先を差し替えられても別の場所へ載らないことを、実マウントで決定的に照合するため）。
/// 検証は緩めず、検査後に任意処理を挟むだけ。`exec-test-support` feature を付けたビルドにだけ存在し、通常の利用者は呼ばない。
#[cfg(feature = "exec-test-support")]
#[doc(hidden)]
pub fn mount_binds_with_attach_hook(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
    hook: AttachHook<'_>,
) -> Result<BindMountReport, ExecError> {
    mount_binds_checked(isolation, prepared, set, hook)
}

/// [`mount_binds`] の証跡検証・user namespace の確認と、本番の差し込み点の組み立て。
fn mount_binds_checked(
    isolation: &MountIsolation,
    prepared: &PreparedRootfs,
    set: &BindMountSet,
    before_attach: &dyn Fn(),
) -> Result<BindMountReport, ExecError> {
    isolation.verify_caller(STAGE)?;
    if set.is_empty() {
        return Ok(BindMountReport { mounts: Vec::new() });
    }
    check_user_namespace()?;
    let deps = BindDeps {
        is_shared: &|dir| mount_is_shared(dir, STAGE),
        still_at: &fd_still_at,
        open_tree: &sys::open_tree_clone_bind,
        pre_cloned: &|index| isolation.host_slave_clones().take(index),
        set_attrs: &sys::set_bind_mount_attrs,
        flags_of: &sys::mount_flags,
        attach: &sys::move_mount_empty_path,
        observe: &observe_real,
        mountinfo: &|| read_thread_mountinfo(STAGE),
        source_path: &pinned_source_path,
        source_mnt_id: &pinned_source_mnt_id,
        umount: &umount_fd,
        source_fs_type: &|src| sys::fs_type(src.as_fd()),
        state_identity: &fresh_state_identity,
        before_attach,
    };
    mount_binds_at(prepared.new_root(), set, &deps)
}

/// 副作用・観測の差し込み点（本番は実 syscall、単体テストは記録つきの dry-run。tmpfs の `mount_tmpfs_at` と同形）。
struct BindDeps<'a> {
    /// マウント先が shared propagation か。
    is_shared: &'a dyn Fn(&OwnedFd) -> Result<bool, ExecError>,
    /// 固定した fd が今も期待するホスト側パスにあるか。
    still_at: &'a dyn Fn(&OwnedFd, &Path) -> bool,
    /// 検証済みの元を切り離して複製する。
    open_tree: &'a dyn Fn(&VerifiedBindSourceFd, MountTreeScope) -> Result<OwnedFd, SysError>,
    /// `rslave` の bind について、`MountIsolation::establish_with` が `/` の private 化の前に固定・複製した元と複製を取り出す
    /// （1 件につき 1 回。#2669）。`rslave` でない bind では呼ばない。
    pre_cloned: &'a dyn Fn(usize) -> Option<HostSlaveClone>,
    /// 切り離したマウントへ属性を足す。
    set_attrs: &'a dyn Fn(BorrowedFd<'_>, BindMountAttrs, MountTreeScope) -> Result<(), SysError>,
    /// fd が属するマウントのフラグ。
    flags_of: &'a dyn Fn(BorrowedFd<'_>) -> Result<MountFlags, SysError>,
    /// 切り離したマウントを固定済みのマウント先へ付け替える（from, to）。
    attach: &'a dyn Fn(BorrowedFd<'_>, BorrowedFd<'_>) -> Result<(), SysError>,
    /// 付け替え後の観測（マウント前の先・開き直した先・自分のマウント）。
    observe: &'a dyn Fn(&OwnedFd, &OwnedFd, &OwnedFd) -> Result<BindObservation, ExecError>,
    /// 呼び出しスレッドの mountinfo。
    mountinfo: &'a dyn Fn() -> Result<String, ExecError>,
    /// 固定した元の、呼び出しスレッドの mount namespace での現在のパス（保護対象との照合用）。
    source_path: &'a dyn Fn(&VerifiedBindSourceFd) -> Result<String, ExecError>,
    /// 固定した元の属するマウントの ID。
    source_mnt_id: &'a dyn Fn(&VerifiedBindSourceFd) -> Result<u64, ExecError>,
    /// 自分のマウントを fd 指定で外す（`MNT_DETACH`）。
    umount: &'a dyn Fn(BorrowedFd<'_>) -> Result<(), SysError>,
    /// 固定した元の `statfs.f_type`（疑似 FS の拒否用。#2098）。
    source_fs_type: &'a dyn Fn(&VerifiedBindSourceFd) -> Result<i64, SysError>,
    /// 状態ルートの (dev, path) を適用の時点の mountinfo から作り直す（記録した `chain_path` を辿り直し、fd の `mnt_id` で行を引く。
    /// 作り直せなければ `None`。start の後の下層の改名で FS 内パスが変わっても追従するため。SEC-1・#2166）。
    state_identity: &'a dyn Fn(&ProtectedFsRoot, &[MountRow]) -> Option<FsIdentity>,
    /// 移動検査の後・付け替えの直前に呼ぶ（本番は空。結合試験専用の入口だけが差し込む）。
    before_attach: &'a dyn Fn(),
}

/// `rslave` の bind について、`/` の再帰 private 化の前に固定・複製した元と複製（#2669・OCI-4・CRI-2・SEC-1）。
pub(super) struct HostSlaveClone {
    /// 固定した元（`mount_binds` が、従来の固定の代わりに使う。同じ inode の照合は変えない）。
    source: PinnedSource,
    /// 切り離した複製（`ro`・`noexec` の属性はまだ付いていない）。
    clone: OwnedFd,
}

/// `MountIsolation` が持つ `HostSlaveClone` の置き場（`spec.index()` で取り出す。1 件につき 1 回）。
///
/// `MountIsolation` の `Debug`・`PartialEq` のために、未取得の添字だけで比べる。fd は持ち出せない。
#[derive(Default)]
pub(super) struct HostSlaveClones {
    items: RefCell<Vec<(usize, HostSlaveClone)>>,
}

impl HostSlaveClones {
    /// `index` の複製を取り出す（取り出すと無くなる）。
    pub(super) fn take(&self, index: usize) -> Option<HostSlaveClone> {
        let mut items = self.items.borrow_mut();
        let pos = items.iter().position(|(i, _)| *i == index)?;
        Some(items.swap_remove(pos).1)
    }

    fn indices(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.items.borrow().iter().map(|(i, _)| *i).collect();
        v.sort_unstable();
        v
    }
}

impl std::fmt::Debug for HostSlaveClones {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSlaveClones")
            .field("indices", &self.indices())
            .finish()
    }
}

impl PartialEq for HostSlaveClones {
    fn eq(&self, other: &Self) -> bool {
        self.indices() == other.indices()
    }
}

impl Eq for HostSlaveClones {}

/// mountinfo の `mnt_id` のマウントが「ホストから受ける slave」か（`master:` か `propagate_from:` があり、`shared:` が無い）。
/// 該当なし・複数・書式違反は `Err`（fail-closed。純関数）。
fn source_mount_is_host_slave(info: &str, mnt_id: u64) -> Result<bool, String> {
    let entries = parse_all_mountinfo(info)?;
    let mut found = entries.iter().filter(|e| e.id == mnt_id);
    let Some(e) = found.next() else {
        return Err("no mount entry found for the bind mount source".to_owned());
    };
    if found.next().is_some() {
        return Err("duplicate mount ID in /proc/thread-self/mountinfo".to_owned());
    }
    let slave = e
        .optional
        .iter()
        .any(|f| f.starts_with("master:") || f.starts_with("propagate_from:"));
    let shared = e.optional.iter().any(|f| f.starts_with("shared:"));
    Ok(slave && !shared)
}

/// `rslave` の bind の元を固定し、ホスト側が shared か slave であることを確かめて、`/` の再帰 private 化の前に複製する
/// （`MountIsolation::establish_with` から、`unshare(CLONE_NEWNS)` の直後に呼ぶ。#2669）。
///
/// 再帰 private 化は接続済みの木の `master` 関係を消すため、後からでは `rslave` を表現できない。同じ mount namespace の中で
/// 複製するので `check_mnt` を満たす。元のマウントが slave でない（ホスト側が private）なら、rootfs に触れる前に
/// `FAILED_PRECONDITION` で拒否する（黙って private で載せない。containerd の `ensureSharedOrSlave` 相当）。
/// 疑似 FS・rootfs・状態ルートとの重なりの検査は、従来どおり `mount_binds` が付け替えの前に行う。
pub(super) fn clone_host_slave_sources(set: &BindMountSet) -> Result<HostSlaveClones, ExecError> {
    let clones = HostSlaveClones::default();
    for spec in set
        .mounts()
        .iter()
        .filter(|m| m.propagation() == BindPropagation::HostSlave)
    {
        let source = pin_source(spec)?;
        let mnt_id = pinned_source_mnt_id(&source.fd).map_err(|e| annotate(spec, e))?;
        let info = read_thread_mountinfo(STAGE).map_err(|e| annotate(spec, e))?;
        let is_slave =
            source_mount_is_host_slave(&info, mnt_id).map_err(|why| failed(spec, &why))?;
        if !is_slave {
            return Err(failed(
                spec,
                "the rslave bind mount source is not a shared or slave mount on the host; make it shared (for example `mount --make-rshared`) or remove rslave",
            ));
        }
        let scope = if spec.recursive() {
            MountTreeScope::Recursive
        } else {
            MountTreeScope::MountOnly
        };
        let clone = sys::open_tree_clone_bind(&source.fd, scope)
            .map_err(|e| open_tree_error(spec, e, scope))?;
        clones
            .items
            .borrow_mut()
            .push((spec.index(), HostSlaveClone { source, clone }));
    }
    Ok(clones)
}

/// 拒否リストの 1 行（疑似 FS の `statfs.f_type` と、mountinfo の fstype 欄の名前）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PseudoFs {
    /// `statfs.f_type`（include/uapi/linux/magic.h、非 uapi の 3 つはカーネルのソース。値は `sys` の定数）。
    /// `None` は `f_type` で区別できない FS（devtmpfs。tmpfs と同じ値になる）で、mountinfo の fstype 名だけで判定する（#2129）。
    magic: Option<i64>,
    /// mountinfo の fstype 欄（各 FS の `struct file_system_type` の `.name`）。
    name: &'static str,
}

/// bind mount の元として拒否する疑似 FS の**拒否リスト**（#2098・#2065 案 B。SEC-1。SSOT。適用の段だけが使う）。
///
/// 一次情報は Linux の `include/uapi/linux/magic.h` と、uapi に無い 3 つ（configfs・mqueue・fusectl）のソース
/// （`fs/configfs/mount.c`・`ipc/mqueue.c`・`fs/fuse/control.c`）。
///
/// # Linux v7.0 での確認（#2129。この表が出典の SSOT。`sys` の各定数はここを参照する）
///
/// - magic（`include/uapi/linux/magic.h`）: DEBUGFS:13・SECURITYFS:14・SELINUX:15・SMACK:16・XENFS:26・PSTOREFS:35・EFIVARFS:36・
///   FUSE_SUPER:39・CGROUP:70・CGROUP2:71・RDTGROUP:73・TRACEFS:77・BINFMTFS:83・DEVPTS_SUPER:84・BINDERFS_SUPER:85・
///   PROC_SUPER:88・SYSFS:90・NSFS:95・BPF_FS:96（行番号）。uapi に無い 3 つは `fs/configfs/mount.c:23`・`ipc/mqueue.c:50`・
///   `fs/fuse/control.c:16`
/// - fstype 名（`struct file_system_type` の `.name`）: proc `fs/proc/root.c:358`・sysfs `fs/sysfs/mount.c:93`・
///   debugfs `fs/debugfs/inode.c:326`・tracefs `fs/tracefs/inode.c:538`・securityfs `security/inode.c:73`・
///   cgroup/cgroup2 `kernel/cgroup/cgroup.c:2394`/`:2402`・bpf `kernel/bpf/inode.c:1076`・configfs `fs/configfs/mount.c:117`・
///   pstore `fs/pstore/inode.c:499`・efivarfs `fs/efivarfs/super.c:533`・selinuxfs `security/selinux/selinuxfs.c:2102`・
///   smackfs `security/smack/smackfs.c:2978`・binfmt_misc `fs/binfmt_misc.c:1023`・fusectl `fs/fuse/control.c:360`・
///   resctrl `fs/resctrl/rdtgroup.c:3193`・xenfs `drivers/xen/xenfs/super.c:89`・nsfs `fs/nsfs.c:677`・mqueue `ipc/mqueue.c:1614`・
///   devpts `fs/devpts/inode.c:454`・binder `drivers/android/binderfs.c:750`・devtmpfs `drivers/base/devtmpfs.c:66`/`:107`
///
/// **devtmpfs**: superblock は `internal_fs_type`（名前 `devtmpfs`）が作り、`statfs.f_type` は tmpfs（または ramfs）と同じ値に
/// なるため `magic` は `None`。適用後の mountinfo（`find_pseudo_fs_in_subtree`。自分のマウント自身の fstype 欄も照合するため
/// 非再帰の bind でも効く）の名前だけで判定する。
///
/// **拒否しないもの（文書化済みの限界。#2129・#2166）**: FUSE（`fuse`・`fuseblk`・`fuse.<subtype>`）と overlayfs は、データを持つ FS として
/// 受ける。overlayfs の層は `check_overlay_layers` が super_options から照合する（#2166）。FUSE デーモンが見せる中身は検出しない。
/// カーネルの版を上げるときの見直し手順は `docs/api/bind-mounts.md`。ホストのプロセス・カーネル・LSM・cgroup 階層・BPF・
/// 名前空間などの情報や制御口を見せる FS を並べる。`proc` は `linux.maskedPaths`・`readonlyPaths` が効かない別の宛先から
/// 見えること、`nsfs` は `ip netns` などが通常ファイルへ bind した名前空間の固定（`/run/netns/*`）を辿れてしまうこと、
/// `mqueue` はホストの IPC namespace の分離を越えること、`devpts`・`binder` は `nodev` で開けないが安全側に倒すこと、
/// `cgroup`（v1）は CORE-4 で非対応でも元としてはホストの階層を見せるため v2 と同じく拒否すること、が理由。
/// 通常のデータを持つ FS（ext4・xfs・btrfs・tmpfs・overlayfs・NFS・FUSE など）は拒否しない。
const PSEUDO_FS_DENYLIST: [PseudoFs; 22] = [
    PseudoFs {
        magic: Some(sys::PROC_MAGIC),
        name: "proc",
    },
    PseudoFs {
        magic: Some(sys::SYSFS_MAGIC),
        name: "sysfs",
    },
    PseudoFs {
        magic: Some(sys::DEBUGFS_MAGIC),
        name: "debugfs",
    },
    PseudoFs {
        magic: Some(sys::TRACEFS_MAGIC),
        name: "tracefs",
    },
    PseudoFs {
        magic: Some(sys::SECURITYFS_MAGIC),
        name: "securityfs",
    },
    PseudoFs {
        magic: Some(sys::CGROUP_SUPER_MAGIC),
        name: "cgroup",
    },
    PseudoFs {
        magic: Some(sys::CGROUP2_MAGIC),
        name: "cgroup2",
    },
    PseudoFs {
        magic: Some(sys::BPF_FS_MAGIC),
        name: "bpf",
    },
    PseudoFs {
        magic: Some(sys::CONFIGFS_MAGIC),
        name: "configfs",
    },
    PseudoFs {
        magic: Some(sys::PSTOREFS_MAGIC),
        name: "pstore",
    },
    PseudoFs {
        magic: Some(sys::EFIVARFS_MAGIC),
        name: "efivarfs",
    },
    PseudoFs {
        magic: Some(sys::SELINUX_MAGIC),
        name: "selinuxfs",
    },
    PseudoFs {
        magic: Some(sys::SMACK_MAGIC),
        name: "smackfs",
    },
    PseudoFs {
        magic: Some(sys::BINFMTFS_MAGIC),
        name: "binfmt_misc",
    },
    PseudoFs {
        magic: Some(sys::FUSE_CTL_SUPER_MAGIC),
        name: "fusectl",
    },
    PseudoFs {
        magic: Some(sys::RDTGROUP_SUPER_MAGIC),
        name: "resctrl",
    },
    PseudoFs {
        magic: Some(sys::XENFS_SUPER_MAGIC),
        name: "xenfs",
    },
    PseudoFs {
        magic: Some(sys::NSFS_MAGIC),
        name: "nsfs",
    },
    PseudoFs {
        magic: Some(sys::MQUEUE_MAGIC),
        name: "mqueue",
    },
    PseudoFs {
        magic: Some(sys::DEVPTS_MAGIC),
        name: "devpts",
    },
    PseudoFs {
        magic: Some(sys::BINDERFS_SUPER_MAGIC),
        name: "binder",
    },
    PseudoFs {
        magic: None,
        name: "devtmpfs",
    },
];

/// 固定した fd の `statfs.f_type` を拒否リストと照合する純関数。
fn pseudo_fs_by_magic(f_type: i64) -> Option<&'static PseudoFs> {
    PSEUDO_FS_DENYLIST.iter().find(|p| p.magic == Some(f_type))
}

/// mountinfo の fstype 欄を拒否リストの名前と**完全一致**で照合する純関数（`fuse.lxcfs` などの派生名は一致しない）。
fn pseudo_fs_by_name(fstype: &str) -> Option<&'static PseudoFs> {
    PSEUDO_FS_DENYLIST.iter().find(|p| p.name == fstype)
}

/// 疑似 FS の拒否を作る。message の末尾には拒否リストの静的な FS 名だけを足す（ホスト側のパスは載せない。SEC-4）。
fn pseudo_fs_violation(spec: &BindMountSpec, fs: &PseudoFs) -> ExecError {
    let mut err = violation(spec, ViolationReason::BindSourcePseudoFs);
    err.message.push_str(&format!(" ({})", fs.name));
    err
}

/// 付け替え前後の観測値（[`check_new_bind`] の入力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BindObservation {
    /// マウント前に固定した先が属するマウントの ID。
    before_mnt_id: u64,
    /// 開き直した先が属するマウントの ID。
    after_mnt_id: u64,
    /// 自分のマウント（複製の fd）の ID。
    own_mnt_id: u64,
    /// 開き直した先が属するマウントのフラグ。
    flags: MountFlags,
    /// 開き直した先の `(st_dev, st_ino)`。
    dev_ino: (u64, u64),
}

/// 要求した属性（`nosuid`・`nodev` は常に付くため持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expected {
    read_only: bool,
    noexec: bool,
}

/// 1 件の適用で rootfs・mount namespace に加えた変更の記録（失敗時の [`roll_back_binds`] が使う）。
struct Applied<'a> {
    /// マウント先の要素列（正規化済み）。
    names: Vec<&'a OsStr>,
    /// この呼び出しの `mkdirat` が成功した要素の添字（昇順）。
    created_dirs: Vec<usize>,
    /// 作った各ディレクトリの `(要素の添字, (st_dev, st_ino))`（作成直後に記録。後始末は一致したものだけ消す）。
    created_dir_ids: Vec<(usize, (u64, u64))>,
    /// この呼び出しが作った空ファイル（末尾の要素）の `(st_dev, st_ino)`。
    created_file: Option<(u64, u64)>,
    /// 付け替えた「自分のマウントのルート」を指す fd（付け替え直後に保持し、事後検証に通らなくても外せる）。
    mounted: Option<OwnedFd>,
}

impl<'a> Applied<'a> {
    fn new(spec: &'a BindMountSpec) -> Self {
        Self {
            names: spec
                .destination()
                .as_str()
                .split('/')
                .filter(|e| !e.is_empty())
                .map(OsStr::new)
                .collect(),
            created_dirs: Vec::new(),
            created_dir_ids: Vec::new(),
            created_file: None,
            mounted: None,
        }
    }
}

/// 適用中に共通の値。
struct Ctx<'a> {
    /// rootfs（新しい mount top）の fd。
    root: BorrowedFd<'a>,
    /// rootfs のホスト側実パス（移動検査用。メッセージ・監査には載せない）。
    host_root: PathBuf,
    /// rootfs とその祖先の `(st_dev, st_ino)`。
    rootfs_ids: Vec<(u64, u64)>,
    /// start の段が固定した状態ルートの inode の鎖（自身が先頭、`/` が末尾。SEC-1・#2066）。
    state_chains: Vec<&'a [(u64, u64)]>,
    /// 状態ルートの記録したホスト側パスを適用の段で辿り直した鎖（#2129）。固定した実体と先頭が一致しない・辿れない
    /// （start の後に移動・改名・差し替えがあった）場合は `None` で、元の判定の後に `FAILED_PRECONDITION` にする。
    fresh_state_chains: Option<Vec<Vec<(u64, u64)>>>,
    /// start の段が検査した保護対象（状態ストアのルート）の実体。空なら照合しない。
    protected: &'a [ProtectedFsRoot],
    deps: &'a BindDeps<'a>,
}

/// [`mount_binds`] の本体。`root` は rootfs（新しい mount top）の fd。
fn mount_binds_at(
    root: BorrowedFd<'_>,
    set: &BindMountSet,
    deps: &BindDeps<'_>,
) -> Result<BindMountReport, ExecError> {
    if set.is_empty() {
        return Ok(BindMountReport { mounts: Vec::new() });
    }
    let protected = set.protected_roots();
    // 状態ルートの実体を固定できていない集合は、inode で照合できないため拒否する（fail-closed。SEC-1・#2066）。
    // 保護対象が無い集合（start を通らない単体テストの経路）は照合しない。
    let state_chains: Vec<&[(u64, u64)]> = protected
        .iter()
        .filter(|p| !p.is_containment_only() && !p.inode_chain().is_empty())
        .map(|p| p.inode_chain())
        .collect();
    if !protected.is_empty() && state_chains.is_empty() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            STAGE,
            "the state store root identity is missing, so bind mount sources cannot be checked",
        ));
    }
    let fresh_state_chains = resolve_fresh_state_chains(protected);
    let ctx = Ctx {
        root,
        host_root: root_display(root),
        rootfs_ids: rootfs_identity_chain(root)?,
        state_chains,
        fresh_state_chains,
        protected,
        deps,
    };
    // 件数は `BindMountSet`（`CONFIG_MAX_MOUNTS` 以下）で上限が決まっている。
    let mut mounts = Vec::with_capacity(set.mounts().len());
    let mut applied: Vec<Applied<'_>> = Vec::with_capacity(set.mounts().len());
    for spec in set.mounts() {
        let mut state = Applied::new(spec);
        let result = apply_one(&ctx, spec, &mut state);
        let created_target =
            state.created_file.is_some() || state.created_dirs.contains(&last_index(&state));
        applied.push(state);
        match result {
            Ok(kind) => mounts.push(BindMountOutcome {
                index: spec.index(),
                destination: spec.destination().as_str().to_owned(),
                source_kind: kind.into(),
                read_only: spec.read_only(),
                noexec: spec.noexec(),
                recursive: spec.recursive(),
                created_target,
            }),
            Err(e) => {
                let failures = roll_back_binds(&ctx, &applied);
                return Err(with_cleanup_failures(e, &failures));
            }
        }
    }
    Ok(BindMountReport { mounts })
}

/// 状態ルートの記録したホスト側パスを `/` から辿り直して鎖を作る（SEC-1・#2129）。start が固定した実体（先頭の inode）と
/// 一致しない・辿れないものが 1 つでもあれば `None`（fail-closed）。start の後に状態ルートが別の親へ付け替えられると、
/// 固定した鎖には新しい親が入らず祖先の判定をすり抜けるため、毎回辿り直した新しい鎖でも照合する。
fn resolve_fresh_state_chains(protected: &[ProtectedFsRoot]) -> Option<Vec<Vec<(u64, u64)>>> {
    let mut fresh_all = Vec::new();
    for p in protected
        .iter()
        .filter(|p| !p.is_containment_only() && !p.inode_chain().is_empty())
    {
        let fresh = dir_identity_chain(p.chain_path()?)?;
        if fresh.first() != p.inode_chain().first() {
            return None;
        }
        fresh_all.push(fresh);
    }
    Some(fresh_all)
}

/// 末尾の要素の添字（空なら 0。`Applied::new` は空を作り得るが、`apply_one` が先に拒否する）。
fn last_index(state: &Applied<'_>) -> usize {
    state.names.len().saturating_sub(1)
}

/// 1 件の適用。成功時は元の種別を返す。
fn apply_one(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    state: &mut Applied<'_>,
) -> Result<BindSourceKind, ExecError> {
    let deps = ctx.deps;
    // `rslave` の bind は、`establish_with` が `/` の private 化の前に固定・複製した元と複製を使う（そこで master 関係が
    // 消える前に複製しておく必要がある。取り出せなければ establish を通っていないため fail-closed。#2669）。
    let (PinnedSource { fd: src, dir_ids }, mut pre_clone) = if spec.propagation()
        == BindPropagation::HostSlave
    {
        let Some(HostSlaveClone { source, clone }) = (deps.pre_cloned)(spec.index()) else {
            return Err(annotate(
                spec,
                ExecError::new(
                    ErrorCode::Internal,
                    STAGE,
                    "the rslave bind mount source was not cloned before the root was made private",
                ),
            ));
        };
        (source, Some(clone))
    } else {
        (pin_source(spec)?, None)
    };
    // 固定した fd の FS の種類を見る（パスで再解決しない）。procfs・sysfs などの疑似 FS は、宛先に何も作る前に拒否する（#2098・SEC-1）。
    let f_type = (deps.source_fs_type)(&src)
        .map_err(|e| mount_api_error(spec, e, "fstatfs(bind mount source)"))?;
    if let Some(fs) = pseudo_fs_by_magic(f_type) {
        return Err(pseudo_fs_violation(spec, fs));
    }
    // rootfs（と bundle・その祖先）・状態ルートとの重なりを (st_dev, st_ino) で照合する。mountinfo の照合とは独立の層。
    if let Some(reason) =
        judge_source_inodes(src.dev_ino(), &dir_ids, &ctx.rootfs_ids, &ctx.state_chains)
    {
        return Err(violation(spec, reason));
    }
    // 状態ルートが start の後に移動・差し替えられていないかを、辿り直した鎖で確かめる（#2129）。固定した鎖での判定を先に行い、
    // 既存の違反（と監査）を保つ。message にホスト側のパスは載せない（SEC-4）。
    let Some(fresh) = &ctx.fresh_state_chains else {
        return Err(failed(
            spec,
            "the state store root moved after start, so bind mount sources cannot be checked",
        ));
    };
    let fresh_chains: Vec<&[(u64, u64)]> = fresh.iter().map(Vec::as_slice).collect();
    if let Some(reason) =
        judge_source_inodes(src.dev_ino(), &dir_ids, &ctx.rootfs_ids, &fresh_chains)
    {
        return Err(violation(spec, reason));
    }
    // 保護対象が overlayfs の上にあるとき、その層（下層 FS 上の実パス）を経由した別名を、宛先に何かを作る前に塞ぐ
    // （逆方向の照合。#2317・SEC-1）。mountinfo は 1 回だけ読み、続く mountinfo の照合にも使い回す。
    if !ctx.protected.is_empty() {
        let info = (deps.mountinfo)()?;
        let layers = protected_overlay_layers(ctx, spec, &info)?;
        if let Some(reason) = judge_source_against_layers(src.dev_ino(), &dir_ids, &layers) {
            return Err(violation(spec, reason));
        }
        check_source_not_protected(ctx, spec, &src, &info, &layers)?;
    }
    let kind = src.kind();
    let dest = pin_target(ctx, spec, kind, state)?;
    if (deps.is_shared)(&dest)? {
        return Err(violation(spec, ViolationReason::TargetOnSharedMount));
    }
    let scope = if spec.recursive() {
        MountTreeScope::Recursive
    } else {
        MountTreeScope::MountOnly
    };
    let expected = Expected {
        read_only: spec.read_only(),
        noexec: spec.noexec(),
    };
    let clone = match pre_clone.take() {
        Some(clone) => clone,
        None => (deps.open_tree)(&src, scope).map_err(|e| open_tree_error(spec, e, scope))?,
    };
    (deps.set_attrs)(
        clone.as_fd(),
        BindMountAttrs {
            read_only: expected.read_only,
            noexec: expected.noexec,
        },
        scope,
    )
    .map_err(|e| mount_api_error(spec, e, "mount_setattr(bind mount)"))?;
    let flags = (deps.flags_of)(clone.as_fd())
        .map_err(|e| mount_api_error(spec, e, "fstatfs(detached bind mount)"))?;
    check_flags(flags, expected).map_err(|why| failed(spec, &format!("before attach: {why}")))?;
    // fd 固定後に別プロセスがマウント先（または祖先）を改名・移動・削除していれば拒否する。この確認から
    // 付け替えまでに移動された場合も、付け替えは固定した fd（検証済みの実体）にしか載らず rootfs の別の場所を
    // 覆わない。事後検証が名前の位置に自分のマウントが無いことを検出して失敗させ、後始末が自分のマウントを外す。
    let expected_path = state
        .names
        .iter()
        .fold(ctx.host_root.clone(), |p, n| p.join(n));
    if !(deps.still_at)(&dest, &expected_path) {
        return Err(violation(spec, ViolationReason::TargetMoved));
    }
    (deps.before_attach)();
    (deps.attach)(clone.as_fd(), dest.as_fd())
        .map_err(|e| mount_api_error(spec, e, "move_mount(bind mount)"))?;
    // 付け替え直後に自分のマウントの fd を保持する（事後検証に通らなくても後始末が外せる）。
    state.mounted = Some(clone);
    let after = reopen_target(ctx, spec, state)?;
    let Some(own) = state.mounted.as_ref() else {
        return Err(failed(spec, "the bind mount handle was lost"));
    };
    let observed = (deps.observe)(&dest, &after, own)?;
    check_new_bind(&observed, expected, src.dev_ino()).map_err(|why| failed(spec, &why))?;
    let info = (deps.mountinfo)()?;
    check_bind_subtree_with(
        &info,
        observed.own_mnt_id,
        expected,
        spec.recursive(),
        spec.propagation() == BindPropagation::HostSlave,
    )
    .map_err(|why| failed(spec, &why))?;
    // 付け替えた木そのものの fstype を照合する（`rbind` の配下の疑似 FS を含む。検査から複製までの TOCTOU が無い）。
    match find_pseudo_fs_in_subtree(&info, observed.own_mnt_id, spec.recursive()) {
        Ok(None) => {}
        Ok(Some(fs)) => return Err(pseudo_fs_violation(spec, fs)),
        Err(why) => return Err(failed(spec, &why)),
    }
    // 付け替えた木の overlayfs の層（lowerdir・upperdir・workdir）が rootfs・状態ルートの別名でないかを照合する（#2166）。
    check_overlay_layers(ctx, spec, &info, observed.own_mnt_id)?;
    Ok(kind)
}

/// 1 件の bind で照合する overlayfs の層の合計の上限。`rbind` の配下に overlay が多数あっても、パスを辿る回数を頭打ちにする。
const OVERLAY_LAYER_BUDGET: usize = 4096;

/// 付け替えた自分のマウント（`rbind` なら配下全体）のうち fstype が `overlay` のものについて、層のパスを各々 `/` から
/// `O_NOFOLLOW` で辿り、rootfs・状態ルートの実体と同一・祖先・子孫でないことを inode で照合する（SEC-1・OCI-4・#2166）。
///
/// overlayfs は別の superblock なので、元が overlay 上にあると inode の照合も mountinfo の `(dev, path)` の照合も
/// 下層の実体を見ない。照合は付け替えた木そのものに対して行い、検査から複製までの TOCTOU が無い。違反は既存の理由
/// （`BindSourceReachesStateRoot`・`BindSourceContainsRootfs`）で返し、message・監査には層のパスを載せない（SEC-4）。
/// 解析できない・現在の namespace で解決できない（相対パス・消えた層・symlink・ディレクトリでない）・上限超過・
/// 層が別の overlay の上にある（入れ子。再帰的には照合しない）場合は fail-closed の `FAILED_PRECONDITION`。
fn check_overlay_layers(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    info: &str,
    own_id: u64,
) -> Result<(), ExecError> {
    // 行数上限つきの解析を先に行う（#2536）。
    let rows = parse_mountinfo(info)
        .ok_or_else(|| failed(spec, "malformed or oversized /proc/thread-self/mountinfo"))?;
    let entries = parse_all_mountinfo(info).map_err(|why| failed(spec, &why))?;
    let members =
        subtree_members(&entries, own_id, spec.recursive()).map_err(|why| failed(spec, &why))?;
    let unchecked = || {
        failed(
            spec,
            "the overlay layers of the bind mount source cannot be checked",
        )
    };
    let mut budget = OVERLAY_LAYER_BUDGET;
    let mut found_overlay = false;
    // inode の照合をすべての層で終えてから、mountinfo の照合に進む（違反の理由を inode 側で先に確定させる）。
    let mut resolved: Vec<(u64, String)> = Vec::new();
    for member in members.iter().filter(|e| e.fstype == "overlay") {
        found_overlay = true;
        let layers = resolve_overlay_layers(&entries, member.super_options, &mut budget)
            .map_err(|()| unchecked())?;
        for layer in layers {
            let Some((&layer_id, layer_dirs)) = layer.chain.split_first() else {
                return Err(unchecked());
            };
            let mut state_chains: Vec<&[(u64, u64)]> = ctx.state_chains.clone();
            if let Some(fresh) = &ctx.fresh_state_chains {
                state_chains.extend(fresh.iter().map(Vec::as_slice));
            }
            if let Some(reason) =
                judge_source_inodes(layer_id, layer_dirs, &ctx.rootfs_ids, &state_chains)
            {
                return Err(violation(spec, reason));
            }
            // mountinfo の (dev, path) でも照合する。inode の鎖は bind mount を挟んだ祖先関係（状態ルートの別名の配下を指す層など）を
            // 映さないため、層の属するマウントの ID から (dev, path) を求め、保護対象・子マウントと突き合わせる（再帰的に配下も見る）。
            resolved.push((layer.mnt_id, layer.path));
        }
    }
    for (mnt_id, layer) in &resolved {
        check_place_not_protected(
            ctx,
            spec,
            &rows,
            *mnt_id,
            layer,
            PlaceScope {
                recursive: true,
                is_dir: true,
            },
            &ProtectedOverlayLayers::default(),
        )?;
    }
    // 層のパスの開き直しは、overlay が保持する実際の backing directory と同一とは限らない（overlay を作った後に lowerdir の
    // パスを別の bind mount で覆うと、開き直しは覆った側を安全と判定し、実際には元の層が公開される）。overlayfs は層の
    // 実体を識別できる情報を公開しないため、同一性を保証できない overlay の元は、上の照合に通っても fail-closed で拒否する。
    //
    // 注意（#2317）: この判定を外すと fail-open になる。上の照合は必要条件にすぎず、同一性の保証ではない
    // （層を後から別の bind mount で覆う等で、開き直した層と overlay の実体が食い違う）。外す場合は
    // `sec1_2317_overlay_source_is_always_rejected_even_when_layers_pass` を見直すこと。
    if found_overlay {
        return Err(failed(
            spec,
            "the overlay layers of the bind mount source cannot be verified to be the directories they were created from",
        ));
    }
    Ok(())
}

/// 開き直して解決した overlayfs の層 1 つ。
struct ResolvedLayer {
    /// 層自身を先頭、`/` を末尾にした `(st_dev, st_ino)` の鎖。
    chain: Vec<(u64, u64)>,
    /// 層の属するマウントの ID（開いた fd の fdinfo の `mnt_id`）。
    mnt_id: u64,
    /// 層のパス（`/` からの絶対パス）。
    path: String,
}

/// overlayfs の super_options の層を `/` から `O_NOFOLLOW` で辿って解決する（順方向の `check_overlay_layers` と、
/// 保護対象が overlay 上にあるときの逆方向の `protected_overlay_layers` が共有する。SEC-1・#2166・#2317）。
///
/// 解析できない・上限（`budget` は呼び出し側の合計）超過・解決できない（相対パス・消えた層・symlink・ディレクトリでない）・
/// 層が別の overlay の上にある（入れ子）・`.`/`..`/連続スラッシュを含むパス（文字列の接頭辞照合が成り立たない）は `Err`（fail-closed）。
fn resolve_overlay_layers(
    entries: &[MountInfoEntry<'_>],
    super_options: &str,
    budget: &mut usize,
) -> Result<Vec<ResolvedLayer>, ()> {
    let layers = overlay_layer_paths(super_options).map_err(|_| ())?;
    *budget = budget.checked_sub(layers.len()).ok_or(())?;
    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        let (chain, mnt_id) = dir_identity_chain_with_mnt_id(&layer).ok_or(())?;
        // 層が別の overlay の上にある場合は、その層の実体をさらに辿る必要があるため拒否で代える。
        if entries
            .iter()
            .any(|e| e.id == mnt_id && e.fstype == "overlay")
        {
            return Err(());
        }
        if layer
            .split('/')
            .skip(1)
            .any(|c| c == "." || c == ".." || (c.is_empty() && layer != "/"))
        {
            return Err(());
        }
        out.push(ResolvedLayer {
            chain,
            mnt_id,
            path: layer,
        });
    }
    Ok(out)
}

/// 保護対象が overlay 上にあるときの層 1 つ（下層 FS 上の実体）。
#[derive(Clone)]
struct ProtectedLayer {
    /// 層自身を先頭、`/` を末尾にした `(st_dev, st_ino)` の鎖。
    chain: Vec<(u64, u64)>,
    /// 層の mountinfo 上の `(dev, path)`。bind mount を挟んだ別名の検出に使う。
    identity: FsIdentity,
}

/// 保護対象（状態ルート・rootfs・bundle）が overlay 上にあるときの、その層の集合（逆方向の別名の照合。SEC-1・OCI-4・SEC-5・#2317）。
///
/// overlay と下層 FS は `st_dev` が異なるため、保護対象が overlay 上にあると、bind の元が層の実パス（下層 FS 上）を指しても
/// inode の照合も mountinfo の `(dev, path)` の照合も一致しない。層を保護対象に加えて塞ぐ。
#[derive(Default)]
struct ProtectedOverlayLayers {
    /// 状態ルート由来。元が同一・祖先・子孫なら `BindSourceReachesStateRoot`。
    state: Vec<ProtectedLayer>,
    /// rootfs・bundle 由来。層の内側の対応（redirect_dir・metacopy）は信頼できず、配下のどこが rootfs の祖先に当たるかを
    /// 決められないため、同一・祖先・子孫のすべてを `BindSourceContainsRootfs` で拒否する（層は実行基盤の内部の backing storage で、
    /// 配下を元にできなくても実害は小さい）。
    contained: Vec<ProtectedLayer>,
    /// `ctx.protected` と同じ添字で、各保護対象自身の層が属する FS の dev（状態ルート由来のみ。それ以外は空）。
    /// ハードリンクの検査は、その保護対象自身の層の dev とだけ対にする（他の保護対象の層の FS と混ぜない）。
    devs_by_root: Vec<Vec<String>>,
}

impl ProtectedOverlayLayers {
    /// `idx` 番目の保護対象自身の層が属する FS の dev（ハードリンクの検査で、その保護対象の dev と同じ FS とみなす）。
    fn state_devs_of(&self, idx: usize) -> impl Iterator<Item = &str> {
        self.devs_by_root
            .get(idx)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }
}

/// `dev` の FS が overlay なら、その層を解決する。overlay でなければ空。同じ dev に overlay と他の fstype が混在する、
/// super_options が食い違う、または `dev` の行が mountinfo に 1 つも無い（保護対象の FS を確認できない）場合は
/// `Err`（fail-closed。#2536）。
fn overlay_layers_of_dev(
    entries: &[MountInfoEntry<'_>],
    rows: &[MountRow],
    dev: &str,
    budget: &mut usize,
) -> Result<Vec<ProtectedLayer>, ()> {
    let on_dev: Vec<&MountInfoEntry<'_>> = entries.iter().filter(|e| e.dev == dev).collect();
    let overlays = on_dev.iter().filter(|e| e.fstype == "overlay").count();
    let Some(first) = on_dev.first() else {
        return Err(());
    };
    if overlays == 0 {
        return Ok(Vec::new());
    }
    if overlays != on_dev.len()
        || on_dev
            .iter()
            .any(|e| e.super_options != first.super_options)
    {
        return Err(());
    }
    resolve_overlay_layers(entries, first.super_options, budget)?
        .into_iter()
        .map(|l| {
            let identity = fs_identity(rows, l.mnt_id, &l.path).ok_or(())?;
            Ok(ProtectedLayer {
                chain: l.chain,
                identity,
            })
        })
        .collect()
}

/// 保護対象の属する FS が overlay なら、その層を解決して保護対象に加える（SEC-1・#2317）。
///
/// 保護対象の dev と同じ dev の行が `overlay` かを適用の時点の mountinfo で判定する。解決できない場合（Docker のように `/` が
/// overlay で下層が見えない環境を含む）は `FAILED_PRECONDITION`。message に層のパスは載せない（SEC-4）。
/// 残余: 開き直した層が overlay の実際の backing directory と同一とは限らない（#2166 と同じ）。逆方向では一律拒否にせず、
/// 検出できる範囲を照合する（一律拒否にすると保護対象が overlay 上にある限りどの bind も拒否になるため）。
fn protected_overlay_layers(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    info: &str,
) -> Result<ProtectedOverlayLayers, ExecError> {
    let unchecked = || {
        failed(
            spec,
            "the overlay layers of a protected root cannot be checked",
        )
    };
    // 行数上限つきの解析を先に行う（#2536）。
    let rows = parse_mountinfo(info)
        .ok_or_else(|| failed(spec, "malformed or oversized /proc/thread-self/mountinfo"))?;
    let entries = parse_all_mountinfo(info).map_err(|why| failed(spec, &why))?;
    let mut budget = OVERLAY_LAYER_BUDGET;
    let mut by_dev: Vec<(&str, Vec<ProtectedLayer>)> = Vec::new();
    let mut out = ProtectedOverlayLayers::default();
    for p in ctx.protected {
        let idx = if let Some(i) = by_dev.iter().position(|(d, _)| *d == p.dev()) {
            i
        } else {
            // 保護対象の dev の行が無いと FS の種別を確認できず、逆方向の照合が素通りする（fail-open）ため拒否する（#2536）。
            if !entries.iter().any(|e| e.dev == p.dev()) {
                return Err(failed(
                    spec,
                    "the filesystem of a protected root is not found in mountinfo",
                ));
            }
            let layers = overlay_layers_of_dev(&entries, &rows, p.dev(), &mut budget)
                .map_err(|()| unchecked())?;
            by_dev.push((p.dev(), layers));
            by_dev.len() - 1
        };
        let Some((_, layers)) = by_dev.get(idx) else {
            return Err(unchecked());
        };
        let dst = if p.is_containment_only() {
            &mut out.contained
        } else {
            &mut out.state
        };
        dst.extend(layers.iter().cloned());
        out.devs_by_root.push(if p.is_containment_only() {
            Vec::new()
        } else {
            layers.iter().map(|l| l.identity.dev.clone()).collect()
        });
    }
    Ok(out)
}

/// 元を保護対象の層と inode で照合する純関数（#2317）。状態ルート由来の層は同一・祖先・子孫で `BindSourceReachesStateRoot`、
/// rootfs・bundle 由来の層は同一・祖先・子孫のすべてで `BindSourceContainsRootfs`。
fn judge_source_against_layers(
    src: (u64, u64),
    src_dirs: &[(u64, u64)],
    layers: &ProtectedOverlayLayers,
) -> Option<ViolationReason> {
    let chains: Vec<&[(u64, u64)]> = layers.state.iter().map(|l| l.chain.as_slice()).collect();
    if let Some(reason) = judge_source_inodes(src, src_dirs, &[], &chains) {
        return Some(reason);
    }
    let hit = layers
        .contained
        .iter()
        .any(|l| l.chain.contains(&src) || l.chain.first().is_some_and(|f| src_dirs.contains(f)));
    hit.then_some(ViolationReason::BindSourceContainsRootfs)
}
/// 固定した元（と再帰 bind で一緒に公開される配下のマウント）が保護対象（状態ストアのルート）に到達しないことを、
/// 適用の時点の mountinfo で照合する（SEC-1・#1915）。start の段の検査は一時点のパス解決に対するもので、
/// その後の改名・マウントによる差し替え（restart では検査が再実行されない）を、ここで固定した fd の現在位置から塞ぐ。
/// 読めない・解釈できない・位置を特定できない場合は fail-closed。保護対象が無ければ何もしない。
fn check_source_not_protected(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    src: &VerifiedBindSourceFd,
    info: &str,
    layers: &ProtectedOverlayLayers,
) -> Result<(), ExecError> {
    if ctx.protected.is_empty() {
        return Ok(());
    }
    let real = (ctx.deps.source_path)(src)?;
    let mnt_id = (ctx.deps.source_mnt_id)(src)?;
    let mounts = parse_mountinfo(info)
        .ok_or_else(|| failed(spec, "malformed or oversized /proc/thread-self/mountinfo"))?;
    // 元の属するマウントは固定した fd の mnt_id で特定する（パスの最長一致は overmount で食い違い得る）。
    let Some(identity) = fs_identity(&mounts, mnt_id, &real) else {
        return Err(failed(
            spec,
            "the mount of the pinned bind mount source is not found in mountinfo",
        ));
    };
    // 通常ファイルのハードリンクは別名のパスを持たず、パス・マウントの照合では状態ファイルとの同一性が分からない。
    // 保護対象と同じファイルシステム上でリンク数が 2 以上の通常ファイルは、状態ファイルへのリンクかもしれないため拒否する
    // （fail-closed）。保護対象が overlay 上にあるときは状態ファイルの実体が層の FS 上にあるため、層の dev も同じ FS とみなす（#2317）。
    if src.kind() == BindSourceKind::RegularFile
        && src.nlink() > 1
        && ctx.protected.iter().enumerate().any(|(i, p)| {
            !p.is_containment_only()
                && (p.dev() == identity.dev || layers.state_devs_of(i).any(|d| d == identity.dev))
        })
    {
        return Err(violation(spec, ViolationReason::BindSourceReachesStateRoot));
    }
    check_place_not_protected(
        ctx,
        spec,
        &mounts,
        mnt_id,
        &real,
        PlaceScope {
            recursive: spec.recursive(),
            is_dir: src.kind() == BindSourceKind::Directory,
        },
        layers,
    )
}

/// [`check_place_not_protected`] の照合範囲（引数の数を抑えるための束ね）。
#[derive(Clone, Copy)]
struct PlaceScope {
    /// 配下のマウントも照合するか（`rbind`）。
    recursive: bool,
    /// 場所がディレクトリか（ハードリンクの検査の対象）。
    is_dir: bool,
}

/// 固定した場所（`mnt_id` のマウントの `real`。`recursive` なら配下のマウントも）が保護対象に到達しないことを mountinfo の
/// `(dev, path)` で照合する（`check_source_not_protected` の本体。overlayfs の層の照合にも使う。SEC-1・#1915・#2166）。
fn check_place_not_protected(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    mounts: &[MountRow],
    mnt_id: u64,
    real: &str,
    scope: PlaceScope,
    layers: &ProtectedOverlayLayers,
) -> Result<(), ExecError> {
    let PlaceScope { recursive, is_dir } = scope;
    // ディレクトリ元の配下にある状態ファイルの別名は走査では見つけられない。代わりに start の段が状態ルート側の
    // 状態ファイルのリンク数を調べており（`has_hard_linked_files`）、別名を持つ状態ファイルがあるなら、同じ FS 上の
    // ディレクトリ元は別名を含み得るため拒否する（fail-closed。SEC-1）。
    // 再帰 bind では子マウント（別 FS を含む）も一緒に公開されるため、公開されるすべてのデバイスで照合する。
    if is_dir {
        let Some(devs) = exposed_devs(mounts, mnt_id, real, recursive) else {
            return Err(failed(
                spec,
                "the pinned bind mount source cannot be located in mountinfo",
            ));
        };
        if ctx.protected.iter().enumerate().any(|(i, p)| {
            (devs.contains(p.dev()) || layers.state_devs_of(i).any(|d| devs.contains(d)))
                && p.has_hard_linked_files()
        }) {
            return Err(violation(spec, ViolationReason::BindSourceReachesStateRoot));
        }
    }
    for p in ctx.protected {
        let state = FsIdentity {
            dev: p.dev().to_owned(),
            path: p.path().to_owned(),
        };
        // 照合する保護対象の実体。記録したもの（start の時点）に加え、状態ルートは適用の時点の mountinfo から作り直した
        // (dev, path) と子マウントも照合する（下層の実パスでの改名では `chain_path` は同じ inode に解決し続け、
        // 記録した FS 内パスだけが古くなる。判定が厳しくなる方向のみ。#2166）。
        let mut targets = vec![state];
        if !p.is_containment_only()
            && let Some(chain_path) = p.chain_path()
        {
            let Some(fresh) = (ctx.deps.state_identity)(p, mounts) else {
                return Err(failed(
                    spec,
                    "the state store root cannot be located in mountinfo again",
                ));
            };
            if fresh.dev != p.dev() {
                return Err(failed(
                    spec,
                    "the state store root moved to another filesystem after start",
                ));
            }
            targets.push(fresh);
            targets.extend(
                mounts_under(mounts, chain_path)
                    .into_iter()
                    .map(|(id, _)| id),
            );
        }
        for target in &targets {
            let reached = if p.is_containment_only() {
                source_contains(mounts, mnt_id, real, recursive, target)
            } else {
                source_reaches(mounts, mnt_id, real, recursive, target)
            };
            match reached {
                Some(false) => {}
                Some(true) => {
                    return Err(violation(spec, ViolationReason::BindSourceReachesStateRoot));
                }
                None => {
                    return Err(failed(
                        spec,
                        "the pinned bind mount source cannot be located in mountinfo",
                    ));
                }
            }
        }
    }
    // 保護対象が overlay 上にあるときの層の実体（下層 FS 上の (dev, path)）とも照合する。bind mount を挟んだ別名と、
    // `rbind` で一緒に公開される子マウントを検出する（#2317）。
    let layer_checks = layers
        .state
        .iter()
        .map(|l| (l, ViolationReason::BindSourceReachesStateRoot))
        .chain(
            layers
                .contained
                .iter()
                .map(|l| (l, ViolationReason::BindSourceContainsRootfs)),
        );
    for (layer, reason) in layer_checks {
        match source_reaches(mounts, mnt_id, real, recursive, &layer.identity) {
            Some(false) => {}
            Some(true) => return Err(violation(spec, reason)),
            None => {
                return Err(failed(
                    spec,
                    "the pinned bind mount source cannot be located in mountinfo",
                ));
            }
        }
    }
    Ok(())
}

/// 状態ルートの (dev, path) を適用の時点の mountinfo で作り直す本番の実装（記録した `chain_path` を開き直し、fd の `mnt_id` で行を引く）。
fn fresh_state_identity(p: &ProtectedFsRoot, mounts: &[MountRow]) -> Option<FsIdentity> {
    let chain_path = p.chain_path()?;
    let mnt = path_mount_id(chain_path)?;
    fs_identity(mounts, mnt, chain_path)
}

/// 固定した元の属するマウントの ID（`/proc/thread-self/fdinfo/N` の `mnt_id`）。
fn pinned_source_mnt_id(src: &VerifiedBindSourceFd) -> Result<u64, ExecError> {
    let fdinfo = std::fs::read_to_string(format!(
        "/proc/thread-self/fdinfo/{}",
        src.as_fd().as_raw_fd()
    ))
    .map_err(|_| mountinfo_failed("cannot read fdinfo of the pinned bind mount source"))?;
    parse_fdinfo_mnt_id(&fdinfo)
        .ok_or_else(|| mountinfo_failed("no mnt_id in fdinfo of the pinned bind mount source"))
}

/// 固定した元の現在のパス（`/proc/thread-self/fd/N` のリンク先）。削除済み・絶対パスでないものは拒否する。
fn pinned_source_path(src: &VerifiedBindSourceFd) -> Result<String, ExecError> {
    let link = std::fs::read_link(format!("/proc/thread-self/fd/{}", src.as_fd().as_raw_fd()))
        .map_err(|_| mountinfo_failed("cannot resolve the pinned bind mount source"))?;
    let path = link
        .to_str()
        .filter(|p| p.starts_with('/') && !p.ends_with(" (deleted)"))
        .ok_or_else(|| mountinfo_failed("the pinned bind mount source has no usable path"))?;
    Ok(path.to_owned())
}

fn mountinfo_failed(msg: &str) -> ExecError {
    ExecError::new(ErrorCode::FailedPrecondition, STAGE, msg)
}

/// 固定した元と、辿った途中のディレクトリ（`/` から葉の親まで）の `(st_dev, st_ino)`。
pub(super) struct PinnedSource {
    fd: VerifiedBindSourceFd,
    /// 元の祖先ディレクトリの実体。元が状態ルートの bind 別名の配下にあれば、別名の mount root（状態ルートと同じ inode）が入る。
    dir_ids: Vec<(u64, u64)>,
}

/// 元の `(st_dev, st_ino)` を rootfs・状態ルートの実体と照合する純関数（SEC-1・SEC-4・#2066）。単体テストは (dev, ino) を
/// 差し替えてここを直接試験する。違反理由にホスト側のパスは含まれない。
///
/// - 元が rootfs とその祖先（bundle を含む）と同一 → `BindSourceContainsRootfs`。bundle・rootfs の配下は受ける（#2063 案 B）
/// - 元が状態ルートまたはその祖先と同一、または元の祖先に状態ルートがある（元が配下）→ `BindSourceReachesStateRoot`
fn judge_source_inodes(
    src: (u64, u64),
    src_dirs: &[(u64, u64)],
    rootfs_ids: &[(u64, u64)],
    state_chains: &[&[(u64, u64)]],
) -> Option<ViolationReason> {
    if rootfs_ids.contains(&src) {
        return Some(ViolationReason::BindSourceContainsRootfs);
    }
    let reaches = state_chains.iter().any(|chain| {
        chain.contains(&src) || chain.first().is_some_and(|first| src_dirs.contains(first))
    });
    reaches.then_some(ViolationReason::BindSourceReachesStateRoot)
}

/// 元をルートから 1 要素ずつ `O_NOFOLLOW` で固定し、種別と読み取り権限を確かめる（モジュール doc の手順 1）。
/// 辿った途中のディレクトリの実体も記録する（`judge_source_inodes` の子孫判定に使う）。
fn pin_source(spec: &BindMountSpec) -> Result<PinnedSource, ExecError> {
    let names: Vec<&str> = spec.source().split('/').filter(|e| !e.is_empty()).collect();
    let Some((leaf, parents)) = names.split_last() else {
        return Err(failed(spec, "bind mount source is empty"));
    };
    let c_name = |n: &str| {
        CString::new(n.as_bytes()).map_err(|_| failed(spec, "bind mount source contains NUL"))
    };
    let dir_id = |fd: &OwnedFd| {
        fstat_fd(fd.as_fd())
            .map(|st| (st.dev, st.ino))
            .map_err(|e| mount_api_error(spec, e, "fstat(bind mount source parent)"))
    };
    let mut cur = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| source_open_error(spec, e, "openat(/)"))?;
    // 長さは字句検証済みのパス長（`CONFIG_MAX_PATH_BYTES`）の要素数で頭打ち。
    let mut dir_ids = Vec::with_capacity(parents.len() + 1);
    dir_ids.push(dir_id(&cur)?);
    for name in parents {
        let c = c_name(name)?;
        cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &c)
            .map_err(|e| source_open_error(spec, e, "openat(bind mount source)"))?;
        dir_ids.push(dir_id(&cur)?);
    }
    let c = c_name(leaf)?;
    let fd = sys::open_path_nofollow(cur.as_fd(), &c)
        .map_err(|e| source_open_error(spec, e, "openat(bind mount source)"))?;
    let verified = sys::verify_bind_source_fd(fd).map_err(|e| match e {
        BindSourceError::NotDirOrRegular { mode } if mode & S_IFMT == S_IFLNK => {
            violation(spec, ViolationReason::BindSourceSymlink)
        }
        BindSourceError::NotDirOrRegular { .. } => {
            violation(spec, ViolationReason::BindSourceUnsupportedType)
        }
        BindSourceError::Sys(e) => mount_api_error(spec, e, "fstat(bind mount source)"),
    })?;
    // 読み取り権限の確認: 固定した inode を開き直す（パスを再 walk しない）。開いた fd は直ちに閉じる。
    match sys::reopen_pinned_read_nonblock(verified.as_fd()) {
        Ok(_checked) => {}
        Err(SysError::Os(e)) if e == sys::EACCES || e == sys::EPERM => {
            return Err(violation(spec, ViolationReason::BindSourceNotAccessible));
        }
        Err(e) => return Err(mount_api_error(spec, e, "open(bind mount source)")),
    }
    Ok(PinnedSource {
        fd: verified,
        dir_ids,
    })
}

/// `st_mode` の種別ビットとシンボリックリンクの値（`sys/stat.h`）。
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

/// 元の経路の open の失敗を写す。
fn source_open_error(spec: &BindMountSpec, e: SysError, what: &str) -> ExecError {
    match e {
        // `O_DIRECTORY|O_NOFOLLOW` では中間の symlink も `ENOTDIR` になる。`ELOOP` は念のため残す。
        SysError::Os(sys::ENOTDIR) | SysError::Os(sys::ELOOP) => {
            violation(spec, ViolationReason::BindSourceSymlink)
        }
        SysError::Os(sys::ENOENT) => {
            let mut err = failed(spec, "bind mount source does not exist");
            err.code = ErrorCode::NotFound;
            err
        }
        SysError::Os(sys::EACCES) => violation(spec, ViolationReason::BindSourceNotAccessible),
        other => mount_api_error(spec, other, what),
    }
}

/// マウント先を rootfs の fd から固定する（無い要素は作る。モジュール doc の手順 3）。
fn pin_target(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    kind: BindSourceKind,
    state: &mut Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let names = state.names.clone();
    let Some((leaf, parents)) = names.split_last() else {
        return Err(failed(spec, "bind mount destination is empty"));
    };
    let parent_fd = if parents.is_empty() {
        None
    } else {
        Some(open_parents_recording(ctx, spec, parents, state)?)
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    let c_leaf = CString::new(leaf.as_bytes())
        .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
    let fd = match sys::open_path_nofollow(parent, &c_leaf) {
        Ok(fd) => fd,
        Err(SysError::Os(sys::ENOENT)) => {
            if kind == BindSourceKind::Directory {
                // 自分が作った実体であることを証明してから配置する（作成と開き直しの間の差し替えを許さない）。
                match create_dir_proven(parent, &c_leaf) {
                    Ok(Some((fd, id, leftover))) => {
                        // 配置済みの実体は、ステージング掃除の失敗より先に記録する（失敗しても後始末が回収できる）。
                        state.created_dirs.push(last_index(state));
                        state.created_dir_ids.push((last_index(state), id));
                        if let Some(detail) = leftover {
                            return Err(failed(
                                spec,
                                &format!("mkdirat(bind mount target) rmdir: {detail}"),
                            ));
                        }
                        fd
                    }
                    Ok(None) => reopen_created(spec, kind, parent, &c_leaf, state)?,
                    Err((what, detail)) => {
                        return Err(failed(
                            spec,
                            &format!("mkdirat(bind mount target) {what}: {detail}"),
                        ));
                    }
                }
            } else {
                create_target(spec, kind, parent, &c_leaf, state)?;
                reopen_created(spec, kind, parent, &c_leaf, state)?
            }
        }
        Err(e) => return Err(mount_api_error(spec, e, "openat(bind mount target)")),
    };
    check_target_kind(spec, &fd, kind)?;
    Ok(fd)
}

/// マウント先の親を rootfs の fd から 1 要素ずつ固定する（無い要素は作る）。
///
/// 作った要素は、作成直後に開き直して固定した fd の `(st_dev, st_ino)` をその場で `created_dir_ids` へ記録する
/// （名前を辿り直さない）。途中で失敗しても、それまでに作った分は記録済みのため後始末が照合して消せる。
/// 失敗は宛先の接頭辞つきの `IsolationStage::MountBinds` のエラーにする。
fn open_parents_recording(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    parents: &[&OsStr],
    state: &mut Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let mut cur: Option<OwnedFd> = None;
    for (index, name) in parents.iter().enumerate() {
        let c = CString::new(name.as_bytes())
            .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
        let dir = cur.as_ref().map_or(ctx.root, |f| f.as_fd());
        let next = match sys::open_dir_path_nofollow(Some(dir), &c) {
            Ok(fd) => fd,
            Err(SysError::Os(sys::ENOENT)) => {
                // 自分が作った実体であることを証明してから配置する（作成と開き直しの間の差し替えを許さない）。
                match create_dir_proven(dir, &c) {
                    Ok(Some((fd, id, leftover))) => {
                        // 配置済みの実体は、ステージング掃除の失敗より先に記録する（失敗しても後始末が回収できる）。
                        state.created_dirs.push(index);
                        state.created_dir_ids.push((index, id));
                        if let Some(detail) = leftover {
                            return Err(failed(
                                spec,
                                &format!("mkdirat(bind mount target) rmdir: {detail}"),
                            ));
                        }
                        fd
                    }
                    Ok(None) => sys::open_dir_path_nofollow(Some(dir), &c).map_err(|e| {
                        annotate(
                            spec,
                            super::open_error(e, true, Path::new("/"), parents).at_stage(STAGE),
                        )
                    })?,
                    Err((what, detail)) => {
                        return Err(failed(
                            spec,
                            &format!("mkdirat(bind mount target) {what}: {detail}"),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(annotate(
                    spec,
                    super::open_error(e, true, Path::new("/"), parents).at_stage(STAGE),
                ));
            }
        };
        cur = Some(next);
    }
    cur.ok_or_else(|| failed(spec, "bind mount destination is empty"))
}

/// 無いマウント先の末尾の通常ファイルを空の 0644 で作る（ディレクトリは `create_dir_proven`）。競合で先に作られた場合は何もしない。
fn create_target(
    spec: &BindMountSpec,
    kind: BindSourceKind,
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    state: &mut Applied<'_>,
) -> Result<(), ExecError> {
    match kind {
        // ディレクトリは `create_dir_proven` が作る（作成と所有証明の間に差し替えを許さないため）。
        BindSourceKind::Directory => {
            return Err(failed(
                spec,
                "directory targets are created by create_dir_proven",
            ));
        }
        BindSourceKind::RegularFile => match sys::create_file_excl_at(parent, c_leaf, FILE_MODE) {
            Ok(created) => {
                let st = fstat_fd(created.as_fd())
                    .map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
                state.created_file = Some((st.dev, st.ino));
            }
            Err(SysError::Os(sys::EEXIST)) => {}
            Err(e) => return Err(mount_api_error(spec, e, "create(bind mount target)")),
        },
    }
    Ok(())
}

/// 作成した（または競合で先に作られた）マウント先を開き直す。自分が作ったファイルは作成時の `(dev, ino)` と一致を確かめる。
fn reopen_created(
    spec: &BindMountSpec,
    kind: BindSourceKind,
    parent: BorrowedFd<'_>,
    c_leaf: &CString,
    state: &Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let fd = sys::open_path_nofollow(parent, c_leaf)
        .map_err(|e| mount_api_error(spec, e, "openat(bind mount target)"))?;
    if let (BindSourceKind::RegularFile, Some(recorded)) = (kind, state.created_file) {
        let st = fstat_fd(fd.as_fd())
            .map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
        if (st.dev, st.ino) != recorded {
            return Err(violation(spec, ViolationReason::TargetMoved));
        }
    }
    Ok(fd)
}

/// 固定したマウント先の種別を元と突き合わせる（symlink は拒否、種別違いは `bind_target_kind_mismatch`）。
fn check_target_kind(
    spec: &BindMountSpec,
    fd: &OwnedFd,
    kind: BindSourceKind,
) -> Result<(), ExecError> {
    let st =
        fstat_fd(fd.as_fd()).map_err(|e| mount_api_error(spec, e, "fstat(bind mount target)"))?;
    if st.is_symlink {
        return Err(violation(spec, ViolationReason::PathSymlinkOrNotDirectory));
    }
    match (kind, st.is_dir, st.is_file) {
        (BindSourceKind::Directory, true, _) | (BindSourceKind::RegularFile, _, true) => Ok(()),
        _ => Err(violation(spec, ViolationReason::BindTargetKindMismatch)),
    }
}

/// 付け替え後に、同じ要素を作らずに名前で開き直す（事後検証・観測用）。
fn reopen_target(
    ctx: &Ctx<'_>,
    spec: &BindMountSpec,
    state: &Applied<'_>,
) -> Result<OwnedFd, ExecError> {
    let Some((leaf, parents)) = state.names.split_last() else {
        return Err(failed(spec, "bind mount destination is empty"));
    };
    let parent_fd = if parents.is_empty() {
        None
    } else {
        Some(
            open_chain(ctx.root, Path::new("/"), parents, None)
                .map_err(|e| annotate(spec, e.at_stage(STAGE)))?,
        )
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    let c_leaf = CString::new(leaf.as_bytes())
        .map_err(|_| violation(spec, ViolationReason::PathContainsNul))?;
    sys::open_path_nofollow(parent, &c_leaf)
        .map_err(|e| mount_api_error(spec, e, "openat(bind mount target)"))
}

/// 付け替え前後の fd の観測（本番）。
fn observe_real(
    before: &OwnedFd,
    after: &OwnedFd,
    own: &OwnedFd,
) -> Result<BindObservation, ExecError> {
    let flags = sys::mount_flags(after.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstatfs(bind mount target)"))?;
    let st = fstat_fd(after.as_fd())
        .map_err(|e| ExecError::from_sys(e, STAGE, "fstat(bind mount target)"))?;
    Ok(BindObservation {
        before_mnt_id: fd_mount_id(before, STAGE)?,
        after_mnt_id: fd_mount_id(after, STAGE)?,
        own_mnt_id: fd_mount_id(own, STAGE)?,
        flags,
        dev_ino: (st.dev, st.ino),
    })
}

/// 自分のマウントを fd 指定で `umount2(MNT_DETACH)` する（fd を直接指す syscall が無いため `/proc/thread-self/fd/N` 経由）。
fn umount_fd(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    let target = CString::new(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| SysError::Os(sys::EINVAL))?;
    sys::umount_detach_at(&target)
}

/// 付け替え前後のフラグの判定（純関数）。成功なら `Ok`、不一致なら英語の理由。
///
/// `nosuid`・`nodev` は常に必須。`ro`・`noexec` は要求と一致しなければならない（`attr_clr` を持たないため、
/// ロックされた属性や読み取り専用の FS の元は要求より強い制限が残る。黙って別の属性で載せない）。
fn check_flags(flags: MountFlags, expected: Expected) -> Result<(), String> {
    if !flags.is_valid() {
        return Err("the mount flags are not available".to_owned());
    }
    if !flags.is_nosuid() || !flags.is_nodev() {
        return Err("nosuid and nodev are not set on the bind mount".to_owned());
    }
    match (flags.is_read_only(), expected.read_only) {
        (true, false) => {
            return Err(
                "the bind mount is read-only (a locked attribute or a read-only \
                        filesystem); specify ro"
                    .to_owned(),
            );
        }
        (false, true) => return Err("ro was not applied to the bind mount".to_owned()),
        _ => {}
    }
    match (flags.is_noexec(), expected.noexec) {
        (true, false) => {
            Err("the bind mount is noexec (a locked attribute); specify noexec".to_owned())
        }
        (false, true) => Err("noexec was not applied to the bind mount".to_owned()),
        _ => Ok(()),
    }
}

/// 事後条件の判定（純関数）。マウント前とは別のマウントで、自分のマウントで、フラグが要求どおりで、元と同じ
/// `(st_dev, st_ino)` でなければ拒否する。
fn check_new_bind(
    observed: &BindObservation,
    expected: Expected,
    source: (u64, u64),
) -> Result<(), String> {
    if observed.after_mnt_id == observed.before_mnt_id {
        return Err("no new mount is present at the bind mount destination after mount".to_owned());
    }
    if observed.after_mnt_id != observed.own_mnt_id {
        return Err(
            "the mount at the bind mount destination is not the mount created by this call"
                .to_owned(),
        );
    }
    check_flags(observed.flags, expected).map_err(|why| format!("after mount: {why}"))?;
    if observed.dev_ino != source {
        return Err(
            "the bind mount destination is not the same inode as the pinned source".to_owned(),
        );
    }
    Ok(())
}

/// mountinfo の 1 行（必要なフィールドだけ）。
struct MountInfoEntry<'a> {
    id: u64,
    parent: u64,
    /// `major:minor`（保護対象の FS が overlay かの判定に使う。出力へは写さない。#2317）。
    dev: &'a str,
    options: &'a str,
    optional: Vec<&'a str>,
    /// 区切り `-` の次の fstype 欄（疑似 FS の照合に使う。出力へは写さない）。
    fstype: &'a str,
    /// fstype・source の次の super_options 欄（overlayfs の層の照合に使う。出力へは写さない。#2166）。
    super_options: &'a str,
}

/// mountinfo の 1 行に必須の固定フィールド数（`id parent major:minor root mount_point options`）。
const MOUNTINFO_FIXED_FIELDS: usize = 6;
/// 区切り `-` の後ろの必須フィールド数（`fstype source super_options`）。
const MOUNTINFO_TAIL_FIELDS: usize = 3;

fn parse_mountinfo_line(line: &str) -> Option<MountInfoEntry<'_>> {
    let fields: Vec<&str> = line.split(' ').collect();
    let sep = fields
        .iter()
        .skip(MOUNTINFO_FIXED_FIELDS)
        .position(|f| *f == "-")?
        + MOUNTINFO_FIXED_FIELDS;
    // 区切りの後ろは `fstype source super_options` の 3 つちょうど。余るフィールドは壊れた行として拒否する（fail-closed）。
    if fields.len() != sep + 1 + MOUNTINFO_TAIL_FIELDS {
        return None;
    }
    Some(MountInfoEntry {
        id: fields.first()?.parse().ok()?,
        parent: fields.get(1)?.parse().ok()?,
        dev: fields.get(2)?,
        options: fields.get(5)?,
        optional: fields.get(MOUNTINFO_FIXED_FIELDS..sep)?.to_vec(),
        fstype: fields.get(sep + 1)?,
        super_options: fields.get(sep + 3)?,
    })
}

/// 自分のマウント（`recursive` なら親子関係で集めた配下全体）を返す。最初の要素が mount top。件数は行数が上限。
/// 書式の崩れ・該当なし・重複は fail-closed の `Err`。
fn subtree_members<'a, 'b>(
    entries: &'b [MountInfoEntry<'a>],
    own_id: u64,
    recursive: bool,
) -> Result<Vec<&'b MountInfoEntry<'a>>, String> {
    let mut own = entries.iter().filter(|e| e.id == own_id);
    let Some(top) = own.next() else {
        return Err("no mount entry found for the bind mount".to_owned());
    };
    if own.next().is_some() {
        return Err("duplicate mount ID in /proc/thread-self/mountinfo".to_owned());
    }
    let mut members: Vec<&MountInfoEntry<'_>> = vec![top];
    if recursive {
        // 親子関係で配下を集める（件数は行数が上限）。
        let mut ids = vec![top.id];
        loop {
            let before = ids.len();
            for e in entries {
                if !ids.contains(&e.id) && ids.contains(&e.parent) {
                    ids.push(e.id);
                    members.push(e);
                }
            }
            if ids.len() == before {
                break;
            }
        }
    }
    Ok(members)
}

/// 付け替えた自分のマウント（`recursive` なら配下全体）に拒否リストの疑似 FS があるか、fstype 欄の完全一致で探す純関数
/// （#2098）。書式に反する行・該当なし・重複は fail-closed の `Err`。
fn find_pseudo_fs_in_subtree(
    info: &str,
    own_id: u64,
    recursive: bool,
) -> Result<Option<&'static PseudoFs>, String> {
    let entries = parse_all_mountinfo(info)?;
    Ok(subtree_members(&entries, own_id, recursive)?
        .iter()
        .find_map(|e| pseudo_fs_by_name(e.fstype)))
}

/// mountinfo 全行を解析する。行数上限は [`parse_mountinfo`] と同じ（解析より先に効かせる。#2536）。
fn parse_all_mountinfo(info: &str) -> Result<Vec<MountInfoEntry<'_>>, String> {
    if info.lines().nth(MOUNTINFO_MAX_LINES).is_some() {
        return Err("oversized /proc/thread-self/mountinfo".to_owned());
    }
    info.lines()
        .map(|l| {
            parse_mountinfo_line(l)
                .ok_or_else(|| "malformed line in /proc/thread-self/mountinfo".to_owned())
        })
        .collect()
}

/// 自分のマウント（`recursive` なら配下全体）の mountinfo を判定する（純関数）。
///
/// 全マウントに `shared:`・`master:`・`propagate_from:` が無く、per-mount options に `nosuid`・`nodev` があること。
/// 自分のマウント（mount top）は `ro`・`noexec` の有無が要求と完全に一致すること。配下は、要求した制限
/// （`ro`・`noexec`）が付いていれば足りる（元が持つ、より強い制限は安全側のため許す）。書式に反する行・該当なし・
/// 重複は fail-closed。
#[cfg(test)]
fn check_bind_subtree(
    info: &str,
    own_id: u64,
    expected: Expected,
    recursive: bool,
) -> Result<(), String> {
    check_bind_subtree_with(info, own_id, expected, recursive, false)
}

/// [`check_bind_subtree`] の本体。`host_slave` が真（`rslave` の bind）のときは、`shared:` を全メンバーで禁止したまま、
/// 自分のマウント（mount top）に `master:`・`propagate_from:` のどちらかを必須にし、配下の `master:` は許す（配下も
/// 元の slave を引き継ぐため。#2669・OCI-4・SEC-1）。偽のときは従来どおり 3 つとも禁止する。
fn check_bind_subtree_with(
    info: &str,
    own_id: u64,
    expected: Expected,
    recursive: bool,
    host_slave: bool,
) -> Result<(), String> {
    let entries = parse_all_mountinfo(info)?;
    let members = subtree_members(&entries, own_id, recursive)?;
    let Some(top) = members.first() else {
        return Err("no mount entry found for the bind mount".to_owned());
    };
    let has = |e: &MountInfoEntry<'_>, opt: &str| e.options.split(',').any(|o| o == opt);
    for e in &members {
        let slave_field = |f: &&str| f.starts_with("master:") || f.starts_with("propagate_from:");
        if e.optional.iter().any(|f| f.starts_with("shared:")) {
            return Err(
                "the bind mount is shared or a slave in /proc/thread-self/mountinfo".to_owned(),
            );
        }
        if !host_slave && e.optional.iter().any(slave_field) {
            return Err(
                "the bind mount is shared or a slave in /proc/thread-self/mountinfo".to_owned(),
            );
        }
        if host_slave && e.id == top.id && !e.optional.iter().any(slave_field) {
            return Err(
                "the rslave bind mount is not a slave in /proc/thread-self/mountinfo".to_owned(),
            );
        }
        if !has(e, "nosuid") || !has(e, "nodev") {
            return Err("nosuid and nodev are not set in /proc/thread-self/mountinfo".to_owned());
        }
        let is_top = e.id == top.id;
        if (expected.read_only || is_top) && has(e, "ro") != expected.read_only {
            return Err(if expected.read_only {
                "ro is not set in /proc/thread-self/mountinfo".to_owned()
            } else {
                "the bind mount is read-only in /proc/thread-self/mountinfo; specify ro".to_owned()
            });
        }
        if (expected.noexec || is_top) && has(e, "noexec") != expected.noexec {
            return Err(if expected.noexec {
                "noexec is not set in /proc/thread-self/mountinfo".to_owned()
            } else {
                "the bind mount is noexec in /proc/thread-self/mountinfo; specify noexec".to_owned()
            });
        }
    }
    Ok(())
}

/// 後始末で失敗した 1 件（元のエラーへ併記する。#1913・REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupFailure {
    /// [`display_destination`] を通した宛先（エスケープ・切り詰め済み）。
    destination: String,
    /// 失敗した操作（`umount2`・`unlink`・`rmdir`・`open`・`rename`・`verify`）。
    what: &'static str,
    /// 失敗理由（英語の短い文）。
    detail: String,
}

/// 後始末の失敗を、元のエラーの message に `; cleanup failed: <what>(<dest>) failed: <detail>` として併記する
/// （`code`・`stage`・`violation` は保つ）。失敗が無ければ `err` をそのまま返す。件数は集合側の上限で抑えられる。
fn with_cleanup_failures(mut err: ExecError, failures: &[CleanupFailure]) -> ExecError {
    for f in failures {
        err.message.push_str(&format!(
            "; cleanup failed: {}({}) failed: {}",
            f.what, f.destination, f.detail
        ));
    }
    err
}

/// 要素列を表示用の宛先文字列にする。
fn destination_of(names: &[&OsStr]) -> String {
    display_destination(&format!(
        "/{}",
        names
            .iter()
            .map(|n| n.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    ))
}

/// 失敗時の後始末（最善努力）。新しい順に、自分のマウントを外し、自分が作った空ファイル・ディレクトリを消す。
///
/// 解除するのは付け替え時に得た自分のマウントの fd が指すマウントだけで、名前から開き直した先は解除しない。
/// 空ファイル・ディレクトリは [`remove_verified`] で、作成時に記録した `(dev, ino)` と一致した実体だけを消す。
/// 失敗（umount・開き直し・照合不一致・削除）は戻り値で返し、呼び出し元が元のエラーに併記する（黙って捨てない）。
fn roll_back_binds(ctx: &Ctx<'_>, applied: &[Applied<'_>]) -> Vec<CleanupFailure> {
    let mut failures = Vec::new();
    for state in applied.iter().rev() {
        if let Some(mount) = &state.mounted
            && let Err(error) = (ctx.deps.umount)(mount.as_fd())
        {
            failures.push(CleanupFailure {
                destination: destination_of(&state.names),
                what: "umount2",
                detail: super::describe(error),
            });
        }
        if let Some(recorded) = state.created_file {
            let last = state.names.len().saturating_sub(1);
            remove_created(ctx, state, last, recorded, false, &mut failures);
        }
        for &index in state.created_dirs.iter().rev() {
            let Some((_, recorded)) = state.created_dir_ids.iter().find(|(i, _)| *i == index)
            else {
                failures.push(CleanupFailure {
                    destination: destination_of(state.names.get(..=index).unwrap_or(&[])),
                    what: "verify",
                    detail: "the created directory was not recorded; left in place".to_owned(),
                });
                break;
            };
            if !remove_created(ctx, state, index, *recorded, true, &mut failures) {
                break;
            }
        }
    }
    failures
}

/// `state.names[index]` の要素（自分が作ったもの）を消す。失敗は `failures` へ積み、続行してよければ `true`。
fn remove_created(
    ctx: &Ctx<'_>,
    state: &Applied<'_>,
    index: usize,
    recorded: (u64, u64),
    is_dir: bool,
    failures: &mut Vec<CleanupFailure>,
) -> bool {
    let destination = destination_of(state.names.get(..=index).unwrap_or(&[]));
    let mut fail = |what: &'static str, detail: String| {
        failures.push(CleanupFailure {
            destination: destination.clone(),
            what,
            detail,
        });
        false
    };
    let (Some(name), Some(prefix)) = (state.names.get(index), state.names.get(..index)) else {
        return fail("verify", "the created element is out of range".to_owned());
    };
    let Ok(c_name) = CString::new(name.as_bytes()) else {
        return fail("verify", "the element name contains NUL".to_owned());
    };
    let parent_fd = if prefix.is_empty() {
        None
    } else {
        match open_chain(ctx.root, Path::new("/"), prefix, None) {
            Ok(fd) => Some(fd),
            Err(e) => return fail("open", e.message),
        }
    };
    let parent = parent_fd.as_ref().map_or(ctx.root, |f| f.as_fd());
    match remove_verified(parent, &c_name, recorded, is_dir) {
        Ok(()) => true,
        Err((what, detail)) => fail(what, detail),
    }
}

/// 後始末用の隔離ディレクトリ名の連番（同一プロセス内の衝突回避）。
static QUARANTINE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 隔離ディレクトリの中での、移した実体の名前。
const QUARANTINED: &str = "victim";

/// 隔離ディレクトリの権限（所有者のみ。排除するのは別の uid のプロセスだけで、同じ uid は隔離しない。モジュール doc 参照）。
const QUARANTINE_MODE: u32 = 0o700;

/// `parent` 配下の `name` を、記録した `(dev, ino)` と一致する実体のときだけ消す（検証対象と削除対象を一致させる）。
///
/// 名前のまま照合して `unlinkat` すると、照合と削除の間に別プロセスが同名の別実体へ差し替えられる。同じ親の中に
/// 隔離名で改名するだけでも、その隔離名が他者から見えて書けるため差し替えられる。そこで
/// (1) `parent` の中に自分専用（0700・実効 uid 所有）の隔離ディレクトリを作って fd で固定し、
/// (2) `RENAME_NOREPLACE` の `renameat2` で対象をその中へ原子的に移し（別の uid のプロセスはそこへ入れない。同じ uid は隔離しない。モジュール doc 参照）、
/// (3) 移した実体を開いて `(dev, ino)` を照合し、(4) 一致したときだけ消す。不一致・削除失敗のときは元の名前へ
/// `RENAME_NOREPLACE` で戻す。戻し先に別の実体が作られていれば上書きせず、実体を隔離ディレクトリに残して
/// 失敗として報告する。マウントが残っている要素は改名が `EBUSY` で拒否されるため、umount に失敗した場合も消さない。
fn remove_verified(
    parent: BorrowedFd<'_>,
    name: &CString,
    recorded: (u64, u64),
    is_dir: bool,
) -> Result<(), (&'static str, String)> {
    let errno = |e: SysError| super::describe(e);
    let seq = QUARANTINE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let qname = CString::new(format!(
        ".fandhe-rollback-{}-{seq}-{nanos:08x}",
        std::process::id()
    ))
    .map_err(|_| ("rename", "invalid quarantine name".to_owned()))?;
    let victim =
        CString::new(QUARANTINED).map_err(|_| ("rename", "invalid quarantine name".to_owned()))?;
    sys::mkdir_at(parent, &qname, QUARANTINE_MODE).map_err(|e| ("mkdir", errno(e)))?;
    // 隔離ディレクトリを（空のときだけ）消す。差し替えられていても空ディレクトリしか消えない。失敗は文字列で返す。
    let drop_qdir = || -> Option<String> {
        sys::remove_dir_at(parent, &qname).err().map(|e| {
            format!(
                "removing the quarantine directory failed: {}; it was left in place",
                errno(e)
            )
        })
    };
    let qdir = match sys::open_dir_path_nofollow(Some(parent), &qname) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), drop_qdir()))),
    };
    let qst = match fstat_fd(qdir.as_fd()) {
        Ok(st) => st,
        Err(e) => return Err(("verify", join_detail(errno(e), drop_qdir()))),
    };
    if !qst.is_dir || qst.uid != sys::effective_uid() || qst.mode & 0o777 != QUARANTINE_MODE {
        // 作った直後に他者が差し替えた。中へ移すと他者から触れるため何もしない。
        return Err((
            "verify",
            join_detail(
                "the quarantine directory is not private to this process; left in place".to_owned(),
                drop_qdir(),
            ),
        ));
    }
    match sys::rename_noreplace_at(parent, name, qdir.as_fd(), &victim) {
        Ok(()) => {}
        // 既に無い（自分の作った実体が消えている）なら後始末は済んでいる。
        Err(SysError::Os(sys::ENOENT)) => {
            return match drop_qdir() {
                None => Ok(()),
                Some(x) => Err(("rmdir", x)),
            };
        }
        Err(e) => return Err(("rename", join_detail(errno(e), drop_qdir()))),
    }
    let put_back = |what: &'static str, detail: String| {
        let detail = match sys::rename_noreplace_at(qdir.as_fd(), &victim, parent, name) {
            Ok(()) => join_detail(detail, drop_qdir()),
            Err(SysError::Os(sys::EEXIST)) => format!(
                "{detail}; the original name was re-created by another process, so the element was left in the quarantine directory"
            ),
            Err(e) => format!(
                "{detail}; restoring the original name failed: {}; the element was left in the quarantine directory",
                errno(e)
            ),
        };
        Err((what, detail))
    };
    let id = sys::open_path_nofollow(qdir.as_fd(), &victim)
        .and_then(|fd| fstat_fd(fd.as_fd()))
        .map(|st| (st.dev, st.ino));
    match id {
        Ok(id) if id == recorded => {}
        Ok(_) => {
            return put_back(
                "verify",
                "the element is not the one created by this call; left in place".to_owned(),
            );
        }
        Err(e) => return put_back("verify", errno(e)),
    }
    let removed = if is_dir {
        sys::remove_dir_at(qdir.as_fd(), &victim)
    } else {
        sys::remove_file_at(qdir.as_fd(), &victim)
    };
    match removed {
        Ok(()) => match drop_qdir() {
            None => Ok(()),
            Some(x) => Err(("rmdir", x)),
        },
        Err(e) => put_back(if is_dir { "rmdir" } else { "unlink" }, errno(e)),
    }
}

/// 元のエラー文に、後始末の失敗（あれば）を併記する。
fn join_detail(detail: String, extra: Option<String>) -> String {
    match extra {
        Some(x) => format!("{detail}; {x}"),
        None => detail,
    }
}

/// `create_dir_proven` の結果（作った fd と `(dev, ino)`、既存なら `None`、失敗は段名と詳細）。
///
/// 3 つ目はステージングディレクトリを消せなかったときの詳細。配置は済んでいるため `Ok` で返し、呼び出し側が
/// 配置した実体を `created_dirs` / `created_dir_ids` へ記録してからエラー扱いにする（記録しないと後始末が回収できない）。
type CreateProven = Result<Option<(OwnedFd, (u64, u64), Option<String>)>, (&'static str, String)>;

/// `parent` 配下に新しいディレクトリ `name` を作り、自分が作った実体であることを証明した fd と `(dev, ino)` を返す。
/// 既に `name` がある（競合を含む）ときは `Ok(None)`（何も作らない）。
///
/// `mkdirat` してから名前で開き直すと、その間に別プロセスが改名して別の同名ディレクトリを置ける。そこで
/// (1) `parent` の中に自分専用（0700・実効 uid 所有）のステージングディレクトリを作って fd で固定し、
/// (2) その中（別の uid のプロセスは入れない。同じ uid は隔離しない。モジュール doc 参照）に `mkdirat` して fd を開き直し `(dev, ino)` を取り、
/// (3) `RENAME_NOREPLACE` の `renameat2` で `name` へ原子的に移す（inode は変わらない）。
/// 記録する実体は常に自分が作ったものになる。ステージングディレクトリは成否に関わらず空にして消し、
/// 削除の失敗はエラーに併記する（SEC-1・REPAIR-4）。
fn create_dir_proven(parent: BorrowedFd<'_>, name: &CString) -> CreateProven {
    let errno = |e: SysError| super::describe(e);
    let seq = QUARANTINE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let stage = CString::new(format!(
        ".fandhe-stage-{}-{seq}-{nanos:08x}",
        std::process::id()
    ))
    .map_err(|_| ("mkdir", "invalid staging name".to_owned()))?;
    let inner = CString::new("new").map_err(|_| ("mkdir", "invalid staging name".to_owned()))?;
    sys::mkdir_at(parent, &stage, QUARANTINE_MODE).map_err(|e| ("mkdir", errno(e)))?;
    let drop_stage = || -> Option<String> {
        sys::remove_dir_at(parent, &stage).err().map(|e| {
            format!(
                "removing the staging directory failed: {}; it was left in place",
                errno(e)
            )
        })
    };
    let sdir = match sys::open_dir_path_nofollow(Some(parent), &stage) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), drop_stage()))),
    };
    match fstat_fd(sdir.as_fd()) {
        Ok(st)
            if st.is_dir
                && st.uid == sys::effective_uid()
                && st.mode & 0o777 == QUARANTINE_MODE => {}
        Ok(_) => {
            return Err((
                "verify",
                join_detail(
                    "the staging directory is not private to this process; left in place"
                        .to_owned(),
                    drop_stage(),
                ),
            ));
        }
        Err(e) => return Err(("verify", join_detail(errno(e), drop_stage()))),
    }
    // ステージング内の `new`（作っていれば）とステージング自体を消し、失敗を元のエラーへ併記する。
    let unstage = |made: bool| -> Option<String> {
        let first = if made {
            sys::remove_dir_at(sdir.as_fd(), &inner)
                .err()
                .map(|e| format!("removing the staged directory failed: {}", errno(e)))
        } else {
            None
        };
        match (first, drop_stage()) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        }
    };
    if let Err(e) = sys::mkdir_at(sdir.as_fd(), &inner, DIR_MODE) {
        return Err(("mkdir", join_detail(errno(e), unstage(false))));
    }
    let fd = match sys::open_dir_path_nofollow(Some(sdir.as_fd()), &inner) {
        Ok(fd) => fd,
        Err(e) => return Err(("open", join_detail(errno(e), unstage(true)))),
    };
    let id = match fstat_fd(fd.as_fd()) {
        Ok(st) => (st.dev, st.ino),
        Err(e) => return Err(("verify", join_detail(errno(e), unstage(true)))),
    };
    match sys::rename_noreplace_at(sdir.as_fd(), &inner, parent, name) {
        Ok(()) => Ok(Some((fd, id, drop_stage()))),
        // 既に同名がある。作った分は捨てて、既存を使わせる。
        Err(SysError::Os(sys::EEXIST)) => match unstage(true) {
            None => Ok(None),
            Some(x) => Err(("rmdir", x)),
        },
        Err(e) => Err(("rename", join_detail(errno(e), unstage(true)))),
    }
}

/// rootfs とその祖先の `(st_dev, st_ino)`（先頭が rootfs 自身）。`..` を `O_NOFOLLOW` で辿り、同じ位置に戻ったら
/// （namespace のルート）終わる。上限 [`MAX_ANCESTORS`] 段を超えたら fail-closed。
fn rootfs_identity_chain(root: BorrowedFd<'_>) -> Result<Vec<(u64, u64)>, ExecError> {
    let id = |fd: BorrowedFd<'_>| {
        fstat_fd(fd)
            .map(|st| (st.dev, st.ino))
            .map_err(|e| ExecError::from_sys(e, STAGE, "fstat(rootfs ancestor)"))
    };
    let mut ids = vec![id(root)?];
    let mut cur = root
        .try_clone_to_owned()
        .map_err(|e| ExecError::from_io(&e, STAGE, "dup(rootfs)"))?;
    loop {
        let parent = sys::open_dir_path_nofollow(Some(cur.as_fd()), c"..")
            .map_err(|e| ExecError::from_sys(e, STAGE, "openat(rootfs ancestor)"))?;
        let parent_id = id(parent.as_fd())?;
        if ids.last() == Some(&parent_id) {
            return Ok(ids);
        }
        ids.push(parent_id);
        if ids.len() > MAX_ANCESTORS {
            return Err(ExecError::new(
                ErrorCode::FailedPrecondition,
                STAGE,
                "the rootfs has too many ancestors to verify the bind mount sources",
            ));
        }
        cur = parent;
    }
}

/// `fstat` の結果のうち必要な値。
struct FdStat {
    dev: u64,
    ino: u64,
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
}

/// `fd`（`O_PATH` でもよい）の `fstat`。fd は複製して見るだけで、呼び出し側の fd は保持される。
fn fstat_fd(fd: BorrowedFd<'_>) -> Result<FdStat, SysError> {
    use std::os::unix::fs::MetadataExt as _;
    let os = |e: std::io::Error| SysError::Os(e.raw_os_error().unwrap_or(sys::EINVAL));
    let dup = fd.try_clone_to_owned().map_err(os)?;
    let meta = std::fs::File::from(dup).metadata().map_err(os)?;
    Ok(FdStat {
        dev: meta.dev(),
        ino: meta.ino(),
        is_dir: meta.file_type().is_dir(),
        is_file: meta.file_type().is_file(),
        is_symlink: meta.file_type().is_symlink(),
        uid: meta.uid(),
        mode: meta.mode(),
    })
}

/// user namespace の確認（純関数）。PID 1 が初期 user namespace にいる、またはホストの ID 0 を写像した経路は拒否する
/// （user namespace なしでは特権ランチャー由来の capability がホストの inode に効くため適用しない。SEC-5）。
fn judge_user_namespace(
    user_ns_inode: u64,
    uid_map: &[IdMapping],
    gid_map: &[IdMapping],
) -> Result<(), ViolationReason> {
    if user_ns_inode == USER_NS_INIT_INO {
        return Err(ViolationReason::UserNamespaceRequired);
    }
    if uid_map
        .iter()
        .chain(gid_map)
        .any(|m| m.host_id == 0 && m.count > 0)
    {
        return Err(ViolationReason::HostRootIdentityMapping);
    }
    Ok(())
}

/// 呼び出しスレッドの user namespace を確認する（[`judge_user_namespace`] の入力を `/proc` から集める）。
fn check_user_namespace() -> Result<(), ExecError> {
    let fail = |msg: &str| ExecError::new(ErrorCode::FailedPrecondition, STAGE, msg);
    let link = thread_ns_link("user").map_err(|_| fail("cannot read /proc/thread-self/ns/user"))?;
    let inode = link
        .strip_prefix("user:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| fail("malformed /proc/thread-self/ns/user"))?;
    let read_map = |name: &str| -> Result<Vec<IdMapping>, ExecError> {
        let file = std::fs::File::open(format!("/proc/thread-self/{name}"))
            .map_err(|_| fail("cannot read the id map of the user namespace"))?;
        let mut buf = Vec::new();
        file.take(MAX_ID_MAP_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|_| fail("cannot read the id map of the user namespace"))?;
        if buf.len() as u64 > MAX_ID_MAP_BYTES {
            return Err(fail("the id map of the user namespace is too large"));
        }
        parse_id_map(&buf).map_err(|_| fail("malformed id map of the user namespace"))
    };
    let uid = read_map("uid_map")?;
    let gid = read_map("gid_map")?;
    judge_user_namespace(inode, &uid, &gid)
        .map_err(|r| ExecError::from_violation_at(r, None, STAGE))
}

/// 違反の拒否を作る。違反記録の対象と message のパスは**コンテナ内の宛先**（ホスト側のマウント元は載せない）。
fn violation(spec: &BindMountSpec, reason: ViolationReason) -> ExecError {
    let mut err = ExecError::from_violation_at(reason, Some(spec.destination().as_path()), STAGE);
    err.message = format!(
        "mounts[{}] ({}): {}",
        spec.index(),
        display_destination(spec.destination().as_str()),
        reason.message()
    );
    err
}

/// 違反ではない前提不成立（`FAILED_PRECONDITION`）。message の先頭に位置と宛先を付ける。
fn failed(spec: &BindMountSpec, what: &str) -> ExecError {
    ExecError::new(
        ErrorCode::FailedPrecondition,
        STAGE,
        format!(
            "mounts[{}] ({}): {what}",
            spec.index(),
            display_destination(spec.destination().as_str())
        ),
    )
}

/// 共有ヘルパが返したエラーの message に位置と宛先を前置きする（違反記録・code・段は保つ）。
fn annotate(spec: &BindMountSpec, mut err: ExecError) -> ExecError {
    err.message = format!(
        "mounts[{}] ({}): {}",
        spec.index(),
        display_destination(spec.destination().as_str()),
        err.message
    );
    err
}

/// 新マウント API・syscall の失敗を写す。`Unsupported` は縮退せず `UNIMPLEMENTED` で拒否する。
fn mount_api_error(spec: &BindMountSpec, e: SysError, what: &str) -> ExecError {
    if matches!(e, SysError::Unsupported) {
        let mut err = failed(
            spec,
            "bind mount requires the new mount API (open_tree, mount_setattr, move_mount; \
             Linux 5.12 or later)",
        );
        err.code = ErrorCode::Unimplemented;
        return err;
    }
    annotate(spec, ExecError::from_sys(e, STAGE, what))
}

/// `open_tree(OPEN_TREE_CLONE)` の失敗を写す。非再帰の `EINVAL` は、配下にロックされたマウントを持つ元を
/// user namespace の中で非再帰に複製できないときに返る（`rbind` を促す）。この写像は、`establish` の `MS_PRIVATE` で
/// unbindable が残らないことと、同じ mount namespace の fd を開くことが前提（モジュール doc の一次情報の節、#2064）。
/// 前提が崩れても fail-closed で、メッセージが過剰に特定的になるだけ。
fn open_tree_error(spec: &BindMountSpec, e: SysError, scope: MountTreeScope) -> ExecError {
    if e == SysError::Os(sys::EINVAL) && scope == MountTreeScope::MountOnly {
        return failed(
            spec,
            "the source has submounts that cannot be bound non-recursively in a user namespace; \
             use rbind",
        );
    }
    mount_api_error(spec, e, "open_tree(bind mount source)")
}
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use crate::audit_log::mount::tests::VecSink;
    use crate::audit_log::{AuditDelivery, AuditLayer};
    use crate::exec::{ViolationKind, audit_mount_violation};
    use crate::oci_runtime::parse_config_bytes;
    use crate::test_support::TestTempDir;
    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};

    /// `statfs.f_flags` の値（include/linux/statfs.h）。
    const VALID: i64 = 0x20;
    const RDONLY: i64 = 0x1;
    const NOSUID: i64 = 0x2;
    const NODEV: i64 = 0x4;
    const NOEXEC: i64 = 0x8;

    /// 一時ディレクトリ配下の rootfs と元の置き場。
    struct Fx {
        tmp: TestTempDir,
        rootfs: PathBuf,
        src: PathBuf,
    }

    fn fx() -> Fx {
        let tmp = TestTempDir::new("bind-mounts").expect("temp dir");
        let rootfs = tmp.path().join("rootfs");
        let src = tmp.path().join("src");
        std::fs::create_dir(&rootfs).expect("rootfs");
        std::fs::create_dir(&src).expect("src");
        std::fs::create_dir(src.join("dir")).expect("src/dir");
        std::fs::write(src.join("file"), b"data").expect("src/file");
        Fx { tmp, rootfs, src }
    }

    impl Fx {
        fn src(&self, rel: &str) -> String {
            self.src.join(rel).to_str().expect("utf8").to_owned()
        }

        fn rootfs_fd(&self) -> OwnedFd {
            let c = CString::new(self.rootfs.as_os_str().as_bytes()).expect("cstring");
            sys::open_dir_path_nofollow(None, &c).expect("open rootfs")
        }

        /// `tmp` からの相対表記（記録を決定的にするため）。
        fn rel(&self, p: &Path) -> String {
            p.strip_prefix(self.tmp.path())
                .map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
        }
    }

    fn set_of(mounts: Vec<Value>) -> BindMountSet {
        let cfg = json!({"ociVersion": "1.2.0", "root": {"path": "rootfs"}, "mounts": mounts});
        let cfg = parse_config_bytes(cfg.to_string().as_bytes()).expect("valid config");
        BindMountSet::from_mounts(cfg.mounts()).expect("valid bind set")
    }

    /// 状態ルートの inode の鎖を持つ保護対象が無い集合は適用の段が fail-closed で拒否する（#2066）。mountinfo の層だけを
    /// 試験する既存のテストのため、元と無関係な状態ルート（`/proc`。FS 内パスと dev も無関係）を 1 件足す。
    fn pinned(mut roots: Vec<ProtectedFsRoot>) -> Vec<ProtectedFsRoot> {
        if !roots
            .iter()
            .any(|r| !r.is_containment_only() && !r.inode_chain().is_empty())
        {
            roots.push(
                ProtectedFsRoot::new("9:9".to_owned(), "/unrelated-state".to_owned(), false)
                    .with_inode_chain(
                        "/proc".to_owned(),
                        dir_identity_chain("/proc").expect("chain of /proc"),
                    ),
            );
        }
        roots
    }

    fn m(dest: &str, src: &str, opts: &[&str]) -> Value {
        json!({"destination": dest, "type": "bind", "source": src, "options": opts})
    }

    fn one(dest: &str, src: &str, opts: &[&str]) -> BindMountSet {
        set_of(vec![m(dest, src, opts)])
    }

    /// dry-run の挙動を変える設定。
    #[derive(Default)]
    struct Knobs {
        /// `rslave` の bind の事前の複製を返す（`establish_with` の代わり。#2669）。
        pre_cloned: bool,
        shared: bool,
        moved: bool,
        open_tree_err: Option<SysError>,
        /// 2 件目の `is_shared` だけを真にする。
        shared_on_second: bool,
        clone_flags: Option<i64>,
        observe_mod: Option<fn(BindObservation) -> BindObservation>,
        mountinfo: Option<String>,
        /// 真なら、保護対象の dev の行が無い mountinfo をそのまま渡す（#2536 の拒否の試験）。既定では、保護対象の dev ごとに
        /// overlay ではない行を `with_protected_dev_rows` で足す（既存の試験の意図を保つため。足した行は配下・祖先の判定に入らない）。
        strict_protected_dev: bool,
        umount_fail: bool,
        /// 固定した元の `f_type` を差し替える（`None` は本番と同じ `sys::fs_type`）。
        source_fs_type: Option<Result<i64, SysError>>,
        /// 状態ルートの (dev, path) の作り直しを差し替える（`None` は記録した値をそのまま返す。#2166）。
        state_identity: Option<fn(&ProtectedFsRoot) -> Option<FsIdentity>>,
    }

    fn bits(read_only: bool, noexec: bool) -> i64 {
        VALID
            | NOSUID
            | NODEV
            | if read_only { RDONLY } else { 0 }
            | if noexec { NOEXEC } else { 0 }
    }

    fn ideal_mountinfo(own: u64, read_only: bool, noexec: bool) -> String {
        let opts = format!(
            "{},nosuid,nodev{}",
            if read_only { "ro" } else { "rw" },
            if noexec { ",noexec" } else { "" }
        );
        format!("{own} 1 0:1 / /x {opts} - tmpfs none rw\n")
    }

    /// 保護対象の dev の行が `info` に無ければ、overlay ではない行（tmpfs。親は `/`、マウントポイントは保護対象と無関係）を足す。
    /// fail-closed 化（#2536）前の試験が前提にしていた「保護対象の dev は mountinfo に有る」状態を明示的に作る。
    fn with_protected_dev_rows(info: &str, roots: &[ProtectedFsRoot]) -> String {
        let mut out = info.to_owned();
        let mut seen: Vec<&str> = Vec::new();
        for r in roots {
            let dev = r.dev();
            if seen.contains(&dev) || info.lines().any(|l| l.split(' ').nth(2) == Some(dev)) {
                continue;
            }
            seen.push(dev);
            out.push_str(&format!(
                "{} 1 {dev} / /fixture-protected-dev-{} rw - tmpfs none rw\n",
                9000 + seen.len(),
                seen.len()
            ));
        }
        out
    }

    /// dry-run で `mount_binds_at` を回し、結果と呼び出し記録を返す。
    fn run(
        fx: &Fx,
        set: &BindMountSet,
        k: &Knobs,
    ) -> (Result<BindMountReport, ExecError>, Vec<String>) {
        let log = RefCell::new(Vec::<String>::new());
        let attrs = Cell::new((false, false));
        let src_id = Cell::new((0u64, 0u64));
        let shared_calls = Cell::new(0usize);
        let push = |s: String| log.borrow_mut().push(s);
        let deps = BindDeps {
            is_shared: &|_| {
                push("is_shared".into());
                shared_calls.set(shared_calls.get() + 1);
                Ok(k.shared || (k.shared_on_second && shared_calls.get() == 2))
            },
            still_at: &|_, p| {
                push(format!("still_at({})", fx.rel(p)));
                !k.moved
            },
            pre_cloned: &|index| {
                push(format!("pre_cloned({index})"));
                if !k.pre_cloned {
                    return None;
                }
                let spec = set.mounts().iter().find(|m| m.index() == index)?;
                let source = pin_source(spec).ok()?;
                src_id.set(source.fd.dev_ino());
                let clone = source.fd.as_fd().try_clone_to_owned().ok()?;
                Some(HostSlaveClone { source, clone })
            },
            open_tree: &|src, scope| {
                push(format!("open_tree({scope:?})"));
                if let Some(e) = k.open_tree_err {
                    return Err(e);
                }
                src_id.set(src.dev_ino());
                src.as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| SysError::Os(sys::EBADF))
            },
            set_attrs: &|_, a, scope| {
                let (set, clr, _, _, flags, _) = sys::bind_mount_call_params(a, scope);
                push(format!("setattr({set:#x},{clr:#x},{flags:#x})"));
                attrs.set((a.read_only, a.noexec));
                Ok(())
            },
            flags_of: &|_| {
                push("statfs_clone".into());
                let (ro, ne) = attrs.get();
                Ok(MountFlags::from_bits(k.clone_flags.unwrap_or(bits(ro, ne))))
            },
            attach: &|_, to| {
                let path = std::fs::read_link(format!("/proc/thread-self/fd/{}", to.as_raw_fd()))
                    .expect("readlink dest");
                push(format!("move_mount({})", fx.rel(&path)));
                Ok(())
            },
            observe: &|_, _, _| {
                push("observe".into());
                let (ro, ne) = attrs.get();
                let o = BindObservation {
                    before_mnt_id: 100,
                    after_mnt_id: 200,
                    own_mnt_id: 200,
                    flags: MountFlags::from_bits(bits(ro, ne)),
                    dev_ino: src_id.get(),
                };
                Ok(k.observe_mod.map_or(o, |f| f(o)))
            },
            mountinfo: &|| {
                push("mountinfo".into());
                let (ro, ne) = attrs.get();
                let info = k
                    .mountinfo
                    .clone()
                    .unwrap_or_else(|| ideal_mountinfo(200, ro, ne));
                Ok(if k.strict_protected_dev {
                    info
                } else {
                    with_protected_dev_rows(&info, set.protected_roots())
                })
            },
            source_mnt_id: &|_| Ok(1),
            source_path: &|src| {
                let path =
                    std::fs::read_link(format!("/proc/thread-self/fd/{}", src.as_fd().as_raw_fd()))
                        .expect("readlink source");
                Ok(path.to_str().expect("utf8").to_owned())
            },
            umount: &|fd| {
                let path = std::fs::read_link(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()))
                    .expect("readlink clone");
                push(format!("umount({})", fx.rel(&path)));
                if k.umount_fail {
                    Err(SysError::Os(sys::EBUSY))
                } else {
                    Ok(())
                }
            },
            source_fs_type: &|src| {
                k.source_fs_type
                    .unwrap_or_else(|| sys::fs_type(src.as_fd()))
            },
            state_identity: &|p, _| match k.state_identity {
                Some(f) => f(p),
                None => Some(FsIdentity {
                    dev: p.dev().to_owned(),
                    path: p.path().to_owned(),
                }),
            },
            before_attach: &|| push("before_attach".into()),
        };
        let root = fx.rootfs_fd();
        let result = mount_binds_at(root.as_fd(), set, &deps);
        (result, log.into_inner())
    }

    fn ok(fx: &Fx, set: &BindMountSet) -> BindMountReport {
        let (r, log) = run(fx, set, &Knobs::default());
        r.unwrap_or_else(|e| panic!("unexpected error: {e}; log: {log:?}"))
    }

    fn reason_of(err: &ExecError) -> Option<ViolationReason> {
        err.violation.as_ref().map(|v| v.reason)
    }

    /// SEC-1（#1915）: 適用の時点で固定した元が検査済みの状態ルートの実体に到達すれば、マウントせず拒否する。
    #[test]
    fn sec1_pinned_source_reaching_state_root_is_rejected_at_apply() {
        let fx = fx();
        let real = std::fs::canonicalize(fx.src("dir")).expect("canon");
        let real = real.to_str().expect("utf8").to_owned();
        // 状態ルートの実体 = 元と同じ FS 内パス（差し替えで元が状態ルートの別名になった状況）。
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::new("0:1".to_owned(), real, false),
        ]));
        let knobs = Knobs {
            mountinfo: Some("1 0 0:1 / / rw - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        assert_eq!(log, ["mountinfo"]);
        assert!(!fx.rootfs.join("mnt").exists());
    }

    /// SEC-1（#1915）: 固定した元が状態ルートの祖先（状態ルートを配下に含む）でも拒否する。
    #[test]
    fn sec1_pinned_ancestor_of_state_root_is_rejected_at_apply() {
        let fx = fx();
        let real = std::fs::canonicalize(fx.src("dir")).expect("canon");
        let state = format!("{}/state", real.to_str().expect("utf8"));
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::new("0:1".to_owned(), state, false),
        ]));
        let knobs = Knobs {
            mountinfo: Some("1 0 0:1 / / rw - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        let err = r.expect_err("must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
    }

    /// SEC-1・SEC-4（#2066）: (dev, ino) を差し替える継ぎ目。字句が別でも同じ実体の元（bind の別名）、状態ルートの祖先、
    /// 状態ルートの別名の配下は `BindSourceReachesStateRoot`、rootfs の鎖（bundle とその祖先）の別名は
    /// `BindSourceContainsRootfs`。bundle・rootfs の配下と無関係な元は受ける（#2063 案 B）。
    #[test]
    fn sec1_judge_source_inodes_detects_aliases_by_identity() {
        let state: &[(u64, u64)] = &[(7, 300), (7, 200), (7, 2)];
        let chains = [state];
        // rootfs の鎖: rootfs・bundle・`/`。
        let rootfs = [(7, 400), (7, 390), (7, 2)];
        let judge = |src, dirs: &[(u64, u64)]| judge_source_inodes(src, dirs, &rootfs, &chains);
        // 状態ルートの別名（同じ dev/ino）。
        assert_eq!(
            judge((7, 300), &[(7, 2)]),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        // 状態ルートの祖先（鎖の 2 番目）。
        assert_eq!(
            judge((7, 200), &[(7, 2)]),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        // 状態ルートの別名の配下（元の祖先に状態ルートがある）。
        assert_eq!(
            judge((7, 301), &[(7, 2), (7, 300)]),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        // bundle の別名・rootfs の別名。
        assert_eq!(
            judge((7, 390), &[(7, 2)]),
            Some(ViolationReason::BindSourceContainsRootfs)
        );
        assert_eq!(
            judge((7, 400), &[(7, 2)]),
            Some(ViolationReason::BindSourceContainsRootfs)
        );
        // bundle の配下（元の祖先に bundle がある）は受ける。
        assert_eq!(judge((7, 500), &[(7, 2), (7, 390)]), None);
        // 無関係な元。dev が違えば inode が同じでも別の実体。
        assert_eq!(judge((7, 600), &[(7, 2), (7, 599)]), None);
        assert_eq!(judge((8, 300), &[(8, 2)]), None);
    }

    /// SEC-1・SEC-4（#2066）: 実ファイルで、状態ルートの同一・祖先・配下（ディレクトリ・通常ファイル）を inode の層が拒否する。
    /// 保護対象の FS 内パス・dev は無関係な値にして、mountinfo の層では拒否されない条件にする。兄弟は受ける。（#2063 の決定 (d)。OCI-4）
    #[test]
    fn sec1_state_root_identity_rejects_same_ancestor_and_descendant_at_apply() {
        let fx = fx();
        let state = fx.src.join("state");
        std::fs::create_dir_all(state.join("sub")).expect("state/sub");
        std::fs::write(state.join("file"), b"s").expect("state/file");
        std::fs::create_dir(fx.src.join("sibling")).expect("sibling");
        let chain = dir_identity_chain(state.to_str().expect("utf8")).expect("chain");
        let protected = || {
            vec![
                ProtectedFsRoot::new("9:9".to_owned(), "/registered/state".to_owned(), false)
                    .with_inode_chain(state.to_str().expect("utf8").to_owned(), chain.clone()),
            ]
        };
        let reject = Knobs {
            mountinfo: Some("1 0 0:1 / / rw - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        for (what, src) in [
            ("same", fx.src("state")),
            ("ancestor", fx.src.to_str().expect("utf8").to_owned()),
            ("descendant dir", fx.src("state/sub")),
            ("descendant file", fx.src("state/file")),
        ] {
            let set = one("/mnt/d", &src, &[]).with_protected_roots(protected());
            let (r, _log) = run(&fx, &set, &reject);
            assert_eq!(
                reason_of(&r.expect_err(what)),
                Some(ViolationReason::BindSourceReachesStateRoot),
                "{what}"
            );
        }
        let ok = Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n{}",
                ideal_mountinfo(200, false, false)
            )),
            ..Knobs::default()
        };
        let set = one("/mnt/d", &fx.src("sibling"), &[]).with_protected_roots(protected());
        let (r, _log) = run(&fx, &set, &ok);
        r.expect("a sibling of the state root is applied");
    }

    /// SEC-1（#2066）: start の後に状態ルートが改名されても、固定した inode の鎖で拒否する（mountinfo の保存パスは古くなる）。
    #[test]
    fn sec1_renamed_state_root_is_still_rejected_at_apply() {
        let fx = fx();
        let state = fx.src.join("state");
        std::fs::create_dir_all(state.join("sub")).expect("state/sub");
        let chain = dir_identity_chain(state.to_str().expect("utf8")).expect("chain");
        std::fs::rename(&state, fx.src.join("moved")).expect("rename");
        let reject = Knobs {
            mountinfo: Some("1 0 0:1 / / rw - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        for src in [fx.src("moved"), fx.src("moved/sub")] {
            let set = one("/mnt/d", &src, &[]).with_protected_roots(vec![
                ProtectedFsRoot::new("9:9".to_owned(), "/registered/state".to_owned(), false)
                    .with_inode_chain(state.to_str().expect("utf8").to_owned(), chain.clone()),
            ]);
            let (r, _log) = run(&fx, &set, &reject);
            assert_eq!(
                reason_of(&r.expect_err("renamed state root")),
                Some(ViolationReason::BindSourceReachesStateRoot)
            );
        }
    }

    /// SEC-1（#2129）: start の後に状態ルートが別の親へ付け替えられる・差し替えられると、適用の段は記録したパスを辿り直して
    /// 一致しないため `FAILED_PRECONDITION` で拒否する（何も作らず、`open_tree` もしない）。変更なしは受ける。
    #[test]
    fn sec1_2129_state_root_moved_after_start_fails_closed_at_apply() {
        let fx = fx();
        std::fs::create_dir_all(fx.src.join("a/state")).expect("a/state");
        std::fs::create_dir(fx.src.join("b")).expect("b");
        std::fs::create_dir(fx.src.join("sibling")).expect("sibling");
        let state_a = fx.src.join("a/state");
        let chain = dir_identity_chain(state_a.to_str().expect("utf8")).expect("chain");
        let protected = |path: &Path| {
            vec![
                ProtectedFsRoot::new("9:9".to_owned(), "/registered/state".to_owned(), false)
                    .with_inode_chain(path.to_str().expect("utf8").to_owned(), chain.clone()),
            ]
        };
        let knobs = Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n{}",
                ideal_mountinfo(200, false, false)
            )),
            ..Knobs::default()
        };
        // (b) 変更なしは受ける。
        let set = one("/mnt/d", &fx.src("sibling"), &[]).with_protected_roots(protected(&state_a));
        let (r, _) = run(&fx, &set, &knobs);
        r.expect("unchanged state root is accepted");
        let _ = std::fs::remove_dir_all(fx.rootfs.join("mnt"));
        // (a) 別の親へ付け替える。
        std::fs::rename(&state_a, fx.src.join("b/state")).expect("reparent");
        let set = one("/mnt/d", &fx.src("sibling"), &[]).with_protected_roots(protected(&state_a));
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("moved state root");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "mounts[0] (/mnt/d): the state store root moved after start, so bind mount sources cannot be checked"
        );
        assert!(!log.iter().any(|l| l.starts_with("open_tree(")), "{log:?}");
        assert!(!fx.rootfs.join("mnt").exists());
        // (c) 元のパスを同名の新しいディレクトリで置き換える。
        std::fs::create_dir(&state_a).expect("replace");
        let set = one("/mnt/d", &fx.src("sibling"), &[]).with_protected_roots(protected(&state_a));
        let (r, _) = run(&fx, &set, &knobs);
        assert_eq!(
            r.expect_err("replaced state root").code,
            ErrorCode::FailedPrecondition
        );
    }

    /// SEC-1（#2066）: 保護対象があるのに inode の鎖を持つ状態ルートが無い集合は、照合できないため `FAILED_PRECONDITION`。
    #[test]
    fn sec1_apply_fails_closed_without_state_root_identity() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(vec![
            ProtectedFsRoot::new("9:9".to_owned(), "/registered/state".to_owned(), false),
            ProtectedFsRoot::contained("0:1".to_owned(), "/srv/bundle".to_owned()),
        ]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let err = r.expect_err("must fail closed");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message,
            "the state store root identity is missing, so bind mount sources cannot be checked"
        );
        assert!(log.is_empty());
    }

    /// SEC-1（#1915）: rootfs・bundle の実体（`ProtectedFsRoot::contained`）は、元がそれと同一・祖先のときだけ拒否する。
    /// 保護対象の配下の別の実体を元にすること、同じ FS 上のリンク数 2 以上の通常ファイルは拒否しない。（#2063 の決定 (d)。OCI-4）
    #[test]
    fn sec1_contained_root_rejects_only_same_or_ancestor_sources() {
        let fx = fx();
        std::fs::hard_link(fx.src.join("file"), fx.src.join("alias")).expect("link");
        let real = std::fs::canonicalize(fx.src("dir")).expect("canon");
        let real = real.to_str().expect("utf8").to_owned();
        let ok_info = format!(
            "1 0 0:1 / / rw - tmpfs none rw\n{}",
            ideal_mountinfo(200, false, false)
        );
        let knobs_ok = Knobs {
            mountinfo: Some(ok_info),
            ..Knobs::default()
        };
        let knobs_reject = Knobs {
            mountinfo: Some("1 0 0:1 / / rw - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        // 元が保護対象（bundle）の祖先 → 拒否。
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::contained("0:1".to_owned(), format!("{real}/bundle")),
        ]));
        let (r, _log) = run(&fx, &set, &knobs_reject);
        assert_eq!(
            reason_of(&r.expect_err("ancestor of bundle")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        // 保護対象の方が祖先（元はその配下）→ 許す。
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::contained("0:1".to_owned(), "/".to_owned()),
        ]));
        let (r, _log) = run(&fx, &set, &knobs_ok);
        r.expect("a source under the protected path is applied");
        // 同じ FS 上のリンク数 2 の通常ファイルは、rootfs・bundle の保護では拒否しない。
        let set = one("/mnt/f", &fx.src("alias"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::contained("0:1".to_owned(), "/srv/bundle".to_owned()),
        ]));
        let (r, _log) = run(&fx, &set, &knobs_ok);
        r.expect("hard-linked file is not a state file");
    }

    /// SEC-1（#1915）: 状態ルートと無関係な元は、保護対象があっても適用される（照合は mountinfo を 1 回読むだけ）。
    #[test]
    fn sec1_pinned_unrelated_source_passes_protected_check() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::new("0:9".to_owned(), "/srv/state".to_owned(), false),
        ]));
        let knobs = Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n{}",
                ideal_mountinfo(200, false, false)
            )),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &knobs);
        r.expect("applied");
        assert_eq!(log.first().map(String::as_str), Some("mountinfo"));
    }

    /// SEC-1（#1915）: 保護対象と同じファイルシステム上でリンク数が 2 以上の通常ファイルは、状態ファイルへの
    /// ハードリンクかもしれないため拒否する。リンク数 1 の通常ファイルや別 FS のファイルは拒否しない。
    #[test]
    fn sec1_hard_linked_regular_file_on_state_fs_is_rejected_at_apply() {
        let fx = fx();
        std::fs::hard_link(fx.src.join("file"), fx.src.join("alias")).expect("link");
        let info = "1 0 0:1 / / rw - tmpfs none rw\n".to_owned();
        let knobs = Knobs {
            mountinfo: Some(info.clone()),
            ..Knobs::default()
        };
        let protected = |dev: &str| {
            vec![ProtectedFsRoot::new(
                dev.to_owned(),
                "/srv/state".to_owned(),
                false,
            )]
        };
        // 同じ FS（0:1）の状態ルートがあり、リンク数 2 の通常ファイルを元にする → 拒否。
        let set =
            one("/mnt/f", &fx.src("alias"), &[]).with_protected_roots(pinned(protected("0:1")));
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        assert_eq!(log, ["mountinfo"]);
        // 状態ルートが別 FS（0:9）なら、同じファイルでもハードリンクで届かないため拒否しない。
        let set =
            one("/mnt/f", &fx.src("alias"), &[]).with_protected_roots(pinned(protected("0:9")));
        let knobs = Knobs {
            mountinfo: Some(format!("{info}{}", ideal_mountinfo(200, false, false))),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        r.expect("different filesystem is applied");
        // リンク数 1 の通常ファイルは拒否しない。
        std::fs::remove_file(fx.src.join("alias")).expect("unlink");
        let set =
            one("/mnt/f", &fx.src("file"), &[]).with_protected_roots(pinned(protected("0:1")));
        let knobs = Knobs {
            mountinfo: Some(format!("{info}{}", ideal_mountinfo(200, false, false))),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        r.expect("single link is applied");
    }

    /// SEC-1（#1915）: 状態ルート配下にハードリンクを持つ状態ファイルがあるとき、同じ FS 上のディレクトリ元は拒否する。
    #[test]
    fn sec1_directory_source_is_rejected_when_state_files_are_hard_linked() {
        let fx = fx();
        let info = "1 0 0:1 / / rw - tmpfs none rw\n".to_owned();
        let knobs = Knobs {
            mountinfo: Some(info),
            ..Knobs::default()
        };
        let protected = |linked: bool| {
            vec![ProtectedFsRoot::new(
                "0:1".to_owned(),
                "/srv/state".to_owned(),
                linked,
            )]
        };
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(protected(true)));
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        assert_eq!(log, ["mountinfo"]);
        let knobs = Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n{}",
                ideal_mountinfo(200, false, false)
            )),
            ..Knobs::default()
        };
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(protected(false)));
        let (r, _log) = run(&fx, &set, &knobs);
        r.expect("no hard linked state files is applied");
    }

    /// SEC-1・OCI-4（#1915）: 再帰 bind のときだけ、元の配下のマウント（状態ルートの実体）を理由に拒否する。
    #[test]
    fn sec1_nested_state_mount_is_rejected_only_for_rbind_at_apply() {
        let fx = fx();
        let real = std::fs::canonicalize(fx.src("dir")).expect("canon");
        let info = format!(
            "1 0 0:1 / / rw - tmpfs none rw\n5 1 0:2 /st {}/inner rw - tmpfs none rw\n",
            real.to_str().expect("utf8")
        );
        let protected = || {
            vec![ProtectedFsRoot::new(
                "0:2".to_owned(),
                "/st".to_owned(),
                false,
            )]
        };
        let set =
            one("/mnt/d", &fx.src("dir"), &["rbind"]).with_protected_roots(pinned(protected()));
        let knobs = Knobs {
            mountinfo: Some(info.clone()),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        let err = r.expect_err("rbind must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        // 非再帰 bind は配下のマウントを公開しないため、状態ルートの実体が配下にあっても拒否しない。
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(protected()));
        let knobs = Knobs {
            mountinfo: Some(format!("{info}{}", ideal_mountinfo(200, false, false))),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        r.expect("non-recursive bind is applied");
    }

    /// SEC-1（#1915）: 再帰 bind の子マウントが別 FS のとき、その FS 上のハードリンクの保護も適用する。
    /// 非再帰 bind は子マウントを公開しないため拒否しない。
    #[test]
    fn sec1_child_mount_fs_hard_links_are_checked_only_for_rbind() {
        let fx = fx();
        let real = std::fs::canonicalize(fx.src("dir")).expect("canon");
        let info = format!(
            "1 0 0:1 / / rw - tmpfs none rw\n5 1 0:7 / {}/inner rw - tmpfs none rw\n",
            real.to_str().expect("utf8")
        );
        let protected = || {
            vec![ProtectedFsRoot::new(
                "0:7".to_owned(),
                "/st".to_owned(),
                true,
            )]
        };
        let set =
            one("/mnt/d", &fx.src("dir"), &["rbind"]).with_protected_roots(pinned(protected()));
        let knobs = Knobs {
            mountinfo: Some(info.clone()),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        let err = r.expect_err("rbind with linked child fs must be rejected");
        assert_eq!(
            reason_of(&err),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(protected()));
        let knobs = Knobs {
            mountinfo: Some(format!("{info}{}", ideal_mountinfo(200, false, false))),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        r.expect("non-recursive bind is applied");
    }

    /// CORE-1・SEC-1・OCI-4: ディレクトリ・非再帰・rw の呼び出し順と具体値。
    #[test]
    fn core1_sec1_directory_bind_runs_in_order() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let report = r.expect("applied");
        assert_eq!(
            log,
            [
                "is_shared",
                "open_tree(MountOnly)",
                "setattr(0x6,0x0,0x1000)",
                "statfs_clone",
                "still_at(rootfs/mnt/d)",
                "before_attach",
                "move_mount(rootfs/mnt/d)",
                "observe",
                "mountinfo",
            ]
        );
        assert_eq!(report.mounts.len(), 1);
        let o = &report.mounts[0];
        assert_eq!(
            (
                o.index,
                o.destination.as_str(),
                o.source_kind,
                o.read_only,
                o.noexec,
                o.recursive,
                o.created_target
            ),
            (
                0,
                "/mnt/d",
                BindSourceType::Directory,
                false,
                false,
                false,
                true
            )
        );
        assert!(fx.rootfs.join("mnt/d").is_dir());
    }

    /// CORE-1・SEC-1: `rbind`＋`ro`＋`noexec` は再帰で複製し、属性は 0xf・`AT_RECURSIVE` を足す。
    #[test]
    fn core1_sec1_rbind_ro_noexec_uses_recursive_scope_and_all_attrs() {
        let fx = fx();
        let set = one("/d", &fx.src("dir"), &["rbind", "ro", "noexec"]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let report = r.expect("applied");
        assert_eq!(log.get(1).map(String::as_str), Some("open_tree(Recursive)"));
        assert_eq!(
            log.get(2).map(String::as_str),
            Some("setattr(0xf,0x0,0x9000)")
        );
        let o = &report.mounts[0];
        assert_eq!((o.read_only, o.noexec, o.recursive), (true, true, true));
    }

    /// CORE-1: 通常ファイルの元で宛先が無い場合、親ディレクトリと空の通常ファイルを作る。
    #[test]
    fn core1_file_source_creates_parent_and_empty_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = fx();
        let set = one("/etc/app/conf", &fx.src("file"), &[]);
        let report = ok(&fx, &set);
        let o = &report.mounts[0];
        assert_eq!(
            (o.source_kind, o.created_target),
            (BindSourceType::RegularFile, true)
        );
        let target = fx.rootfs.join("etc/app/conf");
        let meta = std::fs::symlink_metadata(&target).expect("target");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 0);
        let dir = std::fs::metadata(fx.rootfs.join("etc/app")).expect("dir");
        assert_eq!(dir.permissions().mode() & 0o700, 0o700);
    }

    /// CORE-1: 既存のマウント先は作らず（`created_target` は偽）、中身も消さない。
    #[test]
    fn core1_existing_target_is_not_created() {
        let fx = fx();
        std::fs::create_dir(fx.rootfs.join("mnt")).expect("mnt");
        std::fs::write(fx.rootfs.join("existing"), b"keep").expect("file");
        let set = set_of(vec![
            m("/mnt", &fx.src("dir"), &[]),
            m("/existing", &fx.src("file"), &[]),
        ]);
        let report = ok(&fx, &set);
        assert_eq!(
            report
                .mounts
                .iter()
                .map(|o| o.created_target)
                .collect::<Vec<_>>(),
            [false, false]
        );
        assert_eq!(
            std::fs::read(fx.rootfs.join("existing")).expect("read"),
            b"keep"
        );
    }

    /// 元の拒否は syscall の記録が 0 件で、宛先に何も作らない。
    fn assert_source_rejected(
        fx: &Fx,
        source: &str,
        reason: Option<ViolationReason>,
        code: ErrorCode,
    ) -> ExecError {
        let set = one("/mnt/x", source, &[]);
        let (r, log) = run(fx, &set, &Knobs::default());
        let err = r.expect_err("must be rejected");
        assert_eq!(log, Vec::<String>::new(), "{source}");
        assert!(!fx.rootfs.join("mnt").exists(), "{source}");
        assert_eq!(reason_of(&err), reason, "{source}: {err}");
        assert_eq!((err.code, err.stage), (code, IsolationStage::MountBinds));
        err
    }

    /// SEC-1: 元の経路の symlink（中間・末端）は辿らず拒否する。
    #[test]
    fn sec1_source_symlinks_are_rejected() {
        let fx = fx();
        std::fs::create_dir(fx.src.join("real")).expect("real");
        std::fs::create_dir(fx.src.join("real/sub")).expect("sub");
        std::os::unix::fs::symlink("real", fx.src.join("lnk")).expect("symlink");
        std::os::unix::fs::symlink("file", fx.src.join("flnk")).expect("symlink");
        for source in [fx.src("lnk/sub"), fx.src("lnk"), fx.src("flnk")] {
            assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceSymlink),
                ErrorCode::InvalidArgument,
            );
        }
    }

    /// SEC-1: ソケットなどディレクトリ・通常ファイル以外は拒否する。
    #[test]
    fn sec1_source_unsupported_type_is_rejected() {
        let fx = fx();
        let _listener =
            std::os::unix::net::UnixListener::bind(fx.src.join("sock")).expect("socket");
        assert_source_rejected(
            &fx,
            &fx.src("sock"),
            Some(ViolationReason::BindSourceUnsupportedType),
            ErrorCode::InvalidArgument,
        );
    }

    /// 存在しない元は違反ではなく `NOT_FOUND`（何も作らない）。
    #[test]
    fn missing_source_is_not_found_without_violation() {
        let fx = fx();
        let err = assert_source_rejected(&fx, &fx.src("nope"), None, ErrorCode::NotFound);
        assert!(err.message.contains("does not exist"), "{}", err.message);
        let err = assert_source_rejected(&fx, &fx.src("nope/deeper"), None, ErrorCode::NotFound);
        assert!(
            err.message.starts_with("mounts[0] (/mnt/x): "),
            "{}",
            err.message
        );
    }

    /// 後始末の前に権限を戻す（`TestTempDir` の再帰削除が失敗しないように）。
    struct RestoreMode(PathBuf);

    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    /// SEC-1: 起動を依頼した利用者の権限で読めない元（ディレクトリ・ファイル）は拒否する。
    ///
    /// 非 root 前提（CI の GitHub ホステッド runner と開発コンテナは非 root）。root で読めてしまう場合は
    /// 黙って通さず、前提が崩れたことを明示して失敗させる。
    #[test]
    fn sec1_unreadable_source_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = fx();
        std::fs::create_dir(fx.src.join("locked")).expect("locked");
        std::fs::write(fx.src.join("locked.txt"), b"x").expect("locked file");
        let _g1 = RestoreMode(fx.src.join("locked"));
        let _g2 = RestoreMode(fx.src.join("locked.txt"));
        for p in ["locked", "locked.txt"] {
            std::fs::set_permissions(fx.src.join(p), std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
        }
        assert!(
            std::fs::read_dir(fx.src.join("locked")).is_err()
                && std::fs::read(fx.src.join("locked.txt")).is_err(),
            "this test requires a non-root user; the fixture is readable"
        );
        for source in [fx.src("locked"), fx.src("locked.txt")] {
            let err = assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceNotAccessible),
                ErrorCode::PermissionDenied,
            );
            assert!(
                !err.message.contains("locked"),
                "host path leaked: {}",
                err.message
            );
        }
    }

    /// SEC-1: rootfs 自身とその祖先は元にできない（実体の `(dev, ino)` で照合する）。
    #[test]
    fn sec1_source_containing_rootfs_is_rejected() {
        let fx = fx();
        for source in [
            fx.rootfs.to_str().expect("utf8").to_owned(),
            fx.tmp.path().to_str().expect("utf8").to_owned(),
        ] {
            assert_source_rejected(
                &fx,
                &source,
                Some(ViolationReason::BindSourceContainsRootfs),
                ErrorCode::InvalidArgument,
            );
        }
    }

    /// rootfs の祖先の鎖は rootfs 自身から始まり、名前空間のルートで終わる。
    #[test]
    fn rootfs_identity_chain_starts_at_rootfs_and_ends_at_root() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let root = fx.rootfs_fd();
        let chain = rootfs_identity_chain(root.as_fd()).expect("chain");
        let id = |p: &Path| {
            let m = std::fs::metadata(p).expect("metadata");
            (m.dev(), m.ino())
        };
        assert_eq!(chain.first(), Some(&id(&fx.rootfs)));
        assert_eq!(chain.get(1), Some(&id(fx.tmp.path())));
        assert_eq!(chain.last(), Some(&id(Path::new("/"))));
        assert!(chain.len() >= 3);
    }

    /// SEC-1: マウント先の symlink（中間・末端）は拒否し、既存の内容は残る。
    #[test]
    fn sec1_target_symlinks_are_rejected() {
        let fx = fx();
        std::fs::create_dir(fx.rootfs.join("keep")).expect("keep");
        std::fs::write(fx.rootfs.join("keep/inside"), b"x").expect("inside");
        std::os::unix::fs::symlink("/etc", fx.rootfs.join("keep/sym")).expect("symlink");
        std::os::unix::fs::symlink("/etc", fx.rootfs.join("leaf")).expect("symlink");
        for dest in ["/keep/sym/x", "/leaf"] {
            let set = one(dest, &fx.src("dir"), &[]);
            let (r, log) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("must be rejected");
            assert_eq!(
                reason_of(&err),
                Some(ViolationReason::PathSymlinkOrNotDirectory),
                "{dest}"
            );
            assert_eq!(log, Vec::<String>::new(), "{dest}");
        }
        assert!(fx.rootfs.join("keep/inside").is_file());
        // 拒否前に作ったディレクトリ（`new/...`）は後始末で消える。
        let set = set_of(vec![
            m("/new/deep", &fx.src("dir"), &[]),
            m("/leaf", &fx.src("dir"), &[]),
        ]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        assert!(r.is_err());
        assert!(log.iter().any(|l| l.starts_with("umount")), "{log:?}");
        assert!(!fx.rootfs.join("new").exists());
    }

    /// SEC-1: 既存のマウント先の種別が元と違えば拒否し、既存のものは消さない。
    #[test]
    fn sec1_target_kind_mismatch_is_rejected() {
        let fx = fx();
        std::fs::write(fx.rootfs.join("afile"), b"keep").expect("file");
        std::fs::create_dir(fx.rootfs.join("adir")).expect("dir");
        for (dest, source) in [("/afile", fx.src("dir")), ("/adir", fx.src("file"))] {
            let set = one(dest, &source, &[]);
            let (r, log) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("must be rejected");
            assert_eq!(
                reason_of(&err),
                Some(ViolationReason::BindTargetKindMismatch),
                "{dest}"
            );
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            assert_eq!(log, Vec::<String>::new());
        }
        assert_eq!(
            std::fs::read(fx.rootfs.join("afile")).expect("read"),
            b"keep"
        );
        assert!(fx.rootfs.join("adir").is_dir());
    }

    /// SEC-1・CORE-1: shared の宛先には載せない（複製に進まず、作った要素は消える）。
    #[test]
    fn sec1_shared_target_is_rejected_before_clone() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            shared: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::TargetOnSharedMount));
        assert_eq!(log, ["is_shared"]);
        assert!(!fx.rootfs.join("mnt").exists());
    }

    /// SEC-1: 付け替え直前の移動検査。付け替えには進まず、作った要素は消える。
    #[test]
    fn sec1_moved_target_is_rejected_before_attach() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            moved: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::TargetMoved));
        assert_eq!(
            log.last().map(String::as_str),
            Some("still_at(rootfs/mnt/d)")
        );
        assert!(!log.iter().any(|l| l.starts_with("move_mount")), "{log:?}");
        assert!(!log.iter().any(|l| l == "before_attach"), "{log:?}");
        assert!(!log.iter().any(|l| l.starts_with("umount")), "{log:?}");
        assert!(!fx.rootfs.join("mnt").exists());
    }

    /// SEC-1: 付け替え前の属性確認。読み取り専用の元を rw で載せない・要求した `ro`/`noexec` が付かなければ拒否する。
    #[test]
    fn sec1_pre_attach_flag_mismatch_is_rejected() {
        let fx = fx();
        let cases: [(&[&str], i64, &str); 4] = [
            (&[], bits(true, false), "specify ro"),
            (&[], bits(false, true), "specify noexec"),
            (&["ro"], bits(false, false), "ro was not applied"),
            (&["noexec"], bits(false, false), "noexec was not applied"),
        ];
        for (opts, flags, needle) in cases {
            let set = one("/mnt/d", &fx.src("dir"), opts);
            let k = Knobs {
                clone_flags: Some(flags),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opts:?}");
            assert_eq!(err.violation, None);
            assert!(err.message.contains(needle), "{}", err.message);
            assert!(err.message.contains("before attach"), "{}", err.message);
            assert!(!log.iter().any(|l| l.starts_with("move_mount")), "{log:?}");
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// SEC-1: 事後検証の各失敗は `FAILED_PRECONDITION`。自分のマウントを外し、作った要素を消す。
    #[test]
    fn sec1_post_verification_failures_roll_back() {
        let fx = fx();
        type Modify = fn(BindObservation) -> BindObservation;
        let observed: [(Modify, &str); 4] = [
            (
                |o| BindObservation {
                    after_mnt_id: o.before_mnt_id,
                    ..o
                },
                "no new mount",
            ),
            (
                |o| BindObservation { own_mnt_id: 7, ..o },
                "not the mount created by this call",
            ),
            (
                |o| BindObservation {
                    flags: MountFlags::from_bits(VALID | NODEV),
                    ..o
                },
                "after mount: nosuid and nodev",
            ),
            (
                |o| BindObservation {
                    dev_ino: (1, 2),
                    ..o
                },
                "not the same inode",
            ),
        ];
        for (modify, needle) in observed {
            let set = one("/mnt/d", &fx.src("dir"), &[]);
            let k = Knobs {
                observe_mod: Some(modify),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert!(err.message.contains(needle), "{}", err.message);
            assert_eq!(
                log.last().map(String::as_str),
                Some("umount(src/dir)"),
                "{log:?}"
            );
            assert!(!fx.rootfs.join("mnt").exists(), "{needle}");
        }
        let infos = [
            (
                "200 1 0:1 / /x rw,nosuid,nodev shared:5 - tmpfs none rw\n",
                "shared or a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid,nodev master:3 - tmpfs none rw\n",
                "shared or a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid - tmpfs none rw\n",
                "nosuid and nodev",
            ),
            (
                "201 1 0:1 / /x rw,nosuid,nodev - tmpfs none rw\n",
                "no mount entry",
            ),
            ("garbage\n", "malformed line"),
        ];
        for (info, needle) in infos {
            let set = one("/mnt/d", &fx.src("dir"), &[]);
            let k = Knobs {
                mountinfo: Some(info.to_owned()),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &k);
            let err = r.expect_err("must be rejected");
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert!(err.message.contains(needle), "{}", err.message);
            assert_eq!(
                log.last().map(String::as_str),
                Some("umount(src/dir)"),
                "{log:?}"
            );
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// REPAIR-4: 2 件目の失敗で 1 件目の自分のマウントが外れる。後始末の失敗は message に併記し、
    /// code・stage・violation は保つ。
    #[test]
    fn repair4_second_failure_rolls_back_first_and_reports_cleanup_failure() {
        let fx = fx();
        let set = set_of(vec![
            m("/a", &fx.src("dir"), &[]),
            m("/b/c", &fx.src("file"), &[]),
        ]);
        let k = Knobs {
            shared_on_second: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let base = r.expect_err("second must fail");
        assert_eq!(reason_of(&base), Some(ViolationReason::TargetOnSharedMount));
        assert_eq!(base.stage, IsolationStage::MountBinds);
        assert_eq!(log.last().map(String::as_str), Some("umount(src/dir)"));
        assert_eq!(
            log.iter().filter(|l| l.starts_with("umount")).count(),
            1,
            "{log:?}"
        );
        assert!(!fx.rootfs.join("a").exists());
        assert!(!fx.rootfs.join("b").exists());
        assert!(
            base.message.starts_with("mounts[1] (/b/c): "),
            "{}",
            base.message
        );

        let k = Knobs {
            shared_on_second: true,
            umount_fail: true,
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let failed = r.expect_err("second must fail");
        assert_eq!(
            (failed.code, failed.stage, &failed.violation),
            (base.code, base.stage, &base.violation)
        );
        let suffix = failed
            .message
            .strip_prefix(&base.message)
            .expect("same prefix");
        assert!(
            suffix.starts_with("; cleanup failed: umount2(/a) failed: "),
            "{suffix}"
        );
    }

    /// 新マウント API の無いカーネルは `mount(2)` へ縮退せず `UNIMPLEMENTED`。非再帰の `EINVAL` は `rbind` を促す。
    #[test]
    fn unsupported_kernel_is_unimplemented_and_einval_hints_rbind() {
        let fx = fx();
        let set = one("/mnt/d", &fx.src("dir"), &[]);
        let k = Knobs {
            open_tree_err: Some(SysError::Unsupported),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(err.code, ErrorCode::Unimplemented);
        assert!(err.message.contains("new mount API"), "{}", err.message);
        assert_eq!(log, ["is_shared", "open_tree(MountOnly)"]);
        assert!(!fx.rootfs.join("mnt").exists());

        let k = Knobs {
            open_tree_err: Some(SysError::Os(sys::EINVAL)),
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let err = r.expect_err("must be rejected");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("use rbind"), "{}", err.message);
        let rset = one("/mnt/d", &fx.src("dir"), &["rbind"]);
        let (r, _) = run(&fx, &rset, &k);
        assert!(!r.expect_err("rejected").message.contains("use rbind"));
    }

    /// 空の集合は何もしない（rootfs の祖先も辿らない）。
    #[test]
    fn empty_set_does_nothing() {
        let fx = fx();
        let (r, log) = run(&fx, &BindMountSet::default(), &Knobs::default());
        assert_eq!(r.expect("empty"), BindMountReport { mounts: Vec::new() });
        assert_eq!(log, Vec::<String>::new());
    }

    /// SEC-5: user namespace の判定（初期 user namespace・ホストの ID 0 の写像は拒否）。
    #[test]
    fn sec5_judge_user_namespace() {
        let map = |c, h, n| IdMapping {
            container_id: c,
            host_id: h,
            count: n,
        };
        let ok_ns = USER_NS_INIT_INO + 100;
        assert_eq!(
            judge_user_namespace(USER_NS_INIT_INO, &[map(0, 1000, 1)], &[map(0, 1000, 1)]),
            Err(ViolationReason::UserNamespaceRequired)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 0, 4_294_967_295)], &[map(0, 1000, 1)]),
            Err(ViolationReason::HostRootIdentityMapping)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 1000, 1)], &[map(0, 0, 1)]),
            Err(ViolationReason::HostRootIdentityMapping)
        );
        assert_eq!(
            judge_user_namespace(ok_ns, &[map(0, 1000, 1)], &[map(0, 1000, 1)]),
            Ok(())
        );
        assert_eq!(
            judge_user_namespace(
                ok_ns,
                &[map(0, 1000, 1), map(1, 100_000, 65_536)],
                &[map(0, 1000, 1), map(1, 100_000, 65_536)]
            ),
            Ok(())
        );
    }

    fn flags(b: i64) -> MountFlags {
        MountFlags::from_bits(b)
    }

    /// `check_flags` の具体値。
    #[test]
    fn check_flags_is_exact() {
        let rw = Expected {
            read_only: false,
            noexec: false,
        };
        let ro_ne = Expected {
            read_only: true,
            noexec: true,
        };
        assert_eq!(check_flags(flags(bits(false, false)), rw), Ok(()));
        assert_eq!(check_flags(flags(bits(true, true)), ro_ne), Ok(()));
        assert!(check_flags(flags(NOSUID | NODEV), rw).is_err());
        assert!(check_flags(flags(VALID | NODEV), rw).is_err());
        assert!(check_flags(flags(VALID | NOSUID), rw).is_err());
        assert!(
            check_flags(flags(bits(true, false)), rw)
                .unwrap_err()
                .ends_with("specify ro")
        );
        assert!(
            check_flags(flags(bits(false, true)), rw)
                .unwrap_err()
                .ends_with("specify noexec")
        );
        assert!(check_flags(flags(bits(false, false)), ro_ne).is_err());
    }

    fn line(id: u64, parent: u64, opts: &str, optional: &str) -> String {
        format!("{id} {parent} 0:1 / /x {opts} {optional} - tmpfs none rw\n")
    }

    /// OCI-4・SEC-1（#2669）: `rslave` の bind は事前の複製を使い、`open_tree` を呼ばない。最上位に `master:` があれば受ける。
    #[test]
    fn oci4_rslave_bind_uses_pre_cloned_source_and_accepts_master() {
        let fx = fx();
        let set = one("/d", &fx.src("dir"), &["rbind", "rslave"]);
        let knobs = Knobs {
            pre_cloned: true,
            mountinfo: Some("200 1 0:1 / /x rw,nosuid,nodev master:3 - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &knobs);
        let report = r.unwrap_or_else(|e| panic!("unexpected error: {e}; log: {log:?}"));
        assert_eq!(log.first().map(String::as_str), Some("pre_cloned(0)"));
        assert!(!log.iter().any(|l| l.starts_with("open_tree(")), "{log:?}");
        assert_eq!(report.mounts.len(), 1);
        assert!(report.mounts[0].recursive);
    }

    /// SEC-1（#2669）: `rslave` でも最上位に `master:` が無ければ（private で載った）拒否し、`shared:` は拒否する。
    #[test]
    fn sec1_rslave_bind_requires_master_and_rejects_shared() {
        for (info, needle) in [
            (
                "200 1 0:1 / /x rw,nosuid,nodev - tmpfs none rw\n",
                "not a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid,nodev shared:5 - tmpfs none rw\n",
                "shared or a slave",
            ),
            (
                "200 1 0:1 / /x rw,nosuid,nodev shared:5 master:3 - tmpfs none rw\n",
                "shared or a slave",
            ),
        ] {
            let fx = fx();
            let set = one("/d", &fx.src("dir"), &["rbind", "rslave"]);
            let knobs = Knobs {
                pre_cloned: true,
                mountinfo: Some(info.to_owned()),
                ..Knobs::default()
            };
            let (r, _log) = run(&fx, &set, &knobs);
            let err = r.expect_err(info);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{info}");
            assert!(err.message.contains(needle), "{info}: {}", err.message);
        }
    }

    /// SEC-1（#2669）: private の bind は従来どおり `master:` を拒否する（`rslave` の許可を private へ広げない）。
    #[test]
    fn sec1_private_bind_still_rejects_master() {
        let fx = fx();
        let set = one("/d", &fx.src("dir"), &["rbind"]);
        let knobs = Knobs {
            mountinfo: Some("200 1 0:1 / /x rw,nosuid,nodev master:3 - tmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        let (r, _log) = run(&fx, &set, &knobs);
        let err = r.expect_err("master on a private bind");
        assert!(err.message.contains("shared or a slave"), "{}", err.message);
    }

    /// SEC-1（#2669）: `establish_with` を通っていない（事前の複製が無い）`rslave` の bind は、何も作らず `INTERNAL` で拒否する。
    #[test]
    fn sec1_rslave_bind_without_pre_clone_fails_closed() {
        let fx = fx();
        let set = one("/d", &fx.src("dir"), &["rbind", "rslave"]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let err = r.expect_err("no pre clone");
        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(log, ["pre_cloned(0)"]);
        assert!(!fx.rootfs.join("d").exists());
    }

    /// OCI-4（#2669）: ホスト側の元が slave か判定する純関数。`master:`・`propagate_from:` があり `shared:` が無ければ真。
    #[test]
    fn oci4_source_mount_is_host_slave_by_mountinfo() {
        let l = |id: u64, optional: &str| line(id, 1, "rw", optional);
        assert_eq!(source_mount_is_host_slave(&l(10, "master:3"), 10), Ok(true));
        assert_eq!(
            source_mount_is_host_slave(&l(10, "master:3 propagate_from:2"), 10),
            Ok(true)
        );
        assert_eq!(
            source_mount_is_host_slave(&l(10, "propagate_from:2"), 10),
            Ok(true)
        );
        assert_eq!(source_mount_is_host_slave(&l(10, ""), 10), Ok(false));
        assert_eq!(
            source_mount_is_host_slave(&l(10, "shared:5"), 10),
            Ok(false)
        );
        assert_eq!(
            source_mount_is_host_slave(&l(10, "shared:5 master:3"), 10),
            Ok(false)
        );
        // 別のマウントの行は見ない。
        let two = format!("{}{}", l(10, ""), l(11, "master:3"));
        assert_eq!(source_mount_is_host_slave(&two, 10), Ok(false));
        assert_eq!(source_mount_is_host_slave(&two, 11), Ok(true));
        // 該当なし・重複・書式違反は fail-closed。
        assert!(
            source_mount_is_host_slave(&l(10, "master:3"), 99)
                .unwrap_err()
                .contains("no mount entry")
        );
        let dup = format!("{}{}", l(10, "master:3"), l(10, "master:3"));
        assert!(
            source_mount_is_host_slave(&dup, 10)
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            source_mount_is_host_slave("x y\n", 10)
                .unwrap_err()
                .contains("malformed")
        );
    }

    /// `check_bind_subtree`: 自分のマウントは `ro`・`noexec` が要求と完全一致、配下は要求した制限が付いていればよい。
    #[test]
    fn check_bind_subtree_is_exact_for_top_and_requires_restrictions_for_children() {
        let rw = Expected {
            read_only: false,
            noexec: false,
        };
        let ro = Expected {
            read_only: true,
            noexec: false,
        };
        let good_top = line(10, 1, "rw,nosuid,nodev", "");
        let child_ro = line(11, 10, "ro,nosuid,nodev,noexec", "");
        let child_plain = line(11, 10, "rw,nosuid,nodev", "");
        let child_no_nosuid = line(11, 10, "rw,nodev", "");
        let child_shared = line(11, 10, "rw,nosuid,nodev", "shared:9");
        let grandchild_shared = line(12, 11, "rw,nosuid,nodev", "master:9");
        let other = line(50, 1, "rw", "shared:1");

        assert_eq!(check_bind_subtree(&good_top, 10, rw, false), Ok(()));
        // 非再帰では配下を見ない。
        assert_eq!(
            check_bind_subtree(&format!("{good_top}{child_no_nosuid}"), 10, rw, false),
            Ok(())
        );
        // 無関係のマウントは見ない。
        assert_eq!(
            check_bind_subtree(&format!("{other}{good_top}"), 10, rw, true),
            Ok(())
        );
        // 配下の元が持つより強い制限は許す。
        assert_eq!(
            check_bind_subtree(&format!("{good_top}{child_ro}"), 10, rw, true),
            Ok(())
        );
        for (info, needle) in [
            (format!("{good_top}{child_no_nosuid}"), "nosuid and nodev"),
            (format!("{good_top}{child_shared}"), "shared or a slave"),
            (
                format!("{good_top}{child_plain}{grandchild_shared}"),
                "shared or a slave",
            ),
        ] {
            let e = check_bind_subtree(&info, 10, rw, true).unwrap_err();
            assert!(e.contains(needle), "{e}");
        }
        // 配下に要求した `ro` が付いていなければ拒否。
        let ro_top = line(10, 1, "ro,nosuid,nodev", "");
        assert_eq!(check_bind_subtree(&ro_top, 10, ro, true), Ok(()));
        let e = check_bind_subtree(&format!("{ro_top}{child_plain}"), 10, ro, true).unwrap_err();
        assert!(e.contains("ro is not set"), "{e}");
        // 自分のマウントは完全一致。
        let e = check_bind_subtree(&ro_top, 10, rw, false).unwrap_err();
        assert!(e.contains("specify ro"), "{e}");
        let e = check_bind_subtree(&good_top, 10, ro, false).unwrap_err();
        assert!(e.contains("ro is not set"), "{e}");
        // 該当なし・重複・書式違反は fail-closed。
        assert!(
            check_bind_subtree(&good_top, 99, rw, false)
                .unwrap_err()
                .contains("no mount entry")
        );
        assert!(
            check_bind_subtree(&format!("{good_top}{good_top}"), 10, rw, false)
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(
            check_bind_subtree("10 1 0:1 / /x rw,nosuid,nodev\n", 10, rw, false)
                .unwrap_err()
                .contains("malformed")
        );
        assert!(
            check_bind_subtree(&format!("{good_top}x y\n"), 10, rw, false)
                .unwrap_err()
                .contains("malformed")
        );
    }

    /// 宛先をエスケープして message に入れる（ログ注入の防止）。
    #[test]
    fn message_escapes_destination() {
        let fx = fx();
        let set = one("/new\ndir", &fx.src("dir"), &[]);
        let k = Knobs {
            shared: true,
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &k);
        let err = r.expect_err("rejected");
        assert!(err.message.contains("/new\\ndir"), "{}", err.message);
        assert!(!err.message.contains('\n'), "{}", err.message);
    }

    /// SEC-4: 新しい理由の `ExecError` は `audit_mount_violation` で `Mount` レコードになり、パスはコンテナ内の宛先。
    #[test]
    fn sec4_violations_become_mount_audit_records_with_container_path() {
        let fx = fx();
        std::os::unix::fs::symlink("file", fx.src.join("flnk")).expect("symlink");
        std::fs::write(fx.rootfs.join("afile"), b"x").expect("file");
        let cases = [
            (
                one("/mnt/x", &fx.src("flnk"), &[]),
                "bind_source_symlink",
                "/mnt/x",
            ),
            (
                one("/afile", &fx.src("dir"), &[]),
                "bind_target_kind_mismatch",
                "/afile",
            ),
        ];
        for (set, token, dest) in cases {
            let (r, _) = run(&fx, &set, &Knobs::default());
            let err = r.expect_err("rejected");
            let sink = VecSink::new(false);
            let out = audit_mount_violation(err, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::Recorded, "{token}");
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(
                recs[0].reason().map(crate::audit_log::AuditReason::as_str),
                Some(token)
            );
            assert_eq!(recs[0].path(), Some(Path::new(dest)));
        }
    }

    /// SEC-1・SEC-4（#2098）: 拒否リストの表の件数・各行の (magic, name) の具体値・重複なし。
    #[test]
    fn sec1_2098_denylist_table_is_exact() {
        let expected: [(Option<i64>, &str); 22] = [
            (Some(0x9fa0), "proc"),
            (Some(0x6265_6572), "sysfs"),
            (Some(0x6462_6720), "debugfs"),
            (Some(0x7472_6163), "tracefs"),
            (Some(0x7363_6673), "securityfs"),
            (Some(0x0027_e0eb), "cgroup"),
            (Some(0x6367_7270), "cgroup2"),
            (Some(0xcafe_4a11), "bpf"),
            (Some(0x6265_6570), "configfs"),
            (Some(0x6165_676c), "pstore"),
            (Some(0xde5e_81e4), "efivarfs"),
            (Some(0xf97c_ff8c), "selinuxfs"),
            (Some(0x4341_5d53), "smackfs"),
            (Some(0x4249_4e4d), "binfmt_misc"),
            (Some(0x6573_5543), "fusectl"),
            (Some(0x0765_5821), "resctrl"),
            (Some(0xabba_1974), "xenfs"),
            (Some(0x6e73_6673), "nsfs"),
            (Some(0x1980_0202), "mqueue"),
            (Some(0x1cd1), "devpts"),
            (Some(0x6c6f_6f70), "binder"),
            (None, "devtmpfs"),
        ];
        let actual: Vec<(Option<i64>, &str)> = PSEUDO_FS_DENYLIST
            .iter()
            .map(|p| (p.magic, p.name))
            .collect();
        assert_eq!(actual, expected);
        for (i, a) in PSEUDO_FS_DENYLIST.iter().enumerate() {
            for b in &PSEUDO_FS_DENYLIST[i + 1..] {
                assert_ne!(a.magic, b.magic);
                assert_ne!(a.name, b.name);
            }
        }
    }

    /// SEC-1（#2129）: devtmpfs は `f_type` が tmpfs と同じで、fstype 名だけで拒否する。
    #[test]
    fn sec1_2129_devtmpfs_is_rejected_by_name_only() {
        assert_eq!(pseudo_fs_by_magic(sys::TMPFS_MAGIC), None);
        assert_eq!(
            pseudo_fs_by_name("devtmpfs").map(|x| x.name),
            Some("devtmpfs")
        );
        assert_eq!(pseudo_fs_by_name("tmpfs"), None);
    }

    /// SEC-1（#2098）: 拒否リストの各値は拒否され、通常の FS は受ける（f_type・fstype 名の両方）。
    #[test]
    fn sec1_2098_pseudo_fs_by_magic_and_name() {
        for p in &PSEUDO_FS_DENYLIST {
            if let Some(m) = p.magic {
                assert_eq!(pseudo_fs_by_magic(m).map(|x| x.name), Some(p.name));
            }
            assert_eq!(pseudo_fs_by_name(p.name).map(|x| x.magic), Some(p.magic));
        }
        for regular in [
            0xef53,      // ext4
            0x5846_5342, // xfs
            0x9123_683e, // btrfs
            0x0102_1994, // tmpfs（devtmpfs も同じ値で区別できない）
            0x794c_7630, // overlayfs
            0x6573_5546, // FUSE
            0x6969,      // NFS
            0x8584_58f6, // ramfs
            0,
            -1,
        ] {
            assert_eq!(pseudo_fs_by_magic(regular), None, "{regular:#x}");
        }
        for name in ["ext4", "tmpfs", "fuse.lxcfs", "overlay", "", "Proc"] {
            assert_eq!(pseudo_fs_by_name(name), None, "{name}");
        }
    }

    /// SEC-1・SEC-4（#2098）: 拒否リストの各 f_type は、宛先に何も作る前に `bind_source_pseudo_fs` で拒否され、
    /// message はコンテナ内の宛先と FS 名だけを含みホスト側の元のパスを含まない（ディレクトリ・通常ファイルの元）。
    #[test]
    fn sec1_2098_pseudo_fs_source_is_rejected_before_any_mount() {
        let fx = fx();
        for source in [fx.src("dir"), fx.src("file")] {
            for p in PSEUDO_FS_DENYLIST.iter().filter(|p| p.magic.is_some()) {
                let set = one("/mnt/x", &source, &[]);
                let knobs = Knobs {
                    source_fs_type: p.magic.map(Ok),
                    ..Knobs::default()
                };
                let (r, log) = run(&fx, &set, &knobs);
                let err = r.expect_err("must be rejected");
                assert_eq!(log, Vec::<String>::new(), "{}", p.name);
                assert!(!fx.rootfs.join("mnt").exists(), "{}", p.name);
                assert_eq!(reason_of(&err), Some(ViolationReason::BindSourcePseudoFs));
                assert_eq!(
                    (err.code, err.stage),
                    (ErrorCode::InvalidArgument, IsolationStage::MountBinds)
                );
                assert!(
                    err.message.starts_with("mounts[0] (/mnt/x): "),
                    "{}",
                    err.message
                );
                assert!(
                    err.message.ends_with(&format!(" ({})", p.name)),
                    "{}",
                    err.message
                );
                assert!(!err.message.contains(&source), "{}", err.message);
            }
        }
    }

    /// SEC-1（#2098）: 通常の FS の値なら従来どおり最後まで適用される。
    #[test]
    fn sec1_2098_regular_fs_source_is_accepted() {
        let fx = fx();
        let set = one("/mnt/x", &fx.src("dir"), &[]);
        let knobs = Knobs {
            source_fs_type: Some(Ok(0xef53)),
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &knobs);
        r.unwrap_or_else(|e| panic!("unexpected error: {e}; log: {log:?}"));
        assert!(log.iter().any(|l| l.starts_with("move_mount(")), "{log:?}");
    }

    /// SEC-1・REPAIR-4（#2098）: `fstatfs` の失敗は fail-closed（何も作らない）。対応外は `UNIMPLEMENTED`。
    #[test]
    fn sec1_2098_source_fs_type_errors_fail_closed() {
        let fx = fx();
        for (e, code) in [
            (SysError::Unsupported, ErrorCode::Unimplemented),
            (
                SysError::Os(sys::EBADF),
                ExecError::from_sys(SysError::Os(sys::EBADF), STAGE, "x").code,
            ),
        ] {
            let set = one("/mnt/x", &fx.src("dir"), &[]);
            let knobs = Knobs {
                source_fs_type: Some(Err(e)),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err("must fail");
            assert_eq!(err.code, code, "{e:?}");
            assert_eq!(reason_of(&err), None);
            assert_eq!(log, Vec::<String>::new());
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// SEC-1（#2098）: 本番の `sys::fs_type` で、実際の procfs（`/proc/sys`。symlink でないディレクトリ）の元が拒否される。
    #[test]
    fn sec1_2098_real_procfs_source_is_rejected() {
        let fx = fx();
        if !Path::new("/proc/sys").is_dir() {
            return;
        }
        let set = one("/mnt/x", "/proc/sys", &[]);
        let (r, log) = run(&fx, &set, &Knobs::default());
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::BindSourcePseudoFs));
        assert!(err.message.ends_with(" (proc)"), "{}", err.message);
        assert_eq!(log, Vec::<String>::new());
    }

    fn pseudo_mountinfo(child_fstype: &str) -> String {
        format!(
            "200 1 0:1 / /x rw,nosuid,nodev - tmpfs none rw\n\
             201 200 0:2 / /x/c rw,nosuid,nodev - {child_fstype} none rw\n"
        )
    }

    /// SEC-1（#2098）: `rbind` の配下に疑似 FS があれば拒否して自分のマウントを外す。非 `rbind` は配下を公開しないため受ける。
    #[test]
    fn sec1_2098_rbind_child_pseudo_fs_is_rejected_and_rolled_back() {
        let fx = fx();
        let knobs = Knobs {
            mountinfo: Some(pseudo_mountinfo("proc")),
            ..Knobs::default()
        };
        let set = one("/mnt/x", &fx.src("dir"), &["rbind"]);
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("must be rejected");
        assert_eq!(reason_of(&err), Some(ViolationReason::BindSourcePseudoFs));
        assert!(err.message.ends_with(" (proc)"), "{}", err.message);
        assert!(log.iter().any(|l| l.starts_with("umount(")), "{log:?}");
        assert!(!fx.rootfs.join("mnt").exists());

        let set = one("/mnt/x", &fx.src("dir"), &[]);
        let (r, log) = run(&fx, &set, &knobs);
        r.unwrap_or_else(|e| panic!("non-recursive must be accepted: {e}; log: {log:?}"));
    }

    /// SEC-1（#2129）: devtmpfs は `f_type` では見分けられず、付け替えた自分のマウント自身の fstype 名で拒否して外す
    /// （非 `rbind` でも `rbind` でも）。
    #[test]
    fn sec1_2129_devtmpfs_own_mount_is_rejected_and_rolled_back() {
        let fx = fx();
        let knobs = Knobs {
            mountinfo: Some("200 1 0:1 / /x rw,nosuid,nodev - devtmpfs none rw\n".to_owned()),
            ..Knobs::default()
        };
        for opts in [&[][..], &["rbind"][..]] {
            let set = one("/mnt/x", &fx.src("dir"), opts);
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err("must be rejected");
            assert_eq!(reason_of(&err), Some(ViolationReason::BindSourcePseudoFs));
            assert!(err.message.ends_with(" (devtmpfs)"), "{}", err.message);
            assert!(log.iter().any(|l| l.starts_with("umount(")), "{log:?}");
            assert!(!fx.rootfs.join("mnt").exists());
        }
    }

    /// SEC-1（#2098）: 配下の照合は孫も見つけ、親が別の行は無視し、書式の崩れは `Err`。
    #[test]
    fn sec1_2098_find_pseudo_fs_in_subtree_is_exact() {
        let tree = "200 1 0:1 / /x rw - tmpfs none rw\n\
                    201 200 0:2 / /x/c rw - ext4 none rw\n\
                    202 201 0:3 / /x/c/g rw - cgroup2 none rw\n\
                    300 1 0:4 / /other rw - proc none rw\n";
        assert_eq!(
            find_pseudo_fs_in_subtree(tree, 200, true).map(|o| o.map(|p| p.name)),
            Ok(Some("cgroup2"))
        );
        assert_eq!(find_pseudo_fs_in_subtree(tree, 200, false), Ok(None));
        assert_eq!(find_pseudo_fs_in_subtree(tree, 201, false), Ok(None));
        assert_eq!(
            find_pseudo_fs_in_subtree(tree, 300, false).map(|o| o.map(|p| p.name)),
            Ok(Some("proc"))
        );
        assert!(find_pseudo_fs_in_subtree("garbage\n", 200, true).is_err());
        assert!(find_pseudo_fs_in_subtree(tree, 999, true).is_err());
    }

    /// SEC-4（#2098）: 疑似 FS の拒否は `Mount` 監査レコード（理由 `bind_source_pseudo_fs`・コンテナ内の宛先）になる。
    #[test]
    fn sec4_2098_pseudo_fs_rejection_becomes_mount_audit_record() {
        let fx = fx();
        let set = one("/mnt/x", &fx.src("dir"), &[]);
        let knobs = Knobs {
            source_fs_type: Some(Ok(sys::SYSFS_MAGIC)),
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &knobs);
        let err = r.expect_err("rejected");
        let sink = VecSink::new(false);
        let out = audit_mount_violation(err, None, &sink);
        assert_eq!(out.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(
            recs[0].reason().map(crate::audit_log::AuditReason::as_str),
            Some("bind_source_pseudo_fs")
        );
        assert_eq!(recs[0].path(), Some(Path::new("/mnt/x")));
    }

    /// 新しい 5 理由の具体値（種別・ビヘイビア ID・`ErrorCode`・トークン）。
    #[test]
    fn violation_reasons_have_exact_attributes() {
        let table = [
            (
                ViolationReason::BindSourceSymlink,
                "bind_source_symlink",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindSourceUnsupportedType,
                "bind_source_unsupported_type",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindSourceNotAccessible,
                "bind_source_not_accessible",
                ErrorCode::PermissionDenied,
            ),
            (
                ViolationReason::BindSourceContainsRootfs,
                "bind_source_contains_rootfs",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindTargetKindMismatch,
                "bind_target_kind_mismatch",
                ErrorCode::InvalidArgument,
            ),
            (
                ViolationReason::BindSourcePseudoFs,
                "bind_source_pseudo_fs",
                ErrorCode::InvalidArgument,
            ),
        ];
        for (reason, token, code) in table {
            assert_eq!(reason.as_str(), token);
            assert_eq!(reason.kind(), ViolationKind::MountTarget);
            assert_eq!(reason.behavior_id(), "SEC-1");
            assert_eq!(reason.error_code(), code);
            assert_eq!(ViolationReason::from_launch_token(token), Some(reason));
            assert!(!reason.message().is_empty());
        }
    }

    /// ディレクトリ `dir` を開いた fd と `(dev, ino)`。
    fn dir_fd_and_id(dir: &Path) -> (OwnedFd, (u64, u64)) {
        use std::os::unix::fs::MetadataExt as _;
        let c = CString::new(dir.as_os_str().as_bytes()).expect("cstring");
        let fd = sys::open_dir_path_nofollow(None, &c).expect("open dir");
        let meta = std::fs::metadata(dir).expect("metadata");
        (fd, (meta.dev(), meta.ino()))
    }

    /// SEC-1・REPAIR-4: ステージング経由で作ったディレクトリの `(dev, ino)` は配置後の実体と一致し、ステージングは残らない。
    /// 既存の名前は作らず `None`（上書きしない）。
    #[test]
    fn sec1_create_dir_proven_returns_the_placed_inode_and_leaves_no_staging() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let name = CString::new("d").expect("cstring");
        let (fd, id, leftover) = create_dir_proven(parent.as_fd(), &name)
            .expect("created")
            .expect("some");
        assert_eq!(leftover, None);
        let meta = std::fs::metadata(fx.rootfs.join("d")).expect("meta");
        assert_eq!(id, (meta.dev(), meta.ino()));
        let st = fstat_fd(fd.as_fd()).expect("fstat");
        assert_eq!((st.dev, st.ino), id);
        let names: Vec<_> = std::fs::read_dir(&fx.rootfs)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .filter(|n| n.to_string_lossy().starts_with(".fandhe-"))
            .collect();
        assert!(names.is_empty(), "leftover: {names:?}");
        assert!(
            create_dir_proven(parent.as_fd(), &name)
                .expect("exists")
                .is_none()
        );
    }

    /// SEC-1・REPAIR-4: 照合と削除の間に同名の別実体へ差し替えられたら消さず、元の名前へ戻して失敗を返す。
    #[test]
    fn sec1_remove_verified_leaves_a_swapped_file_and_reports() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("t");
        std::fs::write(&path, b"").expect("create");
        let meta = std::fs::metadata(&path).expect("meta");
        let ours = (meta.dev(), meta.ino());
        // 自分が作った実体を別プロセスが改名し、同名の別ファイルを置いた状況。
        std::fs::rename(&path, fx.rootfs.join("moved")).expect("rename");
        std::fs::write(&path, b"other").expect("swap");
        let name = CString::new("t").expect("cstring");
        let (what, _) = remove_verified(parent.as_fd(), &name, ours, false).expect_err("mismatch");
        assert_eq!(what, "verify");
        assert_eq!(std::fs::read(&path).expect("kept"), b"other");
        // 一致する実体は消える。
        let meta = std::fs::metadata(&path).expect("meta");
        remove_verified(parent.as_fd(), &name, (meta.dev(), meta.ino()), false).expect("removed");
        assert!(!path.exists());
        // 既に無い要素は成功扱い。
        remove_verified(parent.as_fd(), &name, ours, false).expect("already gone");
    }

    /// SEC-1・REPAIR-4: 差し替えられた空ディレクトリは消さず、中身のあるディレクトリは削除失敗として返す。
    #[test]
    fn sec1_remove_verified_leaves_a_swapped_or_non_empty_dir_and_reports() {
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("d");
        std::fs::create_dir(&path).expect("mkdir");
        let (_, ours) = dir_fd_and_id(&path);
        std::fs::rename(&path, fx.rootfs.join("moved")).expect("rename");
        std::fs::create_dir(&path).expect("swap");
        let name = CString::new("d").expect("cstring");
        let (what, _) = remove_verified(parent.as_fd(), &name, ours, true).expect_err("mismatch");
        assert_eq!(what, "verify");
        assert!(path.is_dir());

        let (_, id) = dir_fd_and_id(&path);
        std::fs::write(path.join("f"), b"x").expect("content");
        let (what, _) = remove_verified(parent.as_fd(), &name, id, true).expect_err("not empty");
        assert_eq!(what, "rmdir");
        assert!(path.join("f").exists(), "restored under the original name");
    }

    /// SEC-1: 成功した削除は隔離ディレクトリを残さない。`RENAME_NOREPLACE` の改名は既存の同名を上書きしない。
    #[test]
    fn sec1_remove_verified_leaves_no_quarantine_and_rename_never_replaces() {
        use std::os::unix::fs::MetadataExt as _;
        let fx = fx();
        let (parent, _) = dir_fd_and_id(&fx.rootfs);
        let path = fx.rootfs.join("t");
        std::fs::write(&path, b"").expect("create");
        let meta = std::fs::metadata(&path).expect("meta");
        let name = CString::new("t").expect("cstring");
        remove_verified(parent.as_fd(), &name, (meta.dev(), meta.ino()), false).expect("removed");
        let left: Vec<_> = std::fs::read_dir(&fx.rootfs)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .filter(|n| n.to_string_lossy().starts_with(".fandhe-rollback-"))
            .collect();
        assert!(left.is_empty(), "quarantine left: {left:?}");

        std::fs::write(fx.rootfs.join("a"), b"a").expect("a");
        std::fs::write(fx.rootfs.join("b"), b"b").expect("b");
        let (a, b) = (
            CString::new("a").expect("cstring"),
            CString::new("b").expect("cstring"),
        );
        let err = sys::rename_noreplace_at(parent.as_fd(), &a, parent.as_fd(), &b)
            .expect_err("must not replace");
        assert!(matches!(err, SysError::Os(sys::EEXIST)), "{err:?}");
        assert_eq!(std::fs::read(fx.rootfs.join("b")).expect("kept"), b"b");
    }

    /// SEC-1・REPAIR-4: `create_dir_proven` が配置したディレクトリを記録すれば、`roll_back_binds` が回収して残さない
    /// （ステージング掃除の失敗でも配置済みの実体を記録する契約の回帰）。
    #[test]
    fn sec1_placed_dir_recorded_from_create_dir_proven_is_rolled_back() {
        let fx = fx();
        let fd = fx.rootfs_fd();
        let name = CString::new("p").expect("cstring");
        let (_pfd, id, leftover) = create_dir_proven(fd.as_fd(), &name)
            .expect("created")
            .expect("some");
        assert_eq!(leftover, None);
        let unused = || SysError::Os(sys::EINVAL);
        let deps = BindDeps {
            is_shared: &|_| Ok(false),
            still_at: &|_, _| true,
            open_tree: &|_, _| Err(unused()),
            pre_cloned: &|_| None,
            set_attrs: &|_, _, _| Err(unused()),
            flags_of: &|_| Err(unused()),
            attach: &|_, _| Err(unused()),
            observe: &|_, _, _| Err(ExecError::new(ErrorCode::Internal, STAGE, "unused")),
            mountinfo: &|| Ok(String::new()),
            source_path: &|_| Ok(String::new()),
            source_mnt_id: &|_| Ok(0),
            umount: &|_| Ok(()),
            source_fs_type: &|_| Ok(0),
            state_identity: &|_, _| None,
            before_attach: &|| {},
        };
        let ctx = Ctx {
            root: fd.as_fd(),
            host_root: fx.rootfs.clone(),
            rootfs_ids: Vec::new(),
            state_chains: Vec::new(),
            fresh_state_chains: Some(Vec::new()),
            protected: &[],
            deps: &deps,
        };
        let set = one("/p", &fx.src("dir"), &[]);
        let mut state = Applied::new(&set.mounts()[0]);
        state.created_dirs = vec![0];
        state.created_dir_ids = vec![(0, id)];
        let failures = roll_back_binds(&ctx, &[state]);
        assert!(failures.is_empty(), "{failures:?}");
        assert!(!fx.rootfs.join("p").exists());
    }

    /// REPAIR-4: 後始末中の開き直しの失敗も `; cleanup failed: ...` として元のエラーへ併記する。
    #[test]
    fn repair4_cleanup_open_failure_is_reported() {
        let fx = fx();
        let fd = fx.rootfs_fd();
        let unused = || SysError::Os(sys::EINVAL);
        let deps = BindDeps {
            is_shared: &|_| Ok(false),
            still_at: &|_, _| true,
            open_tree: &|_, _| Err(unused()),
            pre_cloned: &|_| None,
            set_attrs: &|_, _, _| Err(unused()),
            flags_of: &|_| Err(unused()),
            attach: &|_, _| Err(unused()),
            observe: &|_, _, _| Err(ExecError::new(ErrorCode::Internal, STAGE, "unused")),
            mountinfo: &|| Ok(String::new()),
            source_path: &|_| Ok(String::new()),
            source_mnt_id: &|_| Ok(0),
            umount: &|_| Ok(()),
            source_fs_type: &|_| Ok(0),
            state_identity: &|_, _| None,
            before_attach: &|| {},
        };
        let ctx = Ctx {
            root: fd.as_fd(),
            host_root: fx.rootfs.clone(),
            rootfs_ids: Vec::new(),
            state_chains: Vec::new(),
            fresh_state_chains: Some(Vec::new()),
            protected: &[],
            deps: &deps,
        };
        let set = one("/a/b", &fx.src("dir"), &[]);
        let spec = &set.mounts()[0];
        let mut state = Applied::new(spec);
        state.created_dirs = vec![0, 1];
        state.created_dir_ids = vec![(0, (1, 1)), (1, (1, 1))];
        let failures = roll_back_binds(&ctx, &[state]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].what, "open");
        let err = with_cleanup_failures(failed(spec, "x"), &failures);
        assert!(
            err.message
                .contains("; cleanup failed: open(/a/b) failed: "),
            "{}",
            err.message
        );
    }
    // ---- #2166: overlayfs の層の照合と、状態ルートの (dev, path) の再解決（SEC-1・OCI-4・SEC-5） ----

    /// 親（`/`）と自分のマウント（id 200）の 2 行。自分のマウントの fstype を overlay にして super_options を差し替える。
    fn overlay_knobs(super_options: &str) -> Knobs {
        Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n\
                 200 1 0:2 / /x rw,nosuid,nodev - overlay overlay {super_options}\n"
            )),
            ..Knobs::default()
        }
    }

    /// 状態ルート（`src/state/sub` を持つ）を保護対象にした集合。保護対象の FS 内パス・dev は無関係な値にして、
    /// mountinfo の層では拒否されない条件にする。
    fn overlay_state_set(fx: &Fx, opts: &[&str]) -> (BindMountSet, String) {
        let state = fx.src.join("state");
        std::fs::create_dir_all(state.join("sub")).expect("state/sub");
        let state_s = state.to_str().expect("utf8").to_owned();
        let chain = dir_identity_chain(&state_s).expect("chain");
        let set = one("/mnt/d", &fx.src("dir"), opts).with_protected_roots(vec![
            ProtectedFsRoot::new("9:9".to_owned(), "/registered/state".to_owned(), false)
                .with_inode_chain(state_s.clone(), chain),
        ]);
        (set, state_s)
    }

    /// SEC-1・#2166: overlay の lowerdir・upperdir・workdir が状態ルートの同一・祖先・子孫なら拒否し、rootfs の祖先は
    /// `BindSourceContainsRootfs`。無関係な層も同一性を保証できないため `FAILED_PRECONDITION`。拒否のときは自分のマウントを外す（後始末）。
    #[test]
    fn sec1_2166_overlay_layers_aliasing_state_or_rootfs_are_rejected() {
        let fx = fx();
        let (set, state) = overlay_state_set(&fx, &[]);
        let other = fx.tmp.path().join("other");
        std::fs::create_dir(&other).expect("other");
        let other = other.to_str().expect("utf8").to_owned();
        let parent = fx.src.to_str().expect("utf8").to_owned();
        let tmp = fx.tmp.path().to_str().expect("utf8").to_owned();
        let reaches = Some(ViolationReason::BindSourceReachesStateRoot);
        let cases = [
            (format!("lowerdir={state}"), reaches),
            (format!("lowerdir={other}:{state}"), reaches),
            (
                format!("lowerdir={other},upperdir={state},workdir={other}"),
                reaches,
            ),
            (
                format!("lowerdir={other},upperdir={other},workdir={state}"),
                reaches,
            ),
            (format!("lowerdir+={state}"), reaches),
            (format!("lowerdir={other}::{state}"), reaches),
            (format!("lowerdir={parent}"), reaches),
            (format!("lowerdir={state}/sub"), reaches),
            (
                format!("lowerdir={tmp}"),
                Some(ViolationReason::BindSourceContainsRootfs),
            ),
            (
                format!("lowerdir={other},upperdir={other},workdir={other},redirect_dir=off"),
                None,
            ),
        ];
        for (opts, want) in cases {
            let (r, log) = run(&fx, &set, &overlay_knobs(&opts));
            match want {
                Some(reason) => {
                    let err = r.expect_err(&opts);
                    assert_eq!(reason_of(&err), Some(reason), "{opts}");
                    assert!(
                        log.iter().any(|l| l.starts_with("umount(")),
                        "{opts}: {log:?}"
                    );
                    assert!(!err.message.contains(&state), "{}", err.message);
                }
                None => {
                    // 無関係な層でも、実際の backing directory との同一性を保証できないため fail-closed で拒否する（#2166）。
                    let err = r.expect_err(&opts);
                    assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opts}");
                    assert!(err.violation.is_none(), "{opts}");
                    assert!(
                        log.iter().any(|l| l.starts_with("umount(")),
                        "{opts}: {log:?}"
                    );
                }
            }
        }
    }

    /// SEC-1・#2166: 解析できない・解決できない・入れ子・上限超過の層は `FAILED_PRECONDITION`（fail-closed）。
    #[test]
    fn sec1_2166_unresolvable_overlay_layers_fail_closed() {
        let fx = fx();
        let (set, _) = overlay_state_set(&fx, &[]);
        let dir = fx.tmp.path().join("layer");
        std::fs::create_dir(&dir).expect("layer");
        let link = fx.tmp.path().join("layer-link");
        std::os::unix::fs::symlink(&dir, &link).expect("symlink");
        let file = fx.tmp.path().join("layer-file");
        std::fs::write(&file, b"f").expect("file");
        let p = |p: &Path| p.to_str().expect("utf8").to_owned();
        let many = (0..=500)
            .map(|i| format!("/l{i}"))
            .collect::<Vec<_>>()
            .join(":");
        for opts in [
            "lowerdir=relative/layer".to_owned(),
            format!("lowerdir={}/missing", p(fx.tmp.path())),
            format!("lowerdir={}", p(&link)),
            format!("lowerdir={}", p(&file)),
            format!("lowerdir={}\\x", p(&dir)),
            "rw".to_owned(),
            format!("lowerdir={many}"),
        ] {
            let (r, log) = run(&fx, &set, &overlay_knobs(&opts));
            let err = r.expect_err(&opts);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opts}");
            assert!(err.violation.is_none(), "{opts}");
            assert!(
                err.message.contains("overlay layers"),
                "{opts}: {}",
                err.message
            );
            assert!(
                log.iter().any(|l| l.starts_with("umount(")),
                "{opts}: {log:?}"
            );
        }
        // 層が別の overlay の上にある（入れ子）。層の属するマウントの行を overlay にする。
        let n = path_mount_id(&p(&dir)).expect("mnt id");
        let info = format!(
            "1 0 0:1 / / rw - tmpfs none rw\n\
             200 1 0:2 / /x rw,nosuid,nodev - overlay overlay lowerdir={}\n\
             {n} 1 0:3 / /y rw - overlay overlay lowerdir=/zz\n",
            p(&dir)
        );
        let knobs = Knobs {
            mountinfo: Some(info),
            ..Knobs::default()
        };
        let (r, _) = run(&fx, &set, &knobs);
        let err = r.expect_err("nested overlay");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
    }

    /// SEC-1・#2166: `rbind` では配下の overlay の層も照合し、`bind`（非再帰）は自分のマウントだけを見る。
    #[test]
    fn sec1_2166_overlay_below_the_mount_is_checked_only_when_recursive() {
        let fx = fx();
        let info = |state: &str| Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n\
                 200 1 0:2 / /x rw,nosuid,nodev - tmpfs none rw\n\
                 300 200 0:3 / /x/sub rw,nosuid,nodev - overlay overlay lowerdir={state}\n"
            )),
            ..Knobs::default()
        };
        let (set, state) = overlay_state_set(&fx, &["rbind"]);
        let (r, _) = run(&fx, &set, &info(&state));
        assert_eq!(
            reason_of(&r.expect_err("rbind")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        let (set, state) = overlay_state_set(&fx, &["bind"]);
        // 非再帰では配下の行は自分のマウントではない。
        let (r, _) = run(&fx, &set, &info(&state));
        r.expect("non-recursive bind ignores the child overlay");
    }

    /// SEC-4・#2166: overlay の層による拒否の監査レコードには、コンテナ内の宛先だけが載り、層のパスは載らない。
    #[test]
    fn sec4_2166_overlay_rejection_audit_has_destination_only() {
        let fx = fx();
        let (set, state) = overlay_state_set(&fx, &[]);
        let (r, _) = run(&fx, &set, &overlay_knobs(&format!("lowerdir={state}")));
        let err = r.expect_err("rejected");
        let sink = VecSink::new(false);
        let out = audit_mount_violation(err, None, &sink);
        assert_eq!(out.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].reason().map(crate::audit_log::AuditReason::as_str),
            Some("bind_source_reaches_state_root")
        );
        assert_eq!(recs[0].path(), Some(Path::new("/mnt/d")));
        assert!(!format!("{:?}", recs[0]).contains(&state));
    }

    /// mountinfo の super_options 欄を取り出し、区切りの後ろに余るフィールドがある行は拒否する。
    #[test]
    fn sec1_2166_mountinfo_entry_exposes_super_options() {
        let line = "200 1 0:2 / /x rw - overlay overlay rw,lowerdir=/a:/b,upperdir=/u";
        let e = parse_mountinfo_line(line).expect("parse");
        assert_eq!(e.fstype, "overlay");
        assert_eq!(e.dev, "0:2");
        assert_eq!(e.super_options, "rw,lowerdir=/a:/b,upperdir=/u");
        assert!(parse_mountinfo_line(&format!("{line} extra")).is_none());
        assert!(parse_mountinfo_line("200 1 0:2 / /x rw - overlay overlay").is_none());
    }

    /// 反例の土台。start の時点の記録は状態ルート `8:1 /srv/state`、元は `8:1` 上の `src/dir`（記録とは無関係に見える）。
    fn rebuilt_state_set(fx: &Fx) -> (BindMountSet, Knobs) {
        let state = fx.tmp.path().join("state");
        std::fs::create_dir(&state).expect("state");
        let state_s = state.to_str().expect("utf8").to_owned();
        let chain = dir_identity_chain(&state_s).expect("chain");
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(vec![
            ProtectedFsRoot::new("8:1".to_owned(), "/srv/state".to_owned(), false)
                .with_inode_chain(state_s, chain),
        ]);
        let knobs = Knobs {
            mountinfo: Some(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n\
                 200 1 8:1 / /x rw,nosuid,nodev - ext4 /dev/sda1 rw\n"
                    .to_owned(),
            ),
            ..Knobs::default()
        };
        (set, knobs)
    }

    /// SEC-1・#2166: 下層の実パスで状態ルートが改名され、記録した FS 内パスが古くなっても、適用の時点で作り直した
    /// (dev, path) で照合して拒否する。記録と同じ値なら従来どおり受ける。
    #[test]
    fn sec1_2166_rebuilt_state_identity_catches_a_stale_recorded_path() {
        let fx = fx();
        let (set, knobs) = rebuilt_state_set(&fx);
        run(&fx, &set, &knobs)
            .0
            .expect("recorded identity does not overlap");
        // 改名後の状態ルートは、元（`src/dir`）の祖先の位置にある。
        fn renamed(_: &ProtectedFsRoot) -> Option<FsIdentity> {
            Some(FsIdentity {
                dev: "8:1".to_owned(),
                path: "/".to_owned(),
            })
        }
        let knobs = Knobs {
            state_identity: Some(renamed),
            ..knobs
        };
        let (r, _) = run(&fx, &set, &knobs);
        assert_eq!(
            reason_of(&r.expect_err("rejected")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
    }

    /// SEC-1・#2166: 作り直せない・dev が記録と食い違う場合は `FAILED_PRECONDITION`（fail-closed）。
    #[test]
    fn sec1_2166_unrebuildable_or_changed_state_identity_fails_closed() {
        let fx = fx();
        let (set, knobs) = rebuilt_state_set(&fx);
        fn missing(_: &ProtectedFsRoot) -> Option<FsIdentity> {
            None
        }
        fn other_dev(_: &ProtectedFsRoot) -> Option<FsIdentity> {
            Some(FsIdentity {
                dev: "8:2".to_owned(),
                path: "/srv/state".to_owned(),
            })
        }
        for f in [
            missing as fn(&ProtectedFsRoot) -> Option<FsIdentity>,
            other_dev,
        ] {
            let k = Knobs {
                mountinfo: knobs.mountinfo.clone(),
                state_identity: Some(f),
                ..Knobs::default()
            };
            let (r, _) = run(&fx, &set, &k);
            let err = r.expect_err("fail closed");
            assert_eq!(err.code, ErrorCode::FailedPrecondition);
            assert!(err.violation.is_none());
        }
    }
    // ---- #2317: 保護対象が overlay 上にあるときの逆方向の別名の照合（SEC-1・OCI-4・SEC-5） ----

    /// 層の置き場。`tmp/ovl/{a,b,c}`（b の配下に `sub`）と無関係な `tmp/other`。
    struct OvlFx {
        a: String,
        b: String,
        c: String,
        sub: String,
        parent: String,
        other: String,
        /// 層が属するマウントの実の ID（dry-run の mountinfo にこの ID の行を足す）。
        mnt: u64,
    }

    fn ovl_fx(fx: &Fx) -> OvlFx {
        let base = fx.tmp.path().join("ovl");
        for d in ["a", "b/sub", "c"] {
            std::fs::create_dir_all(base.join(d)).expect("layer dir");
        }
        let other = fx.tmp.path().join("other");
        std::fs::create_dir_all(&other).expect("other");
        let p = |p: &Path| p.to_str().expect("utf8").to_owned();
        let b = p(&base.join("b"));
        let mnt = path_mount_id(&b).expect("mnt id of the layer");
        // dry-run の mountinfo の固定 ID（1・200・300）と衝突すると試験の前提が崩れるため、明示的に失敗させる。
        assert!(![1, 200, 300].contains(&mnt), "mnt id collision: {mnt}");
        OvlFx {
            a: p(&base.join("a")),
            sub: p(&base.join("b/sub")),
            c: p(&base.join("c")),
            parent: p(&base),
            other: p(&other),
            b,
            mnt,
        }
    }

    impl OvlFx {
        fn opts(&self) -> String {
            format!("lowerdir={},upperdir={},workdir={}", self.a, self.b, self.c)
        }

        /// 保護対象（dev `9:9`）が `fstype` の FS の上にある mountinfo。層の属するマウントは dev `0:7` の非 overlay。
        fn info(&self, fstype: &str, super_options: &str) -> String {
            format!(
                "1 0 0:1 / / rw - tmpfs none rw\n\
                 200 1 0:2 / /x rw,nosuid,nodev - tmpfs none rw\n\
                 {} 1 0:7 / / rw - tmpfs none rw\n\
                 300 1 9:9 / /var/state rw - {fstype} {fstype} {super_options}\n",
                self.mnt
            )
        }

        fn knobs(&self) -> Knobs {
            Knobs {
                mountinfo: Some(self.info("overlay", &self.opts())),
                ..Knobs::default()
            }
        }
    }

    /// dev `9:9` の状態ルート（inode の鎖は無関係な `/proc`）。
    fn state_on_9_9() -> ProtectedFsRoot {
        ProtectedFsRoot::new("9:9".to_owned(), "/state".to_owned(), false).with_inode_chain(
            "/proc".to_owned(),
            dir_identity_chain("/proc").expect("chain of /proc"),
        )
    }

    /// 宛先に何も作る前に拒否されたこと（rootfs に宛先が無く、付け替え・後始末のマウント操作が無い）。
    fn assert_rejected_before_target(fx: &Fx, log: &[String], what: &str) {
        assert!(!fx.rootfs.join("mnt").exists(), "{what}: target created");
        assert!(
            !log.iter()
                .any(|l| l.starts_with("umount(") || l.starts_with("move_mount(")),
            "{what}: {log:?}"
        );
    }

    /// SEC-1・#2317: 状態ルートが overlay 上にあるとき、元が層（lowerdir・upperdir・workdir）の同一・祖先・子孫なら
    /// `BindSourceReachesStateRoot` で拒否する。宛先は作らない。無関係な元は通る。
    #[test]
    fn sec1_2317_state_on_overlay_rejects_layer_aliases() {
        let fx = fx();
        let o = ovl_fx(&fx);
        let cases = [
            ("upperdir", &o.b),
            ("upperdir subdir", &o.sub),
            ("upperdir parent", &o.parent),
            ("workdir", &o.c),
            ("lowerdir", &o.a),
        ];
        for (what, src) in cases {
            let set = one("/mnt/d", src, &[]).with_protected_roots(vec![state_on_9_9()]);
            let (r, log) = run(&fx, &set, &o.knobs());
            let err = r.expect_err(what);
            assert_eq!(
                reason_of(&err),
                Some(ViolationReason::BindSourceReachesStateRoot),
                "{what}"
            );
            assert!(!err.message.contains(src.as_str()), "{}", err.message);
            assert_rejected_before_target(&fx, &log, what);
        }
        let set = one("/mnt/d", &o.other, &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, log) = run(&fx, &set, &o.knobs());
        r.unwrap_or_else(|e| panic!("unrelated source must pass: {e}; {log:?}"));
        assert!(fx.rootfs.join("mnt/d").is_dir());
    }

    /// SEC-1・#2317: rootfs・bundle が overlay 上にあるとき、元が層の同一・祖先・子孫のいずれでも `BindSourceContainsRootfs`。
    #[test]
    fn sec1_2317_contained_root_on_overlay_rejects_layer_overlap() {
        let fx = fx();
        let o = ovl_fx(&fx);
        let knobs = Knobs {
            mountinfo: Some(o.info("overlay", &o.opts()).replace("9:9", "7:7")),
            ..Knobs::default()
        };
        for (what, src) in [
            ("upper", &o.b),
            ("upper subdir", &o.sub),
            ("parent", &o.parent),
        ] {
            let roots = pinned(vec![ProtectedFsRoot::contained(
                "7:7".to_owned(),
                "/".to_owned(),
            )]);
            let set = one("/mnt/d", src, &[]).with_protected_roots(roots);
            let (r, log) = run(&fx, &set, &knobs);
            assert_eq!(
                reason_of(&r.expect_err(what)),
                Some(ViolationReason::BindSourceContainsRootfs),
                "{what}"
            );
            assert_rejected_before_target(&fx, &log, what);
        }
        let roots = pinned(vec![ProtectedFsRoot::contained(
            "7:7".to_owned(),
            "/".to_owned(),
        )]);
        let set = one("/mnt/d", &o.other, &[]).with_protected_roots(roots);
        let (r, log) = run(&fx, &set, &knobs);
        r.unwrap_or_else(|e| panic!("unrelated source must pass: {e}; {log:?}"));
    }

    /// SEC-1・#2317: 層を bind mount した別名の配下（inode の鎖には映らない形）は、mountinfo の `(dev, path)` の照合で拒否する。
    #[test]
    fn sec1_2317_bind_alias_of_layer_is_rejected_by_mountinfo() {
        let fx = fx();
        let o = ovl_fx(&fx);
        // 元の属するマウント（ID 1）を、upperdir の FS 内パスを root にした別名として見せる。
        let alias = o.info("overlay", &o.opts()).replace(
            "1 0 0:1 / / rw - tmpfs none rw",
            &format!(
                "1 0 0:7 {} {} rw - tmpfs none rw",
                o.b,
                fx.src.to_str().expect("utf8")
            ),
        );
        let knobs = Knobs {
            mountinfo: Some(alias),
            ..Knobs::default()
        };
        let set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, log) = run(&fx, &set, &knobs);
        assert_eq!(
            reason_of(&r.expect_err("alias of the layer")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        assert_rejected_before_target(&fx, &log, "alias");
    }

    /// SEC-1・#2317: 状態ルートが overlay 上のとき、層と同じ FS 上のリンク数 2 以上の通常ファイルの元を拒否する
    /// （保護対象の dev は overlay の値で、実在する元の dev と一致しないため、層の dev を加えて照合する）。
    #[test]
    fn sec1_2317_hard_linked_file_on_layer_fs_is_rejected() {
        let fx = fx();
        let o = ovl_fx(&fx);
        std::fs::hard_link(fx.src.join("file"), fx.src.join("file2")).expect("hard link");
        // 元の属するマウント（ID 1）を層と同じ dev `0:7` にする。
        let info = o.info("overlay", &o.opts()).replace(
            "1 0 0:1 / / rw - tmpfs none rw",
            "1 0 0:7 / / rw - tmpfs none rw",
        );
        let knobs = Knobs {
            mountinfo: Some(info),
            ..Knobs::default()
        };
        let set = one("/mnt/f", &fx.src("file2"), &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, log) = run(&fx, &set, &knobs);
        assert_eq!(
            reason_of(&r.expect_err("hard linked file")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
        assert_rejected_before_target(&fx, &log, "hard link");
        // 層と別の FS（dev `0:1`）上なら、同じ元は通る（層の dev だけが効いていること）。
        let set = one("/mnt/f", &fx.src("file2"), &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, log) = run(&fx, &set, &o.knobs());
        r.unwrap_or_else(|e| panic!("file on another fs must pass: {e}; {log:?}"));
    }

    /// SEC-1・#2317: ハードリンクの検査は、各保護対象自身の層の dev とだけ対にする。別の保護対象にハードリンク済みの
    /// 状態ファイルがあっても、overlay 上の状態ルートの層の FS 上のディレクトリ元を誤って拒否しない。
    #[test]
    fn sec1_2317_hard_link_scan_is_paired_per_root_layer_devs() {
        let fx = fx();
        let o = ovl_fx(&fx);
        // 元の属するマウント（ID 1）を層と同じ dev `0:7` にする。
        let info = o.info("overlay", &o.opts()).replace(
            "1 0 0:1 / / rw - tmpfs none rw",
            "1 0 0:7 / / rw - tmpfs none rw",
        );
        let knobs = Knobs {
            mountinfo: Some(info),
            ..Knobs::default()
        };
        // overlay 上の状態ルート（リンクなし）と、別 FS（dev `0:2`）上のハードリンクを持つ状態ルート。
        let other =
            |linked: bool| ProtectedFsRoot::new("0:2".to_owned(), "/other".to_owned(), linked);
        let set = one("/mnt/d", &fx.src("dir"), &[])
            .with_protected_roots(vec![state_on_9_9(), other(true)]);
        let (r, log) = run(&fx, &set, &knobs);
        r.unwrap_or_else(|e| panic!("unrelated backing fs must pass: {e}; {log:?}"));
        // 対照: overlay 上の状態ルート自身にリンクがあれば、層の FS 上のディレクトリ元は拒否する。
        let linked_overlay = ProtectedFsRoot::new("9:9".to_owned(), "/state".to_owned(), true)
            .with_inode_chain(
                "/proc".to_owned(),
                dir_identity_chain("/proc").expect("chain of /proc"),
            );
        let fx2 = self::fx();
        let o2 = ovl_fx(&fx2);
        let info2 = o2.info("overlay", &o2.opts()).replace(
            "1 0 0:1 / / rw - tmpfs none rw",
            "1 0 0:7 / / rw - tmpfs none rw",
        );
        let knobs2 = Knobs {
            mountinfo: Some(info2),
            ..Knobs::default()
        };
        let set = one("/mnt/d", &fx2.src("dir"), &[])
            .with_protected_roots(vec![linked_overlay, other(false)]);
        let (r, _log) = run(&fx2, &set, &knobs2);
        assert_eq!(
            reason_of(&r.expect_err("own layer fs with links")),
            Some(ViolationReason::BindSourceReachesStateRoot)
        );
    }

    /// SEC-1・#2317: 層を解決できない・解析できない・入れ子・食い違いは、`FAILED_PRECONDITION`（fail-closed）。
    /// message は保護対象の層であることだけを示し、層のパスを含まない。
    #[test]
    fn sec1_2317_unresolvable_protected_overlay_fails_closed() {
        let fx = fx();
        let o = ovl_fx(&fx);
        let link = fx.tmp.path().join("layer-link");
        std::os::unix::fs::symlink(&o.a, &link).expect("symlink");
        let file = fx.tmp.path().join("layer-file");
        std::fs::write(&file, b"f").expect("file");
        let p = |p: &Path| p.to_str().expect("utf8").to_owned();
        let many = (0..=500)
            .map(|i| format!("/l{i}"))
            .collect::<Vec<_>>()
            .join(":");
        let set = one("/mnt/d", &o.other, &[]).with_protected_roots(vec![state_on_9_9()]);
        let cases = [
            "lowerdir=relative/layer".to_owned(),
            format!("lowerdir={}/missing", o.parent),
            format!("lowerdir={}", p(&link)),
            format!("lowerdir={}", p(&file)),
            format!("lowerdir={}\\x", o.a),
            "rw".to_owned(),
            format!("lowerdir={many}"),
        ];
        for opts in cases {
            let knobs = Knobs {
                mountinfo: Some(o.info("overlay", &opts)),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err(&opts);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opts}");
            assert!(err.violation.is_none(), "{opts}");
            assert!(err.message.contains("protected root"), "{}", err.message);
            assert!(!err.message.contains(&o.parent), "{}", err.message);
            assert_rejected_before_target(&fx, &log, &opts);
        }
        // 層が別の overlay の上にある（入れ子）。層の属するマウントの行を overlay にする。
        let nested = o.info("overlay", &o.opts()).replace(
            "0:7 / / rw - tmpfs none rw",
            "0:7 / / rw - overlay overlay lowerdir=/zz",
        );
        // 同じ dev の overlay の行が 2 つあり super_options が食い違う。
        let mismatch = format!(
            "{}301 1 9:9 / /var/other rw - overlay overlay lowerdir={}\n",
            o.info("overlay", &o.opts()),
            o.other
        );
        // 同じ dev に overlay と他の fstype が混在する。
        let mixed = format!(
            "{}301 1 9:9 / /var/other rw - ext4 /dev/sda1 rw\n",
            o.info("overlay", &o.opts())
        );
        for (what, info) in [("nested", nested), ("mismatch", mismatch), ("mixed", mixed)] {
            let knobs = Knobs {
                mountinfo: Some(info),
                ..Knobs::default()
            };
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err(what);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{what}");
            assert!(err.violation.is_none(), "{what}");
            assert!(err.message.contains("protected root"), "{}", err.message);
            assert_rejected_before_target(&fx, &log, what);
        }
    }

    /// SEC-1・#2317: 保護対象の FS が overlay でなければ層の照合をしない（従来の挙動。層を元にしても通る）。
    #[test]
    fn sec1_2317_non_overlay_protected_root_is_unchanged() {
        let fx = fx();
        let o = ovl_fx(&fx);
        let knobs = Knobs {
            mountinfo: Some(o.info("ext4", "rw")),
            ..Knobs::default()
        };
        let set = one("/mnt/d", &o.b, &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, log) = run(&fx, &set, &knobs);
        r.unwrap_or_else(|e| panic!("non-overlay root must not check layers: {e}; {log:?}"));
    }

    /// SEC-4・#2317: 逆方向の拒否の監査レコードには、コンテナ内の宛先だけが載り、層のパスは載らない。
    #[test]
    fn sec4_2317_reverse_overlay_rejection_audit_has_destination_only() {
        let fx = fx();
        let o = ovl_fx(&fx);
        let set = one("/mnt/d", &o.b, &[]).with_protected_roots(vec![state_on_9_9()]);
        let (r, _) = run(&fx, &set, &o.knobs());
        let err = r.expect_err("rejected");
        let sink = VecSink::new(false);
        let out = audit_mount_violation(err, None, &sink);
        assert_eq!(out.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].reason().map(crate::audit_log::AuditReason::as_str),
            Some("bind_source_reaches_state_root")
        );
        assert_eq!(recs[0].path(), Some(Path::new("/mnt/d")));
        assert!(!format!("{:?}", recs[0]).contains(&o.parent));
    }

    /// SEC-1・#2166・#2317（外すと fail-open になる判定の固定）: 層がすべて無関係で解決でき、inode と mountinfo の照合に通る
    /// overlay の元でも、同一性を保証できないため必ず `FAILED_PRECONDITION` で拒否し、自分のマウントを外す。`bind`・`rbind` の両方。
    #[test]
    fn sec1_2317_overlay_source_is_always_rejected_even_when_layers_pass() {
        let fx = fx();
        for opt in ["bind", "rbind"] {
            let (set, _) = overlay_state_set(&fx, &[opt]);
            let other = fx.tmp.path().join("unrelated-layer");
            std::fs::create_dir_all(&other).expect("layer");
            let other = other.to_str().expect("utf8");
            let opts = format!("lowerdir={other},upperdir={other},workdir={other}");
            // 層の属するマウントの行を足し、(dev, path) の照合まで通る条件にする（無いと別の理由で拒否される）。
            let mnt = path_mount_id(other).expect("mnt id of the layer");
            assert!(![1, 200].contains(&mnt), "mnt id collision: {mnt}");
            let mut knobs = overlay_knobs(&opts);
            if let Some(info) = knobs.mountinfo.as_mut() {
                info.push_str(&format!("{mnt} 1 0:7 / / rw - tmpfs none rw\n"));
            }
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err(opt);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{opt}");
            assert!(err.violation.is_none(), "{opt}");
            assert!(
                err.message.ends_with(
                    "the overlay layers of the bind mount source cannot be verified to be the directories they were created from"
                ),
                "{opt}: {}",
                err.message
            );
            assert!(
                log.iter().any(|l| l.starts_with("umount(")),
                "{opt}: {log:?}"
            );
        }
    }

    /// SEC-1・OCI-4・SEC-5（#2536）: 保護対象の dev の行が適用の時点の mountinfo に無いときは、状態ルート・rootfs・bundle の
    /// いずれでも `FAILED_PRECONDITION` で拒否する（保護対象の FS を確認できず逆方向の照合が素通りするため）。
    /// dev の行が有り overlay でなければ、無関係な元は従来どおり通る。
    #[test]
    fn sec1_2536_protected_root_dev_absent_from_mountinfo_fails_closed() {
        let fx = fx();
        let (state_set, _) = overlay_state_set(&fx, &[]);
        let contained_set = one("/mnt/d", &fx.src("dir"), &[]).with_protected_roots(pinned(vec![
            ProtectedFsRoot::contained("7:7".to_owned(), "/".to_owned()),
        ]));
        // dev `9:9`・`7:7` の行を持たない mountinfo。
        let absent = Knobs {
            mountinfo: Some(ideal_mountinfo(200, false, false)),
            strict_protected_dev: true,
            ..Knobs::default()
        };
        for (what, set) in [("state", &state_set), ("contained", &contained_set)] {
            let (r, log) = run(&fx, set, &absent);
            let err = r.expect_err(what);
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{what}");
            assert!(err.violation.is_none(), "{what}");
            assert!(err.message.contains("protected root"), "{}", err.message);
            assert!(
                !err.message.contains(fx.tmp.path().to_str().expect("utf8")),
                "{}",
                err.message
            );
            assert_rejected_before_target(&fx, &log, what);
            assert_eq!(log.last().map(String::as_str), Some("mountinfo"), "{what}");
        }
        // dev の行が有り overlay ではない形は、無関係な元を受理する。
        let present = Knobs {
            mountinfo: Some(format!(
                "1 0 0:1 / / rw - tmpfs none rw\n{}9001 1 9:9 / /fixture-state rw - tmpfs none rw\n9002 1 7:7 / /fixture-root rw - tmpfs none rw\n",
                ideal_mountinfo(200, false, false)
            )),
            strict_protected_dev: true,
            ..Knobs::default()
        };
        for (what, set) in [("state", &state_set), ("contained", &contained_set)] {
            let (r, log) = run(&fx, set, &present);
            r.unwrap_or_else(|e| panic!("{what}: unrelated source must pass: {e}; {log:?}"));
            assert!(fx.rootfs.join("mnt/d").is_dir(), "{what}");
            std::fs::remove_dir_all(fx.rootfs.join("mnt")).expect("reset target");
        }
    }

    /// SEC-1（#2536）: `parse_all_mountinfo` の行数上限は `parse_mountinfo` と同じで、解析より先に効く
    /// （上限ちょうどは通り、超えたら 1 行目が壊れていても `oversized` で拒否する）。
    #[test]
    fn sec1_2536_parse_all_mountinfo_rejects_oversized_before_parsing() {
        let line = "1 0 0:1 / / rw - tmpfs none rw\n";
        let ok = line.repeat(MOUNTINFO_MAX_LINES);
        assert_eq!(
            parse_all_mountinfo(&ok).map(|v| v.len()),
            Ok(MOUNTINFO_MAX_LINES)
        );
        let over = line.repeat(MOUNTINFO_MAX_LINES + 1);
        let err = parse_all_mountinfo(&over).err().expect("over the limit");
        assert!(err.contains("oversized"), "{err}");
        let broken_first = format!("garbage\n{}", line.repeat(MOUNTINFO_MAX_LINES));
        let err = parse_all_mountinfo(&broken_first)
            .err()
            .expect("over the limit and malformed");
        assert!(err.contains("oversized"), "{err}");
        // 保護対象つきの適用でも、上限超過の mountinfo は宛先を作る前に FAILED_PRECONDITION。
        let fx = fx();
        let (set, _) = overlay_state_set(&fx, &[]);
        let knobs = Knobs {
            mountinfo: Some(over),
            strict_protected_dev: true,
            ..Knobs::default()
        };
        let (r, log) = run(&fx, &set, &knobs);
        let err = r.expect_err("oversized mountinfo");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert!(err.message.contains("oversized"), "{}", err.message);
        assert_rejected_before_target(&fx, &log, "oversized");
    }

    /// glibc の `gnu_dev_major` / `gnu_dev_minor` と同じ式（`st_dev` から mountinfo の `major:minor` を求める試験用）。
    fn dev_major_minor(dev: u64) -> (u64, u64) {
        (
            ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff),
            (dev & 0xff) | ((dev >> 12) & !0xff),
        )
    }

    #[test]
    fn sec1_2536_dev_major_minor_matches_glibc_encoding() {
        // makedev(8, 1) = 0x801、makedev(259, 70000) = (259 << 8) | (70000 & 0xff) | ((70000 & !0xff) << 12)。
        assert_eq!(dev_major_minor(0x801), (8, 1));
        let dev = (259u64 << 8) | (70000 & 0xff) | ((70000 & !0xffu64) << 12);
        assert_eq!(dev_major_minor(dev), (259, 70000));
        assert_eq!(dev_major_minor(0), (0, 0));
    }

    /// 回収猶予内に子を回収できなければ無期限に待たず失敗させる（REPAIR-5）。
    fn reap_within(child: &mut std::process::Child, grace: std::time::Duration) {
        let start = std::time::Instant::now();
        while child.try_wait().expect("try_wait").is_none() {
            assert!(start.elapsed() < grace, "child was not reaped in time");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// SEC-1・OCI-4・SEC-5（TASK-29 追補・#2536）: 実機の overlayfs（mount(2) 形式の `lowerdir=a:b` と、新マウント API 形式の
    /// `lowerdir+`、空白を含む層のパス）の上にある保護対象について、逆方向の照合を実 mountinfo で確認する実機前提試験。
    ///
    /// `#[ignore]` で既定のテスト集合から分離する（実行は
    /// `cargo test -p fandhe-container-core --lib -- --ignored sec1_2536_protected_root_on_real_overlay`）。必要環境は
    /// Linux 6.8 以降（非特権 user namespace 内の overlayfs と `lowerdir+`）・util-linux の `unshare` / `mount`・非特権 user
    /// namespace を許可するホスト。libtest はテストをスレッドで動かし `CLONE_NEWUSER` が `EINVAL` になるため、外側のテストが
    /// `unshare --user --map-root-user --mount` で自身を再実行し、内側（環境変数で判別）が namespace 内で overlay を作る。
    /// ホストのマウントは変えない。内側は (a) start が記録する dev（mountinfo の `major:minor`）が overlay の行の dev と一致する、
    /// (b) それが `st_dev` から求めた `major:minor` と一致する、(c) 層（lower 2・upper・work）が過不足なく解決される、
    /// (d) 層を元にすると `BindSourceReachesStateRoot`、(e) rootfs 側は `BindSourceContainsRootfs`、
    /// (f) mountinfo に無い dev は `FAILED_PRECONDITION` になる、ことを具体値で照合する。
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[ignore = "real-machine test: needs Linux 6.8+ (unprivileged overlayfs in a user namespace, lowerdir+), util-linux unshare and mount, unprivileged user namespaces. SEC-1/OCI-4/SEC-5"]
    fn sec1_2536_protected_root_on_real_overlay() {
        const INNER_ENV: &str = "FANDHE_BIND_OVERLAY_INNER";
        if std::env::var_os(INNER_ENV).is_some() {
            real_overlay_inner();
            return;
        }
        let exe = std::env::current_exe().expect("current exe");
        use std::os::unix::process::CommandExt as _;
        let mut child = std::process::Command::new("unshare")
            // 専用のプロセスグループで起動し、期限超過時に内側の `mount` などの子孫も含めて回収する（REPAIR-5）。
            .process_group(0)
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--propagation",
                "private",
            ])
            .arg(exe)
            .args([
                "--exact",
                "exec::bind_mounts::tests::sec1_2536_protected_root_on_real_overlay",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INNER_ENV, "1")
            .spawn()
            .expect("spawn unshare (util-linux required)");
        // 相手の終了待ちには必ず期限を設ける（REPAIR-5）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if std::time::Instant::now() >= deadline {
                // グループ全体（pgid = 子の pid）へ SIGKILL を送り、孤児の `mount` を残さない。
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.kill();
                reap_within(&mut child, std::time::Duration::from_secs(5));
                panic!("inner overlay test timed out after 60s");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        // 内側が作った空のマウント先（子の pid 名）を後始末する。マウントは namespace と共に消えている。
        let _ = std::fs::remove_dir(
            std::env::temp_dir().join(format!("fandhe-bind-overlay-{}", child.id())),
        );
        assert!(status.success(), "inner overlay test failed: {status:?}");
    }

    /// [`sec1_2536_protected_root_on_real_overlay`] の内側（新しい user + mount namespace の中）。
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn real_overlay_inner() {
        use crate::oci_runtime::mountinfo_identity::read_mountinfo_bounded;
        use std::os::unix::fs::MetadataExt as _;

        fn mount(args: &[&str]) {
            let out = std::process::Command::new("mount")
                .args(args)
                .output()
                .expect("spawn mount");
            assert!(
                out.status.success(),
                "mount {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        fn mkdir(p: &Path) -> String {
            std::fs::create_dir_all(p).expect("mkdir");
            p.to_str().expect("utf8").to_owned()
        }

        let base = std::env::temp_dir().join(format!("fandhe-bind-overlay-{}", std::process::id()));
        std::fs::create_dir(&base).expect("base");
        let base_s = base.to_str().expect("utf8").to_owned();
        mount(&["-t", "tmpfs", "tmpfs", &base_s]);

        // 層のパスの 1 つに空白を含め、mountinfo の `\040` エスケープを往復させる。
        for (case, plus) in [("mount2", false), ("plus", true)] {
            let root = base.join(case);
            let lower1 = mkdir(&root.join("lower one"));
            let lower2 = mkdir(&root.join("lower2"));
            let upper = mkdir(&root.join("upper"));
            let work = mkdir(&root.join("work"));
            let merged = mkdir(&root.join("merged"));
            let opts = if plus {
                format!("lowerdir+={lower1},lowerdir+={lower2},upperdir={upper},workdir={work}")
            } else {
                format!("lowerdir={lower1}:{lower2},upperdir={upper},workdir={work}")
            };
            mount(&["-t", "overlay", "overlay", "-o", &opts, &merged]);
            let state = mkdir(&Path::new(&merged).join("state"));

            let info = read_mountinfo_bounded("/proc/thread-self/mountinfo").expect("mountinfo");
            let entries = parse_all_mountinfo(&info).expect("entries");
            let rows = parse_mountinfo(&info).expect("rows");

            // (a) start と同じ求め方の dev が、マウントポイントが merged の overlay の行の dev と一致する。
            let mnt = path_mount_id(&state).expect("mount id of state");
            let identity = fs_identity(&rows, mnt, &state).expect("identity");
            let overlay_row = rows
                .iter()
                .find(|r| r.point == merged)
                .unwrap_or_else(|| panic!("{case}: no row for the overlay mount"));
            assert_eq!(identity.dev, overlay_row.dev, "{case}");
            assert!(
                entries
                    .iter()
                    .any(|e| e.dev == identity.dev && e.fstype == "overlay"),
                "{case}"
            );
            // (b) st_dev から求めた major:minor と一致する（ディレクトリで比べる）。
            let st_dev = std::fs::metadata(&merged).expect("stat merged").dev();
            let (major, minor) = dev_major_minor(st_dev);
            assert_eq!(identity.dev, format!("{major}:{minor}"), "{case}");

            // (c) 層が過不足なく解決される（lower 2・upper・work）。
            let mut budget = OVERLAY_LAYER_BUDGET;
            let layers = overlay_layers_of_dev(&entries, &rows, &identity.dev, &mut budget)
                .unwrap_or_else(|()| panic!("{case}: layers must resolve"));
            assert_eq!(layers.len(), 4, "{case}");
            for dir in [&lower1, &lower2, &upper, &work] {
                let meta = std::fs::metadata(dir).expect("stat layer");
                assert!(
                    layers
                        .iter()
                        .any(|l| l.chain.first() == Some(&(meta.dev(), meta.ino()))),
                    "{case}: layer {dir} not resolved"
                );
            }
            let base_dev = rows
                .iter()
                .find(|r| r.point == base_s)
                .map(|r| r.dev.clone())
                .expect("tmpfs base row");
            assert!(layers.iter().all(|l| l.identity.dev == base_dev), "{case}");

            // (d) 状態ルートが overlay 上にあるとき、層を元にすると拒否する。宛先は作らない。
            let chain = dir_identity_chain(&state).expect("state chain");
            let state_root = || {
                ProtectedFsRoot::new(identity.dev.clone(), identity.path.clone(), false)
                    .with_inode_chain(state.clone(), chain.clone())
            };
            let knobs = Knobs {
                mountinfo: Some(format!("{info}{}", ideal_mountinfo(200, false, false))),
                strict_protected_dev: true,
                ..Knobs::default()
            };
            let fx = fx();
            for (what, src) in [("upper", &upper), ("lower", &lower1)] {
                let set = one("/mnt/d", src, &[]).with_protected_roots(vec![state_root()]);
                let (r, log) = run(&fx, &set, &knobs);
                assert_eq!(
                    reason_of(&r.expect_err(what)),
                    Some(ViolationReason::BindSourceReachesStateRoot),
                    "{case}/{what}"
                );
                assert_rejected_before_target(&fx, &log, what);
            }
            // (e) rootfs・bundle が overlay 上にあるときは `BindSourceContainsRootfs`。
            // 状態ルートは overlay と重ならない非 overlay の実在 FS（tmpfs 上の別ディレクトリ）にする。同じ overlay を渡すと
            // 状態ルート由来の層が先に判定され `BindSourceReachesStateRoot` になり、rootfs の照合に到達しない。
            // `pinned` は dev 9:9 の保護対象を足し、実 mountinfo に無いため使わない。
            let other_state = mkdir(&base.join(format!("state-{case}")));
            let other_mnt = path_mount_id(&other_state).expect("mount id of other state");
            let other_id = fs_identity(&rows, other_mnt, &other_state).expect("other identity");
            assert_ne!(
                other_id.dev, identity.dev,
                "{case}: state root must not be on the overlay"
            );
            let other_chain = dir_identity_chain(&other_state).expect("other chain");
            let other_state_root = || {
                ProtectedFsRoot::new(other_id.dev.clone(), other_id.path.clone(), false)
                    .with_inode_chain(other_state.clone(), other_chain.clone())
            };
            let contained = vec![
                other_state_root(),
                ProtectedFsRoot::contained(identity.dev.clone(), identity.path.clone()),
            ];
            let set = one("/mnt/d", &upper, &[]).with_protected_roots(contained);
            let (r, log) = run(&fx, &set, &knobs);
            assert_eq!(
                reason_of(&r.expect_err("contained")),
                Some(ViolationReason::BindSourceContainsRootfs),
                "{case}"
            );
            assert_rejected_before_target(&fx, &log, "contained");
            // (f) mountinfo に存在しない dev は fail-closed。
            let ghost = vec![
                other_state_root(),
                ProtectedFsRoot::contained("4095:1048575".to_owned(), "/".to_owned()),
            ];
            let set = one("/mnt/d", &upper, &[]).with_protected_roots(ghost);
            let (r, log) = run(&fx, &set, &knobs);
            let err = r.expect_err("ghost dev");
            assert_eq!(err.code, ErrorCode::FailedPrecondition, "{case}");
            assert!(err.message.contains("protected root"), "{}", err.message);
            assert_rejected_before_target(&fx, &log, "ghost");
        }
    }
}
