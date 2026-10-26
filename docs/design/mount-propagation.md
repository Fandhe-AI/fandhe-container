# mount の propagation（rslave を受け、rshared を受けない理由）

`mounts[]` の bind と CRI の `Mount.propagation` のうち、`rslave`（CRI の HostToContainer）を受け、`rshared`（CRI の Bidirectional）を受けない判断と、その実装方式の記録である（#2669。CRI-2・OCI-4・SEC-1・TASK-114 追補・TASK-56。REPAIR-3）。`rshared` を受けるかはオーナー判断待ちである。

## 結論

| 指定 | 扱い | 理由 |
| ---- | ---- | ---- |
| CRI PRIVATE / `private`・`rprivate`・指定なし | 受ける（既定） | 従来どおり |
| CRI HOST_TO_CONTAINER / `rslave` | 受ける | ホストから受けるだけで、コンテナからホストへは伝播しない。user namespace の中でも成り立つ |
| CRI BIDIRECTIONAL / `rshared`・`shared` | 受けない（`UNIMPLEMENTED` / `InvalidArgument`） | 下記「rshared を受けない理由」 |
| `slave`（非再帰の指定） | 受けない | 今回の仕組みは `rbind` のとき配下も slave になり、OCI の `slave`（最上位だけ）の意味と食い違う |
| `unbindable`・`runbindable` | 受けない | 用途が無く、必須の private 化と矛盾する |
| `rslave` と `private` / `rprivate` の併記 | `InvalidArgument`（`ConflictingPropagation`） | `bind` と `rbind` の併記の拒否（#2063 の決定 (a)）と同じ扱い |

`linux.rootfsPropagation` は使わない（CRI も出力しない）。指定があれば従来どおり `UNIMPLEMENTED`（`UnappliedField::LinuxRootfsPropagation`）。

## peer group と user namespace の仕組み

- マウントは propagation の種類（shared / slave / private / unbindable）と peer group を持つ。slave は master の peer group からの伝播を受け、こちらの変更は master へ戻らない
- 非特権 user namespace で mount namespace をコピーすると、ホストの shared マウントはカーネルの `CL_SHARED_TO_SLAVE` により slave に格下げされる（`mount_namespaces(7)`）。本番の bind はいつも user namespace の中で適用する（`user_namespace_required`・`host_root_identity_mapping` が他の経路を拒否済み）ため、コンテナからホストへの伝播は原理的に成り立たない
- 既に slave のマウントは、コピー・複製（`open_tree(OPEN_TREE_CLONE)`）で master を保つ。private のマウントは private のまま

## 採用した方式: 再帰 private 化の前に rslave の元だけを複製する

`/` を `MS_REC|MS_PRIVATE` にする不変条件（`MountIsolation::establish`）は保つ。再帰 private 化は接続済みの木の master 関係をすべて消すため、`rslave` を求めた bind だけ、その前に元を複製する。

1. **中間プロセス側**（`unshare_and_configure`）: 計画が `rslave` を求めるときだけ `/` を `MS_REC|MS_SLAVE` にする（既定は `MS_REC|MS_PRIVATE`）。この namespace のマウントはもともと slave か private で、master 関係を消さないだけの変更。外へは伝播しない。launcher が `BindMountSet::has_host_slave` で選ぶ
2. **PID 1 側**（`MountIsolation::establish_with`）: `unshare(CLONE_NEWNS)` の後、`/` の再帰 private 化の前に、`rslave` の bind ごとに (a) 元を `/` から `O_NOFOLLOW` で固定し、(b) 固定した fd の `mnt_id` を `/proc/thread-self/mountinfo` で引いて `master:` か `propagate_from:` があり `shared:` が無いことを確かめ（満たさなければ rootfs に触れる前に `FAILED_PRECONDITION`）、(c) `open_tree(OPEN_TREE_CLONE)`（`rbind` のときは `AT_RECURSIVE`）で複製する。複製は匿名 namespace にあり、続く再帰 private 化の対象にならない。同じ mount namespace の中での複製なので `check_mnt` を満たす
3. **`mount_binds`**: `rslave` の bind は、2 の固定と複製を使う（`open_tree` を呼ばない）。疑似 FS・rootfs・状態ルートの照合、属性（`nosuid`・`nodev`・`ro`・`noexec`）、移動検査、付け替えは private の bind と同じ。`mount_setattr` の `propagation` は 0 のまま。付け替え後の mountinfo の照合は、`shared:` を全メンバーで禁止したまま、`rslave` の bind の最上位に `master:` か `propagate_from:` を必須にする（配下は許す）
4. **rootful**（`isolate_rootful_host_root`）の計画は伝播を選べず常に private。bind 自体を user namespace の外では受けないため、新たに失うものは無い

### 却下した案: `/` 全体を条件つきで `MS_REC|MS_SLAVE` にする

runc や containerd が `rootfsPropagation=rslave` を設定する流儀。次の理由で採らない。

- private の bind にも `master:` が付くため、`mount_setattr` で明示的に `MS_PRIVATE` を設定することになり、#2165 で見送った変更を蒸し返す
- user namespace 経路の `/sys`（ホストの再帰 bind）と `/dev` ノードの複製まで slave になる。ホストから伝播したマウントは、こちらの `ro`・`nosuid`・`nodev` を持たずに入ってくるため SEC-2 が後退する

## rshared を受けない理由と、受けるときの緩和点

Kubernetes も Bidirectional を privileged コンテナに限っており、privileged は本リポで拒否している。受けたように見せると REPAIR-3（実装済みを装わない）に反する。成り立たせるには、次の fail-closed の検査を弱める必要がある。弱めるかはオーナー判断（要対応）である。

- `/` の再帰 private 化をやめる（または rshared の bind だけ除く）。`pivot_root` が shared の親で `EINVAL` になる問題の回避が要る
- `mount_binds` の手順 4（付け替え先が shared なら拒否）と手順 9（`shared:` の不在の照合）
- `exec/rootfs.rs` の `SharedPropagation` の拒否
- 上の格下げ（`CL_SHARED_TO_SLAVE`）のため、user namespace の中では緩和してもホストへ伝播しない。rootful でだけ意味があり、本番は rootful の bind を受けない

## ホスト側の元が private のときは拒否する

containerd の `ensureSharedOrSlave` と同じ考え方で、`rslave` を求めたのにホスト側の元が shared でも slave でもなければ、起動を `FAILED_PRECONDITION` で拒否する（黙って private で載せない）。runc は private のまま載せる点で異なる。対処は、ホスト側で `mount --make-rshared <元>` を済ませる（`docs/api/bind-mounts.md`）。systemd のホストの `/` は既定で shared で、その配下の元はそのまま通る。

## 残余（REPAIR-3）

- ホストから `rslave` の bind へ伝播してきたマウントには、ホスト側のマウントの属性とカーネルのロック（`CL_UNPRIVILEGED`）が付き、こちらの `nosuid`・`nodev`・`ro`・`noexec` は付かない。疑似 FS と状態ルートの検査も、付け替える時点の 1 回だけである。HostToContainer の意味に内在する性質で、Kubernetes でも同じ。引き起こせるのはホストの特権主体だけ
- Landlock は経路を辿って判定するので、bind 先の規則は伝播したマウントにも効く
- ホスト側での伝播の実機確認（root が要る）は `docs/verification/bind-rslave-propagation.md`。CI は sudo を使わないため、伝播そのものは CI では確かめない（`production_launcher` のシナリオ U が、コンテナ内で bind 先が slave であり shared でないことと、ホスト側が private のときの拒否を照合する）
