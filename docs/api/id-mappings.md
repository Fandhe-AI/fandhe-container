# config の uidMappings・gidMappings の扱い

OCI `config.json` の `linux.uidMappings` / `linux.gidMappings` は受けない（SEC-5・CORE-6・TASK-40・MS-2。判断は [#2240](https://github.com/Fandhe-AI/fandhe-container/issues/2240)、設計は [config-id-mappings.md](../design/config-id-mappings.md)）。

## 挙動

- config のパース時の検証（`size` が 0 の写像などはここで先に拒否される）を通った写像で、どちらかの配列が非空なら `start` は `INVALID_ARGUMENT`（終了コード 2）で拒否する。message は次の固定文言（config の値は含めない）。`linux.uidMappings / linux.gidMappings are not accepted: ID mappings are derived from the runtime privilege model (SEC-5)`
- 変更前（#4711 より前）は同じ入力が `UNIMPLEMENTED`（終了コード 8。message `start does not support yet: linux.uidMappings / linux.gidMappings`）だった。終了コードや code で分岐している呼び出し元は、2 / `INVALID_ARGUMENT` へ移す
- 空配列・省略は受ける
- 拒否はプロセス起動・状態の予約より前で行い、新たな起動予約やプロセスは残らず、create 済みの状態レコードは `Created` のまま。監査ログには記録しない（config の誤りで、脱出の試行ではないため）
- CLI の `start`（supervisor 経由）では、委譲 cgroup の準備（`prepare`）が先に走り、状態レコードに cgroup の配置を記録してから写像を拒否する。cgroup の削除は拒否の応答の後に supervisor が試みるもので、CLI が `INVALID_ARGUMENT` を返した時点で済んでいるとは限らない（削除に失敗することもある）。配置の記録は残る。そのため config を直して同じ ID で `start` し直すと `FAILED_PRECONDITION`（message `cgroup scope is already recorded; delete and recreate the container`）になる。直すときは `delete` してから作り直す

## 受けない理由

（SEC-5・CORE-6・TASK-40・MS-2）user namespace の ID 写像は、権限モデルから導く。rootless の単一写像は呼び出し側の euid / egid、範囲写像は `/etc/subuid`・`/etc/subgid` に従う。config で指定できると、コンテナ内 root をホストの非特権 UID へ写す SEC-5 の契約を迂回できるため。

## Docker / runc との差

runc は config の写像をそのままカーネルへ書き込む。本ランタイムは config の写像を受けず、権限モデルから導く。`linux.namespaces` の `user` は必須（無ければ `PERMISSION_DENIED`）で、写像の配列は省略するか空配列にする。
