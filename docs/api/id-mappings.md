# config の uidMappings・gidMappings の扱い

OCI `config.json` の `linux.uidMappings` / `linux.gidMappings` は受けない（SEC-5・CORE-6。判断は [#2240](https://github.com/Fandhe-AI/fandhe-container/issues/2240)、設計は [config-id-mappings.md](../design/config-id-mappings.md)）。

## 挙動

- どちらかの配列が非空なら `start` は終了コード非 0 の `INVALID_ARGUMENT` で拒否する。message は次の固定文言（config の値は含めない）。`linux.uidMappings / linux.gidMappings are not accepted: ID mappings are derived from the runtime privilege model (SEC-5)`
- 空配列・省略は受ける
- 拒否はプロセス起動・状態の予約より前で行い、プロセスも状態も残さない。監査ログには記録しない（config の誤りで、脱出の試行ではないため）

## 受けない理由

user namespace の ID 写像は、権限モデルから導く。rootless の単一写像は呼び出し側の euid / egid、範囲写像は `/etc/subuid`・`/etc/subgid` に従う。config で指定できると、コンテナ内 root をホストの非特権 UID へ写す SEC-5 の契約を迂回できるため。

## Docker / runc との差

runc は config の写像をそのままカーネルへ書き込む。本ランタイムは config の写像を受けず、権限モデルから導く。user namespace を使うときは `linux.namespaces` に `user` だけを書き、写像の配列は省略する（または空配列）。
