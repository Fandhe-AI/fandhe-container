# Windows ホストの FileStateStore を設計上の恒久拒否にする判断記録（旧題: 所有者 SID・保護 DACL の実装方式）

Windows で `FileStateStore` の状態ルートを信頼境界として検査する方式（`windows-sys` を core に足すか、自前の `extern "system"` 宣言か、そもそも実装しないか）の判断材料と、決定（案 C）を記録する（OCI-5・SEC-4・WIN-1）。

> **位置づけ**: **決定済み**（[#2428](https://github.com/Fandhe-AI/fandhe-container/issues/2428) のオーナー判断、2026-11-09）。**案 C: Windows ホストでは `FileStateStore` を設計上恒久的に拒否する**。`FileStateStore::open` は、副作用（ディレクトリの作成）の前に `FailedPrecondition` で拒否する（fail-closed）。実装は [#4332](https://github.com/Fandhe-AI/fandhe-container/issues/4332)。案 A・B は採らない。以下の「選択肢」「比較」は採否の根拠として残す。

- 対象ビヘイビア: OCI-5（状態の永続化）・SEC-4（監査）・REPAIR-3（未実装を装わない）・CLI-1（3 OS 一級対応）・IO-5。タスク: TASK-31
- 親: [#2247](https://github.com/Fandhe-AI/fandhe-container/issues/2247)。検出元: PR #2369（macOS で `FileStateStore` を開けるようにした変更）
- 関連: [windows-execution-layout.md](windows-execution-layout.md)（#1415・#1539）

## 現状

- `crates/core/src/state_store.rs` の `ensure_supported_platform`（`cfg(not(any(linux, macos)))`。対応 3 OS でこの分岐に入るのは Windows だけ）が、何も作る前に `FailedPrecondition`（固定の英語文言 `file state store is not supported on a Windows host by design; the state root belongs in the Linux guest`。パス・OS エラーを含めない）を返す（#4332 で `Unimplemented` から変更）
- 実装しないもの（案 A・B の範囲）: (1) 状態ルートの所有者 SID と現在のユーザーの SID の照合、(2) 保護 DACL（継承を切り、所有者だけに権限を与える）の作成と検証
- core には Windows 用の `sys` が無い（`lib.rs` にあるのは linux と macos の `sys` だけ）。`windows-sys` への依存も無い
- 既定の状態ルート（`StateRoot::resolve`）は Linux ゲスト内のパス前提で、Windows では上書き指定が要る

## 先例

| 方式 | 先例 | 要点 |
| ---- | ---- | ---- |
| 自前宣言 | `crates/io/src/sys/windows.rs` | `NtCreateFile`・`FlushFileBuffers` の宣言と構造体レイアウトを自前で持つ（依存を増やさない） |
| `windows-sys` | `crates/platform-windows`（`windows-sys =0.61.2`。#371 で承認済み。承認範囲は platform-windows の `cfg(windows)` 依存） | `GetSecurityInfo`・`SetSecurityInfo`・`PROTECTED_DACL_SECURITY_INFORMATION` を使い、宣言は手書きしない |

- ルート `Cargo.toml` の `[workspace.dependencies]` に `windows-sys = "=0.61.2"` が既にある。core が使っても `Cargo.lock` の版は増えないが、core から `windows-sys` への依存の辺が新しく増えるため新たな承認が要る
- core が `platform-windows` に依存して先例を再利用する案は取らない（上位から下位への一方向依存に反する。coding-rust.md）

## 実装する場合に要る Win32 の範囲（案 A・B 共通）

- 現在のユーザーの SID: `GetCurrentProcess`・`OpenProcessToken`・`GetTokenInformation(TokenUser)`・`CloseHandle`
- 所有者 SID と DACL の取得・照合: `GetSecurityInfo(OWNER | DACL)`・`EqualSid`・`LocalFree`・制御フラグ `SE_DACL_PROTECTED` の確認・ACE の列挙（`GetAclInformation`・`GetAce`）で「所有者以外への許可が無いこと」を検証
- 保護 DACL の作成: `InitializeAcl`・`AddAccessAllowedAceEx`（`OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`）・`InitializeSecurityDescriptor`・`SetSecurityDescriptorDacl`。`CreateDirectoryW` に `SECURITY_ATTRIBUTES` を渡すか、作成後に `SetSecurityInfo(PROTECTED_DACL_SECURITY_INFORMATION)`
- symlink・junction の拒否: `CreateFileW` に `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` を付けて開き、`GetFileInformationByHandleEx` で reparse 属性を見る（Unix の `O_NOFOLLOW` 相当）
- 祖先の検査（Unix の「祖先は group / other 書き込み不可」に相当）: 祖先の DACL が他ユーザーへ子の追加・書き込みを許す ACE を拒否する。方針は設計判断を要する論点
- 宣言の機械照合: Linux の `libc` 照合（#1318）に相当する手段が自前宣言には無い。照合用に `windows-sys` を dev-dependencies へ入れること自体が承認事項になる

## 選択肢

### A. core に `windows-sys` を足す

`[target.'cfg(windows)'.dependencies]` に `windows-sys = { workspace = true, features = [...] }`。feature は最小に絞る（見込み: `Win32_Foundation`・`Win32_Security`・`Win32_Security_Authorization`・`Win32_Storage_FileSystem`・`Win32_System_Threading`）。

- 長所: 宣言とレイアウトの誤りが起きない。platform-windows の先例とそろう。版は既存 lock と同じ
- 短所: core の依存の辺が増える（承認事項。core の依存最小方針から外れる）。`unsafe` は `sys` に閉じる必要がある
- バイナリ・常駐メモリ（CORE-7〜9）: `windows-sys` は宣言中心で影響は小さい見込みだが、数値は未計測

### B. core の `sys/windows.rs` に自前宣言を置く

`crates/core/src/sys/windows.rs` を新設し、`lib.rs` に `cfg(target_os = "windows")` の `mod sys` を足す。`unsafe` は `sys` に閉じる範囲で事前承認済み。

- 長所: 依存を足さない。`crates/io` の先例がある
- 短所: 宣言の量が io の先例よりかなり多い（SID・ACL・ACE・SECURITY_DESCRIPTOR・TOKEN_USER）。機械照合の手段が無い（上記）。レイアウトの誤りがそのまま信頼境界の誤りになる

### C. Windows ホストでは恒久的に拒否する

[windows-execution-layout.md](windows-execution-layout.md) の既決の構成（#1415・#1539）では core・CLI・supervisor は WSL2 ゲスト内で動き、状態ファイルはゲスト内の Linux パスに置く（OCI-5）。Windows ホストの薄い起動役は状態を持たない。この構成に従えば Windows ホストで `FileStateStore` を開く設計上の呼び出し元は無く、拒否が恒久で足りる。

- 長所: Win32 FFI もテストも要らない。依存の追加が無い
- 決定: 採用（2026-11-09・#2428）。エラーは「未実装」ではなく設計上の拒否として `FailedPrecondition` にした（次節）
- 再評価条件: Windows ホストで状態を持つ構成（#1415 の既決の構成の変更）になったとき、案 A を再評価する

## 比較

| 観点 | A | B | C |
| ---- | -- | -- | -- |
| 依存の承認 | 要（core への `windows-sys`） | 要らない（照合用 dev-dependency を足すなら要） | 要らない |
| `unsafe` | `sys` 内（`windows-sys` の呼び出し） | `sys` 内（宣言も手書き。量が多い） | 無し |
| 宣言の照合 | 不要（`windows-sys` が正） | 手段なし | 不要 |
| #1415 との整合 | ホストで開く前提を認めることになる | 同左 | 最も整合する |
| 必要な試験 | Windows ネイティブ（`icacls` で ACL を付けて拒否を確認） | 同左 | 文言の試験のみ |
| CI での確認 | PR は型検査のみ。実行は main の `platform-ci` か `workflow_dispatch`（3 OS） | 同左 | 通常の CI で足りる |

## エラーのコードと文言

- コード: `FailedPrecondition`（ERR-2 の終了コード 5）。「実行環境（Linux ゲスト内）という前提を満たさない」ことを表し、「いつか実装する」と読める `Unimplemented`（8）と区別する。`PermissionDenied`（権限不足）・`Unavailable`（再試行で回復し得る）は意味が合わない。新しい `ErrorCode` は足さない
- 文言（固定・英語）: `file state store is not supported on a Windows host by design; the state root belongs in the Linux guest`。#4333（oci の `ImageStore` の恒久拒否）はこの流儀に合わせる
- 影響: Windows の CLI で表に出るのは `plugin_backend` の `UnavailableAuditSink` が出す stderr 1 行（`audit_sink_unavailable` の `code`）だけで、`UNIMPLEMENTED` から `FAILED_PRECONDITION` に変わる。CLI コマンドの終了コードは変わらない（非 Linux の `open_store` は `FileStateStore::open` を呼ばない）
- macOS の `StateRoot::resolve(None)` は #2431 案 A で `FailedPrecondition` の恒久拒否に確定（#4665）。Windows の `resolve(None)` は `Unimplemented` のまま（別の判断）
- 試験: core 単体・core 結合・oci 結合（`cfg(not(any(linux, macos)))`）が上記の具体値と「状態ルートを作らない」ことを照合する。Windows の実行は main の `platform-ci` で行われる

## 呼び出しの棚卸し（Windows ホストでの到達）

core・CLI・supervisor は WSL2 ゲスト内で動く構成（#1415）で、ホストの起動役（`platform-windows`・`plugin-windows`）は core に依存しないため `FileStateStore` を呼べない。Windows 向けにコンパイルされる `FileStateStore::open` の呼び出しは次のとおりで、いずれも `open` の先頭で拒否され状態ルートは作られない。

| 呼び出し箇所 | Windows ビルドに入るか | 結論 |
| ------------ | ---------------------- | ---- |
| cli `commands/create_start.rs` の `open_store` | Linux のみ（非 Linux は `plugin_backend::unavailable`） | 呼ばない |
| cli `commands/stop_delete.rs` の `id_is_still_deleted` | 入る（cfg なし） | 到達しても拒否され `false`（fail-closed）。呼び出し元の経路は非 Linux では `open_store` が先に失敗する |
| cli `commands/plugin_backend.rs` の `production_audit_sink` → core `FileAuditSink::open_in_state_root` → `FileStateStore::open` | 入る | 拒否され `SinkFailed`（記録先なし。W-C の採否は #2430） |
| cli `exec`・`image`・`list_logs`・`network`・`ref_reconcile`・`commands.rs`・`setup.rs` | `open_store` 経由（上記）または試験のみ | `open_store` が先に失敗する |
| supervisor `state::open_default_store`（`start_entry`・`healthcheck`・`stream_exec` が利用） | `state`・`start_entry`・`healthcheck` は cfg なし（`stream_exec`・`exec`・`start_client` は Linux のみ） | 到達しても拒否される。supervisor はゲスト内で動く前提 |
| plugin-mcp `backend.rs` の `CoreBackend::list_containers` | 入る（cfg なし） | 到達しても拒否される（`FailedPrecondition` を返す） |
| plugin-cri `adapter.rs`・`shim.rs` | `adapter`・`shim` は cfg なし | 到達しても拒否される。plugin-cri はゲスト内で動く前提 |
| cri `shim_v2/bootstrap.rs` の `open_audit_sink` | Linux のみ（非 Linux は `None`） | 呼ばない |
| core `plugin_trust/report.rs`（doc の言及のみ） | — | 呼ばない |
| 試験のみ（cli・supervisor・plugin-cri・plugin-mcp・core の `#[cfg(test)]` と `tests/`） | 試験ビルド | 対象外 |

- ホストの起動役が `Ok` で状態ルートを開く経路は見つかっていない（拒否は core 側にあるため理屈上も起きない）。見つかった場合は本書の対象外として別 issue で扱う

## 決定（2026-11-09・#2428）

- 案 C を採用する。根拠は OCI-5 (4)（macOS / Windows の状態ファイルはゲスト VM 内の Linux パスに置く）と #1415 の既決の構成。依存の追加は無い（`windows-sys` を足さない）
- 採らなかった案: A（core に `windows-sys`）・B（自前宣言）。Windows ホストで状態を持つ構成が前提で、#1415 と整合しない。B は宣言の量が多く機械照合の手段も無い
- 再評価条件: Windows ホストで状態を持つ構成になったとき（案 A を再評価する）

## 決定後に残る作業

- C（#4332）: エラーコードと文言の変更、doc の整理、ホスト側経路の棚卸し結果の記録（本書）。`SinkFailed` の説明の整理
- A・B は実施しない。再評価で A を採る場合は、所有者 SID の照合と保護 DACL の作成・検証、reparse point の拒否、Windows ネイティブの試験（`icacls` 方式）、`windows-sys` の依存承認が要る
