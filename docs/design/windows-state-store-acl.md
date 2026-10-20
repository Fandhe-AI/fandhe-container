# Windows の FileStateStore の信頼境界（所有者 SID・保護 DACL）の実装方式（判断記録）

Windows で `FileStateStore` の状態ルートを信頼境界として検査する方式（`windows-sys` を core に足すか、自前の `extern "system"` 宣言か、そもそも実装しないか）の判断材料を整理する（OCI-5・SEC-4）。

> **位置づけ**: 状態は **オーナー承認待ち**（[#2428](https://github.com/Fandhe-AI/fandhe-container/issues/2428)）。本書は決定ではなく判断材料である。決まるまで Windows の `FileStateStore::open` は、副作用（ディレクトリの作成）の前に `Unimplemented` で拒否したままにする（fail-closed。分離を緩めない）。

- 対象ビヘイビア: OCI-5（状態の永続化）・SEC-4（監査）・REPAIR-3（未実装を装わない）・CLI-1（3 OS 一級対応）・IO-5。タスク: TASK-31
- 親: [#2247](https://github.com/Fandhe-AI/fandhe-container/issues/2247)。検出元: PR #2369（macOS で `FileStateStore` を開けるようにした変更）
- 関連: [windows-execution-layout.md](windows-execution-layout.md)（#1415・#1539）

## 現状

- `crates/core/src/state_store.rs` の `ensure_supported_platform`（`cfg(not(any(linux, macos)))`）が、Windows では何も作る前に `Unimplemented`（固定の英語文言。パス・OS エラーを含めない）を返す
- 足りないもの: (1) 状態ルートの所有者 SID と現在のユーザーの SID の照合、(2) 保護 DACL（継承を切り、所有者だけに権限を与える）の作成と検証
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
- 決定後の作業: エラーを「未実装」（`Unimplemented`）から設計上の拒否の文言に替えるか、`Unimplemented` のままにするか
- **未確認の点（棚卸しの事実）**: Windows ビルドの CLI にも `FileStateStore::open` を呼ぶ非テストのコードがある（`crates/cli/src/commands/create_start.rs`・`commands.rs`・`supervisor_start.rs`・`setup.rs` の周辺、`crates/plugin-mcp/src/backend.rs`、`crates/supervisor/src/state.rs`、`crates/plugin-cri/src/adapter.rs`）。これらがホスト側で実際に到達するか（ゲスト内でのみ動くか）は #1415 の構成の実装次第で、本書では確定できない。オーナーに確認したい

## 比較

| 観点 | A | B | C |
| ---- | -- | -- | -- |
| 依存の承認 | 要（core への `windows-sys`） | 要らない（照合用 dev-dependency を足すなら要） | 要らない |
| `unsafe` | `sys` 内（`windows-sys` の呼び出し） | `sys` 内（宣言も手書き。量が多い） | 無し |
| 宣言の照合 | 不要（`windows-sys` が正） | 手段なし | 不要 |
| #1415 との整合 | ホストで開く前提を認めることになる | 同左 | 最も整合する |
| 必要な試験 | Windows ネイティブ（`icacls` で ACL を付けて拒否を確認） | 同左 | 文言の試験のみ |
| CI での確認 | PR は型検査のみ。実行は main の `platform-ci` か `workflow_dispatch`（3 OS） | 同左 | 通常の CI で足りる |

## 推奨案（材料。決定ではない）

- 第一案は C。#1415 の既決の構成と最も整合し、信頼境界のコードを増やさないため。前提は、上記「未確認の点」で、ホスト側に到達する呼び出し元が無いと確かめられること
- Windows ホストで開く必要があるとオーナーが判断する場合は A。宣言の範囲が広く、B は手書きの誤りの危険と照合手段の欠如が弱点になるため
- 最終判断はオーナーに委ねる

## 決定後に残る作業（実装 issue の下書き。起票はオーナーの決定後）

- A・B: 次を #2247 の配下に起票する
  - 所有者 SID の照合と保護 DACL の作成・検証。所有者以外の許可 ACE の拒否
  - reparse point（symlink・junction）の拒否と、祖先のすり替えへの対策の方針
  - `cfg(target_os = "windows")` での局所化（CLI-1・IO-5）
  - Windows ネイティブの試験（`icacls` 方式）と、`gh workflow run ci.yml --ref <branch>` による 3 OS での確認
  - `FileAuditSink` 等の `SinkFailed` を説明するコメントの整理
  - B の場合: `unsafe` の一覧・security-auditor 観点のレビュー記録を PR 本文に載せる
- C: エラー文言と doc の変更、ホスト側経路の棚卸し結果の記録、`SinkFailed` の説明の整理

## 承認事項

- 案の選択
- A の場合: core への `windows-sys`（`=0.61.2`・feature の一覧）の追加
- B の場合: 宣言の照合用に `windows-sys` を dev-dependencies へ入れるか
