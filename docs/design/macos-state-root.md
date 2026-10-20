# macOS の既定の状態ルート（`StateRoot::resolve(None)`）の判断記録

macOS ホスト側で、状態ルートの既定をどこに置くか（そもそも置くか）の判断材料を整理する。

> 位置づけ: **オーナー承認待ち（#2431）**。本書は判断材料であり決定ではない。決まるまで macOS の `StateRoot::resolve(None)` は `Unimplemented` のまま（fail-closed）で、実行時の挙動は変わらない（REPAIR-3）。

- 対象ビヘイビア: OCI-5・SEC-4・CLI-1（関連: PLUG-11・PLUG-12・REPAIR-3）
- タスク: TASK-31（#141 の 2026-09-26 決定）の追補
- 関連 issue: #2431（本書）・#2247（親。macOS で `FileStateStore::open` を通した）・PR #2369・#2373（拡張 ACL の検査）・#1906（macos-shared-vm.md）・#1869（plugin-backend-wiring.md 4.6）・#2428（Windows の対の判断記録）
- 作成日: 2026-10-20

## 1. 現状

- `StateRoot::resolve` の既定は Linux のみ。root は `/run/fandhe-container`、rootless は `$XDG_RUNTIME_DIR/fandhe-container`（未設定は `FailedPrecondition`）
- macOS で上書き指定（`--root`）が無いと `Unimplemented`
- `FileStateStore::open` は macOS でも通る（#2247）。検査は、所有者＝実効 UID（または root）・モード 0700・祖先の書き込み権限・symlink 拒否・拡張 ACL があれば拒否
- 祖先の検査は `fs::metadata` で辿るため、祖先の symlink は実体で判定される

## 2. 論点 0: ホストに状態ルートを持つか（先に決めること）

OCI-5 (4) は「macOS / Windows では状態ファイルをゲスト VM 内の Linux パスに置く」とする。macos-shared-vm.md（承認待ち #1906）も、ホストに置くのは保持役のロックと所属記録だけで、状態ファイル本体はゲスト内としている。

一方、macOS ホスト側で `resolve(None)` に届く呼び出し元が現にある。

| 呼び出し元 | 用途 |
| ---------- | ---- |
| `crates/cli` の `production_audit_sink` → `FileAuditSink::open_in_state_root` | plugin 信頼検証の拒否の記録先（PLUG-11・SEC-4）。`--root` が無いと `UnavailableAuditSink` |
| `crates/plugin-mcp` の `CoreBackend::production()` | `root: None` で既定解決 |
| `crates/plugin-cri` のアダプタ | 既定に固定で既定解決 |

OCI-5 (4) の字面ではホストの既定は不要だが、上の呼び出し元は既定を要求する。「ホストに持つか、持つなら用途を監査の記録先などに限るか」は OCI-5 (4) だけでは答えられず、spec の明確化が要るかもしれない。spec 側の変更は本リポでは決めず、オーナーへ報告する。

## 3. 選択肢

いずれの案でも、`/tmp` 等への推測のフォールバックはしない（OCI-5 (2)・ERR-2）。環境変数由来のパスは絶対パス・`..` 拒否（`from_override` と同じ）と上記の検査を通す。

- **案 A: ホストでは既定を持たない（恒久の fail-closed）**。ホストの呼び出し元は `--root` を必須にするか、ゲスト内のパスへ中継する（macos-shared-vm.md の中継と合わせる）。OCI-5 (4) と字面で一致する。欠点は、plugin 信頼検証の拒否の記録がホストに残らないこと（中継か別の記録先が要る）
- **案 B: `~/Library/Application Support/fandhe-container`**（永続）。ホーム等に既定の deny ACL（例: 削除を拒否する ACE）がある場合、祖先の拡張 ACL 検査で拒否される（実機で未確認）。採るには ACL 検査を「deny だけなら許す」等へ緩める必要があり、曖昧なときは fail-closed とする #2373 と逆向き。ホームの解決は `HOME` ではなく `getpwuid` にする（macos-shared-vm.md と同じ姿勢）
- **案 C: ユーザーごとの一時ディレクトリ（`/var/folders/<xx>/<hash>/T/fandhe-container` 相当）**。揮発で、Linux の `XDG_RUNTIME_DIR` に近い性質。`TMPDIR` は環境変数由来で詐称されうる（`XDG_RUNTIME_DIR` と同種。Linux 規則は受け入れている）。環境に頼らない取得は `confstr(_CS_DARWIN_USER_TEMP_DIR)` で、`sys/macos.rs` に新しい FFI の薄いラッパーが要る。祖先（`/var` から `/private/var` への symlink、`/var/folders` 配下の所有者・モード・ACL）が検査を通るか、OS の定期掃除で状態が消えないかは実機で未確認
- **案 D: XDG 相当**。`XDG_RUNTIME_DIR` が設定されていれば Linux と同じ規則、無ければ `FailedPrecondition`。macOS は既定で `XDG_RUNTIME_DIR` を持たないため、実質は「設定が要る」状態のまま
- 共通の論点: root 実行時（`/var/run/fandhe-container` 等）を案ごとに扱うか、macOS では rootful を扱わないか

## 4. 比較

| 観点 | A | B | C | D |
| ---- | - | - | - | - |
| OCI-5 (4) との整合 | 一致 | 要明確化 | 要明確化 | 要明確化 |
| 今の検査を通るか | 該当なし | ACL で拒否の恐れ | 祖先の実機確認が要る | 設定次第 |
| 永続か揮発か | 該当なし | 永続 | 揮発 | 設定次第 |
| 環境変数への依存 | なし | なし（`getpwuid`） | なし（`confstr`）または `TMPDIR` | `XDG_RUNTIME_DIR` |
| 新規 unsafe | なし | `getpwuid` のラッパー | `confstr` のラッパー | なし |
| #2373（曖昧なら fail-closed）との整合 | 整合 | 逆向き | 整合の見込み（実機確認後） | 整合 |
| 揮発による SEC-4 の記録喪失 | 該当なし | なし | あり | 設定次第 |

## 5. 推奨（Agent の推奨。決定ではない）

当面は案 A（既定を持たない）を推奨する。理由は、挙動が今と同じで安全側であり、ACL 検査を緩めず（#2373 と整合）、新規 unsafe も増えないため。ホストに置く必要が確定したら、環境に頼らない案 C（`confstr`）を実機確認の上で検討する。最終判断はオーナー。

## 6. 決定後の作業（実装 issue に書く項目）

- `resolve` の macOS 分の実装（`cfg(target_os = "macos")` を core 内に局所化。CLI-1）
- #2373 の ACL 検査との整合（所有者・モード・拡張 ACL の検査を #2247 の配下で揃える）
- 試験: パスの解決は純粋関数に切り出して 3 OS で試験できる形にし、ビヘイビア ID を名前に入れる
- macOS の実行時確認: PR の CI は ubuntu のみのため `gh workflow run ci.yml --ref <branch>` で 3 OS を回す
- `state_store.rs` の doc と本書の更新

## 7. 実機で未確認の事項

- ホーム・`~/Library` の既定 ACL
- `/var/folders` 配下の祖先の所有者・モード・ACL と、OS による掃除の挙動
- `HOME` / `TMPDIR` の要否（plugin-backend-wiring.md 4.6・#1628）
