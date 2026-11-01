# ゲスト物理メモリアクセス型の所有先と /dev/kvm 試験の分離（判断記録）

virtio の virtqueue 処理がゲスト物理アドレスでゲストメモリを読み書きするために必要な最小限のアクセス型を、TASK-74.1 側と TASK-75.1 側のどちらが持つかを決めて記録する（MVM-1・MVM-4・TASK-74.1.3・#876。親 #689）。

> **位置づけ**: Agent が記録した判断であり、オーナー決定ではない。承認を得たものとして扱わない。本記録ではアクセス型のコードを実装しない（コード・依存は変えない）。

## 前提の依存関係

| issue | 内容 | 依存 |
| ---- | ---- | ---- |
| #877（TASK-74.2.1） | virtio-mmio 共通基盤 | #689（TASK-74.1）のみ |
| #878（TASK-74.2.2） | virtio-block の virtqueue | #877 |
| #880（TASK-74.3.1） | virtio-net の virtqueue | #877・#689 |
| #696（TASK-75.1） | mmap と `KVM_SET_USER_MEMORY_REGION`（成果物 `crates/microvm/src/microvm.rs`） | #688（TASK-74 全体） |

virtqueue 処理（#878・#880）はディスクリプタのゲスト物理アドレスでゲストメモリに触れるが、実体の mmap を持つ #696 はそれより後になる。アクセス型の置き場所を決めないと、#878・#880 はその場しのぎのスライス処理を作ることになる。

## 決定

所有を 2 つに分ける。

### アクセス型は TASK-74.1 側が持つ

`crates/microvm` 内の OS 非依存モジュール（想定 `crates/microvm/src/guest_memory.rs`。名前は実装 issue で確定する）に置く。

- ゲスト物理アドレスの newtype（例 `GuestAddress(u64)`）。生の `u64` を渡し回さない（REPAIR-2）
- 領域の記述（base・len）と、アドレスから領域内オフセットへの変換
- コピーで渡す読み書き API（例 `read_at(addr, &mut [u8])`・`write_at(addr, &[u8])`・固定長の読み出し）。`&[u8]`・`&mut [u8]` は外へ渡さない。vCPU がゲストメモリを並行して書き換えるため、参照を作ると Rust のエイリアシング規則に反するから
- `unsafe` を使わない。backing は trait（または型パラメータ）で差し込む。試験用に heap（`Vec<u8>`）の backing を用意し、virtqueue 処理の単体テストを `/dev/kvm` なしで既定のテスト集合に置けるようにする

### backing は TASK-75.1（#696）が持つ

- 匿名 mmap（フラグの選択は #696 で決める）・`KVM_SET_USER_MEMORY_REGION` による登録・munmap と Drop の後始末
- `unsafe` は `crates/microvm/src/sys.rs` に閉じる（coding-rust の事前承認の範囲。SAFETY コメントと security-auditor 観点のレビューは #696 の PR で行う）
- アクセス型へは安全なコンストラクタ経由で渡し、アクセス型の API は変えない

## 理由

- 依存順: #878・#880 は #696 より前に走る。アクセス型を TASK-75.1 に置くと依存が逆になる
- 単一責務（REPAIR-1）: アドレス変換と境界検査は OS にも KVM にも依存しない純粋な計算。mmap と KVM 登録は特権操作の側。分けておくと検査ロジックの改修が `unsafe` の箇所へ広がらない
- テスト分離: アクセス型と virtqueue のパースを既定のテスト集合で検証でき、実機前提に回すのは KVM ioctl の試験だけになる
- MVM-4: `vm-memory`（rust-vmm）を使わず自作する根拠にもなる

## #882 の例外（TASK-74.4.1）

`KVM_RUN` でゲストコードを実機で実行して示すには、ゲストメモリの登録が最低 1 ページ要る。そこで #882 では次だけを `sys.rs` に持つ（MVM-1）。

- `GuestPage`（`alloc_zeroed` した 4 KiB）と `RegisteredPage<'vm>`（`KVM_SET_USER_MEMORY_REGION` で登録済みの 1 ページ。VM fd を借用し、drop で slot を削除してから解放する。削除に失敗したページは解放せず漏らす）
- 公開 API には出さず、自己診断の入口 `KvmDevice::probe_guest_execution()`（x86_64 のみ。VM・ページ・vCPU の寿命がこの関数の中で完結する）だけが使う

汎用の backing（匿名 mmap・複数領域・アクセス型との接続）は上記のとおり引き続き #696 の担当で、#696 は #882 の型を流用せず置き換えてよい。

## 却下案

| 案 | 却下理由 |
| ---- | ---- |
| (A) 全部を TASK-75.1 に置く | #878・#880 が #696 を待つことになり、#696 が #688 全体に依存する依存グラフと循環する |
| (B) 全部を TASK-74.1 に置く | mmap と KVM 登録が #696 の受け入れ条件と重なり、TASK-74 側で `unsafe` の承認範囲が広がる |

## アクセス型の契約（外部入力の検証）

ゲスト物理アドレスと長さは virtqueue ディスクリプタから届く、ゲストが自由に決められる非信頼入力である。

- `addr + len` は checked 演算で計算し、桁あふれを拒否する。領域をまたぐアクセス・領域外へのアクセスも拒否する
- 添字 `[]` ではなく `get()` を使い、`unwrap` / `expect` は使わない
- ディスクリプタ長を上限で検査してからバッファを確保する（無制限確保による DoS の防止）
- 失敗は panic せず `MicrovmError`（`InvalidArgument`。ERR-1）で返し、ホストのメモリへ到達させない

## 実装の担い手

アクセス型を担当する issue が無かったため、TASK-74.2.2（#878）で最小限を実装した（`crates/microvm/src/guest_memory.rs`。単一領域・heap backing・コピー API・unsafe なし）。mmap backing と KVM への登録は引き続き #696（TASK-75.1）。複数領域は再評価条件に従う。

## /dev/kvm を要する試験の分離

`crates/microvm/tests/kvm_device.rs` の実機前提の試験（各アーキテクチャで計 4 件）は `#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]` で既定のテスト集合から分離済みで、実行コマンド・必要環境・恒常ルールは AGENTS.md「実機前提テスト」の `kvm_device` の項に置く。KVM を使わない論理（アクセス型・virtqueue のパース）は heap の backing で既定のテスト集合に置き、実機前提へ移さない（ci.md「実機前提テスト」）。

## 再評価条件

- #696 で backing がコピー API を volatile で満たせないと分かったとき
- 複数領域（MMIO hole など）の扱いで API を変える必要が出たとき
- TASK-117 で plugin 境界をまたいでゲストメモリを渡す要求が出たとき

関連: MVM-1・MVM-4・TASK-74・TASK-75・REPAIR-1・REPAIR-2・REPAIR-3・ERR-1。
