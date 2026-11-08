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
- `unsafe` は `crates/microvm/src/sys.rs`（Linux）・`src/sys/hvf.rs`（macOS。TASK-192.1・#3783）に閉じる（coding-rust の事前承認の範囲。SAFETY コメントと security-auditor 観点のレビューは #696 の PR で行う）
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

アクセス型を担当する issue が無かったため、TASK-74.2.2（#878）で最小限を実装した（`crates/microvm/src/guest_memory.rs`。単一領域・heap backing・コピー API・unsafe なし）。mmap backing と KVM への登録は引き続き #696（TASK-75.1）。複数領域は #3697 で実装した（本書末尾の記録）。

## /dev/kvm を要する試験の分離

`crates/microvm/tests/kvm_device.rs` の実機前提の試験（各アーキテクチャで計 4 件）は `#[ignore = "requires read/write access to /dev/kvm (MVM-1)"]` で既定のテスト集合から分離済みで、実行コマンド・必要環境・恒常ルールは docs/verification/real-machine-tests.mdの `kvm_device` の項に置く。KVM を使わない論理（アクセス型・virtqueue のパース）は heap の backing で既定のテスト集合に置き、実機前提へ移さない（ci.md「実機前提テスト」）。

## 再評価条件

- #696 で backing がコピー API を volatile で満たせないと分かったとき
- 複数領域（MMIO hole など）の扱いで API を変える必要が出たとき
- TASK-117 で plugin 境界をまたいでゲストメモリを渡す要求が出たとき

関連: MVM-1・MVM-4・TASK-74・TASK-75・REPAIR-1・REPAIR-2・REPAIR-3・ERR-1。

## TASK-75.1（#696）での実装記録

backing（匿名 mmap・`KVM_SET_USER_MEMORY_REGION` 登録・munmap と Drop の後始末）を `crates/microvm/src/microvm.rs`（安全な API）と `sys.rs`（`GuestRamMap`・登録 / 削除のラッパー）に実装した。アクセス型（`guest_memory.rs`）の API は変えていない（MVM-1）。

- mmap のフラグ: `MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE`（疎に使われるゲスト RAM が swap を予約しない。上限 `MAX_GUEST_RAM_BYTES` = 16 GiB で抑える）と `madvise(MADV_DONTFORK)`（fork 先へゲストメモリの内容を引き継がない）
- 寿命: `RegisteredGuestRam` は VM fd を dup して持つ（`'vm` の借用を持たない。後続の VM 構成体 #697 が自己参照にならないため）。drop は slot を削除してから munmap し、削除に失敗したら mapping を漏らす（fail-closed）
- 読み書き: 参照を作らず、範囲検査つきのバイト単位 volatile のみ。例外として virtqueue の共有 index（`avail.idx` の読み・`used.idx` の書き）だけは、2 バイト整列した u16 の単一命令 volatile（`read_u16_le_aligned` / `write_u16_le_aligned`。tear を避ける。#3862・MVM-1・MVM-5・REPAIR-3）。「単一命令」は言語仕様の保証ではなく x86_64・aarch64 の lowering に依る（`READ_ONCE` と同じ前提）。ring の要素・記述子・u32 以上には適用しない（要素は idx の前後の fence で順序づけられ、記述子は 1 回コピーして検査する）。`AtomicU16` は混在サイズのアクセスと参照の生成を招くため採らない。順序は引き続き fence と実機のバリアに頼る。性能（ブロック I/O のバッチ化）は後続の課題
- 置き換えなかったもの: #882 の自己診断用 `GuestPage` / `RegisteredPage` と `probe_*` は残している（置き換えは任意の後続作業）
- 範囲外: 複数領域・`KVM_CAP_NR_MEMSLOTS` の照会（どちらも #3697 で実装済み。本書末尾の記録）・hugepage・`KVM_MEM_READONLY` / `KVM_MEM_LOG_DIRTY_PAGES`

## TASK-192.4（#3787）での macOS の実装記録

backing と登録の所有先は `crates/microvm/src/hvf/memory.rs`（安全な API。`HvfGuestRam`・`RegisteredHvfRam`）と `src/sys/hvf.rs`（`HostMapping`・`GuestMapping` の mmap・`hv_vm_map` / `hv_vm_unmap`・volatile のコピー）。アクセス型（`guest_memory.rs`）の API は変えていない（MVM-5・MVM-1）。

- mmap のフラグ: `MAP_ANON | MAP_PRIVATE`（`MAP_NORESERVE`・`MADV_DONTFORK` は使わない）。RWX で `hv_vm_map` する
- 寿命: `RegisteredHvfRam<'vm>` は `&'vm HvVm` を借用するため `HvVm` より先に drop される。drop は `hv_vm_unmap` が成功したときだけ munmap し、失敗したら backing をリークする（fail-closed）。構成体（#3797）が `HvVm` をどう持つかはその issue の担当
- 読み書き: 参照を作らず、範囲検査つきのバイト単位 volatile のみ。例外として virtqueue の共有 index（`avail.idx` の読み・`used.idx` の書き）だけは、2 バイト整列した u16 の単一命令 volatile（`read_u16_le_aligned` / `write_u16_le_aligned`。tear を避ける。#3862・MVM-1・MVM-5・REPAIR-3）。「単一命令」は言語仕様の保証ではなく x86_64・aarch64 の lowering に依る（`READ_ONCE` と同じ前提）。ring の要素・記述子・u32 以上には適用しない（要素は idx の前後の fence で順序づけられ、記述子は 1 回コピーして検査する）。`AtomicU16` は混在サイズのアクセスと参照の生成を招くため採らない。順序は引き続き fence と実機のバリアに頼る
- IPA の上限: `register` が引数で受ける。既定値 `HVF_DEFAULT_IPA_LIMIT`（36 ビット）は macOS 27.2・Apple M4 Max の実機の既定と一致し、最大は 40 ビットだった（#3997。他の機種・版は未確認）
- 範囲外: 複数領域・`hv_vm_protect` の利用は対象外（#4023 の判断。本書末尾の記録）。`Sync` は不要（共有は `Arc<Mutex<..>>`。`Send` は #4024 で導入）。解除失敗の構造化ログは未実装

## #3697 での複数領域の実装記録（MVM-1・TASK-75.1 追補）

再評価条件の「複数領域（MMIO hole など）の扱いで API を変える必要が出たとき」に当たったため、アクセス型を複数領域に広げた。決め事は次のとおり。

- 領域の持ち方: `GuestMemory<B>` は同じ backing 型 `B` の領域の `Vec`（base の昇順・非重複・1 件以上 `MAX_GUEST_MEMORY_REGIONS` = 8 件以下）を持つ。`GuestMemory::new` は従来どおり 1 領域のコンストラクタで、複数領域は `from_regions`。0 件・件数超過・長さ 0・未ソート・重なり・桁あふれは `InvalidArgument`。隣接は登録できるが、またぐアクセスはできない
- アクセスの変換: GPA は `partition_point` で領域を探し、領域内の offset を checked 演算で求める。hole の中・どの領域よりも下・領域の終端をまたぐ範囲（隣接していても）は `"guest memory access out of range"`（ゲストが決める非信頼入力。別々の mapping をまたいで読み書きしない）
- 公開 API の変更（呼び出し元は crate 内だけ）: `GuestMemory::check_range` は offset を返さず `Result<(), _>` になった。`len()` は全領域の総バイト数、`base()` は最も低い領域の base。`regions()` が領域の記述子（`GuestMemoryRegion`）を返す。`boot_x86::plan_boot` は最後の引数が `mem_len` から領域の一覧になり、`BootPlan::e820` は `Vec` になった
- x86_64 の配置: `mem_size` のうち `X86_LOW_RAM_LIMIT`（= `VIRTIO_MMIO_BASE` = 0xd000_0000）までを GPA 0 から、超えた分を `X86_HIGH_RAM_BASE`（4 GiB）から置く。RAM は MMIO hole `[0xd000_0000, 4 GiB)`（virtio-mmio・IOAPIC・LAPIC・identity map・TSS）に入らない。RAM と MMIO の窓の重なりは `check_occupied_disjoint` が ioctl の前に拒否する（以前は `mem_size <= VIRTIO_MMIO_BASE` で暗に保証していた）。総量の上限は `MAX_GUEST_RAM_BYTES`（16 GiB）のまま
- 登録: 領域 i を slot i の別の memslot で登録する（`register_ram_regions`）。`KVM_CHECK_EXTENSION(KVM_CAP_NR_MEMSLOTS)`（`VmFd::max_user_memslots`。x86_64 は 32764）を mmap の前に照会し、足りなければ `ResourceExhausted`、照会できない・0 以下なら `FailedPrecondition`（fail-closed）。途中で失敗したときは登録済みの領域が drop され、slot の削除と munmap が済む（削除に失敗した領域は従来どおり漏らす）。aarch64 の RAM は hole が無いため 1 領域のまま同じ経路を通る。macOS（HVF）は 1 領域のまま
- e820 との一致: 先頭の領域（GPA 0 から）が従来の 3 本（RAM・MP テーブルの予約・RAM）、2 番目以降が RAM 1 本ずつ。カーネル・initrd・boot_params・SIPI のページは先頭の領域の中にだけ置く。`check_loaded_within` と SIPI の範囲検査は総バイト数ではなく先頭の領域の長さで行い、hole を挟んでも SEC-1 の検査を緩めない
- 挙動の変化: x86_64 で 3.25 GiB（`VIRTIO_MMIO_BASE`）を超える `mem_size` が受理されるようになった（以前は拒否）
- 範囲外（REPAIR-3）: hugepage・`KVM_MEM_READONLY` / `KVM_MEM_LOG_DIRTY_PAGES`（必要になった時点で別に扱う）。ゲストの物理アドレス幅と最上位 GPA の照合・e820 の予約表記は #4106 で実装済み（本書末尾の記録）。実カーネルを 4 GiB 超の RAM で起動し `/proc/meminfo` で確かめる通し試験。macOS（HVF）の複数領域は対象外（#4023 の判断。本書末尾の記録）
- 試験: KVM を使わない部分は既定のテスト集合の `mvm1_3697_*`。実 KVM は `crates/microvm/tests/kvm_device.rs` の `kvm_device_assemble_microvm_high_memory`（実機前提。`docs/verification/real-machine-tests.md`）

## #4024 での `Send` の導入記録（MVM-5・MVM-1・SEC-1）

- `HostMapping`（`crates/microvm/src/sys/hvf.rs`）に `unsafe impl Send` を 1 件だけ足した。`Sync` は足さない（`&HostMapping` の共有は型で禁じ、共有は `Arc<Mutex<..>>`）。個別承認は [#4022 の判断コメント](https://github.com/Fandhe-AI/fandhe-container/issues/4022#issuecomment-6690213069)（案 A）の 1 件に限る
- 自動で `Send` になる型: `GuestMapping`・`RegisteredHvfRam`・`GuestMemory<RegisteredHvfRam<'static>>`。固定は `sys/hvf.rs` の const assert（`Sync` は E0283 の曖昧性ガード）と `hvf/memory.rs` の const assert
- 残り（`ExitHandlers` への受け渡し・QueueNotify の配線・期限切れ後の回収）は #3908

## #4023・#4033 での macOS（HVF）の複数領域と `hv_vm_protect` の判断記録（MVM-5・MVM-1・REPAIR-3）

本節はオーナー決定（2026-11-07。[#4023 の判断コメント](https://github.com/Fandhe-AI/fandhe-container/issues/4023#issuecomment-6690214055)）の記録であり、冒頭の「Agent が記録した判断」の位置づけの対象外。

- 決定: macOS（HVF）の複数領域と `hv_vm_protect` の利用は対象外
- 根拠:
  - ゲスト RAM は `ARM64_RAM_BASE` 以上の単一領域で、GIC・serial・virtio-mmio の窓はすべて RAM の基底より下にある（`arm64_layout.rs` の const assert）。RAM の中に穴は無い
  - `hvf/memory.rs` の登録は全域を `MemoryFlags::RWX` で `hv_vm_map` するのみで、`GuestMapping::protect` の製品コードからの呼び出しは無い
  - spec の MVM-5・MVM-1 に要件が無い
- 帰結: ゲスト RAM は RWX のままホスト側で保護を変えない。ホスト側の防御は、参照を外へ出さないコピー API と範囲検査（`hvf/memory.rs` のモジュール doc）に置く
- 再評価条件: (1) RAM の中に MMIO の穴が要るとき、(2) 読み取り専用の領域が要るとき
- 再評価時の土台: OS 非依存の `GuestMemory::from_regions`（#3697）と `sys/hvf.rs` の `GuestMapping::protect` は既にある。足りないのは HVF 側で複数の対応付けを登録する配線と、保護の変更を呼ぶ経路
- #3908 との対応: 未実装事項のうち「複数領域・`hv_vm_protect`」は本記録で閉じる。残り（`ExitHandlers` への受け渡し・QueueNotify の配線・期限切れ後の回収は #4032 で実装済み〔実機未確認 #4034〕等）は #3908 の分解表の各 issue が担う

## #4106 での物理アドレス幅の照合と e820 の予約表記の記録（MVM-1・REPAIR-3・SEC-1）

Agent が記録した判断（オーナー承認待ちの位置づけは冒頭と同じ）。

- 照合（x86_64 KVM のみ）: `MicroVm::assemble` は `create_vm` の前に `KVM_GET_SUPPORTED_CPUID` を取得し、`CpuidTable::physical_address_bits()`（leaf 0x8000_0008・subleaf 0 の EAX\[7:0\]）と最上位 GPA の終端を `check_physical_address_width` で照合する。収まらなければ `FailedPrecondition`（構成ではなくホストの能力に依存する失敗。`KVM_CAP_IOEVENTFD` 欠如と同じ扱い）。VM fd・memslot・mmap は 1 つも作られない
- 最上位 GPA: `system_regions` の出力（occupied と reserved の両方）の `end` の最大値。RAM の最後の領域だけで決めないので、将来 4 GiB 超にデバイスの窓を置いても自動で対象に入る。最大構成（16 GiB）では 0x4_3000_0000 で、34 bit は拒否・35 bit は通る
- fail-closed: leaf が無い・値が 0・52（x86-64 のアーキテクチャ上限）超は `FailedPrecondition`。SDM の「leaf が無ければ 36 bit とみなす」フォールバックは使わない。シフトは `checked_shl`。message に幅・アドレスは載せない（ERR-1）
- ベースの表で 1 回照合すれば足りる: `for_vcpu` は leaf 1・0xB・0x1F しか書き換えず、leaf 0x8000_0008 はゲストが見る値と同じ（`mvm1_4106_for_vcpu_keeps_address_width_leaf` で固定）
- e820 の予約表記（載せる）: `system_regions` の RAM 以外の領域（使用中の virtio-mmio の窓・IOAPIC・LAPIC・identity map・TSS）を 1 対 1 で type 2 として載せる（`e820_reservations` → `plan_boot` の `E820Reservation`）。領域の一覧と e820 の出どころが 1 つなので一致が機械的に保たれる。`plan_boot` は addr の昇順に整列し、size 0・溢れ・RAM / MP テーブルの予約 / 予約どうしの重なり・合計が `E820_MAX`（128）超を `InvalidArgument` で拒否する（最悪でも約 16 件。const assert で固定）
- 却下案: (1) hole 全体 `[0xd000_0000, 4 GiB)` を 1 本の reserved にする案。32 bit の範囲に未使用の隙間が無くなり、カーネルが PCI の隙間を探す処理に影響しうることと、「領域の一覧と一致」の単一の出どころから外れることが理由（カーネル側の挙動は `arch/x86/kernel/e820.c` の原文を未確認のため、影響は推測にとどまる）。(2) 36 bit フォールバック（上記）
- 一次情報の確認状況: Intel SDM の leaf 0x8000_0008 の EAX\[7:0\] が MAXPHYADDR である点を前提にした。Linux の `arch/x86/kvm/cpuid.c`・`arch/x86/kernel/cpu/common.c` と EAX\[23:16\]（AMD の GuestPhysAddrSize）の扱いは今回原文で確認していない（未確認）。EAX\[23:16\] は未考慮（EAX\[7:0\] のみ参照）
- 範囲外（REPAIR-3）: aarch64 の IPA サイズ（`KVM_CAP_ARM_VM_IPA_SIZE`）の照合、macOS（HVF。単一領域で e820 が無い）、SIPI ページの e820 予約、実カーネルでの e820 の予約と 4 GiB 超の RAM の `/proc/iomem`・`/proc/meminfo` での通し確認（実機前提。`tests/kernel_boot.rs` の `--ignored`。追跡 issue: #4194）
- 再評価条件: 4 GiB 超にデバイスの窓を置くとき、PCI を導入するとき、ゲストが予約の範囲で不具合を示したとき
- 試験: 既定のテスト集合の `mvm1_4106_*`（cpuid_x86・boot_x86・microvm の各 tests）
