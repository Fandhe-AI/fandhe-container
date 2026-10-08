# Venus デコーダ最小サブセット PoC（設計ドラフト）

macOS の virtio-gpu Venus 自前実装（ヘッドレス Vulkan compute のみ）で、最小 venus デコーダが扱う Vulkan コマンドの候補を記録する（GPU-6）。TASK-172 全体の PoC 文書で、本版は候補抽出（TASK-172.1）・wire パース骨格（TASK-172.2）・記録と再生ハーネス（TASK-172.5）の章を埋める。

> **位置づけ**: 本書はドラフトであり、候補を列挙するだけで対象サブセットを確定しない。最終確定は #726（TASK-172.h2。人間担当）で行う。優先度（必須・推奨・保留）は抽出時点の見立てで、確定扱いにしない。

- 対象ビヘイビア: GPU-6（関連: MAC-5・MVM-4）
- タスク: TASK-172（MS-13・G-別枠）。本版は TASK-172.1（#722。親 #721）と TASK-172.2（#723）。前提 TASK-7（#25。完了済み）
- 後続・関連: #723（wire パース骨格）・#724（capset 応答）・#889（コマンドストリーム記録）・#725（1〜3 段目の結果）・#726（確定）・#776 / #777（対象範囲判断・工数再確定）・#781（サブセットのフィルタ機構）。ディスパッチ・ハンドラ群は TASK-177.x（#765・#769・#771・#773・#774）
- 出典（spec）: GPU-6・TASK-172・D-15・PoC-14（submodule リビジョン `984f8a2`）。作業環境で `docs/spec` を取得できなかったため、spec 本文は参照せず ID のみで辿れるようにしている
- 出典（外部。確認日 2026-10-08）:
  - Vulkan レジストリ `vk.xml`: KhronosGroup/Vulkan-Headers のタグ `vulkan-sdk-1.4.363.0`（`registry/vk.xml`。`VK_HEADER_VERSION` 363。SHA-256 `55ec60950cfb18c3575dcf5fd52741b2bb70eb1e466408f803a91049973ee6fb`）
  - venus 固有コマンド: virgl/venus-protocol（freedesktop.org の GitLab）のタグ `v1.1.3`（コミット `ca19b6358d7c`）の `xmls/VK_MESA_venus_protocol.xml`（SHA-256 `d92839bc728fa9ad9a7decdc6b91df6fa1a0fb26cffae4009865f18a789e0535`）
  - Mesa Venus ドキュメント（docs.mesa3d.org/drivers/venus.html）・MoltenVK Runtime User Guide（KhronosGroup/MoltenVK の `Docs/MoltenVK_Runtime_UserGuide.md`）

## 1. 前提と範囲

- 用途はヘッドレスの Vulkan compute のみ。2D スキャンアウトは対象外（GPU-6）
- ゲスト側ドライバは Mesa venus 専用。他のドライバ向けのプロトコルは扱わない（GPU-6）
- CUDA は対象外（本書は Vulkan のみ）
- ゲストから届くコマンドストリームは untrusted 入力として扱う。候補を最小に保つことが攻撃面の縮小になる。候補にないコマンドの受信は、黙って無視せずエラー応答する（fail-closed）方針を #723・#769 への申し送りとする
- Mesa のドキュメントによると、venus ホスト側は Vulkan 1.1 と `VK_KHR_external_memory_fd`（Linux）を要求する。本書の `*2` 系中心の構成はこの前提に沿う

## 2. 候補の抽出方法

推測の列挙にしないため、次の手順で導出した。

1. **基準ワークロードを定義**する。(a) 物理デバイス列挙と各種プロパティ取得（`vulkaninfo` 相当）、(b) 最小のヘッドレス compute（入力バッファ → compute dispatch → 出力バッファ → 読み戻し）、(c) バッファ・イメージ間の転送
2. ワークロードが発行するコマンドを列挙し、**`vk.xml` と突き合わせて**正確なコマンド名と導入元を確定する。導入元は `vk.xml` の `<feature>` / `<extension>` の `require` から機械的に引いた（`VK_BASE_VERSION_x_y`・`VK_COMPUTE_VERSION_x_y` は Vulkan x.y core の機能分割名で、表では `x.y` と略記する）。alias のみの名前は採用していない
3. **venus 固有コマンド**は `VK_MESA_venus_protocol.xml` から全件（18 件）を取り出し、同 XML の `SPEC_VERSION` コメントでプロトコル版（v1〜v4）を付した
4. 本書の全コマンド名（`vk*`）が、上記 2 つの XML のコマンド名集合に存在することを一時スクリプトで機械照合した（不一致 0 件）。XML とスクリプトはリポジトリに含めない
5. **MoltenVK 対応**: MoltenVK は Vulkan 1.4 の graphics / compute 実装を謳っており、2 段目で再生する core 1.0〜1.3 の compute・転送系は対応範囲に入る見込みである。ただしコマンド単位の対応状況は未確認で、断定しない（5 章）

## 3. 候補コマンド一覧

優先度の意味は次のとおり。

- **必須**: 基準ワークロードが必ず発行する
- **推奨**: 基準ワークロードの周辺で発行されうる、または互換上あると望ましい
- **保留**: 最小構成では不要と見込むが、実コマンドストリームの記録（#725・#889）の結果次第で昇格しうる

件数の集計（#777 の工数再確定の入力）:

| カテゴリ | 必須 | 推奨 | 保留 | 計 |
| -------- | ---- | ---- | ---- | -- |
| 1 プロトコル制御（venus 固有） | 7 | 2 | 9 | 18 |
| 2 インスタンス・物理デバイス | 11 | 1 | 1 | 13 |
| 3 デバイス・キュー | 6 | 1 | 1 | 8 |
| 4 メモリ | 6 | 0 | 4 | 10 |
| 5 バッファ・イメージ・サンプラ | 2 | 6 | 3 | 11 |
| 6 シェーダ・パイプライン・ディスクリプタ | 12 | 2 | 2 | 16 |
| 7 コマンドバッファ（記録・実行） | 11 | 3 | 2 | 16 |
| 8 転送 | 2 | 5 | 1 | 8 |
| 9 同期 | 5 | 2 | 9 | 16 |
| **合計** | **62** | **22** | **32** | **116** |

### 3.1 プロトコル制御（venus 固有）

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkSetReplyCommandStreamMESA`（MESA venus v1）<br>`vkSeekReplyCommandStreamMESA`（MESA venus v1）<br>`vkExecuteCommandStreamsMESA`（MESA venus v1）<br>`vkCreateRingMESA`（MESA venus v1）<br>`vkDestroyRingMESA`（MESA venus v1）<br>`vkNotifyRingMESA`（MESA venus v1）<br>`vkWriteRingExtraMESA`（MESA venus v1） | 全コマンドの入口。reply ストリームの設定と、コマンドストリームの実行・ring の生成/通知がないと他のコマンドが到達しない | wire パース骨格 #723 と ring 実装 #765 の対象 |
| 推奨 | `vkGetMemoryResourcePropertiesMESA`（MESA venus v1）<br>`vkResetFenceResourceMESA`（MESA venus v1） | リソース（blob）とメモリ・fence の対応づけ。ホスト可視メモリを使う構成で必要になる見込み | blob 経路の要否は未検証（要確認） |
| 保留 | `vkWaitSemaphoreResourceMESA`（MESA venus v1）<br>`vkImportSemaphoreResourceMESA`（MESA venus v1）<br>`vkSubmitVirtqueueSeqnoMESA`（MESA venus v1）<br>`vkWaitVirtqueueSeqnoMESA`（MESA venus v1）<br>`vkWaitRingSeqnoMESA`（MESA venus v1） | セマフォのリソース共有・virtqueue / ring の seqno 待ち。単一ゲスト・単一 ring の最小構成で不要かは未検証 | 1 段目の記録（#725・#889）で実際に現れるかを見て採否を決める |
| 保留 | `vkCopyImageToMemoryMESA`（MESA venus v3）<br>`vkCopyMemoryToImageMESA`（MESA venus v3）<br>`vkWriteSamplerDescriptorMESA`（MESA venus v4）<br>`vkWriteResourceDescriptorMESA`（MESA venus v4） | イメージ⇔メモリの直接コピーとディスクリプタの直接書き込み（プロトコル v3・v4 の最適化用）。最小構成では通常経路で代替できる見込み | ゲスト側 Mesa が発行するかは未検証（要確認） |

### 3.2 インスタンス・物理デバイス

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkEnumerateInstanceVersion`（1.1）<br>`vkEnumerateInstanceExtensionProperties`（1.0）<br>`vkCreateInstance`（1.0）<br>`vkDestroyInstance`（1.0）<br>`vkEnumeratePhysicalDevices`（1.0）<br>`vkEnumerateDeviceExtensionProperties`（1.0）<br>`vkGetPhysicalDeviceFeatures2`（1.1）<br>`vkGetPhysicalDeviceProperties2`（1.1）<br>`vkGetPhysicalDeviceQueueFamilyProperties2`（1.1）<br>`vkGetPhysicalDeviceMemoryProperties2`（1.1）<br>`vkGetPhysicalDeviceFormatProperties2`（1.1） | 基準ワークロード (a)。デバイス列挙とプロパティ取得（`vulkaninfo` 相当）。Mesa venus は Vulkan 1.1 以上を要求するため `*2` 系が主 | 後続 #769 |
| 推奨 | `vkGetPhysicalDeviceImageFormatProperties2`（1.1） | (b) のバッファ・イメージ作成前のフォーマット/用途の可否判定 | 後続 #769 |
| 保留 | `vkEnumeratePhysicalDeviceGroups`（1.1） | 複数物理デバイスのグループ化。単一デバイス前提の最小構成では不要 | デバイスグループは対象外とする案（要判断） |

### 3.3 デバイス・キュー

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCreateDevice`（1.0）<br>`vkDestroyDevice`（1.0）<br>`vkGetDeviceQueue2`（1.1）<br>`vkDeviceWaitIdle`（1.0）<br>`vkQueueWaitIdle`（1.0）<br>`vkQueueSubmit`（1.0） | 基準ワークロード (b)。論理デバイスとキューの取得、submit と完了待ち | 後続 #769 |
| 推奨 | `vkGetDeviceQueue`（1.0） | ゲストのローダ／アプリが 1.0 形式でキューを取得する場合の互換 | `vkGetDeviceQueue2` と重複。発行有無は 1 段目の記録で確認 |
| 保留 | `vkQueueSubmit2`（1.3） | Vulkan 1.3 の submit。timeline semaphore（同期カテゴリ）の採否と連動 | 採否は同期カテゴリと一括で判断 |

### 3.4 メモリ

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkAllocateMemory`（1.0）<br>`vkFreeMemory`（1.0）<br>`vkBindBufferMemory2`（1.1）<br>`vkBindImageMemory2`（1.1）<br>`vkGetBufferMemoryRequirements2`（1.1）<br>`vkGetImageMemoryRequirements2`（1.1） | 基準ワークロード (b)。バッファ・イメージ用メモリの確保・束縛と要件問い合わせ | 後続 #771 |
| 保留 | `vkMapMemory`（1.0）<br>`vkFlushMappedMemoryRanges`（1.0）<br>`vkInvalidateMappedMemoryRanges`（1.0） | ホスト可視メモリの読み戻し。venus ではゲスト側で blob をマップするため wire に載らない可能性がある | wire に載るかは未検証（要確認）。Mesa docs は vkMapMemory が実装依存の挙動に依存すると記す |
| 保留 | `vkGetDeviceBufferMemoryRequirements`（1.3） | デバイス作成情報からのバッファ要件問い合わせ（Vulkan 1.3）。作成前の見積りに使われうる | 発行有無は未検証 |

### 3.5 バッファ・イメージ・サンプラ

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCreateBuffer`（1.0）<br>`vkDestroyBuffer`（1.0） | 基準ワークロード (b)。入出力バッファ | 後続 #769 |
| 推奨 | `vkCreateBufferView`（1.0）<br>`vkDestroyBufferView`（1.0）<br>`vkCreateImage`（1.0）<br>`vkDestroyImage`（1.0）<br>`vkCreateImageView`（1.0）<br>`vkDestroyImageView`（1.0） | storage texel buffer・画像を扱う compute と転送 (c) | 画像対応の範囲は #726 で判断 |
| 保留 | `vkCreateSampler`（1.0）<br>`vkDestroySampler`（1.0）<br>`vkGetImageSubresourceLayout`（1.0） | サンプラ付き画像アクセスや tiling 依存のレイアウト取得。基準ワークロードの範囲外 | 採否は #726 |

### 3.6 シェーダ・パイプライン・ディスクリプタ

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCreateShaderModule`（1.0）<br>`vkDestroyShaderModule`（1.0）<br>`vkCreatePipelineLayout`（1.0）<br>`vkDestroyPipelineLayout`（1.0）<br>`vkCreateComputePipelines`（1.0）<br>`vkDestroyPipeline`（1.0）<br>`vkCreateDescriptorSetLayout`（1.0）<br>`vkDestroyDescriptorSetLayout`（1.0）<br>`vkCreateDescriptorPool`（1.0）<br>`vkDestroyDescriptorPool`（1.0）<br>`vkAllocateDescriptorSets`（1.0）<br>`vkUpdateDescriptorSets`（1.0） | 基準ワークロード (b)。compute シェーダ（SPIR-V）の登録、compute パイプライン、バッファ束縛 | 後続 #769。SPIR-V の受け渡しは untrusted 入力のため検証方針を #723 以降で定める |
| 推奨 | `vkResetDescriptorPool`（1.0）<br>`vkFreeDescriptorSets`（1.0） | ディスクリプタの再利用（プール単位のリセットと個別解放） | 後続 #769 |
| 保留 | `vkCreatePipelineCache`（1.0）<br>`vkDestroyPipelineCache`（1.0） | パイプラインキャッシュ。性能最適化用で機能上は不要 | 採否は #726 |

### 3.7 コマンドバッファ（記録・実行）

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCreateCommandPool`（1.0）<br>`vkDestroyCommandPool`（1.0）<br>`vkAllocateCommandBuffers`（1.0）<br>`vkFreeCommandBuffers`（1.0）<br>`vkBeginCommandBuffer`（1.0）<br>`vkEndCommandBuffer`（1.0）<br>`vkCmdBindPipeline`（1.0）<br>`vkCmdBindDescriptorSets`（1.0）<br>`vkCmdPushConstants`（1.0）<br>`vkCmdDispatch`（1.0）<br>`vkCmdPipelineBarrier`（1.0） | 基準ワークロード (b)。コマンドの記録と compute dispatch | 後続 #773 |
| 推奨 | `vkResetCommandBuffer`（1.0）<br>`vkResetCommandPool`（1.0）<br>`vkCmdDispatchIndirect`（1.0） | コマンドバッファ・プールの再利用と indirect dispatch | 後続 #773 |
| 保留 | `vkCmdPipelineBarrier2`（1.3）<br>`vkCmdDispatchBase`（1.1） | Vulkan 1.3 の同期 2 系のバリア・ベース指定 dispatch。`vkQueueSubmit2` と連動して採否を判断 | 採否は #726 |

### 3.8 転送

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCmdCopyBuffer`（1.0）<br>`vkCmdFillBuffer`（1.0） | 基準ワークロード (c)。バッファ間コピーとバッファのクリア | 後続 #773 |
| 推奨 | `vkCmdCopyImage`（1.0）<br>`vkCmdCopyBufferToImage`（1.0）<br>`vkCmdCopyImageToBuffer`（1.0）<br>`vkCmdUpdateBuffer`（1.0）<br>`vkCmdClearColorImage`（1.0） | 画像を扱う場合の転送・クリア、インライン更新 | 画像対応の範囲は #726 で判断 |
| 保留 | `vkCmdCopyBuffer2`（1.3） | Vulkan 1.3 の `*2` 系コピー。1.1 要件の venus では通常発行されない見込み | 発行有無は未検証 |

### 3.9 同期

| 優先度 | コマンド（導入元） | 必要理由 | 備考 |
| ------ | ------------------ | -------- | ---- |
| 必須 | `vkCreateFence`（1.0）<br>`vkDestroyFence`（1.0）<br>`vkWaitForFences`（1.0）<br>`vkResetFences`（1.0）<br>`vkGetFenceStatus`（1.0） | 基準ワークロード (b)。submit 完了の待機（fence） | 後続 #774 |
| 推奨 | `vkCreateSemaphore`（1.0）<br>`vkDestroySemaphore`（1.0） | キュー間・submit 間の依存（バイナリセマフォ） | 後続 #774 |
| 保留 | `vkWaitSemaphores`（1.2）<br>`vkSignalSemaphore`（1.2）<br>`vkGetSemaphoreCounterValue`（1.2）<br>`vkCreateEvent`（1.0）<br>`vkDestroyEvent`（1.0）<br>`vkCmdSetEvent`（1.0）<br>`vkCreateQueryPool`（1.0）<br>`vkDestroyQueryPool`（1.0）<br>`vkCmdWriteTimestamp`（1.0） | timeline semaphore（Vulkan 1.2）・event・query（timestamp）。最小構成では不要の見込み | 採否は #726・#776 |

## 4. 対象外とするコマンド群

GPU-6 の決定（ヘッドレス compute のみ・2D スキャンアウト非対応・venus 専用）に紐づけて、vk.xml 上の拡張名・機能群の単位で除外する。個々のコマンドは列挙しない。

| 除外群 | 例（拡張名・機能群） | 理由 |
| ------ | -------------------- | ---- |
| WSI（表示系） | `VK_KHR_surface`・`VK_KHR_swapchain`・`VK_KHR_display` | 2D スキャンアウト非対応（GPU-6） |
| グラフィックスパイプライン | graphics pipeline・render pass・framebuffer・draw 系・`VK_KHR_dynamic_rendering` | compute のみ（GPU-6） |
| ray tracing | `VK_KHR_acceleration_structure`・`VK_KHR_ray_tracing_pipeline` | 用途外 |
| video | `VK_KHR_video_*` | 用途外 |
| sparse リソース | sparse binding / residency 関連 | 最小構成に不要 |
| デバッグ・ツール拡張 | `VK_EXT_debug_utils`・`VK_EXT_debug_report` | 機能上不要。ゲストからの入力面を増やさない |
| 他ドライバ向けプロトコル | venus 以外の virtio-gpu 3D プロトコル | venus 専用（GPU-6） |

## 5. 未決事項・確定時の判断材料

判断は #726・#776（人間担当）で行い、本書では決めない。

- 「保留」優先度の採否（`vkQueueSubmit2`・timeline semaphore・event・query・サンプラ・パイプラインキャッシュ・メモリ map 系）
- 1 段目で記録する実コマンドストリーム（#725・#889）との差分で候補を増減する手順
- メモリ map（`vkMapMemory`）が wire に載るか、blob 経由でゲスト側に閉じるか（Mesa docs は実装依存の挙動に依存すると記す。未確認）
- venus 固有コマンドのうち保留・推奨としたもの（resource / seqno 系・v3・v4 の最適化系）が、ゲスト側 Mesa の実際の発行に含まれるか（未確認）
- MoltenVK のコマンド単位の対応状況（未確認）。特に compute シェーダが使う機能・拡張の可否
- 画像（image / image view / 画像転送）を compute の範囲に含めるか

## 6. wire パース骨格（TASK-172.2・#723）

実装は `crates/plugin-macos/src/gpu/venus/`（`fandhe_container_plugin_macos::gpu::venus`）。

- 確認した wire 規則（venus-protocol `v1.1.3`・コミット `ca19b6358d7c` の `docs/VK_EXT_command_serialization.txt`）: リトルエンディアン。コマンドは DW0 = `VkCommandTypeEXT`、DW1 = `VkCommandFlagsEXT`、DW2.. = 引数。長さは種別から暗黙に決まり、未知の種別は読み飛ばせない。ポインタ・配列は 64bit 件数＋値列で、末尾を 32bit にパディングする。ハンドルは 64bit。enum は `int32_t`。フラグで定義済みのビットは `VK_COMMAND_GENERATE_REPLY_BIT_EXT`（bit 0）のみ
- ID の出典: 同タグの `xmls/VK_EXT_command_serialization.xml`（SHA-256 `2451e5dcc5306f604c52da48a8cc883a24de708dd86f38bbb035d29a753a0474`）。`xmls/VK_MESA_venus_protocol.xml`（SHA-256 は前掲）の記載と一致することを確認した。3 章の候補 116 件（必須 62・推奨 22・保留 32）すべてについてコマンド名から ID を機械抽出し、欠落 0 件、ID 重複なしを確認した。同じ対応表をテスト（`task172_2_gpu6_candidate_table_matches_command_type`）で照合している
- パース済み: 境界検査つきカーソル（`WireReader`）、候補コマンド種別（`CommandType`）、フラグ（`CommandFlags`。定義外ビットは拒否）、ヘッダ（`parse_command_header`）、構造化エラー（`VenusWireError`。`venus_wire.*`）
- fail-closed: 候補外・未知の種別は `unsupported_command` でストリームを拒否する。配列件数は `MAX_ARRAY_LEN` で確保前に検証する
- 先送り: コマンドごとの引数パース・ディスパッチ（TASK-177.x: #765・#769・#771・#773・#774）、reply の符号化、ring、frame_loop／adapter への配線。優先度は確定扱いにしない

## 7. コマンドストリームの記録と再生ハーネス（TASK-172.5・#889）

実装は `crates/plugin-macos/src/gpu/venus/replay/`（`fandhe_container_plugin_macos::gpu::venus::replay`）。1 段目（GPU 付き Linux 実機＋治具 VMM）でゲストの Mesa venus が提出したバッファを保存し、2 段目（Apple Silicon Mac）で VMM なしに自前デコーダへ流し込むための道具（GPU-6。形式は REPAIR-2・REPAIR-12）。

- 記録単位: ゲストが 1 回に提出したコマンドストリームのバッファ 1 個。venus wire はコマンド長を持たず、引数パーサ（TASK-177.x）なしには境界を切れないため、長さはレコード側で持つ
- 形式（リトルエンディアン）:

| 部分 | フィールド | 長さ | 備考 |
| ---- | ---------- | ---- | ---- |
| ファイルヘッダ | magic `FCVNSREC` | 8 B | 不一致は拒否 |
| | format version | 2 B | 現行 1。未知は拒否 |
| | flags | 2 B | 現行 0 のみ許可 |
| | record_count | 4 B | 上限 65,536 |
| | header_crc | 4 B | CRC-32C（先行 16 B） |
| レコード（繰り返し） | kind | 1 B | 1 = ゲスト提出バッファ。他は未対応として拒否 |
| | 予約 | 3 B | 0 のみ許可 |
| | seqno | 4 B | 0 起点の連番 |
| | payload_len | 4 B | 上限 16 MiB |
| | payload | N B | |
| | checksum | 4 B | CRC-32C（kind から payload まで） |

- 保証範囲: `validate` が全レコードのチェックサム・seqno 連続・余剰バイト無しまで確認し、`ValidatedRecording` を返す。`replay` はこの型しか受け取らず、さらに全レコードの先頭がコマンドヘッダとして有効かを提出前に検査する。長さ・件数・ファイル全体長（256 MiB）は確保前に検証する。CRC-32C は偶発的な破損の検出用で、改ざん耐性はない（署名・ハッシュ照合は将来課題）
- 配置の逸脱: issue 記載の `poc/venus-decoder/replay/` ではなく既存骨格の隣に置いた。`poc/` は存在せず、新設には workspace メンバー追加（ルート `Cargo.toml` の変更）が要る。再生器は同モジュールの `parse_command_header` を直接使う
- 取り扱い: 実機で採取したストリームにはワークロード由来のデータが含まれうる。テストの fixture は合成データのみで、実ストリームはリポジトリにコミットしない
- **未達（実装済みを装わない。REPAIR-3）**: 受け入れ条件「lavapipe 上で記録を再生し、最小 compute の結果が記録時と一致する」は本書時点で未達。理由は (1) コマンド引数のパース・Vulkan ディスパッチが未実装（TASK-177.x）、(2) lavapipe 実行に Vulkan バインディング（外部クレートまたは自前 FFI。依存追加・`unsafe` の承認が必要）が要る、(3) 実ストリームの採取は #725（人間担当）。再生先は `ReplayBackend` トレイトの差し替え点として定義し、`CollectingBackend`（提出内容を保持する模擬）でのみ検証している
- 先送り: reply ストリーム・期待出力レコード（kind の番号のみ未割当）、実機側の記録フック配線（#888・#725）

## 8. 以降の章（未着手）

| 章 | 内容 | 担当 issue |
| -- | ---- | ---------- |
| capset 応答 | venus capset の応答仕様 | #724 |
| 1〜3 段目の結果 | 段階的な再検証の結果 | #725 |
| 最終確定 | 対象サブセットの確定 | #726（TASK-172.h2。人間担当） |
