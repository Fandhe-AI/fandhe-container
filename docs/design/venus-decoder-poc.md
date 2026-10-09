# Venus デコーダ最小サブセット PoC（設計ドラフト）

macOS の virtio-gpu Venus 自前実装（ヘッドレス Vulkan compute のみ）で、最小 venus デコーダが扱う Vulkan コマンドの候補を記録する（GPU-6）。TASK-172 全体の PoC 文書で、本版は候補抽出（TASK-172.1）・wire パース骨格（TASK-172.2）・記録と再生ハーネス（TASK-172.5）・capset 応答（TASK-172.3）・試験治具 VMM の選定と capset アダプタ（TASK-172.4）・VZCustomVirtioDevice 登録可否確認ハーネス（TASK-172.6）の章を埋める。

> **位置づけ**: 本書はドラフトであり、候補を列挙するだけで対象サブセットを確定しない。最終確定は #726（TASK-172.h2。人間担当）で行う。優先度（必須・推奨・保留）は抽出時点の見立てで、確定扱いにしない。

- 対象ビヘイビア: GPU-6（関連: MAC-5・MVM-4）
- タスク: TASK-172（MS-13・G-別枠）。本版は TASK-172.1（#722。親 #721）・TASK-172.2（#723）・TASK-172.3（#724）・TASK-172.4（#888）・TASK-172.6（#1056）。前提 TASK-7（#25。完了済み）
- 後続・関連: #723（wire パース骨格）・#724（capset 応答。実装済み）・#889（コマンドストリーム記録）・#888（試験治具。アダプタまで実装済み・トランスポート未実装）・#725（1〜3 段目の結果）・#726（確定）・#776 / #777（対象範囲判断・工数再確定）・#781（サブセットのフィルタ機構）。ディスパッチ・ハンドラ群は TASK-177.x（#765・#769・#771・#773・#774）
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

## 8. capset 応答（TASK-172.3・#724）

実装は `crates/plugin-macos/src/gpu/venus/capset.rs`（`capset_info`・`respond_capset_query`）。PoC-14 で既存 OSS 構成が venus capset（id 4）を `max-size=0` で返し、ゲストの Mesa venus が物理デバイス 0 件と判定した問題への対処として、`max_size` が 0 でない（160）応答を返す最小実装を置いた。トランスポート非依存で、virtio-gpu の ctrl 枠は TASK-175 のデバイスモデルが包む。疎通の成否は #725 で確認する。本章は実装の存在のみを示す。

- 出典（確認日 2026-10-09。値のみ転記。SHA-256 は全件を計画フェーズで上流から再取得して照合）:
  - virglrenderer `virglrenderer-1.1.0` の `src/venus_hw.h`（`7bc1a8195294d681f4081719e7c4dfea396765e82b5583a2471fad9705aab64e`）
  - mesa `mesa-25.0.0` の `src/virtio/virtio-gpu/venus_hw.h`（`fa736817518a9c94bf50788a404cae8282987e2e82bcee6436370b2cc6a5988b`）: `vk_extension_mask1` の bit 0 の意味もここ
  - mesa `mesa-25.0.0` の `src/virtio/vulkan/vn_renderer_virtgpu.c`（`a7a0f1a395d006bfb1ef4aea4d3b2c6a44c30c50ede855416e1183442e1e03aa`）
  - mesa `mesa-25.0.0` の `src/virtio/vulkan/vn_instance.c`（`b8d3461d9a8b8d740d7c383100ac972e256263d9bd55e663be31f709c4e838a9`）: ゲストの受理条件
  - venus-protocol `v1.1.3` の `xmls/VK_EXT_command_serialization.xml`（`2451e5dcc5306f604c52da48a8cc883a24de708dd86f38bbb035d29a753a0474`）: 拡張番号 384・spec version 1
  - venus-protocol `v1.1.3` の `xmls/VK_MESA_venus_protocol.xml`（`d92839bc728fa9ad9a7decdc6b91df6fa1a0fb26cffae4009865f18a789e0535`）: 拡張番号 385・spec version 4
  - venus-protocol `v1.1.3` の `xmls/vk.xml`（`264d0d7350e37d70c82407fb430d085040fc01a9a961d43dec8c2d6ed1dfd183`）: `VK_HEADER_VERSION`（357）だけを取った。venus の 2 拡張は含まれない
  - ライセンス・著作権表記は `capset.rs` のモジュール doc に記載（転記はフィールド名・並び・数値定数のみ。NOTICE は作らない）
- レイアウト（全て `u32` リトルエンディアン、計 160 バイト）:

| offset | フィールド | 広告値 |
| ------ | ---------- | ------ |
| 0 | `wire_format_version` | 1（Mesa が完全一致を要求） |
| 4 | `vk_xml_version` | `VK_MAKE_API_VERSION(0,1,4,357)` = `0x0040_4165`（ゲスト側で上限クランプ） |
| 8 | `vk_ext_command_serialization_spec_version` | 1 |
| 12 | `vk_mesa_venus_protocol_spec_version` | 4（ゲスト側で上限クランプ） |
| 16 | `supports_blob_id_0` | 1（Mesa は `assert` で非 0 を前提。release ビルドでは無検査） |
| 20〜147 | `vk_extension_mask1[32]` | `[0]` = 0x1（マスク有効）、`[12]` = 0x3（拡張 384・385）、他 0 |
| 148 | `allow_vk_wait_syncs` | 1（Mesa は `assert` で非 0 を前提。release ビルドでは無検査） |
| 152 | `supports_multiple_timelines` | 1（Mesa は `assert` で非 0 を前提。release ビルドでは無検査） |
| 156 | `use_guest_vram` | 0 |

- 上表の `assert` の根拠は `vn_renderer_virtgpu.c` の 1394（`supports_blob_id_0`）・1402（`allow_vk_wait_syncs`）・1404（`supports_multiple_timelines`）・1456 行。release ビルドでは検査されないため、0 を返してもゲストが即座に拒否するとは限らない
- ゲスト（Mesa 25.0.0）の受理条件: capset id 4・version 0 で要求する。`wire_format_version` の完全一致必須・`vk_xml_version` の上限クランプ・最小版（Vulkan 1.1）未満の拒否は `vn_instance.c` の 165〜184 行。拡張マスクは `venus_hw.h` のコメントどおり bit 0 が立っていないと「全拡張対応」とみなされるため、最小集合を明示した（fail-closed）
- エラー方針: id 4・version 0・index 0 以外は `venus_capset.*` のエラーで拒否する（`VenusCapsetError`）
- 先送り・未決事項（値は暫定で確定扱いにしない）:
  - protocol spec version 4 を広告すると v3・v4 のコマンドがゲストから発行されうる（3 章では保留扱い）。下げるかは #725 の実ストリームと #726 で判断
  - 拡張マスクを最小にしてゲストの物理デバイス列挙が通るかは未確認（#725）。デバイス拡張の広告は #726・TASK-176
  - `use_guest_vram` は VMM の共有メモリ方式に依存し、3 段目（#1057）の判定まで未決
  - flag 3 件を 1 にするのは対応機能（blob id 0・待機系コマンド・複数タイムライン。TASK-176・177）を後続が実装する前提の宣言で、現時点では未実装（REPAIR-3）

## 9. VZCustomVirtioDevice 登録可否確認ハーネス（TASK-172.6・#1056）

macOS 27 の `VZCustomVirtioDevice` で、VENUS capset のみ・scanout なしの最小 virtio-gpu を TASK-64（#350。完了済み）の最小 VM に登録できるかの確認ハーネス（GPU-6・MAC-5）。配置は `poc/vz-custom-virtio-gpu/`（製品 crate 外・workspace 外）。判定は #1057（TASK-172.h5。人間担当）。

- 実装したもの: ゲスト側確認スクリプト `poc/vz-custom-virtio-gpu/guest/check-virtio-gpu.sh`（dmesg の virtio_gpu 行から probe・feature・KMS・capset・host memory window を判定）、自己テスト（合成 fixture。`make vz-virtio-gpu-guest-check-selftest`。CI の `integration-test` ジョブが 3 OS で実行）、README（デバイス契約・実機手順）
- **ホスト側のデバイス登録コードは未実装（REPAIR-3）**。計画フェーズの調査（確認日 2026-10-08）で、受け入れ条件の「新規依存・`unsafe` が要る場合は止めて承認事項として報告」に当たったため
- 調査結果:
  - 採用済み `objc2-virtualization =0.3.2`（承認 #356）は `VZCustomVirtioDevice`・`VZVirtioQueue`・`VZVirtioSharedMemoryRegion*` を含まない。crates.io の最新も 0.3.2（2025-10-04）で、macOS 27 対応版は未リリース
  - upstream `madsmtm/objc2` main のコミット `b735fb4d6b9c`（2026-09-24「Update to Xcode 27.0 beta 1」）には対応 feature がある（生成コードは `madsmtm/objc2-generated`）。Xcode 27 beta 1 基準で、正式版で変わりうる
  - 生成バインディング上は `VZCustomVirtioDeviceConfiguration` に `deviceID`・`virtioQueueCount`・`mandatoryFeatures` / `optionalFeatures`・`deviceSpecificConfiguration`・`sharedMemoryRegions` があり、`VZVirtioSharedMemoryRegionConfiguration` は `initWithRegionID:size:`。API 上は共有メモリ領域を提示できる見込みだが実機では未確認
  - `deny.toml` の `[sources]` は `unknown-git = "deny"` で、git 依存は現設定では入れられない
  - ゲスト Linux driver は mainline で `num_scanouts == 0` を `KMS disabled` として受理する。古いカーネルは `num_scanouts is zero` で probe が失敗しうる（受理される版数は未確認）
- 承認事項（オーナー決定済み。ホスト側ハーネス本体は #1522〔sub-issue #1523・#1524〕で追跡）:
  - A. バインディングの入手経路。**決定: A1**（承認は #1521）。A1: macOS 27 対応の `objc2-virtualization` の crates.io リリースを待ち `=x.y.z` で更新（`objc2`・`objc2-foundation`・`block2`・`dispatch2` の連鎖更新を含む）。A2: 上記コミットを git 依存で固定（`deny.toml` の変更が要りサプライチェーン上非推奨）。A3: 自前 `extern_class!` / `define_class!`（`unsafe` の新規追加。セレクタ・型を macOS 27 SDK と照合する必要がある）
  - B. ホスト側ハーネスの配置（ルート `Cargo.toml` の `members` 追加・`exclude`・入れ子 workspace のいずれか。7 章の「配置の逸脱」と同じ論点）。**決定: `poc/` 配下の独立パッケージ**（ルート workspace の外。既存の `poc/vz-custom-virtio-gpu/`）
  - C. `unsafe` の扱い（delegate 実装と `unsafe fn` バインディング呼び出し。事前承認の範囲は `sys` モジュールで、PoC crate が対象かは不明確なため個別承認）。**決定: 実装時に個別承認**
  - D. 実行環境（macOS 27＋Xcode 27 SDK の Apple Silicon 実機。CI に macOS 27 ランナーは無く、ホスト側コードは CI でビルド検証できない見込み）。**決定: macOS 27＋Xcode 27 SDK の Apple Silicon 実機で人間が実行する**（#1057）
- 受け入れ条件の状態:

| 条件 | 状態 |
| ---- | ---- |
| 1. VENUS capset のみ・scanout なしの virtio-gpu をゲストが probe する | 実機前提で未確認（#1057）。ゲスト側確認スクリプトは用意済み |
| 2. host visible 共有メモリ領域を提示できる | API 上は提示できる見込み。ゲストで host visible が有効になるかは未確認（#1057） |
| 3. 新規依存・`unsafe` が要る場合は止めて報告 | ゲートに当たり停止。承認事項 A〜D はオーナー決定済み（上記）。本体は #1522 |

- 先送り: ホスト側の登録ハーネス本体（#1522 で追跡）、`num_scanouts=0` が古いカーネルで通らない場合の受け入れ条件見直し（#1057 へ申し送り）
- セキュリティ: host visible 共有メモリと virtqueue 経由の ctrl コマンドはゲストからの untrusted 入力。ホスト側実装時は security-auditor を必須とし、境界検査・サイズ上限・fail-closed（#723 の方針）を適用する

## 10. 試験治具 VMM と外部バックエンド接続（TASK-172.4・#888）

1 段目（GPU 付き Linux 実機）で、既存 OSS の VMM が持つ「virtio-gpu をプロセス外のバックエンドへ出す仕組み」に自前デコーダをつなぐための治具。実装は `poc/venus-decoder/jig/`（ルート workspace の外の独立 PoC パッケージ。確定 19 crate＋benches の crate 境界を変えないため。製品 crate は依存しない）。

### 10.1 本 PR の範囲と未達（実装済みを装わない。REPAIR-3）

- 実装済み: 候補比較（本章）、ctrl の `GET_CAPSET_INFO` / `GET_CAPSET` の復号・応答符号化・構造化ログ 1 行（`adapter`）、#1520 で `GET_DISPLAY_INFO`（scanout なし）・`CTX_CREATE`（venus の context_init）・`CTX_DESTROY` を追加（ctx 表は上限 64）、治具が広告する feature と config の定数（`device`）、ログ照合器と実機前提テストの枠（`log`・`tests/real_machine_capset_log.rs`）。socket は開かない
- 実装済み（F1.1・#1516）: vhost-user メッセージの codec（`vhost_user`。10.5）。virtqueue・セッションは未実装（F1.3・F1.4）
- 実装済み（F1.2・#1517）: `SCM_RIGHTS` の fd 送受信とゲストメモリの mmap のラッパー（`vhost_user::fd_passing` / `guest_memory`・`src/sys.rs`。Linux 限定。10.6）
- **受入基準 2（ゲストの Mesa venus の capset クエリが自前デコーダに届いたことをログで確認）は未達**。トランスポート（後続 F1）と実機実行（F3・#725。人間担当）が必要なため
- 後続（issue 起票は未実施・承認待ち）: F1 vhost-user トランスポート（メッセージ codec・fd 受け渡しと `mmap` の `sys` ラッパー・split virtqueue・kick / call。rust-vmm 系クレートは MVM-4 で使えないため自作）、F2 残りの ctrl 応答（10.4 節。`RESOURCE_CREATE_BLOB`・`SUBMIT_3D` 等）、F3 実機疎通（#725）
- CI: `make poc-venus-jig-check`（fmt-check・clippy・test）は CI の `rust-ci-default-features` ジョブが 3 OS で実行し、`crates/plugin-macos` 側の変更による治具の破損を検出する（実機前提テストは `#[ignore]` で分離済みで CI では走らない）

### 10.2 候補比較

計画フェーズの調査結果。出典タグとファイルは下記のとおりで、crosvm の CLI 構文・render server の capset 転送の有無は**未確認**（実装フェーズでは取得できなかった。F1 着手時に確認する）。

| 候補 | 外部バックエンド接続 | ゲストへ BLOB・CONTEXT_INIT が届くか | venus capset の扱い | ライセンス | 改変の要否 |
| ---- | -------------------- | ------------------------------------ | ------------------- | ---------- | ---------- |
| QEMU `vhost-user-gpu-pci`（`hw/display/vhost-user-gpu.c`。タグ `v10.1.0`） | vhost-user | 届かない（realize が立てるのは VIRGL・EDID・RESOURCE_UUID のみ） | Mesa が capset 取得前に中止するため到達しない | GPL-2.0 | 標準では不適 |
| QEMU 汎用 `vhost-user-device(-pci)`（`hw/virtio/vhost-user-base.c`） | vhost-user。バックエンドの feature を素通し | 届く | バックエンド次第 | GPL-2.0 | 必要（`user_creatable = false` のため標準ビルドでは `-device` で作れない） |
| crosvm vhost-user frontend（`devices/src/virtio/vhost_user_frontend/mod.rs`。コミット `044c3e3fc53d`） | vhost-user。GPU 向け共有メモリ領域（SHMEM）にも対応 | 届く（デバイス固有 feature とバックエンド feature の積） | バックエンド次第 | BSD-3-Clause | 不要の見込み（`--vhost-user` の CLI 構文と最小カーネル版数は未確認） |
| virglrenderer の render server（`virgl_render_server`） | virglrenderer 利用側が必要。単体では VMM ではない | VMM 次第 | capset を server へ転送するか未確認 | MIT | — |
| Cloud Hypervisor・Firecracker | — | — | — | — | 比較対象外（GPU デバイスを持たず、依存・流用は禁止。dependency-policy） |

決め手: Mesa venus（`mesa-25.0.0` の `src/virtio/vulkan/vn_renderer_virtgpu.c`。`required_params`）は capset 取得より前に 3D 機能・`CAPSET_QUERY_FIX`・`RESOURCE_BLOB`・`CONTEXT_INIT` を必須として検査し、欠けると初期化を中止する。治具 VMM がゲストへ `VIRGL`・`RESOURCE_BLOB`・`CONTEXT_INIT` を見せられることが capset クエリ発行の前提になる。

選定（暫定）: **crosvm の vhost-user frontend**。BSD-3-Clause で改変不要の見込みであり、feature が素通しされる。QEMU を使う場合は GPL の VMM バイナリを外部プロセスとして実行するだけでリンクせず、汎用デバイスの有効化には GPL の改変ビルドが要る。この扱いは**要確認（ユーザー判断。licensing.md）**。`use_guest_vram`（8 章）は選定した VMM の共有メモリ方式に従属し、3 段目（#1057）まで未決。

### 10.3 ctrl の値と広告 feature

出典: Linux `include/uapi/linux/virtio_gpu.h` タグ `v6.12`（確認日 2026-10-08。SHA-256 `7c9e2f7d47fa0b1a2c737fc5a741f57c5cf25303dd5c68c2c9738e9bb761eee6`）。値のみ転記。

| 項目 | 値 |
| ---- | -- |
| `virtio_gpu_ctrl_hdr` | 24 バイト（type・flags・fence_id・ctx_id・ring_idx・padding[3]） |
| `GET_CAPSET_INFO` / `OK_CAPSET_INFO` | 0x0108（capset_index・padding）/ 0x1102（capset_id・max_version・max_size・padding） |
| `GET_CAPSET` / `OK_CAPSET` | 0x0109（capset_id・capset_version）/ 0x1103（capset データ 160 バイト） |
| エラー | `ERR_UNSPEC` 0x1200（未知の種別）・`ERR_INVALID_PARAMETER` 0x1205（長さ・値の不正） |
| fence | `FLAG_FENCE` が立つ要求では応答ヘッダへ flags・fence_id・ctx_id・ring_idx を引き継ぐ |
| 広告 feature | VIRGL（bit 0）・RESOURCE_BLOB（3）・CONTEXT_INIT（4）・VERSION_1（32）。`num_capsets` = 1、`num_scanouts` = 0（カーネルが 0 を受け付けるかは未確認。F1 の実機で確認） |

issue #1520（GPU-6・TASK-172 後続 F2）で追加した ctrl:

| 項目 | 値 |
| ---- | -- |
| `GET_DISPLAY_INFO` / `OK_DISPLAY_INFO` | 0x0100（ヘッダのみ 24 バイト）/ 0x1101（ヘッダ + `pmodes[16]`。1 件 24 バイト = rect 16 + enabled 4 + flags 4。全長 408）。全 scanout を無効（全 0）で返す |
| `CTX_CREATE` / `CTX_DESTROY` | 0x0200（ヘッダ + nlen 4 + context_init 4 + debug_name[64] = 96 バイト）/ 0x0201（ヘッダのみ）。成功は `OK_NODATA` 0x1100 |
| `context_init` | 下位 8 bit（`CAPSET_ID_MASK` 0x000000ff）が VENUS（4）のときだけ受理。上位 bit が立つ値・0・他 id は拒否 |
| 追加エラー | `ERR_OUT_OF_MEMORY` 0x1201（ctx 表が上限 64 件）・`ERR_INVALID_CONTEXT_ID` 0x1204（ctx_id 0・重複・未作成） |
| 割り当て | 要求長不正・capset id 違い・`nlen` > 64 は `ERR_INVALID_PARAMETER`。対象 ctx_id はヘッダの `ctx_id` |

ログ形式（数値と固定語彙のみ。ゲストのバイト列はエコーしない。`debug_name` は保持も出力もしない）:

- `venus_jig event=capset_query cmd=GET_CAPSET capset_id=4 version=0 result=ok max_size=160`
- `venus_jig event=display_info cmd=GET_DISPLAY_INFO num_scanouts=0 result=ok`
- `venus_jig event=ctx cmd=CTX_CREATE ctx_id=1 capset_id=4 nlen=5 result=ok`
- `venus_jig event=ctx cmd=CTX_DESTROY ctx_id=1 result=ok`

要求長はコマンドごとにちょうどの値のみ受理する（PoC。余剰バイトも拒否）。

### 10.4 未実装の ctrl（REPAIR-3）

Mesa venus が capset 取得の後に発行する ctrl の一次情報（`mesa-25.0.0` の `vn_renderer_virtgpu.c`）は**本 PR では未確認**。推測で確定させず、`virtio_gpu.h`（v6.12）上の 3D 系の候補だけを挙げる。いずれも**未実装（`ERR_UNSPEC`）**: `RESOURCE_CREATE_BLOB`（0x010c）・`RESOURCE_MAP_BLOB` / `UNMAP_BLOB`（0x0208 / 0x0209）・`CTX_ATTACH_RESOURCE` / `DETACH_RESOURCE`（0x0202 / 0x0203）・`SUBMIT_3D`（0x0207）・`RESOURCE_UNREF`（0x0102）。製品版の ctrl 枠は TASK-175.1.3（#915）・TASK-176.1（#749）。

### 10.5 vhost-user メッセージの値（F1.1・#1516）

出典（確認日 2026-10-09。転記したのは要求 ID・ビット値・フィールド配置という事実だけで、コードは流用していない。crosvm の `vmm_vhost` は rust-vmm の `vhost` 由来の系統のため構造体定義やロジックは写さない。MVM-4・from-scratch-policy）。

| 出典 | 版 | SHA-256 |
| ---- | -- | ------- |
| QEMU `docs/interop/vhost-user.rst` | タグ `v10.1.0` | `1c06e32a3306172499767170b0b64ce8de4a8a90cbe543a00cc1b3861ae5bccd` |
| crosvm `third_party/vmm_vhost/src/message.rs` | コミット `044c3e3fc53d` | `df6c31711167fe3b94080db4655826bb834cd2e9ac085915ce448652b8ab3495` |
| crosvm `third_party/vmm_vhost/src/backend_client.rs` | 同上 | `709fe08830a38c5e15a00c0c5af47ef7dabf19a784c0694abf8c10d335dec7c2` |
| crosvm `devices/src/virtio/vhost_user_frontend/mod.rs` | 同上 | `9506fcaae2e7e4aec09baa1374cbbd0a3807c5f38f8566b5c4f5856e4ea22266` |

前提（実際に広告するのは F1.4・#1519）: virtio feature は bit 30（`VHOST_USER_F_PROTOCOL_FEATURES`）を立て、protocol feature は CONFIG（bit 9。virtio-gpu config の読み出しに要る）と MQ（bit 0）だけにする。REPLY_ACK・BACKEND_REQ・SHMEM・DEVICE_STATE・CONFIGURE_MEM_SLOTS は host-visible 共有メモリの方式が決まる #1057 まで後送りで、追加する場合は対応する要求を codec に足す。

最小要求集合（16 種。QEMU と crosvm で ID が一致）。これ以外は既知 ID も含め `UNKNOWN_REQUEST` で拒否する。

| ID | 要求 | ペイロード |
| -- | ---- | ---------- |
| 1 / 15 / 17 | GET_FEATURES / GET_PROTOCOL_FEATURES / GET_QUEUE_NUM | なし（応答は u64 8 バイト） |
| 2 / 16 | SET_FEATURES / SET_PROTOCOL_FEATURES | u64（8 バイト） |
| 3 | SET_OWNER | なし |
| 5 | SET_MEM_TABLE | 8 + n × 32 バイト（num_regions u32・padding u32・領域 n 個） |
| 8 / 10 / 11 / 18 | SET_VRING_NUM / SET_VRING_BASE / GET_VRING_BASE / SET_VRING_ENABLE | vring state 8 バイト（index u32・num u32）。GET_VRING_BASE の応答も同形 |
| 9 | SET_VRING_ADDR | 40 バイト（index・flags 各 u32、descriptor・used・available・log 各 u64） |
| 12 / 13 | SET_VRING_KICK / SET_VRING_CALL | u64（bit 0-7 が vring index、bit 8 が NOFD。bit 9 以上は拒否） |
| 24 / 25 | GET_CONFIG / SET_CONFIG | 12 + size バイト（offset・size・flags 各 u32 + データ）。GET_CONFIG は要求側もデータ領域を含む |

ヘッダは 12 バイト（request・flags・size の各 u32）。flags の下位 2 ビットが version（1）、bit 2 が REPLY、bit 3 が NEED_REPLY で、他は予約。バイト順は rst 上「ホストのネイティブ順」で、治具の動作環境（Linux x86_64 / aarch64、CI の 3 OS）はすべて little-endian のため little-endian 固定とし、big-endian ターゲットは `compile_error!` にする。

上限と QEMU / crosvm の食い違いへの対応:

- `MAX_PAYLOAD_LEN` = 1032（32 領域）、ヘッダ込みの最大は 1044。size は確保・読み取りより前に検証する
- メモリ領域数は 1〜32。QEMU の rst は 8 だが crosvm は最大 32（0 は拒否）なので、crosvm の正当な要求を拒否しないよう大きい方に揃える
- config データは治具独自の上限 256 バイト（`virtio_gpu_config` は 16 バイト）。config の flags は crosvm のビット（`WRITABLE`=0x1・`LIVE_MIGRATION`=0x2）を受理し、他のビットは拒否する（QEMU の rst は値として 0 / 1 を定めるが、crosvm の GET_CONFIG は毎回 0x1 を送るため両方を受理できる形にした）
- 検査順は固定: `SHORT_HEADER` → `UNSUPPORTED_VERSION` → `INVALID_FLAGS`（予約ビット・方向） → `PAYLOAD_TOO_LARGE` → `UNKNOWN_REQUEST` → `LENGTH_MISMATCH` → `INVALID_VALUE`

F1.1 の範囲外（申し送り）: 値の意味の検証（vring addr のアラインメント・index < キュー数・log ビット・avail index）は F1.3（#1518）、ネゴシエーション済み feature との照合・セッション状態は F1.4（#1519）、fd・mmap・タイムアウト（REPAIR-5）は F1.2（#1517。10.6）で扱う。

### 10.6 fd の受け渡しと共有メモリ（F1.2・#1517）

frontend（crosvm 等）は UDS の補助データ（`SCM_RIGHTS`）でゲストメモリ領域の fd と eventfd を渡し、backend は `SET_MEM_TABLE` の領域を `mmap` して GPA 経由でアクセスする。rust-vmm 系は MVM-4 で使えないため自作し、crosvm の構造体やロジックは写していない。`unsafe` は `src/sys.rs` にだけ置く（個別承認: [#1517 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6074351741)。U1 `syscall` 宣言・U2 `recvmsg`・U3 受信 fd の所有・U4 `sendmsg`・U5 `memfd_create`・U6 `mmap`・U7 `Drop` の `munmap`・U8 境界検査後のコピー。レビュー指摘で U9 `fcntl`〔`F_GET_SEALS` / `F_ADD_SEALS`〕を `sys` モジュールの事前承認の範囲で追加）。

出典（確認日 2026-10-09。値だけを転記）: Linux UAPI ヘッダ（`linux-libc-dev`）の `asm-generic/socket.h`（SHA-256 `e833d32d3d8d03732021da6968665431d693ab4effdd4d39965ff05115a4ed21`）・`linux/socket.h`（`f4331fd201269894f63242a2521b3d5b3290ca556969011d7858908d5fe658c4`）・`asm-generic/mman-common.h`・`linux/memfd.h`、syscall 番号は `asm/unistd_64.h`（x86_64）と asm-generic `unistd.h`（aarch64）、man `recvmsg(2)`・`unix(7)`・`cmsg(3)`・`mmap(2)`・`memfd_create(2)`。

| 定数 | x86_64 | aarch64 |
| ---- | ------ | ------- |
| `sendmsg` / `recvmsg` | 46 / 47 | 211 / 212 |
| `mmap` / `munmap` | 9 / 11 | 222 / 215 |
| `memfd_create` | 319 | 279 |
| `fcntl` | 72 | 25 |
| `F_ADD_SEALS` / `F_GET_SEALS` / `F_SEAL_SHRINK` / `MFD_ALLOW_SEALING` | 1033 / 1034 / 0x2 / 0x2 | 同左（個別に定義） |
| `SOL_SOCKET` / `SCM_RIGHTS` | 1 / 1 | 1 / 1 |
| `MSG_CTRUNC` / `MSG_TRUNC` / `MSG_NOSIGNAL` / `MSG_CMSG_CLOEXEC` | 0x8 / 0x20 / 0x4000 / 0x4000_0000 | 同左（個別に定義） |

設計判断:

- `recvmsg` 等は `syscall(2)` 経由でカーネル ABI の `user_msghdr` / `cmsghdr` を直接使う（glibc / musl の `msghdr` のパディング差に依存しない）。`sysconf` は使わない。タイムアウト（REPAIR-5）は呼び出しごとの期限を持ち、`MSG_DONTWAIT` の `recvmsg` / `sendmsg` と `ppoll`（U10）で待つ（共有ソケットの `SO_RCVTIMEO` に依存しない）
- 受け取る fd は `MAX_FDS`（32）。受信した fd は検証より前にすべて `OwnedFd` にし、`MSG_CTRUNC`・上限超過・構造異常のどのエラー経路でも `Drop` で閉じる。`MSG_CMSG_CLOEXEC` で close-on-exec を原子的に付ける
- map は file offset 0 から `mmap_offset + memory_size` バイトを `MAP_SHARED` で行い、領域の先頭をマップ内の `mmap_offset` の位置として扱う（ページ境界にそろっていない `mmap_offset` でも `EINVAL` にしない）。QEMU `vhost-user.rst` の `mmap_offset` の定義との照合は未実施で、F1.4 の結合で確認する
- 上限は治具独自: 1 領域の map 長 64 GiB・合計 128 GiB。合計の上限は mmap より前に checked 演算で判定する（`INVALID_REGION`）。fd は `F_SEAL_SHRINK` が確認できなければ `SHRINK_NOT_SEALED` で拒否し（seal 非対応の fd も同様）、そのうえでファイル長が map 長に届かなければ `FILE_TOO_SHORT`。領域をまたぐアクセスは `OUT_OF_BOUNDS`（PoC の割り切り）
- マッピングへの参照は作らず、境界検査したコピーだけで出し入れする。`MmapRegion` は `!Send` / `!Sync`
- 縮小の封じ込め: frontend が後から `ftruncate` で縮めると `SIGBUS` になるため、`F_SEAL_SHRINK` つきの memfd だけを受け付ける。seal を付けない frontend は接続できない（PoC の割り切り。製品版の fd 要件は TASK-173 系で扱う）
- aarch64 の定数と構造体は CI で型検査されない（治具はルート workspace 外で `aarch64-linux-check` の対象外）。固定値テストも実行アーキの分しか走らない。ローカルでは `cargo check --target aarch64-unknown-linux-gnu --all-targets` の型検査のみ通した（実行は未検証）
- 範囲外: ヘッダ単位の読み書きの枠組み・セッション・UDS の bind と所有者・権限・peer credential の検証（PLUG-12 相当）・eventfd の待機は F1.4（#1519）、virtqueue と `userspace_addr` の変換は F1.3（#1518）

## 11. 以降の章（未着手。10 章は #888 の範囲）

| 章 | 内容 | 担当 issue |
| -- | ---- | ---------- |
| 1〜3 段目の結果 | 段階的な再検証の結果 | #725 |
| 3 段目の実機判定 | VZCustomVirtioDevice 登録の実機結果と VMM 方式の判定 | #1057（TASK-172.h5。人間担当） |
| 最終確定 | 対象サブセットの確定 | #726（TASK-172.h2。人間担当） |
