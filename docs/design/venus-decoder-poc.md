# Venus デコーダ最小サブセット PoC（設計ドラフト）

macOS の virtio-gpu Venus 自前実装（ヘッドレス Vulkan compute のみ）で、最小 venus デコーダが扱う Vulkan コマンドの候補を記録する（GPU-6）。TASK-172 全体の PoC 文書で、本版は候補抽出（TASK-172.1）・wire パース骨格（TASK-172.2）・記録と再生ハーネス（TASK-172.5）・capset 応答（TASK-172.3）・試験治具 VMM の選定と capset アダプタ（TASK-172.4）・VZCustomVirtioDevice 登録可否確認ハーネス（TASK-172.6）の章を埋める。

> **位置づけ**: 本書はドラフトであり、候補を列挙するだけで対象サブセットを確定しない。最終確定は #726（TASK-172.h2。人間担当）で行う。優先度（必須・推奨・保留）は抽出時点の見立てで、確定扱いにしない。

- 対象ビヘイビア: GPU-6（関連: MAC-5・MVM-4）
- タスク: TASK-172（MS-13・G-別枠）。本版は TASK-172.1（#722。親 #721）・TASK-172.2（#723）・TASK-172.3（#724）・TASK-172.4（#888）・TASK-172.6（#1056）。前提 TASK-7（#25。完了済み）
- 後続・関連: #723（wire パース骨格）・#724（capset 応答。実装済み）・#889（コマンドストリーム記録）・#888（試験治具。アダプタまで実装済み・トランスポート未実装）・#725（1〜3 段目の結果）・#726（確定）・#776 / #777（対象範囲判断・工数再確定）・#781（サブセットのフィルタ機構）。ディスパッチ・ハンドラ群は TASK-177.x（#765・#769・#771・#773・#774）
- 出典（spec）: GPU-6・TASK-172・D-15・PoC-14（submodule リビジョン `984f8a2`）。作業環境で `docs/spec` を取得できなかったため、spec 本文は参照せず ID のみで辿れるようにしている
- 出典（外部。確認日 2026-10-08）:
  - Vulkan レジストリ `vk.xml`: KhronosGroup/Vulkan-Headers のタグ `vulkan-sdk-1.4.363.0`（`registry/vk.xml`。`VK_HEADER_VERSION` 363。SHA-256 `55ec60950cfb18c3575dcf5fd52741b2bb70eb1e466408f803a91049973ee6fb`）。ライセンス: ファイル内 SPDX `Apache-2.0 OR MIT`（Copyright 2015-2026 The Khronos Group Inc.）
  - venus 固有コマンド: virgl/venus-protocol（freedesktop.org の GitLab）のタグ `v1.1.3`（コミット `ca19b6358d7c`）の `xmls/VK_MESA_venus_protocol.xml`（SHA-256 `d92839bc728fa9ad9a7decdc6b91df6fa1a0fb26cffae4009865f18a789e0535`）。ライセンス: ファイル内 SPDX `Apache-2.0 OR MIT`（Copyright 2020 Google LLC）。同タグの `xmls/VK_EXT_command_serialization.xml` も同じ SPDX・著作権者
  - Mesa Venus ドキュメント（docs.mesa3d.org/drivers/venus.html）（ページ自体に SPDX は無い。Mesa の `docs/license.rst`〔`mesa-25.0.0`〕は「コアは MIT、個別ファイルは固有ライセンスがありうる」とし、`docs/drivers/venus.rst` に個別のライセンス表記は無い。ドキュメントの個別ライセンスは未確認）・MoltenVK Runtime User Guide（KhronosGroup/MoltenVK の `Docs/MoltenVK_Runtime_UserGuide.md`。`main` のコミット `67b2682699d7` で確認、SHA-256 `6939c675f01e20acd5fcff05a586530055c31a0d0bf94d3813d9eab93763f769`。同コミットの `LICENSE` は Apache License 2.0 の標準全文で SPDX 行は無く、著作権者の記載も無い）
  - 帰属表示（NOTICE 等）の要否: **未決**（ユーザー判断待ち。#1603 で報告）。転記は値（事実情報）のみでコードは流用していない

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
- fail-closed: 候補外・未知の種別は `unsupported_command` でストリームを拒否する。配列件数は `MAX_ARRAY_LEN` と、要素の最小 wire サイズ × 件数 ≤ 残りバイト数（`read_array_len_sized`）で確保前に検証する。入れ子の配列では呼び出し側が累積の予算を持つ
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

- 保証範囲: `validate` が全レコードのチェックサム・seqno 連続・余剰バイト無しまで確認し、`ValidatedRecording` を返す。`replay` はこの型しか受け取らず、さらに全レコードの先頭がコマンドヘッダとして有効かを提出前に検査する。ファイルは `read_recording_file` が読む。開く前（`symlink_metadata`）と開いた後（fd の `metadata`）に通常ファイルであることを確かめ（symlink・ディレクトリ・FIFO・デバイスは `not_regular_file`。FIFO の open によるブロックを避ける）、全体長（256 MiB）を読み込み前に検証し、読み込みは上限 + 1 バイトで打ち切る。`validate` は受け取り済みの `&[u8]` の長さと件数を検査するだけで、件数による `Vec` 確保は残りバイト数 / 16 で頭打ちにする。観測（REPAIR-4）: `read_recording_file_observed` が早期拒否・I/O エラーを含む全終了経路で結果コード・終了段階・バイト数・所要時間（`ReadObservation`。path と内容は含めない）を返し、呼び出し側が構造化ログ / メトリクスへ流す。TOCTOU: Linux x86_64 / aarch64 と macOS では `sys::open_nofollow_nonblock`（`O_NOFOLLOW | O_NONBLOCK`）で開くため、検査後の FIFO 差し替えは open がブロックせず、末尾 symlink 差し替えは `ELOOP` で `not_regular_file` になり、fd の `metadata` 再確認で種別も弾く。残存リスク: フラグ値が未確認の OS では通常の open にフォールバックし、検査から open までの差し替えは塞がらない（事後の fd 検証のみ）。親ディレクトリ要素の差し替えも対象外。CRC-32C は偶発的な破損の検出用で、改ざん耐性はない（署名・ハッシュ照合は将来課題）
- 配置の逸脱: issue 記載の `poc/venus-decoder/replay/` ではなく既存骨格の隣に置いた。`poc/` は存在せず、新設には workspace メンバー追加（ルート `Cargo.toml` の変更）が要る。再生器は同モジュールの `parse_command_header` を直接使う
- 取り扱い: 実機で採取したストリームにはワークロード由来のデータが含まれうる。テストの fixture は合成データのみで、実ストリームはリポジトリにコミットしない
- **未達（実装済みを装わない。REPAIR-3）**: 受け入れ条件「lavapipe 上で記録を再生し、最小 compute の結果が記録時と一致する」は本書時点で未達。理由は (1) コマンド引数のパース・Vulkan ディスパッチが未実装（TASK-177.x）、(2) lavapipe 実行に Vulkan バインディング（外部クレートまたは自前 FFI。依存追加・`unsafe` の承認が必要）が要る、(3) 実ストリームの採取は #725（人間担当）。再生先は `ReplayBackend` トレイトの差し替え点として定義し、`CollectingBackend`（提出内容を保持する模擬）でのみ検証している
- 先送り: reply ストリーム・期待出力レコード（kind の番号は未割当。REPAIR-3）、実機側の記録フック配線（#888・#725）

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
- 実装済み（F1.1・#1516）: vhost-user メッセージの codec（`vhost_user`。10.5）。virtqueue・セッションは F1.3・F1.4 で実装
- 実装済み（F1.2・#1517）: `SCM_RIGHTS` の fd 送受信とゲストメモリの mmap のラッパー（`vhost_user::fd_passing` / `guest_memory`・`src/sys.rs`。Linux 限定。10.6）
- **受入基準 2（ゲストの Mesa venus の capset クエリが自前デコーダに届いたことをログで確認）は未達**。トランスポート（後続 F1）と実機実行（F3・#725。人間担当）が必要なため
- 後続（issue 起票は未実施・承認待ち）: F1 vhost-user トランスポート（メッセージ codec・fd 受け渡しと `mmap` の `sys` ラッパー・split virtqueue・kick / call。rust-vmm 系クレートは MVM-4 で使えないため自作）、F2 残りの ctrl 応答（10.4 節。`RESOURCE_CREATE_BLOB`・`SUBMIT_3D` 等）、F3 実機疎通（#725）
- 実装済み（F1.3・#1518）: split virtqueue（`virtqueue`。10.7）
- 実装済み（F1.4・#1519）: vhost-user のセッションと ctrl キューの応答ループ（`session`。Linux 限定。10.8）。受入基準 2 は F3（#725）の実機待ちのまま
- 後続（F5。#1599）: F5.1（#1600）で capset 以降の ctrl の列と治具の応答範囲を一次情報で確かめて 10.4 節に記録した。F5.2（#1601）は ctrl の応答（共有メモリを要しない部分）、F6（#1602）は記録、共有メモリの対応（F5.2b。issue 起票は未実施・承認待ち）は 10.4.4 節
- CI: `make poc-venus-jig-check`（fmt-check・clippy・test）は CI の `rust-ci-default-features` ジョブが 3 OS で実行し、`crates/plugin-macos` 側の変更による治具の破損を検出する（実機前提テストは `#[ignore]` で分離済みで CI では走らない）

### 10.2 候補比較

計画フェーズの調査結果。出典タグとファイルは下記のとおりで、crosvm の CLI 構文・最小カーネル版数・render server の capset 転送の有無は**未確認**（F1.4〔#1519〕でも取得できなかった。2026-10-09 に `book/src/devices/vhost_user.md` の取得を試みたが 404 で、記憶では埋めない。F3〔#725〕の着手時に crosvm の版を固定して確認する）。

| 候補 | 外部バックエンド接続 | ゲストへ BLOB・CONTEXT_INIT が届くか | venus capset の扱い | ライセンス | 改変の要否 |
| ---- | -------------------- | ------------------------------------ | ------------------- | ---------- | ---------- |
| QEMU `vhost-user-gpu-pci`（`hw/display/vhost-user-gpu.c`。タグ `v10.1.0`） | vhost-user | 届かない（realize が立てるのは VIRGL・EDID・RESOURCE_UUID のみ） | Mesa が capset 取得前に中止するため到達しない | GPL-2.0 | 標準では不適 |
| QEMU 汎用 `vhost-user-device(-pci)`（`hw/virtio/vhost-user-base.c`） | vhost-user。バックエンドの feature を素通し | 届く | バックエンド次第 | GPL-2.0 | 必要（`user_creatable = false` のため標準ビルドでは `-device` で作れない） |
| crosvm vhost-user frontend（`devices/src/virtio/vhost_user_frontend/mod.rs`。コミット `044c3e3fc53d`） | vhost-user。GPU 向け共有メモリ領域（SHMEM）にも対応 | 届く（デバイス固有 feature とバックエンド feature の積） | バックエンド次第 | BSD-3-Clause | 不要の見込み（`--vhost-user` の CLI 構文と最小カーネル版数は未確認） |
| virglrenderer の render server（`virgl_render_server`） | virglrenderer 利用側が必要。単体では VMM ではない | VMM 次第 | capset を server へ転送するか未確認 | MIT | — |
| Cloud Hypervisor・Firecracker | — | — | — | — | 比較対象外（GPU デバイスを持たず、依存・流用は禁止。dependency-policy） |

決め手: Mesa venus（`mesa-25.0.0` の `src/virtio/vulkan/vn_renderer_virtgpu.c`。`required_params`）は capset 取得より前に 3D 機能・`CAPSET_QUERY_FIX`・`RESOURCE_BLOB`・`CONTEXT_INIT` を必須として検査し、欠けると初期化を中止する。治具 VMM がゲストへ `VIRGL`・`RESOURCE_BLOB`・`CONTEXT_INIT` を見せられることが capset クエリ発行の前提になる。ただし `required_params` の後に、`HOST_VISIBLE`（virtio の共有メモリ領域 id 1）か `GUEST_VRAM` の一方も必須で、mainline カーネルでは前者だけが成立しうる。共有メモリ領域が無いと capset 取得まで届かない見込みである（10.4 節）。

選定（暫定）: **crosvm の vhost-user frontend**。BSD-3-Clause で改変不要の見込みであり、feature が素通しされる。QEMU を使う場合は GPL の VMM バイナリを外部プロセスとして実行するだけでリンクせず、汎用デバイスの有効化には GPL の改変ビルドが要る。この扱いは**要確認（ユーザー判断。licensing.md）**。`use_guest_vram`（8 章）は選定した VMM の共有メモリ方式に従属し、3 段目（#1057）まで未決。

### 10.3 ctrl の値と広告 feature

出典: Linux `include/uapi/linux/virtio_gpu.h` タグ `v6.12`（確認日 2026-10-08。SHA-256 `7c9e2f7d47fa0b1a2c737fc5a741f57c5cf25303dd5c68c2c9738e9bb761eee6`）。値のみ転記。ライセンス: ファイル先頭に SPDX 行は無く、BSD 系の許諾文（3 条項。「This header is BSD licensed」、Copyright Red Hat, Inc. 2013-2014、3 条項目の名指しは IBM）が書かれている。SPDX 表記は `BSD-3-Clause` 相当だが、ファイルに SPDX は無いため断定せず原文を正とする。帰属表示の要否は未決（#1603 で報告）。

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

### 10.4 capset 以降の ctrl の列と治具の応答範囲（F5.1・#1600）

TASK-172 後続 F5（#1599）の一次情報の確認。結論を先に書く。コードは変えていない（`poc/venus-decoder/jig/` は未変更）。

- **結論 1（前提の不足）**: Mesa venus は capset を取る前に `virtgpu_init_params` で `VIRTGPU_PARAM_HOST_VISIBLE` か `VIRTGPU_PARAM_GUEST_VRAM` の一方を必須にしている。mainline カーネルの `HOST_VISIBLE` は virtio の共有メモリ領域 `VIRTIO_GPU_SHM_ID_HOST_VISIBLE`（id 1）が見えるときだけ真になり、`GUEST_VRAM` は mainline v6.12 に case が無い。今の治具は protocol feature を MQ と CONFIG しか広告せず共有メモリ領域を見せないので、**Mesa は `GET_CAPSET` も `CTX_CREATE` も出す前に中止する見込み**になる。10.2 節の「決め手」と #888 の受入基準 2 の前提（`required_params` を満たせば capset クエリが届く）はこの分だけ足りない。
- **結論 2（治具の応答範囲）**: ctrl 単体の応答（資源表・`SUBMIT_3D` の受け取り）は #1601 の範囲として確定できる。ただし ring・reply 用の共有メモリ（`RESOURCE_MAP_BLOB`）は vhost-user の新しい仕組み（protocol feature `SHMEM` と `BACKEND_REQ`・`GET_SHMEM_CONFIG`・バックエンド要求）が前提で、本 Issue では実装を決めず承認待ちの別段（F5.2b）に切り出す。
- **結論 3（記録対象）**: venus の通常のコマンドは共有メモリ上のリングに書かれ、`SUBMIT_3D` に載るのはリングの制御（作成・起床・破棄）だけ。
- **結論 4（上限）**: リング制御のペイロードは最大 256 バイトで、`MAX_CTRL_REQ_LEN`（4096）の固定長バッファに収まる。
- **結論 5（reply 待ち）**: 最初に reply を要するコマンドで、ゲストはホストがリングを消費して reply を書くのを待つ。自前デコーダに dispatch（TASK-177.x）が無いのでここを越えられない見込み。

#### 10.4.1 出典

確認日 2026-10-09。転記したのは値（要求 ID・bit 値・フィールド配置・順序・サイズ）という事実だけで、コードは流用していない（MVM-4・from-scratch-policy）。行番号は下記の版のファイルでの値。

| 出典 | 版 | SHA-256 |
| ---- | -- | ------- |
| Mesa `src/virtio/vulkan/vn_renderer_virtgpu.c` | タグ `mesa-25.0.0` | `a7a0f1a395d006bfb1ef4aea4d3b2c6a44c30c50ede855416e1183442e1e03aa` |
| Mesa `src/virtio/vulkan/vn_instance.c` | 同上 | `b8d3461d9a8b8d740d7c383100ac972e256263d9bd55e663be31f709c4e838a9` |
| Mesa `src/virtio/vulkan/vn_ring.c` | 同上 | `927d4f1c292dbf4b0bf5cb87c3a0d3b7a2f2144b295b30d94afdd1f8f2cc2103` |
| Mesa `src/virtio/vulkan/vn_ring.h` | 同上 | `a56794982b64b94019158e6775f75e4d0e0609a57d69f676fab49f431b98f806` |
| Mesa `src/virtio/vulkan/vn_renderer.h` | 同上 | `120385cf9a90657184623e07c3ba895e4a31ccdf1a34b6b3d3e0ce65772b7b80` |
| Mesa `src/virtio/vulkan/vn_cs.c` | 同上 | `e3c66ff11030fdf13d57e0415825a5beae3dbfece121452d64d173023c32c46e` |
| Mesa `src/virtio/vulkan/vn_renderer_util.c` | 同上 | `53fdb195e751bf13366540576b99e0c600a4f8585ba51db6c73e6545962fbe75` |
| Linux `include/uapi/linux/virtio_gpu.h` | タグ `v6.12` | `7c9e2f7d47fa0b1a2c737fc5a741f57c5cf25303dd5c68c2c9738e9bb761eee6` |
| Linux `drivers/gpu/drm/virtio/virtgpu_kms.c` | 同上 | `9388cdb019b5bbf52f442d8d5073fcc7c6d00b2952d8ddc2c8b7229947346a7d` |
| Linux `drivers/gpu/drm/virtio/virtgpu_ioctl.c` | 同上 | `509cc5f489a489849e163fc7947859b7febf15237cb05c620762f69a207d6865` |
| Linux `drivers/gpu/drm/virtio/virtgpu_vq.c` | 同上 | `ae7c9bab76af9672414dc7fe001259a0cfbc617dc2888445c504c4f96b994be8` |
| Linux `drivers/gpu/drm/virtio/virtgpu_vram.c` | 同上 | `58561c4bc32b435785608efd057542cd4a37a2697b64f2cb85abb1e8f3649158` |
| Linux `drivers/gpu/drm/virtio/virtgpu_submit.c` | 同上 | `d3f947bc18f181d1d95f946fee3e4220a471b878991dc06968a48c0c24f2f3eb` |
| Linux `drivers/gpu/drm/virtio/virtgpu_gem.c` | 同上 | `8508331c97838c144011e5c6e789c3350825468c4ccf7388d2bf9696863d0cba` |
| Linux `drivers/gpu/drm/virtio/virtgpu_object.c` | 同上 | `a26e29eecee86b60b9654cddfc50945bc2c7bd37ce1f669b4f446c62a112d912` |
| crosvm `third_party/vmm_vhost/src/message.rs` | コミット `044c3e3fc53d` | `df6c31711167fe3b94080db4655826bb834cd2e9ac085915ce448652b8ab3495` |
| crosvm `devices/src/virtio/vhost_user_frontend/mod.rs` | 同上 | `9506fcaae2e7e4aec09baa1374cbbd0a3807c5f38f8566b5c4f5856e4ea22266` |
| QEMU `docs/interop/vhost-user.rst` | タグ `v10.1.0` | `1c06e32a3306172499767170b0b64ce8de4a8a90cbe543a00cc1b3861ae5bccd` |

Mesa は 2 層で読む。Mesa は ctrl を直接出さず、DRM ioctl を呼ぶ。ゲストのカーネル（`drivers/gpu/drm/virtio/`）がその ioctl から ctrl を組み立てて virtqueue に積む。以下の表は「Mesa の呼び出し → ioctl → カーネルが出す ctrl」の順に書く。

#### 10.4.2 ctrl の列（最小 compute: インスタンス作成からキューへの提出まで）

| 順 | Mesa 側（`vn_renderer_virtgpu.c` ほか） | ioctl | カーネルが出す ctrl | 出典の行 |
| -- | ---------------------------------------- | ----- | ------------------- | -------- |
| 0 | Mesa 以前（ゲストカーネルの probe） | なし | `GET_DISPLAY_INFO`・`GET_CAPSET_INFO` | 未確認（`virtgpu_kms.c` の probe 経路は ctrl 名の確認まで行っていない。10.3 の既存実装が前提） |
| 1 | `virtgpu_init_params`（`virtgpu_init` の中で `init_capset` より前。1497・1667 行） | `GETPARAM`（`3D_FEATURES`・`CAPSET_QUERY_FIX`・`RESOURCE_BLOB`・`CONTEXT_INIT`、続けて `HOST_VISIBLE`、0 なら `GUEST_VRAM`） | なし（カーネル内で答える）。`HOST_VISIBLE` も `GUEST_VRAM` も 0 なら `VK_ERROR_INITIALIZATION_FAILED` で中止（1515〜1531 行） | `virtgpu_ioctl.c` 88〜125 行（`GUEST_VRAM` の case は無く `-EINVAL`）。`virtgpu_kms.c` 177〜191 行（`has_host_visible` は共有メモリ領域 id 1 の取得に成功したときだけ真） |
| 2 | `virtgpu_init_capset`（1477 行） | `GET_CAPS`（capset id 4・version 0） | `GET_CAPSET`（カーネルのキャッシュに無いとき） | 10.3 と同じ。ここから先は 1 を越えたときだけ |
| 3 | `virtgpu_init_context`（`virtgpu_ioctl_context_init`。600〜622 行） | `CONTEXT_INIT`（`CAPSET_ID`=4・`NUM_RINGS`=64・`POLL_RINGS_MASK`=0） | `CTX_CREATE`（0x0200）。`context_init` に capset id 4 が入る（`virtgpu_ioctl.c` の `create_context_locked`）。10.3 の「下位 8 bit が VENUS のときだけ受理」と矛盾しない | `virtgpu_ioctl.c` 42〜60 行、`virtgpu_vq.c` 912〜927 行 |
| 4 | `virtgpu_shmem_create`（1289〜1326 行）。ring・cs pool・reply pool 用。`blob_mem`=HOST3D・`blob_flags`=USE_MAPPABLE・`blob_id`=0 | `RESOURCE_CREATE_BLOB`、続けて `MAP`（mmap 用のオフセット取得） | `RESOURCE_CREATE_BLOB`（0x010c。ヘッダの `ctx_id`=呼び出した ctx、`nr_entries`=0）→ GEM open で `CTX_ATTACH_RESOURCE`（0x0202）→ **作成の直後に** `RESOURCE_MAP_BLOB`（0x0208。`offset` は共有メモリ領域内。応答は `OK_MAP_INFO`）。`MAP_BLOB` は `DRM_IOCTL_VIRTGPU_MAP` ではなく作成時に出る | `virtgpu_ioctl.c` 一帯の `verify_blob` と `virtio_gpu_resource_create_blob_ioctl`、`virtgpu_vram.c` 141〜175・205〜222 行、`virtgpu_gem.c` 137 行、`virtgpu_vq.c` 1200〜1223・1242〜1262 行 |
| 5 | `sim_syncobj_create`（`SIMULATE_SYNCOBJ`。初回のみ。143〜187 行） | `EXECBUFFER`（size 0・`RING_IDX`・`FENCE_FD_OUT`・`ring_idx` 0） | `SUBMIT_3D`（0x0207）の見込み。本体 0 バイトで flags に `FENCE` と `INFO_RING_IDX` | Mesa 側のみ確認。size 0 の execbuf が `SUBMIT_3D` を出すかは**未確認**（`virtgpu_submit.c` の size 0 経路を追っていない） |
| 6 | `vn_ring_create`（`vkCreateRingMESA`。`vn_ring.c` 339〜361 行）→ `vn_renderer_submit_simple` → `sim_submit` | `EXECBUFFER`（`ring_idx` 0） | `SUBMIT_3D`。ペイロードは `vkCreateRingMESA` のエンコード。ring の共有メモリの `res_id` と各オフセットを持つ | `vn_ring.c` 339〜362 行。`vn_renderer_submit_simple` の定義は未取得のファイル（`vn_renderer_util.h`）にあり**未確認** |
| 7 | 以降の venus コマンド（`vkEnumerateInstanceVersion`〜`vkCreateInstance`〜`vkQueueSubmit`） | なし（ring の共有メモリへ書く） | リングが idle のときの `vkNotifyRingMESA` だけが `SUBMIT_3D` で届く | `vn_ring.c` 427〜470・612〜636 行 |
| 8 | reply（`vkSetReplyCommandStreamMESA` は ring に書く。reply 本体は reply pool の共有メモリ） | 4 と同じ blob 経路 | 4 と同じ | `vn_ring.c` 658〜727 行、`vn_instance.c` 300〜312 行 |
| 9 | 解放（`virtgpu_shmem_destroy_now`。`vkDestroyRingMESA` は `vn_ring.c` 370〜378 行） | `GEM_CLOSE` | `CTX_DETACH_RESOURCE`（0x0203）→ `RESOURCE_UNMAP_BLOB`（0x0209）→ `RESOURCE_UNREF`（0x0102） | `virtgpu_gem.c` 159 行、`virtgpu_vram.c` 6〜20 行、`virtgpu_vq.c` 1226〜1240 行 |
| — | プロセス終了 | close | `CTX_DESTROY`（0x0201） | `virtgpu_vq.c` 930〜940 行 |

0x0100 台と 0x0200 台の値は `virtio_gpu.h`（v6.12）72〜97 行の列挙から数えた値。エラー応答は同じ列挙の `ERR_UNSPEC`（0x1200）の後ろへ連番で、`ERR_OUT_OF_MEMORY` 0x1201・`ERR_INVALID_SCANOUT_ID` 0x1202・`ERR_INVALID_RESOURCE_ID` 0x1203・`ERR_INVALID_CONTEXT_ID` 0x1204・`ERR_INVALID_PARAMETER` 0x1205。

#### 10.4.3 要求ごとの決定（治具の応答・資源表・検証・新しい仕組みの要否）

「#1601」は F5.2（ctrl の応答。共有メモリを要しない部分）、「F5.2b」は共有メモリの対応（新規・承認待ち。10.4.4）。

| 要求 | 治具の応答 | 資源表と上限 | ゲスト由来の入力の検証 | 新しい `unsafe` / vhost-user の要否 |
| ---- | ---------- | ------------ | ---------------------- | ------------------------------------ |
| `RESOURCE_CREATE_BLOB`（0x010c） | #1601: 成功（`OK_NODATA`）は HOST3D・`blob_flags` = MAPPABLE（0x0001）だけ・`blob_id` 0・`nr_entries` 0・ctx 作成済みのときだけ。それ以外の `blob_mem`・flags・`blob_id`・`nr_entries` は `ERR_INVALID_PARAMETER` | 件数 256・1 件の size 16 MiB・合計 64 MiB（案。根拠は下の「上限の根拠」） | res_id 0・重複・size 0・4096 の倍数でない size は拒否。`ctx_id` は作成済みの ctx。上限は確保より前に検査し、size は checked 演算 | #1601 は不要。**実際の確保**（memfd 等）は F5.2b |
| `CTX_ATTACH_RESOURCE` / `DETACH_RESOURCE`（0x0202 / 0x0203） | #1601: 作成済みの ctx と res の組だけ成功。未知の ctx は `ERR_INVALID_CONTEXT_ID`、未知の res は `ERR_INVALID_RESOURCE_ID` | 資源表に所属 ctx の集合を持つ（上限は ctx 表の 64 × 資源表の件数の範囲内） | 二重 attach・未 attach の detach は `ERR_INVALID_PARAMETER` | 不要 |
| `RESOURCE_UNREF`（0x0102） | #1601: 作成済みの res だけ成功し、表から消す。attach 中の res は拒否（`ERR_INVALID_PARAMETER`）。map 中の扱いは F5.2b で決める | 同上 | res_id の検査 | 不要（`munmap` は F5.2b） |
| `RESOURCE_MAP_BLOB` / `UNMAP_BLOB`（0x0208 / 0x0209） | **#1601 では未実装のまま**（`ERR_UNSPEC`）。ゲストカーネルが作成直後に出すので、実装するとき F5.2b | — | `offset` が共有メモリ領域の内側で、`offset + size` が領域内、他の map と重ならないこと（F5.2b への申し送り） | 要る。protocol feature `SHMEM` と `BACKEND_REQ`、`GET_SHMEM_CONFIG`、バックエンド要求 `SHMEM_MAP` / `SHMEM_UNMAP`。10.4.4 |
| `SUBMIT_3D`（0x0207） | #1601: 受理して、ペイロードを記録の受け渡し点へ渡す。dispatch はしない（応答は `OK_NODATA` で、`FLAG_FENCE` なら fence を引き継ぐ） | ペイロードは上限つきの固定長（10.4.6） | ctx が作成済みか、`ring_idx` < 64（`INFO_RING_IDX` が立つときだけ見る。`NUM_RINGS`=64）、`size` とペイロード実長の一致。本体 0 バイトも受理 | 不要（既存の `SplitQueue` で連結できる範囲。10.4.6） |

上限の根拠: Mesa が確保する共有メモリは、ring が 128 KiB に extra 4 バイトを足した大きさ（`vn_instance.c` 128〜140 行、`vn_ring.c` 262〜270 行付近のレイアウト。行番号は付近）、cs pool が 8 MiB、reply pool が 1 MiB（`vn_instance.c` 300〜312 行）。1 件 16 MiB は最大の cs pool の 2 倍、合計 64 MiB は同時に持つ ring・cs・reply の合計に余裕を足した値で、いずれも**案**（実機でプール拡張の挙動を確かめて#725 で見直す）。cs pool の拡張は `vn_cs.c` の `next_buffer_size` が倍々に増やすため、16 MiB を超える要求は拒否して Mesa に失敗を返す（`VK_ERROR_OUT_OF_DEVICE_MEMORY` で止まる見込みで、挙動は未確認）。

#### 10.4.4 共有メモリの前提（F5.2b の要件）

- ゲストカーネルは `virtio_get_shm_region(..., id 1)` が成功したときだけ `has_host_visible` を立てる（`virtgpu_kms.c` 177〜191 行）。vhost-user では frontend 側がバックエンドに共有メモリ領域を問い合わせる
- crosvm の frontend（`mod.rs` 514〜543 行）は、バックエンドが protocol feature `SHMEM`（bit 22、`0x0040_0000`。`message.rs` 384 行）をネゴシエーションしたときだけ `GET_SHMEM_CONFIG`（要求 ID 44。`message.rs` 154 行）で領域を取得し、領域が 0 個なら共有メモリ無し、1 個ならそれを使い、2 個以上はエラーにする。ネゴシエーションの前提として crosvm は `BACKEND_REQ`（bit 5、`0x20`）と `REPLY_ACK`（bit 3、`0x08`）も広告する（`mod.rs` 143〜151 行）
- バックエンドから frontend への要求は `SET_BACKEND_REQ_FD`（要求 ID 21。ancillary data で fd を渡す。QEMU の rst と crosvm で同じ）で張ったソケットで送る。`SHMEM_MAP` = 9、`SHMEM_UNMAP` = 10（`message.rs` 192・194 行）。`SHMEM_MAP` のペイロードは `shmid`（u8）+ padding 7 バイト、`fd_offset`（u64）、`shm_offset`（u64）、`len`（u64）、`flags`（u64。`MAP_RW` = 0x1）の 40 バイトで、map する fd は ancillary data で渡す（`message.rs` 776〜815 行）
- crosvm には非標準の `GPU_MAP`（1006）と `EXTERNAL_MAP`（1007）もある（`message.rs` 200〜204 行）。ring・reply・cs 用の HOST3D・`blob_id` 0 の共有メモリに `SHMEM_MAP` と `GPU_MAP` のどちらを使うかは**未確認**（crosvm の gpu backend 側の呼び出しは取得していない）。`GET_SHMEM_CONFIG` の応答ペイロードの配置も**未確認**
- crosvm は `REPLY_ACK` を広告するが、`need_reply` は立てない（`SHMEM_MAP` の競合を避けるためという旨のコメント。`mod.rs` 146〜151 行）。治具が `REPLY_ACK` を広告するかは F5.2b で決める
- **QEMU v10.1.0 の `docs/interop/vhost-user.rst` には `SHMEM` の protocol feature も `GET_SHMEM_CONFIG`・`SHMEM_MAP` / `SHMEM_UNMAP` も見当たらない**（語 `shmem` で検索して 0 件）。10.5 節の「QEMU と crosvm で ID が一致」は最小要求集合 16 種の範囲の話で、共有メモリの要求は crosvm 側だけの拡張になる。10.2 節の暫定選定（crosvm）はこの点でも補強される
- バックエンド側の設計の見込み: memfd を作り、`SHMEM_MAP` で frontend に渡す。fd の送受信（`SCM_RIGHTS`）・`memfd_create`・`mmap` の `sys` ラッパーは 10.6 節で実装済みで、既存の範囲に収まる見込み。ただし、バックエンドが frontend 宛にバックエンド要求を**送る**経路（`SET_BACKEND_REQ_FD` で受けた fd へ書く）は新規で、新しい `unsafe` が要るかどうかは F5.2b の承認事項（10.6 節の `sys` ラッパーで足りれば不要）

#### 10.4.5 コマンドストリームの経路と #1602 の記録対象

- venus の通常のコマンドは、ring の共有メモリ（HOST3D・`blob_id` 0 の blob）へ書かれる。ring の書き込み先は共有メモリで、virtqueue を通らない。ホストは ring を消費して処理する。`vn_ring_submit_locked` はコマンドをリングに書き（`vn_ring.c` 436〜442 行）、`SUBMIT_3D` を使うのは idle のリングを起こす `vkNotifyRingMESA` だけ（同 457〜469・627〜636 行）
- 取得したファイルの範囲では、リングを使わない直接提出は `vkCreateRingMESA`・`vkDestroyRingMESA`・`vkNotifyRingMESA`・ring の roundtrip（`vn_ring.c` 741 行）の 4 か所の `vn_renderer_submit_simple` だけ。ほかのファイル（キュー提出の `vn_queue.c` 等）は取得しておらず、`vn_renderer_submit` を直接呼ぶ経路は**未確認**
- したがって #1602 の第 1 段は、`SUBMIT_3D` のペイロードを 1 回 1 レコードで記録する（偽の frontend で試験できる）。ただし中身はリングの制御だけで、2 段目の再生に使える価値は小さい。**リングの中身の記録は F5.2b（共有メモリ）の後に回す**。#1602 の本文は編集していない。範囲の確定は本節と #1600 のコメントで行う

#### 10.4.6 `SUBMIT_3D` のペイロード上限

- ゲストのカーネルが組み立てる `SUBMIT_3D` は、ヘッダ 24 バイト + `size` 4 バイト + padding 4 バイトの 32 バイトに本体が続く（`virtgpu_vq.c` 1078〜1099 行）。本体は `vmemdup_user` で取られ（`virtgpu_submit.c` 416 行）、カーネル側に明示の上限は無い。vmalloc の領域はページごとの sg になり、readable の記述子が複数に分かれる（`virtgpu_vq.c` 274〜290・387〜400 行）
- リング制御のエンコードは Mesa 側の固定長バッファで作られる: `vkCreateRingMESA` は `uint32_t[64]` = 256 バイト（`vn_ring.c` 339〜361 行）、`vkNotifyRingMESA` は `uint32_t[8]` = 32 バイト、`vkDestroyRingMESA` は `uint32_t[4]` = 16 バイト、roundtrip は `uint32_t[8]` = 32 バイト。ヘッダ込みで最大 288 バイトで、`MAX_CTRL_REQ_LEN`（4096。`session/mod.rs`）に十分収まる
- 決定: **当面は 4096（ヘッダ込み）の固定長のまま**にする。超える要求は既存どおり `ERR_INVALID_PARAMETER`（ゲストに失敗を返す）。ヒープで受ける経路（上限を検証してから確保）は、リング以外の直接提出が見つかった場合に後続で決める。複数の記述子にまたがる本体の連結は、既存の `SplitQueue`（10.7）の記述子チェーン（64 本・1 MiB）で足りる見込み

#### 10.4.7 reply 待ちで止まる箇所と dispatch の要否

- 見込み: `vn_instance_init_renderer_versions`（`vn_instance.c` 74〜113 行。`vkEnumerateInstanceVersion`）が、ring に書いたコマンドの reply を待つ最初の箇所。`vn_ring_submit_command` が reply を要するコマンドで `vn_ring_wait_seqno` を呼ぶ（`vn_ring.c` 700〜713・175〜192 行）。待ちはリングの head を見る `vn_relax` のポーリングで、タイムアウトで中止するか待ち続けるかは**未確認**（`vn_relax` の実装は `vn_common.c` にあり未取得）
- このポーリングを越えるには、ホストが共有メモリ上のリングを消費して reply を書く必要がある。これには共有メモリ（F5.2b）と、コマンドの dispatch（TASK-177.x。`vkEnumerateInstanceVersion` の応答の符号化）が両方要る。自前デコーダには dispatch が無いので越えられない見込み
- #725（TASK-172.h1・人間担当）の受入基準 1 は、「どこまで進み、どこで止まったか」の記録になる。現状の治具では**（結論 1 のとおり）capset の前で止まる**見込みで、共有メモリを入れても reply の待ちで止まる見込み
- 治具側のタイムアウト（REPAIR-5。10.8 節の `message_timeout` / `idle_timeout`）は、ゲストの待ちとは別にホスト側の切断を保証する

#### 10.4.8 範囲外にしたもの（理由つき）と 10.3 の表との対応

| 項目 | 範囲外にした理由 |
| ---- | ---------------- |
| `RESOURCE_MAP_BLOB` / `UNMAP_BLOB` の実装 | 共有メモリ（`SHMEM`・`BACKEND_REQ`）が前提で、承認待ちの F5.2b。#1057（共有メモリ方式の判定）とも関わる |
| リングの消費と dispatch | TASK-177.x（デコーダ本体）の範囲 |
| `GET_DISPLAY_INFO` の scanout あり・`RESOURCE_CREATE_2D` 系・cursor | 最小 compute の ctrl の列に出ない（10.4.2 の表に無い） |
| `RESOURCE_CREATE_BLOB` の `GUEST` / `HOST3D_GUEST`・`USE_SHAREABLE` / `USE_CROSS_DEVICE` | ring・cs・reply の用途は HOST3D・MAPPABLE・`blob_id` 0 だけ。sg を要する経路は範囲外 |
| `ERR_INVALID_SCANOUT_ID`（0x1202） | scanout を持たないため使わない |

10.3 の表との対応: 既存の `GET_CAPSET_INFO` / `GET_CAPSET`・`GET_DISPLAY_INFO`・`CTX_CREATE` / `CTX_DESTROY` は変更しない。追加するのは上の表の `RESOURCE_CREATE_BLOB`・`CTX_ATTACH_RESOURCE` / `DETACH_RESOURCE`・`RESOURCE_UNREF`・`SUBMIT_3D` の応答で、`MAP_BLOB` / `UNMAP_BLOB` は引き続き未実装（`ERR_UNSPEC`）。製品版の ctrl 枠は TASK-175.1.3（#915）・TASK-176.1（#749）。

### 10.5 vhost-user メッセージの値（F1.1・#1516）

出典（確認日 2026-10-09。転記したのは要求 ID・ビット値・フィールド配置という事実だけで、コードは流用していない。crosvm の `vmm_vhost` は rust-vmm の `vhost` 由来の系統のため構造体定義やロジックは写さない。MVM-4・from-scratch-policy）。

| 出典 | 版 | SHA-256 |
| ---- | -- | ------- |
| QEMU `docs/interop/vhost-user.rst` | タグ `v10.1.0` | `1c06e32a3306172499767170b0b64ce8de4a8a90cbe543a00cc1b3861ae5bccd` |
| crosvm `third_party/vmm_vhost/src/message.rs` | コミット `044c3e3fc53d` | `df6c31711167fe3b94080db4655826bb834cd2e9ac085915ce448652b8ab3495` |
| crosvm `third_party/vmm_vhost/src/backend_client.rs` | 同上 | `709fe08830a38c5e15a00c0c5af47ef7dabf19a784c0694abf8c10d335dec7c2` |
| crosvm `devices/src/virtio/vhost_user_frontend/mod.rs` | 同上 | `9506fcaae2e7e4aec09baa1374cbbd0a3807c5f38f8566b5c4f5856e4ea22266` |

前提（実際に広告するのは F1.4・#1519）: virtio feature は bit 30（`VHOST_USER_F_PROTOCOL_FEATURES`）を立て、protocol feature は CONFIG（bit 9。virtio-gpu config の読み出しに要る）と MQ（bit 0）だけにする。REPLY_ACK・BACKEND_REQ・SHMEM・DEVICE_STATE・CONFIGURE_MEM_SLOTS は host-visible 共有メモリの方式が決まる #1057 まで後送りで、追加する場合は対応する要求を codec に足す。最小要求集合に SHMEM 系は無く、crosvm だけの拡張は 10.4.4 節で扱う。

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

frontend（crosvm 等）は UDS の補助データ（`SCM_RIGHTS`）でゲストメモリ領域の fd と eventfd を渡し、backend は `SET_MEM_TABLE` の領域を `mmap` して GPA 経由でアクセスする。rust-vmm 系は MVM-4 で使えないため自作し、crosvm の構造体やロジックは写していない。`unsafe` は `src/sys.rs` にだけ置く（個別承認: [#1517 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6074351741)。U1 `syscall` 宣言・U2 `recvmsg`・U3 受信 fd の所有・U4 `sendmsg`・U5 `memfd_create`・U6 `mmap`・U7 `Drop` の `munmap`・U8 境界検査後のコピー。レビュー指摘への対応で U9 `fcntl`〔`F_GET_SEALS` / `F_ADD_SEALS`〕・U10 `ppoll` を #1517 の追加承認〔[#1517 のコメント](https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6075711404)〕で加えた。#4 の `sys` モジュールの事前承認は根拠にしない）。lint は `lib.rs` に crate 全体の `#![deny(unsafe_code)]` を置き、`sys` にだけ `#[allow(unsafe_code)]` を付ける（承認条件）。

出典（確認日 2026-10-09。値だけを転記）: Linux UAPI ヘッダ（`linux-libc-dev`）の `asm-generic/socket.h`（SHA-256 `e833d32d3d8d03732021da6968665431d693ab4effdd4d39965ff05115a4ed21`）・`linux/socket.h`（`f4331fd201269894f63242a2521b3d5b3290ca556969011d7858908d5fe658c4`）・`asm-generic/mman-common.h`・`linux/memfd.h`、`linux/fcntl.h`（`F_ADD_SEALS` / `F_GET_SEALS` / `F_SEAL_*`）・`asm-generic/poll.h`（`POLLIN` / `POLLOUT`）、syscall 番号は `asm/unistd_64.h`（x86_64）と asm-generic `unistd.h`（aarch64）、man `recvmsg(2)`・`unix(7)`・`cmsg(3)`・`mmap(2)`・`memfd_create(2)`・`fcntl(2)`・`ppoll(2)`。

| 定数 | x86_64 | aarch64 |
| ---- | ------ | ------- |
| `sendmsg` / `recvmsg` | 46 / 47 | 211 / 212 |
| `mmap` / `munmap` | 9 / 11 | 222 / 215 |
| `memfd_create` | 319 | 279 |
| `fcntl` | 72 | 25 |
| `ppoll` | 271 | 73 |
| `F_ADD_SEALS` / `F_GET_SEALS` / `F_SEAL_SHRINK` / `MFD_ALLOW_SEALING` | 1033 / 1034 / 0x2 / 0x2 | 同左（個別に定義） |
| `SOL_SOCKET` / `SCM_RIGHTS` | 1 / 1 | 1 / 1 |
| `MSG_CTRUNC` / `MSG_TRUNC` / `MSG_NOSIGNAL` / `MSG_CMSG_CLOEXEC` | 0x8 / 0x20 / 0x4000 / 0x4000_0000 | 同左（個別に定義） |
| `SCM_PIDFD` / `MSG_DONTWAIT` / `POLLIN` / `POLLOUT` | 4 / 0x40 / 0x1 / 0x4 | 同左（個別に定義） |
| `CMSG_HDR_LEN` / `CMSG_ALIGN` | 16 / 8 | 同左（個別に定義） |

定数・カーネル ABI の構造体・`unsafe` は `sys` の `imp`（`cfg(any(target_arch = "x86_64", target_arch = "aarch64"))`）にだけ置く。それ以外のアーキの `imp` は定数を一切定義せず、すべて `UNSUPPORTED` を返す（0 などの代替定数はビット判定を常に偽にして fail-open になり得るため置かない）。riscv64 では clippy（`--all-targets -D warnings`）の型検査のみ通した。

設計判断:

- `recvmsg` 等は `syscall(2)` 経由でカーネル ABI の `user_msghdr` / `cmsghdr` を直接使う（glibc / musl の `msghdr` のパディング差に依存しない）。`sysconf` は使わない。タイムアウト（REPAIR-5）は呼び出しごとの期限を持ち、`MSG_DONTWAIT` の `recvmsg` / `sendmsg` と `ppoll`（U10）で待つ（共有ソケットの `SO_RCVTIMEO` に依存しない）
- 受け取る fd は `MAX_FDS`（32）。受信した fd は `sys::recvmsg_fds` が補助データをローカルなバッファで受け、同じ呼び出しの中で検証より前にすべて `OwnedFd` にして返す（生の番号から `OwnedFd` を作る経路を `sys` の外へ出さないので、細工したバイト列で任意の fd を所有したり同じ補助データを二度解析して二重に閉じたりできない）。`MSG_CTRUNC`・上限超過・構造異常のどのエラー経路でも `Drop` で閉じる。`MSG_CMSG_CLOEXEC` で close-on-exec を原子的に付ける
- map は file offset 0 から `mmap_offset + memory_size` バイトを `MAP_SHARED` で行い、領域の先頭をマップ内の `mmap_offset` の位置として扱う（ページ境界にそろっていない `mmap_offset` でも `EINVAL` にしない）。QEMU `vhost-user.rst` の `mmap_offset` の定義との照合は未実施で、F1.4 の結合で確認する
- 上限は治具独自: 1 領域の map 長 64 GiB・合計 128 GiB。合計の上限は mmap より前に checked 演算で判定する（`INVALID_REGION`）。fd は治具自身が作る memfd（shmem）と `st_dev` が違えば `UNSUPPORTED_BACKING`（hugetlb の memfd は hole punch の後に SIGBUS になり得て、huge page に揃わない長さの munmap が失敗してマッピングが残るため。通常ファイルも同じ）、`F_SEAL_SHRINK` が確認できなければ `SHRINK_NOT_SEALED` で拒否し（seal 非対応の fd も同様）、そのうえでファイル長が map 長に届かなければ `FILE_TOO_SHORT`。これらとアクセス範囲の占有は `sys::MmapRegion::map_shared` が map と不可分に行い、呼び出し側に頼らない。領域をまたぐアクセスは `OUT_OF_BOUNDS`（PoC の割り切り）
- マッピングへの参照は作らず、境界検査したコピーだけで出し入れする。`MmapRegion` は `!Send` / `!Sync`（`PhantomData<*mut u8>` で明示し、`compile_fail` の doctest で照合）
- プロセス内の排他性: コピーは非アトミックなので、同じ backing file（`st_dev`・`st_ino`）のファイル上のアクセス範囲（`[mmap_offset, mmap_offset + memory_size)`）が重なる領域は、プロセス全体で同時に 1 個だけ map できる（重なれば mmap 前に `BACKING_IN_USE`。fd を複製しても同じ判定）。同じ memfd の重ならない範囲を別領域にするのは受け付ける。frontend プロセスの同時書き込みは vhost-user の前提として残る（値が不定になるだけ）。アトミックなコピーへの置き換えは U8 と別の unsafe になるため、承認を得るまで行わない
- 縮小の封じ込め: frontend が後から `ftruncate` で縮めると `SIGBUS` になるため、`F_SEAL_SHRINK` つきの memfd だけを受け付ける。seal を付けない frontend は接続できない（PoC の割り切り。製品版の fd 要件は TASK-173 系で扱う）
- aarch64 の定数と構造体は CI で型検査されない（治具はルート workspace 外で `aarch64-linux-check` の対象外）。固定値テストも実行アーキの分しか走らない。ローカルでは `cargo check --target aarch64-unknown-linux-gnu --all-targets` の型検査のみ通した（実行は未検証）
- 範囲外: ヘッダ単位の読み書きの枠組み・セッション・UDS の bind と所有者・権限・peer credential の検証（PLUG-12 相当）・eventfd の待機は F1.4（#1519）、virtqueue と `userspace_addr` の変換は F1.3（#1518）
- F1.4（#1519）への注意: `SET_MEM_TABLE` を送り直されたとき、古い `GuestMemory` を生かしたまま新しい表を map すると、同じ memfd の重なる範囲が `BACKING_IN_USE` で拒否される。F1.4 では「古い表を drop してから新しい表を map する」順序を決める必要がある。また合計上限（128 GiB）は `GuestMemory` 1 個の中だけで、複数の `GuestMemory` をまたぐ上限は無いため、セッション単位の上限も F1.4 で決める

残っている前提:

- frontend プロセスによる同時書き込みは、Rust の抽象機械の外にある非アトミックなコピー（`copy_nonoverlapping`）として扱っている。プロセス内の並行アクセスは `!Send` / `!Sync` と範囲の占有で封じたが、frontend の書き込みと backend のコピーの競合は vhost-user の前提として残る（コピーした値が不定になるだけで、マッピング外は触らない）。アトミックなアクセスへの置き換えは U1〜U10 の承認範囲外
- 後続の F1.3（#1518）は、共有メモリから `read_at` でコピーした後のバッファだけを解析する。同じ値を共有メモリから二度読むと、frontend がその間に書き換えて検査済みの値と使う値が食い違い得る（二度読み・TOCTOU）ため、検査と使用は同じコピーに対して行う
- `vm.overcommit_memory=2`（厳格な課金）の環境では、長さだけを `ftruncate` で伸ばした shmem の memfd（ページ未割り当ての疎なファイル）への初回の書き込みで、ページの課金に失敗すると `SIGBUS` になり得る（環境に依存する DoS）。治具は seal と長さを検査するが、ページが実際に確保済みかは確かめない。製品版の fd 要件（TASK-173 系）への申し送り: frontend 側での事前確保（`fallocate` 等）を要件にするか、backend 側で確保を確かめる方法を決める

### 10.7 split virtqueue（F1.3・#1518）

実装は `poc/venus-decoder/jig/src/virtqueue/`。トランスポートに依存しないので `vhost_user` の外に置き、全 OS で合成メモリのテストが動く（Linux では `GuestMemory` が `QueueMemory` を実装）。呼び出し元は F1.4（#1519）。

出典（確認日 2026-10-09。値だけを転記）: OASIS VIRTIO 1.2 の 2.7 系（レイアウト・アラインメント・記述子 flags・avail / used ring・要素を書いてから idx を更新する順序・readable を writable より前に置く driver 要件）、Linux `virtio_ring.h`（`INDIRECT_DESC`=28・`EVENT_IDX`=29）、QEMU `vhost-user.rst`（`SET_VRING_ADDR` の flags bit 0 が log）。節番号は記憶に基づく転記で、仕様本文の再取得による照合は未実施（F1.4 の結合か実機で食い違いが出たら直す）。

| 項目 | 値 |
| ---- | -- |
| アラインメント | desc 16・avail 2・used 4（user アドレスと GPA の両方を検査） |
| Queue Size | 2 の冪、1〜32768 |
| 記述子 flags | NEXT=1・WRITE=2・INDIRECT=4（他のビットは `INVALID_DESC_FLAGS`） |
| 治具独自の上限 | チェーン長 `min(64, num)`・総バイト長 1 MiB |

- 検査: `num`、`SET_VRING_ADDR.flags == 0`（log は未ネゴシエーション）、リング全体が 1 領域に収まること、avail の未処理数 <= num、head / next < num、循環（`CHAIN_LOOP`）、上限（`CHAIN_TOO_LONG`）、readable が writable の後ろにないこと、総バイト長・`addr + len` の溢れ。すべて fail-closed で、失敗した `pop` は `last_avail` を進めない
- TOCTOU: avail の idx・ring 要素・記述子 16 バイトは共有メモリから 1 回だけコピーし、そのコピーだけを解析する（テストで読み出し回数を照合）
- 順序: `pop` は `avail.idx` の後に Acquire、`add_used` は used 要素の後に Release の fence を置いてから `used.idx` を書く。コピーは非アトミックなので、fence が実機のバリアになることに頼る前提が残る（アトミックなコピーは U1〜U10 の承認範囲外）
- 扱わない: `INDIRECT`・`EVENT_IDX`（`device::FEATURES` が広告しない。`used_event` / `avail_event` は読み書きしない）、packed virtqueue。`unsafe` と依存は追加していない
- F1.4（#1519）への申し送り: kick / call の eventfd、`SET_VRING_ENABLE`、`GET_VRING_BASE` での `last_avail` の返却、キュー番号と ctrl / cursor の対応づけ、エラー後のキューの扱い（リセットか切断）、virtqueue の観測カウンタ

### 10.8 セッションと応答ループ（F1.4・#1519）

実装は `poc/venus-decoder/jig/src/session/`（Linux 限定。`unsafe` は追加せず `sys.rs` も変更していない。依存の追加なし）。入口は `session::run(&UnixStream, &SessionLimits, sink)`。接続 1 本分を最後まで処理し、ログ（1 要求 1 行）を `sink` へ流す。

- 広告値: `GET_FEATURES` は `0x0000_0001_4000_0019`（VIRGL・RESOURCE_BLOB・CONTEXT_INIT・VERSION_1・PROTOCOL_FEATURES）、`GET_PROTOCOL_FEATURES` は `0x201`（MQ・CONFIG）、`GET_QUEUE_NUM` は 2（controlq・cursorq）。`GET_CONFIG` は 16 バイトの config（`num_capsets` = 1）の `offset + size <= 16` を返し、範囲外は空ペイロードのエラー応答でセッションは続ける
- `SET_FEATURES`: 広告外のビットは `FEATURE_NOT_OFFERED`、広告した 5 ビットのどれかが欠ければ `REQUIRED_FEATURE_MISSING`（Mesa venus が capset 取得前に中止するため、PoC では fail-closed）
- 順序のゲート（違反は `OUT_OF_ORDER` で要求 ID を載せる）。本当の依存関係だけを判定し、一本道は強制しない（QEMU と crosvm で `SET_OWNER` / `GET_PROTOCOL_FEATURES` の位置が違うため）。根拠は 10.5 で固定済みの crosvm コミット `044c3e3fc53d` の `backend_client.rs` / `vhost_user_frontend/mod.rs` と QEMU `vhost-user.rst`（v10.1.0）だが、**この節の表は PR 作成時点で両者の再取得による照合を行っていない（未照合）**。F3 で食い違えばここを直す

| 要求 | 前提 |
| ---- | ---- |
| `GET_FEATURES`・`GET_PROTOCOL_FEATURES` | なし |
| `SET_OWNER` | 2 回目は拒否 |
| `SET_PROTOCOL_FEATURES` | `GET_PROTOCOL_FEATURES` の後。広告外のビットは `FEATURE_NOT_OFFERED` |
| `GET_QUEUE_NUM` / `GET_CONFIG` | 確定した protocol feature に MQ / CONFIG がある |
| `SET_FEATURES` | owner の後。どの ring も実行中でない |
| `SET_MEM_TABLE` | owner と `SET_FEATURES` の後。どの ring も実行中でない。送り直しでは古い `GuestMemory` を先に drop し、ring のアドレス検証結果を無効にして `SET_VRING_ADDR` からやり直させる |
| `SET_VRING_NUM` / `SET_VRING_BASE` | owner の後。番号 < 2。その ring が実行中でない。base は u16 に収まる（収まらなければ `INVALID_VALUE`） |
| `SET_VRING_ADDR` | `SET_MEM_TABLE` と `SET_VRING_NUM` の後。`QueueConfig::new` で検証 |
| `SET_VRING_KICK` / `SET_VRING_CALL` | `SET_MEM_TABLE` の後。`VRING_NOFD`（polling）は `NOFD_UNSUPPORTED` |
| `SET_VRING_ENABLE` | bit 30 が確定済みで ADDR が設定済み。値は 0 / 1 |
| `GET_VRING_BASE` | ring を停止し kick / call を閉じて `last_avail` を返す |
| `SET_CONFIG` | 未対応として `UNSUPPORTED_REQUEST` |

- ring の起動: ADDR・KICK・CALL・ENABLE(1) がそろった時点で `SplitQueue::new(cfg, base, base)`。初期の used_idx は base とする（新規開始では 0。inflight は扱わない割り切り）
- fd の個数: `SET_MEM_TABLE` は領域数、NOFD でない kick / call は 1、それ以外は 0。復号の後に照合し、合わなければ `FD_COUNT_MISMATCH` / `UNEXPECTED_FDS`。受け取った fd は `OwnedFd` で、どのエラー経路でも `Drop` で閉じる。fd は各メッセージの最初の受信でだけ受け付ける
- タイムアウト（REPAIR-5）: `SessionLimits` の `message_timeout`（1 メッセージの受信・応答送信・call の書き込み。超過は `TIMEOUT`）と `idle_timeout`（無通信。超過は `IDLE_TIMEOUT`）。どちらも 0 より大きく 1 時間以下
- 応答ループ: socket と ctrl キューの kick を、単一 fd 用の `sys::wait_fd` で `poll_slice`（既定 10ms）ずつ交互に待つ。1 回の kick で最大 `num` 件を処理して used へ書き、1 件以上なら call へ 1 を書く。`pop` / `add_used` の失敗はセッションを終了する（壊れたキューを黙って続けない）。writable が応答に足りない要求は応答を捨てて len=0 で返し、`response_dropped` の行を出してセッションは続ける。readable が 4 KiB を超える要求はアダプタへ渡さず `ERR_INVALID_PARAMETER`
- ログ: 既存の `venus_jig event=...` 形式を保つ。追加は `session_error`（`code`・`request`）・`need_reply_ignored`・`response_dropped`・`session_end`。固定語彙と数値だけで、frontend やゲスト由来のバイト列・fd 番号・GPA は出さない
- 扱わない（REPAIR-3）: `NEED_REPLY`（REPLY_ACK を広告しないので `SET_*` には応答せず、ログに 1 行出す）、cursorq（ring 1）の要求処理、`SET_CONFIG`、`VRING_NOFD`、inflight、`INDIRECT` / `EVENT_IDX`、`observe::snapshot_lines` の定期出力と virtqueue 個別の観測カウンタ（終了時の集計出力は `session::run` で実装済み）
- peer credential の検証（PLUG-12）は起動入口が accept 直後に `SO_PEERCRED`（`sys::peer_uid`＝U11）で行い、`session::run` は照合済みの `UnixStream` を受け取る API に留める。UDS の bind と所有者・権限・symlink の検証は起動入口（10.9）が行う。治具は PoC で、実機の実行は人間が担当する閉じた環境という前提
- 承認事項: socket と kick を同時に待つ複数 fd の `ppoll` は `sys.rs` の `unsafe`（U10）の変更になるため行っていない。kick への反応に最大 `poll_slice` の遅延が乗る

### 10.9 起動入口（F4・#1598）

`launch`（lib）と bin `venus-jig` が、UDS の bind・期限つき accept・ログのファイル出力を担う。Linux 限定。1 接続を `session::run` で最後まで処理して終わる（実機の疎通は #725）。

- 引数: `--socket <絶対パス>`・`--log <絶対パス>`（必須）、`--message-timeout-ms`（既定 5000）・`--idle-timeout-ms`（既定 60000）・`--poll-slice-ms`・`--accept-timeout-ms`（既定 60000、0 より大きく 1 時間以下）。VMM 側から指定するのは `--socket` に渡した絶対パス。記録ファイルのパスは #1602 で足す
- bind 前の検証（拒否時は何も作らず、既存のパスは消さない）: 絶対パス・成分に `.` / `..` / 空がない・NUL なし・ソケットとログが別パス（`PATH_NOT_ABSOLUTE` / `PATH_INVALID`）、ソケットパスが `sun_path` の 107 バイト以下（`PATH_TOO_LONG`。`linux/un.h` の `UNIX_PATH_MAX` 108 から NUL を除く）、ソケットの親ディレクトリが symlink でない・ディレクトリ・実行ユーザー（`/proc/self/status` の effective UID）の所有・モード `0700`（`SOCKET_DIR_SYMLINK` / `SOCKET_DIR_NOT_DIRECTORY` / `SOCKET_DIR_NOT_OWNED` / `SOCKET_DIR_NOT_PRIVATE`）、`/` までの祖先が存在し（無ければ拒否。検査後に別 UID が作って差し替えるのを防ぐ。ログの置き場所も同じ規則で `LOG_DIR_UNSAFE`）、symlink でなく自 UID か root の所有で、グループ／他者が書ける場合は sticky が立っている（`SOCKET_DIR_ANCESTOR_UNSAFE`。別 UID の rename 差し替えを防ぐ）、ソケットパスに何もない（`SOCKET_PATH_EXISTS`）。ソケットディレクトリ自身が無ければ（その親は検証済みで存在が必須）1 段だけ `DirBuilder` の mode `0700` で作る
- ログ: `create_new` + `0600`（既存は `LOG_PATH_EXISTS`、symlink も `O_EXCL` で失敗）。`log::LogSink` が総量 4 MiB・1 行 512 バイト・10 万行の照合器の上限に収め、超えたら `venus_jig event=log_truncated reason=limit` を 1 回だけ書いて以降を捨てる。パス文字列・ゲスト由来のバイト列は出さない
- 実行時エラーは stderr に 1 行の JSON `{"code","message"}`（`SESSION_FAILED` のみ `cause` にセッションの code）。終了コードは検証エラー 2、それ以外の失敗 1、正常終了 0
- accept は非ブロックの sleep ループ（10ms 刻み、期限切れは `ACCEPT_TIMEOUT`）。`sys::wait_fd`（ppoll）の listener fd への別用途の呼び出しは承認範囲外のため採らなかった（承認されれば置き換え可能な改善案）。1 接続を受けたら listener を閉じてソケットファイルを消す
- peer credential（PLUG-12）: accept 直後に `sys::peer_uid`（`getsockopt(SO_PEERCRED)`。U11）で接続元 UID を取得し、実行ユーザーの effective UID と照合する。不一致（`PEER_UID_MISMATCH`）・取得失敗（`PEER_CRED_UNAVAILABLE`）は接続を閉じて拒否する（fail-closed）。加えてソケットディレクトリを自 UID 所有・`0700` に限る。限界は、同じ UID の別プロセスは接続できること、検査と bind の間の TOCTOU は、祖先が他 UID に差し替え不能であることと所有者が自分で `0700` のディレクトリであることで抑えるに留まること（同じ UID と root は差し替えられる。祖先に symlink がある環境は拒否される）。別 UID の接続拒否は別 UID を用意できないため実機前提で、単体試験は期待 UID をずらして照合関数を検証する。U11 は `sys` モジュールの事前承認（coding-rust.md）の条件で追加した。
- ログ読み取り側（事後監査 #1528 D2）: `log::read_log_file` が open 前に `symlink_metadata` で通常ファイル以外（FIFO・symlink・ディレクトリ）を拒否し、open 後も `metadata` で確かめ直し、上限つきで読む。(1) と open の間に FIFO へ差し替える競合は残る。実機前提テストは読み取りを補助スレッドで動かし 30 秒の `recv_timeout` で待つ

## 11. 以降の章（未着手。10 章は #888 の範囲）

| 章 | 内容 | 担当 issue |
| -- | ---- | ---------- |
| 1〜3 段目の結果 | 段階的な再検証の結果 | #725 |
| 3 段目の実機判定 | VZCustomVirtioDevice 登録の実機結果と VMM 方式の判定 | #1057（TASK-172.h5。人間担当） |
| 最終確定 | 対象サブセットの確定 | #726（TASK-172.h2。人間担当） |
