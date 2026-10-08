//! venus コマンドのヘッダ（種別＋フラグ）と候補コマンド表（GPU-6・TASK-172.2）。
//!
//! ストリーム上のコマンドは「DW0 = `VkCommandTypeEXT`、DW1 = `VkCommandFlagsEXT`、DW2.. = 引数」で、
//! 長さは種別から暗黙に決まり明示されない。したがって未知の種別は読み飛ばせず、ストリーム全体を
//! 拒否する（fail-closed。`docs/design/venus-decoder-poc.md` の申し送り）。
//!
//! 出典: virgl/venus-protocol タグ `v1.1.3`（コミット `ca19b6358d7c`）の
//! `xmls/VK_EXT_command_serialization.xml`（SHA-256 `2451e5dcc5306f604c52da48a8cc883a24de708dd86f38bbb035d29a753a0474`）
//! の `VkCommandTypeEXT` 値と `VkCommandFlagBitsEXT`、および `docs/VK_EXT_command_serialization.txt`。
//! 種別は TASK-172.1 の候補 116 件（必須 62・推奨 22・保留 32）に限る。優先度は抽出時点の見立てで、
//! 対象サブセットの確定（#726）・フィルタ機構（#781）まで確定扱いにしない。
//!
//! 将来の呼び出し元: ring／コマンドストリーム実行（#765）がヘッダを読み、続く引数を各ハンドラ
//! （TASK-177.x）が [`super::WireReader`] で読む。現時点で呼び出し元はない（独立した骨格）。

use super::error::VenusWireError;
use super::reader::WireReader;

/// 候補コマンドの優先度（TASK-172.1 の見立て。確定ではない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPriority {
    Required,
    Recommended,
    Deferred,
}

/// 候補コマンド種別（`VkCommandTypeEXT` の値。候補 116 件のみ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum CommandType {
    // --- 3.1 プロトコル制御（venus 固有） ---
    SetReplyCommandStreamMESA = 178,
    SeekReplyCommandStreamMESA = 179,
    ExecuteCommandStreamsMESA = 180,
    CreateRingMESA = 188,
    DestroyRingMESA = 189,
    NotifyRingMESA = 190,
    WriteRingExtraMESA = 191,
    GetMemoryResourcePropertiesMESA = 192,
    ResetFenceResourceMESA = 244,
    WaitSemaphoreResourceMESA = 245,
    ImportSemaphoreResourceMESA = 246,
    SubmitVirtqueueSeqnoMESA = 251,
    WaitVirtqueueSeqnoMESA = 252,
    WaitRingSeqnoMESA = 253,
    CopyImageToMemoryMESA = 297,
    CopyMemoryToImageMESA = 298,
    WriteSamplerDescriptorMESA = 335,
    WriteResourceDescriptorMESA = 336,
    // --- 3.2 インスタンス・物理デバイス ---
    EnumerateInstanceVersion = 137,
    EnumerateInstanceExtensionProperties = 13,
    CreateInstance = 0,
    DestroyInstance = 1,
    EnumeratePhysicalDevices = 2,
    EnumerateDeviceExtensionProperties = 14,
    GetPhysicalDeviceFeatures2 = 147,
    GetPhysicalDeviceProperties2 = 148,
    GetPhysicalDeviceQueueFamilyProperties2 = 151,
    GetPhysicalDeviceMemoryProperties2 = 152,
    GetPhysicalDeviceFormatProperties2 = 149,
    GetPhysicalDeviceImageFormatProperties2 = 150,
    EnumeratePhysicalDeviceGroups = 143,
    // --- 3.3 デバイス・キュー ---
    CreateDevice = 11,
    DestroyDevice = 12,
    GetDeviceQueue2 = 155,
    DeviceWaitIdle = 20,
    QueueWaitIdle = 19,
    QueueSubmit = 18,
    GetDeviceQueue = 17,
    QueueSubmit2 = 206,
    // --- 3.4 メモリ ---
    AllocateMemory = 21,
    FreeMemory = 22,
    BindBufferMemory2 = 138,
    BindImageMemory2 = 139,
    GetBufferMemoryRequirements2 = 145,
    GetImageMemoryRequirements2 = 144,
    MapMemory = 23,
    FlushMappedMemoryRanges = 25,
    InvalidateMappedMemoryRanges = 26,
    GetDeviceBufferMemoryRequirements = 230,
    // --- 3.5 バッファ・イメージ・サンプラ ---
    CreateBuffer = 50,
    DestroyBuffer = 51,
    CreateBufferView = 52,
    DestroyBufferView = 53,
    CreateImage = 54,
    DestroyImage = 55,
    CreateImageView = 57,
    DestroyImageView = 58,
    CreateSampler = 70,
    DestroySampler = 71,
    GetImageSubresourceLayout = 56,
    // --- 3.6 シェーダ・パイプライン・ディスクリプタ ---
    CreateShaderModule = 59,
    DestroyShaderModule = 60,
    CreatePipelineLayout = 68,
    DestroyPipelineLayout = 69,
    CreateComputePipelines = 66,
    DestroyPipeline = 67,
    CreateDescriptorSetLayout = 72,
    DestroyDescriptorSetLayout = 73,
    CreateDescriptorPool = 74,
    DestroyDescriptorPool = 75,
    AllocateDescriptorSets = 77,
    UpdateDescriptorSets = 79,
    ResetDescriptorPool = 76,
    FreeDescriptorSets = 78,
    CreatePipelineCache = 61,
    DestroyPipelineCache = 62,
    // --- 3.7 コマンドバッファ（記録・実行） ---
    CreateCommandPool = 85,
    DestroyCommandPool = 86,
    AllocateCommandBuffers = 88,
    FreeCommandBuffers = 89,
    BeginCommandBuffer = 90,
    EndCommandBuffer = 91,
    CmdBindPipeline = 93,
    CmdBindDescriptorSets = 103,
    CmdPushConstants = 132,
    CmdDispatch = 110,
    CmdPipelineBarrier = 126,
    ResetCommandBuffer = 92,
    ResetCommandPool = 87,
    CmdDispatchIndirect = 111,
    CmdPipelineBarrier2 = 204,
    CmdDispatchBase = 142,
    // --- 3.8 転送 ---
    CmdCopyBuffer = 112,
    CmdFillBuffer = 118,
    CmdCopyImage = 113,
    CmdCopyBufferToImage = 115,
    CmdCopyImageToBuffer = 116,
    CmdUpdateBuffer = 117,
    CmdClearColorImage = 119,
    CmdCopyBuffer2 = 207,
    // --- 3.9 同期 ---
    CreateFence = 35,
    DestroyFence = 36,
    WaitForFences = 39,
    ResetFences = 37,
    GetFenceStatus = 38,
    CreateSemaphore = 40,
    DestroySemaphore = 41,
    WaitSemaphores = 173,
    SignalSemaphore = 174,
    GetSemaphoreCounterValue = 172,
    CreateEvent = 42,
    DestroyEvent = 43,
    CmdSetEvent = 123,
    CreateQueryPool = 47,
    DestroyQueryPool = 48,
    CmdWriteTimestamp = 130,
}

impl CommandType {
    /// ワイヤ上の `VkCommandTypeEXT` 値。
    pub fn as_raw(self) -> u32 {
        self as u32
    }

    /// Vulkan のコマンド名。
    pub fn name(self) -> &'static str {
        match self {
            // --- 3.1 プロトコル制御（venus 固有） ---
            Self::SetReplyCommandStreamMESA => "vkSetReplyCommandStreamMESA",
            Self::SeekReplyCommandStreamMESA => "vkSeekReplyCommandStreamMESA",
            Self::ExecuteCommandStreamsMESA => "vkExecuteCommandStreamsMESA",
            Self::CreateRingMESA => "vkCreateRingMESA",
            Self::DestroyRingMESA => "vkDestroyRingMESA",
            Self::NotifyRingMESA => "vkNotifyRingMESA",
            Self::WriteRingExtraMESA => "vkWriteRingExtraMESA",
            Self::GetMemoryResourcePropertiesMESA => "vkGetMemoryResourcePropertiesMESA",
            Self::ResetFenceResourceMESA => "vkResetFenceResourceMESA",
            Self::WaitSemaphoreResourceMESA => "vkWaitSemaphoreResourceMESA",
            Self::ImportSemaphoreResourceMESA => "vkImportSemaphoreResourceMESA",
            Self::SubmitVirtqueueSeqnoMESA => "vkSubmitVirtqueueSeqnoMESA",
            Self::WaitVirtqueueSeqnoMESA => "vkWaitVirtqueueSeqnoMESA",
            Self::WaitRingSeqnoMESA => "vkWaitRingSeqnoMESA",
            Self::CopyImageToMemoryMESA => "vkCopyImageToMemoryMESA",
            Self::CopyMemoryToImageMESA => "vkCopyMemoryToImageMESA",
            Self::WriteSamplerDescriptorMESA => "vkWriteSamplerDescriptorMESA",
            Self::WriteResourceDescriptorMESA => "vkWriteResourceDescriptorMESA",
            // --- 3.2 インスタンス・物理デバイス ---
            Self::EnumerateInstanceVersion => "vkEnumerateInstanceVersion",
            Self::EnumerateInstanceExtensionProperties => "vkEnumerateInstanceExtensionProperties",
            Self::CreateInstance => "vkCreateInstance",
            Self::DestroyInstance => "vkDestroyInstance",
            Self::EnumeratePhysicalDevices => "vkEnumeratePhysicalDevices",
            Self::EnumerateDeviceExtensionProperties => "vkEnumerateDeviceExtensionProperties",
            Self::GetPhysicalDeviceFeatures2 => "vkGetPhysicalDeviceFeatures2",
            Self::GetPhysicalDeviceProperties2 => "vkGetPhysicalDeviceProperties2",
            Self::GetPhysicalDeviceQueueFamilyProperties2 => {
                "vkGetPhysicalDeviceQueueFamilyProperties2"
            }
            Self::GetPhysicalDeviceMemoryProperties2 => "vkGetPhysicalDeviceMemoryProperties2",
            Self::GetPhysicalDeviceFormatProperties2 => "vkGetPhysicalDeviceFormatProperties2",
            Self::GetPhysicalDeviceImageFormatProperties2 => {
                "vkGetPhysicalDeviceImageFormatProperties2"
            }
            Self::EnumeratePhysicalDeviceGroups => "vkEnumeratePhysicalDeviceGroups",
            // --- 3.3 デバイス・キュー ---
            Self::CreateDevice => "vkCreateDevice",
            Self::DestroyDevice => "vkDestroyDevice",
            Self::GetDeviceQueue2 => "vkGetDeviceQueue2",
            Self::DeviceWaitIdle => "vkDeviceWaitIdle",
            Self::QueueWaitIdle => "vkQueueWaitIdle",
            Self::QueueSubmit => "vkQueueSubmit",
            Self::GetDeviceQueue => "vkGetDeviceQueue",
            Self::QueueSubmit2 => "vkQueueSubmit2",
            // --- 3.4 メモリ ---
            Self::AllocateMemory => "vkAllocateMemory",
            Self::FreeMemory => "vkFreeMemory",
            Self::BindBufferMemory2 => "vkBindBufferMemory2",
            Self::BindImageMemory2 => "vkBindImageMemory2",
            Self::GetBufferMemoryRequirements2 => "vkGetBufferMemoryRequirements2",
            Self::GetImageMemoryRequirements2 => "vkGetImageMemoryRequirements2",
            Self::MapMemory => "vkMapMemory",
            Self::FlushMappedMemoryRanges => "vkFlushMappedMemoryRanges",
            Self::InvalidateMappedMemoryRanges => "vkInvalidateMappedMemoryRanges",
            Self::GetDeviceBufferMemoryRequirements => "vkGetDeviceBufferMemoryRequirements",
            // --- 3.5 バッファ・イメージ・サンプラ ---
            Self::CreateBuffer => "vkCreateBuffer",
            Self::DestroyBuffer => "vkDestroyBuffer",
            Self::CreateBufferView => "vkCreateBufferView",
            Self::DestroyBufferView => "vkDestroyBufferView",
            Self::CreateImage => "vkCreateImage",
            Self::DestroyImage => "vkDestroyImage",
            Self::CreateImageView => "vkCreateImageView",
            Self::DestroyImageView => "vkDestroyImageView",
            Self::CreateSampler => "vkCreateSampler",
            Self::DestroySampler => "vkDestroySampler",
            Self::GetImageSubresourceLayout => "vkGetImageSubresourceLayout",
            // --- 3.6 シェーダ・パイプライン・ディスクリプタ ---
            Self::CreateShaderModule => "vkCreateShaderModule",
            Self::DestroyShaderModule => "vkDestroyShaderModule",
            Self::CreatePipelineLayout => "vkCreatePipelineLayout",
            Self::DestroyPipelineLayout => "vkDestroyPipelineLayout",
            Self::CreateComputePipelines => "vkCreateComputePipelines",
            Self::DestroyPipeline => "vkDestroyPipeline",
            Self::CreateDescriptorSetLayout => "vkCreateDescriptorSetLayout",
            Self::DestroyDescriptorSetLayout => "vkDestroyDescriptorSetLayout",
            Self::CreateDescriptorPool => "vkCreateDescriptorPool",
            Self::DestroyDescriptorPool => "vkDestroyDescriptorPool",
            Self::AllocateDescriptorSets => "vkAllocateDescriptorSets",
            Self::UpdateDescriptorSets => "vkUpdateDescriptorSets",
            Self::ResetDescriptorPool => "vkResetDescriptorPool",
            Self::FreeDescriptorSets => "vkFreeDescriptorSets",
            Self::CreatePipelineCache => "vkCreatePipelineCache",
            Self::DestroyPipelineCache => "vkDestroyPipelineCache",
            // --- 3.7 コマンドバッファ（記録・実行） ---
            Self::CreateCommandPool => "vkCreateCommandPool",
            Self::DestroyCommandPool => "vkDestroyCommandPool",
            Self::AllocateCommandBuffers => "vkAllocateCommandBuffers",
            Self::FreeCommandBuffers => "vkFreeCommandBuffers",
            Self::BeginCommandBuffer => "vkBeginCommandBuffer",
            Self::EndCommandBuffer => "vkEndCommandBuffer",
            Self::CmdBindPipeline => "vkCmdBindPipeline",
            Self::CmdBindDescriptorSets => "vkCmdBindDescriptorSets",
            Self::CmdPushConstants => "vkCmdPushConstants",
            Self::CmdDispatch => "vkCmdDispatch",
            Self::CmdPipelineBarrier => "vkCmdPipelineBarrier",
            Self::ResetCommandBuffer => "vkResetCommandBuffer",
            Self::ResetCommandPool => "vkResetCommandPool",
            Self::CmdDispatchIndirect => "vkCmdDispatchIndirect",
            Self::CmdPipelineBarrier2 => "vkCmdPipelineBarrier2",
            Self::CmdDispatchBase => "vkCmdDispatchBase",
            // --- 3.8 転送 ---
            Self::CmdCopyBuffer => "vkCmdCopyBuffer",
            Self::CmdFillBuffer => "vkCmdFillBuffer",
            Self::CmdCopyImage => "vkCmdCopyImage",
            Self::CmdCopyBufferToImage => "vkCmdCopyBufferToImage",
            Self::CmdCopyImageToBuffer => "vkCmdCopyImageToBuffer",
            Self::CmdUpdateBuffer => "vkCmdUpdateBuffer",
            Self::CmdClearColorImage => "vkCmdClearColorImage",
            Self::CmdCopyBuffer2 => "vkCmdCopyBuffer2",
            // --- 3.9 同期 ---
            Self::CreateFence => "vkCreateFence",
            Self::DestroyFence => "vkDestroyFence",
            Self::WaitForFences => "vkWaitForFences",
            Self::ResetFences => "vkResetFences",
            Self::GetFenceStatus => "vkGetFenceStatus",
            Self::CreateSemaphore => "vkCreateSemaphore",
            Self::DestroySemaphore => "vkDestroySemaphore",
            Self::WaitSemaphores => "vkWaitSemaphores",
            Self::SignalSemaphore => "vkSignalSemaphore",
            Self::GetSemaphoreCounterValue => "vkGetSemaphoreCounterValue",
            Self::CreateEvent => "vkCreateEvent",
            Self::DestroyEvent => "vkDestroyEvent",
            Self::CmdSetEvent => "vkCmdSetEvent",
            Self::CreateQueryPool => "vkCreateQueryPool",
            Self::DestroyQueryPool => "vkDestroyQueryPool",
            Self::CmdWriteTimestamp => "vkCmdWriteTimestamp",
        }
    }

    /// 優先度（確定ではない。#726 で確定）。
    pub fn priority(self) -> CommandPriority {
        match self {
            // --- 3.1 プロトコル制御（venus 固有） ---
            Self::SetReplyCommandStreamMESA => CommandPriority::Required,
            Self::SeekReplyCommandStreamMESA => CommandPriority::Required,
            Self::ExecuteCommandStreamsMESA => CommandPriority::Required,
            Self::CreateRingMESA => CommandPriority::Required,
            Self::DestroyRingMESA => CommandPriority::Required,
            Self::NotifyRingMESA => CommandPriority::Required,
            Self::WriteRingExtraMESA => CommandPriority::Required,
            Self::GetMemoryResourcePropertiesMESA => CommandPriority::Recommended,
            Self::ResetFenceResourceMESA => CommandPriority::Recommended,
            Self::WaitSemaphoreResourceMESA => CommandPriority::Deferred,
            Self::ImportSemaphoreResourceMESA => CommandPriority::Deferred,
            Self::SubmitVirtqueueSeqnoMESA => CommandPriority::Deferred,
            Self::WaitVirtqueueSeqnoMESA => CommandPriority::Deferred,
            Self::WaitRingSeqnoMESA => CommandPriority::Deferred,
            Self::CopyImageToMemoryMESA => CommandPriority::Deferred,
            Self::CopyMemoryToImageMESA => CommandPriority::Deferred,
            Self::WriteSamplerDescriptorMESA => CommandPriority::Deferred,
            Self::WriteResourceDescriptorMESA => CommandPriority::Deferred,
            // --- 3.2 インスタンス・物理デバイス ---
            Self::EnumerateInstanceVersion => CommandPriority::Required,
            Self::EnumerateInstanceExtensionProperties => CommandPriority::Required,
            Self::CreateInstance => CommandPriority::Required,
            Self::DestroyInstance => CommandPriority::Required,
            Self::EnumeratePhysicalDevices => CommandPriority::Required,
            Self::EnumerateDeviceExtensionProperties => CommandPriority::Required,
            Self::GetPhysicalDeviceFeatures2 => CommandPriority::Required,
            Self::GetPhysicalDeviceProperties2 => CommandPriority::Required,
            Self::GetPhysicalDeviceQueueFamilyProperties2 => CommandPriority::Required,
            Self::GetPhysicalDeviceMemoryProperties2 => CommandPriority::Required,
            Self::GetPhysicalDeviceFormatProperties2 => CommandPriority::Required,
            Self::GetPhysicalDeviceImageFormatProperties2 => CommandPriority::Recommended,
            Self::EnumeratePhysicalDeviceGroups => CommandPriority::Deferred,
            // --- 3.3 デバイス・キュー ---
            Self::CreateDevice => CommandPriority::Required,
            Self::DestroyDevice => CommandPriority::Required,
            Self::GetDeviceQueue2 => CommandPriority::Required,
            Self::DeviceWaitIdle => CommandPriority::Required,
            Self::QueueWaitIdle => CommandPriority::Required,
            Self::QueueSubmit => CommandPriority::Required,
            Self::GetDeviceQueue => CommandPriority::Recommended,
            Self::QueueSubmit2 => CommandPriority::Deferred,
            // --- 3.4 メモリ ---
            Self::AllocateMemory => CommandPriority::Required,
            Self::FreeMemory => CommandPriority::Required,
            Self::BindBufferMemory2 => CommandPriority::Required,
            Self::BindImageMemory2 => CommandPriority::Required,
            Self::GetBufferMemoryRequirements2 => CommandPriority::Required,
            Self::GetImageMemoryRequirements2 => CommandPriority::Required,
            Self::MapMemory => CommandPriority::Deferred,
            Self::FlushMappedMemoryRanges => CommandPriority::Deferred,
            Self::InvalidateMappedMemoryRanges => CommandPriority::Deferred,
            Self::GetDeviceBufferMemoryRequirements => CommandPriority::Deferred,
            // --- 3.5 バッファ・イメージ・サンプラ ---
            Self::CreateBuffer => CommandPriority::Required,
            Self::DestroyBuffer => CommandPriority::Required,
            Self::CreateBufferView => CommandPriority::Recommended,
            Self::DestroyBufferView => CommandPriority::Recommended,
            Self::CreateImage => CommandPriority::Recommended,
            Self::DestroyImage => CommandPriority::Recommended,
            Self::CreateImageView => CommandPriority::Recommended,
            Self::DestroyImageView => CommandPriority::Recommended,
            Self::CreateSampler => CommandPriority::Deferred,
            Self::DestroySampler => CommandPriority::Deferred,
            Self::GetImageSubresourceLayout => CommandPriority::Deferred,
            // --- 3.6 シェーダ・パイプライン・ディスクリプタ ---
            Self::CreateShaderModule => CommandPriority::Required,
            Self::DestroyShaderModule => CommandPriority::Required,
            Self::CreatePipelineLayout => CommandPriority::Required,
            Self::DestroyPipelineLayout => CommandPriority::Required,
            Self::CreateComputePipelines => CommandPriority::Required,
            Self::DestroyPipeline => CommandPriority::Required,
            Self::CreateDescriptorSetLayout => CommandPriority::Required,
            Self::DestroyDescriptorSetLayout => CommandPriority::Required,
            Self::CreateDescriptorPool => CommandPriority::Required,
            Self::DestroyDescriptorPool => CommandPriority::Required,
            Self::AllocateDescriptorSets => CommandPriority::Required,
            Self::UpdateDescriptorSets => CommandPriority::Required,
            Self::ResetDescriptorPool => CommandPriority::Recommended,
            Self::FreeDescriptorSets => CommandPriority::Recommended,
            Self::CreatePipelineCache => CommandPriority::Deferred,
            Self::DestroyPipelineCache => CommandPriority::Deferred,
            // --- 3.7 コマンドバッファ（記録・実行） ---
            Self::CreateCommandPool => CommandPriority::Required,
            Self::DestroyCommandPool => CommandPriority::Required,
            Self::AllocateCommandBuffers => CommandPriority::Required,
            Self::FreeCommandBuffers => CommandPriority::Required,
            Self::BeginCommandBuffer => CommandPriority::Required,
            Self::EndCommandBuffer => CommandPriority::Required,
            Self::CmdBindPipeline => CommandPriority::Required,
            Self::CmdBindDescriptorSets => CommandPriority::Required,
            Self::CmdPushConstants => CommandPriority::Required,
            Self::CmdDispatch => CommandPriority::Required,
            Self::CmdPipelineBarrier => CommandPriority::Required,
            Self::ResetCommandBuffer => CommandPriority::Recommended,
            Self::ResetCommandPool => CommandPriority::Recommended,
            Self::CmdDispatchIndirect => CommandPriority::Recommended,
            Self::CmdPipelineBarrier2 => CommandPriority::Deferred,
            Self::CmdDispatchBase => CommandPriority::Deferred,
            // --- 3.8 転送 ---
            Self::CmdCopyBuffer => CommandPriority::Required,
            Self::CmdFillBuffer => CommandPriority::Required,
            Self::CmdCopyImage => CommandPriority::Recommended,
            Self::CmdCopyBufferToImage => CommandPriority::Recommended,
            Self::CmdCopyImageToBuffer => CommandPriority::Recommended,
            Self::CmdUpdateBuffer => CommandPriority::Recommended,
            Self::CmdClearColorImage => CommandPriority::Recommended,
            Self::CmdCopyBuffer2 => CommandPriority::Deferred,
            // --- 3.9 同期 ---
            Self::CreateFence => CommandPriority::Required,
            Self::DestroyFence => CommandPriority::Required,
            Self::WaitForFences => CommandPriority::Required,
            Self::ResetFences => CommandPriority::Required,
            Self::GetFenceStatus => CommandPriority::Required,
            Self::CreateSemaphore => CommandPriority::Recommended,
            Self::DestroySemaphore => CommandPriority::Recommended,
            Self::WaitSemaphores => CommandPriority::Deferred,
            Self::SignalSemaphore => CommandPriority::Deferred,
            Self::GetSemaphoreCounterValue => CommandPriority::Deferred,
            Self::CreateEvent => CommandPriority::Deferred,
            Self::DestroyEvent => CommandPriority::Deferred,
            Self::CmdSetEvent => CommandPriority::Deferred,
            Self::CreateQueryPool => CommandPriority::Deferred,
            Self::DestroyQueryPool => CommandPriority::Deferred,
            Self::CmdWriteTimestamp => CommandPriority::Deferred,
        }
    }
}

impl TryFrom<u32> for CommandType {
    type Error = VenusWireError;

    /// 候補外・未知の値は `UnsupportedCommand`（黙って無視しない）。
    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        match raw {
            // --- 3.1 プロトコル制御（venus 固有） ---
            178 => Ok(Self::SetReplyCommandStreamMESA),
            179 => Ok(Self::SeekReplyCommandStreamMESA),
            180 => Ok(Self::ExecuteCommandStreamsMESA),
            188 => Ok(Self::CreateRingMESA),
            189 => Ok(Self::DestroyRingMESA),
            190 => Ok(Self::NotifyRingMESA),
            191 => Ok(Self::WriteRingExtraMESA),
            192 => Ok(Self::GetMemoryResourcePropertiesMESA),
            244 => Ok(Self::ResetFenceResourceMESA),
            245 => Ok(Self::WaitSemaphoreResourceMESA),
            246 => Ok(Self::ImportSemaphoreResourceMESA),
            251 => Ok(Self::SubmitVirtqueueSeqnoMESA),
            252 => Ok(Self::WaitVirtqueueSeqnoMESA),
            253 => Ok(Self::WaitRingSeqnoMESA),
            297 => Ok(Self::CopyImageToMemoryMESA),
            298 => Ok(Self::CopyMemoryToImageMESA),
            335 => Ok(Self::WriteSamplerDescriptorMESA),
            336 => Ok(Self::WriteResourceDescriptorMESA),
            // --- 3.2 インスタンス・物理デバイス ---
            137 => Ok(Self::EnumerateInstanceVersion),
            13 => Ok(Self::EnumerateInstanceExtensionProperties),
            0 => Ok(Self::CreateInstance),
            1 => Ok(Self::DestroyInstance),
            2 => Ok(Self::EnumeratePhysicalDevices),
            14 => Ok(Self::EnumerateDeviceExtensionProperties),
            147 => Ok(Self::GetPhysicalDeviceFeatures2),
            148 => Ok(Self::GetPhysicalDeviceProperties2),
            151 => Ok(Self::GetPhysicalDeviceQueueFamilyProperties2),
            152 => Ok(Self::GetPhysicalDeviceMemoryProperties2),
            149 => Ok(Self::GetPhysicalDeviceFormatProperties2),
            150 => Ok(Self::GetPhysicalDeviceImageFormatProperties2),
            143 => Ok(Self::EnumeratePhysicalDeviceGroups),
            // --- 3.3 デバイス・キュー ---
            11 => Ok(Self::CreateDevice),
            12 => Ok(Self::DestroyDevice),
            155 => Ok(Self::GetDeviceQueue2),
            20 => Ok(Self::DeviceWaitIdle),
            19 => Ok(Self::QueueWaitIdle),
            18 => Ok(Self::QueueSubmit),
            17 => Ok(Self::GetDeviceQueue),
            206 => Ok(Self::QueueSubmit2),
            // --- 3.4 メモリ ---
            21 => Ok(Self::AllocateMemory),
            22 => Ok(Self::FreeMemory),
            138 => Ok(Self::BindBufferMemory2),
            139 => Ok(Self::BindImageMemory2),
            145 => Ok(Self::GetBufferMemoryRequirements2),
            144 => Ok(Self::GetImageMemoryRequirements2),
            23 => Ok(Self::MapMemory),
            25 => Ok(Self::FlushMappedMemoryRanges),
            26 => Ok(Self::InvalidateMappedMemoryRanges),
            230 => Ok(Self::GetDeviceBufferMemoryRequirements),
            // --- 3.5 バッファ・イメージ・サンプラ ---
            50 => Ok(Self::CreateBuffer),
            51 => Ok(Self::DestroyBuffer),
            52 => Ok(Self::CreateBufferView),
            53 => Ok(Self::DestroyBufferView),
            54 => Ok(Self::CreateImage),
            55 => Ok(Self::DestroyImage),
            57 => Ok(Self::CreateImageView),
            58 => Ok(Self::DestroyImageView),
            70 => Ok(Self::CreateSampler),
            71 => Ok(Self::DestroySampler),
            56 => Ok(Self::GetImageSubresourceLayout),
            // --- 3.6 シェーダ・パイプライン・ディスクリプタ ---
            59 => Ok(Self::CreateShaderModule),
            60 => Ok(Self::DestroyShaderModule),
            68 => Ok(Self::CreatePipelineLayout),
            69 => Ok(Self::DestroyPipelineLayout),
            66 => Ok(Self::CreateComputePipelines),
            67 => Ok(Self::DestroyPipeline),
            72 => Ok(Self::CreateDescriptorSetLayout),
            73 => Ok(Self::DestroyDescriptorSetLayout),
            74 => Ok(Self::CreateDescriptorPool),
            75 => Ok(Self::DestroyDescriptorPool),
            77 => Ok(Self::AllocateDescriptorSets),
            79 => Ok(Self::UpdateDescriptorSets),
            76 => Ok(Self::ResetDescriptorPool),
            78 => Ok(Self::FreeDescriptorSets),
            61 => Ok(Self::CreatePipelineCache),
            62 => Ok(Self::DestroyPipelineCache),
            // --- 3.7 コマンドバッファ（記録・実行） ---
            85 => Ok(Self::CreateCommandPool),
            86 => Ok(Self::DestroyCommandPool),
            88 => Ok(Self::AllocateCommandBuffers),
            89 => Ok(Self::FreeCommandBuffers),
            90 => Ok(Self::BeginCommandBuffer),
            91 => Ok(Self::EndCommandBuffer),
            93 => Ok(Self::CmdBindPipeline),
            103 => Ok(Self::CmdBindDescriptorSets),
            132 => Ok(Self::CmdPushConstants),
            110 => Ok(Self::CmdDispatch),
            126 => Ok(Self::CmdPipelineBarrier),
            92 => Ok(Self::ResetCommandBuffer),
            87 => Ok(Self::ResetCommandPool),
            111 => Ok(Self::CmdDispatchIndirect),
            204 => Ok(Self::CmdPipelineBarrier2),
            142 => Ok(Self::CmdDispatchBase),
            // --- 3.8 転送 ---
            112 => Ok(Self::CmdCopyBuffer),
            118 => Ok(Self::CmdFillBuffer),
            113 => Ok(Self::CmdCopyImage),
            115 => Ok(Self::CmdCopyBufferToImage),
            116 => Ok(Self::CmdCopyImageToBuffer),
            117 => Ok(Self::CmdUpdateBuffer),
            119 => Ok(Self::CmdClearColorImage),
            207 => Ok(Self::CmdCopyBuffer2),
            // --- 3.9 同期 ---
            35 => Ok(Self::CreateFence),
            36 => Ok(Self::DestroyFence),
            39 => Ok(Self::WaitForFences),
            37 => Ok(Self::ResetFences),
            38 => Ok(Self::GetFenceStatus),
            40 => Ok(Self::CreateSemaphore),
            41 => Ok(Self::DestroySemaphore),
            173 => Ok(Self::WaitSemaphores),
            174 => Ok(Self::SignalSemaphore),
            172 => Ok(Self::GetSemaphoreCounterValue),
            42 => Ok(Self::CreateEvent),
            43 => Ok(Self::DestroyEvent),
            123 => Ok(Self::CmdSetEvent),
            47 => Ok(Self::CreateQueryPool),
            48 => Ok(Self::DestroyQueryPool),
            130 => Ok(Self::CmdWriteTimestamp),
            _ => Err(VenusWireError::UnsupportedCommand { raw }),
        }
    }
}

/// `VkCommandFlagsEXT`。定義済みビットは `VK_COMMAND_GENERATE_REPLY_BIT_EXT`（bit 0）のみ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFlags(u32);

impl CommandFlags {
    const GENERATE_REPLY: u32 = 1;

    /// 定義外ビットが立っていれば拒否する（fail-closed）。
    pub fn from_raw(raw: u32) -> Result<Self, VenusWireError> {
        if raw & !Self::GENERATE_REPLY != 0 {
            return Err(VenusWireError::InvalidFlags { raw });
        }
        Ok(Self(raw))
    }

    pub fn as_raw(self) -> u32 {
        self.0
    }

    /// 応答ストリームへの reply 生成を要求しているか。
    pub fn generates_reply(self) -> bool {
        self.0 & Self::GENERATE_REPLY != 0
    }
}

/// コマンドヘッダ（8 バイト）。引数はリーダに残る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    pub command: CommandType,
    pub flags: CommandFlags,
}

/// ヘッダ長（バイト）。
pub const COMMAND_HEADER_LEN: usize = 8;

/// ヘッダを読む。引数以降は読まない（各ハンドラが続きを読む）。
pub fn parse_command_header(r: &mut WireReader<'_>) -> Result<CommandHeader, VenusWireError> {
    let command = CommandType::try_from(r.read_u32()?)?;
    let flags = CommandFlags::from_raw(r.read_u32()?)?;
    Ok(CommandHeader { command, flags })
}
