//! venus wire パース骨格の単体テスト（GPU-6・TASK-172.2）。3 OS 共通（cfg なし）。

use super::*;

/// 候補 116 件の (名前, ID, 優先度)。出典: venus-protocol v1.1.3（コミット `ca19b6358d7c`）の
/// `xmls/VK_EXT_command_serialization.xml`（SHA-256 `2451e5dc…0a474`）と TASK-172.1 の優先度。
const TABLE: &[(&str, u32, CommandPriority)] = &[
    (
        "vkSetReplyCommandStreamMESA",
        178,
        CommandPriority::Required,
    ),
    (
        "vkSeekReplyCommandStreamMESA",
        179,
        CommandPriority::Required,
    ),
    (
        "vkExecuteCommandStreamsMESA",
        180,
        CommandPriority::Required,
    ),
    ("vkCreateRingMESA", 188, CommandPriority::Required),
    ("vkDestroyRingMESA", 189, CommandPriority::Required),
    ("vkNotifyRingMESA", 190, CommandPriority::Required),
    ("vkWriteRingExtraMESA", 191, CommandPriority::Required),
    (
        "vkGetMemoryResourcePropertiesMESA",
        192,
        CommandPriority::Recommended,
    ),
    (
        "vkResetFenceResourceMESA",
        244,
        CommandPriority::Recommended,
    ),
    (
        "vkWaitSemaphoreResourceMESA",
        245,
        CommandPriority::Deferred,
    ),
    (
        "vkImportSemaphoreResourceMESA",
        246,
        CommandPriority::Deferred,
    ),
    ("vkSubmitVirtqueueSeqnoMESA", 251, CommandPriority::Deferred),
    ("vkWaitVirtqueueSeqnoMESA", 252, CommandPriority::Deferred),
    ("vkWaitRingSeqnoMESA", 253, CommandPriority::Deferred),
    ("vkCopyImageToMemoryMESA", 297, CommandPriority::Deferred),
    ("vkCopyMemoryToImageMESA", 298, CommandPriority::Deferred),
    (
        "vkWriteSamplerDescriptorMESA",
        335,
        CommandPriority::Deferred,
    ),
    (
        "vkWriteResourceDescriptorMESA",
        336,
        CommandPriority::Deferred,
    ),
    ("vkEnumerateInstanceVersion", 137, CommandPriority::Required),
    (
        "vkEnumerateInstanceExtensionProperties",
        13,
        CommandPriority::Required,
    ),
    ("vkCreateInstance", 0, CommandPriority::Required),
    ("vkDestroyInstance", 1, CommandPriority::Required),
    ("vkEnumeratePhysicalDevices", 2, CommandPriority::Required),
    (
        "vkEnumerateDeviceExtensionProperties",
        14,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceFeatures2",
        147,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceProperties2",
        148,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceQueueFamilyProperties2",
        151,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceMemoryProperties2",
        152,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceFormatProperties2",
        149,
        CommandPriority::Required,
    ),
    (
        "vkGetPhysicalDeviceImageFormatProperties2",
        150,
        CommandPriority::Recommended,
    ),
    (
        "vkEnumeratePhysicalDeviceGroups",
        143,
        CommandPriority::Deferred,
    ),
    ("vkCreateDevice", 11, CommandPriority::Required),
    ("vkDestroyDevice", 12, CommandPriority::Required),
    ("vkGetDeviceQueue2", 155, CommandPriority::Required),
    ("vkDeviceWaitIdle", 20, CommandPriority::Required),
    ("vkQueueWaitIdle", 19, CommandPriority::Required),
    ("vkQueueSubmit", 18, CommandPriority::Required),
    ("vkGetDeviceQueue", 17, CommandPriority::Recommended),
    ("vkQueueSubmit2", 206, CommandPriority::Deferred),
    ("vkAllocateMemory", 21, CommandPriority::Required),
    ("vkFreeMemory", 22, CommandPriority::Required),
    ("vkBindBufferMemory2", 138, CommandPriority::Required),
    ("vkBindImageMemory2", 139, CommandPriority::Required),
    (
        "vkGetBufferMemoryRequirements2",
        145,
        CommandPriority::Required,
    ),
    (
        "vkGetImageMemoryRequirements2",
        144,
        CommandPriority::Required,
    ),
    ("vkMapMemory", 23, CommandPriority::Deferred),
    ("vkFlushMappedMemoryRanges", 25, CommandPriority::Deferred),
    (
        "vkInvalidateMappedMemoryRanges",
        26,
        CommandPriority::Deferred,
    ),
    (
        "vkGetDeviceBufferMemoryRequirements",
        230,
        CommandPriority::Deferred,
    ),
    ("vkCreateBuffer", 50, CommandPriority::Required),
    ("vkDestroyBuffer", 51, CommandPriority::Required),
    ("vkCreateBufferView", 52, CommandPriority::Recommended),
    ("vkDestroyBufferView", 53, CommandPriority::Recommended),
    ("vkCreateImage", 54, CommandPriority::Recommended),
    ("vkDestroyImage", 55, CommandPriority::Recommended),
    ("vkCreateImageView", 57, CommandPriority::Recommended),
    ("vkDestroyImageView", 58, CommandPriority::Recommended),
    ("vkCreateSampler", 70, CommandPriority::Deferred),
    ("vkDestroySampler", 71, CommandPriority::Deferred),
    ("vkGetImageSubresourceLayout", 56, CommandPriority::Deferred),
    ("vkCreateShaderModule", 59, CommandPriority::Required),
    ("vkDestroyShaderModule", 60, CommandPriority::Required),
    ("vkCreatePipelineLayout", 68, CommandPriority::Required),
    ("vkDestroyPipelineLayout", 69, CommandPriority::Required),
    ("vkCreateComputePipelines", 66, CommandPriority::Required),
    ("vkDestroyPipeline", 67, CommandPriority::Required),
    ("vkCreateDescriptorSetLayout", 72, CommandPriority::Required),
    (
        "vkDestroyDescriptorSetLayout",
        73,
        CommandPriority::Required,
    ),
    ("vkCreateDescriptorPool", 74, CommandPriority::Required),
    ("vkDestroyDescriptorPool", 75, CommandPriority::Required),
    ("vkAllocateDescriptorSets", 77, CommandPriority::Required),
    ("vkUpdateDescriptorSets", 79, CommandPriority::Required),
    ("vkResetDescriptorPool", 76, CommandPriority::Recommended),
    ("vkFreeDescriptorSets", 78, CommandPriority::Recommended),
    ("vkCreatePipelineCache", 61, CommandPriority::Deferred),
    ("vkDestroyPipelineCache", 62, CommandPriority::Deferred),
    ("vkCreateCommandPool", 85, CommandPriority::Required),
    ("vkDestroyCommandPool", 86, CommandPriority::Required),
    ("vkAllocateCommandBuffers", 88, CommandPriority::Required),
    ("vkFreeCommandBuffers", 89, CommandPriority::Required),
    ("vkBeginCommandBuffer", 90, CommandPriority::Required),
    ("vkEndCommandBuffer", 91, CommandPriority::Required),
    ("vkCmdBindPipeline", 93, CommandPriority::Required),
    ("vkCmdBindDescriptorSets", 103, CommandPriority::Required),
    ("vkCmdPushConstants", 132, CommandPriority::Required),
    ("vkCmdDispatch", 110, CommandPriority::Required),
    ("vkCmdPipelineBarrier", 126, CommandPriority::Required),
    ("vkResetCommandBuffer", 92, CommandPriority::Recommended),
    ("vkResetCommandPool", 87, CommandPriority::Recommended),
    ("vkCmdDispatchIndirect", 111, CommandPriority::Recommended),
    ("vkCmdPipelineBarrier2", 204, CommandPriority::Deferred),
    ("vkCmdDispatchBase", 142, CommandPriority::Deferred),
    ("vkCmdCopyBuffer", 112, CommandPriority::Required),
    ("vkCmdFillBuffer", 118, CommandPriority::Required),
    ("vkCmdCopyImage", 113, CommandPriority::Recommended),
    ("vkCmdCopyBufferToImage", 115, CommandPriority::Recommended),
    ("vkCmdCopyImageToBuffer", 116, CommandPriority::Recommended),
    ("vkCmdUpdateBuffer", 117, CommandPriority::Recommended),
    ("vkCmdClearColorImage", 119, CommandPriority::Recommended),
    ("vkCmdCopyBuffer2", 207, CommandPriority::Deferred),
    ("vkCreateFence", 35, CommandPriority::Required),
    ("vkDestroyFence", 36, CommandPriority::Required),
    ("vkWaitForFences", 39, CommandPriority::Required),
    ("vkResetFences", 37, CommandPriority::Required),
    ("vkGetFenceStatus", 38, CommandPriority::Required),
    ("vkCreateSemaphore", 40, CommandPriority::Recommended),
    ("vkDestroySemaphore", 41, CommandPriority::Recommended),
    ("vkWaitSemaphores", 173, CommandPriority::Deferred),
    ("vkSignalSemaphore", 174, CommandPriority::Deferred),
    ("vkGetSemaphoreCounterValue", 172, CommandPriority::Deferred),
    ("vkCreateEvent", 42, CommandPriority::Deferred),
    ("vkDestroyEvent", 43, CommandPriority::Deferred),
    ("vkCmdSetEvent", 123, CommandPriority::Deferred),
    ("vkCreateQueryPool", 47, CommandPriority::Deferred),
    ("vkDestroyQueryPool", 48, CommandPriority::Deferred),
    ("vkCmdWriteTimestamp", 130, CommandPriority::Deferred),
];

fn le(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[test]
fn task172_2_gpu6_candidate_table_matches_command_type() {
    assert_eq!(TABLE.len(), 116);
    let count = |p| TABLE.iter().filter(|t| t.2 == p).count();
    assert_eq!(count(CommandPriority::Required), 62);
    assert_eq!(count(CommandPriority::Recommended), 22);
    assert_eq!(count(CommandPriority::Deferred), 32);
    let mut ids: Vec<u32> = TABLE.iter().map(|t| t.1).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 116);
    for (name, id, p) in TABLE {
        let c = CommandType::try_from(*id).expect("candidate id");
        assert_eq!(c.name(), *name);
        assert_eq!(c.as_raw(), *id);
        assert_eq!(c.priority(), *p);
    }
}

#[test]
fn task172_2_gpu6_header_ok() {
    let buf = le(&[137, 1, 0xdead_beef]);
    let mut r = WireReader::new(&buf);
    let h = parse_command_header(&mut r).unwrap();
    assert_eq!(h.command, CommandType::EnumerateInstanceVersion);
    assert!(h.flags.generates_reply());
    assert_eq!(r.position(), COMMAND_HEADER_LEN);
    assert_eq!(r.read_u32().unwrap(), 0xdead_beef);
}

#[test]
fn task172_2_gpu6_reply_flag() {
    assert!(!CommandFlags::from_raw(0).unwrap().generates_reply());
    assert!(CommandFlags::from_raw(1).unwrap().generates_reply());
}

#[test]
fn task172_2_gpu6_undefined_flag_bits_rejected() {
    assert_eq!(
        CommandFlags::from_raw(2),
        Err(VenusWireError::InvalidFlags { raw: 2 })
    );
    let buf = le(&[0, 0x8000_0001]);
    let mut r = WireReader::new(&buf);
    assert_eq!(
        parse_command_header(&mut r).unwrap_err().code(),
        "venus_wire.invalid_flags"
    );
}

#[test]
fn task172_2_gpu6_truncated_input() {
    let buf = le(&[0, 0]);
    for n in [0usize, 1, 3, 4, 7] {
        let mut r = WireReader::new(&buf[..n]);
        let e = parse_command_header(&mut r).unwrap_err();
        assert_eq!(e.code(), "venus_wire.truncated", "n={n}");
    }
    let mut r = WireReader::new(&buf[..3]);
    assert_eq!(
        r.read_u32(),
        Err(VenusWireError::Truncated {
            needed: 4,
            remaining: 3
        })
    );
    assert_eq!(r.position(), 0);
}

#[test]
fn task172_2_gpu6_unknown_command_rejected() {
    for raw in [3000u32, 5, u32::MAX] {
        let buf = le(&[raw, 0]);
        let mut r = WireReader::new(&buf);
        let e = parse_command_header(&mut r).unwrap_err();
        assert_eq!(e, VenusWireError::UnsupportedCommand { raw });
        assert_eq!(e.code(), "venus_wire.unsupported_command");
    }
}

#[test]
fn task172_2_gpu6_array_len_limit() {
    let mut buf = u64::MAX.to_le_bytes().to_vec();
    let mut r = WireReader::new(&buf);
    assert_eq!(
        r.read_array_len(MAX_ARRAY_LEN),
        Err(VenusWireError::LengthExceeded {
            requested: u64::MAX,
            max: MAX_ARRAY_LEN
        })
    );
    buf = (MAX_ARRAY_LEN + 1).to_le_bytes().to_vec();
    assert_eq!(
        WireReader::new(&buf)
            .read_array_len(MAX_ARRAY_LEN)
            .unwrap_err()
            .code(),
        "venus_wire.length_exceeded"
    );
    buf = MAX_ARRAY_LEN.to_le_bytes().to_vec();
    assert_eq!(
        WireReader::new(&buf).read_array_len(MAX_ARRAY_LEN),
        Ok(MAX_ARRAY_LEN as usize)
    );
}

#[test]
fn task172_2_gpu6_read_bytes_aligns_to_4() {
    let buf = [7u8; 16];
    for (len, consumed) in [(0usize, 0usize), (1, 4), (2, 4), (3, 4), (4, 4), (5, 8)] {
        let mut r = WireReader::new(&buf);
        assert_eq!(r.read_bytes(len).unwrap().len(), len);
        assert_eq!(r.position(), consumed, "len={len}");
    }
    let mut r = WireReader::new(&buf[..5]);
    assert_eq!(
        r.read_bytes(5).unwrap_err(),
        VenusWireError::Truncated {
            needed: 8,
            remaining: 5
        }
    );
    assert_eq!(
        WireReader::new(&buf)
            .read_bytes(usize::MAX)
            .unwrap_err()
            .code(),
        "venus_wire.misaligned"
    );
}

#[test]
fn task172_2_gpu6_scalars_little_endian() {
    let mut buf = 0x0102_0304u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&(-2i32).to_le_bytes());
    buf.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let mut r = WireReader::new(&buf);
    assert_eq!(r.read_u32().unwrap(), 0x0102_0304);
    assert_eq!(r.read_i32().unwrap(), -2);
    assert_eq!(r.read_u64().unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(r.remaining(), 0);
}

#[test]
fn task172_2_gpu6_two_headers_in_sequence() {
    let buf = le(&[178, 0, 21, 1]);
    let mut r = WireReader::new(&buf);
    let a = parse_command_header(&mut r).unwrap();
    let b = parse_command_header(&mut r).unwrap();
    assert_eq!(a.command, CommandType::SetReplyCommandStreamMESA);
    assert!(!a.flags.generates_reply());
    assert_eq!(b.command, CommandType::AllocateMemory);
    assert!(b.flags.generates_reply());
    assert_eq!(r.remaining(), 0);
}

#[test]
fn task172_2_gpu6_error_codes_fixed() {
    let cases = [
        (
            VenusWireError::Truncated {
                needed: 1,
                remaining: 0,
            },
            "venus_wire.truncated",
        ),
        (
            VenusWireError::UnsupportedCommand { raw: 1 },
            "venus_wire.unsupported_command",
        ),
        (
            VenusWireError::LengthExceeded {
                requested: 2,
                max: 1,
            },
            "venus_wire.length_exceeded",
        ),
        (
            VenusWireError::Misaligned { len: 1 },
            "venus_wire.misaligned",
        ),
        (
            VenusWireError::InvalidFlags { raw: 2 },
            "venus_wire.invalid_flags",
        ),
    ];
    for (e, code) in cases {
        assert_eq!(e.code(), code);
        assert!(e.to_string().starts_with(code));
    }
}

/// B1: 件数 × 最小要素長が残りバイト数を超える配列を拒否する（GPU-6・REPAIR-5）。
#[test]
fn b1_gpu6_array_len_sized_rejects_count_exceeding_remaining() {
    let mk = |tail: usize| {
        let mut b = 3u64.to_le_bytes().to_vec();
        b.extend(std::iter::repeat_n(0u8, tail));
        b
    };
    let b = mk(16);
    assert_eq!(
        WireReader::new(&b).read_array_len_sized(MAX_ARRAY_LEN, 8),
        Err(VenusWireError::Truncated {
            needed: 24,
            remaining: 16
        })
    );
    let b = mk(23);
    assert_eq!(
        WireReader::new(&b).read_array_len_sized(MAX_ARRAY_LEN, 8),
        Err(VenusWireError::Truncated {
            needed: 24,
            remaining: 23
        })
    );
    let b = mk(24);
    assert_eq!(
        WireReader::new(&b).read_array_len_sized(MAX_ARRAY_LEN, 8),
        Ok(3)
    );
}

/// B1: 積の溢れと件数上限超過は `LengthExceeded`。
#[test]
fn b1_gpu6_array_len_sized_overflow_and_max() {
    let b = MAX_ARRAY_LEN.to_le_bytes();
    assert_eq!(
        WireReader::new(&b).read_array_len_sized(MAX_ARRAY_LEN, usize::MAX),
        Err(VenusWireError::LengthExceeded {
            requested: MAX_ARRAY_LEN,
            max: MAX_ARRAY_LEN
        })
    );
    let b = (MAX_ARRAY_LEN + 1).to_le_bytes();
    assert_eq!(
        WireReader::new(&b).read_array_len_sized(MAX_ARRAY_LEN, 1),
        Err(VenusWireError::LengthExceeded {
            requested: MAX_ARRAY_LEN + 1,
            max: MAX_ARRAY_LEN
        })
    );
}
