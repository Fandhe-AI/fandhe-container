//! arm64 ゲストへ渡す FDT（Flattened Devicetree。DTB）の組み立て器（OS 非依存・`unsafe` なし）。
//!
//! 役割: Devicetree Specification v0.4「Flattened Devicetree (DTB) Format」（version 17・last_comp_version 16）の
//! バイナリを、ノードとプロパティの追加呼び出しから組み立てる。arm64 のゲストは起動時に x0 = FDT の物理アドレスで
//! 機器構成を受け取るため、macOS の Hypervisor.framework バックエンド（TASK-192・MVM-5）と将来の KVM aarch64
//! （MVM-1）の両方が使う共有部品である。現状は呼び出し元が無い（起動経路への結線は後続）。
//!
//! 契約（TASK-192.5・#3784・MVM-5・MVM-1・REPAIR-2）:
//! - header と予約ブロックは固定長の型（`FdtHeader`・`FdtReserveEntry`）、structure block はトークン型つきの
//!   writer で組み、生の `Vec<u8>` を手で組まない。値はすべてビッグエンディアン。
//! - 入力（ノード名・プロパティ名・入れ子・全体サイズ）の違反は `MicrovmErrorCode::InvalidArgument`。
//!   検証に失敗した呼び出しは builder の状態を一切変えない（部分的に壊れた blob を作らない）。
//! - 出力全体は `MAX_FDT_BYTES`（64 KiB。arm64 起動規約の 2 MiB 以下）に制限する。
//! - エラー文言は固定の英語で、入力の中身をエコーしない。
//!
//! 未実装（REPAIR-3）: memory reservation のエントリ追加・`FDT_NOP`・兄弟ノード名の重複検査・phandle の採番・
//! DTB の読み取り（パース）は対象外。
//!
//! # 出力の並び
//! header（40 バイト）→ memory reservation block（終端の 16 バイト 0 のみ）→ structure block → strings block。
//! strings block のプロパティ名は初出順に追記し、完全一致の名前だけを重複排除する。

use std::collections::{HashMap, HashSet};

use crate::error::{MicrovmError, MicrovmErrorCode};

/// FDT の magic（`0xd00dfeed`）。
pub const FDT_MAGIC: u32 = 0xd00d_feed;
/// 出力する DTB の version。
pub const FDT_VERSION: u32 = 17;
/// 後方互換な最小 version。
pub const FDT_LAST_COMP_VERSION: u32 = 16;
/// 出力全体の上限（バイト）。arm64 の起動規約（2 MiB 以下）より小さく取る。
pub const MAX_FDT_BYTES: usize = 64 * 1024;

const _: () = assert!(MAX_FDT_BYTES <= 2 * 1024 * 1024);

/// ノード名の base 部・プロパティ名の最大文字数（Devicetree Specification の 31 文字）。
const MAX_NAME_LEN: usize = 31;
const HEADER_SIZE: usize = 40;
const RSVMAP_ENTRY_SIZE: usize = 16;
/// 終端トークン `FDT_END` の大きさ。
const END_TOKEN_SIZE: usize = 4;

const OFF_MAGIC: usize = 0;
const OFF_TOTALSIZE: usize = 4;
const OFF_OFF_DT_STRUCT: usize = 8;
const OFF_OFF_DT_STRINGS: usize = 12;
const OFF_OFF_MEM_RSVMAP: usize = 16;
const OFF_VERSION: usize = 20;
const OFF_LAST_COMP_VERSION: usize = 24;
const OFF_BOOT_CPUID_PHYS: usize = 28;
const OFF_SIZE_DT_STRINGS: usize = 32;
const OFF_SIZE_DT_STRUCT: usize = 36;

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

/// structure block のトークン。`FDT_NOP`（4）は出力しないため定義しない。
#[derive(Clone, Copy)]
enum FdtToken {
    BeginNode = 1,
    EndNode = 2,
    Prop = 3,
    End = 9,
}

/// 固定長 40 バイトの FDT header（REPAIR-2）。
struct FdtHeader {
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl FdtHeader {
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let fields: [(usize, u32); 10] = [
            (OFF_MAGIC, FDT_MAGIC),
            (OFF_TOTALSIZE, self.totalsize),
            (OFF_OFF_DT_STRUCT, self.off_dt_struct),
            (OFF_OFF_DT_STRINGS, self.off_dt_strings),
            (OFF_OFF_MEM_RSVMAP, self.off_mem_rsvmap),
            (OFF_VERSION, FDT_VERSION),
            (OFF_LAST_COMP_VERSION, FDT_LAST_COMP_VERSION),
            (OFF_BOOT_CPUID_PHYS, self.boot_cpuid_phys),
            (OFF_SIZE_DT_STRINGS, self.size_dt_strings),
            (OFF_SIZE_DT_STRUCT, self.size_dt_struct),
        ];
        for (off, value) in fields {
            if let Some(dst) = out.get_mut(off..off + 4) {
                dst.copy_from_slice(&value.to_be_bytes());
            }
        }
        out
    }
}

/// memory reservation block の 1 エントリ（address・size。16 バイト）。終端は (0, 0)。
struct FdtReserveEntry {
    address: u64,
    size: u64,
}

impl FdtReserveEntry {
    fn to_bytes(&self) -> [u8; RSVMAP_ENTRY_SIZE] {
        let mut out = [0u8; RSVMAP_ENTRY_SIZE];
        if let Some(dst) = out.get_mut(0..8) {
            dst.copy_from_slice(&self.address.to_be_bytes());
        }
        if let Some(dst) = out.get_mut(8..16) {
            dst.copy_from_slice(&self.size.to_be_bytes());
        }
        out
    }
}

/// 4 バイト境界へ切り上げた長さ（オーバーフロー時は None）。
fn align4(len: usize) -> Option<usize> {
    len.checked_add(3).map(|v| v & !3)
}

/// structure block。トークン・セル・4 バイト詰めの値だけを書ける型つき writer。
#[derive(Default)]
struct StructBlock(Vec<u8>);

impl StructBlock {
    fn token(&mut self, token: FdtToken) {
        self.0.extend_from_slice(&(token as u32).to_be_bytes());
    }

    fn cell(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    /// `bytes` を書き、4 バイト境界まで 0 で詰める。
    fn bytes_padded(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
        while !self.0.len().is_multiple_of(4) {
            self.0.push(0);
        }
    }
}

/// strings block。初出順に追記し、完全一致の名前だけ重複排除する。
#[derive(Default)]
struct StringTable {
    bytes: Vec<u8>,
    offsets: HashMap<String, u32>,
}

impl StringTable {
    fn lookup(&self, name: &str) -> Option<u32> {
        self.offsets.get(name).copied()
    }

    fn intern(&mut self, name: &str) -> Result<u32, MicrovmError> {
        if let Some(off) = self.lookup(name) {
            return Ok(off);
        }
        let off =
            u32::try_from(self.bytes.len()).map_err(|_| invalid("fdt size limit exceeded"))?;
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.offsets.insert(name.to_owned(), off);
        Ok(off)
    }
}

fn is_node_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ',' | '.' | '_' | '+' | '-')
}

fn is_property_char(c: char) -> bool {
    is_node_char(c) || matches!(c, '?' | '#')
}

/// 根以外のノード名（`base[@unit-address]`）を検査する。
fn validate_node_name(name: &str) -> Result<(), MicrovmError> {
    let mut parts = name.split('@');
    let base = parts.next().unwrap_or("");
    let unit = parts.next();
    if parts.next().is_some() {
        return Err(invalid("fdt node name has too many unit separators"));
    }
    if base.is_empty() || base.len() > MAX_NAME_LEN || !base.chars().all(is_node_char) {
        return Err(invalid("fdt node name is invalid"));
    }
    if let Some(unit) = unit
        && (unit.is_empty() || !unit.chars().all(is_node_char))
    {
        return Err(invalid("fdt node unit address is invalid"));
    }
    Ok(())
}

fn validate_property_name(name: &str) -> Result<(), MicrovmError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || !name.chars().all(is_property_char) {
        return Err(invalid("fdt property name is invalid"));
    }
    Ok(())
}

/// 開いているノードごとの状態。
#[derive(Default)]
struct NodeState {
    prop_names: HashSet<String>,
    has_child: bool,
}

/// FDT の組み立て器。`begin_node` / `property_*` / `end_node` を呼び、`finish` で DTB を得る。
pub struct FdtBuilder {
    structure: StructBlock,
    strings: StringTable,
    stack: Vec<NodeState>,
    root_done: bool,
    boot_cpuid_phys: u32,
}

impl Default for FdtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FdtBuilder {
    /// 空の builder。
    pub fn new() -> Self {
        Self {
            structure: StructBlock::default(),
            strings: StringTable::default(),
            stack: Vec::new(),
            root_done: false,
            boot_cpuid_phys: 0,
        }
    }

    /// header の `boot_cpuid_phys`（既定 0）。
    pub fn set_boot_cpuid_phys(&mut self, id: u32) {
        self.boot_cpuid_phys = id;
    }

    /// 現在の内容に `extra_struct` と `extra_strings` を足したときの出力全体の大きさが上限内か確かめる。
    fn check_size(&self, extra_struct: usize, extra_strings: usize) -> Result<(), MicrovmError> {
        let total = HEADER_SIZE
            .checked_add(RSVMAP_ENTRY_SIZE)
            .and_then(|v| v.checked_add(self.structure.0.len()))
            .and_then(|v| v.checked_add(extra_struct))
            .and_then(|v| v.checked_add(END_TOKEN_SIZE))
            .and_then(|v| v.checked_add(self.strings.bytes.len()))
            .and_then(|v| v.checked_add(extra_strings))
            .ok_or_else(|| invalid("fdt size limit exceeded"))?;
        if total > MAX_FDT_BYTES {
            return Err(invalid("fdt size limit exceeded"));
        }
        Ok(())
    }

    /// ノードを開く。最初の呼び出しは根（名前は空文字列）、以降は `base[@unit-address]`。
    pub fn begin_node(&mut self, name: &str) -> Result<(), MicrovmError> {
        if self.stack.is_empty() {
            if self.root_done {
                return Err(invalid("fdt root node already defined"));
            }
            if !name.is_empty() {
                return Err(invalid("fdt root node name must be empty"));
            }
        } else {
            validate_node_name(name)?;
        }
        // BEGIN_NODE トークン + 名前 + NUL を 4 バイト境界まで。
        let name_len = name
            .len()
            .checked_add(1)
            .and_then(align4)
            .ok_or_else(|| invalid("fdt size limit exceeded"))?;
        let added = name_len
            .checked_add(4)
            .ok_or_else(|| invalid("fdt size limit exceeded"))?;
        self.check_size(added, 0)?;

        if let Some(parent) = self.stack.last_mut() {
            parent.has_child = true;
        }
        self.structure.token(FdtToken::BeginNode);
        let mut buf = Vec::with_capacity(name.len() + 1);
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        self.structure.bytes_padded(&buf);
        self.stack.push(NodeState::default());
        Ok(())
    }

    /// 現在のノードを閉じる。開いているノードが無ければ拒否する。
    pub fn end_node(&mut self) -> Result<(), MicrovmError> {
        if self.stack.is_empty() {
            return Err(invalid("fdt node nesting underflow"));
        }
        self.check_size(4, 0)?;
        self.structure.token(FdtToken::EndNode);
        self.stack.pop();
        if self.stack.is_empty() {
            self.root_done = true;
        }
        Ok(())
    }

    fn property(&mut self, name: &str, value: &[u8]) -> Result<(), MicrovmError> {
        validate_property_name(name)?;
        let node = self
            .stack
            .last()
            .ok_or_else(|| invalid("fdt property outside of a node"))?;
        if node.has_child {
            return Err(invalid("fdt property after child node"));
        }
        if node.prop_names.contains(name) {
            return Err(invalid("fdt duplicate property name"));
        }
        let len = u32::try_from(value.len()).map_err(|_| invalid("fdt size limit exceeded"))?;
        let padded = align4(value.len()).ok_or_else(|| invalid("fdt size limit exceeded"))?;
        let added = padded
            .checked_add(12)
            .ok_or_else(|| invalid("fdt size limit exceeded"))?;
        let extra_strings = if self.strings.lookup(name).is_some() {
            0
        } else {
            name.len() + 1
        };
        self.check_size(added, extra_strings)?;

        let nameoff = self.strings.intern(name)?;
        if let Some(node) = self.stack.last_mut() {
            node.prop_names.insert(name.to_owned());
        }
        self.structure.token(FdtToken::Prop);
        self.structure.cell(len);
        self.structure.cell(nameoff);
        self.structure.bytes_padded(value);
        Ok(())
    }

    /// 32 ビット整数 1 セルのプロパティ。
    pub fn property_u32(&mut self, name: &str, value: u32) -> Result<(), MicrovmError> {
        self.property(name, &value.to_be_bytes())
    }

    /// 64 ビット整数（2 セル）のプロパティ。
    pub fn property_u64(&mut self, name: &str, value: u64) -> Result<(), MicrovmError> {
        self.property(name, &value.to_be_bytes())
    }

    /// 32 ビットセル列のプロパティ。空スライスは拒否する（空の値は `property_empty` を使う）。
    pub fn property_cells(&mut self, name: &str, cells: &[u32]) -> Result<(), MicrovmError> {
        if cells.is_empty() {
            return Err(invalid("fdt cell list is empty"));
        }
        // 上限を超える入力は確保前に拒否する。
        if cells.len() > MAX_FDT_BYTES / 4 {
            return Err(invalid("fdt size limit exceeded"));
        }
        let mut buf = Vec::with_capacity(cells.len() * 4);
        for cell in cells {
            buf.extend_from_slice(&cell.to_be_bytes());
        }
        self.property(name, &buf)
    }

    /// NUL 終端の文字列プロパティ。`value` に NUL を含むものは拒否する。
    pub fn property_string(&mut self, name: &str, value: &str) -> Result<(), MicrovmError> {
        self.property_string_list(name, &[value])
    }

    /// NUL 終端文字列の連結プロパティ。要素に NUL を含むもの・空のリストは拒否する。
    pub fn property_string_list(
        &mut self,
        name: &str,
        values: &[&str],
    ) -> Result<(), MicrovmError> {
        if values.is_empty() {
            return Err(invalid("fdt string list is empty"));
        }
        let mut buf = Vec::new();
        for value in values {
            if value.as_bytes().contains(&0) {
                return Err(invalid("fdt string contains NUL"));
            }
            if buf.len().saturating_add(value.len()) >= MAX_FDT_BYTES {
                return Err(invalid("fdt size limit exceeded"));
            }
            buf.extend_from_slice(value.as_bytes());
            buf.push(0);
        }
        self.property(name, &buf)
    }

    /// 値を持たないプロパティ（長さ 0）。
    pub fn property_empty(&mut self, name: &str) -> Result<(), MicrovmError> {
        self.property(name, &[])
    }

    /// DTB を確定して返す。根が未作成、または未閉じのノードがあれば拒否する。
    pub fn finish(mut self) -> Result<Vec<u8>, MicrovmError> {
        if !self.stack.is_empty() {
            return Err(invalid("fdt unclosed node at finish"));
        }
        if !self.root_done {
            return Err(invalid("fdt root node missing at finish"));
        }
        self.check_size(0, 0)?;
        self.structure.token(FdtToken::End);

        let too_big = || invalid("fdt size limit exceeded");
        let off_mem_rsvmap = HEADER_SIZE;
        let off_dt_struct = off_mem_rsvmap
            .checked_add(RSVMAP_ENTRY_SIZE)
            .ok_or_else(too_big)?;
        let off_dt_strings = off_dt_struct
            .checked_add(self.structure.0.len())
            .ok_or_else(too_big)?;
        let totalsize = off_dt_strings
            .checked_add(self.strings.bytes.len())
            .ok_or_else(too_big)?;
        if totalsize > MAX_FDT_BYTES {
            return Err(too_big());
        }
        let to_u32 = |v: usize| u32::try_from(v).map_err(|_| too_big());
        let header = FdtHeader {
            totalsize: to_u32(totalsize)?,
            off_dt_struct: to_u32(off_dt_struct)?,
            off_dt_strings: to_u32(off_dt_strings)?,
            off_mem_rsvmap: to_u32(off_mem_rsvmap)?,
            boot_cpuid_phys: self.boot_cpuid_phys,
            size_dt_strings: to_u32(self.strings.bytes.len())?,
            size_dt_struct: to_u32(self.structure.0.len())?,
        };
        let terminator = FdtReserveEntry {
            address: 0,
            size: 0,
        };

        let mut out = Vec::with_capacity(totalsize);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&terminator.to_bytes());
        out.extend_from_slice(&self.structure.0);
        out.extend_from_slice(&self.strings.bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(blob: &[u8], off: usize) -> u32 {
        u32::from_be_bytes(blob[off..off + 4].try_into().unwrap())
    }

    fn code(r: Result<(), MicrovmError>) -> MicrovmErrorCode {
        r.expect_err("must be rejected").code()
    }

    fn golden_builder() -> FdtBuilder {
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.property_u32("#address-cells", 2).unwrap();
        b.property_u32("#size-cells", 2).unwrap();
        b.property_string("compatible", "linux,dummy-virt").unwrap();
        b.begin_node("memory@40000000").unwrap();
        b.property_string("device_type", "memory").unwrap();
        b.property_cells("reg", &[0, 0x4000_0000, 0, 0x1000_0000])
            .unwrap();
        b.end_node().unwrap();
        b.end_node().unwrap();
        b
    }

    /// 仕様の規則から手計算した期待 blob（空白は読みやすさのための区切り）。
    const GOLDEN: &str = "d00dfeed 00000106 00000038 000000d0 00000028 00000011 00000010 00000000 \
        00000036 00000098 0000000000000000 0000000000000000 \
        00000001 00000000 \
        00000003 00000004 00000000 00000002 \
        00000003 00000004 0000000f 00000002 \
        00000003 00000011 0000001b 6c696e75 782c6475 6d6d792d 76697274 00000000 \
        00000001 6d656d6f 72794034 30303030 30303000 \
        00000003 00000007 00000026 6d656d6f 72790000 \
        00000003 00000010 00000032 00000000 40000000 00000000 10000000 \
        00000002 00000002 00000009 \
        2361646472657373 2d63656c6c7300 2373697a652d63656c6c7300 \
        636f6d70617469626c6500 6465766963655f7479706500 72656700";

    fn golden_bytes() -> Vec<u8> {
        let hex: String = GOLDEN.split_whitespace().collect();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// MVM-5・MVM-1: 黄金 blob との完全一致。
    #[test]
    fn mvm5_3784_golden_blob_matches() {
        let blob = golden_builder().finish().unwrap();
        assert_eq!(blob.len(), 262);
        assert_eq!(blob, golden_bytes());
    }

    #[test]
    fn mvm5_3784_header_fields() {
        let blob = golden_builder().finish().unwrap();
        assert_eq!(be32(&blob, 0), 0xd00d_feed);
        assert_eq!(be32(&blob, 4), 262);
        assert_eq!(be32(&blob, 8), 56);
        assert_eq!(be32(&blob, 12), 208);
        assert_eq!(be32(&blob, 16), 40);
        assert_eq!(be32(&blob, 20), 17);
        assert_eq!(be32(&blob, 24), 16);
        assert_eq!(be32(&blob, 28), 0);
        assert_eq!(be32(&blob, 32), 54);
        assert_eq!(be32(&blob, 36), 152);
        assert_eq!(&blob[40..56], &[0u8; 16]);
    }

    /// 第二の角度: structure block をトークン単位で歩いて名前解決する。
    #[test]
    fn mvm5_3784_parse_back_walks_tokens() {
        let blob = golden_builder().finish().unwrap();
        let off_struct = be32(&blob, 8) as usize;
        let off_strings = be32(&blob, 12) as usize;
        let size_struct = be32(&blob, 36) as usize;
        let mut pos = off_struct;
        let end = off_struct + size_struct;
        let mut events: Vec<String> = Vec::new();
        while pos < end {
            let tok = be32(&blob, pos);
            pos += 4;
            match tok {
                1 => {
                    let nul = blob[pos..].iter().position(|&b| b == 0).unwrap();
                    let name = std::str::from_utf8(&blob[pos..pos + nul]).unwrap();
                    events.push(format!("B:{name}"));
                    pos += (nul + 1 + 3) & !3;
                }
                2 => events.push("E".into()),
                3 => {
                    let len = be32(&blob, pos) as usize;
                    let nameoff = be32(&blob, pos + 4) as usize;
                    pos += 8;
                    let s = off_strings + nameoff;
                    let nul = blob[s..].iter().position(|&b| b == 0).unwrap();
                    let name = std::str::from_utf8(&blob[s..s + nul]).unwrap();
                    events.push(format!("P:{name}:{len}"));
                    pos += (len + 3) & !3;
                }
                9 => events.push("END".into()),
                other => panic!("unexpected token {other}"),
            }
        }
        assert_eq!(pos, end);
        assert_eq!(
            events,
            [
                "B:",
                "P:#address-cells:4",
                "P:#size-cells:4",
                "P:compatible:17",
                "B:memory@40000000",
                "P:device_type:7",
                "P:reg:16",
                "E",
                "E",
                "END",
            ]
        );
    }

    #[test]
    fn mvm5_3784_strings_deduplicated() {
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.begin_node("a@1").unwrap();
        b.property_u32("reg", 1).unwrap();
        b.end_node().unwrap();
        b.begin_node("b@2").unwrap();
        b.property_u32("reg", 2).unwrap();
        b.end_node().unwrap();
        b.end_node().unwrap();
        let blob = b.finish().unwrap();
        assert_eq!(be32(&blob, 32), 4);
        let s = be32(&blob, 12) as usize;
        assert_eq!(&blob[s..], b"reg\0");
    }

    #[test]
    fn mvm5_3784_value_encodings() {
        let mut b = FdtBuilder::new();
        b.set_boot_cpuid_phys(3);
        b.begin_node("").unwrap();
        b.property_u64("x", 0x1122_3344_5566_7788).unwrap();
        b.property_string_list("l", &["a", "bc"]).unwrap();
        b.property_empty("e").unwrap();
        b.end_node().unwrap();
        let blob = b.finish().unwrap();
        assert_eq!(be32(&blob, 28), 3);
        let s = be32(&blob, 8) as usize;
        let st = &blob[s..s + be32(&blob, 36) as usize];
        let expect: Vec<u8> = [
            &[0, 0, 0, 1, 0, 0, 0, 0][..],
            &[0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            &[0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 2],
            &[0x61, 0, 0x62, 0x63, 0, 0, 0, 0],
            &[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4],
            &[0, 0, 0, 2, 0, 0, 0, 9],
        ]
        .concat();
        assert_eq!(st, &expect[..]);
    }

    #[test]
    fn mvm5_3784_unclosed_node_rejected() {
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.begin_node("c").unwrap();
        assert_eq!(
            b.finish().unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        assert_eq!(
            b.finish().unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            FdtBuilder::new().finish().unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    #[test]
    fn mvm5_3784_end_node_underflow_rejected() {
        assert_eq!(
            code(FdtBuilder::new().end_node()),
            MicrovmErrorCode::InvalidArgument
        );
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.end_node().unwrap();
        assert_eq!(code(b.end_node()), MicrovmErrorCode::InvalidArgument);
    }

    #[test]
    fn mvm5_3784_invalid_names_rejected() {
        let long = "x".repeat(32);
        let bad_nodes = ["a#", "a b", "a/b", "a\0b", "", "a@b@c", "a@", long.as_str()];
        for name in bad_nodes {
            let mut b = FdtBuilder::new();
            b.begin_node("").unwrap();
            assert_eq!(
                code(b.begin_node(name)),
                MicrovmErrorCode::InvalidArgument,
                "{name:?}"
            );
        }
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.begin_node(&"x".repeat(31)).unwrap();
        assert_eq!(
            code(FdtBuilder::new().begin_node("root")),
            MicrovmErrorCode::InvalidArgument
        );
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.end_node().unwrap();
        assert_eq!(code(b.begin_node("")), MicrovmErrorCode::InvalidArgument);
        for name in ["a@b", "a b", "", long.as_str()] {
            let mut b = FdtBuilder::new();
            b.begin_node("").unwrap();
            assert_eq!(
                code(b.property_empty(name)),
                MicrovmErrorCode::InvalidArgument,
                "{name:?}"
            );
        }
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.property_empty(&"p".repeat(31)).unwrap();
        b.property_empty("#a?b").unwrap();
    }

    #[test]
    fn mvm5_3784_property_constraints() {
        assert_eq!(
            code(FdtBuilder::new().property_u32("a", 1)),
            MicrovmErrorCode::InvalidArgument
        );
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        b.property_u32("a", 1).unwrap();
        assert_eq!(
            code(b.property_u32("a", 2)),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            code(b.property_string("s", "a\0b")),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            code(b.property_string_list("s", &[])),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            code(b.property_cells("c", &[])),
            MicrovmErrorCode::InvalidArgument
        );
        b.begin_node("n").unwrap();
        b.end_node().unwrap();
        assert_eq!(
            code(b.property_u32("late", 1)),
            MicrovmErrorCode::InvalidArgument
        );
    }

    #[test]
    fn mvm5_3784_size_limit_rejected() {
        let mut b = FdtBuilder::new();
        b.begin_node("").unwrap();
        let cells = vec![0u32; 16 * 1024];
        assert_eq!(
            code(b.property_cells("big", &cells)),
            MicrovmErrorCode::InvalidArgument
        );
        // 失敗後も継続できる。
        b.property_u32("ok", 1).unwrap();
    }

    /// 失敗した呼び出しが状態（string table・stack・重複検査）を変えないこと。
    #[test]
    fn mvm5_3784_rejected_call_leaves_builder_unchanged() {
        let mut x = FdtBuilder::new();
        x.begin_node("").unwrap();
        x.property_u32("a", 1).unwrap();
        let mut y = FdtBuilder::new();
        y.begin_node("").unwrap();
        y.property_u32("a", 1).unwrap();
        assert!(y.begin_node("bad name").is_err());
        assert!(y.property_u32("a", 2).is_err());
        assert!(y.property_string("s", "x\0y").is_err());
        assert!(y.property_u32("bad name", 2).is_err());
        for b in [&mut x, &mut y] {
            b.property_u32("z", 9).unwrap();
            b.end_node().unwrap();
        }
        assert_eq!(x.finish().unwrap(), y.finish().unwrap());
    }
}
