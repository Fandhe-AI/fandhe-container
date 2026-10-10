//! デバイス cgroup（`BPF_PROG_TYPE_CGROUP_DEVICE`）の eBPF 命令列の組み立て（TASK-32 追補・MS-2・#1678・
//! SEC-1・CORE-1・CORE-4）。
//!
//! # 役割
//! OCI default devices と `/dev/ptmx`・`/dev/pts/*` を表す封印した許可リスト（[`DeviceAllowList`]）から、
//! cgroup v2 のデバイス制御用 eBPF プログラム（[`DeviceProgram`]）の命令列を組み立てる。
//! syscall を呼ばない純粋な組み立て層で、`unsafe` を持たない。ロード（`BPF_PROG_LOAD`。#1679）・
//! アタッチと事後検証（`BPF_CGROUP_DEVICE`。#1680）・実機の verifier 照合（#1681）・起動経路への結線
//! （#1314）・GPU の CDI `deviceNodes` の追加入口（TASK-129・GPU-4・#561）は別 issue の担当で、
//! 現状は未結線（REPAIR-3）。
//!
//! # 命令列のレイアウト
//! `r1` は `struct bpf_cgroup_dev_ctx`（`u32 access_type`〔`(ACC << 16) | DEV`〕・`u32 major`・`u32 minor`）
//! を指す。前置きで種別・アクセス・major・minor を `r2`〜`r5` へ読み、規則ごとに「種別一致・許可外アクセス
//! ビット無し・major 一致・（全範囲でなければ）minor 一致」で `r0 = 1; exit`、不一致は次の規則へ前方
//! ジャンプする。末尾は `r0 = 0; exit`（既定拒否）。許可外アクセスは `deny_mask`（`0xFFFF & !allowed`）との
//! `JSET` で判定するため、未知のアクセスビットも拒否側に倒れる（fail-closed）。
//!
//! # 一次情報
//! 構造体・定数は `/usr/include/linux/{bpf.h,bpf_common.h}` による。`UNIX98_PTY_SLAVE_MAJOR`（136）は
//! `linux/major.h` による。pty の minor が major 136 の 1 つに収まること（`NR_UNIX98_PTY_MAX`・
//! `drivers/tty/pty.c` の割り当て）はカーネルソースでの再確認は未実施で、実機結合試験（#1681）で照合する。
//! verifier の受理（ctx の 4 バイト整列読み・ヘルパー無し・`r0` が 0 か 1）も #1681 で確かめる。
//!
//! # 設計上の制約
//! - 命令は列挙 opcode と 0〜10 のレジスタ newtype からしか作れない（REPAIR-2）。seccomp の cBPF 型とは
//!   形式が違うため流用しない
//! - 規則の構築子は非公開で、許可リストの公開構築は固定表の [`DeviceAllowList::oci_default`] だけ。利用者・
//!   外部入力から major / minor を受け取る経路は作らない。任意 major の全範囲は表現できない
//! - 命令数は checked 演算で数え、`BPF_MAXINSNS` 以下であることを確かめてから確保する

#[cfg(not(target_endian = "little"))]
compile_error!("the device cgroup program encoder supports little-endian targets only");

use std::ffi::CStr;

use super::{CgroupError, CgroupStep};
use crate::traits::ErrorCode;

/// プログラムの命令数の上限。カーネルの `BPF_MAXINSNS`（`linux/bpf_common.h`）。
pub const DEVICE_PROGRAM_MAX_INSNS: usize = 4096;

/// `BPF_PROG_LOAD` に渡す license 文字列（#1679 が使う）。
///
/// 本プログラムは BPF ヘルパーを呼ばないため、カーネルがこの文字列から決める GPL 互換性は検証結果に
/// 影響しない見込み。本リポの中核ライセンス（Apache-2.0 単独）と同じ値を宣言する。
pub const DEVICE_PROGRAM_LICENSE: &CStr = c"Apache-2.0";

/// `BPF_DEVCG_DEV_BLOCK`。
const DEVCG_DEV_BLOCK: u32 = 1;
/// `BPF_DEVCG_DEV_CHAR`。
const DEVCG_DEV_CHAR: u32 = 2;
/// `ctx.access_type` の下位 16 ビット（デバイス種別）のマスク。
const DEVCG_TYPE_MASK: i32 = 0xFFFF;
/// `ctx.access_type` のアクセス部の右シフト量。
const DEVCG_ACC_SHIFT: u8 = 16;
/// `struct bpf_cgroup_dev_ctx` の `access_type` のオフセット。
const CTX_OFF_ACCESS_TYPE: i16 = 0;
/// `struct bpf_cgroup_dev_ctx` の `major` のオフセット。
const CTX_OFF_MAJOR: i16 = 4;
/// `struct bpf_cgroup_dev_ctx` の `minor` のオフセット。
const CTX_OFF_MINOR: i16 = 8;

/// eBPF レジスタ（`r0`〜`r10`）。範囲外の値は表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfReg(u8);

impl EbpfReg {
    /// 戻り値・`exit` の結果。
    pub const R0: Self = Self(0);
    /// ctx へのポインタ。
    pub const R1: Self = Self(1);
    /// 作業レジスタ。
    pub const R2: Self = Self(2);
    /// 作業レジスタ。
    pub const R3: Self = Self(3);
    /// 作業レジスタ。
    pub const R4: Self = Self(4);
    /// 作業レジスタ。
    pub const R5: Self = Self(5);
    /// フレームポインタ。
    pub const R10: Self = Self(10);

    /// 0〜10 のときだけ `Some`。
    pub const fn new(n: u8) -> Option<Self> {
        if n <= 10 { Some(Self(n)) } else { None }
    }

    /// レジスタ番号。
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// 本モジュールが使う eBPF 命令の opcode（`code` フィールド）。これ以外は作れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EbpfOpcode {
    /// `BPF_LDX | BPF_MEM | BPF_W`: `dst = *(u32 *)(src + off)`。
    LdxMemW = 0x61,
    /// `BPF_ALU | BPF_AND | BPF_K`（32 ビット）。
    AluAndK = 0x54,
    /// `BPF_ALU | BPF_RSH | BPF_K`（32 ビット）。
    AluRshK = 0x74,
    /// `BPF_JMP | BPF_JNE | BPF_K`。
    JmpJneK = 0x55,
    /// `BPF_JMP | BPF_JSET | BPF_K`。
    JmpJsetK = 0x45,
    /// `BPF_ALU64 | BPF_MOV | BPF_K`。
    Alu64MovK = 0xb7,
    /// `BPF_JMP | BPF_EXIT`。
    JmpExit = 0x95,
}

impl EbpfOpcode {
    /// 評価器（テスト）がバイト列から opcode を復元するために使う。
    #[cfg(test)]
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x61 => Self::LdxMemW,
            0x54 => Self::AluAndK,
            0x74 => Self::AluRshK,
            0x55 => Self::JmpJneK,
            0x45 => Self::JmpJsetK,
            0xb7 => Self::Alu64MovK,
            0x95 => Self::JmpExit,
            _ => return None,
        })
    }
}

/// `struct bpf_insn`（8 バイト）。構築は命令ごとの `const fn` だけ。
///
/// `regs` は `(src << 4) | dst`（カーネルのビットフィールドは dst が下位ニブル）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EbpfInstruction {
    code: EbpfOpcode,
    regs: u8,
    off: i16,
    imm: i32,
}

impl EbpfInstruction {
    const fn raw(op: EbpfOpcode, dst: EbpfReg, src: EbpfReg, off: i16, imm: i32) -> Self {
        Self {
            code: op,
            regs: (src.0 << 4) | dst.0,
            off,
            imm,
        }
    }

    /// `dst = *(u32 *)(src + off)`。
    pub const fn ldx_mem_w(dst: EbpfReg, src: EbpfReg, off: i16) -> Self {
        Self::raw(EbpfOpcode::LdxMemW, dst, src, off, 0)
    }

    /// `dst &= imm`（32 ビット）。
    pub const fn alu32_and_k(dst: EbpfReg, imm: i32) -> Self {
        Self::raw(EbpfOpcode::AluAndK, dst, EbpfReg::R0, 0, imm)
    }

    /// `dst >>= shift`（32 ビット）。`shift` が 32 以上なら `None`。
    pub const fn alu32_rsh_k(dst: EbpfReg, shift: u8) -> Option<Self> {
        if shift >= 32 {
            return None;
        }
        Some(Self::raw(
            EbpfOpcode::AluRshK,
            dst,
            EbpfReg::R0,
            0,
            shift as i32,
        ))
    }

    /// `if dst != imm goto +off`。
    pub const fn jne_k(dst: EbpfReg, imm: i32, off: i16) -> Self {
        Self::raw(EbpfOpcode::JmpJneK, dst, EbpfReg::R0, off, imm)
    }

    /// `if dst & imm goto +off`。
    pub const fn jset_k(dst: EbpfReg, imm: i32, off: i16) -> Self {
        Self::raw(EbpfOpcode::JmpJsetK, dst, EbpfReg::R0, off, imm)
    }

    /// `dst = imm`（64 ビット・符号拡張）。
    pub const fn mov64_k(dst: EbpfReg, imm: i32) -> Self {
        Self::raw(EbpfOpcode::Alu64MovK, dst, EbpfReg::R0, 0, imm)
    }

    /// `exit`（`r0` を返す）。
    pub const fn exit() -> Self {
        Self::raw(EbpfOpcode::JmpExit, EbpfReg::R0, EbpfReg::R0, 0, 0)
    }

    /// opcode。
    pub const fn code(&self) -> EbpfOpcode {
        self.code
    }

    /// dst レジスタ番号。
    pub const fn dst(&self) -> u8 {
        self.regs & 0x0f
    }

    /// src レジスタ番号。
    pub const fn src(&self) -> u8 {
        self.regs >> 4
    }

    /// 分岐・メモリのオフセット。
    pub const fn off(&self) -> i16 {
        self.off
    }

    /// 即値。
    pub const fn imm(&self) -> i32 {
        self.imm
    }

    /// カーネルへ渡す 8 バイト表現（リトルエンディアン固定。ホストの値表現に依存しない）。
    pub fn to_le_bytes(&self) -> [u8; 8] {
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code as u8,
            self.regs,
            off[0],
            off[1],
            imm[0],
            imm[1],
            imm[2],
            imm[3],
        ]
    }
}

/// デバイス種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// 文字デバイス。
    Char,
    /// ブロックデバイス。
    Block,
}

impl DeviceType {
    /// `BPF_DEVCG_DEV_*` の値。
    pub const fn bpf_value(self) -> u32 {
        match self {
            Self::Char => DEVCG_DEV_CHAR,
            Self::Block => DEVCG_DEV_BLOCK,
        }
    }
}

/// 許可するアクセス（`r` / `w` / `m` のビット集合）。値は `BPF_DEVCG_ACC_*`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAccess(u8);

impl DeviceAccess {
    /// `mknod`。
    pub const MKNOD: Self = Self(1);
    /// 読み取り。
    pub const READ: Self = Self(2);
    /// 書き込み。
    pub const WRITE: Self = Self(4);
    /// `rwm`。
    pub const RWM: Self = Self(7);

    /// 和集合。
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `other` の全ビットを含むか。
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// ビット値。
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// 規則の minor。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMinor {
    /// 指定値のみ。
    Exact(u32),
    /// 全範囲。
    Any,
}

/// 許可規則 1 件。構築子は非公開（固定表とテストだけが作る）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRule {
    ty: DeviceType,
    major: u32,
    minor: DeviceMinor,
    access: DeviceAccess,
}

impl DeviceRule {
    const fn new(ty: DeviceType, major: u32, minor: DeviceMinor, access: DeviceAccess) -> Self {
        Self {
            ty,
            major,
            minor,
            access,
        }
    }

    /// 種別。
    pub const fn ty(&self) -> DeviceType {
        self.ty
    }

    /// major。
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// minor。
    pub const fn minor(&self) -> DeviceMinor {
        self.minor
    }

    /// 許可するアクセス。
    pub const fn access(&self) -> DeviceAccess {
        self.access
    }

    /// 規則が生成する命令数（種別・アクセス・major・[minor]・`mov`・`exit`）。
    const fn insn_len(&self) -> usize {
        match self.minor {
            DeviceMinor::Exact(_) => 6,
            DeviceMinor::Any => 5,
        }
    }
}

const fn char_rwm(major: u32, minor: DeviceMinor) -> DeviceRule {
    DeviceRule::new(DeviceType::Char, major, minor, DeviceAccess::RWM)
}

/// OCI default devices（`/dev/{null,zero,full,random,urandom,tty}`）と `/dev/ptmx`・`/dev/pts/*` の固定表。
///
/// `/dev/console`（5:1）・`/dev/net/tun`（10:200）は含めない（#1609）。
static OCI_DEFAULT_DEVICE_RULES: [DeviceRule; 8] = [
    char_rwm(1, DeviceMinor::Exact(3)),
    char_rwm(1, DeviceMinor::Exact(5)),
    char_rwm(1, DeviceMinor::Exact(7)),
    char_rwm(1, DeviceMinor::Exact(8)),
    char_rwm(1, DeviceMinor::Exact(9)),
    char_rwm(5, DeviceMinor::Exact(0)),
    char_rwm(5, DeviceMinor::Exact(2)),
    // UNIX98_PTY_SLAVE_MAJOR（`linux/major.h`）。
    char_rwm(136, DeviceMinor::Any),
];

/// 許可リスト。公開の構築は固定表の [`DeviceAllowList::oci_default`] だけ。
#[derive(Debug, Clone, Copy)]
pub struct DeviceAllowList {
    rules: &'static [DeviceRule],
}

impl DeviceAllowList {
    /// OCI default devices と pty の既定の許可リスト。
    pub const fn oci_default() -> Self {
        Self {
            rules: &OCI_DEFAULT_DEVICE_RULES,
        }
    }

    /// 規則の一覧。
    pub const fn rules(&self) -> &'static [DeviceRule] {
        self.rules
    }
}

/// 組み立て済みの命令列。命令数は [`DEVICE_PROGRAM_MAX_INSNS`] 以下。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProgram {
    insns: Vec<EbpfInstruction>,
}

impl DeviceProgram {
    /// 許可リストから組み立てる。上限超過は `InvalidArgument`（`BuildDeviceProgram` 段）。
    pub fn from_allow_list(list: &DeviceAllowList) -> Result<Self, CgroupError> {
        build_device_program(list.rules())
    }

    /// 命令列。
    pub fn instructions(&self) -> &[EbpfInstruction] {
        &self.insns
    }

    /// 命令数。
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// 命令が空か（常に偽。組み立て結果は必ず末尾の既定拒否を持つ）。
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// カーネルへ渡す連続バイト列（各命令 8 バイトのリトルエンディアン）。
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.insns.len().saturating_mul(8));
        for i in &self.insns {
            out.extend_from_slice(&i.to_le_bytes());
        }
        out
    }
}

fn build_error(message: String) -> CgroupError {
    CgroupError::new(
        ErrorCode::InvalidArgument,
        CgroupStep::BuildDeviceProgram,
        message,
    )
}

/// 前置き（6 命令）・規則・既定拒否の末尾（2 命令）を組み立てる。
fn build_device_program(rules: &[DeviceRule]) -> Result<DeviceProgram, CgroupError> {
    const PRELUDE: usize = 6;
    const TAIL: usize = 2;
    let mut total = PRELUDE + TAIL;
    for r in rules {
        total = total.saturating_add(r.insn_len());
    }
    if total > DEVICE_PROGRAM_MAX_INSNS {
        return Err(build_error(format!(
            "device cgroup program needs {total} instructions, exceeding the limit of {DEVICE_PROGRAM_MAX_INSNS}"
        )));
    }

    let (r0, r1, r2, r3, r4, r5) = (
        EbpfReg::R0,
        EbpfReg::R1,
        EbpfReg::R2,
        EbpfReg::R3,
        EbpfReg::R4,
        EbpfReg::R5,
    );
    let shift = EbpfInstruction::alu32_rsh_k(r3, DEVCG_ACC_SHIFT)
        .ok_or_else(|| build_error("invalid access shift".to_owned()))?;

    let mut p = Vec::with_capacity(total);
    p.push(EbpfInstruction::ldx_mem_w(r2, r1, CTX_OFF_ACCESS_TYPE));
    p.push(EbpfInstruction::alu32_and_k(r2, DEVCG_TYPE_MASK));
    p.push(EbpfInstruction::ldx_mem_w(r3, r1, CTX_OFF_ACCESS_TYPE));
    p.push(shift);
    p.push(EbpfInstruction::ldx_mem_w(r4, r1, CTX_OFF_MAJOR));
    p.push(EbpfInstruction::ldx_mem_w(r5, r1, CTX_OFF_MINOR));

    for rule in rules {
        let len = rule.insn_len();
        // i 番目の分岐から次の規則の先頭までの前方ジャンプ量。
        let off = |i: usize| -> Result<i16, CgroupError> {
            i16::try_from(len - 1 - i)
                .map_err(|_| build_error("jump offset does not fit in i16".to_owned()))
        };
        let deny_mask = 0xFFFF_u32 & !u32::from(rule.access.bits());
        p.push(EbpfInstruction::jne_k(
            r2,
            rule.ty.bpf_value() as i32,
            off(0)?,
        ));
        p.push(EbpfInstruction::jset_k(r3, deny_mask as i32, off(1)?));
        p.push(EbpfInstruction::jne_k(r4, rule.major as i32, off(2)?));
        if let DeviceMinor::Exact(minor) = rule.minor {
            p.push(EbpfInstruction::jne_k(r5, minor as i32, off(3)?));
        }
        p.push(EbpfInstruction::mov64_k(r0, 1));
        p.push(EbpfInstruction::exit());
    }

    p.push(EbpfInstruction::mov64_k(r0, 0));
    p.push(EbpfInstruction::exit());
    Ok(DeviceProgram { insns: p })
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: EbpfReg = EbpfReg::R1;
    const R2: EbpfReg = EbpfReg::R2;
    const R4: EbpfReg = EbpfReg::R4;

    /// `to_le_bytes` 後の 8 バイト列をデコードして解釈する小さな eBPF 評価器（REPAIR-12）。
    /// ニブル順の誤りが許可・拒否の結果にも出るよう、構造体ではなくバイト列から読む。
    fn eval(program: &[u8], ctx: [u32; 3]) -> Result<u64, String> {
        let mut reg = [0u64; 11];
        let mut pc: usize = 0;
        for _ in 0..10_000 {
            let b: &[u8] = program
                .get(pc * 8..pc * 8 + 8)
                .ok_or_else(|| format!("pc {pc} out of range"))?;
            let op = EbpfOpcode::from_u8(b[0]).ok_or_else(|| format!("bad opcode {:#x}", b[0]))?;
            let dst = usize::from(b[1] & 0x0f);
            let src = usize::from(b[1] >> 4);
            let off = i16::from_le_bytes([b[2], b[3]]);
            let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            let imm64 = i64::from(imm) as u64;
            let mut next = pc + 1;
            match op {
                EbpfOpcode::LdxMemW => {
                    if src != 1 {
                        return Err("ldx from non-ctx register".into());
                    }
                    let idx = match off {
                        0 => 0,
                        4 => 1,
                        8 => 2,
                        _ => return Err(format!("bad ctx offset {off}")),
                    };
                    reg[dst] = u64::from(ctx[idx]);
                }
                EbpfOpcode::AluAndK => reg[dst] = u64::from((reg[dst] as u32) & (imm as u32)),
                EbpfOpcode::AluRshK => reg[dst] = u64::from((reg[dst] as u32) >> (imm as u32)),
                EbpfOpcode::Alu64MovK => reg[dst] = imm64,
                EbpfOpcode::JmpJneK | EbpfOpcode::JmpJsetK => {
                    let taken = if op == EbpfOpcode::JmpJneK {
                        reg[dst] != imm64
                    } else {
                        reg[dst] & imm64 != 0
                    };
                    if taken {
                        next = usize::try_from(pc as i64 + 1 + i64::from(off))
                            .map_err(|_| "negative jump".to_owned())?;
                    }
                }
                EbpfOpcode::JmpExit => return Ok(reg[0]),
            }
            pc = next;
        }
        Err("step limit exceeded".into())
    }

    fn ctx(dev: u32, acc: u32, major: u32, minor: u32) -> [u32; 3] {
        [(acc << 16) | dev, major, minor]
    }

    const C: u32 = DEVCG_DEV_CHAR;
    const B: u32 = DEVCG_DEV_BLOCK;
    const MK: u32 = 1;
    const RD: u32 = 2;
    const WR: u32 = 4;

    fn default_bytes() -> Vec<u8> {
        DeviceProgram::from_allow_list(&DeviceAllowList::oci_default())
            .expect("default program builds")
            .to_le_bytes()
    }

    fn run(bytes: &[u8], c: [u32; 3]) -> u64 {
        eval(bytes, c).expect("evaluation succeeds")
    }

    #[test]
    fn sec1_task32_ebpf_insn_layout() {
        assert_eq!(std::mem::size_of::<EbpfInstruction>(), 8);
        assert_eq!(std::mem::align_of::<EbpfInstruction>(), 4);
    }

    #[test]
    fn sec1_task32_ebpf_insn_bitfield_order() {
        let b = EbpfInstruction::ldx_mem_w(R2, R1, 0).to_le_bytes();
        assert_eq!(b, [0x61, 0x12, 0, 0, 0, 0, 0, 0]);
        assert_ne!(b[1], 0x21);
        let b = EbpfInstruction::ldx_mem_w(EbpfReg::R5, R1, 8).to_le_bytes();
        assert_eq!(b, [0x61, 0x15, 0x08, 0x00, 0, 0, 0, 0]);
        let b = EbpfInstruction::jne_k(R4, -1, -2).to_le_bytes();
        assert_eq!(b, [0x55, 0x04, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let insn = EbpfInstruction::ldx_mem_w(R2, R1, 4);
        assert_eq!(
            (insn.dst(), insn.src(), insn.off(), insn.imm()),
            (2, 1, 4, 0)
        );
        assert_eq!(insn.code(), EbpfOpcode::LdxMemW);
    }

    #[test]
    fn sec1_task32_ebpf_reg_range() {
        assert_eq!(EbpfReg::new(10), Some(EbpfReg::R10));
        assert_eq!(EbpfReg::new(11), None);
        assert_eq!(EbpfInstruction::alu32_rsh_k(EbpfReg::R3, 32), None);
    }

    #[test]
    fn sec1_task32_default_program_golden() {
        #[rustfmt::skip]
        let golden: [[u8; 8]; 55] = [
            [0x61,0x12,0x00,0x00,0x00,0x00,0x00,0x00],
            [0x54,0x02,0x00,0x00,0xff,0xff,0x00,0x00],
            [0x61,0x13,0x00,0x00,0x00,0x00,0x00,0x00],
            [0x74,0x03,0x00,0x00,0x10,0x00,0x00,0x00],
            [0x61,0x14,0x04,0x00,0x00,0x00,0x00,0x00],
            [0x61,0x15,0x08,0x00,0x00,0x00,0x00,0x00],
            // c 1:3
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x01,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x03,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 1:5
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x01,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x05,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 1:7
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x01,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x07,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 1:8
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x01,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x08,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 1:9
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x01,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x09,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 5:0
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x05,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x00,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 5:2
            [0x55,0x02,0x05,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x04,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x03,0x00,0x05,0x00,0x00,0x00],
            [0x55,0x05,0x02,0x00,0x02,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // c 136:*
            [0x55,0x02,0x04,0x00,0x02,0x00,0x00,0x00],
            [0x45,0x03,0x03,0x00,0xf8,0xff,0x00,0x00],
            [0x55,0x04,0x02,0x00,0x88,0x00,0x00,0x00],
            [0xb7,0x00,0x00,0x00,0x01,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            // 既定拒否
            [0xb7,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
            [0x95,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
        ];
        let p = DeviceProgram::from_allow_list(&DeviceAllowList::oci_default()).expect("builds");
        assert_eq!(p.len(), 55);
        assert_eq!(p.to_le_bytes(), golden.concat());
    }

    #[test]
    fn sec1_task32_default_program_allows() {
        let p = default_bytes();
        for (dev, acc, maj, min) in [
            (C, RD, 1, 3),
            (C, WR, 1, 3),
            (C, MK, 1, 3),
            (C, RD | WR, 1, 3),
            (C, RD, 1, 5),
            (C, RD, 1, 7),
            (C, RD, 1, 8),
            (C, RD, 1, 9),
            (C, RD, 5, 0),
            (C, RD, 5, 2),
            (C, RD, 136, 0),
            (C, WR, 136, 4095),
            (C, RD | WR, 136, 0),
        ] {
            assert_eq!(
                run(&p, ctx(dev, acc, maj, min)),
                1,
                "{dev} {acc} {maj}:{min}"
            );
        }
    }

    #[test]
    fn sec1_task32_default_program_denies() {
        let p = default_bytes();
        for (dev, acc, maj, min) in [
            (C, RD, 5, 1),
            (C, RD, 10, 200),
            (C, MK, 10, 200),
            (C, RD, 1, 4),
            (C, RD, 137, 0),
            (B, RD, 8, 0),
            (B, MK, 8, 0),
            (B, RD, 1, 3),
            (C, 8, 1, 3),
        ] {
            assert_eq!(
                run(&p, ctx(dev, acc, maj, min)),
                0,
                "{dev} {acc} {maj}:{min}"
            );
        }
    }

    #[test]
    fn sec1_task32_rule_access_subset() {
        let rule = DeviceRule::new(
            DeviceType::Char,
            1,
            DeviceMinor::Exact(3),
            DeviceAccess::READ.union(DeviceAccess::WRITE),
        );
        assert!(!rule.access().contains(DeviceAccess::MKNOD));
        let p = build_device_program(&[rule]).expect("builds").to_le_bytes();
        assert_eq!(run(&p, ctx(C, RD, 1, 3)), 1);
        assert_eq!(run(&p, ctx(C, WR, 1, 3)), 1);
        assert_eq!(run(&p, ctx(C, RD | WR, 1, 3)), 1);
        assert_eq!(run(&p, ctx(C, MK, 1, 3)), 0);
        assert_eq!(run(&p, ctx(C, RD | MK, 1, 3)), 0);
    }

    #[test]
    fn sec1_task32_rule_minor_any() {
        let rule = DeviceRule::new(DeviceType::Char, 200, DeviceMinor::Any, DeviceAccess::RWM);
        let p = build_device_program(&[rule]).expect("builds").to_le_bytes();
        assert_eq!(run(&p, ctx(C, RD, 200, 0)), 1);
        assert_eq!(run(&p, ctx(C, RD, 200, 1_048_575)), 1);
        assert_eq!(run(&p, ctx(C, RD, 201, 0)), 0);
        assert_eq!(run(&p, ctx(B, RD, 200, 0)), 0);
    }

    #[test]
    fn sec1_task32_empty_rules_deny_all() {
        let p = build_device_program(&[]).expect("builds");
        assert_eq!(p.len(), 8);
        assert_eq!(run(&p.to_le_bytes(), ctx(C, RD, 1, 3)), 0);
    }

    #[test]
    fn sec1_task32_instruction_limit() {
        let rule = DeviceRule::new(
            DeviceType::Char,
            1,
            DeviceMinor::Exact(3),
            DeviceAccess::RWM,
        );
        let ok = build_device_program(&vec![rule; 681]).expect("4094 instructions fit");
        assert_eq!(ok.len(), 4094);
        let err = build_device_program(&vec![rule; 682]).expect_err("4100 instructions exceed");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.step, CgroupStep::BuildDeviceProgram);
        assert_eq!(
            err.message,
            "device cgroup program needs 4100 instructions, exceeding the limit of 4096"
        );
    }

    #[test]
    fn sec1_task32_license_string() {
        assert_eq!(DEVICE_PROGRAM_LICENSE.to_bytes(), b"Apache-2.0");
    }
}
