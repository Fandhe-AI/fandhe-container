//! デバイス cgroup の eBPF 命令列の組み立ての結合試験（SEC-1・TASK-32 追補・#1678）。
//!
//! # 役割
//! crate の公開 API（`DeviceAllowList::oci_default`・`DeviceProgram::from_allow_list`・
//! `EbpfInstruction` の各アクセサ・`to_le_bytes`）だけを使い、既定許可リストから組み立てた命令列を
//! 外部の利用者（#1679 のロード層）と同じ立場で検証する。syscall・特権・cgroup を使わない純粋な試験で、
//! 3 OS の既定のテスト集合で動く。ロード・アタッチの実機確認は #1679・#1680・#1681 の担当。
//!
//! 命令列は公開アクセサで復号する小さな評価器で `struct bpf_cgroup_dev_ctx` に対して実行し、
//! 許可・拒否の結果を具体値で照合する。

use fandhe_container_core::cgroups::{
    DEVICE_PROGRAM_MAX_INSNS, DeviceAccess, DeviceAllowList, DeviceMinor, DeviceProgram,
    DeviceType, EbpfOpcode,
};

const CHAR: u32 = 2;
const BLOCK: u32 = 1;
const MKNOD: u32 = 1;
const READ: u32 = 2;
const WRITE: u32 = 4;

/// 公開アクセサから命令を復号して実行し、`r0`（1 = 許可・0 = 拒否）を返す。
fn eval(program: &DeviceProgram, ctx: [u32; 3]) -> u64 {
    let insns = program.instructions();
    let mut reg = [0u64; 11];
    let mut pc = 0usize;
    for _ in 0..10_000 {
        let i = insns.get(pc).expect("pc stays inside the program");
        let dst = usize::from(i.dst());
        let imm = i64::from(i.imm()) as u64;
        let mut next = pc + 1;
        match i.code() {
            EbpfOpcode::LdxMemW => {
                let idx = match i.off() {
                    0 => 0,
                    4 => 1,
                    8 => 2,
                    other => panic!("unexpected ctx offset {other}"),
                };
                reg[dst] = u64::from(ctx[idx]);
            }
            EbpfOpcode::AluAndK => reg[dst] = u64::from((reg[dst] as u32) & (i.imm() as u32)),
            EbpfOpcode::AluRshK => reg[dst] = u64::from((reg[dst] as u32) >> (i.imm() as u32)),
            EbpfOpcode::Alu64MovK => reg[dst] = imm,
            EbpfOpcode::JmpJneK | EbpfOpcode::JmpJsetK => {
                let taken = if i.code() == EbpfOpcode::JmpJneK {
                    reg[dst] != imm
                } else {
                    reg[dst] & imm != 0
                };
                if taken {
                    next = usize::try_from(pc as i64 + 1 + i64::from(i.off()))
                        .expect("jumps are forward");
                }
            }
            EbpfOpcode::JmpExit => return reg[0],
        }
        pc = next;
    }
    panic!("step limit exceeded");
}

fn ctx(dev: u32, acc: u32, major: u32, minor: u32) -> [u32; 3] {
    [(acc << 16) | dev, major, minor]
}

fn default_program() -> DeviceProgram {
    DeviceProgram::from_allow_list(&DeviceAllowList::oci_default()).expect("default program builds")
}

/// SEC-1: 既定許可リストの内容が OCI default devices と pty の固定表と一致する。
#[test]
fn sec1_task32_default_allow_list_contents() {
    let got: Vec<(DeviceType, u32, DeviceMinor, u8)> = DeviceAllowList::oci_default()
        .rules()
        .iter()
        .map(|r| (r.ty(), r.major(), r.minor(), r.access().bits()))
        .collect();
    let rwm = DeviceAccess::RWM.bits();
    assert_eq!(
        got,
        vec![
            (DeviceType::Char, 1, DeviceMinor::Exact(3), rwm),
            (DeviceType::Char, 1, DeviceMinor::Exact(5), rwm),
            (DeviceType::Char, 1, DeviceMinor::Exact(7), rwm),
            (DeviceType::Char, 1, DeviceMinor::Exact(8), rwm),
            (DeviceType::Char, 1, DeviceMinor::Exact(9), rwm),
            (DeviceType::Char, 5, DeviceMinor::Exact(0), rwm),
            (DeviceType::Char, 5, DeviceMinor::Exact(2), rwm),
            (DeviceType::Char, 136, DeviceMinor::Any, rwm),
        ]
    );
}

/// SEC-1: 生成バイト列の長さ・命令数・前置き・既定拒否の末尾が具体値で一致する。
#[test]
fn sec1_task32_default_program_bytes() {
    let p = default_program();
    let bytes = p.to_le_bytes();
    // 前置き 6 + 7 規則 × 6 + pty 規則 5 + 末尾 2 = 55 命令。
    assert_eq!(p.len(), 55);
    assert!(!p.is_empty());
    assert!(p.len() <= DEVICE_PROGRAM_MAX_INSNS);
    assert_eq!(bytes.len(), 55 * 8);
    // 前置き 1 命令目: ldx r2 = *(u32 *)(r1 + 0)。
    assert_eq!(bytes[..8], [0x61, 0x12, 0, 0, 0, 0, 0, 0]);
    // 末尾: r0 = 0; exit。
    assert_eq!(
        bytes[bytes.len() - 16..],
        [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]
    );
}

/// SEC-1: 許可リストの全規則（種別・major・minor・個別アクセス）が許可される。
#[test]
fn sec1_task32_default_program_allows() {
    let p = default_program();
    for (major, minor) in [
        (1, 3),
        (1, 5),
        (1, 7),
        (1, 8),
        (1, 9),
        (5, 0),
        (5, 2),
        (136, 0),
        (136, 4095),
    ] {
        for acc in [MKNOD, READ, WRITE, READ | WRITE, MKNOD | READ | WRITE] {
            assert_eq!(
                eval(&p, ctx(CHAR, acc, major, minor)),
                1,
                "char acc={acc} {major}:{minor}"
            );
        }
    }
}

/// SEC-1: 許可外のデバイス・種別・未知のアクセスビットは既定拒否（fail-closed）になる。
#[test]
fn sec1_task32_default_program_denies() {
    let p = default_program();
    for (dev, acc, major, minor) in [
        // ブロックデバイス（同じ major:minor でも種別違い）。
        (BLOCK, READ, 1, 3),
        (BLOCK, READ, 136, 0),
        // 許可表に無い major:minor（console 5:1・tun 10:200・/dev/mem 1:1・loop 7:0）。
        (CHAR, READ, 5, 1),
        (CHAR, READ, 10, 200),
        (CHAR, READ, 1, 1),
        (CHAR, READ, 1, 4),
        (BLOCK, READ, 7, 0),
        (CHAR, READ, 0, 0),
        (CHAR, READ, 135, 0),
        (CHAR, READ, 137, 0),
        // 未知のアクセスビット（0x8）は拒否側に倒れる。
        (CHAR, 8, 1, 3),
        (CHAR, READ | 8, 136, 0),
        (CHAR, 0x8000, 1, 3),
        // 未知の種別。
        (0, READ, 1, 3),
        (3, READ, 1, 3),
    ] {
        assert_eq!(
            eval(&p, ctx(dev, acc, major, minor)),
            0,
            "dev={dev} acc={acc} {major}:{minor}"
        );
    }
}
