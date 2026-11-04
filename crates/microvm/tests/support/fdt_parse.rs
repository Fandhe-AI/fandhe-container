//! 試験用の最小 FDT パーサ（flattened device tree を `(パス, プロパティ名) -> 値` に読む）の正本。
//!
//! 役割: `build_guest_fdt` の出力を公開 API だけで読み戻して具体値で照合する。`tests/arm64_layout.rs`（KVM 不要）と
//! `tests/kvm_device.rs`（aarch64 の実機前提試験が FDT の `cpu@N` の `reg` を読む。#3899）が `#[path]` で共有し、複製しない（REPAIR-1）。
//! 対応: MVM-5・MVM-1・#3788・#3899。

use std::collections::HashMap;

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// `(パス, プロパティ名) -> 値` と、存在するノードのパスの一覧。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub struct Parsed {
    pub props: HashMap<(String, String), Vec<u8>>,
    pub nodes: Vec<String>,
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn parse(blob: &[u8]) -> Parsed {
    assert_eq!(be32(blob, 0), 0xd00d_feed);
    let off_struct = be32(blob, 8) as usize;
    let off_strings = be32(blob, 12) as usize;
    let mut pos = off_struct;
    let mut stack: Vec<String> = Vec::new();
    let mut props = HashMap::new();
    let mut nodes = Vec::new();
    loop {
        let tok = be32(blob, pos);
        pos += 4;
        match tok {
            1 => {
                let end = pos + blob[pos..].iter().position(|&c| c == 0).unwrap();
                let name = String::from_utf8(blob[pos..end].to_vec()).unwrap();
                pos = (end + 1 + 3) & !3;
                stack.push(name);
                let path = format!("/{}", stack[1..].join("/"));
                nodes.push(path);
            }
            2 => {
                stack.pop();
            }
            3 => {
                let len = be32(blob, pos) as usize;
                let nameoff = be32(blob, pos + 4) as usize;
                pos += 8;
                let v = blob[pos..pos + len].to_vec();
                pos = (pos + len + 3) & !3;
                let s = off_strings + nameoff;
                let e = s + blob[s..].iter().position(|&c| c == 0).unwrap();
                let name = String::from_utf8(blob[s..e].to_vec()).unwrap();
                let path = format!("/{}", stack[1..].join("/"));
                props.insert((path, name), v);
            }
            4 => continue,
            9 => break,
            t => panic!("unknown token {t}"),
        }
    }
    Parsed { props, nodes }
}

impl Parsed {
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn get(&self, path: &str, name: &str) -> &Vec<u8> {
        self.props
            .get(&(path.to_string(), name.to_string()))
            .unwrap_or_else(|| panic!("missing {path} {name}"))
    }
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn cells(&self, path: &str, name: &str) -> Vec<u32> {
        self.get(path, name)
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect()
    }
    #[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
    pub fn has(&self, path: &str, name: &str) -> bool {
        self.props
            .contains_key(&(path.to_string(), name.to_string()))
    }
}
