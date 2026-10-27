//! CDI の `env` をコンテナプロセスの環境変数列（OCI `process.env`）へ重ねる純粋関数（TASK-127.4・GPU-2・MS-10）。
//!
//! # 責務境界
//! `cdi_edits::AggregatedEdits::env()`（集計済み。同じキーで値が違えば集計時に拒否済み）を、base の
//! `process.env` に上流 CDI と同じ規則で重ね、検証済みの列を返すだけを担う。FS にも環境にも触れない
//! （3 OS でビルドでき、`unsafe` なし。CLI-1）。フックの `env`（`cdi_apply::hooks`）とは別物で、こちらは
//! コンテナ内で exec されるプロセスの環境変数である。
//!
//! # 呼び出し文脈（配線は #2774）
//! core の実行層が config.json の `process.env` を base として本関数へ渡し、戻りの列を `process.env` へ戻して
//! exec する想定。配線は #2774、実機 GPU での確認は #552。`--env` と CDI env の優先順位も #2774 で決める。
//!
//! # 上流との対応
//! cncf-tags/container-device-interface v1.1.1（cb98bcf66dc68530012483bd56e33e14d815e167）の
//! `internal/ociedit/spec_editor.go` の `createEnvCacheMap` / `AddMultipleProcessEnv` / `addEnv` と同じ合成
//! （キーは最初の `=` より前。既存キーはその位置を置換、無ければ末尾へ追加。base に重複キーがあれば最後の出現を
//! 置換し、他の要素は触らない。実効値の後勝ち正規化は exec 直前の core の `dedup_env_last_wins` が行う）。
//! 形式検査は `pkg/cdi/container-edits.go` の `ValidateEnv`（`=` が無い・キーが空を拒否）に NUL・長さの検査を足した。
//!
//! # 判断と残余
//! - `LD_PRELOAD` 等のキー名の許可リストは設けない（上流に規則が無い）。CDI spec 自体の信頼は読み込み側
//!   （TASK-126）の前提で、env の効果はコンテナ内のプロセスに限られる。
//! - base の要素の中身（NUL 等）は再検証しない（core の config パーサの責務）。
//! - 合計バイトの上限は argv を含まない必要条件としての早期拒否で、最終判定は core の `Entrypoint::new`。
//!
//! エラーの `message` は固定の英語で、キーも値も載せない（トークンを含みうる。A09）。

use std::collections::BTreeMap;
use std::fmt;

use super::{CdiApplyError, CdiApplyErrorCode as Code};
use crate::cdi_edits::AggregatedEdits;
use crate::cdi_spec::EnvList;

/// env の最大件数（core の `CONFIG_MAX_ENV` と同値）。base・CDI 分・合成後のそれぞれに課す。
pub const CDI_APPLY_MAX_ENV: usize = 4096;
/// env 1 要素の最大バイト数（core の `CONFIG_MAX_STRING_BYTES` と同値）。
pub const CDI_APPLY_MAX_ENV_ITEM_BYTES: usize = 131_071;
/// 合成後の env の合計最大バイト数（各要素 + NUL 1。core の `ENTRYPOINT_MAX_TOTAL_BYTES` と同値）。
pub const CDI_APPLY_MAX_ENV_TOTAL_BYTES: usize = 1 << 20;

const fn e(code: Code, message: &'static str) -> CdiApplyError {
    CdiApplyError::new(code, message)
}

/// 合成済みのコンテナプロセス env。フィールドは非公開でアクセサから読む（REPAIR-2）。
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CdiProcessEnv {
    env: Vec<String>,
    replaced: usize,
    appended: usize,
}

impl CdiProcessEnv {
    /// 合成後の `KEY=VALUE` の列（OCI `process.env` の順序）。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// 列を取り出す。
    pub fn into_env(self) -> Vec<String> {
        self.env
    }

    /// base の既存キーを置換した件数（観測用。REPAIR-4）。
    pub fn replaced(&self) -> usize {
        self.replaced
    }

    /// 末尾へ追加した件数（観測用。REPAIR-4）。
    pub fn appended(&self) -> usize {
        self.appended
    }
}

impl fmt::Debug for CdiProcessEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 値は秘密を含みうるため件数だけ出す。
        f.debug_struct("CdiProcessEnv")
            .field(
                "env",
                &format_args!("<{} entries redacted>", self.env.len()),
            )
            .field("replaced", &self.replaced)
            .field("appended", &self.appended)
            .finish()
    }
}

/// 集計済みの CDI `env` を base の `process.env` へ重ねる。
///
/// 上限超過は `ResourceExhausted`、形式不正（NUL・`=` 無し・キー空）は `InvalidArgument`。
/// 確保より前に件数を見る。パニックしない。
pub fn apply_cdi_env(
    base: &[String],
    edits: &AggregatedEdits,
) -> Result<CdiProcessEnv, CdiApplyError> {
    merge_env_entries(base, edits.env())
}

/// 要素のキー（最初の `=` より前。`=` が無ければ全体）。
fn key_of(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(k, _)| k)
}

fn merge_env_entries(base: &[String], cdi: &EnvList) -> Result<CdiProcessEnv, CdiApplyError> {
    if cdi.len() > CDI_APPLY_MAX_ENV || base.len() > CDI_APPLY_MAX_ENV {
        return Err(e(Code::ResourceExhausted, "too many env entries"));
    }
    for item in cdi.iter() {
        if item.contains('\0') {
            return Err(e(Code::InvalidArgument, "CDI env entry contains NUL"));
        }
        if !matches!(item.find('='), Some(i) if i > 0) {
            return Err(e(Code::InvalidArgument, "CDI env entry is not KEY=VALUE"));
        }
        if item.len() > CDI_APPLY_MAX_ENV_ITEM_BYTES {
            return Err(e(Code::ResourceExhausted, "CDI env entry is too long"));
        }
    }

    let mut out: Vec<String> = base.to_vec();
    // キー -> 最後の出現位置（上流の createEnvCacheMap と同じ）。
    let mut index: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, item) in base.iter().enumerate() {
        index.insert(key_of(item), i);
    }
    let (mut replaced, mut appended) = (0usize, 0usize);
    for item in cdi.iter() {
        let key = key_of(item);
        match index.get(key).copied() {
            Some(pos) => {
                let slot = out
                    .get_mut(pos)
                    .ok_or_else(|| e(Code::Internal, "env index out of range"))?;
                *slot = item.clone();
                replaced += 1;
            }
            None => {
                if out.len() >= CDI_APPLY_MAX_ENV {
                    return Err(e(Code::ResourceExhausted, "too many env entries"));
                }
                index.insert(key, out.len());
                out.push(item.clone());
                appended += 1;
            }
        }
    }

    let total = out
        .iter()
        .try_fold(0usize, |acc, s| acc.checked_add(s.len())?.checked_add(1));
    match total {
        Some(t) if t <= CDI_APPLY_MAX_ENV_TOTAL_BYTES => {}
        _ => return Err(e(Code::ResourceExhausted, "env total size is too large")),
    }
    Ok(CdiProcessEnv {
        env: out,
        replaced,
        appended,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn run(base: &[&str], cdi: &[&str]) -> Result<CdiProcessEnv, CdiApplyError> {
        merge_env_entries(&s(base), &EnvList::from_entries(s(cdi)))
    }

    /// GPU-2: 既存キーは置換、新キーは末尾へ。
    #[test]
    fn gpu2_task127_4_replace_and_append() {
        let r = run(
            &["PATH=/usr/bin", "NVIDIA_VISIBLE_DEVICES=all"],
            &[
                "NVIDIA_VISIBLE_DEVICES=void",
                "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu",
            ],
        )
        .unwrap();
        assert_eq!(
            r.env(),
            [
                "PATH=/usr/bin",
                "NVIDIA_VISIBLE_DEVICES=void",
                "NVIDIA_CTK_LIBCUDA_DIR=/usr/lib/x86_64-linux-gnu"
            ]
        );
        assert_eq!((r.replaced(), r.appended()), (1, 1));
    }

    /// GPU-2: base のキーが重複していれば最後の出現を置換する（上流と同じ）。
    #[test]
    fn gpu2_task127_4_duplicate_base_key_replaces_last() {
        let r = run(&["K=a", "X=1", "K=b"], &["K=c"]).unwrap();
        assert_eq!(r.env(), ["K=a", "X=1", "K=c"]);
    }

    /// GPU-2: base の `=` 無し要素もキーとして置換される。
    #[test]
    fn gpu2_task127_4_base_without_equals() {
        let r = run(&["K"], &["K=v"]).unwrap();
        assert_eq!(r.env(), ["K=v"]);
    }

    /// GPU-2: 空の入力。
    #[test]
    fn gpu2_task127_4_empty_inputs() {
        let r = run(&["A=1"], &[]).unwrap();
        assert_eq!(r.env(), ["A=1"]);
        assert_eq!((r.replaced(), r.appended()), (0, 0));
        let r = run(&[], &["A=1", "B=2"]).unwrap();
        assert_eq!(r.env(), ["A=1", "B=2"]);
        assert_eq!(r.into_env(), s(&["A=1", "B=2"]));
    }

    /// GPU-2: 値の `=` はキーに含めない。
    #[test]
    fn gpu2_task127_4_value_with_equals() {
        let r = run(&["A=old"], &["A=b=c"]).unwrap();
        assert_eq!(r.env(), ["A=b=c"]);
    }

    /// GPU-2: 形式不正は固定文言で拒否する。
    #[test]
    fn gpu2_task127_4_malformed_rejected() {
        for (bad, msg) in [
            ("NOEQ", "CDI env entry is not KEY=VALUE"),
            ("=v", "CDI env entry is not KEY=VALUE"),
            ("K=\0x", "CDI env entry contains NUL"),
        ] {
            let err = run(&[], &[bad]).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(err.message(), msg);
        }
    }

    /// GPU-2: 件数・要素長・合計バイトの境界。
    #[test]
    fn gpu2_task127_4_limits() {
        let many = |n: usize| -> Vec<String> { (0..n).map(|i| format!("K{i}=v")).collect() };
        let ok = EnvList::from_entries(many(CDI_APPLY_MAX_ENV));
        assert_eq!(merge_env_entries(&[], &ok).unwrap().env().len(), 4096);
        let over = EnvList::from_entries(many(CDI_APPLY_MAX_ENV + 1));
        let err = merge_env_entries(&[], &over).unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
        // base 満杯 + 新キー 1 件は合成後の件数超過。置換なら受理。
        let base = many(CDI_APPLY_MAX_ENV);
        let one = EnvList::from_entries(s(&["NEW=1"]));
        assert_eq!(
            merge_env_entries(&base, &one).unwrap_err().code(),
            Code::ResourceExhausted
        );
        let rep = EnvList::from_entries(s(&["K0=w"]));
        assert_eq!(merge_env_entries(&base, &rep).unwrap().replaced(), 1);
        let too_many_base = many(CDI_APPLY_MAX_ENV + 1);
        assert_eq!(
            merge_env_entries(&too_many_base, &EnvList::from_entries(vec![]))
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );

        // 要素長。
        let item = |n: usize| format!("K={}", "a".repeat(n - 2));
        assert!(run(&[], &[&item(CDI_APPLY_MAX_ENV_ITEM_BYTES)]).is_ok());
        let err = run(&[], &[&item(CDI_APPLY_MAX_ENV_ITEM_BYTES + 1)]).unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
        assert_eq!(err.message(), "CDI env entry is too long");

        // 合計バイト: 各要素に NUL 1 を足して 1 MiB ちょうど（7 * 131_072 + 131_072）。
        let mk = |tail: usize| -> Vec<String> {
            let mut v: Vec<String> = (0..7)
                .map(|i| format!("K{i}={}", "a".repeat(CDI_APPLY_MAX_ENV_ITEM_BYTES - 3)))
                .collect();
            v.push(format!("L={}", "a".repeat(tail)));
            v
        };
        // 各 K 要素は 131_071 バイト（+ NUL 1）。7 * 131_072 + (2 + tail + 1) = 1 MiB。
        let exact = CDI_APPLY_MAX_ENV_TOTAL_BYTES - 7 * (CDI_APPLY_MAX_ENV_ITEM_BYTES + 1) - 3;
        let ok = mk(exact);
        let refs: Vec<&str> = ok.iter().map(String::as_str).collect();
        assert!(run(&[], &refs).is_ok());
        let mut bad = mk(exact);
        bad.push("Z=".to_string());
        let refs: Vec<&str> = bad.iter().map(String::as_str).collect();
        let err = run(&[], &refs).unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
        assert_eq!(err.message(), "env total size is too large");
    }

    /// GPU-2・A09: エラーと Debug に値を載せない。
    #[test]
    fn gpu2_task127_4_no_secret_leak() {
        let err = run(&[], &["TOKEN=DUMMY_SECRET_ENV_12345\0"]).unwrap_err();
        assert!(!err.to_string().contains("DUMMY_SECRET"));
        let r = run(&[], &["TOKEN=DUMMY_SECRET_ENV_12345"]).unwrap();
        assert!(!format!("{r:?}").contains("DUMMY_SECRET"));
    }
}
