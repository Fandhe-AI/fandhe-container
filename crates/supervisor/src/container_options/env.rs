//! 環境変数（`-e KEY=VALUE`・`--env-file`）の指定モデル（SUP-12・TASK-169.4・#529・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! [`super::ContainerOptions`] が保持する env の入口。`-e` と env ファイルを検証済みの型へ解釈し、
//! [`EnvSet`] で 1 つの順序付き集合へ統合する。結果は [`EnvSet::to_env_strings`] の `KEY=VALUE` 列で、
//! core の `exec::Entrypoint::new` の `env` 引数（`execve` の envp）へそのまま渡せる形式。
//! シェルを経由せず、値の展開・連結もしない。OS 非依存で 3 OS でビルド・テストする。
//!
//! # 優先順位
//!
//! ベース（イメージ / config の env）< env ファイル（指定順）< `-e`（指定順）。
//! 同一 KEY は後勝ちで、出力位置は最初に現れた位置を保つ。
//!
//! # 対応しないもの（REPAIR-3）
//!
//! - 値なしの `-e KEY` / env ファイルの `KEY` 行（Docker ではホスト環境から継承）は、ホスト環境の
//!   意図しない漏洩経路になるため fail-closed で拒否する。将来の対応可否は SUP-12 の判断事項。
//! - env ファイル内のクォート除去・変数展開は行わない（VALUE は行の `=` 以降をそのまま使う）。
//! - 本番 launcher・CLI からの結線は未実装（TASK-79・後続作業）。
//!
//! # 外部入力の扱い
//!
//! 件数・1 要素長・合計長・ファイルサイズを確保前に検証する。エラーメッセージは固定の英語文言で、
//! env の値・ファイル内容・入力文字列は含めない（env は秘密情報を含み得るため）。

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use fandhe_container_core::oci_runtime::{CONFIG_MAX_ENV, CONFIG_MAX_STRING_BYTES};
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

/// env 件数の上限（core の `exec::ENTRYPOINT_MAX_ENV` と同値。`exec` は Linux 限定のため
/// OS 非依存の config 側定数を参照する）。
pub const ENV_MAX_ENTRIES: usize = CONFIG_MAX_ENV;
/// 1 要素（`KEY=VALUE`。NUL 終端を含まない）の最大バイト長。
pub const ENV_MAX_ENTRY_BYTES: usize = CONFIG_MAX_STRING_BYTES;
/// 全要素の合計上限（NUL 終端を含む。core の `exec::ENTRYPOINT_MAX_TOTAL_BYTES` と同値）。
pub const ENV_MAX_TOTAL_BYTES: usize = 1 << 20;
/// env ファイル 1 つの最大バイト数。
pub const ENV_FILE_MAX_BYTES: usize = ENV_MAX_TOTAL_BYTES;

/// `open(2)` に渡す `O_NONBLOCK`（unix のみ。`unsafe`・外部クレートなしで std の `custom_flags` へ渡す）。
///
/// FIFO を読み取りで開くと書き手が現れるまで `open` がブロックするため、非ブロッキングで開いて
/// fd の種別検査で弾く（REPAIR-5）。値は OS・アーキテクチャで異なるため `cfg` で分けて定義する（core の `oci_runtime::config` の
/// `open_checked_candidate` と同じ対象を揃える）。
/// 定義できない環境は 0（フラグなし）になり、open 前の `metadata` 検査のみが防御になる。
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;
#[cfg(not(any(
    all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "s390x",
            target_arch = "loongarch64"
        )
    ),
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
#[cfg_attr(not(unix), allow(dead_code))]
const O_NONBLOCK: i32 = 0;

/// 読み取り専用・非ブロッキング（unix）で env ファイルを開く。
fn open_nonblocking(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NONBLOCK);
    }
    opts.open(path)
}

/// `KEY=VALUE` 1 件（検証済み）。
#[derive(Clone, PartialEq, Eq)]
pub struct EnvVar {
    key: String,
    value: String,
}

// 値は秘密情報を含み得るため、Debug に値を出さない。
impl std::fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvVar")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl EnvVar {
    /// `-e KEY=VALUE` を解釈する。
    ///
    /// KEY は空でなく `=`・NUL を含まない。VALUE は空可で NUL を含まない。値なしの `KEY` は拒否する。
    pub fn parse(input: &str) -> Result<Self, TraitError> {
        if input.len() > ENV_MAX_ENTRY_BYTES {
            return Err(invalid("env entry is too long"));
        }
        let (key, value) = input
            .split_once('=')
            .ok_or_else(|| invalid("env entry must be KEY=VALUE"))?;
        if key.is_empty() {
            return Err(invalid("env key must not be empty"));
        }
        if input.contains('\0') {
            return Err(invalid("env entry must not contain NUL"));
        }
        Ok(Self {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }

    /// 変数名。
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 値。
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// env ファイルの解釈結果（検証済み）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvFile {
    vars: Vec<EnvVar>,
}

impl EnvFile {
    /// ファイル内容を解釈する（純関数）。
    ///
    /// 先頭の UTF-8 BOM（U+FEFF。Windows のエディタが付ける）は除去する（付いたままだと先頭 KEY が
    /// 静かに壊れるため。IO-5）。行単位で、空行と `#` 始まりの行（前置空白を除いた先頭）は無視する。行末の `\r` は除去し、
    /// KEY 側の前置空白は除去する。VALUE は加工しない。不正行は行番号つきのエラーにする
    /// （行の内容は含めない）。
    pub fn parse(content: &str) -> Result<Self, TraitError> {
        // 行ごとの確保の前に全体長を検証する（無制限確保の防止。`read` と同じ上限）。
        if content.len() > ENV_FILE_MAX_BYTES {
            return Err(invalid("env file is too large"));
        }
        let content = content.strip_prefix('\u{feff}').unwrap_or(content);
        let mut vars = Vec::new();
        for (idx, raw) in content.split('\n').enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let var = EnvVar::parse(trimmed).map_err(|e| {
                TraitError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid env file line {}: {}", idx + 1, e.message()),
                )
            })?;
            vars.push(var);
            if vars.len() > ENV_MAX_ENTRIES {
                return Err(invalid("env file has too many entries"));
            }
        }
        Ok(Self { vars })
    }

    /// ファイルを読み込んで解釈する。
    ///
    /// FIFO は書き手がいないと `open(2)` 自体がブロックするため、open 前に `metadata` で通常ファイル
    /// であることを確認し（REPAIR-5）、さらに非ブロッキングで open して fd の `metadata` で再確認する。
    /// 検査後に FIFO へ差し替えられても `O_NONBLOCK` により open は即座に返り、fd 種別検査で拒否される
    /// （TOCTOU 対策）。通常ファイルの読み取りは `O_NONBLOCK` の影響を受けない。
    /// [`ENV_FILE_MAX_BYTES`] 超過・非 UTF-8 は拒否する。
    pub fn read(path: &Path) -> Result<Self, TraitError> {
        let pre = std::fs::metadata(path).map_err(|_| invalid("cannot open env file"))?;
        if !pre.is_file() {
            return Err(invalid("env file must be a regular file"));
        }
        let file = open_nonblocking(path).map_err(|_| invalid("cannot open env file"))?;
        let meta = file
            .metadata()
            .map_err(|_| invalid("cannot stat env file"))?;
        if !meta.is_file() {
            return Err(invalid("env file must be a regular file"));
        }
        let mut buf = Vec::new();
        file.take(ENV_FILE_MAX_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|_| invalid("cannot read env file"))?;
        if buf.len() > ENV_FILE_MAX_BYTES {
            return Err(invalid("env file is too large"));
        }
        let content = String::from_utf8(buf).map_err(|_| invalid("env file must be UTF-8"))?;
        Self::parse(&content)
    }

    /// 解釈済みの変数（記載順）。
    pub fn vars(&self) -> &[EnvVar] {
        &self.vars
    }
}

/// 統合済みの env 集合（KEY で重複排除・順序保持）。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EnvSet {
    entries: Vec<EnvVar>,
}

impl std::fmt::Debug for EnvSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(&self.entries).finish()
    }
}

impl EnvSet {
    /// 空の集合。
    pub fn new() -> Self {
        Self::default()
    }

    /// ベース env・env ファイル・`-e` を優先順位どおりに統合する。
    ///
    /// ベース < env ファイル（指定順）< `-e`（指定順）。件数・合計長の上限を超えると `InvalidArgument`。
    /// 検証するのは env 単体の上限のみで、パス・argv を含めた起動可能性は保証しない
    /// （[`EnvSet::check_entrypoint_budget`] で別途検証する）。
    /// 重複排除は KEY の索引で行い入力件数に対し線形。値の複製は上限検証の後に 1 回だけ行う。入力の各要素は検証済み（[`EnvVar::parse`]・
    /// [`EnvFile::parse`] 経由）であることが前提で、統合後の件数は都度上限検証する。
    pub fn resolve(
        base: &[EnvVar],
        files: &[EnvFile],
        vars: &[EnvVar],
    ) -> Result<Self, TraitError> {
        // 値を複製する前に、上書き・追加後の件数と合計長を借用のまま算出して上限検証する
        // （入力が上限超過でも確保しない）。位置は最初に現れた KEY、値は最後に現れたものを採る。
        let mut index: HashMap<&str, usize> = HashMap::new();
        let mut picked: Vec<&EnvVar> = Vec::new();
        let all = base
            .iter()
            .chain(files.iter().flat_map(|f| f.vars.iter()))
            .chain(vars.iter());
        let mut total = 0usize;
        for v in all {
            let len = v.key.len() + 1 + v.value.len();
            match index.get(v.key.as_str()) {
                Some(&i) => {
                    let Some(slot) = picked.get_mut(i) else {
                        return Err(invalid("env index is inconsistent"));
                    };
                    let old = slot.key.len() + 1 + slot.value.len();
                    total = total.saturating_sub(old + 1).saturating_add(len + 1);
                    *slot = v;
                }
                None => {
                    if picked.len() >= ENV_MAX_ENTRIES {
                        return Err(invalid("too many env entries"));
                    }
                    index.insert(v.key.as_str(), picked.len());
                    picked.push(v);
                    total = total.saturating_add(len + 1);
                }
            }
            if total > ENV_MAX_TOTAL_BYTES {
                return Err(invalid("env is too large"));
            }
        }
        let set = Self {
            entries: picked.into_iter().cloned().collect(),
        };
        set.check_limits()?;
        Ok(set)
    }

    /// 起動時のパス・argv を含めた合計が core の `exec::Entrypoint::new` の上限
    /// （[`ENV_MAX_TOTAL_BYTES`]。パス・argv・env の NUL 終端込み合計）に収まるか検証する。
    ///
    /// [`EnvSet::resolve`] は env のみで上限を検証するため、上限近くの env は argv 次第で
    /// `Entrypoint::new` に拒否される。launcher は `Entrypoint::new` の前（または代わりに）これを呼び、
    /// 受け渡し先で初めて失敗することを避ける（SUP-12・TASK-169.4。本番 launcher の結線は TASK-79）。
    pub fn check_entrypoint_budget<S: AsRef<str>>(
        &self,
        path: &str,
        args: &[S],
    ) -> Result<(), TraitError> {
        let mut total = path.len().saturating_add(1);
        for a in args {
            total = total.saturating_add(a.as_ref().len().saturating_add(1));
        }
        for e in &self.entries {
            total = total.saturating_add(e.key.len() + 1 + e.value.len() + 1);
        }
        if total > ENV_MAX_TOTAL_BYTES {
            return Err(invalid("entrypoint with env is too large"));
        }
        Ok(())
    }

    fn check_limits(&self) -> Result<(), TraitError> {
        if self.entries.len() > ENV_MAX_ENTRIES {
            return Err(invalid("too many env entries"));
        }
        let mut total = 0usize;
        for e in &self.entries {
            // KEY + '=' + VALUE。
            let len = e.key.len() + 1 + e.value.len();
            if len > ENV_MAX_ENTRY_BYTES {
                return Err(invalid("env entry is too long"));
            }
            // NUL 終端を含めて合計する。
            total = total.saturating_add(len + 1);
        }
        if total > ENV_MAX_TOTAL_BYTES {
            return Err(invalid("env is too large"));
        }
        Ok(())
    }

    /// 統合済みの変数（出力順）。
    pub fn iter(&self) -> impl Iterator<Item = &EnvVar> {
        self.entries.iter()
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空かどうか。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `exec::Entrypoint::new` の `env` へ渡す `KEY=VALUE` 列。
    pub fn to_env_strings(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|e| format!("{}={}", e.key, e.value))
            .collect()
    }
}

fn invalid(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(s: &str) -> EnvVar {
        EnvVar::parse(s).unwrap()
    }

    /// SUP-12・TASK-169.4: KEY=VALUE の解釈（空 VALUE・VALUE 内の `=`）。
    #[test]
    fn sup12_env_parse_valid() {
        let v = var("A=b");
        assert_eq!((v.key(), v.value()), ("A", "b"));
        let v = var("A=");
        assert_eq!((v.key(), v.value()), ("A", ""));
        let v = var("A=b=c d");
        assert_eq!((v.key(), v.value()), ("A", "b=c d"));
    }

    /// SUP-12・TASK-169.4: 不正な指定は InvalidArgument。入力値はメッセージに出ない。
    #[test]
    fn sup12_env_parse_rejects_invalid() {
        let long = format!("K={}", "x".repeat(ENV_MAX_ENTRY_BYTES));
        for bad in ["", "=V", "KEY", "A=b\0c", "A\0=b", long.as_str()] {
            let e = EnvVar::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad:?}");
        }
        let e = EnvVar::parse("dummy-secret").unwrap_err();
        assert!(!e.message().contains("dummy-secret"));
        // 上限ちょうどは受理。
        let ok = format!("K={}", "x".repeat(ENV_MAX_ENTRY_BYTES - 2));
        assert!(EnvVar::parse(&ok).is_ok());
    }

    /// SUP-12・TASK-169.4: Debug は値を出さない。
    #[test]
    fn sup12_env_debug_redacts_value() {
        let s = format!("{:?}", var("K=dummy-secret"));
        assert!(s.contains('K') && !s.contains("dummy-secret"));
    }

    /// SUP-12・TASK-169.4: env ファイルのコメント・空行・CRLF・前置空白・クォート非加工。
    #[test]
    fn sup12_env_file_parse() {
        let f = EnvFile::parse("# c\n\n  A=1\r\nB=\"q\"\n  # c2\nC=x=y\n").unwrap();
        let got: Vec<_> = f.vars().iter().map(|v| (v.key(), v.value())).collect();
        assert_eq!(got, [("A", "1"), ("B", "\"q\""), ("C", "x=y")]);
    }

    /// SUP-12・TASK-169.4: 値なし行は行番号つきで拒否し、内容を含めない。
    #[test]
    fn sup12_env_file_rejects_bad_line_with_number() {
        let e = EnvFile::parse("A=1\n\nBAD-dummy-secret\n").unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(e.message().contains("line 3"), "{}", e.message());
        assert!(!e.message().contains("dummy-secret"));
    }

    /// SUP-12・TASK-169.4: 統合順序はベース < env ファイル < -e、後勝ちで位置は最初のまま。
    #[test]
    fn sup12_env_resolve_precedence() {
        let base = [var("A=base"), var("B=base"), var("C=base")];
        let f1 = EnvFile::parse("B=f1\nD=f1\n").unwrap();
        let f2 = EnvFile::parse("D=f2\nE=f2\n").unwrap();
        let cli = [var("C=cli"), var("F=cli"), var("E=cli")];
        let set = EnvSet::resolve(&base, &[f1, f2], &cli).unwrap();
        assert_eq!(
            set.to_env_strings(),
            ["A=base", "B=f1", "C=cli", "D=f2", "E=cli", "F=cli"]
        );
        assert_eq!(set.len(), 6);
        assert!(EnvSet::new().is_empty());
    }

    /// SUP-12・TASK-169.4: 件数・合計長の上限超過は拒否する。
    #[test]
    fn sup12_env_resolve_limits() {
        let many: Vec<_> = (0..=ENV_MAX_ENTRIES)
            .map(|i| var(&format!("K{i}=v")))
            .collect();
        assert_eq!(
            EnvSet::resolve(&many, &[], &[]).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        // 1 要素 100000 バイト × 11 = 合計 1 MiB 超。
        let big: Vec<_> = (0..11)
            .map(|i| var(&format!("K{i}={}", "x".repeat(100_000))))
            .collect();
        assert_eq!(
            EnvSet::resolve(&big, &[], &[]).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    /// SUP-12・TASK-169.4: 上限超過の内容は行ごとの確保の前に拒否する。
    #[test]
    fn sup12_env_file_parse_rejects_oversized_content() {
        let content = "\n".repeat(ENV_FILE_MAX_BYTES + 1);
        let e = EnvFile::parse(&content).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "env file is too large");
    }

    /// SUP-12・TASK-169.4: 同一 KEY の上書きで合計が上限内に収まる場合は受理し、複製前に超過を拒否する。
    #[test]
    fn sup12_env_resolve_override_total_checked_before_copy() {
        let big = |k: &str| var(&format!("{k}={}", "x".repeat(100_000)));
        // 同一 KEY の繰り返しは合計に累積しない。
        let same: Vec<_> = (0..50).map(|_| big("K")).collect();
        assert_eq!(EnvSet::resolve(&same, &[], &[]).unwrap().len(), 1);
        // 小さい値を大きい値で上書きして上限を超える場合も拒否する。
        let base: Vec<_> = (0..10).map(|i| var(&format!("K{i}=v"))).collect();
        let over: Vec<_> = (0..11).map(|i| big(&format!("K{i}"))).collect();
        assert_eq!(
            EnvSet::resolve(&base, &[], &over).unwrap_err().message(),
            "env is too large"
        );
    }

    /// SUP-12・TASK-169.4: env 単体で上限ちょうどでも、パス・argv を含めると予算超過で拒否する。
    #[test]
    fn sup12_env_entrypoint_budget() {
        // 1 要素 100000 バイト × 10 = 1_000_000 + NUL 等。env 単体では上限内。
        let big: Vec<_> = (0..10)
            .map(|i| var(&format!("K{i}={}", "x".repeat(100_000))))
            .collect();
        let set = EnvSet::resolve(&big, &[], &[]).unwrap();
        assert!(set.check_entrypoint_budget("/bin/sh", &["sh"]).is_ok());
        let long_arg = "a".repeat(60_000);
        let e = set
            .check_entrypoint_budget("/bin/sh", &["sh", long_arg.as_str()])
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// SUP-12・TASK-169.4: env ファイルの読み込み（上限ちょうど受理・超過拒否・ディレクトリ拒否・非 UTF-8 拒否）。
    #[test]
    fn sup12_env_file_read() {
        let dir = std::env::temp_dir().join(format!("fc-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.env");

        std::fs::write(&p, "A=1\n").unwrap();
        assert_eq!(EnvFile::read(&p).unwrap().vars().len(), 1);

        // 上限ちょうど: 空行で埋める（解釈は成功）。
        std::fs::write(&p, "\n".repeat(ENV_FILE_MAX_BYTES)).unwrap();
        assert!(EnvFile::read(&p).unwrap().vars().is_empty());
        std::fs::write(&p, "\n".repeat(ENV_FILE_MAX_BYTES + 1)).unwrap();
        assert_eq!(
            EnvFile::read(&p).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        std::fs::write(&p, [b'A', b'=', 0xff, 0xfe]).unwrap();
        assert!(EnvFile::read(&p).is_err());

        // BOM 付きファイルでも先頭 KEY が壊れない。
        std::fs::write(&p, "\u{feff}A=1\nB=2\n").unwrap();
        assert_eq!(EnvFile::read(&p).unwrap().vars()[0].key(), "A");

        assert!(EnvFile::read(&dir).is_err());
        assert!(EnvFile::read(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-12・TASK-169.4: 先頭 BOM は除去し、2 行目以降の U+FEFF は KEY に残る（加工しない）。
    #[test]
    fn sup12_env_file_parse_strips_leading_bom() {
        let f = EnvFile::parse("\u{feff}A=1\nB=2\n").unwrap();
        let got: Vec<_> = f.vars().iter().map(|v| (v.key(), v.value())).collect();
        assert_eq!(got, [("A", "1"), ("B", "2")]);
    }

    /// SUP-12・TASK-169.4・REPAIR-5: FIFO は open 前に拒否され、書き手がいなくてもブロックしない。
    #[cfg(unix)]
    #[test]
    fn sup12_env_file_read_rejects_fifo_without_blocking() {
        let dir = std::env::temp_dir().join(format!("fc-envfifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.env");
        let ok = std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "mkfifo must be available on unix test hosts");
        let e = EnvFile::read(&p).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(e.message().contains("regular file"), "{}", e.message());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-12・TASK-169.4・REPAIR-5: metadata 検査後に FIFO へ差し替えられた場合を模し、
    /// 非ブロッキング open が書き手なしの FIFO でも即座に返り、fd 種別が通常ファイルでないことを確認する。
    #[cfg(unix)]
    #[test]
    fn sup12_env_file_open_nonblocking_does_not_hang_on_fifo() {
        let dir = std::env::temp_dir().join(format!("fc-envfifo2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.env");
        let ok = std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "mkfifo must be available on unix test hosts");
        let f = open_nonblocking(&p).unwrap();
        assert!(!f.metadata().unwrap().is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
