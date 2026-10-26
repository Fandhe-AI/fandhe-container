//! 起動オプション文書(`FCOPT1`)の符号化と復号(SUP-12・CLI-1・SEC-1・REPAIR-2・#2713)。
//!
//! # 役割と呼び出し文脈
//!
//! CLI の `create` が検証した `--ulimit`・`--env`(`--env-file` の展開後)・`--ipc`・`--shm-size`・`--tmpfs` を、
//! 状態ルート配下の 0600 のファイル([`store`](super::store))経由で supervisor の `start` へ渡すためのバイト列の形。
//! argv・環境変数・継承 fd は supervisor の起動契約([`crate::start_contract`])で使えず(入口と特権ランチャーが
//! fd 3 以降を閉じ、env を契約に含めない)、制御チャネルは launch の後に作られるため間に合わない。このため
//! ディスク上の私的な文書を `start_entry` の手順 2c が読み、[`ContainerOptionsDocument::to_container_options`] の
//! 結果を `ProductionStartDeps::with_container_options` へ渡す。label は文書に載せない(create 時に core の状態記録へ
//! 直接書く)。secrets / configs も載せない(ホストのパスを特権の supervisor が読むと confused deputy になるため、
//! 別の設計が要る。REPAIR-3)。
//!
//! # 形式
//!
//! ```text
//! FCOPT1\n
//! <kind> <len>\n<len バイトの UTF-8>\n     (繰り返し)
//! ```
//!
//! `kind` は閉じた語彙 `ulimit`・`env`・`ipc`・`shm-size`・`tmpfs`。`len` は 10 進(先頭 0 と `+` は不可)。
//! 中身は Docker 構文の生の文字列で、復号のたびに既存のパーサ([`Ulimit::parse`] 等)へ通し直す(未信頼の入力として
//! 検証する。値の改行を許すため、行区切りではなく長さ接頭辞にする)。符号化と復号を同じ型に置き、壊れた文書を
//! 作れないようにする(REPAIR-2)。
//!
//! # 外部入力の扱い
//!
//! ファイル全体・レコード数・1 レコードの長さを、確保の前に上限と照合する。エラーは固定の英語文言で、値を含めない。
//! `Debug` は env の値を伏せる(秘密情報を含み得る)。

use fandhe_container_core::tmpfs::TMPFS_MAX_MOUNTS;
use fandhe_container_core::traits::types::{ErrorCode, TraitError};

use super::env::{ENV_MAX_ENTRIES, ENV_MAX_ENTRY_BYTES, ENV_MAX_TOTAL_BYTES, EnvSet, EnvVar};
use super::mounts::{MountOptions, ShmSize, TmpfsOption};
use super::{ContainerOptions, IpcMode, Ulimit};

/// 文書の先頭行(版つき。版が変わる形式変更ではこの値を上げる)。
pub const OPTIONS_DOC_MAGIC: &[u8] = b"FCOPT1\n";

/// 文書全体の最大バイト数(env の合計上限に、ulimit・tmpfs・見出し行の余裕を足した値)。
pub const OPTIONS_DOC_MAX_BYTES: usize = ENV_MAX_TOTAL_BYTES + 256 * 1024;

/// `--ulimit` の最大件数(rlimit の種別は 16 種で、重複は拒否される)。
pub const OPTIONS_MAX_ULIMITS: usize = 16;

const ULIMIT_RECORD_MAX: usize = 64;
const IPC_RECORD_MAX: usize = 32;
const SHM_RECORD_MAX: usize = 64;
const TMPFS_RECORD_MAX: usize = 4096;
/// 作成世代の識別子の最大バイト数(#2713)。
pub const GENERATION_MAX: usize = 64;
/// 作成世代の記録(`gen <len>\n<値>\n`)の最大バイト数(後から足す分を、全体の上限の検査で確保する)。
const GENERATION_RECORD_RESERVE: usize = 4 + 1 + 2 + 1 + GENERATION_MAX + 1;
/// 見出し行(`<kind> <len>`)の最大バイト数(最長の kind `shm-size` と 10 進 7 桁に十分な余裕)。
const HEADER_LINE_MAX: usize = 24;
/// `len` の最大桁数(`OPTIONS_DOC_MAX_BYTES` は 7 桁に収まる)。
const LEN_DIGITS_MAX: usize = 7;

fn invalid(message: &'static str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

/// 検証済みの起動オプション文書(各フィールドは Docker 構文の生の文字列。構築時に既存のパーサで検証済み)。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ContainerOptionsDocument {
    ulimits: Vec<String>,
    env: Vec<String>,
    ipc: Option<String>,
    shm_size: Option<String>,
    tmpfs: Vec<String>,
    /// 作成世代の識別子(状態記録の annotations と照合する。別の世代の残骸を適用しないため。#2713)。
    generation: Option<String>,
}

impl std::fmt::Debug for ContainerOptionsDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // env の値は秘密情報を含み得るため、キーだけを出す。
        let keys: Vec<&str> = self
            .env
            .iter()
            .map(|e| e.split_once('=').map_or("", |(k, _)| k))
            .collect();
        f.debug_struct("ContainerOptionsDocument")
            .field("ulimits", &self.ulimits)
            .field("env_keys", &keys)
            .field("ipc", &self.ipc)
            .field("shm_size", &self.shm_size)
            .field("tmpfs", &self.tmpfs)
            .field("generation", &self.generation)
            .finish()
    }
}

impl ContainerOptionsDocument {
    /// 生の指定から作る。件数・長さの上限、各パーサの検証、指定同士の矛盾(`--ipc=host` と `--shm-size` 等・
    /// ulimit の種別重複)を、ここで一度に検証する(CLI の create と supervisor の復号が同じ関門を通る)。
    pub fn new(
        ulimits: Vec<String>,
        env: Vec<String>,
        ipc: Option<String>,
        shm_size: Option<String>,
        tmpfs: Vec<String>,
    ) -> Result<Self, TraitError> {
        if ulimits.len() > OPTIONS_MAX_ULIMITS {
            return Err(invalid("too many ulimit records"));
        }
        if env.len() > ENV_MAX_ENTRIES {
            return Err(invalid("too many env records"));
        }
        if tmpfs.len() > TMPFS_MAX_MOUNTS {
            return Err(invalid("too many tmpfs records"));
        }
        let doc = Self {
            ulimits,
            env,
            ipc,
            shm_size,
            tmpfs,
            generation: None,
        };
        doc.check_record_lengths()?;
        // 符号化後の文書全体(見出し・区切りを含む)が、supervisor の読み取りの上限に作成世代の記録の分を足しても
        // 収まることを確かめる。create が書けても start の読み取りが拒否する文書を作らない(REPAIR-2・#2713)。
        if doc.encode().len() + GENERATION_RECORD_RESERVE > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        // 変換に通して検証する(変換結果は捨てる。保持するのは生の文字列)。
        doc.to_container_options()?;
        Ok(doc)
    }

    fn check_record_lengths(&self) -> Result<(), TraitError> {
        let too_long = || invalid("an options record is too long");
        if self.ulimits.iter().any(|s| s.len() > ULIMIT_RECORD_MAX)
            || self.env.iter().any(|s| s.len() > ENV_MAX_ENTRY_BYTES)
            || self.ipc.as_ref().is_some_and(|s| s.len() > IPC_RECORD_MAX)
            || self
                .shm_size
                .as_ref()
                .is_some_and(|s| s.len() > SHM_RECORD_MAX)
            || self.tmpfs.iter().any(|s| s.len() > TMPFS_RECORD_MAX)
        {
            return Err(too_long());
        }
        Ok(())
    }

    /// 作成世代の識別子を持たせる(英数字・`-`・`_` のみ、1〜[`GENERATION_MAX`] バイト。#2713)。
    ///
    /// CLI の create が、同じ値を状態記録の annotations(`store::GENERATION_ANNOTATION`)にも書く。supervisor は両者が
    /// 一致する文書だけを適用する(同じ ID の前のコンテナの残骸を、次のコンテナに適用しない。fail-closed)。
    pub fn with_generation(mut self, generation: String) -> Result<Self, TraitError> {
        let ok = !generation.is_empty()
            && generation.len() <= GENERATION_MAX
            && generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(invalid("the options generation is invalid"));
        }
        self.generation = Some(generation);
        Ok(self)
    }

    /// 作成世代の識別子。
    pub fn generation(&self) -> Option<&str> {
        self.generation.as_deref()
    }

    /// 何も指定していない文書か(空なら CLI は文書を書かない)。
    pub fn is_empty(&self) -> bool {
        self.ulimits.is_empty()
            && self.env.is_empty()
            && self.ipc.is_none()
            && self.shm_size.is_none()
            && self.tmpfs.is_empty()
    }

    /// 検証済みの [`ContainerOptions`] へ変換する(label・secrets・configs は含まない)。
    ///
    /// env の件数・合計長は [`EnvSet::resolve`] が、`--ipc=host` と `/dev/shm` の矛盾は `tmpfs_set` が拒否する。
    pub fn to_container_options(&self) -> Result<ContainerOptions, TraitError> {
        let ulimits = self
            .ulimits
            .iter()
            .map(|s| Ulimit::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let vars = self
            .env
            .iter()
            .map(|s| EnvVar::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        let mut mounts = MountOptions::default();
        if let Some(size) = &self.shm_size {
            mounts = mounts.with_shm_size(ShmSize::parse(size)?);
        }
        for t in &self.tmpfs {
            mounts = mounts.with_tmpfs(TmpfsOption::parse(t)?)?;
        }
        let mut options = ContainerOptions::new()
            .with_ulimits(ulimits)?
            .with_env(EnvSet::resolve(&[], &[], &vars)?)
            .with_mounts(mounts);
        if let Some(ipc) = &self.ipc {
            options = options.with_ipc_mode(IpcMode::parse(ipc)?);
        }
        // 矛盾する指定(ファイルを読まない検査)をここで拒否する。
        options.tmpfs_set()?;
        Ok(options)
    }

    /// `--ulimit` の生の指定。
    pub fn ulimits(&self) -> &[String] {
        &self.ulimits
    }

    /// `--env` の生の指定(`KEY=VALUE`)。
    pub fn env(&self) -> &[String] {
        &self.env
    }

    /// バイト列へ符号化する。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(OPTIONS_DOC_MAGIC);
        let mut put = |kind: &str, body: &str| {
            out.extend_from_slice(kind.as_bytes());
            out.push(b' ');
            out.extend_from_slice(body.len().to_string().as_bytes());
            out.push(b'\n');
            out.extend_from_slice(body.as_bytes());
            out.push(b'\n');
        };
        for s in &self.ulimits {
            put("ulimit", s);
        }
        for s in &self.env {
            put("env", s);
        }
        if let Some(s) = &self.ipc {
            put("ipc", s);
        }
        if let Some(s) = &self.shm_size {
            put("shm-size", s);
        }
        for s in &self.tmpfs {
            put("tmpfs", s);
        }
        if let Some(s) = &self.generation {
            put("gen", s);
        }
        out
    }

    /// バイト列から復号する。マジック違い・桁あふれ・未知の kind・切れ・余剰・上限超過・非 UTF-8・
    /// `ipc` / `shm-size` の重複・各パーサの拒否は `InvalidArgument`(固定文言)。
    pub fn decode(bytes: &[u8]) -> Result<Self, TraitError> {
        if bytes.len() > OPTIONS_DOC_MAX_BYTES {
            return Err(invalid("options document is too large"));
        }
        let mut rest = bytes
            .strip_prefix(OPTIONS_DOC_MAGIC)
            .ok_or_else(|| invalid("options document has an unknown header"))?;
        let (mut ulimits, mut env, mut tmpfs) = (Vec::new(), Vec::new(), Vec::new());
        let (mut ipc, mut shm_size): (Option<String>, Option<String>) = (None, None);
        let mut generation: Option<String> = None;
        // 全体の上限があるため、レコード数は `new` の件数検査と合わせて有限。
        while !rest.is_empty() {
            let line_end = rest
                .iter()
                .take(HEADER_LINE_MAX)
                .position(|b| *b == b'\n')
                .ok_or_else(|| invalid("options record header is malformed"))?;
            let line = rest
                .get(..line_end)
                .ok_or_else(|| invalid("options record header is malformed"))?;
            let (kind, len) = split_header(line)?;
            let body_start = line_end + 1;
            let body_end = body_start
                .checked_add(len)
                .ok_or_else(|| invalid("options record is truncated"))?;
            let body = rest
                .get(body_start..body_end)
                .ok_or_else(|| invalid("options record is truncated"))?;
            if rest.get(body_end) != Some(&b'\n') {
                return Err(invalid("options record is truncated"));
            }
            rest = rest
                .get(body_end + 1..)
                .ok_or_else(|| invalid("options record is truncated"))?;
            let max = match kind {
                "ulimit" => ULIMIT_RECORD_MAX,
                "env" => ENV_MAX_ENTRY_BYTES,
                "ipc" => IPC_RECORD_MAX,
                "shm-size" => SHM_RECORD_MAX,
                "tmpfs" => TMPFS_RECORD_MAX,
                "gen" => GENERATION_MAX,
                _ => return Err(invalid("options record has an unknown kind")),
            };
            if len > max {
                return Err(invalid("an options record is too long"));
            }
            let text = std::str::from_utf8(body)
                .map_err(|_| invalid("an options record is not valid UTF-8"))?
                .to_owned();
            match kind {
                "ulimit" => ulimits.push(text),
                "env" => env.push(text),
                "tmpfs" => tmpfs.push(text),
                "gen" => {
                    if generation.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                "ipc" | "shm-size" => {
                    let slot = if kind == "ipc" {
                        &mut ipc
                    } else {
                        &mut shm_size
                    };
                    if slot.replace(text).is_some() {
                        return Err(invalid("an options record is duplicated"));
                    }
                }
                _ => return Err(invalid("options record has an unknown kind")),
            }
            // 件数の暴走を確保の前に止める(`new` と同じ上限)。
            if ulimits.len() > OPTIONS_MAX_ULIMITS
                || env.len() > ENV_MAX_ENTRIES
                || tmpfs.len() > TMPFS_MAX_MOUNTS
            {
                return Err(invalid("too many options records"));
            }
        }
        let doc = Self::new(ulimits, env, ipc, shm_size, tmpfs)?;
        match generation {
            Some(g) => doc.with_generation(g),
            None => Ok(doc),
        }
    }
}

/// `<kind> <len>` を分ける。`len` は数字だけ・先頭 0 不可(`0` 自体は可)・桁数上限つき。
fn split_header(line: &[u8]) -> Result<(&str, usize), TraitError> {
    let bad = || invalid("options record header is malformed");
    let text = std::str::from_utf8(line).map_err(|_| bad())?;
    let (kind, len) = text.split_once(' ').ok_or_else(bad)?;
    let canonical = !len.is_empty()
        && len.len() <= LEN_DIGITS_MAX
        && len.bytes().all(|b| b.is_ascii_digit())
        && (len == "0" || !len.starts_with('0'));
    if !canonical {
        return Err(bad());
    }
    Ok((kind, len.parse::<usize>().map_err(|_| bad())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> ContainerOptionsDocument {
        ContainerOptionsDocument::new(
            vec!["nofile=1024:2048".into()],
            vec!["A=1".into(), "MULTI=line1\nline2".into()],
            Some("private".into()),
            Some("128m".into()),
            vec!["/run:rw,noexec".into()],
        )
        .expect("document")
    }

    /// SUP-12・CLI-1: 符号化のバイト列が具体値で一致し、復号で元に戻る(値の改行も保つ)。
    #[test]
    fn sup12_options_document_encode_exact_and_round_trip() {
        let d = doc();
        let bytes = d.encode();
        let expected: &[u8] = b"FCOPT1\n\
ulimit 16\nnofile=1024:2048\n\
env 3\nA=1\n\
env 17\nMULTI=line1\nline2\n\
ipc 7\nprivate\n\
shm-size 4\n128m\n\
tmpfs 14\n/run:rw,noexec\n";
        assert_eq!(bytes, expected);
        assert_eq!(ContainerOptionsDocument::decode(&bytes).expect("decode"), d);
    }

    /// SUP-12: 空の文書は空の指定に戻り、`to_container_options` は既定と同じ。
    #[test]
    fn sup12_options_document_empty_round_trip() {
        let d = ContainerOptionsDocument::default();
        assert!(d.is_empty());
        assert_eq!(d.encode(), OPTIONS_DOC_MAGIC);
        let back = ContainerOptionsDocument::decode(OPTIONS_DOC_MAGIC).expect("decode");
        assert_eq!(
            back.to_container_options().expect("opts"),
            ContainerOptions::new()
        );
    }

    /// SUP-12・CLI-1: 変換後のオプションが指定値を具体値で持つ。
    #[test]
    fn sup12_options_document_converts_to_container_options() {
        let o = doc().to_container_options().expect("opts");
        let nofile: Vec<_> = o
            .rlimits()
            .iter()
            .map(|r| (r.kind().as_oci_name(), r.soft(), r.hard()))
            .collect();
        assert_eq!(nofile, vec![("RLIMIT_NOFILE", 1024, 2048)]);
        assert_eq!(o.env().to_env_strings(), vec!["A=1", "MULTI=line1\nline2"]);
        assert_eq!(o.mounts().shm_size().map(|s| s.bytes()), Some(128 << 20));
    }

    fn decode_err(bytes: &[u8]) -> TraitError {
        ContainerOptionsDocument::decode(bytes).expect_err("must be rejected")
    }

    /// SUP-12・SEC-1: 壊れた文書は固定文言の `InvalidArgument` で拒否する(値を含めない)。
    #[test]
    fn sup12_options_document_rejections() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                b"FCOPT2\n".to_vec(),
                "options document has an unknown header",
            ),
            (b"".to_vec(), "options document has an unknown header"),
            (
                b"FCOPT1\nenv 99999999\nx".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv 03\nA=1\n".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv +3\nA=1\n".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nwat 3\nA=1\n".to_vec(),
                "options record has an unknown kind",
            ),
            (
                b"FCOPT1\nenv 3\nA=1".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 9\nA=1\n".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 3\nA=1X".to_vec(),
                "options record is truncated",
            ),
            (
                b"FCOPT1\nenv 3".to_vec(),
                "options record header is malformed",
            ),
            (
                b"FCOPT1\nenv 2\n\xff\xfe\n".to_vec(),
                "an options record is not valid UTF-8",
            ),
            (
                b"FCOPT1\nipc 4\nhost\nipc 7\nprivate\n".to_vec(),
                "an options record is duplicated",
            ),
            (
                b"FCOPT1\nipc 4\nhost\nshm-size 4\n128m\n".to_vec(),
                "--shm-size cannot be combined with --ipc=host",
            ),
            (
                b"FCOPT1\nulimit 9\nnofile=1\nulimit 9\nnofile=2\n".to_vec(),
                "duplicate rlimit kind",
            ),
        ];
        for (bytes, message) in cases {
            let e = decode_err(&bytes);
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{message}");
            // 重複 ulimit の文言は core 側の固定文言なので、コードのみ確かめる。
            if message != "duplicate rlimit kind" {
                assert_eq!(e.message(), message);
            }
        }
    }

    /// SUP-12・SEC-1: 上限超過(全体・件数・1 レコード)は確保の前に拒否する。
    #[test]
    fn sup12_options_document_limits() {
        let huge = vec![b'x'; OPTIONS_DOC_MAX_BYTES + 1];
        assert_eq!(decode_err(&huge).message(), "options document is too large");
        let mut many = Vec::from(OPTIONS_DOC_MAGIC);
        for _ in 0..=OPTIONS_MAX_ULIMITS {
            many.extend_from_slice(b"ulimit 8\nnofile=1\n");
        }
        assert_eq!(decode_err(&many).message(), "too many options records");
        let mut long = Vec::from(OPTIONS_DOC_MAGIC);
        long.extend_from_slice(b"ulimit 65\n");
        long.extend_from_slice(&[b'a'; 65]);
        long.push(b'\n');
        assert_eq!(decode_err(&long).message(), "an options record is too long");
    }

    /// SEC-1: `Debug` は env の値を出さずキーだけを出す。
    #[test]
    fn sec1_options_document_debug_redacts_env_values() {
        let d = ContainerOptionsDocument::new(
            vec![],
            vec!["TOKEN=TOPSECRETVALUE".into()],
            None,
            None,
            vec![],
        )
        .expect("doc");
        let text = format!("{d:?}");
        assert!(!text.contains("TOPSECRETVALUE"), "{text}");
        assert!(text.contains("TOKEN"), "{text}");
    }

    /// SUP-12・SEC-1(#2713): 作成世代は符号化・復号で保たれ、不正な値と重複は拒否する。
    #[test]
    fn sup12_options_document_generation_round_trip_and_rejects() {
        let d = doc().with_generation("abc-123_X".into()).expect("gen");
        let back = ContainerOptionsDocument::decode(&d.encode()).expect("decode");
        assert_eq!(back.generation(), Some("abc-123_X"));
        assert_eq!(back, d);
        assert!(doc().with_generation(String::new()).is_err());
        assert!(doc().with_generation("a b".into()).is_err());
        assert!(
            doc()
                .with_generation("x".repeat(GENERATION_MAX + 1))
                .is_err()
        );
        let mut bytes = d.encode();
        bytes.extend_from_slice(b"gen 1\nz\n");
        assert!(ContainerOptionsDocument::decode(&bytes).is_err());
    }
}
