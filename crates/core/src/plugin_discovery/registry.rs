//! 発見済み plugin 候補のレジストリ（TASK-109.3・PLUG-4・PLUG-11・MS-3）。
//!
//! # 役割と呼び出し元
//!
//! [`super::discover_candidates`] が返す候補は、system と user に同名があると両方が未解決のまま
//! 並ぶ。本モジュールはそれを plugin 名で一意に保持し、同名重複を検出・記録する。呼び出し元は
//! 将来の CLI 配線（TASK-79）と plugin 起動（TASK-110）、出力の受け手は信頼性検証
//! （TASK-122・PLUG-11）である。
//!
//! # 契約
//!
//! - **登録済みは信頼済みではない**。保持するのは未検証の [`PluginCandidate`] で、所有者・
//!   権限ビット・許可済み sha256 の照合は TASK-122 の責務。本モジュールは spawn・接続・
//!   ファイル読み取りを一切行わない。走査後の差し替え（TOCTOU）は検証側が再 stat・再ハッシュ
//!   して扱う前提で、ここでの登録結果を信頼の根拠にしてはならない
//! - レジストリは生の文字列から構築できない。[`PluginCandidate`] 経由でのみ受け取るため、
//!   discovery で検証済みの名前（ASCII 英小文字・数字・ハイフン、64 バイト以下）しか入らない
//! - 保持件数（登録 + shadowed）は [`MAX_REGISTRY_ENTRIES`] で上限を設け、超過は
//!   `FailedPrecondition` で fail-closed とする
//!
//! # 同名重複の解決規則
//!
//! spec（PLUG-4・PLUG-11）には system / user 間の優先順位の規定が無いため、本実装で安全側に
//! 定めた規則である（spec 側での確定が必要。確定時は本規則を spec に合わせる）。
//!
//! - 優先度キーは `(origin, path)` の昇順で、**小さい方が勝つ**
//! - origin は [`PluginDirKind`] の `Ord` に従い system が user に優先する。user ディレクトリは
//!   非管理者が書き込めるため、user 側が system の同名 plugin を上書き（shadow）できる方向は
//!   安全側でないため
//! - 同一 origin で複数ディレクトリに同名がある場合は path の昇順で先のものが勝つ（決定的）
//! - 結果は登録順に依存しない。後から優先度の高い候補が来れば入れ替え、負けた側を shadowed へ移す
//! - 同一キー（同じ origin・path）の再登録は既存を保持する（先勝ち・冪等）。shadowed には積まない
//! - 負けた候補は捨てず [`ShadowedCandidate`] として記録し、重複を観測できるようにする
//!
//! shadowed の候補も未検証である。検証で勝者が拒否された場合に shadowed へ自動フォールバック
//! することはしない（可否は TASK-122 側の判断で、ここでは実装済みを装わない。REPAIR-3）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{PluginCandidate, PluginDirKind};
use crate::traits::{ErrorCode, TraitError};

/// 登録済み候補と shadowed 候補の合計件数の上限。超過は fail-closed で拒否する（無制限確保の防止）。
///
/// 発見の候補総数の上限 [`MAX_TOTAL_CANDIDATES`](super::MAX_TOTAL_CANDIDATES) 以上でなければならない
/// （`plugin_discovery` の const アサートで固定。PLUG-11・REPAIR-12）。
pub const MAX_REGISTRY_ENTRIES: usize = 4096;

/// [`PluginRegistry::register`] の結果区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStatus {
    /// 同名が無く、新規に登録した。
    Registered,
    /// 既存より優先度が高く、既存を shadowed へ移して置き換えた。
    ReplacedExisting,
    /// 既存の方が優先されるため、本候補を shadowed へ記録した。
    Shadowed,
    /// 同一キー（origin・path）が登録済み。既存を保持した（冪等）。
    AlreadyRegistered,
}

/// 同名重複で負けた候補と、その時点の勝者の所在。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowedCandidate {
    candidate: PluginCandidate,
    winner_origin: PluginDirKind,
    winner_path: PathBuf,
}

impl ShadowedCandidate {
    /// 負けた候補（未検証）を返す。
    pub fn candidate(&self) -> &PluginCandidate {
        &self.candidate
    }

    /// 勝者の発見元の区分を返す。
    pub fn winner_origin(&self) -> PluginDirKind {
        self.winner_origin
    }

    /// 勝者のパスを返す。
    pub fn winner_path(&self) -> &Path {
        &self.winner_path
    }

    fn sort_key(&self) -> (&str, PluginDirKind, &Path) {
        (
            self.candidate.name(),
            self.candidate.origin(),
            self.candidate.path(),
        )
    }
}

/// [`PluginRegistry::register`] の戻り値。将来の項目追加に備え構造体で返す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationOutcome {
    name: String,
    status: RegistrationStatus,
    shadowed: Option<ShadowedCandidate>,
}

impl RegistrationOutcome {
    /// 対象の plugin 名を返す。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 結果区分を返す。
    pub fn status(&self) -> RegistrationStatus {
        self.status
    }

    /// この登録で新たに shadowed になった候補を返す（`Shadowed` / `ReplacedExisting` のみ `Some`）。
    pub fn shadowed(&self) -> Option<&ShadowedCandidate> {
        self.shadowed.as_ref()
    }
}

/// plugin 名で一意化した候補のレジストリ（未検証。モジュール doc の契約を参照）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginRegistry {
    entries: BTreeMap<String, PluginCandidate>,
    shadowed: Vec<ShadowedCandidate>,
}

fn priority_key(c: &PluginCandidate) -> (PluginDirKind, &Path) {
    (c.origin(), c.path())
}

impl PluginRegistry {
    /// 空のレジストリを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 候補列から順に [`Self::register`] して構築する。上限超過は最初のエラーを返す。
    pub fn from_candidates(
        candidates: impl IntoIterator<Item = PluginCandidate>,
    ) -> Result<Self, TraitError> {
        let mut registry = Self::new();
        for candidate in candidates {
            registry.register(candidate)?;
        }
        Ok(registry)
    }

    /// 候補を 1 件登録する。
    ///
    /// 同名があれば、`(origin, path)` の昇順で小さい方（system が user に優先。同一 origin は
    /// path 昇順）が勝ち、負けた側は shadowed に記録される。結果は登録順に依存しない。同一キーの
    /// 再登録は `AlreadyRegistered` で既存を保持する。登録しても信頼済みにはならない
    /// （検証は TASK-122）。保持件数が [`MAX_REGISTRY_ENTRIES`] に達していて件数が増える場合は
    /// `FailedPrecondition` を返し、レジストリは変更しない。
    pub fn register(
        &mut self,
        candidate: PluginCandidate,
    ) -> Result<RegistrationOutcome, TraitError> {
        let name = candidate.name().to_owned();

        let Some(existing) = self.entries.get(&name) else {
            self.ensure_capacity()?;
            self.entries.insert(name.clone(), candidate);
            return Ok(RegistrationOutcome {
                name,
                status: RegistrationStatus::Registered,
                shadowed: None,
            });
        };

        let existing_key = priority_key(existing);
        let new_key = priority_key(&candidate);

        if new_key == existing_key || self.is_shadowed(&candidate) {
            return Ok(RegistrationOutcome {
                name,
                status: RegistrationStatus::AlreadyRegistered,
                shadowed: None,
            });
        }

        self.ensure_capacity()?;

        if new_key < existing_key {
            // 新候補が勝つ。既存を負け側へ移し、同名の既存 shadowed の勝者表記も更新する。
            let winner_origin = candidate.origin();
            let winner_path = candidate.path().to_path_buf();
            let Some(old) = self.entries.insert(name.clone(), candidate) else {
                // 直前に get で存在を確認済みのため到達しない。
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "plugin registry entry vanished during replacement",
                ));
            };
            for s in self
                .shadowed
                .iter_mut()
                .filter(|s| s.candidate.name() == name)
            {
                s.winner_origin = winner_origin;
                s.winner_path = winner_path.clone();
            }
            let record = ShadowedCandidate {
                candidate: old,
                winner_origin,
                winner_path,
            };
            self.insert_shadowed(record.clone());
            Ok(RegistrationOutcome {
                name,
                status: RegistrationStatus::ReplacedExisting,
                shadowed: Some(record),
            })
        } else {
            let record = ShadowedCandidate {
                winner_origin: existing.origin(),
                winner_path: existing.path().to_path_buf(),
                candidate,
            };
            self.insert_shadowed(record.clone());
            Ok(RegistrationOutcome {
                name,
                status: RegistrationStatus::Shadowed,
                shadowed: Some(record),
            })
        }
    }

    /// plugin 名で勝者の候補を引く。
    pub fn get(&self, name: &str) -> Option<&PluginCandidate> {
        self.entries.get(name)
    }

    /// 勝者の候補を plugin 名の昇順で列挙する。
    pub fn iter(&self) -> impl Iterator<Item = &PluginCandidate> {
        self.entries.values()
    }

    /// 登録済み（勝者）の件数を返す。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 登録済みが 0 件なら true。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 重複で負けた候補を `(name, origin, path)` の昇順で返す。
    pub fn shadowed(&self) -> &[ShadowedCandidate] {
        &self.shadowed
    }

    fn ensure_capacity(&self) -> Result<(), TraitError> {
        if self.entries.len().saturating_add(self.shadowed.len()) >= MAX_REGISTRY_ENTRIES {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "too many plugin registry entries",
            ));
        }
        Ok(())
    }

    fn is_shadowed(&self, candidate: &PluginCandidate) -> bool {
        self.shadowed.iter().any(|s| {
            s.candidate.name() == candidate.name()
                && priority_key(&s.candidate) == priority_key(candidate)
        })
    }

    fn insert_shadowed(&mut self, record: ShadowedCandidate) {
        let pos = self
            .shadowed
            .partition_point(|s| s.sort_key() < record.sort_key());
        self.shadowed.insert(pos, record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_discovery::{MAX_TOTAL_CANDIDATES, PluginFileKind};

    fn cand(name: &str, origin: PluginDirKind, dir: &str) -> PluginCandidate {
        PluginCandidate {
            name: name.to_owned(),
            path: PathBuf::from(dir).join(format!("fandhe-container-plugin-{name}")),
            origin,
            file_kind: PluginFileKind::File,
        }
    }

    fn names(r: &PluginRegistry) -> Vec<&str> {
        r.iter().map(|c| c.name()).collect()
    }

    #[test]
    fn plug4_registers_unique_names_in_name_order() {
        let r = PluginRegistry::from_candidates([
            cand("net", PluginDirKind::System, "/s"),
            cand("cri", PluginDirKind::User, "/u"),
            cand("mcp", PluginDirKind::System, "/s"),
        ])
        .expect("register");
        assert_eq!(names(&r), vec!["cri", "mcp", "net"]);
        assert_eq!(r.len(), 3);
        assert!(r.shadowed().is_empty());
    }

    #[test]
    fn plug11_system_wins_over_user_for_same_name() {
        let mut r = PluginRegistry::new();
        let first = r
            .register(cand("cri", PluginDirKind::User, "/u"))
            .expect("user");
        assert_eq!(first.status(), RegistrationStatus::Registered);
        let second = r
            .register(cand("cri", PluginDirKind::System, "/s"))
            .expect("system");
        assert_eq!(second.status(), RegistrationStatus::ReplacedExisting);
        assert_eq!(second.name(), "cri");
        assert_eq!(
            second.shadowed().map(|s| s.candidate().origin()),
            Some(PluginDirKind::User)
        );
        let winner = r.get("cri").expect("winner");
        assert_eq!(winner.origin(), PluginDirKind::System);
        assert_eq!(r.shadowed().len(), 1);
        let s = &r.shadowed()[0];
        assert_eq!(s.candidate().origin(), PluginDirKind::User);
        assert_eq!(s.winner_origin(), PluginDirKind::System);
        assert_eq!(s.winner_path(), winner.path());
    }

    #[test]
    fn plug11_later_lower_priority_candidate_is_shadowed() {
        let mut r = PluginRegistry::new();
        r.register(cand("cri", PluginDirKind::System, "/s"))
            .expect("s");
        let out = r
            .register(cand("cri", PluginDirKind::User, "/u"))
            .expect("u");
        assert_eq!(out.status(), RegistrationStatus::Shadowed);
        assert_eq!(r.shadowed().len(), 1);
    }

    #[test]
    fn plug11_duplicate_resolution_is_order_independent() {
        let a = cand("cri", PluginDirKind::User, "/u1");
        let b = cand("cri", PluginDirKind::System, "/s");
        let c = cand("cri", PluginDirKind::User, "/u0");
        let r1 = PluginRegistry::from_candidates([a.clone(), b.clone(), c.clone()]).expect("r1");
        let r2 = PluginRegistry::from_candidates([c, a, b]).expect("r2");
        assert_eq!(r1, r2);
        assert_eq!(r1.shadowed().len(), 2);
        for s in r1.shadowed() {
            assert_eq!(s.winner_origin(), PluginDirKind::System);
        }
    }

    #[test]
    fn plug11_same_origin_duplicate_resolves_by_path() {
        let r = PluginRegistry::from_candidates([
            cand("cri", PluginDirKind::User, "/u2"),
            cand("cri", PluginDirKind::User, "/u1"),
        ])
        .expect("register");
        let winner = r.get("cri").expect("winner");
        assert_eq!(
            winner.path(),
            Path::new("/u1").join("fandhe-container-plugin-cri")
        );
        assert_eq!(
            r.shadowed()[0].candidate().path(),
            Path::new("/u2").join("fandhe-container-plugin-cri")
        );
    }

    #[test]
    fn plug4_reregistering_same_candidate_is_idempotent() {
        let mut r = PluginRegistry::new();
        r.register(cand("cri", PluginDirKind::System, "/s"))
            .expect("1");
        let out = r
            .register(cand("cri", PluginDirKind::System, "/s"))
            .expect("2");
        assert_eq!(out.status(), RegistrationStatus::AlreadyRegistered);
        assert!(out.shadowed().is_none());
        r.register(cand("cri", PluginDirKind::User, "/u"))
            .expect("3");
        let again = r
            .register(cand("cri", PluginDirKind::User, "/u"))
            .expect("4");
        assert_eq!(again.status(), RegistrationStatus::AlreadyRegistered);
        assert_eq!(r.len(), 1);
        assert_eq!(r.shadowed().len(), 1);
    }

    #[test]
    fn plug4_lookup_hit_and_miss() {
        let r = PluginRegistry::from_candidates([cand("cri", PluginDirKind::System, "/s")])
            .expect("register");
        assert_eq!(r.get("cri").map(|c| c.name()), Some("cri"));
        assert!(r.get("net").is_none());
    }

    #[test]
    fn plug4_empty_registry() {
        let r = PluginRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.iter().count(), 0);
        assert!(r.shadowed().is_empty());
    }

    /// 発見が返し得る最大件数（`MAX_TOTAL_CANDIDATES`）を `from_candidates` が受理できる（PLUG-11・REPAIR-12）。
    #[test]
    fn plug11_registry_accepts_max_total_candidates() {
        let cands: Vec<PluginCandidate> = (0..MAX_TOTAL_CANDIDATES)
            .map(|i| cand(&format!("p{i}"), PluginDirKind::System, "/s"))
            .collect();
        let r = PluginRegistry::from_candidates(cands).expect("max total candidates fit");
        assert_eq!(r.len(), MAX_TOTAL_CANDIDATES);
    }

    #[test]
    fn plug11_registry_entry_limit_is_fail_closed() {
        let mut r = PluginRegistry::new();
        for i in 0..MAX_REGISTRY_ENTRIES {
            r.register(cand(&format!("p{i}"), PluginDirKind::System, "/s"))
                .expect("within limit");
        }
        let err = r
            .register(cand("overflow", PluginDirKind::System, "/s"))
            .expect_err("over limit");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.len(), MAX_REGISTRY_ENTRIES);
        // 件数が増えない再登録は上限到達後も成功する。
        let again = r
            .register(cand("p0", PluginDirKind::System, "/s"))
            .expect("idempotent");
        assert_eq!(again.status(), RegistrationStatus::AlreadyRegistered);
    }
}
