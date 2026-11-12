//! (iv)〜(vi) の 1 回分の本体（#869・TASK-184.4.2・OCI-7・CLI-1・REPAIR-5・REPAIR-12。MS-6）。
//!
//! # 役割と呼び出し元
//! 親の `concurrent.rs` のワーカープール（[`super::pool`]）が、種類ごとに 1 回分を呼ぶ。ここは「1 回の操作の中で何をして何を照合するか」
//! だけを持ち、並行フェーズの組み立て・最終の期待集合・成功行は親が持つ。親の非公開型（`Shared`・`World`・`Image`）は
//! 子モジュールとして直接使う。
//! - [`creating_ref_once`]: (iv) 作成途中のコンテナの参照が、prune にイメージとレイヤーを消させない。
//! - [`shared_pull_once`]: (v) 同じ blob を共有する 3 本の pull。先頭が公開してリースを解放しても残りは成功する。
//! - [`tag_race_once`]: (vi) `image tag` と prune の競合。「tag 成功で中身が全部ある」か「NOT_FOUND で何も無い」の一方だけ。
//!
//! # 方針
//! - Timeout・失敗は再試行しない。待ちはすべて期限つき（[`OVERLAP_WAIT`]・CLI の期限。REPAIR-5）。
//! - 失敗の経路でも、未公開の `PullSession` は `abort` し、未確定の参照は外してから返す（資源を残さない）。
//! - (iv) は CLI の実 create の内部の窓（参照の登録から確定まで）を外から止められないため、oci の公開 API で同じ手順を
//!   なぞる模擬である。実 CLI の create は (ii) が並走する。

use super::*;

/// 条件が成り立つまで待つ（期限つき）。`abort` または `fail` が立ったら止める。
fn wait_until(
    sh: &Shared,
    fail: &AtomicBool,
    what: &str,
    mut cond: impl FnMut() -> bool,
) -> Result<(), String> {
    let deadline = Instant::now() + OVERLAP_WAIT;
    loop {
        if cond() {
            return Ok(());
        }
        if sh.abort.load(Ordering::SeqCst) || fail.load(Ordering::SeqCst) {
            return Err(format!("{what}: aborted"));
        }
        if Instant::now() >= deadline {
            return Err(format!("{what}: not reached within {OVERLAP_WAIT:?}"));
        }
        thread::sleep(POLL);
    }
}

/// 公開済みの blob が `blobs/sha256` に揃い、内容の sha256 が digest と一致することを見る。
fn expect_blobs_intact(images: &Path, im: &Image, what: &str) -> Result<(), String> {
    for b in im.blobs() {
        let bytes = fs::read(blob_path(images, &b.hex))
            .map_err(|e| format!("{what}: blob {} is missing: {e}", b.hex))?;
        if Digest::sha256_of(&bytes) != b.digest {
            return Err(format!("{what}: blob {} has a wrong digest", b.hex));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// (iv) 作成途中の参照
// ---------------------------------------------------------------------------------------------

/// (iv) 1 回分。登録済み（未確定）・状態作成前の窓で、参照だけがイメージを守っている間に prune が完了しても何も欠けない。
///
/// 手順は core の create（ゲート共有 → 参照登録〔未確定〕→ 状態作成 → 確定）をなぞる。窓の中でタグを外し、
/// W を守るのは未確定参照だけにする（タグも他のコンテナもリースも無い）。偶数の回は確定して delete 相当の解除、
/// 奇数の回は create の巻き戻し相当の解除で終える。
pub(super) fn creating_ref_once(sh: &Shared, w: &World, k: usize) -> Result<(), String> {
    let img = &w.creating[k];
    let what = format!("creating ref {k}");
    let id = ContainerRefId::new(&sh.create_ids[k]).map_err(|e| format!("{what}: id: {e:?}"))?;
    let store = ImageStore::open(&sh.images).map_err(|e| format!("{what}: open store: {e:?}"))?;
    // 進行中の create の宣言（ゲートの共有）。窓の間ずっと保持する。
    let pass = store
        .enter_container_create()
        .map_err(|e| format!("{what}: enter create gate: {e:?}"))?;
    let reg = store
        .register_container_ref(&id, &img.manifest)
        .map_err(|e| format!("{what}: register: {e:?}"))?;
    if reg != ContainerRefRegistration::Registered {
        return Err(format!("{what}: unexpected registration {reg:?}"));
    }
    let result = creating_window(sh, w, &store, &id, k, &what);
    // 失敗の経路でも未確定の参照を残さない（成功の経路では既に外れている。NotRegistered は無害）。
    if result.is_err() {
        let _ = store.release_container_ref(&id);
    }
    drop(pass);
    result
}

fn creating_window(
    sh: &Shared,
    w: &World,
    store: &ImageStore,
    id: &ContainerRefId,
    k: usize,
    what: &str,
) -> Result<(), String> {
    let img = &w.creating[k];
    sh.protect_image(img);
    // 窓を作る: タグを外し、W を守るのを未確定参照だけにする。
    let tag = tag_key(&World::creating_tag(k))?;
    let mut stopped = StoppedContainers::new();
    stopped.insert(id.clone());
    let out = {
        let mut g = store.lock().map_err(|e| format!("{what}: lock: {e:?}"))?;
        g.execute_image_rm(
            store.root(),
            &ImageRmTarget::Tag(tag),
            &ImageRmOptions::force(),
            &stopped,
        )
        .map_err(|e| format!("{what}: untag: {e:?}"))?
    };
    if out.kind != ImageRmKind::UntagOnly
        || out.manifest != img.manifest
        || out.untagged.len() != 1
        || !out.deleted_blobs.is_empty()
    {
        return Err(format!("{what}: untag outcome: {out:?}"));
    }
    // この窓の中で、窓の後に始まった prune が 1 回以上完了するのを待つ。
    let seen = sh.prunes_completed.load(Ordering::SeqCst);
    sh.wait_prune_after(seen, what)?;
    // 窓の終わりの照合: 参照は自分の未確定参照 1 件だけで、イメージ全体が無傷。
    let (containers, tags) = refs_of(&sh.images, &img.manifest)?;
    if containers != [id.as_str().to_string()] || !tags.is_empty() {
        return Err(format!(
            "{what}: references during the window: {containers:?} {tags:?}"
        ));
    }
    expect_blobs_intact(&sh.images, img, what)?;
    let generation = {
        let g = store.lock().map_err(|e| format!("{what}: lock: {e:?}"))?;
        if !g.manifests().any(|(d, _)| *d == img.manifest) {
            return Err(format!("{what}: manifest left the inventory in the window"));
        }
        g.unbound_containers()
            .find(|(i, _, _)| *i == id)
            .map(|(_, generation, _)| generation)
            .ok_or_else(|| format!("{what}: the reference is not listed as unbound"))?
    };
    // 片づけ。保護を外してから参照を外す（逆だと、正しい削除を監視が違反と誤検出する）。
    sh.unprotect_image(img)?;
    let released = if k.is_multiple_of(2) {
        // 状態作成の成功に相当 → 確定 → delete に相当する世代つきの解除。
        let bound = store
            .bind_container_ref(id)
            .map_err(|e| format!("{what}: bind: {e:?}"))?;
        if bound != generation {
            return Err(format!(
                "{what}: bound generation {bound:?} differs from registered {generation:?}"
            ));
        }
        store.release_container_ref_if(id, bound)
    } else {
        // create の巻き戻しに相当する解除。
        store.release_container_ref(id)
    }
    .map_err(|e| format!("{what}: release: {e:?}"))?;
    if released != ContainerRefRelease::Released(img.manifest.clone()) {
        return Err(format!("{what}: release outcome {released:?}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// (v) 同じ blob を共有する pull 群
// ---------------------------------------------------------------------------------------------

/// 3 本の pull が同期するための共有値。
struct Rendezvous {
    leased: AtomicUsize,
    leader_published: AtomicBool,
    /// 先頭の公開の直後の prune 完了数。
    seen_after_leader: AtomicUsize,
    failed: AtomicBool,
}

/// (v) 1 回分。グループ `g` の 3 本（先頭 1・後続 2）が X_g のリースを取り、種イメージ Y_g を消し、先頭が公開して
/// リースを解放した後も、後続の 2 本は成功し X_g は欠けない。
pub(super) fn shared_pull_once(sh: &Shared, w: &World, g: usize) -> Result<(), String> {
    let rv = Rendezvous {
        leased: AtomicUsize::new(0),
        leader_published: AtomicBool::new(false),
        seen_after_leader: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
    };
    let results: Vec<Result<(), String>> = thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|role| {
                let rv = &rv;
                scope.spawn(move || {
                    let r = shared_member(sh, w, g, role, rv);
                    if r.is_err() {
                        rv.failed.store(true, Ordering::SeqCst);
                    }
                    r
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("shared pull member panicked".to_string()))
            })
            .collect()
    });
    // 最初の失敗を返す（他は「aborted」の連鎖のことが多い）。
    let mut errs: Vec<String> = results.into_iter().filter_map(Result::err).collect();
    errs.sort_by_key(|e| e.contains("aborted"));
    match errs.into_iter().next() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 1 本分。失敗しても、まだ公開していないセッションは `abort` する（`PullSession` に Drop は無い）。
fn shared_member(
    sh: &Shared,
    w: &World,
    g: usize,
    role: usize,
    rv: &Rendezvous,
) -> Result<(), String> {
    let what = format!("shared pull {g}/{role}");
    let store = ImageStore::open(&sh.images).map_err(|e| format!("{what}: open store: {e:?}"))?;
    let session = store
        .begin_pull_generated()
        .map_err(|e| format!("{what}: begin pull: {e:?}"))?;
    let mut slot = Some(session);
    let result = shared_member_body(sh, w, g, role, rv, &store, &mut slot, &what);
    if let Some(s) = slot.take() {
        let _ = s.abort();
    }
    result
}

// 抑止の理由: 3 本の役者が共有する値（共有状態・世界・グループ・役割・同期・ストア・セッションの受け皿・名前）を
// 束ねる構造体を作ると、呼び出しが 1 か所だけの試験専用の補助に型が増えるだけで読みやすくならないため。
#[allow(clippy::too_many_arguments)]
fn shared_member_body<'a>(
    sh: &Shared,
    w: &World,
    g: usize,
    role: usize,
    rv: &Rendezvous,
    store: &'a ImageStore,
    slot: &mut Option<PullSession<'a>>,
    what: &str,
) -> Result<(), String> {
    let x = &w.x[g];
    let img = &w.sp[g][role];
    {
        let s = slot.as_mut().ok_or("session already consumed")?;
        match s
            .lease_existing_blob(&x.digest)
            .map_err(|e| format!("{what}: lease shared blob: {e:?}"))?
        {
            BlobReuse::Leased(_) => {}
            other => return Err(format!("{what}: shared blob was not leasable: {other:?}")),
        }
    }
    rv.leased.fetch_add(1, Ordering::SeqCst);
    wait_until(sh, &rv.failed, what, || {
        rv.leased.load(Ordering::SeqCst) >= 3
    })?;
    let tag = if role == 0 {
        // 3 本ともリースを取った。X_g を保護集合へ入れ、X_g だけを持つ種イメージ Y_g を消す。
        sh.protect_blob(x);
        remove_seed_image(sh, w, g, store, what)?;
        None
    } else {
        // 先頭が公開してリースを解放し、その後に始まった prune が 1 回以上完了するまで待つ。
        wait_until(sh, &rv.failed, what, || {
            rv.leader_published.load(Ordering::SeqCst)
        })?;
        sh.wait_prune_after(rv.seen_after_leader.load(Ordering::SeqCst), what)?;
        Some(World::follower_tag(g, role))
    };
    {
        let s = slot.as_mut().ok_or("session already consumed")?;
        stage(s, &img.config)?;
        stage(s, &img.layers[1])?;
    }
    let mut request = PullPublishRequest::new(img.manifest.clone(), img.composition()?);
    if let Some(t) = &tag {
        request = request.with_tag(tag_key(t)?);
    }
    let out = slot
        .take()
        .ok_or("session already consumed")?
        .publish(request)
        .map_err(|e| format!("{what}: publish: {e:?}"))?;
    if !out.reused_blobs.contains(&x.digest) {
        return Err(format!(
            "{what}: the shared blob was not reported as reused: {out:?}"
        ));
    }
    if role == 0 {
        // 先頭のリースはここで外れた。残りの 2 本のリースだけが X_g を守る。
        rv.seen_after_leader
            .store(sh.prunes_completed.load(Ordering::SeqCst), Ordering::SeqCst);
        rv.leader_published.store(true, Ordering::SeqCst);
        return Ok(());
    }
    // 後続: 公開した全 blob（X_g を含む）が欠けず、内容が digest と一致する。
    expect_blobs_intact(&sh.images, img, what)?;
    sh.protect_image(img);
    Ok(())
}

/// Y_g（タグ付き・X_g だけを持つ）を `image rm` する。X_g はリースが守るので消えず、Y の config だけが消える。
fn remove_seed_image(
    sh: &Shared,
    w: &World,
    g: usize,
    store: &ImageStore,
    what: &str,
) -> Result<(), String> {
    let y = &w.y[g];
    let mut guard = store.lock().map_err(|e| format!("{what}: lock: {e:?}"))?;
    let out = guard
        .execute_image_rm(
            store.root(),
            &ImageRmTarget::Tag(tag_key(&World::y_tag(g))?),
            &ImageRmOptions::default(),
            &StoppedContainers::new(),
        )
        .map_err(|e| format!("{what}: rm seed image: {e:?}"))?;
    drop(guard);
    if out.kind != ImageRmKind::Deleted
        || out.manifest != y.manifest
        || out.deleted_blobs != [y.config.digest.clone()]
    {
        return Err(format!(
            "{what}: seed image removal outcome (the leased shared blob must stay): {out:?}"
        ));
    }
    expect_blobs_intact(
        &sh.images,
        &Image {
            manifest: y.manifest.clone(),
            config: w.x[g].clone(),
            layers: Vec::new(),
        },
        what,
    )
}

// ---------------------------------------------------------------------------------------------
// (vi) tag と prune の競合
// ---------------------------------------------------------------------------------------------

/// `image tag <T の digest> <タグ>` を実行して分類する。成功なら `true`、NOT_FOUND なら `false`。それ以外は失敗。
fn run_tag(
    sh: &Shared,
    w: &World,
    env: Option<&Env>,
    k: usize,
    what: &str,
) -> Result<bool, String> {
    let t = &w.t[k];
    let tag = World::t_tag(k);
    if let Some(env) = env {
        let source = t.manifest.to_string();
        let out = run_cli(
            &env.cli,
            &[
                "--root",
                &env.root_s,
                "image",
                "tag",
                "--image-root",
                &env.images_s,
                &source,
                &tag,
            ],
            CLI_TIMEOUT,
        )?;
        return match out.code {
            Some(0) => {
                let want = format!("tagged\t{}\t{}\n", tag_key(&tag)?, t.manifest);
                expect(
                    out.stdout == want && out.stderr.is_empty(),
                    &format!(
                        "{what}: image tag success output: stdout={:?} stderr={:?}",
                        out.stdout, out.stderr
                    ),
                )?;
                Ok(true)
            }
            Some(3) => {
                let code = stderr_field(&out.stderr, "code")?;
                expect(
                    code == "NOT_FOUND" && out.stdout.is_empty(),
                    &format!(
                        "{what}: image tag exit 3: code={code} stdout={:?}",
                        out.stdout
                    ),
                )?;
                Ok(false)
            }
            other => Err(format!(
                "{what}: image tag: unexpected exit {other:?} stdout={:?} stderr={:?}",
                out.stdout, out.stderr
            )),
        };
    }
    let store = ImageStore::open(&sh.images).map_err(|e| format!("{what}: open store: {e:?}"))?;
    match store.tag_image(
        &ImageTagSource::Manifest(t.manifest.clone()),
        tag_key(&tag)?,
    ) {
        Ok(_) => Ok(true),
        Err(e) if e.code() == OciErrorCode::NotFound => Ok(false),
        Err(e) => Err(format!("{what}: tag_image: {e:?}")),
    }
}

/// (vi) 1 回分。T_k を無参照で公開し、`image tag` を prune と競わせる。戻り値は tag が勝ったか。
///
/// 偶数の回は、公開の後に始まった prune の完了を待ってから tag する（prune が必ず先に回収するので NOT_FOUND）。
/// 奇数の回は待たずに少しだけずらして競わせる（勝敗は観測値）。
pub(super) fn tag_race_once(
    sh: &Shared,
    w: &World,
    env: Option<&Env>,
    k: usize,
) -> Result<bool, String> {
    let t = &w.t[k];
    let what = format!("tag race {k}");
    seed(&sh.images, t, None).map_err(|e| format!("{what}: {e}"))?;
    if k.is_multiple_of(2) {
        let seen = sh.prunes_completed.load(Ordering::SeqCst);
        sh.wait_prune_after(seen, &what)?;
    } else {
        thread::sleep(Duration::from_millis(((k / 2) % 4) as u64 * 2));
    }
    let won = run_tag(sh, w, env, k, &what)?;
    let key = tag_key(&World::t_tag(k))?;
    let store = ImageStore::open(&sh.images).map_err(|e| format!("{what}: open store: {e:?}"))?;
    let guard = store.lock().map_err(|e| format!("{what}: lock: {e:?}"))?;
    let present = guard.manifests().any(|(d, _)| *d == t.manifest);
    let tagged = guard.tags().any(|(tk, d)| *tk == key && *d == t.manifest);
    drop(guard);
    drop(store);
    if won {
        // tag が成功したなら、イメージ全体（manifest と全 blob）が残っている。
        expect(
            present && tagged,
            &format!("{what}: tag succeeded but present={present} tagged={tagged}"),
        )?;
        expect_blobs_intact(&sh.images, t, &what)?;
        sh.protect_image(t);
    } else {
        // NOT_FOUND なら、タグも manifest も blob も無い（タグだけあって中身が無い状態を残さない）。
        expect(
            !present && !tagged,
            &format!("{what}: tag failed but present={present} tagged={tagged}"),
        )?;
        if let Some(b) = t.blobs().find(|b| blob_path(&sh.images, &b.hex).exists()) {
            return Err(format!(
                "{what}: tag failed but blob {} is still on disk",
                b.hex
            ));
        }
    }
    Ok(won)
}
