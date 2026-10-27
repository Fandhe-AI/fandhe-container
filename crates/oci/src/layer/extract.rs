//! レイヤー tar のルート配下への安全な展開（TASK-52.3・OCI-1・MS-4・#409）。
//!
//! `layer` の gzip 展開（TASK-52.2。`GzipLayerReader`）が返す tar バイトストリームを、rootfs 相当の
//! ステージング用ディレクトリへ書き出す。レイヤー tar は非信頼入力のため、このモジュールは次を担う。
//!
//! - パス検証と正規化（`..`・絶対パス・NUL・過大な長さ / 深さの拒否）。
//! - 親ディレクトリの解決はルートに閉じ込める（symlink を辿ってもホストの絶対パスへ抜けない。chroot 意味論）。
//! - symlink エントリはリンク先がルートより上へ出る場合に拒否し、hardlink はルート内の通常ファイルに限る。
//! - デバイス・FIFO・sparse は拒否する（既定拒否の最小権限）。
//! - エントリ数と累積展開バイト数に必須の上限を課し、超過したら書き込み前に中断する（DoS 対策）。
//! - 展開先 FS が別表記（大文字小文字・Unicode 正規化）を既存の実体へ解決する名前は、
//!   削除・権限変更・リンク作成の前に `AlreadyExists` で拒否する（IO-5。下記「別表記の衝突」）。
//! - whiteout・不透明ディレクトリを下位レイヤーの実体へ適用し、マーカー自体は展開しない（OCI-2。下記
//!   「レイヤーごとの 3 パス」）。
//! - AUFS のメタデータ（`.wh..wh.` で始まり `.wh..wh..opq` 以外の名前。`.wh..wh.plnk` 等）は、種別を予約名の外と
//!   同じ規則で検査してから、深さを問わずエントリごと読み飛ばして rootfs へ何も書かない
//!   （#2183・#2312・OCI-2。下記「AUFS メタデータの予約名」）。
//!
//! tar クレートは解析（エントリ列挙）だけに使い、`unpack` / `unpack_in` は使わない（#408 の承認条件）。
//!
//! # 呼び出し契約
//!
//! - イメージの展開（`extract_image_layers`）は、`VerifiedLayerBlob`（`open_blob_nofollow` で開き、同じハンドルで
//!   信頼条件と digest を確かめた値。#2309）だけを受ける。パスを開き直さないため、検証と展開の間にパスを別の
//!   ファイルへ差し替えられても展開物は変わらない。パスを受けて走査のたびに開き直す旧入口（`extract_layer_blob(s)*`）は、
//!   検証と展開の間の差し替えを防げないため #2535 で廃止した（#2309）。入口は検証済みハンドル版
//!   （`extract_image_layers*`）と、`Read + Seek` を受けるストリーム版（`extract_layers*`・`extract_tar*`）の 2 系統である。
//! - `root` は呼び出し側が排他的に所有する既存の空ディレクトリ（ステージング）で、`root` 自体が
//!   symlink であってはならない。空でなければ `FailedPrecondition` で拒否する（別表記の衝突の判定が
//!   「`root` 配下の実在項目はすべてこの展開が作った」ことに依るため）。別プロセスが同時に `root` を
//!   書き換える競合（TOCTOU）は、Linux の x86_64 / aarch64 では変更操作を `root` のディレクトリ fd 起点に閉じて
//!   防ぐ（下記「ディレクトリ fd 起点の解決」）。それ以外のホストでは防げない。
//! - 失敗時は部分的な展開物が残るため、呼び出し側が `root` ごと破棄すること。
//! - 複数レイヤーは `extract_layers` / `extract_image_layers` で下位から上位の順に同一 `root` へ重ねる
//!   （TASK-52.4・#410）。空であることの検査は最初のレイヤーの前だけで、別表記の索引・遅延ディレクトリ mode・
//!   4 種の上限（`max_input_bytes` を含む）は全レイヤーで共有・累積する。
//! - 各レイヤーの tar は 2 回走査する（下記「レイヤーごとの 3 パス」）。ハンドル版（`VerifiedLayerBlob`）は各走査の前に
//!   ハンドルの先頭へ戻し、ストリーム版（`extract_tar`・`extract_layers`）は
//!   入力に `Seek` を求めて最初の位置へ戻す。展開後 tar の diff_id（sha256）はパス 1 の読み取りで計算し、
//!   `extract_image_layers` では image config の `rootfs.diff_ids` と突合する（#2017・OCI-1）。パス 3 でも同じ構成で
//!   同じハッシュを計算し、末尾でパス 1 の値と照合して、違えば `DataLoss` にする（#2309。同じ inode への上書きなど、
//!   開き直しの間の内容の変化を検出する。全入口に効く）。不一致は末尾でしか分からないため、そのレイヤーの展開物が
//!   `root` に残る。`Err` を受けたら `root` ごと破棄すること（変わっても、パス 3 はマーカー名を書き出さない）。
//! - tar の終端後に入力を EOF まで読み捨てる（gzip トレーラの CRC32・ISIZE 検証のため）。読み捨てを含む
//!   入力全体は `ExtractLimits::max_input_bytes` で上限を課す（超過は `ResourceExhausted`）。
//!
//! # レイヤーごとの 3 パス（OCI-1・OCI-2・TASK-53.3）
//!
//! image-spec は whiteout（`.wh.<name>`）と不透明ディレクトリ（`.wh..wh..opq`）を下位レイヤーのリソースにだけ
//! 適用すると定め、同一レイヤー内の並び順は問わない。各レイヤーを次の 3 パスで処理し、並び順に依らない
//! 結果を構成上成り立たせる（OCI-2）。
//!
//! 1. 収集・検証（副作用なし）: tar を走査し、全エントリのパス検証（`normalize_entry_path`）・親コンポーネントの
//!    whiteout 名の拒否・マーカーの形（中身の無い通常ファイル）の検査・未対応の種別の拒否を済ませ、マーカーを
//!    `Marker` として集める。件数は `ExtractLimits::max_entries` で頭打ちにする。ここで拒否したレイヤーは
//!    rootfs を一切変更しない。入力の読み取りにはパス 3 と同じ上限を別に課す。
//! 2. マーカーの適用: 集めたマーカーの親を、このレイヤーを展開する前のツリー（下位レイヤーまでの rootfs）で
//!    すべて解決してから（`resolve_dir` の chroot 意味論でルート外へ出ない）、whiteout は対象を
//!    `whiteout::remove_tree_nofollow`、不透明は中身を `whiteout::remove_dir_contents_nofollow` で消す。
//!    解決を削除より先に済ませるので、symlink を経由する親や別表記の検査（IO-5）の結果もマーカーの並びに依らない。
//!    親や対象が無い・親が非ディレクトリなら何もしない（下位に消す実体が無い）。マーカーは同じレイヤーが
//!    作る実体（symlink を含む）を経由して解決しない。
//! 3. 展開: tar をもう一度走査して通常エントリを展開し、マーカーは書かずに読み飛ばす。既存のノードとの関係は
//!    image-spec の「Changeset over existing files」に従う。既存もエントリもディレクトリなら属性だけを置き換え、
//!    それ以外は既存パスを再帰削除してからエントリを作る（暗黙の親ディレクトリの位置にある下位の非ディレクトリも
//!    同様に置き換える）。ただし置き換えるのは下位レイヤー由来のノードに限り、このレイヤーが作った・経路として
//!    通ったノード（`Extractor::layer_nodes`）との型の衝突は従来どおり `FailedPrecondition` で拒否する
//!    （ディレクトリの位置への非ディレクトリ、非ディレクトリを親に持つパス）。
//!
//! 同じレイヤーの hardlink の参照先が同じレイヤーで whiteout されている場合、参照先はパス 2 で消えるため
//! `NotFound` で拒否する（並び順に依らない）。
//!
//! # AUFS メタデータの予約名（#2183・OCI-2）
//!
//! image-spec v1.1.1 `layer.md` が定めるのは `.wh.<name>` と `.wh..wh..opq` だけで、`.wh..wh.` という予約接頭辞は無い。
//! 一方 AUFS ストレージドライバ時代の Docker のイメージには `.wh..wh.plnk`・`.wh..wh.aufs`・`.wh..wh.orph` 等が残る。
//! moby/go-archive（`UnpackLayer`。commit a9a82af9）はこれらを読み飛ばし、containerd も失敗させないため、
//! 拒否すると古いイメージが展開できない。image-spec 上 `.wh.` で始まる名前は FS に実在できず whiteout 自体も隠す
//! 決まりなので、読み飛ばしても仕様に反しない。よって本実装も読み飛ばす（`Plan::Skip`）。
//!
//! - 判定はパスを先頭から順に分類し、最初に通常でないと判定されたコンポーネントが決める。予約名が先なら
//!   配下（中身のある通常ファイル・ディレクトリ・リンクを含む）をエントリごと読み飛ばす。ただし読み飛ばす前に
//!   種別を予約名の外と同じ規則で検査し、未対応の種別（FIFO・デバイス等）は予約名の下でも `PermissionDenied` で
//!   拒否する（パス 1 で落ちるため rootfs は変わらない。#2312）。親の位置の
//!   `.wh.<x>`・`.wh..wh..opq` が先なら従来どおり `InvalidArgument` で拒否する（fail-closed）。
//! - 判定は `normalize_entry_path` の後なので、`..`・絶対パス・NUL・長すぎるパスは予約名の下でも拒否する。
//! - 読み飛ばしたエントリも `max_entries` と入力上限には数え、展開バイト数には数えない。件数は
//!   `ExtractedLayer::ignored_reserved_entries` に返す（黙って捨てない）。
//! - moby との差（#2312）: moby/go-archive `diff.go`（commit a9a82af9）はルート直下の `.wh..wh.plnk` で始まる
//!   通常ファイルを dest 内の一時ディレクトリへ basename で書き出し、後に来る hardlink の参照先が
//!   `.wh..wh.plnk` で始まると basename だけで引き当てて、hardlink ではなく独立した通常ファイルのコピーを作る
//!   （引き当てられなければ失敗）。本実装はこの差し替えを再現せず、`.wh..wh.plnk` など予約名を含む参照先への
//!   hardlink を、パス 1 で `Unimplemented` により拒否する（fail-closed。パス 2 より前なので rootfs は変わらない）。
//!   理由: (1) 結果がエントリの並びで変わり、並び順に依らない 3 パス設計と相容れない。(2) rootfs 内に作業用の木が
//!   要り、IO-5 の `NameIndex` が依る「`root` 配下の実在項目はすべてこの展開が作った名前」という不変条件の例外に
//!   なる（root の外に置くなら別の書き込み場所と上限の計上が要る）。(3) basename だけの引き当てはパス検証の契約より
//!   弱い。(4) image-spec に定めが無い AUFS 固有の慣例で、実イメージで必要になれば後から足せる（可逆）。
//!   これは #2312 での安全側の判断であり、オーナー承認済みの仕様ではない。symlink 経由で予約名のディレクトリが
//!   物理的に作られた後にそれを字面で指す hardlink も、同じく拒否する。
//!
//! # ディレクトリ fd 起点の解決（SEC-5・OCI-1・OCI-2・#2437）
//! 各コンポーネントの `lstat` による確認（`resolve_dir`・別表記の検出・型の衝突の判定）は従来どおりパスで行うが、
//! 変更操作（ディレクトリ・ファイル・symlink・hardlink の作成、削除、`chown`、mode の適用、whiteout の削除）は
//! `layer::anchored` の `AnchoredRoot` を通し、展開の開始時に 1 回だけ開いた `root` の fd を起点に行う。親ディレクトリは
//! 解決済みの物理コンポーネント列から `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//! RESOLVE_NO_XDEV)` で開き直すため、確認の後に祖先が symlink・非ディレクトリ・別マウントへ差し替えられると
//! `FailedPrecondition`（`an extraction path changed during extraction`）で拒否し、`root` の外へ書き込まない。
//! `openat2` が使えないカーネル（5.6 未満）・seccomp は、パス起点へ縮退せず展開の開始前に `Unimplemented` で
//! 拒否する（`Strip` でも同じ）。macOS・Windows・Linux の他アーキテクチャは従来のパス起点のまま
//! （Linux の他アーキテクチャは定数を確かめていないため `Unimplemented`）。
//!
//! # 別表記の衝突（IO-5）
//! 大文字小文字非区別の FS（Windows・macOS の既定）では `f` と `F`、正規化非区別の FS（APFS）では NFC と NFD の
//! 綴りが同じ実体を指す。綴りの比較（`PathBuf` の一致）だけで同一性を判断すると、`f` の後の hardlink
//! `F → f` が参照元を削除し、`d/` の後の `D/` が先の遅延 mode を残す。
//!
//! 判定は展開先 FS の実際の挙動で行う。`NameIndex` にこの展開が作った名前（親ディレクトリと正確な綴りの組）を
//! 記録し、`lstat` が成功するのに索引に無い綴りは「FS が別表記を既存の実体へ解決した」とみなして拒否する。
//! `root` が空で始まるため、実在するのに索引に無い名前はそれ以外に生じない。
//!
//! - 綴りの畳み込み（`fandhe-container-io` の `fold_component`）で判定しないのは、大文字小文字を区別する FS では
//!   `f` と `F` が別ファイルで正当なレイヤーだからである（区別する FS では `lstat` が `NotFound` になり通す）。
//! - 実体の同一性（inode / file index）で判定しないのは、Windows の file index が安定版の std から取れず、
//!   hardlink が正当に同じ inode を共有するためである。
//! - 検査はパスの全コンポーネント（symlink を辿った先・hardlink の参照先を含む）に、変更操作の前に適用する。
//! - 索引の件数は `ExtractLimits::max_tracked_paths` で上限を課す（超過は `ResourceExhausted`）。
//! - 判定は FS の解決結果だけに依るため、Windows の 8.3 短縮名のような他の別名も同じ経路で拒否されるはずだが、
//!   試験で確かめているのは大文字小文字と NFC / NFD だけである。
//!
//! # 所有者の適用（chown。SEC-5・OCI-1・#2225）
//! 既定（`OwnershipPolicy::Keep`）は `chown` せず、展開物は実行ユーザー所有になる。`OwnershipPolicy::ChownMapped`
//! （複数行の写像 `IdMap`）を `ExtractOptions` に入れた呼び出しだけが、tar の uid / gid（コンテナ内 ID）を写像で
//! ホストの ID へ写して `chown` する。
//!
//! - 呼び出し側の契約: 展開するプロセスは初期 user namespace にいて `CAP_CHOWN` を持つ（典型はホスト root）。
//!   ホストの非特権ユーザーは subuid 範囲の ID へ `chown` できず、`EPERM` は `PermissionDenied` で失敗する。
//!   写像はコンテナを起動するときの user namespace の写像（core の `rootless_mapping`・`/etc/subuid` から作ったもの）と
//!   同じものを渡す（cli の `image_ownership` が start と同じ解決部品から作る。#2389）。非 Linux は展開の開始前に `Unimplemented` で拒否する（黙って飛ばさない）。
//! - 検証: 写像に無い ID は `PermissionDenied`、解析できない ID は `InvalidArgument`。パス 1 で
//!   そのレイヤーの書き込みより前に拒否する（グローバル PAX の取り込みもパス 3 と同じ規則）。
//! - 順序: 通常ファイルは書き込み後に `fchown` し、所有者を読み戻して一致を確かめてから（不一致は
//!   `FailedPrecondition`）`fchmod` する（Linux は `chown` で setuid / setgid を落とすため）。ディレクトリは子の作成を
//!   妨げないよう全レイヤーの後に深い順で `lchown` し、その直後に mode を適用する。symlink は `lchown`（追従しない）。
//!   tar に所有者が無い暗黙のディレクトリはコンテナ内 0:0 を写した ID にする。`root` 自身も最後にコンテナ内 0:0 を
//!   写した ID へ `chown` する（mode は 0700 のまま）。
//! - rootless（`OwnershipPolicy::ChownInUserNamespace`。#2382）: 展開プロセスがコンテナと同じ写像の user namespace の
//!   中にいて、tar のコンテナ内 ID をそのまま `chown` する（`ChownMapped` と順序・検証は同じで、宛先だけが恒等）。
//!   `/proc/self/{uid,gid}_map` と effective / fs の ID を開始前に照合する（条件・根拠・制約は
//!   `docs/design/oci-layer-special-bits.md`）。展開した木はホストから見ると subuid の所有になり、ホスト側からは
//!   消せないことがある（後始末は namespace の中で行う。core 側の配線は未実装）。
//! - hardlink は `chown` しない。inode を共有するため、参照先の所有者と特殊ビットを書き換えないためで、所有者は
//!   参照先のエントリのものになる。
//! - PAX の `uname` / `gname` は使わない（読まない）。数値の uid / gid だけを正とする。名前はイメージの
//!   `/etc/passwd` に属し、ホストの NSS で引くと別のユーザーに写りうるため。
//! - tar の xattr（`security.capability` 等）は扱わない。
//!
//! # 未実装（実装済みを装わない。REPAIR-3）
//!
//! - rootless の user namespace へ入って `ImageRootfsUnpacker::unpack` を呼ぶ core 側の配線と、subuid 所有の
//!   rootfs の削除経路（#2315・#482。本モジュールの `ChownInUserNamespace` は展開器の側だけ）。
//!   `PreserveIfOwnerMapped`（`chown` しない 1 行の写像）は従来どおり。
//! - 0700 の祖先ディレクトリで閉じ込めを判定する方式。`root` が 0700 のため、複数範囲の写像でもコンテナ内の
//!   非 root ユーザーは `/` を辿れない。
//! - macOS・Windows・Linux の他アーキテクチャでの、展開と公開の `remove_extracted_tree` のディレクトリ fd 起点の
//!   解決（現状はパス起点で、確認から使用までの TOCTOU と、木の中に残ったマウントの中身の削除を防げない。#2598 で
//!   広げないと決めた。特殊ビットの保持は Linux 限定のため SEC-5 の TOCTOU は Linux 固有で、macOS・Windows の本番経路は
//!   cli が先に fail-closed にし、Linux の他アーキテクチャは展開が `Unimplemented`。広げるには macOS の `openat` 系・
//!   Windows のハンドル起点操作の新しい FFI 宣言と libc 照合、Windows はオーナー判断が要る）。
//! - 綴りの畳み込みによる名前衝突の検出（展開先 FS が区別する別表記は衝突として扱わない。IO-5）。HFS+ のように
//!   保存時に名前を書き換える FS は前提外。
//! - Windows ホストでの symlink エントリ（`Unimplemented` で拒否する）。
//!
//! # 通常ファイルの setuid / setgid / sticky（SEC-5・SEC-1・#1810）
//! 既定（`SpecialBitsPolicy::Strip`）は下位 9 ビット（`FILE_MODE_MASK`）だけを適用し、落とした件数を
//! `ExtractedLayer::files_with_stripped_special_bits` に返す（黙って落とさない）。展開物は実行ユーザー所有のため、
//! ホスト root がほかのユーザーも辿れるステージングへ展開したときに root 所有の setuid が生じるのを防ぐ。
//!
//! `SpecialBitsPolicy::PreserveIfOwnerMapped` を渡した呼び出しだけが、次の条件をすべて満たすビットを tar の値のまま
//! 適用する（それ以外は落とす。fail-closed）。条件と根拠は `docs/design/oci-layer-special-bits.md`。
//! - ホストが Linux で、`root` が実行ユーザー所有の 0700（group / other に権限なし）であること。
//! - setuid: 書いたファイルの所有 uid が 0 でなく、tar の uid を写像（`IdRange`）した host uid と一致すること。
//! - setgid: 書いたファイルの所有 uid と gid がともに 0 でなく、tar の gid を写像した host gid と一致すること
//!   （rootful〔所有 uid 0〕は setuid / setgid を常に落とす。#2251 P2-1）。
//! - sticky: 上記のポリシー全体の条件を満たすこと。
//! - 判定の直前と、ビットを付けた直後に、開いた `root` の fd の `fstat` で「`root` が開始時と同じ所有者の 0700」を
//!   確かめ直す。変わっていたら、そのファイルを含め以後のビットはすべて落とし（`SpecialBitsDecision::
//!   RootChangedDuringExtraction`）、保持済みのビットが 1 件でもあれば全レイヤーの展開後に `FailedPrecondition` で
//!   展開全体を拒否する（遡って外さず fail-closed。`Err` を受けた呼び出し側が `root` ごと破棄する）。
//! - 適用後に mode を読み戻し、ビットが残っていなければ適用したことにしない。ビットごとの件数は
//!   `SpecialBitsOutcome::preserved_bits` / `stripped_bits` に返す（一部のビットだけが落ちても残ったビットを
//!   「落とした」と数えない。#2251 P2-6）。
//!
//! `SpecialBitsPolicy::PreserveIfChowned`（`ChownMapped` と組み合わせたときだけ有効。`Keep` との組み合わせは開始前に
//! `InvalidArgument`）は rootful で残す経路で、`chown` と読み戻しの後の所有者で判定する。条件は次のとおり。
//! - ホストが Linux で、`root` が 0700（group / other に権限なし）であること。
//! - setuid: 読み戻した所有 uid が 0 でなく、`uid.map_to_host(tar の uid)` と一致すること。setgid は gid で同様。
//! - sticky: 上記のポリシー全体の条件を満たすこと。「`root` の所有 uid と一致」の共通条件は使わない
//!   （`chown` 後の所有者は写像先のため）。
//! - 根拠: `IdMap` はホスト ID 0 を含む写像を拒否するため、残る setuid / setgid はホスト上で非特権の subuid / subgid
//!   にしか効かず、`root` が 0700 なのでほかのホストユーザーは辿れない。
//!
//! ディレクトリの mode（sticky・setgid を含む）はポリシーに関係なくそのまま適用する。

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use tar::{Archive, EntryType};

pub use super::idmap::{IdMap, IdRange};
use sha2::{Digest as _, Sha256};

use super::anchored::{AnchorHooks, AnchoredRoot, map_at_err, path_changed, remove_path_tree};
use super::{
    DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, GzipLayerReader, LayerMediaType, PlainLayerReader,
    VerifiedLayerBlob, oci_error_from_layer_io,
};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::Digest;
use crate::whiteout::{self, NameClass};

/// エントリ数上限の参考既定値。API は上限を必須引数にしており、上限なしの経路は提供しない。
pub const DEFAULT_MAX_LAYER_ENTRIES: u64 = 1_000_000;

/// 累積展開バイト数上限の参考既定値（gzip 展開後サイズの参考既定値と同値）。
pub const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES;

/// 索引に載せる名前の数の上限の参考既定値（`ExtractLimits::max_tracked_paths`）。
///
/// 親ディレクトリのエントリを省いた tar が暗黙に作るディレクトリの分を見込み、エントリ数の既定の 2 倍とする。
pub const DEFAULT_MAX_TRACKED_PATHS: u64 = 2 * DEFAULT_MAX_LAYER_ENTRIES;

/// 重ねられるレイヤー数の上限（空レイヤーの無限供給による結果 Vec の無制限増加を防ぐ。超過は `ResourceExhausted`）。
const MAX_LAYERS: usize = 1024;
/// パス全体の最大バイト数（Linux の `PATH_MAX`）。
const MAX_PATH_BYTES: usize = 4096;
/// 1 コンポーネントの最大バイト数（`NAME_MAX`）。
const MAX_COMPONENT_BYTES: usize = 255;
/// 1 パスのコンポーネント数の上限。
const MAX_COMPONENTS: usize = 256;
/// symlink の追従回数の上限（`ELOOP` 相当）。
const MAX_SYMLINK_FOLLOWS: u32 = 40;
/// 複写バッファ長（メモリ使用量を入力サイズに依存させない）。
const COPY_BUF_LEN: usize = 64 * 1024;

/// 展開の上限（必須。将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractLimits {
    /// 受け付けるエントリ数の上限（超過は `ResourceExhausted`）。グローバル PAX ヘッダも数える
    /// （`ExtractedLayer::entries` には含めない。#2251 P2-3）。
    pub max_entries: u64,
    /// 累積展開バイト数の上限（ヘッダ宣言サイズで書き込み前に検査。超過は `ResourceExhausted`）。
    pub max_total_bytes: u64,
    /// 入力 tar ストリーム全体（ヘッダ・パディング・終端後の読み捨てを含む）の読み取り上限バイト数
    /// （超過は `ResourceExhausted`）。`max_total_bytes` は通常ファイル本体しか数えないため別に必須とする。
    pub max_input_bytes: u64,
    /// 展開が作る名前（エントリと、暗黙に作る親ディレクトリ）の数の上限（超過は作成前に `ResourceExhausted`）。
    ///
    /// 別表記の衝突検出（IO-5）の索引 `NameIndex` の件数上限で、索引のメモリ使用量を
    /// `max_tracked_paths ×（1 コンポーネントの最大 255 バイト + 固定長）` に抑える。`max_entries` は tar の
    /// エントリしか数えず、1 エントリが多数の親ディレクトリを暗黙に作れるため別に必須とする。
    pub max_tracked_paths: u64,
}

impl ExtractLimits {
    /// 上限を指定して作る。
    pub fn new(
        max_entries: u64,
        max_total_bytes: u64,
        max_input_bytes: u64,
        max_tracked_paths: u64,
    ) -> Self {
        Self {
            max_entries,
            max_total_bytes,
            max_input_bytes,
            max_tracked_paths,
        }
    }
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_LAYER_ENTRIES,
            DEFAULT_MAX_EXTRACTED_BYTES,
            DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            DEFAULT_MAX_TRACKED_PATHS,
        )
    }
}

/// 展開に成功したレイヤーの結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedLayer {
    /// 処理したエントリ数（PAX グローバルヘッダを除く）。
    pub entries: u64,
    /// 書き出したファイル本体の累積バイト数。
    pub bytes: u64,
    /// tar の mode に setuid / setgid / sticky が付いていて、それを落として展開した通常ファイルのエントリ数。
    ///
    /// 0 でなければ、展開結果の mode はレイヤーの記述と一致しない（ポリシーの条件を満たさなかった。
    /// モジュール冒頭の「通常ファイルの setuid / setgid / sticky」を参照）。
    pub files_with_stripped_special_bits: u64,
    /// AUFS メタデータの予約名（`.wh..wh.` で始まり `.wh..wh..opq` 以外。配下を含む）として読み飛ばしたエントリ数。
    ///
    /// 読み飛ばしたエントリは rootfs へ何も書かず、何も消さない（`entries` には数え、`bytes` には数えない。#2183・OCI-2）。
    pub ignored_reserved_entries: u64,
    /// 特殊ビットのポリシーの判定と、保持した件数（#1810）。
    pub special_bits: SpecialBitsOutcome,
    /// 所有者の適用（`chown`）の判定と件数（#2225・SEC-5）。
    pub ownership: OwnershipOutcome,
    /// 展開後 tar（圧縮を解いた全バイト。終端後の読み捨てを含む）の sha256。image config の
    /// `rootfs.diff_ids` の要素と同じ値（#2017・OCI-1）。パス 1 の読み取りで計算し、パス 3 の再計算と一致した値（#2309）。
    pub diff_id: Digest,
}

/// 通常ファイルの setuid / setgid / sticky の扱い（SEC-5・SEC-1・#1810）。既定は `Strip`。
///
/// 展開の入口 `extract_layers_with_policy` / `extract_image_layers_with_policy`（と `*_with_options` の `ExtractOptions`）が受け取る。呼び出し元は、
/// rootfs を排他的に所有し、展開から rootfs として使い終わるまで `root` を 0700 に保つこと（権限の後からの
/// 変更〔TOCTOU〕は防げない）。コンテナ内で setuid が効くかは `process.noNewPrivileges` に依り、本ポリシーは
/// ビットの保持までを扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SpecialBitsPolicy {
    /// 常に落とす（従来の挙動）。
    #[default]
    Strip,
    /// 所有者が user namespace の写像に収まるファイルだけ、tar の値を適用する。条件はモジュール冒頭を参照。
    ///
    /// `chown` しない 1 行の写像の経路（rootless）。rootful（ホスト uid 0）は所有 uid が 0 のため setuid / setgid を
    /// 常に落とす（sticky は共通の条件のみ。#2251 P2-1）。`uid` / `gid` の ID の見え方は `IdRange` を参照。
    /// rootful で残す経路は `PreserveIfChowned`。
    PreserveIfOwnerMapped {
        /// uid の写像。
        uid: IdRange,
        /// gid の写像。
        gid: IdRange,
    },
    /// rootful（`OwnershipPolicy::ChownMapped` で subuid 範囲へ `chown` する展開）で、`chown` と読み戻しの後の
    /// 所有者が写像と一致するファイルだけ、tar の値を適用する（#2225・SEC-5・SEC-1）。
    ///
    /// `OwnershipPolicy::ChownMapped` と組み合わせたときだけ有効で、`Keep` との組み合わせは展開の開始前に
    /// `InvalidArgument` で拒否する（副作用なし）。条件はモジュール冒頭「rootful で特殊ビットを残す条件」を参照。
    PreserveIfChowned,
}

/// 展開物の所有者（uid / gid）の扱い（SEC-5・#2225）。既定は `Keep`。
///
/// `ChownMapped` は tar のコンテナ内 ID を写像でホストの ID へ写して `chown` する。ホストの非特権ユーザーは
/// subuid 範囲の ID へ `chown` できない（`EPERM`）ため、呼び出し側は初期 user namespace で `CAP_CHOWN` を持つ
/// プロセス（典型はホスト root）から使う。権限が無く範囲外の ID へ `chown` すると `PermissionDenied` で失敗する
/// （fail-closed）。非 Linux では展開の開始前に `Unimplemented` で拒否する。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OwnershipPolicy {
    /// `chown` しない（展開物は実行ユーザー所有。従来の挙動）。
    #[default]
    Keep,
    /// tar の uid / gid を写像でホストの ID へ写して `chown` する。写像に無い ID は `PermissionDenied`、
    /// 解析できない ID は `InvalidArgument` で、そのレイヤーの書き込みより前に拒否する。
    ChownMapped {
        /// uid の写像。
        uid: IdMap,
        /// gid の写像。
        gid: IdMap,
    },
    /// rootless: 展開プロセスがコンテナと同じ写像の user namespace の中にいる前提で、tar のコンテナ内 ID を
    /// そのまま `chown` する（namespace の中では恒等写像。#2382・OCI-2・SEC-5）。
    ///
    /// `uid` / `gid` はコンテナの user namespace の写像（`container_id parent_id count`。core の
    /// `rootless_mapping` / `IdMapSet` と同じもの）で、ホスト ID 0 は `IdMap::new` が拒否する。tar の ID が写像に
    /// 含まれるかの判定にだけ使い、写像に無い ID は `PermissionDenied`、解析できない ID は `InvalidArgument` で
    /// そのレイヤーの書き込みより前に拒否する。
    ///
    /// 開始前（`root` に触れる前）に `/proc/self` で次を確かめ、満たさなければ `FailedPrecondition` で拒否する
    /// （fail-closed）: 初期 user namespace でない・`/proc/self/{uid,gid}_map` が渡された写像と集合として一致する・
    /// effective / fs の uid と gid が 0（namespace の中の ID）。呼び出し側の契約: 単一スレッドで、
    /// 初期 user namespace の直下に作った namespace に入っている（入れ子では「親の ID が 0 でない」が
    /// 「ホスト ID が 0 でない」を意味しない）。namespace へ入る処理は core の責務で、oci は入らない。
    /// 非 Linux は開始前に `Unimplemented`。
    ChownInUserNamespace {
        /// uid の写像（コンテナの user namespace の写像）。
        uid: IdMap,
        /// gid の写像。
        gid: IdMap,
    },
}

/// 展開の期限と取り消し（REPAIR-5・CRI-2・#2899）。
///
/// cri の `ImageRootfsSource::prepare`（CreateContainer の rootfs 用意）と `OciImagePuller`（PullImage。#2967）が
/// `extract_image_layers_bounded` / `extract_layers_bounded` へ渡す。展開の結果を決める設定ではないため `ExtractOptions`（展開記録の `settings` に
/// 直列化して pull と create の間で照合する）には入れない。既定（`new()`）は期限も取り消しも無く、従来の入口と同じ。
///
/// 確認はレイヤーの前・パス 1 のエントリごと・パス 2 のマーカーごと・パス 3 のエントリごと（書き込みの前）・
/// 遅延ディレクトリ mode の適用の前に行い、期限超過か取り消しなら `OciErrorCode::Timeout` で止まる。分割できない区間は
/// 1 エントリの本体の書き込み（最大 `max_total_bytes`）と 1 本の tar の終端後の読み捨て（入力上限で有界）。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExtractBudget<'a> {
    /// この時刻以降は `Timeout`（`None` は期限なし）。
    deadline: Option<Instant>,
    /// 立ったら `Timeout`（RPC の期限切れで worker を手放したとき等。`None` は取り消しなし）。
    cancel: Option<&'a AtomicBool>,
    /// 現在時刻の取得口（試験だけが差し替える）。
    now: fn() -> Instant,
}

impl Default for ExtractBudget<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ExtractBudget<'a> {
    /// 期限も取り消しも無い予算（従来の入口と同じ）。
    pub fn new() -> Self {
        Self {
            deadline: None,
            cancel: None,
            now: Instant::now,
        }
    }

    /// 期限（絶対時刻）を足す。
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// 取り消しの旗を足す。
    #[must_use]
    pub fn with_cancel(mut self, cancel: &'a AtomicBool) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// 期限超過か取り消しなら `Timeout`。メッセージにエントリ名・パスは含めない（ERR-3）。
    fn check(&self) -> Result<(), OciError> {
        if let Some(c) = self.cancel
            && c.load(AtomicOrdering::Acquire)
        {
            return Err(err(OciErrorCode::Timeout, "layer extraction was cancelled"));
        }
        if let Some(d) = self.deadline
            && (self.now)() >= d
        {
            return Err(err(
                OciErrorCode::Timeout,
                "layer extraction exceeded its deadline",
            ));
        }
        Ok(())
    }
}

/// 展開の選択肢（所有者・特殊ビット）。将来の項目追加に備え `non_exhaustive`。
///
/// `extract_layers_with_options` / `extract_image_layers_with_options` が受け取る。既定は従来の挙動
/// （`chown` しない・特殊ビットは落とす）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ExtractOptions {
    /// 所有者の扱い。
    pub ownership: OwnershipPolicy,
    /// 通常ファイルの特殊ビットの扱い。
    pub special_bits: SpecialBitsPolicy,
}

impl ExtractOptions {
    /// 既定の選択肢（`chown` しない・特殊ビットは落とす）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 所有者の扱いを設定する。
    #[must_use]
    pub fn with_ownership(mut self, ownership: OwnershipPolicy) -> Self {
        self.ownership = ownership;
        self
    }

    /// 特殊ビットの扱いを設定する。
    #[must_use]
    pub fn with_special_bits(mut self, special_bits: SpecialBitsPolicy) -> Self {
        self.special_bits = special_bits;
        self
    }
}

/// 所有者の適用の判定（REPAIR-4: 機械可読）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnershipDecision {
    /// `OwnershipPolicy::Keep` のため `chown` しなかった。
    NotRequested,
    /// `OwnershipPolicy::ChownMapped` / `ChownInUserNamespace` に従って `chown` した。
    Applied,
}

/// 所有者の適用の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OwnershipOutcome {
    /// ポリシー全体の判定。
    pub decision: OwnershipDecision,
    /// `chown` を実行したノード数（通常ファイル・symlink・ディレクトリ・暗黙のディレクトリ・`root`）。
    /// ディレクトリと `root` は全レイヤーの展開後にまとめて適用するため、最後のレイヤーの結果に数える。
    /// hardlink は参照先と inode を共有するため `chown` せず、数えない。
    pub chowned_entries: u64,
}

/// ポリシー全体の判定結果（REPAIR-4: 機械可読）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecialBitsDecision {
    /// `Strip` のため、すべて落とした。
    StripPolicy,
    /// Linux 以外のホストのため、すべて落とした。
    UnsupportedHost,
    /// `root` が group / other に開かれている、または root の確認ができず、すべて落とした。
    RootAccessibleByOthers,
    /// ファイルごとの条件で判定した。
    Evaluated,
    /// 展開中に `root` の所有者または 0700 が変わったことを検出し、以後のファイルはすべて落とした（#2437）。
    /// 検出前に保持済みのビットがあれば、展開は `FailedPrecondition` で終わる（結果は返らない）。
    RootChangedDuringExtraction,
}

/// 特殊ビットの扱いの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpecialBitsOutcome {
    /// ポリシー全体の判定。
    pub decision: SpecialBitsDecision,
    /// 特殊ビットを tar の値どおりに適用した（読み戻しで確認した）通常ファイルのエントリ数。
    pub preserved_files: u64,
    /// 読み戻しでディスクに残ったビットのビットごとの件数（REPAIR-4・#2251 P2-6）。
    pub preserved_bits: SpecialBitCounts,
    /// 求めたが読み戻しで残らなかったビットのビットごとの件数。一部のビットだけが落ちたファイルでも、
    /// 残ったビットは `preserved_bits`、落ちたビットだけがここに数えられる。
    pub stripped_bits: SpecialBitCounts,
}

/// 通常ファイルの特殊ビットのビットごとの件数（REPAIR-4・#2251 P2-6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SpecialBitCounts {
    /// setuid の件数。
    pub setuid: u64,
    /// setgid の件数。
    pub setgid: u64,
    /// sticky の件数。
    pub sticky: u64,
}

impl SpecialBitCounts {
    /// `bits` に立っている特殊ビットごとに 1 を足す。
    fn add_bits(&mut self, bits: u32) {
        if bits & S_ISUID != 0 {
            self.setuid = self.setuid.saturating_add(1);
        }
        if bits & S_ISGID != 0 {
            self.setgid = self.setgid.saturating_add(1);
        }
        if bits & S_ISVTX != 0 {
            self.sticky = self.sticky.saturating_add(1);
        }
    }

    /// レイヤーごとの差分（`self - base`）。
    fn saturating_sub(self, base: Self) -> Self {
        Self {
            setuid: self.setuid.saturating_sub(base.setuid),
            setgid: self.setgid.saturating_sub(base.setgid),
            sticky: self.sticky.saturating_sub(base.sticky),
        }
    }
}

/// 計装なしの `extract_tar_with`（`NoopOciOpRecorder`）。
pub fn extract_tar<R: Read + Seek>(
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    extract_tar_with(&NoopOciOpRecorder, src, root, limits)
}

/// 展開全体を `OciOpKind::ExtractLayer` として `recorder` へ記録する（REPAIR-4）。
///
/// `src` は gzip 展開済みの tar バイトストリーム。tar を 2 回走査するため `Seek` を求め、各走査の前に
/// 最初に渡された時点の位置へ戻す（モジュール冒頭「レイヤーごとの 3 パス」）。gzip の blob は
/// `extract_image_layers`（検証済みハンドル）を使う。契約はモジュール冒頭を参照。
/// 複数レイヤーを重ねるときは `extract_layers_with` を使う（これは要素 1 つのスタックと同じ）。
pub fn extract_tar_with<R: Read + Seek>(
    recorder: &dyn OciOpRecorder,
    src: R,
    root: &Path,
    limits: ExtractLimits,
) -> Result<ExtractedLayer, OciError> {
    single(extract_stack(
        recorder,
        [Rewind::new(src)],
        root,
        limits,
        host_lstat,
        SpecialSetup::host(SpecialBitsPolicy::Strip),
    )?)
}

/// 計装なしの `extract_layers_with`（`NoopOciOpRecorder`）。
pub fn extract_layers<R: Read + Seek>(
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_layers_with(&NoopOciOpRecorder, layers, root, limits)
}

/// 複数レイヤーの tar を下位から上位の順に同一 `root` へ重ねて展開する（TASK-52.4・OCI-1・#410）。
///
/// `layers` は下位（ベース）から上位の順の tar バイトストリーム。各レイヤーを 2 回走査するため `Seek` を求め、
/// 各走査の前に最初に渡された時点の位置へ戻す。既存のパスとの関係は image-spec の「Changeset over existing
/// files」に従い、whiteout（`.wh.*`）・不透明ディレクトリは下位レイヤーの実体にだけ適用する（OCI-2・TASK-53.3）。
/// 戻り値はレイヤーごとの結果（入力と同じ順）。`root` が空であることは最初のレイヤーの前に 1 回だけ検査し、
/// 別表記の索引（IO-5）・遅延ディレクトリ mode・上限は全レイヤーで共有する（上限は全体で累積）。
/// 各レイヤーを `OciOpKind::ExtractLayer` として 1 回ずつ `recorder` へ記録する（REPAIR-4）。
/// 空の `layers` は `InvalidArgument`。契約はモジュール冒頭を参照。
pub fn extract_layers_with<R: Read + Seek>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_layers_with_policy(recorder, layers, root, limits, SpecialBitsPolicy::Strip)
}

/// `extract_layers_with` に通常ファイルの特殊ビットのポリシーを足した版（SEC-5・#1810）。
///
/// `policy` の契約はモジュール冒頭と `SpecialBitsPolicy` を参照。`Strip` なら `extract_layers_with` と同じ。
pub fn extract_layers_with_policy<R: Read + Seek>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
    policy: SpecialBitsPolicy,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_layers_with_options(
        recorder,
        layers,
        root,
        limits,
        &ExtractOptions::new().with_special_bits(policy),
    )
}

/// `extract_layers_with` に所有者（`chown`）と特殊ビットの選択肢を足した版（SEC-5・OCI-1・#2225）。
///
/// `options` の契約はモジュール冒頭と `OwnershipPolicy` / `SpecialBitsPolicy` を参照。既定の `ExtractOptions` なら
/// `extract_layers_with` と同じ。不正な組み合わせ（`PreserveIfChowned` を `Keep` と組む等）・非 Linux の
/// `ChownMapped` は、`root` に触れる前に拒否する。
pub fn extract_layers_with_options<R: Read + Seek>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
    options: &ExtractOptions,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_stack(
        recorder,
        layers.into_iter().map(Rewind::new),
        root,
        limits,
        host_lstat,
        SpecialSetup::from_options(options),
    )
}

/// `extract_layers_with_options` に期限と取り消しの `budget` を足した版（REPAIR-5・#2899）。契約は
/// `extract_image_layers_bounded` と同じ（`Err` のとき `root` は呼び出し側が破棄する）。
pub fn extract_layers_bounded<R: Read + Seek>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = R>,
    root: &Path,
    limits: ExtractLimits,
    options: &ExtractOptions,
    budget: &ExtractBudget<'_>,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_stack_bounded(
        recorder,
        layers.into_iter().map(Rewind::new),
        root,
        limits,
        host_lstat,
        SpecialSetup::from_options(options),
        *budget,
    )
}

/// 1 レイヤー分の tar バイトストリームを、走査のたびに先頭から開き直す入力。
///
/// `extract_one_layer` がパス 1（収集・検証）とパス 3（展開）の前に 1 回ずつ `open` を呼ぶ。
trait LayerSource {
    /// `open` が返す読み取り口。
    type Reader<'a>: Read
    where
        Self: 'a;

    /// tar の先頭から読める状態の読み取り口を返す。
    fn open(&mut self) -> Result<Self::Reader<'_>, OciError>;

    /// 展開後 tar の sha256 として期待する値（image config の `rootfs.diff_ids` の要素）。`None` なら突合しない。
    fn expected_diff_id(&self) -> Option<&Digest> {
        None
    }
}

/// `Read + Seek` のストリームを、最初に `open` された時点の位置へ戻して読み直す `LayerSource`。
struct Rewind<R> {
    inner: R,
    /// 最初の `open` で記録した開始位置。
    start: Option<u64>,
}

impl<R> Rewind<R> {
    fn new(inner: R) -> Self {
        Self { inner, start: None }
    }
}

fn rewind_failed(_e: std::io::Error) -> OciError {
    err(
        OciErrorCode::Internal,
        "failed to rewind the layer tar stream",
    )
}

impl<R: Read + Seek> LayerSource for Rewind<R> {
    type Reader<'a>
        = &'a mut R
    where
        R: 'a;

    fn open(&mut self) -> Result<&mut R, OciError> {
        match self.start {
            Some(pos) => {
                self.inner
                    .seek(SeekFrom::Start(pos))
                    .map_err(rewind_failed)?;
            }
            None => {
                self.start = Some(self.inner.stream_position().map_err(rewind_failed)?);
            }
        }
        Ok(&mut self.inner)
    }
}

/// blob 系 `LayerSource` の読み取り口。`mediaType` に応じて gzip 展開か素通しかが決まる。
///
/// `R` は読み取り元で、ハンドル版 `VerifiedBlobLayer` は `&File`。
enum LayerReader<R: Read> {
    Gzip(Box<GzipLayerReader<R>>),
    Plain(PlainLayerReader<R>),
}

impl<R: Read> Read for LayerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Gzip(r) => r.read(buf),
            Self::Plain(r) => r.read(buf),
        }
    }
}

/// 検証済みハンドル（`VerifiedLayerBlob`）から読む `LayerSource`（#2309・OCI-1）。パスを一度も開き直さない。
///
/// `open` のたびにハンドルの先頭へ seek してから gzip 展開か素通しで包む。同じ `VerifiedLayerBlob` を複数の
/// レイヤーに渡しても正しく読めるが、読み取り位置はハンドルの中で共有されるため、展開中に同じ値を並行して読まないこと
/// （`extract_stack` は直列に読む）。
struct VerifiedBlobLayer<'b> {
    blob: &'b VerifiedLayerBlob,
    media_type: LayerMediaType,
    max_uncompressed_bytes: u64,
    expected_diff_id: Option<Digest>,
}

impl LayerSource for VerifiedBlobLayer<'_> {
    type Reader<'a>
        = LayerReader<&'a File>
    where
        Self: 'a;

    fn open(&mut self) -> Result<LayerReader<&File>, OciError> {
        let mut handle = self.blob.file();
        handle
            .seek(SeekFrom::Start(0))
            .map_err(|_| err(OciErrorCode::Internal, "failed to rewind the layer blob"))?;
        Ok(match self.media_type {
            LayerMediaType::TarGzip => LayerReader::Gzip(Box::new(GzipLayerReader::new(
                handle,
                self.max_uncompressed_bytes,
            ))),
            LayerMediaType::Tar => {
                LayerReader::Plain(PlainLayerReader::new(handle, self.max_uncompressed_bytes))
            }
        })
    }

    fn expected_diff_id(&self) -> Option<&Digest> {
        self.expected_diff_id.as_ref()
    }
}

/// `extract_image_layers` に渡す 1 レイヤー分の記述（#2017・#2309・OCI-1）。
///
/// blob はパスではなく `VerifiedLayerBlob`（信頼条件と digest を同じハンドルで確かめた値）で受ける。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ImageLayer<'a> {
    /// 信頼条件と digest を検証済みの blob。
    pub blob: &'a VerifiedLayerBlob,
    /// manifest の descriptor の `mediaType`。
    pub media_type: &'a str,
    /// image config の `rootfs.diff_ids` の対応する要素。
    pub diff_id: &'a Digest,
}

impl<'a> ImageLayer<'a> {
    /// 検証済み blob・`mediaType`・期待する diff_id から作る。
    pub fn new(blob: &'a VerifiedLayerBlob, media_type: &'a str, diff_id: &'a Digest) -> Self {
        Self {
            blob,
            media_type,
            diff_id,
        }
    }
}

/// 計装なしの `extract_image_layers_with`（`NoopOciOpRecorder`）。
pub fn extract_image_layers(
    layers: &[ImageLayer<'_>],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_image_layers_with(
        &NoopOciOpRecorder,
        layers,
        root,
        max_uncompressed_bytes,
        limits,
    )
}

/// `mediaType` で入口を選び、展開後 tar の sha256 を `rootfs.diff_ids` と突合しながら重ねて展開する（#2017・OCI-1）。
///
/// 入力は `VerifiedLayerBlob`（検証済みハンドル）で、パスは開き直さない（#2309）。パス 1 とパス 3 は同じハンドルを読み、
/// パス 3 でも同じハッシュを計算して末尾で照合する（不一致は `DataLoss`。`root` ごと破棄すること）。
///
/// 手順は、(1) 全レイヤーの `mediaType` を I/O より前に検査する（未対応は `Unimplemented`。rootfs に触れない）、
/// (2) 各レイヤーのパス 1 で計算した展開後 tar の sha256 を `diff_id` と突合する（不一致は `DataLoss`。そのレイヤーの
/// 変更を始める前に止まるが、先行レイヤーの展開物は残るため、呼び出し側が `root` ごと破棄すること）。
/// `layers` の件数と config の `diff_ids` の件数の照合は `image_layers_from` が行う
/// （`diff_id` を 1 対 1 で渡すため、不一致は型の上で表現できない）。その他は `extract_layers_with` と同じ。
pub fn extract_image_layers_with(
    recorder: &dyn OciOpRecorder,
    layers: &[ImageLayer<'_>],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_image_layers_with_policy(
        recorder,
        layers,
        root,
        max_uncompressed_bytes,
        limits,
        SpecialBitsPolicy::Strip,
    )
}

/// `extract_image_layers_with` に通常ファイルの特殊ビットのポリシーを足した版（SEC-5・#1810）。
pub fn extract_image_layers_with_policy(
    recorder: &dyn OciOpRecorder,
    layers: &[ImageLayer<'_>],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
    policy: SpecialBitsPolicy,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_image_layers_with_options(
        recorder,
        layers,
        root,
        max_uncompressed_bytes,
        limits,
        &ExtractOptions::new().with_special_bits(policy),
    )
}

/// `extract_image_layers_with` に所有者（`chown`）と特殊ビットの選択肢を足した版（SEC-5・OCI-1・#2225・#2323）。
///
/// `options` の契約は `extract_layers_with_options` と同じ。cri の `PullImage` が `PullConfig` の選択肢をそのまま渡す
/// 入口で、`Err` のときは先行レイヤーの展開物が `root` に残りうるため、呼び出し側が `root` ごと破棄すること。
pub fn extract_image_layers_with_options(
    recorder: &dyn OciOpRecorder,
    layers: &[ImageLayer<'_>],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
    options: &ExtractOptions,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_image_layers_bounded(
        recorder,
        layers,
        root,
        max_uncompressed_bytes,
        limits,
        options,
        &ExtractBudget::new(),
    )
}

/// `extract_image_layers_with_options` に期限と取り消しの `budget` を足した版（REPAIR-5・CRI-2・#2899）。
///
/// 空の `budget` なら既存の入口と同一。`budget` はエントリ単位で確かめ、超過・取り消しなら `OciErrorCode::Timeout`。
/// `Err` のときは先行の展開物が `root` に残りうるため、呼び出し側が `root` ごと破棄すること
/// （cri の `ImageRootfsSource::prepare` は `remove_extracted_tree` で消す）。
pub fn extract_image_layers_bounded(
    recorder: &dyn OciOpRecorder,
    layers: &[ImageLayer<'_>],
    root: &Path,
    max_uncompressed_bytes: u64,
    limits: ExtractLimits,
    options: &ExtractOptions,
    budget: &ExtractBudget<'_>,
) -> Result<Vec<ExtractedLayer>, OciError> {
    let setup = SpecialSetup::from_options(options);
    budget.check()?;
    // レイヤー 0 のイメージ（manifest の layers と diff_ids がともに空）は正常な入力。展開物は空の rootfs になる。
    // `extract_stack` は空入力を拒否するため、ここで選択肢の組み合わせと root の前提だけ確かめて空の結果を返す。
    if layers.is_empty() {
        return extract_zero_layers(root, &setup);
    }
    let sources = layers
        .iter()
        .map(|l| {
            Ok(VerifiedBlobLayer {
                blob: l.blob,
                media_type: LayerMediaType::parse(l.media_type)?,
                max_uncompressed_bytes,
                expected_diff_id: Some(l.diff_id.clone()),
            })
        })
        .collect::<Result<Vec<_>, OciError>>()?;
    extract_stack_bounded(recorder, sources, root, limits, host_lstat, setup, *budget)
}

/// レイヤー 0 のイメージの展開（選択肢と root の前提を確かめ、`ChownMapped` なら root だけ写像先へ `chown` する）。
///
/// `ChownMapped` では空の rootfs でも root 自身を写像先へ `chown` する（`extract_stack` の `chown_root` と同じ）。
/// 省くと root が 0700 の実行ユーザー所有のまま公開され、期待所有者の照合が常に食い違う（SEC-5・OCI-1）。
fn extract_zero_layers(root: &Path, setup: &SpecialSetup) -> Result<Vec<ExtractedLayer>, OciError> {
    let own = setup.owner_ctx()?;
    let anchor = AnchoredRoot::open(root, setup.anchor)?;
    check_root_empty(&anchor)?;
    if let Some(o) = &own {
        let ids = o.resolve((Some(0), Some(0)))?;
        (o.fns.lchown)(&anchor, &[], ids.0, ids.1).map_err(|e| chown_err(&e))?;
    }
    Ok(Vec::new())
}

/// 展開した木を symlink を追従せずに消す（#2323）。存在しなければ成功。
///
/// 展開は最後に遅延していたディレクトリの mode（0555 等）を適用するため、展開後に中断した root は通常の
/// `remove_dir_all` では消せないことがある。所有者の rwx が欠けるディレクトリ（0000 を含む）は権限を戻してから消す。
/// cri の `PullImage` のステージングの後始末と、コンテナの rootfs の解放が使う。深さは上限があり、超えれば
/// `ResourceExhausted`。
///
/// Linux の x86_64 / aarch64 では `path` の親を開いた fd 起点で下降し、差し替えられた symlink・マウントポイントを
/// `FailedPrecondition` で拒否する（`path` の外を消さない。`/proc` が必要。OCI-1・SEC-5・#2598）。
/// `file_name` を持たない `path`（`/`・`..` 終わり）は `InvalidArgument`。他のホストはパス起点のままで、確認から
/// 使用までの TOCTOU を防げない（モジュール冒頭「未実装」）。
pub fn remove_extracted_tree(path: &Path) -> Result<(), OciError> {
    remove_path_tree(path)
}

/// 件数と対応の照合つきで `ImageLayer` の列を作る補助（#2017・#2309・OCI-1）。
///
/// manifest の `layers`・検証済みの blob・config の `rootfs.diff_ids` の 3 者の件数が揃わなければ、どの I/O よりも
/// 前に `DataLoss` を返す。各 descriptor の `digest`・`size` が対応する blob の検証済みの値と違う場合も、
/// 取り違えた blob を展開しないよう `DataLoss` で拒否する。
pub fn image_layers_from<'a>(
    descriptors: &'a [crate::manifest::Descriptor],
    blobs: &'a [&'a VerifiedLayerBlob],
    rootfs: &'a crate::config::ImageRootFs,
) -> Result<Vec<ImageLayer<'a>>, OciError> {
    let ids = rootfs.diff_ids();
    if descriptors.len() != ids.len() || descriptors.len() != blobs.len() {
        return Err(err(
            OciErrorCode::DataLoss,
            "layer count does not match rootfs.diff_ids",
        ));
    }
    descriptors
        .iter()
        .zip(blobs)
        .zip(ids)
        .map(|((d, blob), id)| {
            if d.digest != *blob.digest() || d.size != blob.size() {
                return Err(err(
                    OciErrorCode::DataLoss,
                    "layer blob does not match the manifest descriptor",
                ));
            }
            Ok(ImageLayer::new(blob, d.media_type.as_str(), id))
        })
        .collect()
}

/// 読んだバイトを sha256 へ通す読み取りアダプタ（パス 1 で展開後 tar の diff_id を計算する）。
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(read) = buf.get(..n) {
            self.hasher.update(read);
        }
        Ok(n)
    }
}

/// sha256 の出力を `Digest` へ変換する。
fn digest_of(hasher: Sha256) -> Result<Digest, OciError> {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in hasher.finalize() {
        // String への書き込みは失敗しない。
        let _ = write!(s, "{b:02x}");
    }
    Digest::parse(&s)
}

/// 展開先 FS の名前解決（`lstat`）。既定は `fs::symlink_metadata`。
///
/// 大文字小文字を区別する FS しかない CI（Linux）でも「別表記が同じ実体へ解決される」経路を照合できるよう、
/// テストから差し替える注入点にしている。拒否は変更操作より前に行うため、差し替えるのは解決だけでよい。
type Lstat = fn(&Path) -> std::io::Result<fs::Metadata>;

/// 既定の `Lstat`（ホストの FS をそのまま引く）。
fn host_lstat(path: &Path) -> std::io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

/// `NameIndex` での `root` 自身の ID。
const ROOT_ID: u64 = 0;

/// この展開が作った名前の索引（IO-5 の別表記の衝突検出用）。
///
/// 親ディレクトリの ID ごとに「作成時の正確な綴り → ID」を持つ。物理パス全体ではなく親の ID で持つため、1 件あたりの
/// メモリは 1 コンポーネントの長さ（`MAX_COMPONENT_BYTES` 以下）と固定長に収まる。件数は `limit` で頭打ちにする。
/// 親ごとに子を引けるので、削除した木の登録を外す処理（`forget_tree`・`forget_children`）は外す件数に比例する
/// （全登録を走査しない。whiteout が多数あるレイヤーでも線形。OCI-2）。
/// ディレクトリを削除するのは whiteout・不透明の適用と、下位レイヤー由来のノードの置換だけで、そのときは
/// 必ず配下の登録を外す。ID は再利用しないため、残った ID は展開の間ずっと同じディレクトリを指す。
struct NameIndex {
    children: HashMap<u64, HashMap<OsString, u64>>,
    /// 登録件数（`children` の内側の要素数の合計）。
    len: u64,
    limit: u64,
    /// 次に採番する ID。登録を外して件数が減っても過去の ID を再利用しない（旧ディレクトリの登録と
    /// 混ざって別表記の判定を誤らないため）。
    next_id: u64,
}

impl NameIndex {
    fn new(limit: u64) -> Self {
        Self {
            children: HashMap::new(),
            len: 0,
            limit,
            next_id: ROOT_ID + 1,
        }
    }

    /// 削除した `parent` 直下の `name` と、その配下の登録をすべて外し、外した ID を返す（IO-5）。
    /// 外さないと、削除済みの綴りを現在の実体の綴りとして受理してしまう。ID は再利用しない。
    fn forget_tree(&mut self, parent: u64, name: &OsStr) -> Vec<u64> {
        let Some(id) = self.children.get_mut(&parent).and_then(|m| m.remove(name)) else {
            return Vec::new();
        };
        self.len = self.len.saturating_sub(1);
        self.forget_descendants(vec![id])
    }

    /// 不透明ディレクトリ（TASK-53.2）で中身を消した `parent` 直下の全登録と、その配下をまとめて外し、
    /// 外した ID を返す（`parent` 自身の登録は残す。IO-5）。
    fn forget_children(&mut self, parent: u64) -> Vec<u64> {
        let Some(m) = self.children.remove(&parent) else {
            return Vec::new();
        };
        self.len = self.len.saturating_sub(m.len() as u64);
        self.forget_descendants(m.into_values().collect())
    }

    /// `work` の各 ID と、それを親とする登録を再帰的に外す。戻り値は `work` を含む外した全 ID。
    fn forget_descendants(&mut self, mut work: Vec<u64>) -> Vec<u64> {
        let mut out = Vec::new();
        while let Some(id) = work.pop() {
            out.push(id);
            if let Some(m) = self.children.remove(&id) {
                self.len = self.len.saturating_sub(m.len() as u64);
                work.extend(m.into_values());
            }
        }
        out
    }

    /// `parent` 直下に `name` をこの綴りで作っていれば、その ID を返す。
    fn get(&self, parent: u64, name: &OsStr) -> Option<u64> {
        self.children.get(&parent)?.get(name).copied()
    }

    /// `parent` 直下の `name` を索引へ載せて ID を返す（登録済みなら同じ ID）。作成操作の前に呼び、
    /// 上限超過なら何も作らせずに `ResourceExhausted` を返す。
    fn insert(&mut self, parent: u64, name: &OsStr) -> Result<u64, OciError> {
        if let Some(id) = self.get(parent, name) {
            return Ok(id);
        }
        // ROOT_ID（0）と重ならないよう 1 始まりで採番する。
        let id = self.next_id;
        if self.len >= self.limit {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "layer exceeds the tracked path limit",
            ));
        }
        self.next_id = id.checked_add(1).ok_or_else(|| {
            err(
                OciErrorCode::ResourceExhausted,
                "layer exceeds the tracked path limit",
            )
        })?;
        self.children
            .entry(parent)
            .or_default()
            .insert(name.to_os_string(), id);
        self.len = self.len.saturating_add(1);
        Ok(id)
    }
}

/// whiteout・不透明ディレクトリのマーカー（パス 1 で集め、パス 2 で下位レイヤーへ適用する。OCI-2）。
///
/// `parent` は `normalize_entry_path` 済みのコンポーネント列（root 直下は空）。並べ替えと重複除去のため `Ord` を持つ。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Marker {
    /// `parent/.wh.<target>`: 下位の `parent/target` を木ごと消す。
    Whiteout {
        parent: Vec<OsString>,
        target: OsString,
    },
    /// `parent/.wh..wh..opq`: 下位の `parent` の中身を消す（`parent` 自体は残す）。
    Opaque { parent: Vec<OsString> },
}

/// パス 2 で削除を実行する前に、下位ツリーで解決し終えた削除対象。
enum Removal {
    /// `parent`（ID。物理コンポーネント列は `parent_comps`）直下の `name` を木ごと消す。
    Tree {
        parent_comps: Vec<OsString>,
        parent: u64,
        name: OsString,
    },
    /// ディレクトリ（`root` からの物理コンポーネント列は `comps`、ID は `id`）の中身を消す。
    Contents { comps: Vec<OsString>, id: u64 },
}

/// tar エントリ 1 件の検証済みの処理内容（パス 1 とパス 3 で共通の `plan_entry` が作る）。
enum Plan {
    /// whiteout・不透明マーカー（展開しない）。
    Marker(Marker),
    /// AUFS メタデータの予約名（`.wh..wh.` で始まり `.wh..wh..opq` 以外）。何も書かず何も消さない（#2183）。
    Skip,
    /// ディレクトリ（名前が `/` で終わる通常ファイルを含む）。
    Dir(Vec<OsString>, u32),
    /// 通常ファイル。
    File(Vec<OsString>, u32),
    /// symlink。
    Symlink(Vec<OsString>),
    /// hardlink。
    Hardlink(Vec<OsString>),
}

/// `resolve_dir` が解決したディレクトリ（`root` からの物理コンポーネント列と `NameIndex` の ID）。
struct ResolvedDir {
    comps: Vec<OsString>,
    id: u64,
}

/// 遅延するディレクトリ（`root` からの物理コンポーネント列, mode, `chown` 先のホストの (uid, gid)）。
type DeferredDir = (Vec<OsString>, u32, Option<(u32, u32)>);

/// 親ディレクトリの解決・種別ごとの処理を束ねる状態。
struct Extractor<'a> {
    root: &'a Path,
    /// `root` を開いたディレクトリ fd。変更操作はすべてここを起点に行う（`AnchoredRoot`）。
    anchor: AnchoredRoot,
    limits: ExtractLimits,
    entries: u64,
    bytes: u64,
    /// setuid / setgid / sticky を落として展開した通常ファイルのエントリ数。
    stripped_special: u64,
    /// 予約名として読み飛ばしたエントリ数（`ExtractedLayer::ignored_reserved_entries` の元）。
    ignored_reserved: u64,
    /// 特殊ビットを tar の値どおりに適用した通常ファイルのエントリ数。
    preserved_special: u64,
    /// `max_entries` と比べる件数。tar crate が返す全エントリ（`XGlobalHeader` を含む）を全レイヤーで累積する
    /// （#2251 P2-3）。公開の `entries`（グローバルヘッダを除く）とは別に持つ。
    metered_entries: u64,
    /// 読み戻しでディスクに残った特殊ビットのビットごとの件数。
    preserved_bits: SpecialBitCounts,
    /// 求めたが残らなかった特殊ビットのビットごとの件数。
    stripped_bits: SpecialBitCounts,
    /// 書いたファイルの特殊ビットの読み戻し（試験だけが差し替える）。
    mode_readback: fn(&fs::File) -> u32,
    /// 特殊ビットのポリシーの評価結果（展開の開始時に 1 回決める）。
    special: SpecialCtx,
    /// 所有者の rwx が欠けるディレクトリの（物理パス, mode）。子の作成を妨げないよう全レイヤーの処理後に適用する。
    /// キーは `NameIndex` の ID。ディレクトリを削除したら、索引から外した ID の項目も必ず取り除く（`drop_ids`）。
    ///
    /// 第 3 要素は `chown` するホストの (uid, gid)（`ChownMapped` のときだけ `Some`）。ディレクトリの `chown` は
    /// 子の作成を妨げないよう全レイヤーの後に深い順で行い、その直後に mode を適用する。
    deferred_dirs: HashMap<u64, DeferredDir>,
    /// `ChownMapped` のときの写像と `chown` 関数（`None` なら `chown` しない）。
    own: Option<OwnerCtx>,
    /// `chown` を実行したノード数。
    chowned: u64,
    /// この展開が作った名前（IO-5）。
    names: NameIndex,
    /// 現在のレイヤーのパス 3 が作った・属性を定義した・経路として通ったノードの ID（OCI-1・OCI-2）。
    ///
    /// これに含まれないノードは下位レイヤー由来で、image-spec の「Changeset over existing files」に従い置き換えて
    /// よい。含まれるノードとの型の衝突は拒否する。`names` から外した ID は取り除くため、件数は
    /// `ExtractLimits::max_tracked_paths` を超えない。パス 3 の前後で空にする。
    layer_nodes: HashSet<u64>,
    lstat: Lstat,
    /// 期限と取り消し（既定は無制限）。
    budget: ExtractBudget<'a>,
}

pub(crate) fn err(code: OciErrorCode, msg: &'static str) -> OciError {
    OciError::new(code, msg)
}

fn escapes() -> OciError {
    err(
        OciErrorCode::PermissionDenied,
        "entry path escapes the extraction root",
    )
}

/// 展開先 FS が別表記を既存の実体へ解決したときのエラー（IO-5。パスは載せない）。
fn spelling_collision() -> OciError {
    err(
        OciErrorCode::AlreadyExists,
        "entry name resolves to an existing entry with a different spelling \
         (case or Unicode normalization) on the destination filesystem",
    )
}

/// tar 解析 / 読み取りの `io::Error` を構造化エラーへ写す。分類不能なものは tar 構文違反として `DataLoss`。
fn map_stream_err(e: std::io::Error) -> OciError {
    if let Some(v) = e.get_ref().and_then(|i| i.downcast_ref::<GuardViolation>()) {
        return err(v.code, v.msg);
    }
    let m = oci_error_from_layer_io(e);
    if m.code() == OciErrorCode::Internal {
        return err(OciErrorCode::DataLoss, "layer tar stream is malformed");
    }
    m
}

/// 拡張ヘッダ（GNU long name / long link・PAX）本体 1 件あたりの上限バイト数。
///
/// `max_total_bytes` は通常ファイル本体のみを制限するため、メタデータには独立した有限の上限を課す（OCI-1）。
/// パスは `MAX_PATH_BYTES` が上限であり、これを超える拡張ヘッダは正当なレイヤーに現れない。
const MAX_META_BYTES: u64 = 1024 * 1024;

/// `TarGuard` が返す検査違反（`io::Error` の内包値。`map_stream_err` が構造化エラーへ戻す）。
#[derive(Debug)]
struct GuardViolation {
    code: OciErrorCode,
    msg: &'static str,
}

impl std::fmt::Display for GuardViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for GuardViolation {}

fn guard_error(code: OciErrorCode, msg: &'static str) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, GuardViolation { code, msg })
}

/// 読み取った総バイト数を数え、`limit` を超えたら `ResourceExhausted` で中断する読み取りアダプタ。
///
/// tar 解析中と終端後の読み捨ての両方を同じ計数で覆い、終端後に巨大データを付加された入力でも
/// 無制限に読み続けないようにする（OCI-1）。ちょうど `limit` バイトまでは許容する。
struct LimitedReader<R> {
    inner: R,
    read: u64,
    limit: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // 超過検出のため、残りより 1 バイト多く読めるようにする。
        let room = self.limit.saturating_sub(self.read).saturating_add(1);
        let cap = usize::try_from(room).unwrap_or(usize::MAX).min(buf.len());
        let Some(dst) = buf.get_mut(..cap) else {
            return Ok(0);
        };
        let n = self.inner.read(dst)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.limit {
            return Err(guard_error(
                OciErrorCode::ResourceExhausted,
                "layer tar stream exceeds the input size limit",
            ));
        }
        Ok(n)
    }
}

/// `tar` クレートが拡張ヘッダ本体をメモリへ確保する前に、宣言サイズを検査する読み取りアダプタ。
///
/// 512 バイトのヘッダブロック境界で自前に追跡し（データはそのまま通す）、次を拒否する。
/// - GNU long name / long link / PAX の宣言サイズが `MAX_META_BYTES` を超えるもの（確保前に中断する）。
/// - GNU sparse（`S`）: 拡張ヘッダブロックで追跡がずれるうえ、展開でも拒否する種別のため。
/// - PAX の `size` 上書き: ヘッダのサイズと食い違い、追跡をすり抜けて拡張ヘッダを隠せるため。
/// - PAX 形式の GNU sparse（`GNU.sparse.*` キー。typeflag は通常ファイルのまま）: `tar` crate（0.4.46）は
///   これらのキーを解釈せず、穴を詰めた保存データをそのまま通常ファイルとして返す。論理サイズへ膨らむことは
///   ないが、内容が元のファイルと食い違ったまま成功してしまうため、他の sparse と同じく拒否する。
struct TarGuard<R> {
    inner: R,
    header: [u8; 512],
    filled: usize,
    /// 現在のエントリの本体（拡張ヘッダなら内容）の残りバイト数。
    payload_left: u64,
    /// 本体の後ろの 512 バイト境界パディングの残りバイト数。
    pad_left: u64,
    /// PAX ヘッダ本体の収集先（`size` 上書きの検出用。`MAX_META_BYTES` 以下）。
    pax: Option<Vec<u8>>,
}

impl<R> TarGuard<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 512],
            filled: 0,
            payload_left: 0,
            pad_left: 0,
            pax: None,
        }
    }

    fn on_header(&mut self) -> std::io::Result<()> {
        let h = tar::Header::from_byte_slice(&self.header);
        let ty = h.entry_type();
        // サイズが読めないヘッダは tar 側が構文違反として拒否する。
        let size = h.size().unwrap_or(0);
        if ty == EntryType::GNUSparse {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "sparse entries are not supported",
            ));
        }
        // 旧 GNU sparse は typeflag が通常のまま、isextended（offset 482）で sparse map ブロックが後続し、
        // 512 バイト境界の追跡がずれる。GNU magic のヘッダで isextended が立つものは拒否する。
        if h.as_gnu().is_some_and(tar::GnuHeader::is_extended) {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "old GNU sparse entries are not supported",
            ));
        }
        let is_pax = matches!(ty, EntryType::XHeader | EntryType::XGlobalHeader);
        let is_meta = is_pax || matches!(ty, EntryType::GNULongName | EntryType::GNULongLink);
        if is_meta && size > MAX_META_BYTES {
            return Err(guard_error(
                OciErrorCode::ResourceExhausted,
                "extended header exceeds the metadata size limit",
            ));
        }
        self.payload_left = size;
        self.pad_left = size.div_ceil(512).saturating_mul(512) - size;
        self.pax = is_pax.then(Vec::new);
        self.filled = 0;
        Ok(())
    }

    fn after_payload(&mut self) -> std::io::Result<()> {
        if let Some(p) = self.pax.take() {
            pax_reject_unsupported_records(&p)?;
        }
        Ok(())
    }
}

/// PAX 拡張ヘッダ本体を `tar` crate と同じ規則（先に改行で分割し、各行を `<len> <key>=<value>`
/// として解釈。`len` は行 + 改行の長さと一致）で解析し、キーが正確に `size` の行、またはキーが
/// `GNU.sparse.` で始まる行（PAX 形式の GNU sparse 0.0 / 0.1 / 1.0）があれば拒否する（OCI-1）。
/// 長さ欄が後続行にまたがるレコードは `tar` crate も別行として解釈するため、同じ分割で検査して
/// 埋め込み `size` の見逃しを防ぐ。`path` 等の値に ` size=` が含まれるだけの正常な tar は通す。
/// 構文違反（長さ不一致・`=` 欠落・末尾改行欠落・途中の空行）は拒否する。
fn pax_reject_unsupported_records(body: &[u8]) -> std::io::Result<()> {
    let malformed = || {
        guard_error(
            OciErrorCode::InvalidArgument,
            "malformed pax extended header record",
        )
    };
    let mut lines = body.split(|b| *b == b'\n');
    // 本体は改行で終わる必要がある。最後の要素は空でなければ末尾改行欠落。
    let last = lines.next_back();
    if !matches!(last, Some([])) && !body.is_empty() {
        return Err(malformed());
    }
    for line in lines {
        let sp = line.iter().position(|b| *b == b' ').ok_or_else(malformed)?;
        let len: usize = std::str::from_utf8(line.get(..sp).ok_or_else(malformed)?)
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or_else(malformed)?;
        if line.len().checked_add(1) != Some(len) {
            return Err(malformed());
        }
        let kv = line.get(sp.saturating_add(1)..).ok_or_else(malformed)?;
        let eq = kv.iter().position(|b| *b == b'=').ok_or_else(malformed)?;
        let key = kv.get(..eq).ok_or_else(malformed)?;
        if key == b"size" {
            return Err(guard_error(
                OciErrorCode::InvalidArgument,
                "pax size override is not supported",
            ));
        }
        if key.starts_with(b"GNU.sparse.") {
            return Err(guard_error(
                OciErrorCode::DataLoss,
                "sparse entries are not supported",
            ));
        }
    }
    Ok(())
}

/// 添字の境界違反を構造化エラーで返す（外部入力経路では添字アクセスを使わない）。
fn oob() -> std::io::Error {
    guard_error(OciErrorCode::Internal, "tar guard buffer bounds violated")
}

impl<R: Read> Read for TarGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.payload_left > 0 {
            let n = usize::try_from(self.payload_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
            if let (Some(p), Some(got)) = (self.pax.as_mut(), buf.get(..r)) {
                p.extend_from_slice(got);
            }
            self.payload_left -= r as u64;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
            return Ok(r);
        }
        if self.pad_left > 0 {
            let n = usize::try_from(self.pad_left).map_or(buf.len(), |l| l.min(buf.len()));
            let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
            self.pad_left -= r as u64;
            return Ok(r);
        }
        let n = (512 - self.filled).min(buf.len());
        let r = self.inner.read(buf.get_mut(..n).ok_or_else(oob)?)?;
        let end = self.filled.checked_add(r).ok_or_else(oob)?;
        let dst = self.header.get_mut(self.filled..end).ok_or_else(oob)?;
        dst.copy_from_slice(buf.get(..r).ok_or_else(oob)?);
        self.filled = end;
        if self.filled == 512 {
            self.on_header()?;
            if self.payload_left == 0 {
                self.after_payload()?;
            }
        }
        Ok(r)
    }
}
/// ファイルシステム操作の `io::Error` を写す（パス・OS メッセージは載せない）。
pub(crate) fn map_fs_err(e: &std::io::Error) -> OciError {
    match e.kind() {
        ErrorKind::PermissionDenied => err(
            OciErrorCode::PermissionDenied,
            "failed to write the extraction target",
        ),
        ErrorKind::NotFound => err(OciErrorCode::NotFound, "extraction path not found"),
        _ => err(
            OciErrorCode::Internal,
            "failed to write the extraction target",
        ),
    }
}

#[cfg(unix)]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(OsString::from_vec(b.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_os(b: &[u8]) -> Result<OsString, OciError> {
    let s = std::str::from_utf8(b).map_err(|_| {
        err(
            OciErrorCode::InvalidArgument,
            "entry path is not valid UTF-8",
        )
    })?;
    if s.contains(['\\', ':']) {
        return Err(escapes());
    }
    Ok(OsString::from(s))
}

/// Windows の予約デバイス名（拡張子付きの形を含む。大文字小文字を区別しない）か。
fn is_windows_reserved_name(c: &[u8]) -> bool {
    let stem = c.split(|b| *b == b'.').next().unwrap_or(c);
    let stem = stem.trim_ascii_end();
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || matches!(upper.as_slice(), [b'C', b'O', b'M', b'1'..=b'9'])
        || matches!(upper.as_slice(), [b'L', b'P', b'T', b'1'..=b'9'])
}

/// コンポーネントが Win32 の名前正規化で展開 root を脱出または別物になりうるかを判定する。
///
/// 末尾の `.` と空白を除いた結果が `.` / `..` になるもの（`".. "`・`"..."` 等）は全 OS で拒否する。
/// `windows_names` が真（Windows ホスト）では、末尾が `.` / 空白のもの（Win32 が除去して別名になる）と
/// 予約デバイス名（`CON`・`NUL`・`COM1`〜`COM9`・`LPT1`〜`LPT9` 等）も拒否する（OCI-1）。
fn component_is_unsafe(c: &[u8], windows_names: bool) -> bool {
    let trimmed = c.trim_ascii_end();
    let trimmed = trimmed
        .iter()
        .rposition(|b| *b != b'.')
        .map_or(&[][..], |i| trimmed.get(..=i).unwrap_or(&[]));
    let stripped_is_dots = trimmed.is_empty() && c.first() == Some(&b'.');
    let trailing = matches!(c.last(), Some(b'.' | b' '));
    stripped_is_dots && c != b"." || windows_names && (trailing || is_windows_reserved_name(c))
}

/// アーカイブ内のパスを、`.` を除いたコンポーネント列へ正規化する（`..`・絶対パス・NUL・過大な長さを拒否）。
fn normalize_entry_path(raw: &[u8]) -> Result<Vec<OsString>, OciError> {
    normalize_entry_path_for(raw, cfg!(windows))
}

/// `normalize_entry_path` の本体。`windows_names` でホスト依存の名前規則を切り替える（テストで両方を検証する）。
fn normalize_entry_path_for(raw: &[u8], windows_names: bool) -> Result<Vec<OsString>, OciError> {
    if raw.is_empty() {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
    }
    if raw.len() > MAX_PATH_BYTES || raw.contains(&0) {
        return Err(err(OciErrorCode::InvalidArgument, "entry path is invalid"));
    }
    if raw.first() == Some(&b'/') {
        return Err(escapes());
    }
    let mut out = Vec::new();
    for c in raw.split(|b| *b == b'/') {
        if c.is_empty() || c == b"." {
            continue;
        }
        if c == b".." || component_is_unsafe(c, windows_names) {
            return Err(escapes());
        }
        if c.len() > MAX_COMPONENT_BYTES || out.len() >= MAX_COMPONENTS {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "entry path is too long or too deep",
            ));
        }
        out.push(bytes_to_os(c)?);
    }
    Ok(out)
}

/// tar に親ディレクトリのエントリが無い場合に暗黙作成するディレクトリの既定 mode。
const IMPLICIT_DIR_MODE: u32 = 0o755;

/// ルートと解決済みコンポーネントから物理パスを作る。
fn join_resolved(root: &Path, resolved: &[OsString], name: &OsString) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(resolved);
    p.push(name);
    p
}

/// 最終コンポーネントを取り出す。コンポーネントが空（ルート自身）なら `None`。
fn split_last(mut comps: Vec<OsString>) -> Option<(Vec<OsString>, OsString)> {
    let last = comps.pop()?;
    Some((comps, last))
}

#[cfg(unix)]
fn mode_perms(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    fs::Permissions::from_mode(mode & 0o7777)
}

#[cfg(unix)]
fn apply_file_mode(f: &fs::File, mode: u32) -> Result<(), OciError> {
    f.set_permissions(mode_perms(mode))
        .map_err(|e| map_fs_err(&e))
}

#[cfg(not(unix))]
// 非 unix ホストと unix ホストで関数シグネチャ（Result）をそろえ、呼び出し側を cfg 分岐させないため。
#[allow(clippy::unnecessary_wraps)]
fn apply_file_mode(_f: &fs::File, _mode: u32) -> Result<(), OciError> {
    Ok(())
}

/// `comps`（`root` からの物理コンポーネント列）のディレクトリの mode を `root` の fd 起点で適用する。
fn apply_dir_mode(anchor: &AnchoredRoot, comps: &[OsString], mode: u32) -> Result<(), OciError> {
    anchor.set_dir_mode(comps, mode).map_err(|e| map_at_err(&e))
}

/// 親のコンポーネント列と最終コンポーネントを連結する。
fn full_comps(parent: &[OsString], name: &OsStr) -> Vec<OsString> {
    let mut v = parent.to_vec();
    v.push(name.to_os_string());
    v
}

/// 通常ファイルへ適用する mode のマスク（下位 9 ビット）。
///
/// setuid / setgid / sticky は適用しない。展開物は実行ユーザー所有になるため、非信頼のレイヤーが指定した
/// setuid / setgid を残すと、ホスト上で実行ユーザー（root なら root）の権限で動く実行ファイルを作れてしまう
/// （SEC-5 の所有者写像が入るまでの措置）。
const FILE_MODE_MASK: u32 = 0o777;

/// 通常ファイルの setuid / setgid / sticky を合わせたビット。
const SPECIAL_BITS: u32 = 0o7000;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_ISVTX: u32 = 0o1000;

/// ファイルの所有者 `(uid, gid)` を取り出す関数（テストだけが差し替える）。
type OwnerOf = fn(&fs::Metadata) -> (u32, u32);

#[cfg(unix)]
fn host_owner(m: &fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt as _;
    (m.uid(), m.gid())
}

/// 非 unix では所有者の概念が無く、`SpecialBitsDecision::UnsupportedHost` で呼ばれない。
#[cfg(not(unix))]
fn host_owner(_m: &fs::Metadata) -> (u32, u32) {
    (0, 0)
}

/// `chown` と所有者の読み戻しを行う関数の組（テストだけが差し替える。`OwnerOf` と同じ形の差し替え口）。
///
/// 本番は `std::os::unix::fs::{fchown, lchown}` と fd の metadata。ファイルは開いた fd に対する `fchown`、
/// symlink とディレクトリは追従しない `lchown` を使い、新しいパス解決の経路は作らない（SEC-5）。
#[derive(Clone, Copy)]
struct ChownFns {
    fchown: fn(&File, u32, u32) -> std::io::Result<()>,
    lchown: fn(&AnchoredRoot, &[OsString], u32, u32) -> std::io::Result<()>,
    readback: fn(&File) -> std::io::Result<(u32, u32)>,
}

#[cfg(unix)]
impl ChownFns {
    fn host() -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            fchown: |f, u, g| std::os::unix::fs::fchown(f, Some(u), Some(g)),
            lchown: |a, c, u, g| a.lchown(c, u, g),
            readback: |f| f.metadata().map(|m| (m.uid(), m.gid())),
        }
    }
}

/// 非 unix では所有者の概念が無い。`ChownMapped` は開始前に `Unimplemented` で拒否されるため呼ばれない。
#[cfg(not(unix))]
impl ChownFns {
    fn host() -> Self {
        fn unsupported<T>() -> std::io::Result<T> {
            Err(std::io::Error::from(ErrorKind::Unsupported))
        }
        Self {
            fchown: |_, _, _| unsupported(),
            lchown: |_, _, _, _| unsupported(),
            readback: |_| unsupported(),
        }
    }
}

/// `chown` の失敗を構造化エラーにする。権限不足（`EPERM`）は `PermissionDenied`（fail-closed）。
/// パスや ID の生の値はメッセージに載せない。
fn chown_err(e: &std::io::Error) -> OciError {
    // namespace の中で写像に無い ID へ `chown` すると `EINVAL`（`InvalidInput`）になる。権限の失敗として扱う。
    let code = if matches!(
        e.kind(),
        ErrorKind::PermissionDenied | ErrorKind::InvalidInput
    ) {
        OciErrorCode::PermissionDenied
    } else {
        OciErrorCode::Internal
    };
    err(code, "failed to change the owner of an extracted entry")
}

/// tar の（解析済みの）uid / gid を写像でホストの ID へ写す。解析できない値は `InvalidArgument`、
/// 写像に無い値は `PermissionDenied`（SEC-5）。パス 1（書き込み前の検証）とパス 3 が同じ関数を使う。
fn map_tar_owner(
    ids: (Option<u32>, Option<u32>),
    uid: &IdMap,
    gid: &IdMap,
) -> Result<(u32, u32), OciError> {
    let (Some(u), Some(g)) = ids else {
        return Err(err(
            OciErrorCode::InvalidArgument,
            "layer entry owner is malformed",
        ));
    };
    match (uid.map_to_host(u), gid.map_to_host(g)) {
        (Some(hu), Some(hg)) => Ok((hu, hg)),
        _ => Err(err(
            OciErrorCode::PermissionDenied,
            "layer entry owner is outside the id mapping",
        )),
    }
}

/// `ChownMapped` の実行時の文脈（写像と `chown` 関数）。`Extractor::own` に持つ。
struct OwnerCtx {
    uid: IdMap,
    gid: IdMap,
    fns: ChownFns,
    /// `ChownInUserNamespace`（宛先は tar の ID そのまま）か。
    in_userns: bool,
}

impl OwnerCtx {
    /// tar の ID を検証し、`chown` の宛先の ID を返す。`ChownMapped` は写像先のホスト ID、
    /// `ChownInUserNamespace` は tar の ID そのまま（検証だけに写像を使う）。
    fn resolve(&self, ids: (Option<u32>, Option<u32>)) -> Result<(u32, u32), OciError> {
        let mapped = map_tar_owner(ids, &self.uid, &self.gid)?;
        if self.in_userns {
            // 検証済みのため両方 `Some`。
            if let (Some(u), Some(g)) = ids {
                return Ok((u, g));
            }
        }
        Ok(mapped)
    }
}

/// 展開プロセスの user namespace の見え方（`/proc/self`）。`ChownInUserNamespace` の開始前の検証に使う。
#[derive(Debug, Clone, PartialEq, Eq)]
struct UserNsView {
    uid_map: Vec<IdRange>,
    gid_map: Vec<IdRange>,
    /// effective / fs の uid・gid（namespace の中の ID）。
    euid: u32,
    fsuid: u32,
    egid: u32,
    fsgid: u32,
}

/// `/proc/self` 由来の読み取りの上限（バイト）。カーネルの写像は最大 340 行で十分小さい。
#[cfg(target_os = "linux")]
const MAX_PROC_SELF_BYTES: u64 = 16 * 1024;

#[cfg(target_os = "linux")]
fn read_proc_self(name: &str) -> Result<Vec<u8>, OciError> {
    let bad = |_: std::io::Error| {
        err(
            OciErrorCode::FailedPrecondition,
            "cannot read /proc/self to verify the user namespace",
        )
    };
    let f = File::open(Path::new("/proc/self").join(name)).map_err(bad)?;
    let mut buf = Vec::new();
    f.take(MAX_PROC_SELF_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(bad)?;
    if buf.len() as u64 > MAX_PROC_SELF_BYTES {
        return Err(err(
            OciErrorCode::FailedPrecondition,
            "/proc/self file is too large",
        ));
    }
    Ok(buf)
}

/// `/proc/self/status` の `Uid:` / `Gid:` 行から (effective, fs) を取る。
#[cfg(target_os = "linux")]
fn parse_status_ids(status: &str, key: &str) -> Option<(u32, u32)> {
    let line = status.lines().find_map(|l| l.strip_prefix(key))?;
    let mut it = line.split_whitespace().map(|f| f.parse::<u32>().ok());
    let (_real, eff, _saved, fs, rest) = (
        it.next()??,
        it.next()??,
        it.next()??,
        it.next()??,
        it.next(),
    );
    rest.is_none().then_some((eff, fs))
}

/// 既定の `UserNsView` の取得（`/proc/self` を上限つきで読む）。非 Linux は呼ばれない。
fn host_user_ns_view() -> Result<UserNsView, OciError> {
    #[cfg(target_os = "linux")]
    {
        let bad = || {
            err(
                OciErrorCode::FailedPrecondition,
                "malformed /proc/self/status id line",
            )
        };
        let uid_map = super::idmap::parse_proc_id_map(&read_proc_self("uid_map")?)?;
        let gid_map = super::idmap::parse_proc_id_map(&read_proc_self("gid_map")?)?;
        let status = String::from_utf8(read_proc_self("status")?).map_err(|_| bad())?;
        let (euid, fsuid) = parse_status_ids(&status, "Uid:").ok_or_else(bad)?;
        let (egid, fsgid) = parse_status_ids(&status, "Gid:").ok_or_else(bad)?;
        Ok(UserNsView {
            uid_map,
            gid_map,
            euid,
            fsuid,
            egid,
            fsgid,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(err(
            OciErrorCode::Unimplemented,
            "user namespace inspection is only supported on linux",
        ))
    }
}

/// 初期 user namespace の恒等写像（`0 0 4294967295` の 1 行）か。
fn is_initial_userns_map(m: &[IdRange]) -> bool {
    matches!(m, [r] if r.container_id == 0 && r.host_id == 0 && r.count == u32::MAX)
}

/// `ChownInUserNamespace` の開始前の検証（純関数。#2382・SEC-5）。
///
/// 初期 user namespace・渡された写像との不一致・namespace の中で euid / fsuid / egid / fsgid が 0 でない、の
/// いずれかなら `FailedPrecondition`。`user_namespaces(7)` のとおり、読む側と対象が同じ namespace にいるとき
/// 写像の 2 列目は親の namespace の ID になるため、ホストから見た `IdMap` と直接比べられる。
/// 写像はカーネルが 1 回しか書かせないため、検証から使用までの間に書き換えられない。
fn check_user_namespace(view: &UserNsView, uid: &IdMap, gid: &IdMap) -> Result<(), OciError> {
    let fail = |msg: &'static str| Err(err(OciErrorCode::FailedPrecondition, msg));
    if is_initial_userns_map(&view.uid_map) || is_initial_userns_map(&view.gid_map) {
        return fail("the extracting process is not inside a user namespace");
    }
    if !uid.same_lines_as(&view.uid_map) || !gid.same_lines_as(&view.gid_map) {
        return fail("the user namespace id mapping differs from the requested mapping");
    }
    if view.euid != 0 || view.fsuid != 0 || view.egid != 0 || view.fsgid != 0 {
        return fail("the extracting process is not root inside the user namespace");
    }
    Ok(())
}

/// 特殊ビット・所有者の扱いの入力。`extract_stack` の入口で受け取る。
#[derive(Clone)]
struct SpecialSetup {
    policy: SpecialBitsPolicy,
    owner_of: OwnerOf,
    /// 書いたファイルの特殊ビットの読み戻し（試験だけが差し替える。既定は `special_bits_of`）。
    mode_readback: fn(&fs::File) -> u32,
    ownership: OwnershipPolicy,
    chown: ChownFns,
    /// `ChownInUserNamespace` の開始前検証が読む `/proc/self` の見え方（試験だけが差し替える）。
    ns_probe: fn() -> Result<UserNsView, OciError>,
    /// `root` の fd 起点の操作の差し替え口（試験だけが差し替える。`AnchoredRoot` を参照）。
    anchor: AnchorHooks,
}

impl SpecialSetup {
    fn host(policy: SpecialBitsPolicy) -> Self {
        Self {
            policy,
            owner_of: host_owner,
            mode_readback: special_bits_of,
            ownership: OwnershipPolicy::Keep,
            chown: ChownFns::host(),
            ns_probe: host_user_ns_view,
            anchor: AnchorHooks::host(),
        }
    }

    fn from_options(options: &ExtractOptions) -> Self {
        Self {
            ownership: options.ownership.clone(),
            ..Self::host(options.special_bits)
        }
    }

    /// 選択肢の組み合わせとホストを検査し、`ChownMapped` / `ChownInUserNamespace` なら実行時の文脈を作る。`root` に触れる前に呼ぶ。
    fn owner_ctx(&self) -> Result<Option<OwnerCtx>, OciError> {
        match (&self.ownership, self.policy) {
            (OwnershipPolicy::Keep, SpecialBitsPolicy::PreserveIfChowned) => Err(err(
                OciErrorCode::InvalidArgument,
                "the special bits policy requires an ownership mapping",
            )),
            (OwnershipPolicy::Keep, _) => Ok(None),
            (OwnershipPolicy::ChownMapped { .. }, _) if !cfg!(target_os = "linux") => Err(err(
                OciErrorCode::Unimplemented,
                "applying layer ownership is only supported on linux",
            )),
            (OwnershipPolicy::ChownMapped { uid, gid }, _) => Ok(Some(OwnerCtx {
                uid: uid.clone(),
                gid: gid.clone(),
                fns: self.chown,
                in_userns: false,
            })),
            (OwnershipPolicy::ChownInUserNamespace { .. }, _) if !cfg!(target_os = "linux") => {
                Err(err(
                    OciErrorCode::Unimplemented,
                    "applying layer ownership is only supported on linux",
                ))
            }
            (OwnershipPolicy::ChownInUserNamespace { uid, gid }, _) => {
                check_user_namespace(&(self.ns_probe)()?, uid, gid)?;
                Ok(Some(OwnerCtx {
                    uid: uid.clone(),
                    gid: gid.clone(),
                    fns: self.chown,
                    in_userns: true,
                }))
            }
        }
    }
}

/// 展開の開始時に評価した、特殊ビットの扱いの文脈（`Extractor::write_file` が参照する）。
#[derive(Clone, Copy)]
struct SpecialCtx {
    decision: SpecialBitsDecision,
    /// `Evaluated` のときだけ `Some`（uid の写像, gid の写像）。
    ranges: Option<(IdRange, IdRange)>,
    /// `root` の所有 uid（`Evaluated` のときだけ意味を持つ）。
    root_uid: u32,
    owner_of: OwnerOf,
    /// `PreserveIfChowned`（`chown` 後の所有者で判定する経路）か。
    chowned_mode: bool,
    /// `ChownInUserNamespace`（所有者の条件が `special_bits_to_keep_chowned` で変わる）か。
    in_userns: bool,
}

impl SpecialCtx {
    fn strip() -> Self {
        Self {
            decision: SpecialBitsDecision::StripPolicy,
            ranges: None,
            root_uid: 0,
            owner_of: host_owner,
            chowned_mode: false,
            in_userns: false,
        }
    }
}

/// ポリシー全体の条件（ポリシー・ホスト OS・`root` の権限）を評価する。`check_root_empty` の後に 1 回だけ呼ぶ。
fn eval_special_ctx(setup: &SpecialSetup, anchor: &AnchoredRoot) -> Result<SpecialCtx, OciError> {
    let mut ctx = SpecialCtx::strip();
    ctx.owner_of = setup.owner_of;
    let (mapped, chowned) = match setup.policy {
        SpecialBitsPolicy::Strip => return Ok(ctx),
        SpecialBitsPolicy::PreserveIfOwnerMapped { uid, gid } => (Some((uid, gid)), false),
        SpecialBitsPolicy::PreserveIfChowned => (None, true),
    };
    ctx.decision = SpecialBitsDecision::UnsupportedHost;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // 0700 なら祖先の権限に依らず、ほかのユーザーは root より下へ入れない。
        ctx.decision = SpecialBitsDecision::RootAccessibleByOthers;
        let m = anchor.root_meta().map_err(|e| map_fs_err(&e))?;
        if m.is_dir() && m.permissions().mode() & 0o077 == 0 {
            ctx.decision = SpecialBitsDecision::Evaluated;
            ctx.ranges = mapped;
            ctx.chowned_mode = chowned;
            ctx.in_userns = matches!(
                setup.ownership,
                OwnershipPolicy::ChownInUserNamespace { .. }
            );
            ctx.root_uid = (setup.owner_of)(&m).0;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (mapped, chowned, anchor);
    }
    Ok(ctx)
}

/// 残してよい特殊ビットを返す（ファイル単位の条件。モジュール冒頭を参照）。副作用なし。
///
/// `owner` は書いたファイルの実際の所有者。tar の id が `None`（解析不能）のとき setuid / setgid は残さない。
fn special_bits_to_keep(
    requested: u32,
    tar_ids: (Option<u32>, Option<u32>),
    owner: (u32, u32),
    ctx: &SpecialCtx,
) -> u32 {
    let Some((uid_map, gid_map)) = ctx.ranges else {
        return 0;
    };
    if ctx.decision != SpecialBitsDecision::Evaluated || ctx.root_uid != owner.0 {
        return 0;
    }
    let mut keep = requested & S_ISVTX;
    if requested & S_ISUID != 0
        && owner.0 != 0
        && tar_ids.0.and_then(|u| uid_map.map_to_host(u)) == Some(owner.0)
    {
        keep |= S_ISUID;
    }
    // rootful（所有 uid 0）は setuid / setgid を常に落とす。gid が 0 でなくても落とす（SEC-5・#2251 P2-1）。
    if requested & S_ISGID != 0
        && owner.0 != 0
        && owner.1 != 0
        && tar_ids.1.and_then(|g| gid_map.map_to_host(g)) == Some(owner.1)
    {
        keep |= S_ISGID;
    }
    keep
}

/// `PreserveIfChowned` で残してよい特殊ビットを返す（ファイル単位の条件。副作用なし。#2225）。
///
/// `owner` は `chown` の後に読み戻した実際の所有者。共通条件「`root` の所有 uid と一致」は使わない
/// （`chown` 後の所有者は写像先のため）。setuid / setgid は所有者が 0 でなく、tar の ID を写像した ID と
/// 一致するときだけ残す。sticky はポリシー全体の条件（`Evaluated`）だけで残す。
fn special_bits_to_keep_chowned(
    requested: u32,
    tar_ids: (Option<u32>, Option<u32>),
    owner: (u32, u32),
    maps: (&IdMap, &IdMap),
    ctx: &SpecialCtx,
) -> u32 {
    if ctx.decision != SpecialBitsDecision::Evaluated || !ctx.chowned_mode {
        return 0;
    }
    let mut keep = requested & S_ISVTX;
    if ctx.in_userns {
        // namespace の中では所有者は tar の ID と一致し（恒等）、その ID が写像に含まれるときだけ残す。
        // コンテナ root（ns 内 uid 0）の所有も残してよい: ホストでは起動ユーザー / subuid にしか効かず、
        // `root` が 0700 のため他のホストユーザーは辿れない（#2382・SEC-5）。
        if requested & S_ISUID != 0
            && tar_ids.0 == Some(owner.0)
            && maps.0.map_to_host(owner.0).is_some()
        {
            keep |= S_ISUID;
        }
        if requested & S_ISGID != 0
            && tar_ids.1 == Some(owner.1)
            && maps.1.map_to_host(owner.1).is_some()
        {
            keep |= S_ISGID;
        }
        return keep;
    }
    if requested & S_ISUID != 0
        && owner.0 != 0
        && tar_ids.0.and_then(|u| maps.0.map_to_host(u)) == Some(owner.0)
    {
        keep |= S_ISUID;
    }
    if requested & S_ISGID != 0
        && owner.1 != 0
        && tar_ids.1.and_then(|g| maps.1.map_to_host(g)) == Some(owner.1)
    {
        keep |= S_ISGID;
    }
    keep
}

/// レイヤー内のグローバル PAX ヘッダ（`XGlobalHeader`）が指定した所有者。外側の `None` は「未指定」、
/// 内側の `None` は「指定はあるが解析不能〔非信頼入力〕」を表す（SEC-5。後者は setuid / setgid を残さない）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GlobalOwner {
    uid: Option<Option<u32>>,
    gid: Option<Option<u32>>,
}

/// グローバル PAX レコードの本体を読む上限（非信頼入力の無制限確保を防ぐ）。
const MAX_GLOBAL_PAX_BYTES: u64 = 1 << 20;

impl GlobalOwner {
    /// `XGlobalHeader` エントリの本体から `uid` / `gid` を取り込む。後のヘッダが前を上書きする（PAX の規則）。
    fn absorb<R: Read>(&mut self, entry: &mut tar::Entry<'_, R>) -> Result<(), OciError> {
        let mut data = Vec::new();
        entry
            .by_ref()
            .take(MAX_GLOBAL_PAX_BYTES)
            .read_to_end(&mut data)
            .map_err(map_stream_err)?;
        for ext in tar::PaxExtensions::new(&data).flatten() {
            // 空値は PAX の「指定の解除」。不正な数値（解析不能）とは区別する。
            let raw = ext.value().ok();
            let parsed = raw.and_then(|v| v.parse::<u32>().ok());
            let unset = raw == Some("");
            match ext.key() {
                Ok("uid") => self.uid = if unset { None } else { Some(parsed) },
                Ok("gid") => self.gid = if unset { None } else { Some(parsed) },
                _ => {}
            }
        }
        Ok(())
    }
}

/// tar エントリの uid / gid。優先順位はエントリ固有の PAX、グローバル PAX、通常ヘッダの順。
/// 解析できない・u32 に収まらない値は `None`（非信頼入力）。
fn tar_owner<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    global: &GlobalOwner,
) -> (Option<u32>, Option<u32>) {
    let mut uid = entry
        .header()
        .uid()
        .ok()
        .and_then(|v| u32::try_from(v).ok());
    let mut gid = entry
        .header()
        .gid()
        .ok()
        .and_then(|v| u32::try_from(v).ok());
    let (header_uid, header_gid) = (uid, gid);
    if let Some(g) = global.uid {
        uid = g;
    }
    if let Some(g) = global.gid {
        gid = g;
    }
    if let Ok(Some(exts)) = entry.pax_extensions() {
        for ext in exts.flatten() {
            // 空値は指定の解除（通常ヘッダの所有者へ戻す）。不正な数値は解析不能として `None`。
            let raw = ext.value().ok();
            let parsed = raw.and_then(|v| v.parse::<u32>().ok());
            let unset = raw == Some("");
            match ext.key() {
                Ok("uid") => uid = if unset { header_uid } else { parsed },
                Ok("gid") => gid = if unset { header_gid } else { parsed },
                _ => {}
            }
        }
    }
    (uid, gid)
}

/// 書き込み済みファイルの mode の特殊ビットを読み戻す（失敗は 0。偽って「残った」と報告しない）。
#[cfg(unix)]
fn special_bits_of(f: &fs::File) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    f.metadata()
        .map_or(0, |m| m.permissions().mode() & SPECIAL_BITS)
}

#[cfg(not(unix))]
fn special_bits_of(_f: &fs::File) -> u32 {
    0
}
/// 所有者の rwx がそろわない mode か（子の作成を妨げうるため適用を遅延する）。
fn needs_deferral(mode: u32) -> bool {
    mode & 0o700 != 0o700
}

impl Extractor<'_> {
    /// `dir`（ID は `dir_id`）直下の `name`（物理パスは `path`）を `lstat` する。無ければ `None`、
    /// あればメタデータと `NameIndex` の ID を返す。
    ///
    /// 実在するのにこの展開がその綴りで作っていない名前は、展開先 FS が別表記（大文字小文字・Unicode
    /// 正規化など）を既存の実体へ解決したものである（`root` は空で始まる）。削除・権限変更・リンク作成より
    /// 前にここで `AlreadyExists` として拒否する（IO-5）。実在する名前を見る箇所はすべてここを通す。
    fn probe(
        &self,
        dir_id: u64,
        name: &OsStr,
        path: &Path,
    ) -> Result<Option<(fs::Metadata, u64)>, OciError> {
        match (self.lstat)(path) {
            Ok(m) => match self.names.get(dir_id, name) {
                Some(id) => Ok(Some((m, id))),
                None => Err(spelling_collision()),
            },
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(map_fs_err(&e)),
        }
    }

    /// `names` から外した ID に紐づく遅延ディレクトリ mode と `layer_nodes` の項目を取り除く。
    fn drop_ids(&mut self, ids: Vec<u64>) {
        for id in ids {
            self.deferred_dirs.remove(&id);
            self.layer_nodes.remove(&id);
        }
    }

    /// `parent`（ID。物理コンポーネント列は `parent_comps`）直下の `name` を木ごと消し、配下の登録・遅延 mode を外す。
    ///
    /// whiteout の適用（パス 2）と、下位レイヤー由来のノードの置換（パス 3。Changeset over existing files）が使う。
    /// 削除は `root` の fd 起点で、symlink を追従しない。存在しなければ何もしない。
    fn remove_tree(
        &mut self,
        parent: u64,
        parent_comps: &[OsString],
        name: &OsStr,
    ) -> Result<(), OciError> {
        self.anchor.remove_tree(parent_comps, name)?;
        let ids = self.names.forget_tree(parent, name);
        self.drop_ids(ids);
        Ok(())
    }

    /// `rel` の各コンポーネントを 1 つずつ `probe`（`lstat`）で確認しながら、ルート内の物理位置を解決する。
    ///
    /// symlink は読み取ってルート基準で辿る（絶対ターゲットはルートへ戻し、`..` はルートで止める）ため、
    /// ホストの任意パスへは出られない。通ったディレクトリは `layer_nodes` に載せる（パス 3 で、このレイヤーが
    /// 経路として使ったノードを後のエントリが置き換えないため）。`create` が真なら存在しないディレクトリを作り、
    /// 下位レイヤー由来の非ディレクトリ（symlink を除く）はディレクトリへ置き換える（Changeset over existing
    /// files。OCI-1）。このレイヤーが作った非ディレクトリと、`create` が偽のときの非ディレクトリは
    /// `FailedPrecondition`。戻り値はルートからの物理コンポーネント列と、そのディレクトリの `NameIndex` の ID。
    fn resolve_dir(&mut self, rel: &[OsString], create: bool) -> Result<ResolvedDir, OciError> {
        let mut resolved: Vec<OsString> = Vec::new();
        // `resolved` の各コンポーネントの ID（同じ長さを保つ）。
        let mut ids: Vec<u64> = Vec::new();
        let mut queue: VecDeque<OsString> = rel.iter().cloned().collect();
        let mut follows = 0u32;
        while let Some(c) = queue.pop_front() {
            if c == "." {
                continue;
            }
            if c == ".." {
                resolved.pop();
                ids.pop();
                continue;
            }
            let parent_id = ids.last().copied().unwrap_or(ROOT_ID);
            let cand = join_resolved(self.root, &resolved, &c);
            match self.probe(parent_id, &c, &cand)? {
                Some((m, id)) if m.is_dir() => {
                    self.layer_nodes.insert(id);
                    resolved.push(c);
                    ids.push(id);
                }
                Some((m, _)) if m.file_type().is_symlink() => {
                    follows += 1;
                    if follows > MAX_SYMLINK_FOLLOWS {
                        return Err(err(
                            OciErrorCode::InvalidArgument,
                            "too many symbolic links while resolving an entry path",
                        ));
                    }
                    let target = self
                        .anchor
                        .read_link(&resolved, &c)
                        .map_err(|e| map_at_err(&e))?;
                    let mut pending = Vec::new();
                    for comp in target.components() {
                        match comp {
                            Component::RootDir | Component::Prefix(_) => {
                                resolved.clear();
                                ids.clear();
                                pending.clear();
                            }
                            Component::CurDir => {}
                            Component::ParentDir => pending.push(OsString::from("..")),
                            Component::Normal(n) => pending.push(n.to_os_string()),
                        }
                    }
                    for p in pending.into_iter().rev() {
                        queue.push_front(p);
                    }
                }
                Some((_, id)) if create && !self.layer_nodes.contains(&id) => {
                    // 下位レイヤー由来の非ディレクトリの位置に暗黙の親ディレクトリを作る（`d` の後の上位の `d/y`）。
                    // 非ディレクトリなので配下の登録は無く、ID はそのまま使う。
                    self.anchor
                        .unlink(&resolved, &c)
                        .map_err(|e| map_at_err(&e))?;
                    self.create_implicit_dir(&resolved, &c, id)?;
                    self.layer_nodes.insert(id);
                    resolved.push(c);
                    ids.push(id);
                }
                Some(_) => {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "a parent path component is not a directory",
                    ));
                }
                None => {
                    if !create {
                        return Err(err(OciErrorCode::NotFound, "extraction path not found"));
                    }
                    let id = self.names.insert(parent_id, &c)?;
                    self.create_implicit_dir(&resolved, &c, id)?;
                    self.layer_nodes.insert(id);
                    resolved.push(c);
                    ids.push(id);
                }
            }
        }
        Ok(ResolvedDir {
            id: ids.last().copied().unwrap_or(ROOT_ID),
            comps: resolved,
        })
    }

    /// 暗黙の親ディレクトリを作る。ホストの umask に依存させず既定 0755 にする。
    /// 明示的なディレクトリエントリがあれば `make_dir` がその mode で上書きする（OCI-1）。
    ///
    /// `ChownMapped` のときは tar に所有者が無いため、コンテナ内 0:0 を写したホストの ID を全レイヤーの後に
    /// `chown` する（イメージの慣行の root:root。写像は必ずコンテナ内 0 を含む）。`id` はこのノードの `NameIndex` の ID。
    fn create_implicit_dir(
        &mut self,
        parent: &[OsString],
        name: &OsStr,
        id: u64,
    ) -> Result<(), OciError> {
        self.anchor
            .mkdir(parent, name)
            .map_err(|e| map_at_err(&e))?;
        let full = full_comps(parent, name);
        apply_dir_mode(&self.anchor, &full, IMPLICIT_DIR_MODE)?;
        if let Some(o) = &self.own {
            let owner = o.resolve((Some(0), Some(0)))?;
            self.deferred_dirs
                .insert(id, (full, IMPLICIT_DIR_MODE, Some(owner)));
        }
        Ok(())
    }

    /// 非ディレクトリのエントリを置く位置の既存ノードを除去する。存在しなければ何もしない。
    ///
    /// 既存の非ディレクトリは消す（後勝ち）。既存のディレクトリは、下位レイヤー由来なら木ごと消して置き換え
    /// （Changeset over existing files。OCI-1）、このレイヤーが作った・経路として通ったものなら
    /// `FailedPrecondition`。別表記で既存の実体へ解決される名前は、除去の前に `probe` が拒否する（IO-5）。
    fn clear_for_non_dir(
        &mut self,
        dir_id: u64,
        parent_comps: &[OsString],
        name: &OsStr,
        path: &Path,
    ) -> Result<(), OciError> {
        match self.probe(dir_id, name, path)? {
            Some((m, id)) if m.is_dir() => {
                if self.layer_nodes.contains(&id) {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "a directory already exists at the entry path",
                    ));
                }
                self.remove_tree(dir_id, parent_comps, name)
            }
            Some(_) => self
                .anchor
                .unlink(parent_comps, name)
                .map_err(|e| map_at_err(&e)),
            None => Ok(()),
        }
    }

    /// `owner` は `ChownMapped` のときの `chown` 先（ホストの uid, gid）。`chown` は `finish_dirs` で行う。
    fn make_dir(
        &mut self,
        comps: Vec<OsString>,
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Ok(());
        };
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        // 別表記（`d/` の後の `D/`）は、下の遅延 mode の取り消し・mode の適用より前に `probe` が拒否する（IO-5）。
        let id = match self.probe(dir.id, &name, &path)? {
            // 既存もエントリもディレクトリなら属性だけを置き換える（Changeset over existing files）。
            Some((m, id)) if m.is_dir() => id,
            Some((_, id)) => {
                self.anchor
                    .unlink(&dir.comps, &name)
                    .map_err(|e| map_at_err(&e))?;
                self.anchor
                    .mkdir(&dir.comps, &name)
                    .map_err(|e| map_at_err(&e))?;
                id
            }
            None => {
                let id = self.names.insert(dir.id, &name)?;
                self.anchor
                    .mkdir(&dir.comps, &name)
                    .map_err(|e| map_at_err(&e))?;
                id
            }
        };
        self.layer_nodes.insert(id);
        // 同じディレクトリの再定義は後勝ち。先の遅延 mode を残すと finish_dirs が後の mode を上書きする。
        self.deferred_dirs.remove(&id);
        let full = full_comps(&dir.comps, &name);
        if needs_deferral(mode) {
            // umask 等で所有者の rwx が欠けても子を作れるよう、finish_dirs まで一時的に 0700 にする。
            apply_dir_mode(&self.anchor, &full, 0o700)?;
            self.deferred_dirs.insert(id, (full, mode, owner));
            Ok(())
        } else {
            apply_dir_mode(&self.anchor, &full, mode)?;
            if owner.is_some() {
                self.deferred_dirs.insert(id, (full, mode, owner));
            }
            Ok(())
        }
    }

    fn write_file<R: Read>(
        &mut self,
        comps: Vec<OsString>,
        mode: u32,
        tar_ids: (Option<u32>, Option<u32>),
        host_ids: Option<(u32, u32)>,
        size: u64,
        data: &mut R,
    ) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        // 宣言サイズで累積上限を書き込み前に検査する（巨大宣言サイズによる DoS を防ぐ）。
        let next = self
            .bytes
            .checked_add(size)
            .filter(|n| *n <= self.limits.max_total_bytes)
            .ok_or_else(|| {
                err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the extracted size limit",
                )
            })?;
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        self.clear_for_non_dir(dir.id, &dir.comps, &name, &path)?;
        let id = self.names.insert(dir.id, &name)?;
        self.layer_nodes.insert(id);
        // O_CREAT|O_EXCL|O_NOFOLLOW で、最終コンポーネントの symlink を追従しない。親は `root` の fd 起点で開き直す。
        let mut f = self
            .anchor
            .create_file(&dir.comps, &name)
            .map_err(|e| map_at_err(&e))?;
        let mut buf = vec![0u8; COPY_BUF_LEN];
        let mut written = 0u64;
        while written < size {
            let want = usize::try_from(size - written).map_or(buf.len(), |r| r.min(buf.len()));
            let Some(dst) = buf.get_mut(..want) else {
                break;
            };
            let n = match data.read(dst) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_stream_err(e)),
            };
            if let Some(chunk) = buf.get(..n) {
                f.write_all(chunk).map_err(|e| map_fs_err(&e))?;
            }
            written += n as u64;
        }
        if written != size {
            return Err(err(OciErrorCode::DataLoss, "layer tar stream is malformed"));
        }
        // `chown` は `fchmod` より先に行う（Linux は `chown` で setuid / setgid を落とすため）。所有者は読み戻して
        // 確かめ、成功を偽らない。特殊ビットの判定は読み戻した所有者で行う（SEC-5・#2225）。
        let chowned_owner = match (&self.own, host_ids) {
            (Some(o), Some(ids)) => {
                (o.fns.fchown)(&f, ids.0, ids.1).map_err(|e| chown_err(&e))?;
                let got = (o.fns.readback)(&f).map_err(|e| chown_err(&e))?;
                if got != ids {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "the owner of an extracted file differs from the requested owner",
                    ));
                }
                self.chowned = self.chowned.saturating_add(1);
                Some(got)
            }
            (Some(_), None) => {
                return Err(err(OciErrorCode::Internal, "entry owner is not resolved"));
            }
            (None, _) => None,
        };
        let requested = mode & SPECIAL_BITS;
        // 判定の直前に `root` の所有者と 0700 を fd で確かめ直す。変わっていたら以後は一方向に落とす（SEC-5・#2437）。
        if requested != 0
            && self.special.decision == SpecialBitsDecision::Evaluated
            && !self.root_still_private()
        {
            self.special.decision = SpecialBitsDecision::RootChangedDuringExtraction;
        }
        let keep = if requested != 0 && self.special.decision == SpecialBitsDecision::Evaluated {
            if self.special.chowned_mode {
                match (&self.own, chowned_owner) {
                    (Some(o), Some(owner)) => special_bits_to_keep_chowned(
                        requested,
                        tar_ids,
                        owner,
                        (&o.uid, &o.gid),
                        &self.special,
                    ),
                    _ => 0,
                }
            } else {
                // 所有者は書いたファイル自身の metadata から得る（fsuid・親ディレクトリの setgid による gid 継承を反映）。
                f.metadata().map_or(0, |m| {
                    special_bits_to_keep(
                        requested,
                        tar_ids,
                        (self.special.owner_of)(&m),
                        &self.special,
                    )
                })
            }
        } else {
            0
        };
        apply_file_mode(&f, mode & (FILE_MODE_MASK | keep))?;
        if keep != 0 && !self.root_still_private() {
            // 特殊ビットを付けた直後にも確かめる。変わっていたら付けたビットを外し、以後も落とす。
            self.special.decision = SpecialBitsDecision::RootChangedDuringExtraction;
            apply_file_mode(&f, mode & FILE_MODE_MASK)?;
        }
        if requested != 0 {
            // カーネルが黙って落とした場合（所属しない gid への setgid 等）は適用したことにしない。
            // 一部のビットだけが落ちた場合、残ったビットは preserved_bits、落ちたビットだけを stripped_bits に
            // 数える（ファイル単位では落とした側。#2251 P2-6）。読み戻せなければ 0（残ったと偽らない）。
            let actual = (self.mode_readback)(&f) & requested;
            self.preserved_bits.add_bits(actual);
            self.stripped_bits.add_bits(requested & !actual);
            if actual == requested {
                self.preserved_special = self.preserved_special.saturating_add(1);
            } else {
                self.stripped_special = self.stripped_special.saturating_add(1);
            }
        }
        self.bytes = next;
        Ok(())
    }

    fn make_symlink(
        &mut self,
        comps: Vec<OsString>,
        target: &[u8],
        owner: Option<(u32, u32)>,
    ) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        if target.is_empty() || target.len() > MAX_PATH_BYTES || target.contains(&0) {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "symlink target is invalid",
            ));
        }
        let dir = self.resolve_dir(&parent, true)?;
        // リンク先を配置ディレクトリ基準で字句的に検査し、ルートより上へ出るものを拒否する。
        let mut depth = if target.first() == Some(&b'/') {
            0
        } else {
            dir.comps.len()
        };
        for c in target.split(|b| *b == b'/') {
            if c.is_empty() || c == b"." {
                continue;
            }
            if c == b".." {
                depth = depth.checked_sub(1).ok_or_else(escapes)?;
            } else {
                depth += 1;
            }
        }
        let path = join_resolved(self.root, &dir.comps, &name);
        self.clear_for_non_dir(dir.id, &dir.comps, &name, &path)?;
        let id = self.names.insert(dir.id, &name)?;
        self.layer_nodes.insert(id);
        self.anchor
            .symlink(&dir.comps, &name, &bytes_to_os(target)?)
            .map_err(|e| {
                if e.kind() == ErrorKind::Unsupported {
                    err(
                        OciErrorCode::Unimplemented,
                        "symlink entries are not supported on this host",
                    )
                } else {
                    map_at_err(&e)
                }
            })?;
        if let (Some(o), Some(ids)) = (&self.own, owner) {
            // symlink 自体の所有者を変える（リンク先を追従しない）。mode は扱わない。
            (o.fns.lchown)(&self.anchor, &full_comps(&dir.comps, &name), ids.0, ids.1)
                .map_err(|e| chown_err(&e))?;
            self.chowned = self.chowned.saturating_add(1);
        }
        Ok(())
    }

    fn make_hardlink(&mut self, comps: Vec<OsString>, target: &[u8]) -> Result<(), OciError> {
        let Some((parent, name)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        let Some((tparent, tname)) = split_last(normalize_entry_path(target)?) else {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "hardlink target is empty",
            ));
        };
        // 参照先の親も `layer_nodes` に載る（後のエントリが参照先を含む下位の木を置き換えないため）。
        // 同じレイヤーで whiteout された下位の参照先はパス 2 で消えており、`NotFound` になる（OCI-2）。
        let tdir = self.resolve_dir(&tparent, false)?;
        let tpath = join_resolved(self.root, &tdir.comps, &tname);
        // 参照先も `probe` を通す。別表記で既存の実体へ解決される参照先（`g → F` で実在するのは `f`）は拒否する。
        match self.probe(tdir.id, &tname, &tpath)? {
            Some((m, _)) if m.is_file() => {}
            Some(_) => {
                return Err(err(
                    OciErrorCode::PermissionDenied,
                    "hardlink target is not a regular file",
                ));
            }
            None => return Err(err(OciErrorCode::NotFound, "extraction path not found")),
        }
        let dir = self.resolve_dir(&parent, true)?;
        let path = join_resolved(self.root, &dir.comps, &name);
        // 参照先と同一パス（f → f）なら削除すると参照元を失うため、既存ファイルをそのまま保持する。
        // 綴りだけが違う同じ実体（`F → f`）は、下の `clear_for_non_dir` が削除の前に拒否する（IO-5）。
        if tpath == path {
            return Ok(());
        }
        self.clear_for_non_dir(dir.id, &dir.comps, &name, &path)?;
        let id = self.names.insert(dir.id, &name)?;
        self.layer_nodes.insert(id);
        self.anchor
            .hardlink(&tdir.comps, &tname, &dir.comps, &name)
            .map_err(|e| map_at_err(&e))?;
        // 参照先の確認からリンク作成までの間に、参照先が通常ファイル以外（symlink 等）へ差し替えられていないか
        // 確かめる。違えば作ったリンクを消して拒否する（SEC-5・#2437）。
        match self.anchor.is_regular_file(&dir.comps, &name) {
            Ok(true) => Ok(()),
            Ok(false) => {
                let _ = self.anchor.unlink(&dir.comps, &name);
                Err(path_changed())
            }
            Err(e) => Err(map_at_err(&e)),
        }
    }

    /// マーカーの親 `parent` を下位ツリーで解決する。親が無い・非ディレクトリなら `None`（下位に消す実体が無い）。
    ///
    /// 解決は `resolve_dir`（`create` は偽）でルートに閉じ込める。別表記の親（IO-5）・symlink の追従回数超過・
    /// FS のエラーはそのまま返す。
    fn resolve_marker_parent(
        &mut self,
        parent: &[OsString],
    ) -> Result<Option<ResolvedDir>, OciError> {
        match self.resolve_dir(parent, false) {
            Ok(d) => Ok(Some(d)),
            Err(e)
                if matches!(
                    e.code(),
                    OciErrorCode::NotFound | OciErrorCode::FailedPrecondition
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// パス 2: マーカーを下位ツリー（このレイヤーの展開前の rootfs）へ適用する（OCI-2・TASK-53.1〜53.3）。
    ///
    /// 先に全マーカーの親と whiteout の対象を解決・検査してから削除する。解決が削除の順に左右されないため、
    /// symlink を経由する親（`lnk/.wh.x` と `.wh.lnk`）や別表記の検査（IO-5。削除の前に `AlreadyExists`）の
    /// 結果はマーカーの並びに依らない。後から実行する削除の対象が先の削除で消えていても何もしない
    /// （`whiteout` の削除は冪等）。削除した木の `NameIndex` 登録・遅延ディレクトリ mode は外す。
    /// 不透明ディレクトリ自身の登録と遅延 mode は残す。
    fn apply_markers(&mut self, markers: &[Marker]) -> Result<(), OciError> {
        let mut plan = Vec::new();
        for m in markers {
            self.budget.check()?;
            match m {
                Marker::Whiteout { parent, target } => {
                    let Some(dir) = self.resolve_marker_parent(parent)? else {
                        continue;
                    };
                    let path = join_resolved(self.root, &dir.comps, target);
                    if self.probe(dir.id, target, &path)?.is_some() {
                        plan.push(Removal::Tree {
                            parent_comps: dir.comps,
                            parent: dir.id,
                            name: target.clone(),
                        });
                    }
                }
                Marker::Opaque { parent } => {
                    let Some(dir) = self.resolve_marker_parent(parent)? else {
                        continue;
                    };
                    plan.push(Removal::Contents {
                        comps: dir.comps,
                        id: dir.id,
                    });
                }
            }
        }
        for r in plan {
            self.budget.check()?;
            match r {
                Removal::Tree {
                    parent_comps,
                    parent,
                    name,
                } => self.remove_tree(parent, &parent_comps, &name)?,
                Removal::Contents { comps, id } => {
                    self.anchor.remove_contents(&comps)?;
                    let ids = self.names.forget_children(id);
                    self.drop_ids(ids);
                }
            }
        }
        Ok(())
    }

    /// 遅延していたディレクトリの mode を深い順に適用する（実ディレクトリであることを再確認する）。
    fn finish_dirs(&mut self) -> Result<(), OciError> {
        let mut dirs: Vec<DeferredDir> = std::mem::take(&mut self.deferred_dirs)
            .into_values()
            .collect();
        // 深い順。同じ深さはパス順で決定的にする。
        dirs.sort_by(|(a, _, _), (b, _, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        for (comps, mode, owner) in dirs {
            // `root` の fd 起点で実ディレクトリであることを確かめる（symlink・差し替えは拒否）。
            if self.anchor.check_dir(&comps).is_err() {
                return Err(err(
                    OciErrorCode::FailedPrecondition,
                    "an extracted directory was replaced during extraction",
                ));
            }
            // `chown` の後に mode を適用する（ディレクトリは `chown` で setgid を落とさないが、順序を固定する）。
            if let (Some(o), Some(ids)) = (&self.own, owner) {
                (o.fns.lchown)(&self.anchor, &comps, ids.0, ids.1).map_err(|e| chown_err(&e))?;
                self.chowned = self.chowned.saturating_add(1);
            }
            apply_dir_mode(&self.anchor, &comps, mode)?;
        }
        Ok(())
    }

    /// `root` が今も「展開の開始時と同じ所有者で、group / other に権限のない（0700）ディレクトリ」か。
    ///
    /// 特殊ビットを保持してよい前提（`SpecialBitsDecision::Evaluated`）が展開中も成り立つかを、開いた fd の `fstat`
    /// で確かめ直す（パスを開き直さない）。確認できなければ偽（fail-closed）。特殊ビットの保持は Linux 限定のため、
    /// 他の OS では常に偽。fstat と `fchmod` の間の窓は残る（`docs/design/oci-layer-special-bits.md`）。
    #[cfg(target_os = "linux")]
    fn root_still_private(&self) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        self.anchor.root_meta().is_ok_and(|m| {
            m.is_dir()
                && m.permissions().mode() & 0o077 == 0
                && (self.special.owner_of)(&m).0 == self.special.root_uid
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn root_still_private(&self) -> bool {
        false
    }

    /// 全レイヤーの展開後に、保持した特殊ビットの前提（`root` の所有者と 0700）が最後まで保たれたかを確かめる。
    ///
    /// 保持済みのビットが 1 件以上あるのに、展開中に前提が崩れた（検出済み、または今も崩れている）なら、既に付けた
    /// ビットを遡って外す代わりに結果全体を `FailedPrecondition` で拒否する（fail-closed。呼び出し側が `root` ごと
    /// 破棄する契約。#2437・SEC-5）。
    fn verify_root_after_special_bits(&self) -> Result<(), OciError> {
        // 要求の一部だけが残った（例: 06755 のうち setuid だけ）場合も保持済みとして数える。`preserved_special`
        // は全ビットが残ったファイルだけが増えるため、判定には使わない。
        let kept_any = self.preserved_special > 0
            || self.preserved_bits.setuid > 0
            || self.preserved_bits.setgid > 0
            || self.preserved_bits.sticky > 0;
        if kept_any
            && (self.special.decision == SpecialBitsDecision::RootChangedDuringExtraction
                || !self.root_still_private())
        {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                "the extraction root changed while special mode bits were preserved",
            ));
        }
        Ok(())
    }

    /// `ChownMapped` のとき、エントリの tar の uid / gid を写像したホストの ID を返す（それ以外は `None`）。
    /// 解析できない値・写像に無い値はエラー（パス 1 と同じ判定。`map_tar_owner`）。
    fn host_owner_of<R: Read>(
        &self,
        entry: &mut tar::Entry<'_, R>,
        global: &GlobalOwner,
    ) -> Result<Option<(u32, u32)>, OciError> {
        let Some(o) = &self.own else {
            return Ok(None);
        };
        o.resolve(tar_owner(entry, global)).map(Some)
    }

    /// `ChownMapped` のとき `root` 自身をコンテナ内 0:0 を写した ID へ `chown` する（mode は 0700 のまま変えない）。
    ///
    /// 全レイヤーと `finish_dirs` の後に 1 回だけ呼ぶ。ホスト root 所有のままだと、コンテナ root（subuid）が
    /// 自分の `/` を辿れないため。ほかのホストユーザーからの到達性は 0700 のままで変わらない（SEC-5）。
    fn chown_root(&mut self) -> Result<(), OciError> {
        let Some(o) = &self.own else {
            return Ok(());
        };
        let ids = o.resolve((Some(0), Some(0)))?;
        (o.fns.lchown)(&self.anchor, &[], ids.0, ids.1).map_err(|e| chown_err(&e))?;
        self.chowned = self.chowned.saturating_add(1);
        Ok(())
    }
}

/// `root` が空であることを確かめる（最初のレイヤーの前に 1 回だけ呼ぶ）。`root` がディレクトリであること
/// （symlink でないこと）は `AnchoredRoot::open` が確かめ済みで、列挙は開いた fd 経由で行う。
fn check_root_empty(anchor: &AnchoredRoot) -> Result<(), OciError> {
    // 別表記の衝突の判定（`Extractor::probe`）は「`root` 配下の実在項目はすべてこの展開が作った」ことに依る。
    // 呼び出し契約（空のステージング）を前提にせず、ここで確かめる（IO-5）。
    match anchor.root_is_empty() {
        Ok(true) => Ok(()),
        Ok(false) => Err(err(
            OciErrorCode::FailedPrecondition,
            "extraction root is not empty",
        )),
        Err(e) => Err(map_fs_err(&e)),
    }
}

/// tar エントリ 1 件を検証し、処理内容を返す（パス 1 とパス 3 で共通。副作用なし）。
///
/// パスの正規化（`normalize_entry_path`）、先頭から順の各コンポーネントの分類（`whiteout::classify`）。
/// 最初に通常でないと判定されたものが決める: 予約名（AUFS メタデータ）なら、種別を検査した上でエントリ全体を
/// `Plan::Skip`（読み飛ばし。moby / containerd と同じ。#2183・#2312・OCI-2）、親の位置の whiteout 名・不透明マーカーなら拒否。
/// 最終コンポーネントの分類、マーカーの形（中身の無い通常ファイル）の検査、未対応の種別の拒否を行う。
fn plan_entry<R: Read>(entry: &tar::Entry<'_, R>) -> Result<Plan, OciError> {
    let ty = entry.header().entry_type();
    let raw_path = entry.path_bytes();
    let is_dir_name = raw_path.last() == Some(&b'/');
    // 構造の検査（`..`・絶対パス・NUL・長さ）は全 OS 共通。Windows ホスト固有の名前規則（末尾の `.` / 空白・予約デバイス名）
    // は予約名の読み飛ばしの判定後に適用する。読み飛ばすエントリは FS へ触れず、`.wh..wh.` のような末尾 `.` の
    // 予約名を Windows だけ拒否すると OS 間で挙動が分かれるため（OCI-1・OCI-2・#2325）。
    normalize_entry_path_for(&raw_path, false)?;
    let mut raw_comps = raw_path
        .split(|b| *b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .peekable();
    let mut class = NameClass::Regular;
    while let Some(c) = raw_comps.next() {
        let cls = whiteout::classify(c)?;
        if cls == NameClass::Reserved {
            // AUFS メタデータ。最初に現れた非通常コンポーネントが予約名なら、深さ・サイズを問わず
            // エントリ全体を読み飛ばす（配下の通常ファイルは中身を持つためマーカーの形は検査しない）。
            // ただし種別は予約名の外と同じ規則で先に検査する（FIFO・デバイス等は fail-closed。#2312）。
            // 正規化（`..`・絶対パス・NUL・長さ）は上で済んでおり、予約名の下でも従来どおり拒否される。
            check_supported_entry_type(ty)?;
            return Ok(Plan::Skip);
        }
        if raw_comps.peek().is_none() {
            class = cls;
        } else if cls != NameClass::Regular {
            // 親が whiteout 名のパスは意図が不明なため、暗黙のディレクトリ作成などの副作用の前に拒否する。
            return Err(err(
                OciErrorCode::InvalidArgument,
                "whiteout name used as a parent path component",
            ));
        }
    }
    // 読み飛ばさないエントリには、ホスト固有の名前規則を含む正規化を必ず適用する（fail-closed）。
    let comps = normalize_entry_path(&raw_path)?;
    if class != NameClass::Regular {
        // マーカーは中身の無い通常ファイルに限る。他の型・ディレクトリ名のマーカー名は、実体として展開もせず
        // 意図不明のまま黙って落としもしないよう拒否する（fail-closed）。
        if !matches!(ty, EntryType::Regular | EntryType::Continuous)
            || is_dir_name
            || entry.size() != 0
        {
            return Err(err(
                OciErrorCode::InvalidArgument,
                "whiteout marker must be an empty regular file entry",
            ));
        }
        let Some((parent, _)) = split_last(comps) else {
            return Err(err(OciErrorCode::InvalidArgument, "entry path is empty"));
        };
        return Ok(Plan::Marker(match class {
            NameClass::Whiteout { target } => Marker::Whiteout {
                parent,
                target: bytes_to_os(&target)?,
            },
            _ => Marker::Opaque { parent },
        }));
    }
    let mode = || entry.header().mode().map_err(map_stream_err);
    Ok(match ty {
        EntryType::Directory => Plan::Dir(comps, mode()?),
        EntryType::Regular | EntryType::Continuous if is_dir_name => Plan::Dir(comps, mode()?),
        EntryType::Regular | EntryType::Continuous => Plan::File(comps, mode()?),
        EntryType::Symlink => Plan::Symlink(comps),
        EntryType::Link => {
            check_hardlink_target_not_aufs(entry)?;
            Plan::Hardlink(comps)
        }
        _ => {
            check_supported_entry_type(ty)?;
            // 受理する種別は上の腕で網羅済みでここへは来ない（来たら未対応として拒否する）。
            return Err(err(
                OciErrorCode::PermissionDenied,
                "unsupported entry type",
            ));
        }
    })
}

/// 展開できるエントリ種別（ディレクトリ・通常ファイル・Continuous・symlink・hardlink）だけを受理する。
///
/// 予約名（AUFS メタデータ）の下と外の両方で `plan_entry` が呼び、受理する種別の定義を 1 か所にそろえる。
/// 未対応の種別は `PermissionDenied`（#2312・OCI-2）。
fn check_supported_entry_type(ty: EntryType) -> Result<(), OciError> {
    match ty {
        EntryType::Directory
        | EntryType::Regular
        | EntryType::Continuous
        | EntryType::Symlink
        | EntryType::Link => Ok(()),
        _ => Err(err(
            OciErrorCode::PermissionDenied,
            "unsupported entry type",
        )),
    }
}

/// hardlink の参照先の構造を検査し、AUFS の予約名（`.wh..wh.plnk` 等）を含むなら `Unimplemented` で拒否する。
///
/// パス 1 で呼ぶため、パス 2 の whiteout 適用より前に拒否され rootfs は変わらない（#2312・OCI-2）。
/// moby 互換の差し替えを実装しない理由はモジュール doc「AUFS メタデータの予約名」。構造の検査
/// （`..`・絶対パス・NUL・長さ）はパス 3 の `make_hardlink` と同じコードで前倒しする。
fn check_hardlink_target_not_aufs<R: Read>(entry: &tar::Entry<'_, R>) -> Result<(), OciError> {
    let target = entry
        .link_name_bytes()
        .ok_or_else(|| err(OciErrorCode::InvalidArgument, "hardlink target is invalid"))?;
    normalize_entry_path_for(&target, false)?;
    if target.split(|b| *b == b'/').any(whiteout::is_reserved) {
        return Err(err(
            OciErrorCode::Unimplemented,
            "hardlink into AUFS metadata is not supported",
        ));
    }
    Ok(())
}

/// tar 終端後の残りを EOF まで読み捨て、gzip トレーラ（CRC32・ISIZE）を検証させる。
fn drain<R: Read>(src: &mut LimitedReader<R>) -> Result<(), OciError> {
    let mut buf = vec![0u8; COPY_BUF_LEN];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                if let Some(v) = e.get_ref().and_then(|i| i.downcast_ref::<GuardViolation>()) {
                    return Err(err(v.code, v.msg));
                }
                return Err(oci_error_from_layer_io(e));
            }
        }
    }
}

/// パス 1: tar を走査して全エントリを検証し、マーカーを集める（副作用なし。OCI-2）。
///
/// エントリ数（前のレイヤーまでの `x.entries` から数える）が `max_entries` を超えたら `ResourceExhausted`
/// （集めるマーカーの件数もこれで頭打ちになる）。通常ファイルの宣言サイズの累積（`x.bytes` から数える）が
/// `max_total_bytes` を超えても、本体を読み飛ばす前に `ResourceExhausted` にする。入力は `input_budget` バイト
/// まで読む。戻り値のマーカーは並べ替え・重複除去済み。あわせて、EOF まで読んだ展開後 tar 全体の sha256
/// （diff_id。#2017）を返す。
fn collect_markers<R: Read>(
    x: &Extractor<'_>,
    src: R,
    input_budget: u64,
) -> Result<(Vec<Marker>, Digest), OciError> {
    let mut src = LimitedReader {
        inner: HashingReader {
            inner: src,
            hasher: Sha256::new(),
        },
        read: 0,
        limit: input_budget,
    };
    let mut markers = Vec::new();
    {
        let mut seen = x.metered_entries;
        let mut bytes = x.bytes;
        let mut archive = Archive::new(TarGuard::new(&mut src));
        // `ChownMapped` のときだけ、所有者を書き込み前に検証する（範囲外の ID はそのレイヤーの書き込みより前に拒否。SEC-5）。
        let mut global_owner = GlobalOwner::default();
        for entry in archive.entries().map_err(map_stream_err)? {
            let mut entry = entry.map_err(map_stream_err)?;
            // グローバル PAX ヘッダも件数に数える（件数の上限の迂回を防ぐ。#2251 P2-3）。
            seen = seen.saturating_add(1);
            if seen > x.limits.max_entries {
                return Err(err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the entry count limit",
                ));
            }
            x.budget.check()?;
            if entry.header().entry_type() == EntryType::XGlobalHeader {
                if x.own.is_some() {
                    global_owner.absorb(&mut entry)?;
                }
                continue;
            }
            let plan = plan_entry(&entry)?;
            if let Some(o) = &x.own
                && matches!(plan, Plan::Dir(..) | Plan::File(..) | Plan::Symlink(_))
            {
                o.resolve(tar_owner(&mut entry, &global_owner))?;
            }
            match plan {
                Plan::Marker(m) => markers.push(m),
                // 書き出さないため展開バイト数には数えない（エントリ数は上で数え済み）。
                Plan::Skip => {}
                Plan::File(..) => {
                    bytes = bytes
                        .checked_add(entry.size())
                        .filter(|n| *n <= x.limits.max_total_bytes)
                        .ok_or_else(|| {
                            err(
                                OciErrorCode::ResourceExhausted,
                                "layer exceeds the extracted size limit",
                            )
                        })?;
                }
                Plan::Dir(..) | Plan::Symlink(_) | Plan::Hardlink(_) => {}
            }
        }
    }
    drain(&mut src)?;
    markers.sort_unstable();
    markers.dedup();
    Ok((markers, digest_of(src.inner.hasher)?))
}

/// 1 レイヤー分の tar を `x` へ展開する。`input_budget` はこのレイヤーに残された入力バイト数の上限。
///
/// パス 1（`collect_markers`）・パス 2（`Extractor::apply_markers`）・パス 3（通常エントリの展開）の順に行う
/// （モジュール冒頭「レイヤーごとの 3 パス」）。`src` はパス 1 とパス 3 の前に 1 回ずつ開く。
/// 戻り値は（このレイヤー分の結果〔`x` のカウンタの差分〕, パス 3 が読み取った入力バイト数）。入力の課金は
/// パス 3 の分だけで、パス 1 にも同じ上限を別に課す。`finish_dirs` は呼ばない（全レイヤーの展開後に 1 回だけ呼ぶため）。
fn extract_one_layer<S: LayerSource>(
    x: &mut Extractor<'_>,
    src: &mut S,
    input_budget: u64,
) -> Result<(ExtractedLayer, u64), OciError> {
    let (entries0, bytes0, stripped0) = (x.entries, x.bytes, x.stripped_special);
    let (preserved0, chowned0, ignored0) = (x.preserved_special, x.chowned, x.ignored_reserved);
    let (preserved_bits0, stripped_bits0) = (x.preserved_bits, x.stripped_bits);
    let max_entries = x.limits.max_entries;
    let (markers, diff_id) = collect_markers(x, src.open()?, input_budget)?;
    // 突合はパス 2 の前に行う。不一致のレイヤーは rootfs を変更しない（#2017・OCI-1）。
    if let Some(expected) = src.expected_diff_id()
        && *expected != diff_id
    {
        return Err(err(
            OciErrorCode::DataLoss,
            "layer diff_id does not match the image config",
        ));
    }
    x.apply_markers(&markers)?;
    drop(markers);
    x.layer_nodes.clear();
    // パス 3 もパス 1 と同じ構成（読み取り → ハッシュ → 上限）で包み、drain までの全バイトをハッシュする。
    let mut src = LimitedReader {
        inner: HashingReader {
            inner: src.open()?,
            hasher: Sha256::new(),
        },
        read: 0,
        limit: input_budget,
    };
    {
        let mut archive = Archive::new(TarGuard::new(&mut src));
        // グローバル PAX の所有者指定はこのレイヤーの以降のエントリに効く（SEC-5）。
        let mut global_owner = GlobalOwner::default();
        for entry in archive.entries().map_err(map_stream_err)? {
            let mut entry = entry.map_err(map_stream_err)?;
            let ty = entry.header().entry_type();
            x.metered_entries = x.metered_entries.saturating_add(1);
            if x.metered_entries > max_entries {
                return Err(err(
                    OciErrorCode::ResourceExhausted,
                    "layer exceeds the entry count limit",
                ));
            }
            // 書き込みの前に期限・取り消しを確かめる（REPAIR-5・#2899）。
            x.budget.check()?;
            if ty == EntryType::XGlobalHeader {
                global_owner.absorb(&mut entry)?;
                continue;
            }
            x.entries = x.entries.saturating_add(1);
            match plan_entry(&entry)? {
                // マーカーはパス 2 で適用済み。rootfs へは書かない（OCI-2）。
                Plan::Marker(_) => {}
                // 予約名は本体を読み捨てて件数だけ数える（rootfs へ書かない。#2183）。
                Plan::Skip => x.ignored_reserved = x.ignored_reserved.saturating_add(1),
                Plan::Dir(comps, mode) => {
                    let owner = x.host_owner_of(&mut entry, &global_owner)?;
                    x.make_dir(comps, mode, owner)?;
                }
                Plan::File(comps, mode) => {
                    let size = entry.size();
                    let tar_ids = tar_owner(&mut entry, &global_owner);
                    let owner = x.host_owner_of(&mut entry, &global_owner)?;
                    x.write_file(comps, mode, tar_ids, owner, size, &mut entry)?;
                }
                Plan::Symlink(comps) => {
                    let owner = x.host_owner_of(&mut entry, &global_owner)?;
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "symlink target is invalid")
                        })?;
                    x.make_symlink(comps, &target, owner)?;
                }
                Plan::Hardlink(comps) => {
                    let target = entry
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .ok_or_else(|| {
                            err(OciErrorCode::InvalidArgument, "hardlink target is invalid")
                        })?;
                    x.make_hardlink(comps, &target)?;
                }
            }
        }
    }
    x.layer_nodes.clear();
    drain(&mut src)?;
    // パス 1 とパス 3 の間にレイヤーの内容が変わった（同じ inode への上書きなど）場合は fail-closed にする。
    // 差し替え後の内容の展開物が `root` に残るため、呼び出し側は `Err` を受けたら `root` ごと破棄すること。
    if digest_of(src.inner.hasher)? != diff_id {
        return Err(err(
            OciErrorCode::DataLoss,
            "layer content changed between passes",
        ));
    }
    Ok((
        ExtractedLayer {
            entries: x.entries.saturating_sub(entries0),
            bytes: x.bytes.saturating_sub(bytes0),
            files_with_stripped_special_bits: x.stripped_special.saturating_sub(stripped0),
            ignored_reserved_entries: x.ignored_reserved.saturating_sub(ignored0),
            special_bits: SpecialBitsOutcome {
                decision: x.special.decision,
                preserved_files: x.preserved_special.saturating_sub(preserved0),
                preserved_bits: x.preserved_bits.saturating_sub(preserved_bits0),
                stripped_bits: x.stripped_bits.saturating_sub(stripped_bits0),
            },
            ownership: OwnershipOutcome {
                decision: if x.own.is_some() {
                    OwnershipDecision::Applied
                } else {
                    OwnershipDecision::NotRequested
                },
                chowned_entries: x.chowned.saturating_sub(chowned0),
            },
            diff_id,
        },
        src.read,
    ))
}

/// レイヤー列を `root` へ下位から順に重ねて展開する本体（単一レイヤー API もこれの 1 要素版）。
///
/// 各要素は `LayerSource`（ハンドル版は `VerifiedBlobLayer`、ストリーム版は位置を戻す `Rewind`）。
/// `Extractor`（別表記の索引・遅延ディレクトリ mode・上限のカウンタ）は全レイヤーで共有し、上限は全体で
/// 累積する。`lstat` はテストだけが差し替える（`Lstat` を参照）。
fn extract_stack<S: LayerSource>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = S>,
    root: &Path,
    limits: ExtractLimits,
    lstat: Lstat,
    setup: SpecialSetup,
) -> Result<Vec<ExtractedLayer>, OciError> {
    extract_stack_bounded(
        recorder,
        layers,
        root,
        limits,
        lstat,
        setup,
        ExtractBudget::new(),
    )
}

/// `extract_stack` の期限つき版。`stop` は各レイヤーの前に確かめ、`Extractor` に持たせて内側の走査でも確かめる。
fn extract_stack_bounded<'a, S: LayerSource>(
    recorder: &dyn OciOpRecorder,
    layers: impl IntoIterator<Item = S>,
    root: &'a Path,
    limits: ExtractLimits,
    lstat: Lstat,
    setup: SpecialSetup,
    stop: ExtractBudget<'a>,
) -> Result<Vec<ExtractedLayer>, OciError> {
    let mut x: Option<Extractor<'_>> = None;
    let mut input_used = 0u64;
    let mut out = Vec::new();
    let mut layers = layers.into_iter().peekable();
    while let Some(mut item) = layers.next() {
        // 空の reader は件数・入力バイトを消費しないため、既存の上限では結果の Vec の増加を止められない。
        if out.len() >= MAX_LAYERS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "image exceeds the layer count limit",
            ));
        }
        let is_last = layers.peek().is_none();
        let res = record_oci_op(recorder, OciOpKind::ExtractLayer, || {
            stop.check()?;
            if x.is_none() {
                // 選択肢の不正な組み合わせ・非 Linux の `chown` は、`root` に触れる前に拒否する。
                let own = setup.owner_ctx()?;
                let anchor = AnchoredRoot::open(root, setup.anchor)?;
                check_root_empty(&anchor)?;
                x = Some(Extractor {
                    root,
                    limits,
                    entries: 0,
                    bytes: 0,
                    stripped_special: 0,
                    ignored_reserved: 0,
                    preserved_special: 0,
                    metered_entries: 0,
                    preserved_bits: SpecialBitCounts::default(),
                    stripped_bits: SpecialBitCounts::default(),
                    mode_readback: setup.mode_readback,
                    special: eval_special_ctx(&setup, &anchor)?,
                    anchor,
                    deferred_dirs: HashMap::new(),
                    own,
                    chowned: 0,
                    names: NameIndex::new(limits.max_tracked_paths),
                    layer_nodes: HashSet::new(),
                    lstat,
                    budget: stop,
                });
            }
            let Some(ex) = x.as_mut() else {
                return Err(err(OciErrorCode::Internal, "extractor is not initialized"));
            };
            let budget = limits.max_input_bytes.saturating_sub(input_used);
            let (layer, read) = extract_one_layer(ex, &mut item, budget)?;
            input_used = input_used.saturating_add(read);
            // 遅延ディレクトリ権限の適用は最後のレイヤーの記録に含める（失敗・所要時間を計装から漏らさない。REPAIR-4）。
            let mut layer = layer;
            if is_last {
                let chowned0 = ex.chowned;
                stop.check()?;
                ex.finish_dirs()?;
                // `chown_root` は `root` の所有者を正当に変えるため、その前に確かめる。
                ex.verify_root_after_special_bits()?;
                ex.chown_root()?;
                // ディレクトリと `root` の `chown` は最後のレイヤーの結果に数える。
                layer.ownership.chowned_entries = layer
                    .ownership
                    .chowned_entries
                    .saturating_add(ex.chowned.saturating_sub(chowned0));
            }
            Ok(layer)
        })?;
        out.push(res);
    }
    if x.is_none() {
        return Err(err(OciErrorCode::InvalidArgument, "no layers to extract"));
    }
    Ok(out)
}

/// 単一レイヤー版の結果（要素 1 つ）を取り出す。
fn single(mut v: Vec<ExtractedLayer>) -> Result<ExtractedLayer, OciError> {
    match (v.pop(), v.is_empty()) {
        (Some(l), true) => Ok(l),
        _ => Err(err(OciErrorCode::Internal, "unexpected layer result count")),
    }
}

/// テスト用の単一レイヤー展開（`lstat` を差し替える）。
#[cfg(test)]
fn extract_with_lstat<R: Read + Seek>(
    src: R,
    root: &Path,
    limits: ExtractLimits,
    lstat: Lstat,
) -> Result<ExtractedLayer, OciError> {
    single(extract_stack(
        &NoopOciOpRecorder,
        [Rewind::new(src)],
        root,
        limits,
        lstat,
        SpecialSetup::host(SpecialBitsPolicy::Strip),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::OciOpOutcome;
    use crate::instrument::testing::Collect;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// `base/root` を作る一時ディレクトリ。Drop で `base` ごと消す（番兵でルート外書き込みを検出する）。
    struct Sandbox {
        base: PathBuf,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let base =
                std::env::temp_dir().join(format!("fc-oci-extract-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            let root = base.join("root");
            fs::create_dir_all(&root).unwrap();
            fs::write(base.join("sentinel"), b"s").unwrap();
            Self { base, root }
        }

        /// ルート外に番兵以外が増えていないこと。
        fn assert_outside_untouched(&self) {
            let mut names: Vec<_> = fs::read_dir(&self.base)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            assert_eq!(names, vec!["root".to_string(), "sentinel".to_string()]);
            assert_eq!(fs::read(self.base.join("sentinel")).unwrap(), b"s");
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            // 0o555 等のディレクトリを消せるよう権限を戻す。
            #[cfg(unix)]
            restore_perms(&self.base);
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(unix)]
    fn restore_perms(p: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(m) = fs::symlink_metadata(p)
            && m.is_dir()
        {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    restore_perms(&e.path());
                }
            }
        }
    }

    /// 生バイトで 1 エントリ分（ヘッダ + パディング済みデータ）を組み立てる。
    /// `tar::Builder` は `..` や絶対パスを拒否するため、悪意あるアーカイブはここで手組みする。
    fn raw_entry(
        name: &[u8],
        ty: EntryType,
        link: &[u8],
        mode: u32,
        declared: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        {
            let old = h.as_old_mut();
            old.name[..name.len()].copy_from_slice(name);
            old.linkname[..link.len()].copy_from_slice(link);
        }
        h.set_entry_type(ty);
        h.set_mode(mode);
        h.set_size(declared);
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    fn file(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Regular,
            b"",
            mode,
            data.len() as u64,
            data,
        )
    }

    fn dir(name: &str, mode: u32) -> Vec<u8> {
        raw_entry(name.as_bytes(), EntryType::Directory, b"", mode, 0, b"")
    }

    fn symlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Symlink,
            target.as_bytes(),
            0o777,
            0,
            b"",
        )
    }

    fn hardlink(name: &str, target: &str) -> Vec<u8> {
        raw_entry(
            name.as_bytes(),
            EntryType::Link,
            target.as_bytes(),
            0o644,
            0,
            b"",
        )
    }

    fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = entries.concat();
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    fn run(sb: &Sandbox, entries: &[Vec<u8>]) -> Result<ExtractedLayer, OciError> {
        extract_tar(
            Cursor::new(archive(entries)),
            &sb.root,
            ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20),
        )
    }

    /// 大文字小文字と NFC / NFD を区別しない FS の名前解決を模擬する `Lstat`（IO-5）。
    ///
    /// 綴りどおりに無ければ、最終コンポーネントを ASCII 小文字にし `e` + U+0301 を U+00E9 へ畳んで引き直す。
    /// 大文字小文字を区別する FS（Linux の CI）の上で「別表記が既存の実体へ解決される」状況を作る。
    /// 先に小文字・NFC の名前を作り、後から大文字・NFD の綴りで参照する入力に対して使う。
    fn folding_lstat(p: &Path) -> std::io::Result<fs::Metadata> {
        fs::symlink_metadata(p).or_else(|e| {
            let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str()))
            else {
                return Err(e);
            };
            let folded = name.to_ascii_lowercase().replace("e\u{301}", "\u{e9}");
            fs::symlink_metadata(dir.join(folded))
        })
    }

    /// `folding_lstat` を注入して展開する（区別しない FS の模擬）。
    fn run_folding(sb: &Sandbox, entries: &[Vec<u8>]) -> Result<ExtractedLayer, OciError> {
        extract_with_lstat(
            Cursor::new(archive(entries)),
            &sb.root,
            ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20),
            folding_lstat,
        )
    }

    /// `dir` 直下の名前を綴りのまま昇順で返す。
    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// 別表記の衝突として拒否されたこと（`code` と `message` の具体値）を確かめる。
    fn assert_spelling_collision(r: Result<ExtractedLayer, OciError>) {
        let e = r.expect_err("must be rejected as a spelling collision");
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(e.code().as_str(), "ALREADY_EXISTS");
        assert_eq!(
            e.message(),
            "entry name resolves to an existing entry with a different spelling \
             (case or Unicode normalization) on the destination filesystem"
        );
    }

    /// `base` の FS が `a` と `b` を同じ名前として解決するか（`a` を作って `b` で引く。後始末する）。
    fn fs_resolves_as_same(base: &Path, a: &str, b: &str) -> bool {
        fs::write(base.join(a), b"p").unwrap();
        let same = fs::symlink_metadata(base.join(b)).is_ok();
        fs::remove_file(base.join(a)).unwrap();
        same
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// IO-5 / OCI-1: 通常ファイル `f` の後の hardlink `F → f` は、区別しない FS では参照元を削除する前に拒否する。
    #[test]
    fn io5_hardlink_under_alias_spelling_is_rejected_before_removing_source() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"data"), hardlink("F", "f")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: `d/`（0555）の後の `D/`（0755）は、区別しない FS では mode を変える前に拒否する
    /// （先の遅延 mode が残って後勝ちが崩れる経路を作らない）。
    #[test]
    fn io5_directory_alias_redefinition_is_rejected_before_mode_change() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(&sb, &[dir("d/", 0o555), dir("D/", 0o755)]));
        assert_eq!(names_in(&sb.root), ["d"]);
        // `d/` は遅延中の一時 mode（0700）のままで、`D/` の 0755 は適用されていない。
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.root.join("d")), 0o700);
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: 区別しない FS で別表記の通常ファイルが先の内容を上書きしない（`f` の後の `F`、NFC の後の NFD）。
    #[test]
    fn io5_file_alias_does_not_overwrite() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"one"), file("F", 0o644, b"two")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"one");

        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[
                file("caf\u{e9}", 0o644, b"nfc"),
                file("cafe\u{301}", 0o644, b"nfd"),
            ],
        ));
        assert_eq!(names_in(&sb.root), ["caf\u{e9}"]);
        assert_eq!(fs::read(sb.root.join("caf\u{e9}")).unwrap(), b"nfc");
    }

    /// IO-5 / OCI-1: 別表記は親コンポーネント・hardlink の参照先・symlink を辿った先でも拒否し、何も作らない。
    #[test]
    fn io5_alias_in_parent_and_link_targets_is_rejected() {
        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("d/x", 0o644, b"x"), file("D/y", 0o644, b"y")],
        ));
        assert_eq!(names_in(&sb.root), ["d"]);
        assert_eq!(names_in(&sb.root.join("d")), ["x"]);

        let sb = Sandbox::new();
        assert_spelling_collision(run_folding(
            &sb,
            &[file("f", 0o644, b"data"), hardlink("g", "F")],
        ));
        assert_eq!(names_in(&sb.root), ["f"]);

        #[cfg(unix)]
        {
            let sb = Sandbox::new();
            assert_spelling_collision(run_folding(
                &sb,
                &[
                    dir("d/", 0o755),
                    symlink("l", "D"),
                    file("l/x", 0o644, b"x"),
                ],
            ));
            assert_eq!(names_in(&sb.root), ["d", "l"]);
            assert_eq!(names_in(&sb.root.join("d")), Vec::<String>::new());
        }
    }

    /// IO-5 / OCI-1: 区別しない FS の模擬でも、同じ綴りの再定義（後勝ち）と別名は従来どおり通す（過剰に拒否しない）。
    #[test]
    fn io5_same_spelling_redefinition_is_still_accepted_on_folding_fs() {
        let sb = Sandbox::new();
        let r = run_folding(
            &sb,
            &[
                file("f", 0o644, b"one"),
                file("f", 0o644, b"two"),
                hardlink("f", "f"),
                hardlink("g", "f"),
                dir("d/", 0o555),
                dir("d/", 0o755),
                file("d/x", 0o644, b"x"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (7, 7));
        assert_eq!(names_in(&sb.root), ["d", "f", "g"]);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"two");
        assert_eq!(fs::read(sb.root.join("g")).unwrap(), b"two");
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"x");
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.root.join("d")), 0o755);
    }

    /// IO-5 / OCI-1: 実 FS での大文字小文字の別表記。区別する FS（Linux の既定）では別の実体として両方を
    /// 展開し、区別しない FS（Windows・macOS の既定）では先の実体を変える前に拒否する。
    #[test]
    fn io5_case_variants_follow_destination_fs() {
        let sb = Sandbox::new();
        let folds = fs_resolves_as_same(&sb.base, "probe", "PROBE");
        let layers = [
            vec![file("f", 0o644, b"data"), hardlink("F", "f")],
            vec![file("f", 0o644, b"data"), file("F", 0o644, b"two")],
            vec![dir("d/", 0o555), dir("D/", 0o755)],
        ];
        if folds {
            // hardlink `F → f` は参照元 `f` を削除する前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[0]));
            assert_eq!(names_in(&sb.root), ["f"]);
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
            sb.assert_outside_untouched();

            // 通常ファイル `F` は `f` の内容を上書きする前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[1]));
            assert_eq!(names_in(&sb.root), ["f"]);
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            // ディレクトリ `D/` は `d/` の mode（遅延中の一時 0700）を変える前に拒否する。
            let sb = Sandbox::new();
            assert_spelling_collision(run(&sb, &layers[2]));
            assert_eq!(names_in(&sb.root), ["d"]);
            #[cfg(unix)]
            assert_eq!(mode_of(&sb.root.join("d")), 0o700);
        } else {
            let sb = Sandbox::new();
            run(&sb, &layers[0]).unwrap();
            assert_eq!(names_in(&sb.root), ["F", "f"]);
            assert_eq!(fs::read(sb.root.join("F")).unwrap(), b"data");
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            let sb = Sandbox::new();
            run(&sb, &layers[1]).unwrap();
            assert_eq!(names_in(&sb.root), ["F", "f"]);
            assert_eq!(fs::read(sb.root.join("F")).unwrap(), b"two");
            assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");

            let sb = Sandbox::new();
            run(&sb, &layers[2]).unwrap();
            assert_eq!(names_in(&sb.root), ["D", "d"]);
            #[cfg(unix)]
            {
                assert_eq!(mode_of(&sb.root.join("d")), 0o555);
                assert_eq!(mode_of(&sb.root.join("D")), 0o755);
            }
        }
    }

    /// IO-5 / OCI-1: 実 FS での NFC / NFD の別表記。正規化を区別する FS（ext4・NTFS）では両方を展開し、
    /// 区別しない FS（APFS）では先の内容を上書きする前に拒否する。
    #[test]
    fn io5_normalization_variants_follow_destination_fs() {
        let (nfc, nfd) = ("caf\u{e9}", "cafe\u{301}");
        let sb = Sandbox::new();
        let folds = fs_resolves_as_same(&sb.base, nfc, nfd);
        let r = run(&sb, &[file(nfc, 0o644, b"nfc"), file(nfd, 0o644, b"nfd")]);
        if folds {
            assert_spelling_collision(r);
            assert_eq!(names_in(&sb.root), [nfc]);
        } else {
            let r = r.unwrap();
            assert_eq!((r.entries, r.bytes), (2, 6));
            assert_eq!(names_in(&sb.root), [nfd, nfc]);
            assert_eq!(fs::read(sb.root.join(nfd)).unwrap(), b"nfd");
        }
        assert_eq!(fs::read(sb.root.join(nfc)).unwrap(), b"nfc");
        sb.assert_outside_untouched();
    }

    /// IO-5: Windows・macOS の既定の一時領域は大文字小文字を区別しない（macOS の APFS は NFC / NFD も区別しない）。
    ///
    /// `io5_case_variants_follow_destination_fs` と `io5_normalization_variants_follow_destination_fs` は
    /// 展開先 FS の挙動で分岐するため、これらの OS の CI で「実 FS が別表記を既存の実体へ解決し、展開が
    /// 拒否する」側が実際に走ったことをここで固定する（区別する側へ黙って流れたら失敗させる）。
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn io5_default_host_fs_resolves_spelling_variants_as_same() {
        let sb = Sandbox::new();
        assert!(fs_resolves_as_same(&sb.base, "probe", "PROBE"));
        #[cfg(target_os = "macos")]
        assert!(fs_resolves_as_same(&sb.base, "caf\u{e9}", "cafe\u{301}"));
        sb.assert_outside_untouched();
    }

    /// IO-5 / OCI-1: 空でない展開先は `FailedPrecondition` で拒否し、既存の項目に触れない
    /// （別表記の衝突の判定が「実在項目はすべてこの展開が作った」ことに依るため）。
    #[test]
    fn io5_non_empty_root_is_rejected() {
        let sb = Sandbox::new();
        fs::write(sb.root.join("existing"), b"keep").unwrap();
        let e = run(&sb, &[file("existing", 0o644, b"new")]).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "extraction root is not empty");
        assert_eq!(names_in(&sb.root), ["existing"]);
        assert_eq!(fs::read(sb.root.join("existing")).unwrap(), b"keep");
    }

    /// OCI-1 / IO-5: 展開が作る名前（暗黙の親ディレクトリを含む）は上限ちょうどが成功し、超過は作成前に中断する。
    /// 同じ名前の再定義は件数を増やさない。
    #[test]
    fn oci1_tracked_path_limit() {
        let limits = |n| ExtractLimits::new(10, 100, 1 << 30, n);
        let es = [file("a/b/c", 0o644, b"x"), file("a/b/c", 0o644, b"y")];
        let sb = Sandbox::new();
        let r = extract_tar(Cursor::new(archive(&es)), &sb.root, limits(3)).unwrap();
        assert_eq!((r.entries, r.bytes), (2, 2));
        assert_eq!(fs::read(sb.root.join("a/b/c")).unwrap(), b"y");

        let sb = Sandbox::new();
        let e = extract_tar(Cursor::new(archive(&es)), &sb.root, limits(2)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the tracked path limit");
        assert_eq!(names_in(&sb.root.join("a")), ["b"]);
        assert_eq!(names_in(&sb.root.join("a/b")), Vec::<String>::new());

        let sb = Sandbox::new();
        let e = extract_tar(
            Cursor::new(archive(&[dir("x/", 0o755), dir("y/", 0o755)])),
            &sb.root,
            limits(1),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(names_in(&sb.root), ["x"]);
    }

    fn code(r: Result<ExtractedLayer, OciError>) -> OciErrorCode {
        r.expect_err("must fail").code()
    }

    /// OCI-1: `..`・絶対パス・NUL・過大な長さは拒否され、ルート外には何も作られない。
    #[test]
    fn oci1_path_traversal_is_rejected() {
        for name in [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "a/b/../../..",
            "./../evil",
        ] {
            let sb = Sandbox::new();
            assert_eq!(
                code(run(&sb, &[file(name, 0o644, b"x")])),
                OciErrorCode::PermissionDenied,
                "{name}"
            );
            sb.assert_outside_untouched();
        }
        // 1 コンポーネント 256 バイトは GNU long name 経由でしか表せない。
        let sb = Sandbox::new();
        let long = "x".repeat(256);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        let e = extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1 / SEC-5: 通常の展開（暗黙の親ディレクトリ・`./` 正規化・mode・ルート自身の無視）。
    /// 通常ファイルの setuid（04755）は落として 0755 で展開する。
    #[cfg(unix)]
    #[test]
    fn oci1_extracts_regular_tree_with_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                dir("./", 0o755),
                dir("etc/", 0o755),
                file("./etc/hosts", 0o644, b"127.0.0.1"),
                file("usr/bin/tool", 0o4755, b"bin"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (4, 12));
        assert_eq!(fs::read(sb.root.join("etc/hosts")).unwrap(), b"127.0.0.1");
        let mode = |p: &str| fs::metadata(sb.root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("etc/hosts"), 0o644);
        assert_eq!(mode("usr/bin/tool"), 0o755);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(mode("etc"), 0o755);
        sb.assert_outside_untouched();
    }

    /// SEC-5 / OCI-1: 通常ファイルの setuid / setgid / sticky は落とし、落とした件数を結果に返す。
    /// 実行ユーザー所有のまま setuid / setgid を残さない。ディレクトリの mode（sticky の 1777）は変えない。
    #[cfg(unix)]
    #[test]
    fn sec5_special_mode_bits_are_stripped_from_regular_files() {
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                file("suid", 0o4755, b"a"),
                file("sgid", 0o2755, b"b"),
                file("both", 0o6711, b"c"),
                file("sticky", 0o1644, b"d"),
                file("plain", 0o755, b"e"),
                hardlink("link", "suid"),
                dir("tmp/", 0o1777),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (7, 5));
        assert_eq!(r.files_with_stripped_special_bits, 4);
        for (name, want) in [
            ("suid", 0o755),
            ("sgid", 0o755),
            ("both", 0o711),
            ("sticky", 0o644),
            ("plain", 0o755),
            ("link", 0o755),
            ("tmp", 0o1777),
        ] {
            assert_eq!(mode_of(&sb.root.join(name)), want, "{name}");
        }
    }

    /// OCI-1: 親エントリの無い tar の暗黙ディレクトリは既定 0755、後続の明示エントリがあればその mode になる。
    #[cfg(unix)]
    #[test]
    fn oci1_implicit_dirs_get_default_mode_and_explicit_overrides() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(
            &sb,
            &[
                file("usr/bin/tool", 0o755, b"x"),
                file("opt/app/f", 0o644, b"y"),
                dir("opt/", 0o750),
            ],
        )
        .unwrap();
        let mode = |p: &str| fs::metadata(sb.root.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("usr"), 0o755);
        assert_eq!(mode("usr/bin"), 0o755);
        assert_eq!(mode("opt/app"), 0o755);
        assert_eq!(mode("opt"), 0o750);
    }

    /// OCI-1: 所有者の権限が欠けるディレクトリでも子を作れ、最終的に mode が適用される。
    #[cfg(unix)]
    #[test]
    fn oci1_readonly_directory_mode_is_deferred() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(&sb, &[dir("ro/", 0o555), file("ro/child", 0o644, b"c")]).unwrap();
        assert_eq!(fs::read(sb.root.join("ro/child")).unwrap(), b"c");
        let m = fs::metadata(sb.root.join("ro"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(m, 0o555);
    }

    /// OCI-1: 同じディレクトリの再定義は後勝ち（0555 の後に 0755 を定義すると最終 mode は 0755）。
    #[cfg(unix)]
    #[test]
    fn oci1_directory_redefinition_is_last_wins() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode_of = |sb: &Sandbox| {
            fs::metadata(sb.root.join("d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o555), dir("d/", 0o755)]).unwrap();
        assert_eq!(mode_of(&sb), 0o755);
        let sb = Sandbox::new();
        run(&sb, &[dir("d/", 0o755), dir("d/", 0o555)]).unwrap();
        assert_eq!(mode_of(&sb), 0o555);
    }

    /// OCI-1: 巨大な拡張ヘッダ（GNU long name / PAX）は本体を確保する前にメタデータ上限で拒否する。
    #[test]
    fn oci1_oversized_extended_header_is_rejected_before_read() {
        for ty in [
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XHeader,
        ] {
            let sb = Sandbox::new();
            // 宣言サイズだけ巨大で本体は無い。確保前に拒否されなければ DataLoss（切り詰め）になる。
            let e = raw_entry(b"././@LongLink", ty, b"", 0o644, 1 << 40, b"");
            assert_eq!(code(run(&sb, &[e])), OciErrorCode::ResourceExhausted);
        }
    }

    /// OCI-1: PAX の size 上書きは追跡をずらせるため拒否する。
    #[test]
    fn oci1_pax_size_override_is_rejected() {
        let sb = Sandbox::new();
        let rec = b"12 size=999\n";
        let e = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            rec.len() as u64,
            rec,
        );
        assert_eq!(
            code(run(&sb, &[e, file("f", 0o644, b"x")])),
            OciErrorCode::InvalidArgument
        );
    }

    /// OCI-1: PAX の path 値に ` size=` を含むだけの正常な tar は拒否しない。
    #[test]
    fn oci1_pax_path_containing_size_text_is_accepted() {
        let sb = Sandbox::new();
        let body = pax_record("path", "a size=b.txt");
        let e = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            body.len() as u64,
            &body,
        );
        let r = run(&sb, &[e, file("ignored", 0o644, b"x")]);
        assert!(r.is_ok(), "{r:?}");
    }

    /// OCI-1: 構文違反の PAX レコードは構造化エラーで拒否する（パニックしない）。
    #[test]
    fn oci1_pax_malformed_record_is_rejected() {
        for bad in [
            &b"999 size=1\n"[..],
            b"x size=1\n",
            b"3 a\n",
            b"12 size=999",
            // 長さ欄が後続行にまたがるレコード（埋め込み size を隠す）は tar crate と同様に不整合として拒否する。
            b"22 path=a\n12 size=999\n",
        ] {
            assert_eq!(
                pax_reject_unsupported_records(bad).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData,
                "{bad:?}"
            );
        }
    }

    fn pax_record(key: &str, val: &str) -> Vec<u8> {
        let base = key.len() + val.len() + 3;
        let mut n = base;
        while n.to_string().len() + base != n {
            n = base + n.to_string().len();
        }
        format!("{n} {key}={val}\n").into_bytes()
    }

    /// OCI-1: 前のレコードの長さ欄に隠された埋め込み `size` 行も拒否する（改行で先に分割する）。
    #[test]
    fn oci1_pax_embedded_size_record_is_rejected() {
        let sb = Sandbox::new();
        // 1 行目の長さ欄が 2 行分を指していても、tar crate は改行で分割して `size` 行を解釈する。
        for rec in [
            &b"22 path=a\n12 size=999\n"[..],
            b"10 path=a\n12 size=999\n",
        ] {
            let e = raw_entry(
                b"pax",
                EntryType::XHeader,
                b"",
                0o644,
                rec.len() as u64,
                rec,
            );
            assert_eq!(
                code(run(&sb, &[e, file("f", 0o644, b"x")])),
                OciErrorCode::InvalidArgument
            );
        }
    }

    /// OCI-1: symlink のターゲットがルートより上へ出るものは拒否、収まるものは成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_targets_are_confined() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("x", "../../etc")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("y", "..")])),
            OciErrorCode::PermissionDenied
        );
        assert_eq!(
            code(run(&sb, &[symlink("z", "/..")])),
            OciErrorCode::PermissionDenied
        );
        assert!(fs::symlink_metadata(sb.root.join("x")).is_err());
        sb.assert_outside_untouched();

        let sb = Sandbox::new();
        run(
            &sb,
            &[
                symlink("a/b/rel", "../sibling"),
                symlink("abs", "/usr/bin/x"),
                symlink("dotdot", "a/b/../.."),
            ],
        )
        .unwrap();
        assert_eq!(
            fs::read_link(sb.root.join("a/b/rel")).unwrap(),
            PathBuf::from("../sibling")
        );
        assert_eq!(
            fs::read_link(sb.root.join("abs")).unwrap(),
            PathBuf::from("/usr/bin/x")
        );
        sb.assert_outside_untouched();
    }

    /// OCI-1: ルートを指す絶対 symlink 越しの書き込みは、ホストではなく `root` 配下に作られる。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_traversal_stays_inside_root() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[symlink("link", "/"), file("link/etc/x", 0o644, b"in")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("etc/x")).unwrap(), b"in");
        sb.assert_outside_untouched();

        // 相対で上へ登るリンク経由でもルートで止まる。
        let sb = Sandbox::new();
        run(
            &sb,
            &[
                dir("d/", 0o755),
                symlink("d/up", "../"),
                file("d/up/d/up/f", 0o644, b"f"),
            ],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"f");
        sb.assert_outside_untouched();
    }

    /// OCI-1: symlink を指す名前への書き込みはリンク先に追従せず、リンクを置換する。
    #[cfg(unix)]
    #[test]
    fn oci1_write_over_symlink_replaces_link() {
        let sb = Sandbox::new();
        // ルート外の実在ファイル（番兵）のホスト絶対パスを指す symlink をレイヤーで置く。絶対ターゲットは
        // 展開時にはルート基準で解決するが、OS が素朴に追従すればホストの番兵へ届く。
        let victim = sb.base.join("sentinel");
        let target = victim.to_str().unwrap();
        run(&sb, &[symlink("t", target), file("t", 0o644, b"new")]).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"s");
        assert!(fs::symlink_metadata(sb.root.join("t")).unwrap().is_file());
        assert_eq!(fs::read(sb.root.join("t")).unwrap(), b"new");
        sb.assert_outside_untouched();
    }

    /// OCI-1: ループする symlink は追従回数の上限で拒否する。
    #[cfg(unix)]
    #[test]
    fn oci1_symlink_loop_is_rejected() {
        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                symlink("a", "b"),
                symlink("b", "a"),
                file("a/x", 0o644, b"x"),
            ],
        );
        assert_eq!(code(r), OciErrorCode::InvalidArgument);
        sb.assert_outside_untouched();
    }

    /// OCI-1・OCI-2: エントリ数は上限ちょうどが成功し、上限 + 1 はパス 1（副作用なし）で拒否して何も作らない。
    #[test]
    fn oci1_entry_count_limit() {
        let es = [
            file("a", 0o644, b"1"),
            file("b", 0o644, b"2"),
            file("c", 0o644, b"3"),
        ];
        let sb = Sandbox::new();
        let r = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(3, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.entries, 3);

        let sb = Sandbox::new();
        let e = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(2, 100, 1 << 30, 1 << 20),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the entry count limit");
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-1: 累積サイズは上限ちょうどが成功し、超過は中断する。巨大な宣言サイズは書き込み前に拒否する。
    #[test]
    fn oci1_total_bytes_limit() {
        let es = [file("a", 0o644, b"1234"), file("b", 0o644, b"5678")];
        let sb = Sandbox::new();
        let r = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(10, 8, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.bytes, 8);

        let sb = Sandbox::new();
        let e = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(10, 7, 1 << 30, 1 << 20),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert!(!sb.root.join("b").exists());

        let sb = Sandbox::new();
        let huge = raw_entry(b"big", EntryType::Regular, b"", 0o644, 10 << 30, b"tiny");
        let e = run(&sb, &[file("a", 0o644, b"1"), huge]).expect_err("huge");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the extracted size limit");
        // 宣言サイズはパス 1 で本体を読み飛ばす前に検査するため、先の `a` も作られない。
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-1: hardlink はルート内の通常ファイルへのみ成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_hardlink_rules() {
        let sb = Sandbox::new();
        run(
            &sb,
            &[file("orig", 0o644, b"data"), hardlink("sub/copy", "orig")],
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("sub/copy")).unwrap(), b"data");

        for (es, want) in [
            (
                vec![hardlink("h", "../sentinel")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![hardlink("h", "/etc/passwd")],
                OciErrorCode::PermissionDenied,
            ),
            (vec![hardlink("h", "missing")], OciErrorCode::NotFound),
            (
                vec![symlink("s", "orig"), hardlink("h", "s")],
                OciErrorCode::PermissionDenied,
            ),
            (
                vec![dir("d/", 0o755), hardlink("h", "d")],
                OciErrorCode::PermissionDenied,
            ),
        ] {
            let sb = Sandbox::new();
            assert_eq!(code(run(&sb, &es)), want);
            sb.assert_outside_untouched();
        }
    }

    /// OCI-1: 自分自身への hardlink（f → f）は参照元を削除せず成功する。
    #[cfg(unix)]
    #[test]
    fn oci1_hardlink_to_self_keeps_file() {
        let sb = Sandbox::new();
        run(&sb, &[file("f", 0o644, b"data"), hardlink("f", "f")]).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"data");
    }

    /// OCI-1: デバイス・FIFO は拒否する。
    #[test]
    fn oci1_special_entries_are_rejected() {
        for ty in [EntryType::Char, EntryType::Block, EntryType::Fifo] {
            let sb = Sandbox::new();
            let e = raw_entry(b"dev", ty, b"", 0o644, 0, b"");
            assert_eq!(
                code(run(&sb, &[e])),
                OciErrorCode::PermissionDenied,
                "{ty:?}"
            );
            assert!(!sb.root.join("dev").exists());
        }
    }

    /// OCI-1: sparse エントリは拒否する（tar 側の解析で不正な sparse ヘッダとして DataLoss になる）。
    #[test]
    fn oci1_sparse_entry_is_rejected() {
        let sb = Sandbox::new();
        let e = raw_entry(b"sp", EntryType::GNUSparse, b"", 0o644, 0, b"");
        assert_eq!(code(run(&sb, &[e])), OciErrorCode::DataLoss);
        assert!(!sb.root.join("sp").exists());
    }

    /// OCI-1: PAX 形式の GNU sparse（`GNU.sparse.*` キー + 通常ファイルの typeflag）は、穴を詰めた内容のまま
    /// 通常ファイルとして展開せずに拒否する。値やパスに同じ文字列を含むだけの PAX レコードは通す。
    #[test]
    fn oci1_pax_gnu_sparse_entry_is_rejected() {
        let pax = |rec: &[u8]| {
            raw_entry(
                b"pax",
                EntryType::XHeader,
                b"",
                0o644,
                rec.len() as u64,
                rec,
            )
        };
        for (key, val) in [
            // 0.0
            ("GNU.sparse.size", "1073741824"),
            ("GNU.sparse.numblocks", "1"),
            // 0.1
            ("GNU.sparse.map", "0,4"),
            // 1.0
            ("GNU.sparse.major", "1"),
            ("GNU.sparse.realsize", "1073741824"),
            ("GNU.sparse.name", "sp"),
        ] {
            let sb = Sandbox::new();
            let e = run(
                &sb,
                &[pax(&pax_record(key, val)), file("sp", 0o644, b"data")],
            )
            .expect_err(key);
            assert_eq!(e.code(), OciErrorCode::DataLoss, "{key}");
            assert_eq!(e.message(), "sparse entries are not supported", "{key}");
            assert_eq!(names_in(&sb.root), Vec::<String>::new(), "{key}");
        }

        let sb = Sandbox::new();
        let r = run(
            &sb,
            &[
                pax(&pax_record("path", "GNU.sparse.size")),
                file("ignored", 0o644, b"data"),
                pax(&pax_record("comment", "GNU.sparse.map=0,4")),
                file("f", 0o644, b"x"),
            ],
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (2, 5));
        assert_eq!(names_in(&sb.root), ["GNU.sparse.size", "f"]);
        assert_eq!(fs::read(sb.root.join("GNU.sparse.size")).unwrap(), b"data");
    }

    /// OCI-1: 旧 GNU sparse（通常 typeflag + isextended）は拒否する（ヘッダ境界の追跡ずれを防ぐ）。
    #[test]
    fn oci1_old_gnu_sparse_isextended_is_rejected() {
        let sb = Sandbox::new();
        let mut e = file("old", 0o644, b"");
        // GNU ヘッダの isextended は offset 482。チェックサムを再計算する。
        e[482] = 1;
        let mut h = tar::Header::from_byte_slice(&e[..512]).clone();
        h.set_cksum();
        e[..512].copy_from_slice(h.as_bytes());
        assert_eq!(code(run(&sb, &[e])), OciErrorCode::DataLoss);
    }

    /// OCI-1: 末尾ドット・空白付きの `..` は全 OS で脱出として拒否する。
    #[test]
    fn oci1_dotdot_variants_are_rejected() {
        for p in ["a/.. /b", "a/.../b", "a/... /b", ".. "] {
            for win in [false, true] {
                assert!(
                    normalize_entry_path_for(p.as_bytes(), win).is_err(),
                    "{p} win={win}"
                );
            }
        }
        assert!(normalize_entry_path_for(b"a/./b", false).is_ok());
        assert!(normalize_entry_path_for(b"a/.hidden", false).is_ok());
        assert!(normalize_entry_path_for(b"a/foo.", false).is_ok());
    }

    /// OCI-1: Windows ホストでは末尾ドット・空白と予約デバイス名を拒否する。他 OS では通す。
    #[test]
    fn oci1_windows_names_are_rejected_on_windows_only() {
        for p in [
            "CON",
            "con.txt",
            "a/Nul",
            "AUX.tar.gz",
            "COM1",
            "lpt9.x",
            "prn ",
            "foo.",
            "bar ",
        ] {
            assert!(normalize_entry_path_for(p.as_bytes(), true).is_err(), "{p}");
        }
        for p in ["CON", "aux.c", "foo.", "COM0", "COM10", "console", "nul2"] {
            assert!(normalize_entry_path_for(p.as_bytes(), false).is_ok(), "{p}");
        }
        for p in ["COM0", "COM10", "console", "nul2"] {
            assert!(normalize_entry_path_for(p.as_bytes(), true).is_ok(), "{p}");
        }
    }

    /// OCI-1: 所有者権限のないディレクトリの下にも子を作れ、最終 mode は元の値になる。
    #[cfg(unix)]
    #[test]
    fn oci1_zero_mode_directory_accepts_children_then_restores() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        run(&sb, &[dir("z/", 0o000), file("z/child", 0o644, b"c")]).unwrap();
        let m = fs::metadata(sb.root.join("z"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(m, 0);
        restore_perms(&sb.root);
        assert_eq!(fs::read(sb.root.join("z/child")).unwrap(), b"c");
    }

    /// OCI-1: 後勝ち・ディレクトリ上へのファイルは拒否・長いパス（GNU long name）。
    #[test]
    fn oci1_duplicates_and_long_names() {
        let sb = Sandbox::new();
        run(&sb, &[file("f", 0o644, b"one"), file("f", 0o644, b"two")]).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"two");

        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[dir("d/", 0o755), file("d", 0o644, b"x")])),
            OciErrorCode::FailedPrecondition
        );

        let sb = Sandbox::new();
        let long: String = (0..8)
            .map(|i| format!("{}{i}/", "d".repeat(60)))
            .collect::<String>()
            + "leaf";
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &long, &b"ok"[..]).unwrap();
        let bytes = b.into_inner().unwrap();
        extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb.root,
            ExtractLimits::new(10, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join(&long)).unwrap(), b"ok");
    }

    /// OCI-1: 途中で切れた tar は DataLoss。
    #[test]
    fn oci1_truncated_tar_is_data_loss() {
        let sb = Sandbox::new();
        let mut bytes = archive(&[file("f", 0o644, &[7u8; 2000])]);
        bytes.truncate(512 + 700);
        let e = extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb.root,
            ExtractLimits::new(10, 1 << 20, 1 << 30, 1 << 20),
        )
        .expect_err("truncated");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// メモリ上の gzip を走査のたびに先頭から読み直す試験用 `LayerSource`。
    ///
    /// 旧入口 `extract_layer_blob(s)*` の廃止後も、gzip トレーラの検証と展開後サイズの上限を `extract_stack` の
    /// 経路で（Seek 不要・3 OS で）確かめるために置く（#2535・OCI-1）。
    struct MemGzip<'g> {
        gz: &'g [u8],
        max_uncompressed_bytes: u64,
    }

    impl LayerSource for MemGzip<'_> {
        type Reader<'a>
            = LayerReader<&'a [u8]>
        where
            Self: 'a;

        fn open(&mut self) -> Result<LayerReader<&[u8]>, OciError> {
            Ok(LayerReader::Gzip(Box::new(GzipLayerReader::new(
                self.gz,
                self.max_uncompressed_bytes,
            ))))
        }
    }

    fn extract_mem_gzip(
        sb: &Sandbox,
        gz: &[u8],
        max_uncompressed_bytes: u64,
        lim: ExtractLimits,
    ) -> Result<Vec<ExtractedLayer>, OciError> {
        extract_stack(
            &NoopOciOpRecorder,
            [MemGzip {
                gz,
                max_uncompressed_bytes,
            }],
            &sb.root,
            lim,
            host_lstat,
            SpecialSetup::host(SpecialBitsPolicy::Strip),
        )
    }

    /// OCI-1: gzip トレーラ破損は終端後の読み捨てで DataLoss になる。上限は gzip 側でも効く。
    #[test]
    fn oci1_gzip_trailer_is_verified_after_tar_end() {
        let tar_bytes = archive(&[file("f", 0o644, b"hello")]);
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&tar_bytes).unwrap();
        let gz = e.finish().unwrap();
        let lim = ExtractLimits::new(10, 100, 1 << 30, 1 << 20);

        let sb = Sandbox::new();
        let r = extract_mem_gzip(&sb, &gz, 1 << 20, lim).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].bytes, 5);

        let mut bad = gz.clone();
        let n = bad.len();
        bad[n - 8] ^= 0xff; // CRC32 を壊す。
        let sb = Sandbox::new();
        let e = extract_mem_gzip(&sb, &bad, 1 << 20, lim).expect_err("crc");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        // トレーラの検証はパス 1（副作用なし）の終端で行うため、rootfs には何も作られない（OCI-2）。
        assert!(names_in(&sb.root).is_empty());

        let sb = Sandbox::new();
        let e = extract_mem_gzip(&sb, &gz, 600, lim).expect_err("gzip limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// REPAIR-4: 成功と失敗でそれぞれ 1 件、種別 `oci.layer.extract` が記録される。
    #[test]
    fn repair4_records_extract_operation() {
        let c = Collect::default();
        let sb = Sandbox::new();
        extract_tar_with(
            &c,
            Cursor::new(archive(&[file("f", 0o644, b"x")])),
            &sb.root,
            ExtractLimits::new(10, 10, 1 << 30, 1 << 20),
        )
        .unwrap();
        // 展開先は空である必要があるため、失敗側は別のステージングで行う。
        let sb = Sandbox::new();
        extract_tar_with(
            &c,
            Cursor::new(archive(&[file("../f", 0o644, b"x")])),
            &sb.root,
            ExtractLimits::new(10, 10, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        let items = c.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind().as_str(), "oci.layer.extract");
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }

    /// 開くたびに失敗する試験用 `LayerSource`（`LayerSource::open` の失敗の記録を確かめる）。
    struct FailingOpen;

    impl LayerSource for FailingOpen {
        type Reader<'a>
            = LayerReader<&'a [u8]>
        where
            Self: 'a;

        fn open(&mut self) -> Result<LayerReader<&[u8]>, OciError> {
            Err(err(OciErrorCode::NotFound, "layer blob is missing"))
        }
    }

    /// REPAIR-4: レイヤー入力を開く失敗も `oci.layer.extract` の失敗として 1 件記録される。
    /// ハンドル版の open 失敗（`VerifiedLayerBlob::open_with`）は layer.rs 側の試験が確かめる。
    #[test]
    fn repair4_records_blob_open_failure() {
        let c = Collect::default();
        let sb = Sandbox::new();
        let e = extract_stack(
            &c,
            [FailingOpen],
            &sb.root,
            ExtractLimits::new(1, 1, 1 << 30, 1 << 20),
            host_lstat,
            SpecialSetup::host(SpecialBitsPolicy::Strip),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        let items = c.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind().as_str(), "oci.layer.extract");
        assert_eq!(items[0].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[0].error_code(), Some(e.code()));
    }

    /// 終端後に巨大データを付加した入力は、ファイル本体が 0 件でも入力上限で打ち切る（OCI-1）。
    #[test]
    fn trailing_garbage_exceeding_input_limit_is_rejected() {
        let sb = Sandbox::new();
        let mut bytes = archive(&[]);
        bytes.extend(std::iter::repeat_n(0u8, 1 << 20));
        let e = extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb.root,
            ExtractLimits::new(0, 0, 64 * 1024, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// 入力がちょうど上限バイトなら受理する（境界）。
    #[test]
    fn input_exactly_at_limit_is_accepted() {
        let sb = Sandbox::new();
        let bytes = archive(&[]);
        let len = bytes.len() as u64;
        extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb.root,
            ExtractLimits::new(0, 0, len, 1 << 20),
        )
        .unwrap();
        let sb2 = Sandbox::new();
        let e = extract_tar(
            Cursor::new(bytes.as_slice()),
            &sb2.root,
            ExtractLimits::new(0, 0, len - 1, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// root が通常ファイルなら InvalidArgument。
    #[test]
    fn root_must_be_directory() {
        let sb = Sandbox::new();
        let f = sb.base.join("sentinel");
        let e = extract_tar(
            Cursor::new(archive(&[])),
            &f,
            ExtractLimits::new(1, 1, 1 << 30, 1 << 20),
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// 非 unix ホストでは symlink エントリを Unimplemented で拒否する。
    #[cfg(not(unix))]
    #[test]
    fn symlink_is_unimplemented_on_non_unix() {
        let sb = Sandbox::new();
        assert_eq!(
            code(run(&sb, &[symlink("a", "b")])),
            OciErrorCode::Unimplemented
        );
    }

    // ---- 特殊ビットのポリシー（SEC-5・SEC-1・#1810） ----

    /// uid / gid を指定した通常ファイルのエントリを組み立てる。
    #[cfg(unix)]
    fn file_owned(name: &str, mode: u32, uid: u64, gid: u64, data: &[u8]) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_entry_type(EntryType::Regular);
        h.set_mode(mode);
        h.set_uid(uid);
        h.set_gid(gid);
        h.set_size(data.len() as u64);
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    fn owner_1000(_m: &fs::Metadata) -> (u32, u32) {
        (1000, 1000)
    }

    #[cfg(target_os = "linux")]
    fn owner_root(_m: &fs::Metadata) -> (u32, u32) {
        (0, 0)
    }

    /// コンテナ内 0 を host 1000 へ写す 1 行の写像（uid・gid 共通）。
    #[cfg(unix)]
    fn policy_1000() -> SpecialBitsPolicy {
        let r = IdRange {
            container_id: 0,
            host_id: 1000,
            count: 1,
        };
        SpecialBitsPolicy::PreserveIfOwnerMapped { uid: r, gid: r }
    }

    #[cfg(unix)]
    fn run_policy(
        sb: &Sandbox,
        entries: &[Vec<u8>],
        policy: SpecialBitsPolicy,
        owner_of: OwnerOf,
    ) -> ExtractedLayer {
        run_setup(
            sb,
            entries,
            SpecialSetup {
                owner_of,
                ..SpecialSetup::host(policy)
            },
        )
    }

    /// `SpecialSetup` を丸ごと渡して 1 レイヤーを展開する（読み戻しの差し替え用。#2251 P2-6）。
    #[cfg(unix)]
    fn run_setup(sb: &Sandbox, entries: &[Vec<u8>], setup: SpecialSetup) -> ExtractedLayer {
        let tar = archive(entries);
        single(
            extract_stack(
                &NoopOciOpRecorder,
                [Rewind::new(Cursor::new(tar.as_slice()))],
                &sb.root,
                LIM(),
                host_lstat,
                setup,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn chmod_root(sb: &Sandbox, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&sb.root, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn special_entries() -> Vec<Vec<u8>> {
        vec![
            file_owned("suid", 0o4755, 0, 0, b"a"),
            file_owned("sgid", 0o2755, 0, 0, b"b"),
            file_owned("both", 0o6711, 0, 0, b"c"),
            file_owned("sticky", 0o1644, 0, 0, b"d"),
            file_owned("plain", 0o755, 0, 0, b"e"),
        ]
    }

    /// SEC-5: root が 0700 で所有者が写像に収まるとき、setuid / setgid / sticky を tar の値どおりに適用する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_special_bits_preserved_when_owner_mapped() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_policy(&sb, &special_entries(), policy_1000(), owner_1000);
        assert_eq!(r.special_bits.decision, SpecialBitsDecision::Evaluated);
        assert_eq!(r.special_bits.preserved_files, 4);
        assert_eq!(r.files_with_stripped_special_bits, 0);
        for (name, want) in [
            ("suid", 0o4755),
            ("sgid", 0o2755),
            ("both", 0o6711),
            ("sticky", 0o1644),
            ("plain", 0o755),
        ] {
            assert_eq!(mode_of(&sb.root.join(name)), want, "{name}");
        }
    }

    /// SEC-5: root が group / other に開かれている（0755）と、全ビットを落として件数を返す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_special_bits_stripped_when_root_is_accessible_by_others() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o755);
        let r = run_policy(&sb, &special_entries(), policy_1000(), owner_1000);
        assert_eq!(
            r.special_bits.decision,
            SpecialBitsDecision::RootAccessibleByOthers
        );
        assert_eq!(r.special_bits.preserved_files, 0);
        assert_eq!(r.files_with_stripped_special_bits, 4);
        let sb_bits = r.special_bits.stripped_bits;
        assert_eq!((sb_bits.setuid, sb_bits.setgid, sb_bits.sticky), (2, 2, 1));
        for (name, want) in [
            ("suid", 0o755),
            ("sgid", 0o755),
            ("both", 0o711),
            ("sticky", 0o644),
        ] {
            assert_eq!(mode_of(&sb.root.join(name)), want, "{name}");
        }
    }

    /// SEC-5: tar 上の所有者が写像外のファイルは setuid / setgid を落とし、写像内のファイルは残す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_special_bits_dropped_when_tar_owner_is_not_mapped() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_policy(
            &sb,
            &[
                file_owned("mapped", 0o6755, 0, 0, b"a"),
                file_owned("other_uid", 0o4755, 100, 0, b"b"),
                file_owned("other_gid", 0o2755, 0, 100, b"c"),
            ],
            policy_1000(),
            owner_1000,
        );
        assert_eq!(r.special_bits.preserved_files, 1);
        assert_eq!(r.files_with_stripped_special_bits, 2);
        assert_eq!(mode_of(&sb.root.join("mapped")), 0o6755);
        assert_eq!(mode_of(&sb.root.join("other_uid")), 0o755);
        assert_eq!(mode_of(&sb.root.join("other_gid")), 0o755);
    }

    /// SEC-5 / SEC-1: 書いたファイルの所有者が host root（uid / gid 0）なら setuid / setgid を残さない。
    /// sticky だけの mode は、ポリシー全体の条件を満たすため残る。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_special_bits_dropped_when_file_owner_is_host_root() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let root_map = IdRange {
            container_id: 0,
            host_id: 0,
            count: 1,
        };
        let policy = SpecialBitsPolicy::PreserveIfOwnerMapped {
            uid: root_map,
            gid: root_map,
        };
        let r = run_policy(&sb, &special_entries(), policy, owner_root);
        assert_eq!(r.special_bits.preserved_files, 1);
        assert_eq!(r.files_with_stripped_special_bits, 3);
        assert_eq!(mode_of(&sb.root.join("suid")), 0o755);
        assert_eq!(mode_of(&sb.root.join("sgid")), 0o755);
        assert_eq!(mode_of(&sb.root.join("both")), 0o711);
        assert_eq!(mode_of(&sb.root.join("sticky")), 0o1644);
    }

    /// SEC-5: グローバル PAX の uid / gid が写像外なら、通常ヘッダが写像内でも setuid / setgid を落とす。
    /// エントリ固有の PAX はグローバルより優先される（写像内に戻せば残る）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_global_pax_owner_overrides_header_owner() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let mut body = pax_record("uid", "100");
        body.extend(pax_record("gid", "100"));
        let global = raw_entry(
            b"pax_global",
            EntryType::XGlobalHeader,
            b"",
            0o644,
            body.len() as u64,
            &body,
        );
        let local = pax_record("uid", "0");
        let local_hdr = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            local.len() as u64,
            &local,
        );
        let r = run_policy(
            &sb,
            &[
                global,
                file_owned("global_out", 0o6755, 0, 0, b"a"),
                local_hdr,
                file_owned("local_in", 0o4755, 0, 0, b"b"),
            ],
            policy_1000(),
            owner_1000,
        );
        assert_eq!(r.special_bits.preserved_files, 1);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(mode_of(&sb.root.join("global_out")), 0o755);
        assert_eq!(mode_of(&sb.root.join("local_in")), 0o4755);
    }

    /// SEC-5: PAX の `uid` が数値でないときは tar の uid を信用せず、setuid を落とす。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_special_bits_dropped_when_pax_uid_is_malformed() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let body = pax_record("uid", "not-a-number");
        let px = raw_entry(
            b"pax",
            EntryType::XHeader,
            b"",
            0o644,
            body.len() as u64,
            &body,
        );
        let r = run_policy(
            &sb,
            &[px, file_owned("suid", 0o4755, 0, 0, b"a")],
            policy_1000(),
            owner_1000,
        );
        assert_eq!(r.special_bits.preserved_files, 0);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(mode_of(&sb.root.join("suid")), 0o755);
    }

    /// SEC-5: PAX の空値 `uid` は指定の解除で、通常ヘッダの所有者（写像内）へ戻るため setuid が残る。
    /// グローバルの空値もエントリ固有の空値も同じ。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_empty_pax_uid_unsets_override() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let mk = |name: &'static [u8], ty: EntryType, body: &[u8]| {
            raw_entry(name, ty, b"", 0o644, body.len() as u64, body)
        };
        let g1 = mk(
            b"pax_global",
            EntryType::XGlobalHeader,
            &pax_record("uid", "100"),
        );
        let g2 = mk(
            b"pax_global2",
            EntryType::XGlobalHeader,
            &pax_record("uid", ""),
        );
        let l1 = mk(b"pax", EntryType::XHeader, &pax_record("uid", ""));
        let r = run_policy(
            &sb,
            &[
                g1,
                g2,
                file_owned("global_unset", 0o4755, 0, 0, b"a"),
                l1,
                file_owned("local_unset", 0o4755, 0, 0, b"b"),
            ],
            policy_1000(),
            owner_1000,
        );
        assert_eq!(r.special_bits.preserved_files, 2);
        assert_eq!(mode_of(&sb.root.join("global_unset")), 0o4755);
        assert_eq!(mode_of(&sb.root.join("local_unset")), 0o4755);
    }

    /// SEC-5: ポリシーが `Strip` なら、条件が整っていても落とす。
    #[cfg(unix)]
    #[test]
    fn sec5_strip_policy_ignores_owner_mapping() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_policy(
            &sb,
            &special_entries(),
            SpecialBitsPolicy::Strip,
            owner_1000,
        );
        assert_eq!(r.special_bits.decision, SpecialBitsDecision::StripPolicy);
        assert_eq!(r.files_with_stripped_special_bits, 4);
        assert_eq!(mode_of(&sb.root.join("both")), 0o711);
    }

    /// SEC-5: Linux 以外の unix では `PreserveIfOwnerMapped` でも落とす。
    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn sec5_non_linux_host_always_strips() {
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_policy(&sb, &special_entries(), policy_1000(), owner_1000);
        assert_eq!(
            r.special_bits.decision,
            SpecialBitsDecision::UnsupportedHost
        );
        assert_eq!(r.files_with_stripped_special_bits, 4);
    }

    /// OCI-1: ディレクトリの setgid（遅延適用の経路を含む）は、どのポリシーでも tar の値で適用する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci1_directory_setgid_is_applied() {
        use std::os::unix::fs::MetadataExt as _;
        for policy in [SpecialBitsPolicy::Strip, policy_1000()] {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            run_policy(
                &sb,
                &[
                    dir("shared/", 0o2775),
                    file_owned("shared/f", 0o644, 0, 0, b"x"),
                    dir("locked/", 0o2555),
                    dir("tmp/", 0o1777),
                ],
                policy,
                owner_1000,
            );
            assert_eq!(mode_of(&sb.root.join("shared")), 0o2775);
            assert_eq!(mode_of(&sb.root.join("locked")), 0o2555);
            assert_eq!(mode_of(&sb.root.join("tmp")), 0o1777);
            let gid = |p: &str| fs::metadata(sb.root.join(p)).unwrap().gid();
            assert_eq!(gid("shared/f"), gid("shared"));
        }
    }

    /// SEC-5: `IdRange::map_to_host` の境界（範囲外・長さ 0・オーバーフローは `None`）。
    #[test]
    fn sec5_id_range_maps_with_checked_arithmetic() {
        let r = IdRange {
            container_id: 10,
            host_id: 1000,
            count: 3,
        };
        assert_eq!(r.map_to_host(9), None);
        assert_eq!(r.map_to_host(10), Some(1000));
        assert_eq!(r.map_to_host(12), Some(1002));
        assert_eq!(r.map_to_host(13), None);
        let empty = IdRange { count: 0, ..r };
        assert_eq!(empty.map_to_host(10), None);
        let wrap = IdRange {
            container_id: 0,
            host_id: u32::MAX,
            count: 5,
        };
        assert_eq!(wrap.map_to_host(0), Some(u32::MAX));
        assert_eq!(wrap.map_to_host(1), None);
    }

    /// SEC-5: `special_bits_to_keep` の条件の組み合わせを具体値で照合する。
    #[test]
    fn sec5_special_bits_to_keep_matrix() {
        let r = IdRange {
            container_id: 0,
            host_id: 1000,
            count: 1,
        };
        let ctx = SpecialCtx {
            decision: SpecialBitsDecision::Evaluated,
            ranges: Some((r, r)),
            root_uid: 1000,
            owner_of: owner_1000,
            chowned_mode: false,
            in_userns: false,
        };
        let all = S_ISUID | S_ISGID | S_ISVTX;
        let k = |req, ids, owner| special_bits_to_keep(req, ids, owner, &ctx);
        assert_eq!(k(all, (Some(0), Some(0)), (1000, 1000)), all);
        assert_eq!(k(all, (Some(1), Some(0)), (1000, 1000)), S_ISGID | S_ISVTX);
        assert_eq!(k(all, (Some(0), Some(1)), (1000, 1000)), S_ISUID | S_ISVTX);
        assert_eq!(k(all, (None, None), (1000, 1000)), S_ISVTX);
        // root の所有者とファイルの所有者が違うなら何も残さない。
        assert_eq!(k(all, (Some(0), Some(0)), (1001, 1000)), 0);
        // ホスト root 所有（uid / gid 0）は写像が 0 を指していても setuid / setgid を残さない。
        let root_map = IdRange {
            container_id: 0,
            host_id: 0,
            count: 1,
        };
        let root_ctx = SpecialCtx {
            ranges: Some((root_map, root_map)),
            root_uid: 0,
            ..ctx
        };
        assert_eq!(
            special_bits_to_keep(all, (Some(0), Some(0)), (0, 0), &root_ctx),
            S_ISVTX
        );
        // rootful（所有 uid 0）は gid が 0 でなく写像と一致しても setgid を残さない（#2251 P2-1）。
        let gid_map = IdRange {
            container_id: 0,
            host_id: 1000,
            count: 1,
        };
        let rootful_ctx = SpecialCtx {
            ranges: Some((root_map, gid_map)),
            root_uid: 0,
            ..ctx
        };
        assert_eq!(
            special_bits_to_keep(all, (Some(0), Some(0)), (0, 1000), &rootful_ctx),
            S_ISVTX
        );
        let strip = SpecialCtx::strip();
        assert_eq!(
            special_bits_to_keep(all, (Some(0), Some(0)), (1000, 1000), &strip),
            0
        );
    }

    /// 特殊ビットのビットごとの件数の加算（#2251 P2-6）。
    #[test]
    fn sec5_special_bit_counts_add_bits() {
        let mut c = SpecialBitCounts::default();
        c.add_bits(0o7000);
        c.add_bits(0o4000);
        c.add_bits(0);
        assert_eq!((c.setuid, c.setgid, c.sticky), (2, 1, 1));
    }

    /// OCI-2: グローバル PAX ヘッダも `max_entries` の件数に数える。公開の `entries` には含めない（#2251 P2-3）。
    #[test]
    fn oci2_global_pax_headers_count_toward_entry_limit() {
        let body = pax_record("comment", "x");
        let mut es: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                raw_entry(
                    b"pax_global",
                    EntryType::XGlobalHeader,
                    b"",
                    0o644,
                    body.len() as u64,
                    &body,
                )
            })
            .collect();
        es.push(file("a", 0o644, b"1"));
        let sb = Sandbox::new();
        let r = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(4, 100, 1 << 30, 1 << 20),
        )
        .unwrap();
        assert_eq!(r.entries, 1);

        let sb = Sandbox::new();
        let e = extract_tar(
            Cursor::new(archive(&es)),
            &sb.root,
            ExtractLimits::new(3, 100, 1 << 30, 1 << 20),
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the entry count limit");
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-2: グローバル PAX ヘッダの件数は複数レイヤーで累積する（#2251 P2-3）。
    #[test]
    fn oci2_global_pax_headers_accumulate_across_layers() {
        let body = pax_record("comment", "x");
        let layer = || -> Vec<Vec<u8>> {
            (0..2)
                .map(|_| {
                    raw_entry(
                        b"pax_global",
                        EntryType::XGlobalHeader,
                        b"",
                        0o644,
                        body.len() as u64,
                        &body,
                    )
                })
                .collect()
        };
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[layer(), layer()],
            ExtractLimits::new(3, 100, 1 << 30, 1 << 20),
            host_lstat,
        )
        .expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// SEC-5: 所有 uid が host root のファイルは、gid が 0 でなくても setgid を落とす（#2251 P2-1）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_setgid_dropped_when_file_owner_uid_is_host_root() {
        fn owner_root_uid(_m: &fs::Metadata) -> (u32, u32) {
            (0, 1000)
        }
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_policy(
            &sb,
            &[file_owned("sgid", 0o2755, 0, 0, b"a")],
            policy_1000(),
            owner_root_uid,
        );
        assert_eq!(mode_of(&sb.root.join("sgid")), 0o755);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(r.special_bits.preserved_files, 0);
        assert_eq!(r.special_bits.stripped_bits.setgid, 1);
    }

    /// REPAIR-4: setgid だけが読み戻しで落ちたとき、残った setuid を「落とした」と数えない（#2251 P2-6）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec5_readback_setgid_only_drop_does_not_count_setuid_as_stripped() {
        fn without_setgid(f: &fs::File) -> u32 {
            special_bits_of(f) & !S_ISGID
        }
        let sb = Sandbox::new();
        chmod_root(&sb, 0o700);
        let r = run_setup(
            &sb,
            &[file_owned("both", 0o6755, 0, 0, b"a")],
            SpecialSetup {
                owner_of: owner_1000,
                mode_readback: without_setgid,
                ..SpecialSetup::host(policy_1000())
            },
        );
        let b = r.special_bits;
        assert_eq!(b.preserved_files, 0);
        assert_eq!(r.files_with_stripped_special_bits, 1);
        assert_eq!(
            (
                b.stripped_bits.setuid,
                b.stripped_bits.setgid,
                b.stripped_bits.sticky
            ),
            (0, 1, 0)
        );
        assert_eq!(
            (
                b.preserved_bits.setuid,
                b.preserved_bits.setgid,
                b.preserved_bits.sticky
            ),
            (1, 0, 0)
        );
    }
    // ---- 複数レイヤーの重ね合わせ（TASK-52.4・OCI-1・#410） ----

    const LIM: fn() -> ExtractLimits = || ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20);

    fn run_stack(
        sb: &Sandbox,
        layers: &[Vec<Vec<u8>>],
        limits: ExtractLimits,
        lstat: Lstat,
    ) -> Result<Vec<ExtractedLayer>, OciError> {
        let tars: Vec<Vec<u8>> = layers.iter().map(|l| archive(l)).collect();
        extract_stack(
            &NoopOciOpRecorder,
            tars.iter().map(|t| Rewind::new(Cursor::new(t.as_slice()))),
            &sb.root,
            limits,
            lstat,
            SpecialSetup::host(SpecialBitsPolicy::Strip),
        )
    }

    /// OCI-1: 上位レイヤーが下位の同名ファイルを上書きし、下位だけのファイルは残る。結果はレイヤーごと。
    #[test]
    fn oci1_stack_upper_layer_overwrites_lower() {
        let sb = Sandbox::new();
        let r = run_stack(
            &sb,
            &[
                vec![file("f", 0o644, b"lower-long"), file("keep", 0o644, b"k")],
                vec![file("f", 0o644, b"up"), file("new", 0o644, b"n")],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap();
        assert_eq!(
            r.iter().map(|l| (l.entries, l.bytes)).collect::<Vec<_>>(),
            vec![(2, 11), (2, 3)]
        );
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"up");
        assert_eq!(fs::read(sb.root.join("keep")).unwrap(), b"k");
        assert_eq!(fs::read(sb.root.join("new")).unwrap(), b"n");
        assert_eq!(names_in(&sb.root), vec!["f", "keep", "new"]);
    }

    /// OCI-1: root が空でなければ最初のレイヤーの前に拒否し、既存項目に触れない。
    #[test]
    fn oci1_stack_rejects_non_empty_root() {
        let sb = Sandbox::new();
        fs::write(sb.root.join("pre"), b"x").unwrap();
        let e = run_stack(&sb, &[vec![file("f", 0o644, b"a")]], LIM(), host_lstat).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(names_in(&sb.root), vec!["pre"]);
    }

    /// OCI-1: 空のレイヤー列は InvalidArgument。
    #[test]
    fn oci1_stack_rejects_empty_layer_list() {
        let sb = Sandbox::new();
        let e = run_stack(&sb, &[], LIM(), host_lstat).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
    }

    /// OCI-1: エントリ数の上限は全レイヤーで累積する（各レイヤーは 2 件、上限 3）。
    #[test]
    fn oci1_stack_entry_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [
            vec![file("a", 0o644, b"1"), file("b", 0o644, b"1")],
            vec![file("c", 0o644, b"1"), file("d", 0o644, b"1")],
        ];
        let e = run_stack(
            &sb,
            &layers,
            ExtractLimits::new(3, 1 << 20, 1 << 30, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer exceeds the entry count limit");
    }

    /// OCI-1: 展開バイト数の上限は全レイヤーで累積する（各 6 バイト、上限 10）。
    #[test]
    fn oci1_stack_total_bytes_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [
            vec![file("a", 0o644, b"123456")],
            vec![file("b", 0o644, b"123456")],
        ];
        let e = run_stack(
            &sb,
            &layers,
            ExtractLimits::new(100, 10, 1 << 30, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// OCI-1: 入力バイト数の上限も全レイヤーで累積する（1 レイヤー 2048 バイト、上限 3000）。
    #[test]
    fn oci1_stack_input_limit_accumulates() {
        let sb = Sandbox::new();
        let layers = [vec![file("a", 0o644, b"1")], vec![file("b", 0o644, b"1")]];
        // 1 レイヤーは 512（ヘッダ）+ 512（データ）+ 1024（終端）= 2048 バイト。
        assert!(
            run_stack(
                &sb,
                &layers[..1],
                ExtractLimits::new(100, 1 << 20, 3000, 1 << 20),
                host_lstat
            )
            .is_ok()
        );
        let sb2 = Sandbox::new();
        let e = run_stack(
            &sb2,
            &layers,
            ExtractLimits::new(100, 1 << 20, 3000, 1 << 20),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "layer tar stream exceeds the input size limit");
    }

    /// IO-5 / OCI-1: 別表記の衝突検出はレイヤーをまたいで効く（下位の `f` に上位が `F` の hardlink を張れない）。
    #[test]
    fn io5_stack_alias_spelling_collision_across_layers() {
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[vec![file("f", 0o644, b"orig")], vec![hardlink("F", "f")]],
            LIM(),
            folding_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"orig");
        assert_eq!(names_in(&sb.root), vec!["f"]);
    }

    /// 別表記の衝突として拒否されたこと（レイヤー積み上げ版。`code` と `message` の具体値）を確かめる。
    fn assert_stack_spelling_collision(r: Result<Vec<ExtractedLayer>, OciError>) {
        let e = r.expect_err("must be rejected as a spelling collision");
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(e.code().as_str(), "ALREADY_EXISTS");
        assert_eq!(
            e.message(),
            "entry name resolves to an existing entry with a different spelling \
             (case or Unicode normalization) on the destination filesystem"
        );
    }

    /// IO-5・OCI-1・OCI-2: 区別しない FS（`folding_lstat` の模擬。ホスト FS に依らない）で、上位レイヤーが
    /// 別表記（大文字小文字・NFC / NFD）の名前のエントリで下位の中身のあるディレクトリを置き換えようとすると、
    /// Changeset の置換（再帰削除）に入る前に拒否される。下位の木は残り、ルート外は変わらない。
    #[test]
    fn io5_stack_alias_entry_replacing_lower_dir_is_rejected() {
        // (case, 下位ディレクトリ名, 上位エントリ名)
        let names = [("case", "d", "D"), ("nfc-nfd", "caf\u{e9}", "cafe\u{301}")];
        for (case, lower, upper) in names {
            let uppers: Vec<(&str, Vec<u8>)> = vec![
                ("file", file(upper, 0o644, b"file-upper")),
                ("hardlink", hardlink(upper, "keep")),
            ];
            for (kind, upper_entry) in uppers {
                let sb = Sandbox::new();
                let lower_dir = format!("{lower}/");
                let lower_x = format!("{lower}/x");
                let lower_y = format!("{lower}/sub/y");
                let r = run_stack(
                    &sb,
                    &[
                        vec![
                            dir(&lower_dir, 0o755),
                            file(&lower_x, 0o644, b"x"),
                            file(&lower_y, 0o644, b"y"),
                            file("keep", 0o644, b"k"),
                        ],
                        vec![upper_entry],
                    ],
                    LIM(),
                    folding_lstat,
                );
                assert_stack_spelling_collision(r);
                let msg = format!("case={case} kind={kind}");
                let mut expect = vec![lower.to_string(), "keep".to_string()];
                expect.sort();
                assert_eq!(names_in(&sb.root), expect, "{msg}");
                let ld = sb.root.join(lower);
                assert!(fs::symlink_metadata(&ld).unwrap().is_dir(), "{msg}");
                assert_eq!(names_in(&ld), vec!["sub", "x"], "{msg}");
                assert_eq!(fs::read(ld.join("x")).unwrap(), b"x", "{msg}");
                assert_eq!(fs::read(ld.join("sub/y")).unwrap(), b"y", "{msg}");
                assert_eq!(fs::read(sb.root.join("keep")).unwrap(), b"k", "{msg}");
                sb.assert_outside_untouched();
            }
        }
    }

    /// 別表記の whiteout・不透明マーカー検証用の下位レイヤー（`d/{x,sub/y}`・`café/z`・`keep`・`f`）。
    fn alias_marker_lower() -> Vec<Vec<u8>> {
        vec![
            dir("d/", 0o755),
            file("d/x", 0o644, b"x"),
            file("d/sub/y", 0o644, b"y"),
            dir("caf\u{e9}/", 0o755),
            file("caf\u{e9}/z", 0o644, b"z"),
            file("keep", 0o644, b"k"),
            file("f", 0o644, b"F-lower"),
        ]
    }

    /// 下位レイヤー（`alias_marker_lower`）の木がそのまま残っていることを具体値で確かめる。
    fn assert_alias_marker_lower_intact(sb: &Sandbox, msg: &str) {
        assert_eq!(
            names_in(&sb.root),
            vec!["caf\u{e9}", "d", "f", "keep"],
            "{msg}"
        );
        assert_eq!(names_in(&sb.root.join("d")), vec!["sub", "x"], "{msg}");
        assert_eq!(names_in(&sb.root.join("d/sub")), vec!["y"], "{msg}");
        assert_eq!(names_in(&sb.root.join("caf\u{e9}")), vec!["z"], "{msg}");
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"x", "{msg}");
        assert_eq!(fs::read(sb.root.join("d/sub/y")).unwrap(), b"y", "{msg}");
        assert_eq!(
            fs::read(sb.root.join("caf\u{e9}/z")).unwrap(),
            b"z",
            "{msg}"
        );
        assert_eq!(fs::read(sb.root.join("keep")).unwrap(), b"k", "{msg}");
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"F-lower", "{msg}");
        sb.assert_outside_untouched();
    }

    /// IO-5・OCI-2: 区別しない FS（`folding_lstat` の模擬）で、上位レイヤーの whiteout（`.wh.<名前>`）・不透明
    /// ディレクトリ（`.wh..wh..opq`）が、対象または親を別表記（大文字小文字・NFC / NFD）の名前で指すと、
    /// 別表記の衝突として拒否される。名前は書き換えず（`F` を `f` と見なして消さない）、下位の木とルート外は
    /// 変わらず、マーカー名も書かれない。有効なマーカーと混在させても、削除の前に全解決を済ませるため
    /// 有効側も適用されない（パス 2 の解決の先行）。
    #[test]
    fn io5_oci2_stack_alias_markers_are_rejected_without_removal() {
        let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            ("wh-target-case", vec![wh(".wh.F")]),
            ("wh-target-case-dir", vec![wh(".wh.D")]),
            ("wh-target-nfd", vec![wh(".wh.cafe\u{301}")]),
            ("wh-parent-case", vec![wh("D/.wh.x")]),
            ("wh-parent-nfd", vec![wh("cafe\u{301}/.wh.z")]),
            ("opq-parent-case", vec![wh("D/.wh..wh..opq")]),
            ("opq-parent-nfd", vec![wh("cafe\u{301}/.wh..wh..opq")]),
            ("valid-then-alias", vec![wh(".wh.keep"), wh("D/.wh.x")]),
            ("alias-then-valid", vec![wh("D/.wh.x"), wh(".wh.keep")]),
        ];
        for (case, upper) in cases {
            let sb = Sandbox::new();
            let r = run_stack(&sb, &[alias_marker_lower(), upper], LIM(), folding_lstat);
            assert_stack_spelling_collision(r);
            assert_alias_marker_lower_intact(&sb, case);
        }
    }

    /// IO-5・OCI-2: 上の拒否が模擬の過剰反応でないことの対照。同じ綴りのマーカーは効く。
    #[test]
    fn io5_oci2_stack_same_spelling_markers_still_apply() {
        let sb = Sandbox::new();
        run_stack(
            &sb,
            &[alias_marker_lower(), vec![wh(".wh.f")]],
            LIM(),
            folding_lstat,
        )
        .unwrap();
        assert_eq!(names_in(&sb.root), vec!["caf\u{e9}", "d", "keep"]);
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"x");

        let sb = Sandbox::new();
        run_stack(
            &sb,
            &[alias_marker_lower(), vec![wh("d/.wh..wh..opq")]],
            LIM(),
            folding_lstat,
        )
        .unwrap();
        assert!(fs::symlink_metadata(sb.root.join("d")).unwrap().is_dir());
        assert!(names_in(&sb.root.join("d")).is_empty());
        assert_eq!(fs::read(sb.root.join("keep")).unwrap(), b"k");
        sb.assert_outside_untouched();
    }

    /// OCI-1: 上位レイヤーの `..` は既存どおり拒否され、ルート外へは何も書かれない。
    #[test]
    fn oci1_stack_upper_layer_traversal_is_rejected() {
        let sb = Sandbox::new();
        let e = run_stack(
            &sb,
            &[
                vec![file("f", 0o644, b"a")],
                vec![file("../escape", 0o644, b"x")],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        sb.assert_outside_untouched();
    }

    /// OCI-1・OCI-2: 上位レイヤーは下位レイヤー由来のノードを image-spec の「Changeset over existing files」に従い
    /// 置き換える（ディレクトリ同士は属性だけ、それ以外は既存パスを再帰削除してから作る）。下位の遅延 mode
    /// （0555）を持つディレクトリを消しても `finish_dirs` は成功する。
    #[test]
    fn oci1_stack_upper_layer_replaces_lower_nodes_by_changeset() {
        let sb = Sandbox::new();
        run_stack(
            &sb,
            &[
                vec![
                    dir("d/", 0o555),
                    file("d/x", 0o644, b"x"),
                    file("f", 0o644, b"lower-f"),
                    file("g", 0o644, b"lower-g"),
                    dir("e/", 0o700),
                    file("e/keep", 0o644, b"k"),
                ],
                vec![
                    file("d", 0o644, b"file-d"),
                    dir("f/", 0o755),
                    file("g/y", 0o644, b"y"),
                    dir("e/", 0o755),
                ],
            ],
            LIM(),
            host_lstat,
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("d")).unwrap(), b"file-d");
        assert!(sb.root.join("f").is_dir());
        assert!(names_in(&sb.root.join("f")).is_empty());
        assert_eq!(names_in(&sb.root.join("g")), vec!["y".to_string()]);
        assert_eq!(fs::read(sb.root.join("g/y")).unwrap(), b"y");
        assert_eq!(names_in(&sb.root.join("e")), vec!["keep".to_string()]);
        #[cfg(unix)]
        assert_eq!(mode_of(&sb.root.join("e")), 0o755);
        assert_eq!(names_in(&sb.root), vec!["d", "e", "f", "g"]);
    }

    /// OCI-1: 同じレイヤーの中でのディレクトリ → 非ディレクトリの型の衝突は、従来どおり `FailedPrecondition`
    /// （置き換えるのは下位レイヤー由来のノードだけ）。経路として通った下位のディレクトリも同じレイヤーの
    /// ノードとして扱い、配下に作った実体を消さない。image-spec は 1 つの changeset に同一パスの重複エントリを
    /// 含めてはならないと定めるため、同一レイヤー内の型の衝突は不正な入力として拒否するのが正しい（#2017）。
    #[test]
    fn oci1_stack_same_layer_type_conflicts_are_rejected() {
        for upper in [
            vec![dir("d/", 0o755), file("d", 0o644, b"f")],
            vec![file("d/y", 0o644, b"y"), file("d", 0o644, b"f")],
            vec![file("d", 0o644, b"f"), file("d/y", 0o644, b"y")],
            vec![file("n/y", 0o644, b"y"), symlink("n", "d")],
        ] {
            let sb = Sandbox::new();
            let e = run_stack(
                &sb,
                &[vec![file("d/x", 0o644, b"x")], upper],
                LIM(),
                host_lstat,
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        }
    }

    /// OCI-1: 下位が 0555 のディレクトリへ上位が書き込め、最終 mode は 0555（遅延適用は全レイヤー後）。
    #[cfg(unix)]
    #[test]
    fn oci1_stack_upper_writes_into_readonly_lower_dir() {
        let sb = Sandbox::new();
        run_stack(
            &sb,
            &[vec![dir("d/", 0o555)], vec![file("d/x", 0o644, b"up")]],
            LIM(),
            host_lstat,
        )
        .unwrap();
        assert_eq!(fs::read(sb.root.join("d/x")).unwrap(), b"up");
        assert_eq!(mode_of(&sb.root.join("d")), 0o555);
    }

    /// REPAIR-4: 各レイヤーを ExtractLayer として 1 回ずつ記録する。
    #[test]
    fn repair4_stack_records_one_sample_per_layer() {
        let sb = Sandbox::new();
        let rec = Collect::default();
        let tars = [
            archive(&[file("a", 0o644, b"1")]),
            archive(&[file("b", 0o644, b"1")]),
        ];
        extract_layers_with(
            &rec,
            tars.iter().map(|t| Cursor::new(t.as_slice())),
            &sb.root,
            LIM(),
        )
        .unwrap();
        let s = rec.0.lock().unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.kind() == OciOpKind::ExtractLayer));
        assert!(s.iter().all(|x| x.outcome() == OciOpOutcome::Success));
    }

    /// REPAIR-4: 最終のディレクトリ権限適用（finish_dirs）の失敗は最後のレイヤーの記録に Failure として含まれる。
    #[test]
    fn repair4_finish_dirs_failure_is_recorded() {
        struct SwapAtEof {
            data: std::io::Cursor<Vec<u8>>,
            dir: PathBuf,
            done: bool,
        }
        impl Read for SwapAtEof {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.data.read(buf)?;
                // パス 1（副作用なし）の EOF では `d` がまだ無い。パス 3 の EOF で差し替える。
                if n == 0 && !self.done && self.dir.is_dir() {
                    self.done = true;
                    fs::remove_dir(&self.dir)?;
                    fs::write(&self.dir, b"x")?;
                }
                Ok(n)
            }
        }
        impl Seek for SwapAtEof {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.data.seek(pos)
            }
        }
        let sb = Sandbox::new();
        let rec = Collect::default();
        let src = SwapAtEof {
            data: std::io::Cursor::new(archive(&[dir("d", 0o555)])),
            dir: sb.root.join("d"),
            done: false,
        };
        let e = extract_layers_with(&rec, [src], &sb.root, LIM()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let s = rec.items();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), OciOpOutcome::Failure);
        assert_eq!(s[0].error_code(), Some(OciErrorCode::FailedPrecondition));
    }

    /// 空レイヤーを無限に供給してもレイヤー数の上限で ResourceExhausted になる（結果 Vec が増え続けない）。
    #[test]
    fn stack_rejects_unbounded_empty_layers() {
        let sb = Sandbox::new();
        let layers = std::iter::repeat_with(|| Cursor::new(Vec::<u8>::new()));
        let e = extract_layers(layers, &sb.root, LIM()).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        assert_eq!(e.message(), "image exceeds the layer count limit");
    }

    // ---- whiteout の対象削除（TASK-53.1・OCI-2・#412） ----

    impl Extractor<'_> {
        /// whiteout 1 件だけのパス 2（`apply_markers`）。
        fn remove_whiteout_target(
            &mut self,
            parent: &[OsString],
            target: &OsStr,
        ) -> Result<(), OciError> {
            self.apply_markers(&[Marker::Whiteout {
                parent: parent.to_vec(),
                target: target.to_os_string(),
            }])
        }

        /// 不透明マーカー 1 件だけのパス 2（`apply_markers`）。
        fn clear_opaque_dir(&mut self, parent: &[OsString]) -> Result<(), OciError> {
            self.apply_markers(&[Marker::Opaque {
                parent: parent.to_vec(),
            }])
        }
    }

    fn ex_for(sb: &Sandbox, lstat: Lstat) -> Extractor<'_> {
        let limits = LIM();
        Extractor {
            root: &sb.root,
            anchor: AnchoredRoot::open(&sb.root, AnchorHooks::host()).unwrap(),
            limits,
            entries: 0,
            bytes: 0,
            stripped_special: 0,
            ignored_reserved: 0,
            preserved_special: 0,
            metered_entries: 0,
            preserved_bits: SpecialBitCounts::default(),
            stripped_bits: SpecialBitCounts::default(),
            mode_readback: special_bits_of,
            special: SpecialCtx::strip(),
            deferred_dirs: HashMap::new(),
            own: None,
            chowned: 0,
            names: NameIndex::new(limits.max_tracked_paths),
            layer_nodes: HashSet::new(),
            lstat,
            budget: ExtractBudget::new(),
        }
    }

    fn lay(ex: &mut Extractor<'_>, entries: &[Vec<u8>]) {
        extract_one_layer(ex, &mut Rewind::new(Cursor::new(archive(entries))), 1 << 30).unwrap();
    }

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// OCI-2: 下位の `d/foo` を whiteout すると rootfs から消え、同じディレクトリの `d/bar` は残る。
    #[test]
    fn oci2_whiteout_removes_lower_file_and_keeps_siblings() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[file("d/foo", 0o644, b"1"), file("d/bar", 0o644, b"2")],
        );
        ex.remove_whiteout_target(&os(&["d"]), OsStr::new("foo"))
            .unwrap();
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root.join("d")), vec!["bar".to_string()]);
        assert!(!sb.root.join("d/foo").exists());
        sb.assert_outside_untouched();
    }

    /// OCI-2: ディレクトリの whiteout は中身ごと再帰削除し、深いツリー・0555 の中間ディレクトリも消せる。
    #[test]
    #[cfg(unix)]
    fn oci2_whiteout_removes_directory_tree_recursively() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/sub/x", 0o644, b"1"),
                dir("d/ro", 0o755),
                file("d/ro/c", 0o644, b"c"),
                file("keep", 0o644, b"k"),
            ],
        );
        // 深いツリー（tar の名前長の制約を避け、ディスク上に直接作る）と、権限を落とした中間ディレクトリ。
        let deep: PathBuf = (0..60).map(|i| format!("n{i}")).collect();
        fs::create_dir_all(sb.root.join("d").join(&deep)).unwrap();
        fs::write(sb.root.join("d").join(&deep).join("leaf"), b"z").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(sb.root.join("d/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        }
        ex.remove_whiteout_target(&[], OsStr::new("d")).unwrap();
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root), vec!["keep".to_string()]);
        sb.assert_outside_untouched();
    }

    /// OCI-2: symlink を whiteout してもリンク先の実体は残る。親が symlink でも root 外へ出ない。
    #[test]
    #[cfg(unix)]
    fn oci2_whiteout_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/f", 0o644, b"r"),
                symlink("link", "real"),
                symlink("esc", "/"),
                file("real/g", 0o644, b"g"),
            ],
        );
        ex.remove_whiteout_target(&[], OsStr::new("link")).unwrap();
        assert!(fs::symlink_metadata(sb.root.join("link")).is_err());
        assert_eq!(fs::read(sb.root.join("real/f")).unwrap(), b"r");
        // 親が root 外を指す symlink でも root に閉じ込められ、外部の番兵は無傷。
        ex.remove_whiteout_target(&os(&["esc"]), OsStr::new("sentinel"))
            .unwrap();
        ex.remove_whiteout_target(&os(&["real"]), OsStr::new("g"))
            .unwrap();
        assert_eq!(names_in(&sb.root.join("real")), vec!["f".to_string()]);
        sb.assert_outside_untouched();
    }

    /// OCI-2: 存在しない対象・存在しない親・非ディレクトリの親は何もしない（下位に消す実体が無い）。
    #[test]
    fn oci2_whiteout_missing_target_or_parent_is_noop() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        ex.remove_whiteout_target(&[], OsStr::new("nope")).unwrap();
        ex.remove_whiteout_target(&os(&["no", "dir"]), OsStr::new("x"))
            .unwrap();
        ex.remove_whiteout_target(&os(&["f"]), OsStr::new("x"))
            .unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
        assert_eq!(names_in(&sb.root), vec!["f".to_string()]);
    }

    /// OCI-2: 遅延 mode のディレクトリ（mode 0）を whiteout した後でも `finish_dirs` が成功する。
    #[test]
    fn oci2_whiteout_clears_deferred_dir_modes() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[dir("d", 0o000), file("d/f", 0o644, b"x")]);
        ex.remove_whiteout_target(&[], OsStr::new("d")).unwrap();
        ex.finish_dirs().unwrap();
        assert!(names_in(&sb.root).is_empty());
    }

    /// OCI-2・IO-5: 別表記（大文字小文字）で既存の実体へ解決される whiteout は削除せず AlreadyExists。
    #[test]
    fn oci2_whiteout_alias_spelling_is_rejected_without_removal() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        let e = ex.remove_whiteout_target(&[], OsStr::new("F")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
    }

    /// OCI-2: 削除後、上位レイヤーが同名を再作成できる。
    #[test]
    fn oci2_whiteout_then_upper_layer_can_recreate_name() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("foo", 0o644, b"old")]);
        ex.remove_whiteout_target(&[], OsStr::new("foo")).unwrap();
        lay(&mut ex, &[file("foo", 0o644, b"new")]);
        ex.finish_dirs().unwrap();
        assert_eq!(fs::read(sb.root.join("foo")).unwrap(), b"new");
    }

    /// OCI-2・IO-5: 削除した名前の旧綴りで、再作成された別表記の実体を whiteout できない（AlreadyExists）。
    #[test]
    fn oci2_whiteout_forgets_removed_spellings_of_recreated_tree() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[dir("D", 0o755), file("D/F", 0o644, b"old")]);
        ex.remove_whiteout_target(&[], OsStr::new("D")).unwrap();
        lay(&mut ex, &[dir("d", 0o755), file("d/f", 0o644, b"new")]);
        let e = ex
            .remove_whiteout_target(&os(&["d"]), OsStr::new("F"))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        let e = ex.remove_whiteout_target(&[], OsStr::new("D")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"new");
    }

    // ---- 不透明ディレクトリ（TASK-53.2・OCI-2・#413） ----

    /// OCI-2: 不透明ディレクトリは下位由来の子を隠し、上位の子だけが残る。ディレクトリ自体と他は残る。
    #[test]
    fn oci2_opaque_hides_lower_files_in_dir() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/a", 0o644, b"1"),
                file("d/sub/b", 0o644, b"2"),
                file("other/x", 0o644, b"3"),
                file("top", 0o644, b"4"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        lay(&mut ex, &[file("d/new", 0o644, b"n")]);
        ex.finish_dirs().unwrap();
        assert_eq!(names_in(&sb.root.join("d")), vec!["new".to_string()]);
        assert_eq!(fs::read(sb.root.join("d/new")).unwrap(), b"n");
        assert_eq!(fs::read(sb.root.join("other/x")).unwrap(), b"3");
        assert_eq!(fs::read(sb.root.join("top")).unwrap(), b"4");
        sb.assert_outside_untouched();
    }

    /// OCI-2: root 直下の不透明は中身だけ消し、root は残る。
    #[test]
    fn oci2_opaque_at_root_clears_everything_but_root() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("a/b", 0o644, b"1"), file("c", 0o644, b"2")]);
        ex.clear_opaque_dir(&[]).unwrap();
        assert!(sb.root.is_dir());
        assert!(names_in(&sb.root).is_empty());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 不透明適用後もディレクトリの mode は維持され、0555・0000 の子と深いツリーも消せる。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_keeps_dir_mode_and_removes_readonly_children() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("d", 0o750),
                file("d/ro/c", 0o644, b"c"),
                dir("d/zero", 0o000),
            ],
        );
        let deep: PathBuf = (0..60).map(|i| format!("n{i}")).collect();
        fs::create_dir_all(sb.root.join("d").join(&deep)).unwrap();
        fs::set_permissions(sb.root.join("d/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        ex.finish_dirs().unwrap();
        assert!(names_in(&sb.root.join("d")).is_empty());
        let mode = fs::metadata(sb.root.join("d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o750);
        sb.assert_outside_untouched();
    }

    /// OCI-2: 子の symlink はリンクのみ消えリンク先は残る。親が root 外を指す symlink でも root に閉じ込める。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/f", 0o644, b"r"),
                dir("d", 0o755),
                symlink("d/lnk", "../real"),
                symlink("esc", "/"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        assert!(fs::symlink_metadata(sb.root.join("d/lnk")).is_err());
        assert_eq!(fs::read(sb.root.join("real/f")).unwrap(), b"r");
        // 絶対ターゲット `/` は root へ戻されるため、消えるのは root 配下の中身だけ（root 自体は残る）。
        ex.clear_opaque_dir(&os(&["esc"])).unwrap();
        assert!(sb.root.is_dir());
        assert!(names_in(&sb.root).is_empty());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 存在しない親・通常ファイルの親は何もしない（下位に中身を消すディレクトリが無い）。
    #[test]
    fn oci2_opaque_missing_dir_and_file_parent_are_noop() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("f", 0o644, b"x")]);
        ex.clear_opaque_dir(&os(&["no", "dir"])).unwrap();
        ex.clear_opaque_dir(&os(&["f"])).unwrap();
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"x");
        assert_eq!(names_in(&sb.root), vec!["f".to_string()]);
    }

    /// OCI-2: 配下・トップ自身が mode 0 の遅延ディレクトリでも `finish_dirs` が成功し、トップの mode は復元される。
    #[test]
    #[cfg(unix)]
    fn oci2_opaque_clears_deferred_modes_of_descendants() {
        use std::os::unix::fs::PermissionsExt as _;
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                dir("d", 0o000),
                dir("d/s", 0o000),
                file("d/s/f", 0o644, b"x"),
            ],
        );
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        ex.finish_dirs().unwrap();
        let mode = fs::metadata(sb.root.join("d"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o000);
        fs::set_permissions(sb.root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(names_in(&sb.root.join("d")).is_empty());
    }

    /// OCI-2・IO-5: 中身を消した後、旧綴りの別表記で再作成された実体を操作できない（AlreadyExists）。
    #[test]
    fn oci2_opaque_forgets_removed_spellings() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[dir("d", 0o755), file("d/F", 0o644, b"old")]);
        ex.clear_opaque_dir(&os(&["d"])).unwrap();
        lay(&mut ex, &[file("d/f", 0o644, b"new")]);
        let e = ex
            .remove_whiteout_target(&os(&["d"]), OsStr::new("F"))
            .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"new");
    }

    /// OCI-2・IO-5: 親の別表記は削除せず AlreadyExists。
    #[test]
    fn oci2_opaque_alias_parent_is_rejected_without_removal() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, folding_lstat);
        lay(&mut ex, &[file("d/f", 0o644, b"x")]);
        let e = ex.clear_opaque_dir(&os(&["D"])).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::AlreadyExists);
        assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"x");
    }

    // ---- パイプラインへの統合（レイヤーごとの 3 パス。TASK-53.3・OCI-2・#414） ----

    /// whiteout・不透明マーカー（中身の無い通常ファイル）。
    fn wh(name: &str) -> Vec<u8> {
        file(name, 0o644, b"")
    }

    fn lay_err(ex: &mut Extractor<'_>, entries: &[Vec<u8>]) -> OciErrorCode {
        extract_one_layer(ex, &mut Rewind::new(Cursor::new(archive(entries))), 1 << 30)
            .unwrap_err()
            .code()
    }

    /// `root` 配下の全ノード（相対パス → 種別と内容。ディレクトリは unix では mode も）。最終 rootfs の比較用。
    fn snapshot(root: &Path) -> std::collections::BTreeMap<String, String> {
        fn walk(dir: &Path, prefix: &str, out: &mut std::collections::BTreeMap<String, String>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let rel = format!("{prefix}{}", e.file_name().into_string().unwrap());
                let p = e.path();
                let m = fs::symlink_metadata(&p).unwrap();
                if m.file_type().is_symlink() {
                    let t = fs::read_link(&p).unwrap();
                    out.insert(rel, format!("link:{}", t.display()));
                } else if m.is_dir() {
                    #[cfg(unix)]
                    let kind = format!("dir:{:o}", mode_of(&p));
                    #[cfg(not(unix))]
                    let kind = "dir".to_string();
                    out.insert(rel.clone(), kind);
                    walk(&p, &format!("{rel}/"), out);
                } else {
                    let data = fs::read(&p).unwrap();
                    out.insert(rel, format!("file:{}", String::from_utf8_lossy(&data)));
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, "", &mut out);
        out
    }

    /// `items` の全順列。
    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let head = rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, head.clone());
                out.push(tail);
            }
        }
        out
    }

    /// OCI-2: 下位 `lower` に上位 `upper` を重ねる展開を、`upper` のエントリの全順列で行い、最終 rootfs（失敗なら
    /// エラーコード）がすべて一致することを確かめて、その結果を返す。
    fn all_orders(
        lower: &[Vec<u8>],
        upper: &[Vec<u8>],
    ) -> Result<std::collections::BTreeMap<String, String>, OciErrorCode> {
        let mut first: Option<Result<_, OciErrorCode>> = None;
        for order in permutations(upper) {
            let sb = Sandbox::new();
            let got = run_stack(&sb, &[lower.to_vec(), order], LIM(), host_lstat)
                .map(|_| snapshot(&sb.root))
                .map_err(|e| e.code());
            sb.assert_outside_untouched();
            match &first {
                None => first = Some(got),
                Some(f) => assert_eq!(&got, f, "result depends on the entry order"),
            }
        }
        first.unwrap()
    }

    fn snap(items: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[cfg(unix)]
    const D755: &str = "dir:755";
    #[cfg(not(unix))]
    const D755: &str = "dir";

    /// OCI-2: 同一レイヤー内のマーカーと通常エントリは、どの並びでも同じ最終 rootfs になる
    /// （`.wh.d` + ファイル `d` の再作成・不透明 + 同じレイヤーの子・`.wh.d` + `d/x`・`.wh.foo` + `foo`）。
    #[test]
    fn oci2_same_layer_markers_and_entries_are_order_independent() {
        let r = all_orders(
            &[file("d/x", 0o644, b"x"), file("keep", 0o644, b"k")],
            &[wh(".wh.d"), file("d", 0o644, b"new")],
        );
        assert_eq!(r.unwrap(), snap(&[("d", "file:new"), ("keep", "file:k")]));

        let r = all_orders(
            &[
                file("d/old", 0o644, b"o"),
                file("d/sub/x", 0o644, b"x"),
                file("e", 0o644, b"e"),
            ],
            &[
                file("d/before", 0o644, b"b"),
                wh("d/.wh..wh..opq"),
                file("d/after", 0o644, b"a"),
            ],
        );
        assert_eq!(
            r.unwrap(),
            snap(&[
                ("d", D755),
                ("d/after", "file:a"),
                ("d/before", "file:b"),
                ("e", "file:e"),
            ])
        );

        let r = all_orders(
            &[file("d/x", 0o644, b"old"), file("d/z", 0o644, b"z")],
            &[wh(".wh.d"), file("d/x", 0o644, b"new")],
        );
        assert_eq!(r.unwrap(), snap(&[("d", D755), ("d/x", "file:new")]));

        let r = all_orders(
            &[file("d/foo", 0o644, b"old"), file("d/bar", 0o644, b"bar")],
            &[
                file("d/foo", 0o644, b"new"),
                wh("d/.wh.foo"),
                wh("d/.wh.bar"),
            ],
        );
        assert_eq!(r.unwrap(), snap(&[("d", D755), ("d/foo", "file:new")]));
    }

    /// OCI-2: 指摘されたケース。下位のディレクトリ `d` に、上位が `d`（ファイル）・旧実装の退避名と同じ
    /// `.fandhe-displaced-0`（ファイル）・`.wh.d` を置くと、並びに依らず成功し両ファイルが残る。
    #[test]
    fn oci2_former_displacement_name_does_not_collide() {
        let r = all_orders(
            &[file("d/x", 0o644, b"x")],
            &[
                file("d", 0o644, b"f"),
                file(".fandhe-displaced-0", 0o644, b"g"),
                wh(".wh.d"),
            ],
        );
        assert_eq!(
            r.unwrap(),
            snap(&[("d", "file:f"), (".fandhe-displaced-0", "file:g")])
        );
    }

    /// OCI-2: 祖先の `.wh.<dir>`・不透明マーカーが下位のノードを覆い、同じレイヤーがその位置へ別の型の
    /// ノードを置くケースも、並びに依らず成功する。
    #[test]
    fn oci2_ancestor_whiteout_or_opaque_covers_lower_nodes() {
        let lower = [file("a/b/x", 0o644, b"x"), file("c", 0o644, b"c")];
        let r = all_orders(&lower, &[file("a/b", 0o644, b"f"), wh(".wh.a")]);
        assert_eq!(
            r.unwrap(),
            snap(&[("a", D755), ("a/b", "file:f"), ("c", "file:c")])
        );
        let r = all_orders(&lower, &[file("a/b", 0o644, b"f"), wh(".wh..wh..opq")]);
        assert_eq!(r.unwrap(), snap(&[("a", D755), ("a/b", "file:f")]));
        let r = all_orders(&lower, &[file("a/b", 0o644, b"f"), wh("a/.wh..wh..opq")]);
        assert_eq!(
            r.unwrap(),
            snap(&[("a", D755), ("a/b", "file:f"), ("c", "file:c")])
        );
    }

    /// OCI-2: マーカーの親が下位で非ディレクトリなら何もせず、同じレイヤーがそこをディレクトリへ置き換える
    /// 並びと結果が同じ。マーカーなしでも下位のファイルは置き換えられる（Changeset over existing files）。
    #[test]
    fn oci2_marker_under_lower_file_is_noop_in_all_orders() {
        for marker in ["d/.wh.x", "d/.wh..wh..opq"] {
            let r = all_orders(&[file("d", 0o644, b"f")], &[wh(marker), dir("d/", 0o755)]);
            assert_eq!(r.unwrap(), snap(&[("d", D755)]), "{marker}");
            let r = all_orders(&[file("d", 0o644, b"f")], &[wh(marker)]);
            assert_eq!(r.unwrap(), snap(&[("d", "file:f")]), "{marker}");
        }
    }

    /// OCI-2: symlink を経由する親のマーカーと、その symlink 自身の whiteout は、削除の前に下位ツリーで
    /// 解決するため並びに依らない（リンク先の `real/x` も symlink `lnk` も消える）。マーカーは同じレイヤーが
    /// 作る symlink を経由しない（下位に `d` が無いので `real` は無傷）。
    #[test]
    #[cfg(unix)]
    fn oci2_markers_resolve_against_lower_tree_in_all_orders() {
        let lower = [
            file("real/x", 0o644, b"x"),
            file("real/y", 0o644, b"y"),
            symlink("lnk", "real"),
        ];
        let r = all_orders(&lower, &[wh("lnk/.wh.x"), wh(".wh.lnk")]);
        assert_eq!(r.unwrap(), snap(&[("real", D755), ("real/y", "file:y")]));
        let r = all_orders(&lower, &[wh("lnk/.wh..wh..opq"), wh(".wh.lnk")]);
        assert_eq!(r.unwrap(), snap(&[("real", D755)]));
        let r = all_orders(&lower, &[file("lnk/new", 0o644, b"n"), wh(".wh.lnk")]);
        assert_eq!(
            r.unwrap(),
            snap(&[
                ("lnk", D755),
                ("lnk/new", "file:n"),
                ("real", D755),
                ("real/x", "file:x"),
                ("real/y", "file:y"),
            ])
        );
        let r = all_orders(
            &[file("real/x", 0o644, b"x")],
            &[wh("d/.wh.x"), symlink("d", "real")],
        );
        assert_eq!(
            r.unwrap(),
            snap(&[("d", "link:real"), ("real", D755), ("real/x", "file:x")])
        );
    }

    /// OCI-2: 同じレイヤーで whiteout した下位のファイルへの hardlink は、並びに依らず `NotFound`
    /// （参照先はパス 2 で消えている）。不透明マーカーで消えた参照先への自己 hardlink も同じ。
    #[test]
    fn oci2_hardlink_to_whited_out_lower_file_is_not_found() {
        let lower = [file("f", 0o644, b"data"), file("d/f", 0o644, b"x")];
        for upper in [
            vec![hardlink("g", "f"), wh(".wh.f")],
            vec![hardlink("d/f", "d/f"), wh("d/.wh..wh..opq")],
        ] {
            assert_eq!(all_orders(&lower, &upper), Err(OciErrorCode::NotFound));
        }
    }

    /// OCI-2: パス 1 で不正なエントリを見つけたら、先に並ぶマーカー・通常エントリを含め rootfs を一切変更しない。
    #[test]
    fn oci2_pass1_rejection_leaves_rootfs_unchanged() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("d/x", 0o644, b"x"),
                file("e", 0o644, b"e"),
                dir("o/", 0o755),
                file("o/y", 0o644, b"y"),
            ],
        );
        let before = snapshot(&sb.root);
        let head = || {
            vec![
                file("d/new", 0o644, b"n"),
                wh("d/.wh.x"),
                wh(".wh.e"),
                wh("o/.wh..wh..opq"),
            ]
        };
        for (bad, want) in [
            (
                file("../escape", 0o644, b"z"),
                OciErrorCode::PermissionDenied,
            ),
            (
                file(".wh..wh..opq/x", 0o644, b"z"),
                OciErrorCode::InvalidArgument,
            ),
            (file(".wh.a/b", 0o644, b"z"), OciErrorCode::InvalidArgument),
            (
                file("d/.wh.y", 0o644, b"junk"),
                OciErrorCode::InvalidArgument,
            ),
            (dir("d/.wh.y", 0o755), OciErrorCode::InvalidArgument),
            (
                raw_entry(b"fifo", EntryType::Fifo, b"", 0o644, 0, b""),
                OciErrorCode::PermissionDenied,
            ),
        ] {
            let mut entries = head();
            entries.push(bad);
            assert_eq!(lay_err(&mut ex, &entries), want);
            assert_eq!(snapshot(&sb.root), before);
        }
        sb.assert_outside_untouched();
    }

    /// OCI-2・#2183: AUFS メタデータの予約名（配下を含む）は rootfs に書かれず、他のエントリ（通常の whiteout を含む）
    /// の展開に影響しない。結果は並び順に依らない。
    #[test]
    fn oci2_aufs_reserved_entries_are_skipped() {
        let r = all_orders(
            &[file("a", 0o644, b"a"), file("d/c", 0o644, b"c")],
            &[
                dir(".wh..wh.plnk/", 0o755),
                file(".wh..wh.plnk/123", 0o644, b"payload"),
                file(".wh..wh.aufs", 0o644, b"meta"),
                wh(".wh.a"),
                file("b", 0o644, b"b"),
            ],
        );
        assert_eq!(
            r.unwrap(),
            snap(&[("b", "file:b"), ("d", D755), ("d/c", "file:c")])
        );
    }

    /// OCI-2・#2183: 読み飛ばしの件数・バイト数の数え方（ネスト・単体・symlink を含む）。
    #[test]
    fn oci2_aufs_reserved_skip_counts() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        let entries = [
            file("ok", 0o644, b"ok"),
            file("d/.wh..wh.plnk", 0o644, b"abc"),
            file(".wh..wh.orph/x", 0o644, b"zz"),
            wh(".wh..wh."),
            symlink(".wh..wh.orph/l", "/etc/passwd"),
        ];
        let r = extract_one_layer(
            &mut ex,
            &mut Rewind::new(Cursor::new(archive(&entries))),
            1 << 30,
        )
        .unwrap()
        .0;
        assert_eq!(r.entries, 5);
        assert_eq!(r.ignored_reserved_entries, 4);
        assert_eq!(r.bytes, 2);
        assert_eq!(snapshot(&sb.root), snap(&[("ok", "file:ok")]));
        sb.assert_outside_untouched();
    }

    /// OCI-2・#2312: 予約名（AUFS メタデータ）を含む参照先への hardlink は差し替えず、並びに依らず `Unimplemented`。
    #[test]
    fn oci2_hardlink_into_aufs_metadata_is_unimplemented() {
        for target in [
            ".wh..wh.plnk/123",
            "./.wh..wh.plnk/123",
            ".wh..wh.plnk/sub/123",
            "d/.wh..wh.plnk/1",
            ".wh..wh.aufs",
        ] {
            let link = hardlink("g", target);
            let r = all_orders(&[], &[file(".wh..wh.plnk/123", 0o644, b"x"), link.clone()]);
            assert_eq!(r.unwrap_err(), OciErrorCode::Unimplemented, "{target}");
            let r = all_orders(&[], &[link]);
            assert_eq!(r.unwrap_err(), OciErrorCode::Unimplemented, "{target}");
        }
    }

    /// OCI-2・#2312: plnk への hardlink はパス 2（whiteout の適用）より前に拒否され、下位の実体は残る。
    #[test]
    fn oci2_hardlink_into_aufs_metadata_rejected_before_whiteout() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("a", 0o644, b"a")]);
        let before = snapshot(&sb.root);
        assert_eq!(
            lay_err(&mut ex, &[wh(".wh.a"), hardlink("g", ".wh..wh.plnk/1")]),
            OciErrorCode::Unimplemented
        );
        assert_eq!(snapshot(&sb.root), before);
        sb.assert_outside_untouched();
    }

    /// OCI-2・#2312: 予約名配下の未対応の種別は、予約名の外と同じ `PermissionDenied` で拒否し rootfs を変えない。
    #[test]
    fn oci2_aufs_reserved_rejects_unsupported_types() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("keep", 0o644, b"k")]);
        let before = snapshot(&sb.root);
        for (name, ty) in [
            (&b".wh..wh.plnk/f"[..], EntryType::Fifo),
            (&b".wh..wh.orph/c"[..], EntryType::Char),
            (&b"d/.wh..wh.aufs"[..], EntryType::Block),
        ] {
            let bad = raw_entry(name, ty, b"", 0o644, 0, b"");
            assert_eq!(
                lay_err(&mut ex, &[file("new", 0o644, b"n"), bad]),
                OciErrorCode::PermissionDenied
            );
            assert_eq!(snapshot(&sb.root), before);
            // 予約名の外に同じ種別を置いた場合と同じコード。
            let outside = raw_entry(b"x", ty, b"", 0o644, 0, b"");
            assert_eq!(lay_err(&mut ex, &[outside]), OciErrorCode::PermissionDenied);
        }
        sb.assert_outside_untouched();
        let r = all_orders(
            &[file("a", 0o644, b"a")],
            &[
                wh(".wh.a"),
                raw_entry(b".wh..wh.plnk/f", EntryType::Fifo, b"", 0o644, 0, b""),
            ],
        );
        assert_eq!(r.unwrap_err(), OciErrorCode::PermissionDenied);
    }

    /// OCI-2・#2183: 予約名の読み飛ばしでも fail-closed の拒否（`..`・親の位置の whiteout / 不透明）は残り、
    /// 拒否したときは rootfs を変えない。
    #[test]
    fn oci2_reserved_skip_keeps_fail_closed_rules() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("keep", 0o644, b"k")]);
        let before = snapshot(&sb.root);
        for (bad, want) in [
            (
                file(".wh..wh.plnk/../x", 0o644, b"z"),
                OciErrorCode::PermissionDenied,
            ),
            (
                file(".wh.foo/.wh..wh.plnk", 0o644, b"z"),
                OciErrorCode::InvalidArgument,
            ),
            (
                file(".wh..wh..opq/child", 0o644, b"z"),
                OciErrorCode::InvalidArgument,
            ),
        ] {
            assert_eq!(lay_err(&mut ex, &[file("new", 0o644, b"n"), bad]), want);
            assert_eq!(snapshot(&sb.root), before);
        }
        sb.assert_outside_untouched();
    }

    /// OCI-2・IO-5: 別表記で既存の実体へ解決されるマーカーは、同じレイヤーの他のマーカーの削除より前に
    /// `AlreadyExists` で拒否する（並びに依らず、下位の実体は残る）。
    #[test]
    fn io5_marker_alias_is_rejected_before_any_removal() {
        for upper in [
            vec![wh(".wh.g"), wh("d/.wh.F")],
            vec![wh("d/.wh.F"), wh(".wh.g")],
            vec![wh(".wh..wh..opq"), wh("D/.wh.x")],
        ] {
            let sb = Sandbox::new();
            let mut ex = ex_for(&sb, folding_lstat);
            lay(&mut ex, &[file("d/f", 0o644, b"x"), file("g", 0o644, b"g")]);
            assert_eq!(lay_err(&mut ex, &upper), OciErrorCode::AlreadyExists);
            assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"x");
            assert_eq!(fs::read(sb.root.join("g")).unwrap(), b"g");
        }
    }

    /// OCI-2: マーカーは rootfs に残らず、本体は `bytes` に数えない（エントリ数には数える）。root の不透明は
    /// root 自体を残し、対象・親の無い whiteout は何もしない。
    #[test]
    fn oci2_markers_are_not_extracted_and_missing_targets_are_noop() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(&mut ex, &[file("a", 0o644, b"1"), file("d/b", 0o644, b"2")]);
        let (r, _) = extract_one_layer(
            &mut ex,
            &mut Rewind::new(Cursor::new(archive(&[
                wh(".wh.nothing"),
                wh("nodir/.wh.x"),
            ]))),
            1 << 30,
        )
        .unwrap();
        assert_eq!((r.entries, r.bytes), (2, 0));
        assert_eq!(names_in(&sb.root), vec!["a".to_string(), "d".to_string()]);
        lay(&mut ex, &[wh(".wh..wh..opq"), file("n", 0o644, b"n")]);
        assert!(sb.root.is_dir());
        assert_eq!(names_in(&sb.root), vec!["n".to_string()]);
        sb.assert_outside_untouched();
    }

    /// OCI-2: whiteout はルート外を指す symlink の親を経由してもルート外へ出ず、symlink はリンクだけを消す。
    #[test]
    #[cfg(unix)]
    fn oci2_pipeline_whiteout_does_not_follow_symlinks() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        lay(
            &mut ex,
            &[
                file("real/keep", 0o644, b"k"),
                symlink("lnk", "real"),
                symlink("abs", "/"),
            ],
        );
        lay(&mut ex, &[wh(".wh.lnk"), wh("abs/.wh.sentinel")]);
        assert!(fs::symlink_metadata(sb.root.join("lnk")).is_err());
        assert_eq!(fs::read(sb.root.join("real/keep")).unwrap(), b"k");
        assert!(fs::symlink_metadata(sb.root.join("abs")).is_ok());
        sb.assert_outside_untouched();
    }

    /// OCI-2: 遅延 mode（0000・0555）の下位ディレクトリを whiteout・不透明にし、同じレイヤーが同名を作り直しても、
    /// `finish_dirs` が成功して作り直した側の mode になる（並びに依らない）。
    #[test]
    #[cfg(unix)]
    fn oci2_deferred_dir_modes_follow_markers_in_all_orders() {
        let lower = [
            dir("a", 0o000),
            file("a/x", 0o644, b"x"),
            dir("o", 0o555),
            file("o/y", 0o644, b"y"),
        ];
        let r = all_orders(&lower, &[wh(".wh.a"), file("a/new", 0o644, b"n")]);
        assert_eq!(
            r.unwrap(),
            snap(&[
                ("a", "dir:755"),
                ("a/new", "file:n"),
                ("o", "dir:555"),
                ("o/y", "file:y"),
            ])
        );
        let r = all_orders(&lower, &[wh(".wh.a"), wh("o/.wh..wh..opq")]);
        assert_eq!(r.unwrap(), snap(&[("o", "dir:555")]));
    }

    /// OCI-2: 大量の whiteout（10 万件。実在する対象・遅延 mode のディレクトリ・存在しない対象を含む）が
    /// 線形時間で終わる（索引の削除は外す件数に比例し、全登録を走査しない）。
    #[test]
    fn oci2_many_whiteouts_complete_in_linear_time() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        ex.limits = ExtractLimits::new(300_000, 1 << 20, 1 << 32, 300_000);
        let (files, dirs, total) = (5000, 2000, 100_000);
        let mut lower: Vec<Vec<u8>> = (0..files)
            .map(|i| file(&format!("d/f{i}"), 0o644, b""))
            .collect();
        lower.extend((0..dirs).map(|i| dir(&format!("d/s{i}/"), 0o555)));
        lay(&mut ex, &lower);
        let mut upper: Vec<Vec<u8>> = (0..files).map(|i| wh(&format!("d/.wh.f{i}"))).collect();
        upper.extend((0..dirs).map(|i| wh(&format!("d/.wh.s{i}"))));
        upper.extend((files + dirs..total).map(|i| wh(&format!("d/.wh.m{i}"))));
        let t = std::time::Instant::now();
        lay(&mut ex, &upper);
        assert!(t.elapsed() < std::time::Duration::from_secs(30));
        assert!(names_in(&sb.root.join("d")).is_empty());
        assert!(ex.deferred_dirs.is_empty());
        ex.finish_dirs().unwrap();
    }

    /// OCI-2: 不透明マーカーが大量（10 万件。同じディレクトリの重複を含む）でも、同じレイヤーの子を多数持つ
    /// レイヤーが線形時間で終わり、同じレイヤーの子は残る。
    #[test]
    fn oci2_many_opaque_markers_complete_in_linear_time() {
        let sb = Sandbox::new();
        let mut ex = ex_for(&sb, host_lstat);
        ex.limits = ExtractLimits::new(300_000, 1 << 20, 1 << 32, 300_000);
        let n = 3000;
        lay(
            &mut ex,
            &(0..n)
                .map(|i| file(&format!("o{i}/old"), 0o644, b""))
                .collect::<Vec<_>>(),
        );
        let mut upper: Vec<Vec<u8>> = (0..n)
            .map(|i| file(&format!("d/f{i}"), 0o644, b""))
            .collect();
        upper.extend((0..n).map(|i| wh(&format!("o{i}/.wh..wh..opq"))));
        upper.extend((2 * n..100_000).map(|_| wh("d/.wh..wh..opq")));
        let t = std::time::Instant::now();
        lay(&mut ex, &upper);
        assert!(t.elapsed() < std::time::Duration::from_secs(30));
        assert_eq!(names_in(&sb.root.join("d")).len(), n);
        assert!(names_in(&sb.root.join("o0")).is_empty());
    }
    // ---- 所有者の適用（chown）と PreserveIfChowned（SEC-5・OCI-1・#2225） ----
    #[cfg(target_os = "linux")]
    mod chown_tests {
        use super::*;
        use std::cell::{Cell, RefCell};
        use std::os::unix::fs::PermissionsExt as _;

        /// 記録した `chown` 呼び出し（種別 `f` は fchown、`l` は lchown）。
        #[derive(Debug, PartialEq, Eq)]
        struct ChownCall {
            kind: char,
            path: Option<PathBuf>,
            uid: u32,
            gid: u32,
            /// 呼び出し時点の mode（`& 0o7777`）。
            mode: u32,
        }

        thread_local! {
            static CALLS: RefCell<Vec<ChownCall>> = const { RefCell::new(Vec::new()) };
            static LAST: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
        }

        fn rec_fchown(f: &File, uid: u32, gid: u32) -> std::io::Result<()> {
            let mode = f.metadata()?.permissions().mode() & 0o7777;
            CALLS.with_borrow_mut(|c| {
                c.push(ChownCall {
                    kind: 'f',
                    path: None,
                    uid,
                    gid,
                    mode,
                });
            });
            LAST.set((uid, gid));
            Ok(())
        }

        fn rec_lchown(
            a: &AnchoredRoot,
            comps: &[OsString],
            uid: u32,
            gid: u32,
        ) -> std::io::Result<()> {
            let p = a.debug_path(comps);
            let p = p.as_path();
            let mode = fs::symlink_metadata(p)?.permissions().mode() & 0o7777;
            CALLS.with_borrow_mut(|c| {
                c.push(ChownCall {
                    kind: 'l',
                    path: Some(p.to_path_buf()),
                    uid,
                    gid,
                    mode,
                });
            });
            Ok(())
        }

        fn rec_readback(_f: &File) -> std::io::Result<(u32, u32)> {
            Ok(LAST.get())
        }

        fn bad_readback(_f: &File) -> std::io::Result<(u32, u32)> {
            Ok((1, 1))
        }

        fn denied_fchown(_f: &File, _u: u32, _g: u32) -> std::io::Result<()> {
            Err(std::io::Error::from(ErrorKind::PermissionDenied))
        }

        fn rec_fns() -> ChownFns {
            ChownFns {
                fchown: rec_fchown,
                lchown: rec_lchown,
                readback: rec_readback,
            }
        }

        fn take_calls() -> Vec<ChownCall> {
            CALLS.with_borrow_mut(std::mem::take)
        }

        /// subuid 風の写像（0 → 100000 × 1、1 → 100001 × 65535）。
        fn subuid_map() -> IdMap {
            IdMap::new(vec![
                IdRange {
                    container_id: 0,
                    host_id: 100_000,
                    count: 1,
                },
                IdRange {
                    container_id: 1,
                    host_id: 100_001,
                    count: 65_535,
                },
            ])
            .unwrap()
        }

        fn chown_setup(policy: SpecialBitsPolicy, fns: ChownFns) -> SpecialSetup {
            SpecialSetup {
                ownership: OwnershipPolicy::ChownMapped {
                    uid: subuid_map(),
                    gid: subuid_map(),
                },
                chown: fns,
                ..SpecialSetup::host(policy)
            }
        }

        fn run_setup(
            sb: &Sandbox,
            entries: &[Vec<u8>],
            setup: SpecialSetup,
        ) -> Result<ExtractedLayer, OciError> {
            let tar = archive(entries);
            take_calls();
            single(extract_stack(
                &NoopOciOpRecorder,
                [Rewind::new(Cursor::new(tar.as_slice()))],
                &sb.root,
                LIM(),
                host_lstat,
                setup,
            )?)
        }

        fn owned_entry(
            name: &str,
            ty: EntryType,
            link: &str,
            mode: u32,
            uid: u64,
            gid: u64,
        ) -> Vec<u8> {
            let mut h = tar::Header::new_gnu();
            h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            h.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
            h.set_entry_type(ty);
            h.set_mode(mode);
            h.set_uid(uid);
            h.set_gid(gid);
            h.set_size(0);
            h.set_cksum();
            h.as_bytes().to_vec()
        }

        /// SEC-5・OCI-1: レイヤー 0 のイメージでも `ChownMapped` なら root を写像先（0 → 100000）へ chown する。
        #[test]
        fn sec5_zero_layer_image_chowns_root() {
            let sb = Sandbox::new();
            take_calls();
            let r =
                extract_zero_layers(&sb.root, &chown_setup(SpecialBitsPolicy::Strip, rec_fns()))
                    .unwrap();
            assert!(r.is_empty());
            let calls = take_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].kind, 'l');
            assert_eq!(calls[0].path.as_deref(), Some(sb.root.as_path()));
            assert_eq!((calls[0].uid, calls[0].gid), (100_000, 100_000));
        }

        /// SEC-5: 複数行の写像で、ファイル・symlink・ディレクトリ・暗黙のディレクトリ・root へ期待どおりの ID を chown する。
        #[test]
        fn sec5_chown_maps_tar_owner_through_multi_line_map() {
            let sb = Sandbox::new();
            let entries = [
                owned_entry("d/", EntryType::Directory, "", 0o755, 33, 34),
                file_owned("d/f", 0o644, 1000, 1001, b"x"),
                owned_entry("l", EntryType::Symlink, "d/f", 0o777, 5, 6),
                file_owned("x/y", 0o644, 0, 0, b"y"),
            ];
            let r = run_setup(
                &sb,
                &entries,
                chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
            )
            .unwrap();
            let calls = take_calls();
            let summary: Vec<(char, Option<PathBuf>, u32, u32)> = calls
                .iter()
                .map(|c| (c.kind, c.path.clone(), c.uid, c.gid))
                .collect();
            assert_eq!(
                summary,
                vec![
                    ('f', None, 101_000, 101_001),
                    ('l', Some(sb.root.join("l")), 100_005, 100_006),
                    ('f', None, 100_000, 100_000),
                    ('l', Some(sb.root.join("d")), 100_033, 100_034),
                    ('l', Some(sb.root.join("x")), 100_000, 100_000),
                    ('l', Some(sb.root.clone()), 100_000, 100_000),
                ]
            );
            assert_eq!(r.ownership.decision, OwnershipDecision::Applied);
            assert_eq!(r.ownership.chowned_entries, 6);
        }

        /// SEC-5: 通常ファイルは chown が fchmod より先（呼び出し時点で setuid が付いていない）。
        #[test]
        fn sec5_chown_order_file_before_mode() {
            let sb = Sandbox::new();
            run_setup(
                &sb,
                &[file_owned("f", 0o4755, 0, 0, b"x")],
                chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
            )
            .unwrap();
            let calls = take_calls();
            let first = calls.first().unwrap();
            assert_eq!(first.kind, 'f');
            assert_eq!(first.mode & S_ISUID, 0);
            assert_ne!(first.mode, 0o4755);
        }

        /// SEC-5: ディレクトリの chown は深い順で、mode の適用より前（遅延中の 0700 のときに呼ばれる）。
        #[test]
        fn sec5_chown_dirs_deepest_first_before_mode() {
            let sb = Sandbox::new();
            let entries = [
                owned_entry("a/", EntryType::Directory, "", 0o555, 1, 1),
                owned_entry("a/b/", EntryType::Directory, "", 0o755, 2, 2),
            ];
            run_setup(
                &sb,
                &entries,
                chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
            )
            .unwrap();
            let calls = take_calls();
            let paths: Vec<Option<PathBuf>> = calls.iter().map(|c| c.path.clone()).collect();
            assert_eq!(
                paths,
                vec![
                    Some(sb.root.join("a/b")),
                    Some(sb.root.join("a")),
                    Some(sb.root.clone())
                ]
            );
            // `a` は 0555 に遅延される（呼び出し時点は 0700）。chown の後に 0555 が適用される。
            assert_eq!(calls.get(1).map(|c| c.mode), Some(0o700));
            assert_eq!(mode_of(&sb.root.join("a")), 0o555);
            restore_perms(&sb.root);
        }

        /// SEC-5: hardlink は chown しない（inode を共有する参照先の所有者と特殊ビットを書き換えないため）。
        #[test]
        fn sec5_hardlink_is_not_chowned() {
            let sb = Sandbox::new();
            let r = run_setup(
                &sb,
                &[file_owned("a", 0o644, 1, 1, b"x"), hardlink("b", "a")],
                chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
            )
            .unwrap();
            let calls = take_calls();
            assert_eq!(calls.iter().filter(|c| c.kind == 'f').count(), 1);
            assert_eq!(calls.len(), 2);
            assert_eq!(r.ownership.chowned_entries, 2);
        }

        /// SEC-5: 写像に無い uid は PermissionDenied で、そのレイヤーのファイルを 1 件も書く前に拒否する。
        #[test]
        fn sec5_owner_outside_map_is_rejected_before_layer_writes() {
            let sb = Sandbox::new();
            let e = run_setup(
                &sb,
                &[
                    file_owned("a", 0o644, 0, 0, b"x"),
                    file_owned("b", 0o644, 70_000, 0, b"y"),
                ],
                chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert_eq!(e.message(), "layer entry owner is outside the id mapping");
            assert!(!sb.root.join("a").exists());
            assert!(take_calls().is_empty());
        }

        /// SEC-5: 解析できない PAX の uid（エントリ固有・グローバル）は InvalidArgument。
        #[test]
        fn sec5_malformed_pax_owner_is_rejected_when_chowning() {
            for ty in [EntryType::XHeader, EntryType::XGlobalHeader] {
                let sb = Sandbox::new();
                let body = pax_record("uid", "not-a-number");
                let px = raw_entry(b"pax", ty, b"", 0o644, body.len() as u64, &body);
                let e = run_setup(
                    &sb,
                    &[px, file_owned("f", 0o644, 0, 0, b"x")],
                    chown_setup(SpecialBitsPolicy::Strip, rec_fns()),
                )
                .unwrap_err();
                assert_eq!(e.code(), OciErrorCode::InvalidArgument);
                assert_eq!(e.message(), "layer entry owner is malformed");
                assert!(!sb.root.join("f").exists());
            }
        }

        /// SEC-5: 読み戻した所有者が要求と違えば FailedPrecondition（成功を偽らない）。
        #[test]
        fn sec5_chown_readback_mismatch_is_failed_precondition() {
            let sb = Sandbox::new();
            let fns = ChownFns {
                readback: bad_readback,
                ..rec_fns()
            };
            let e = run_setup(
                &sb,
                &[file_owned("f", 0o644, 0, 0, b"x")],
                chown_setup(SpecialBitsPolicy::Strip, fns),
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        }

        /// SEC-5: 権限不足の chown（EPERM）は PermissionDenied（fail-closed）。
        #[test]
        fn sec5_chown_eperm_is_permission_denied() {
            let sb = Sandbox::new();
            let fns = ChownFns {
                fchown: denied_fchown,
                ..rec_fns()
            };
            let e = run_setup(
                &sb,
                &[file_owned("f", 0o644, 0, 0, b"x")],
                chown_setup(SpecialBitsPolicy::Strip, fns),
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert_eq!(
                e.message(),
                "failed to change the owner of an extracted entry"
            );
        }

        /// SEC-5: PreserveIfChowned を Keep と組むと開始前に InvalidArgument で拒否し、root に触れない。
        #[test]
        fn sec5_preserve_if_chowned_requires_chown_policy() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let setup = SpecialSetup {
                chown: rec_fns(),
                ..SpecialSetup::host(SpecialBitsPolicy::PreserveIfChowned)
            };
            let e = run_setup(&sb, &[file_owned("f", 0o4755, 0, 0, b"x")], setup).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::InvalidArgument);
            assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
            assert!(take_calls().is_empty());
        }

        /// SEC-5: 既定（Keep）では chown を 1 回も呼ばない。
        #[test]
        fn sec5_keep_policy_does_not_chown() {
            let sb = Sandbox::new();
            let setup = SpecialSetup {
                chown: rec_fns(),
                ..SpecialSetup::host(SpecialBitsPolicy::Strip)
            };
            let r = run_setup(&sb, &[file_owned("f", 0o644, 0, 0, b"x")], setup).unwrap();
            assert!(take_calls().is_empty());
            assert_eq!(
                r.ownership,
                OwnershipOutcome {
                    decision: OwnershipDecision::NotRequested,
                    chowned_entries: 0
                }
            );
        }

        /// SEC-5・SEC-1: PreserveIfChowned は root が 0700 で、chown 後の所有者が写像と一致するビットを残す。
        #[test]
        fn sec5_preserve_if_chowned_keeps_bits_for_mapped_owner() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let r = run_setup(
                &sb,
                &[
                    file_owned("suid", 0o4755, 0, 0, b"a"),
                    file_owned("sticky", 0o1644, 33, 33, b"b"),
                ],
                chown_setup(SpecialBitsPolicy::PreserveIfChowned, rec_fns()),
            )
            .unwrap();
            assert_eq!(r.special_bits.decision, SpecialBitsDecision::Evaluated);
            assert_eq!(r.special_bits.preserved_files, 2);
            assert_eq!(mode_of(&sb.root.join("suid")), 0o4755);
            assert_eq!(mode_of(&sb.root.join("sticky")), 0o1644);
            take_calls();
        }

        /// SEC-5・SEC-1: root が他者に開かれているときは PreserveIfChowned でもすべて落とす。
        #[test]
        fn sec5_preserve_if_chowned_strips_when_root_is_open() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o755);
            let r = run_setup(
                &sb,
                &[file_owned("suid", 0o4755, 0, 0, b"a")],
                chown_setup(SpecialBitsPolicy::PreserveIfChowned, rec_fns()),
            )
            .unwrap();
            assert_eq!(
                r.special_bits.decision,
                SpecialBitsDecision::RootAccessibleByOthers
            );
            assert_eq!(r.files_with_stripped_special_bits, 1);
            assert_eq!(mode_of(&sb.root.join("suid")), 0o755);
        }

        /// SEC-5: `special_bits_to_keep_chowned` の条件の組み合わせ。
        #[test]
        fn sec5_special_bits_to_keep_chowned_matrix() {
            let m = subuid_map();
            let ctx = SpecialCtx {
                decision: SpecialBitsDecision::Evaluated,
                ranges: None,
                root_uid: 0,
                owner_of: host_owner,
                chowned_mode: true,
                in_userns: false,
            };
            let all = S_ISUID | S_ISGID | S_ISVTX;
            let k = |req, ids, owner| special_bits_to_keep_chowned(req, ids, owner, (&m, &m), &ctx);
            assert_eq!(k(all, (Some(0), Some(0)), (100_000, 100_000)), all);
            // 所有者が 0 なら setuid / setgid は残さない（sticky のみ）。
            assert_eq!(k(all, (Some(0), Some(0)), (0, 0)), S_ISVTX);
            // 写像と所有者の不一致。
            assert_eq!(
                k(all, (Some(5), Some(0)), (100_000, 100_000)),
                S_ISGID | S_ISVTX
            );
            // tar の ID が解析不能。
            assert_eq!(k(all, (None, None), (100_000, 100_000)), S_ISVTX);
            // 全体の判定が Evaluated でなければ 0。
            let strip = SpecialCtx {
                decision: SpecialBitsDecision::RootAccessibleByOthers,
                ..ctx
            };
            assert_eq!(
                special_bits_to_keep_chowned(
                    all,
                    (Some(0), Some(0)),
                    (100_000, 100_000),
                    (&m, &m),
                    &strip
                ),
                0
            );
        }

        // ---- rootless の user namespace の中での展開（ChownInUserNamespace。#2382・OCI-2・SEC-5） ----

        fn view_of(m: &IdMap) -> UserNsView {
            UserNsView {
                uid_map: m.lines().to_vec(),
                gid_map: m.lines().to_vec(),
                euid: 0,
                fsuid: 0,
                egid: 0,
                fsgid: 0,
            }
        }

        fn probe_ok() -> Result<UserNsView, OciError> {
            Ok(view_of(&subuid_map()))
        }

        fn probe_initial_ns() -> Result<UserNsView, OciError> {
            let init = vec![IdRange {
                container_id: 0,
                host_id: 0,
                count: u32::MAX,
            }];
            Ok(UserNsView {
                uid_map: init.clone(),
                gid_map: init,
                ..view_of(&subuid_map())
            })
        }

        fn probe_gid_mismatch() -> Result<UserNsView, OciError> {
            Ok(UserNsView {
                gid_map: vec![IdRange {
                    container_id: 0,
                    host_id: 100_000,
                    count: 1,
                }],
                ..view_of(&subuid_map())
            })
        }

        fn probe_fsuid_nonzero() -> Result<UserNsView, OciError> {
            Ok(UserNsView {
                fsuid: 1,
                ..view_of(&subuid_map())
            })
        }

        fn probe_unreadable() -> Result<UserNsView, OciError> {
            Err(err(OciErrorCode::FailedPrecondition, "cannot read"))
        }

        fn ns_setup(
            policy: SpecialBitsPolicy,
            fns: ChownFns,
            probe: fn() -> Result<UserNsView, OciError>,
        ) -> SpecialSetup {
            SpecialSetup {
                ownership: OwnershipPolicy::ChownInUserNamespace {
                    uid: subuid_map(),
                    gid: subuid_map(),
                },
                chown: fns,
                ns_probe: probe,
                ..SpecialSetup::host(policy)
            }
        }

        /// OCI-2・SEC-5: namespace の中では宛先が tar の ID そのまま（ChownMapped なら 101000 になる ID）で、
        /// 暗黙のディレクトリと root は 0:0。順序・件数は ChownMapped と同じ。
        #[test]
        fn oci2_userns_chown_destination_is_tar_id() {
            let sb = Sandbox::new();
            let entries = [
                owned_entry("d/", EntryType::Directory, "", 0o755, 33, 34),
                file_owned("d/f", 0o644, 1000, 1001, b"x"),
                owned_entry("l", EntryType::Symlink, "d/f", 0o777, 5, 6),
                file_owned("x/y", 0o644, 0, 0, b"y"),
            ];
            let r = run_setup(
                &sb,
                &entries,
                ns_setup(SpecialBitsPolicy::Strip, rec_fns(), probe_ok),
            )
            .unwrap();
            let summary: Vec<(char, Option<PathBuf>, u32, u32)> = take_calls()
                .iter()
                .map(|c| (c.kind, c.path.clone(), c.uid, c.gid))
                .collect();
            assert_eq!(
                summary,
                vec![
                    ('f', None, 1000, 1001),
                    ('l', Some(sb.root.join("l")), 5, 6),
                    ('f', None, 0, 0),
                    ('l', Some(sb.root.join("d")), 33, 34),
                    ('l', Some(sb.root.join("x")), 0, 0),
                    ('l', Some(sb.root.clone()), 0, 0),
                ]
            );
            assert_eq!(r.ownership.decision, OwnershipDecision::Applied);
            assert_eq!(r.ownership.chowned_entries, 6);
        }

        /// OCI-2・SEC-5: 開始前の検証に落ちたら FailedPrecondition で、root に触れず chown も 0 回。
        #[test]
        fn oci2_userns_precondition_failures_touch_nothing() {
            let probes: [fn() -> Result<UserNsView, OciError>; 5] = [
                probe_initial_ns,
                probe_gid_mismatch,
                probe_fsuid_nonzero,
                probe_unreadable,
                || {
                    Ok(UserNsView {
                        euid: 1000,
                        ..view_of(&subuid_map())
                    })
                },
            ];
            for probe in probes {
                let sb = Sandbox::new();
                let e = run_setup(
                    &sb,
                    &[file_owned("f", 0o644, 0, 0, b"x")],
                    ns_setup(SpecialBitsPolicy::Strip, rec_fns(), probe),
                )
                .unwrap_err();
                assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
                assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
                assert!(take_calls().is_empty());
            }
        }

        /// OCI-2・SEC-5: 純関数の検証。順序違いの写像は一致とみなし、uid 側の不一致も拒否する。
        #[test]
        fn oci2_check_user_namespace_cases() {
            let m = subuid_map();
            assert!(check_user_namespace(&view_of(&m), &m, &m).is_ok());
            let mut rev = view_of(&m);
            rev.uid_map.reverse();
            assert!(check_user_namespace(&rev, &m, &m).is_ok());
            let mut bad = view_of(&m);
            bad.uid_map.pop();
            let e = check_user_namespace(&bad, &m, &m).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "the user namespace id mapping differs from the requested mapping"
            );
            let mut g = view_of(&m);
            g.egid = 5;
            assert_eq!(
                check_user_namespace(&g, &m, &m).unwrap_err().message(),
                "the extracting process is not root inside the user namespace"
            );
        }

        /// OCI-2・SEC-5: 写像に無い ID はそのレイヤーを書く前に PermissionDenied。
        #[test]
        fn oci2_userns_owner_outside_map_is_rejected_before_writes() {
            let sb = Sandbox::new();
            let e = run_setup(
                &sb,
                &[
                    file_owned("a", 0o644, 0, 0, b"x"),
                    file_owned("b", 0o644, 70_000, 0, b"y"),
                ],
                ns_setup(SpecialBitsPolicy::Strip, rec_fns(), probe_ok),
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert!(!sb.root.join("a").exists());
            assert!(take_calls().is_empty());
        }

        fn einval_fchown(_f: &File, _u: u32, _g: u32) -> std::io::Result<()> {
            Err(std::io::Error::from(ErrorKind::InvalidInput))
        }

        /// OCI-2・SEC-5: namespace の中の EINVAL（写像に無い ID への chown）は PermissionDenied。
        #[test]
        fn oci2_userns_einval_is_permission_denied() {
            let sb = Sandbox::new();
            let fns = ChownFns {
                fchown: einval_fchown,
                ..rec_fns()
            };
            let e = run_setup(
                &sb,
                &[file_owned("f", 0o644, 0, 0, b"x")],
                ns_setup(SpecialBitsPolicy::Strip, fns, probe_ok),
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        }

        /// OCI-2・SEC-5: レイヤー 0 のイメージでも開始前に検証し、root を 0:0 へ chown する。
        #[test]
        fn oci2_userns_zero_layer_image() {
            let sb = Sandbox::new();
            take_calls();
            let setup = ns_setup(SpecialBitsPolicy::Strip, rec_fns(), probe_ok);
            assert!(extract_zero_layers(&sb.root, &setup).unwrap().is_empty());
            let calls = take_calls();
            assert_eq!(calls.len(), 1);
            assert_eq!((calls[0].uid, calls[0].gid), (0, 0));
            let bad = ns_setup(SpecialBitsPolicy::Strip, rec_fns(), probe_initial_ns);
            assert_eq!(
                extract_zero_layers(&sb.root, &bad).unwrap_err().code(),
                OciErrorCode::FailedPrecondition
            );
            assert!(take_calls().is_empty());
        }

        /// SEC-5・SEC-1: namespace の中では ns 内 uid 0 が所有する setuid も残す（ホストでは subuid にしか効かない）。
        /// 写像に無い ID・root が開いているときは落とす。
        #[test]
        fn sec5_userns_preserve_if_chowned_end_to_end() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let r = run_setup(
                &sb,
                &[
                    file_owned("suid", 0o4755, 0, 0, b"a"),
                    file_owned("sgid", 0o2755, 33, 33, b"b"),
                    file_owned("sticky", 0o1644, 1000, 1000, b"c"),
                ],
                ns_setup(SpecialBitsPolicy::PreserveIfChowned, rec_fns(), probe_ok),
            )
            .unwrap();
            take_calls();
            assert_eq!(r.special_bits.decision, SpecialBitsDecision::Evaluated);
            assert_eq!(r.special_bits.preserved_files, 3);
            assert_eq!(mode_of(&sb.root.join("suid")), 0o4755);
            assert_eq!(mode_of(&sb.root.join("sgid")), 0o2755);
            assert_eq!(mode_of(&sb.root.join("sticky")), 0o1644);

            let sb2 = Sandbox::new();
            chmod_root(&sb2, 0o755);
            let r2 = run_setup(
                &sb2,
                &[file_owned("suid", 0o4755, 0, 0, b"a")],
                ns_setup(SpecialBitsPolicy::PreserveIfChowned, rec_fns(), probe_ok),
            )
            .unwrap();
            take_calls();
            assert_eq!(
                r2.special_bits.decision,
                SpecialBitsDecision::RootAccessibleByOthers
            );
            assert_eq!(mode_of(&sb2.root.join("suid")), 0o755);
        }

        /// SEC-5: ns 内の `special_bits_to_keep_chowned` の条件（所有者 0 でも残す・tar の ID と所有者の不一致は落とす）。
        #[test]
        fn sec5_special_bits_to_keep_in_userns_matrix() {
            let m = subuid_map();
            let ctx = SpecialCtx {
                decision: SpecialBitsDecision::Evaluated,
                ranges: None,
                root_uid: 0,
                owner_of: host_owner,
                chowned_mode: true,
                in_userns: true,
            };
            let all = S_ISUID | S_ISGID | S_ISVTX;
            let k = |req, ids, owner| special_bits_to_keep_chowned(req, ids, owner, (&m, &m), &ctx);
            assert_eq!(k(all, (Some(0), Some(0)), (0, 0)), all);
            assert_eq!(k(all, (Some(1000), Some(1000)), (1000, 1000)), all);
            // 所有者が tar の ID と一致しない。
            assert_eq!(
                k(all, (Some(1000), Some(1000)), (1001, 1000)),
                S_ISGID | S_ISVTX
            );
            // 写像に無い ID（一致していても落とす）。
            assert_eq!(
                k(all, (Some(70_000), Some(0)), (70_000, 0)),
                S_ISGID | S_ISVTX
            );
            assert_eq!(k(all, (None, None), (0, 0)), S_ISVTX);
        }

        /// OCI-2: `/proc/self/status` の Uid / Gid 行の解析（effective と fs を取り、桁の過不足は拒否）。
        #[test]
        fn oci2_parse_status_ids() {
            let st = "Name:\tx\nUid:\t1000\t0\t1000\t0\nGid:\t1000\t0\t1000\t7\n";
            assert_eq!(parse_status_ids(st, "Uid:"), Some((0, 0)));
            assert_eq!(parse_status_ids(st, "Gid:"), Some((0, 7)));
            assert_eq!(parse_status_ids("Uid:\t1\t2\t3\n", "Uid:"), None);
            assert_eq!(parse_status_ids("Uid:\t1\t2\t3\t4\t5\n", "Uid:"), None);
            assert_eq!(parse_status_ids("Uid:\ta\t2\t3\t4\n", "Uid:"), None);
            assert_eq!(parse_status_ids("Name:\tx\n", "Uid:"), None);
        }
    }

    /// SEC-5: Linux 以外では chown を開始前に Unimplemented で拒否し、root に触れない（AC5）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec5_chown_is_unimplemented_off_linux() {
        let sb = Sandbox::new();
        let one = || {
            IdMap::new(vec![IdRange {
                container_id: 0,
                host_id: 1000,
                count: 1,
            }])
            .unwrap()
        };
        let setup = SpecialSetup {
            ownership: OwnershipPolicy::ChownMapped {
                uid: one(),
                gid: one(),
            },
            ..SpecialSetup::host(SpecialBitsPolicy::Strip)
        };
        let tar = archive(&[file("f", 0o644, b"x")]);
        let e = extract_stack(
            &NoopOciOpRecorder,
            [Rewind::new(Cursor::new(tar.as_slice()))],
            &sb.root,
            LIM(),
            host_lstat,
            setup,
        )
        .unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
    }

    /// SEC-5: Linux 以外では PreserveIfOwnerMapped でも特殊ビットをすべて落とす（Strip 相当。AC5）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec5_non_linux_preserve_policy_strips_everything() {
        let sb = Sandbox::new();
        let r = IdRange {
            container_id: 0,
            host_id: 1000,
            count: 1,
        };
        let tar = archive(&[file("suid", 0o4755, b"a")]);
        let l = single(
            extract_stack(
                &NoopOciOpRecorder,
                [Rewind::new(Cursor::new(tar.as_slice()))],
                &sb.root,
                LIM(),
                host_lstat,
                SpecialSetup::host(SpecialBitsPolicy::PreserveIfOwnerMapped { uid: r, gid: r }),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            l.special_bits.decision,
            SpecialBitsDecision::UnsupportedHost
        );
        assert_eq!(l.files_with_stripped_special_bits, 1);
        assert_eq!(l.ownership.decision, OwnershipDecision::NotRequested);
    }

    /// パス 1 とパス 3 で別の tar を返す `LayerSource`（開き直しの間の内容の変化を再現する）。
    struct Flip {
        opens: usize,
        first: Vec<u8>,
        second: Vec<u8>,
        expected: Option<Digest>,
    }

    impl LayerSource for Flip {
        type Reader<'a>
            = Cursor<Vec<u8>>
        where
            Self: 'a;

        fn open(&mut self) -> Result<Cursor<Vec<u8>>, OciError> {
            self.opens += 1;
            Ok(Cursor::new(if self.opens == 1 {
                self.first.clone()
            } else {
                self.second.clone()
            }))
        }

        fn expected_diff_id(&self) -> Option<&Digest> {
            self.expected.as_ref()
        }
    }

    fn sha_digest(data: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(data);
        digest_of(h).unwrap()
    }

    #[cfg(unix)]
    /// 2 回目の `open` の直前に `hook` を呼ぶ試験専用のラッパー（パス 1 とパス 3 の間の差し替えを再現する）。
    struct HookBeforeReopen<S, F: FnMut()> {
        inner: S,
        hook: F,
        opens: usize,
    }

    #[cfg(unix)]
    impl<S: LayerSource, F: FnMut()> LayerSource for HookBeforeReopen<S, F> {
        type Reader<'a>
            = S::Reader<'a>
        where
            Self: 'a;

        fn open(&mut self) -> Result<S::Reader<'_>, OciError> {
            self.opens += 1;
            if self.opens == 2 {
                (self.hook)();
            }
            self.inner.open()
        }

        fn expected_diff_id(&self) -> Option<&Digest> {
            self.inner.expected_diff_id()
        }
    }

    fn extract_one_source<S: LayerSource>(
        sb: &Sandbox,
        src: S,
    ) -> Result<Vec<ExtractedLayer>, OciError> {
        extract_stack(
            &NoopOciOpRecorder,
            [src],
            &sb.root,
            ExtractLimits::new(1000, 1 << 20, 1 << 30, 1 << 20),
            host_lstat,
            SpecialSetup::host(SpecialBitsPolicy::Strip),
        )
    }

    /// OCI-1・#2309: パス 1 とパス 3 で内容が変わったら（期待 diff_id の有無に依らず）`DataLoss`。3 OS で確かめる。
    #[test]
    fn oci1_content_change_between_passes_is_data_loss() {
        let a = archive(&[file("f", 0o644, b"hellp")]);
        let b = archive(&[file("f", 0o644, b"hello")]);
        for expected in [None, Some(sha_digest(&a))] {
            let sb = Sandbox::new();
            let e = extract_one_source(
                &sb,
                Flip {
                    opens: 0,
                    first: a.clone(),
                    second: b.clone(),
                    expected,
                },
            )
            .unwrap_err();
            assert_eq!(e.code(), OciErrorCode::DataLoss);
            assert_eq!(e.message(), "layer content changed between passes");
        }
    }

    /// OCI-1・#2309: 内容が変わらなければパス 3 の再ハッシュは成功し、結果の diff_id はパス 1 の値になる。
    #[test]
    fn oci1_unchanged_content_passes_rehash() {
        let a = archive(&[file("f", 0o644, b"hello")]);
        let sb = Sandbox::new();
        let r = extract_one_source(
            &sb,
            Flip {
                opens: 0,
                first: a.clone(),
                second: a.clone(),
                expected: Some(sha_digest(&a)),
            },
        )
        .unwrap();
        assert_eq!(r[0].diff_id, sha_digest(&a));
        assert_eq!(fs::read(sb.root.join("f")).unwrap(), b"hello");
    }

    /// 0600 で書いて `VerifiedLayerBlob` を作る（Unix 限定の試験用）。
    #[cfg(unix)]
    fn verified_blob(path: &Path, data: &[u8]) -> VerifiedLayerBlob {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(path).unwrap().uid();
        VerifiedLayerBlob::open(path, &sha_digest(data), data.len() as u64, uid).unwrap()
    }

    /// OCI-1・OCI-2・#2309: パス 1 とパス 3 の間にパスのエントリを別ファイルへ差し替えても、
    /// ハンドルを開き直さないので検証済みの内容が展開される。
    #[cfg(unix)]
    #[test]
    fn oci1_handle_layer_ignores_path_swap_between_passes() {
        let sb = Sandbox::new();
        let a = archive(&[file("a", 0o644, b"A1")]);
        let b = archive(&[file("a", 0o644, b"B2")]);
        let path = sb.base.join("l.tar");
        let blob = verified_blob(&path, &a);
        let evil = sb.base.join("evil.tar");
        let src = HookBeforeReopen {
            inner: VerifiedBlobLayer {
                blob: &blob,
                media_type: LayerMediaType::Tar,
                max_uncompressed_bytes: 1 << 20,
                expected_diff_id: Some(sha_digest(&a)),
            },
            hook: || {
                fs::write(&evil, &b).unwrap();
                fs::rename(&evil, &path).unwrap();
            },
            opens: 0,
        };
        let r = extract_one_source(&sb, src).unwrap();
        assert_eq!(fs::read(sb.root.join("a")).unwrap(), b"A1");
        assert_eq!(r[0].diff_id, sha_digest(&a));
    }

    /// OCI-1・#2309: パス 1 とパス 3 の間に同じ inode が書き換えられた場合は、パス 3 の再ハッシュで
    /// `DataLoss` になる（同じ UID なら信頼条件を保ったまま書けるため、ハンドル保持だけでは防げない）。
    #[cfg(unix)]
    #[test]
    fn oci1_handle_layer_detects_in_place_rewrite_between_passes() {
        let sb = Sandbox::new();
        let a = archive(&[file("a", 0o644, b"A1")]);
        let b = archive(&[file("a", 0o644, b"B2")]);
        let path = sb.base.join("l.tar");
        let blob = verified_blob(&path, &a);
        let src = HookBeforeReopen {
            inner: VerifiedBlobLayer {
                blob: &blob,
                media_type: LayerMediaType::Tar,
                max_uncompressed_bytes: 1 << 20,
                expected_diff_id: Some(sha_digest(&a)),
            },
            hook: || fs::write(&path, &b).unwrap(),
            opens: 0,
        };
        let e = extract_one_source(&sb, src).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(e.message(), "layer content changed between passes");
    }
    // ---- ディレクトリ fd 起点の解決と root の再確認（#2437・OCI-1・OCI-2・SEC-5） ----
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    mod anchored_tests {
        use super::*;
        use std::cell::{Cell, RefCell};
        use std::os::fd::{BorrowedFd, OwnedFd};
        use std::os::unix::fs::PermissionsExt as _;

        /// `Lstat` 経由で「確認の後、使用の前」の差し替えを起こす注入口（試験スレッド専用）。
        struct Trap {
            /// 差し替える対象のディレクトリ（`root` 配下の絶対パス）。
            victim: PathBuf,
            /// 差し替え後に `victim` が指す先（`root` の外のディレクトリ）。
            outside: PathBuf,
            /// `victim` が実在すると確認できた何回目で差し替えるか（1 始まり）。
            fire_on: u32,
            seen: u32,
        }

        thread_local! {
            static TRAP: RefCell<Option<Trap>> = const { RefCell::new(None) };
            /// 最初の `lstat` で 1 回だけ実行する副作用（`root` の mode / 所有者の変更を模す）。
            static ON_FIRST: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
            static ROOT_UID: Cell<u32> = const { Cell::new(1000) };
        }

        fn trap_lstat(p: &Path) -> std::io::Result<fs::Metadata> {
            if let Some(f) = ON_FIRST.with_borrow_mut(Option::take) {
                f();
            }
            // 先に確認の結果を取り、その後で差し替える（確認の後・使用の前に祖先が差し替わる状況）。
            let m = fs::symlink_metadata(p);
            TRAP.with_borrow_mut(|t| {
                if let Some(trap) = t.as_mut()
                    && p == trap.victim
                    && m.as_ref().is_ok_and(fs::Metadata::is_dir)
                {
                    trap.seen += 1;
                    if trap.seen == trap.fire_on {
                        let moved = trap.victim.with_extension("moved");
                        fs::rename(&trap.victim, &moved).unwrap();
                        std::os::unix::fs::symlink(&trap.outside, &trap.victim).unwrap();
                    }
                }
            });
            m
        }

        fn run_trap(
            sb: &Sandbox,
            layers: &[Vec<Vec<u8>>],
            setup: SpecialSetup,
        ) -> Result<Vec<ExtractedLayer>, OciError> {
            let tars: Vec<Vec<u8>> = layers.iter().map(|l| archive(l)).collect();
            extract_stack(
                &NoopOciOpRecorder,
                tars.iter().map(|t| Rewind::new(Cursor::new(t.as_slice()))),
                &sb.root,
                LIM(),
                trap_lstat,
                setup,
            )
        }

        fn arm(sb: &Sandbox, victim: &str, fire_on: u32) -> PathBuf {
            let outside = sb.base.join("outside");
            fs::create_dir_all(outside.join("b")).unwrap();
            fs::write(outside.join("x"), b"keep").unwrap();
            TRAP.with_borrow_mut(|t| {
                *t = Some(Trap {
                    victim: sb.root.join(victim),
                    outside: outside.clone(),
                    fire_on,
                    seen: 0,
                });
            });
            outside
        }

        fn disarm() {
            TRAP.with_borrow_mut(|t| *t = None);
            ON_FIRST.with_borrow_mut(|f| *f = None);
        }

        fn outside_listing(outside: &Path) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(outside)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            v.sort();
            v
        }

        /// SEC-5・OCI-1: 親ディレクトリが確認の後で `root` の外を指す symlink に差し替えられても、
        /// 書き込みは `FailedPrecondition` で拒否され、外側のディレクトリは変わらない。
        #[test]
        fn oci1_parent_swapped_to_symlink_after_probe_is_rejected() {
            let sb = Sandbox::new();
            let outside = arm(&sb, "a", 2);
            let r = run_trap(
                &sb,
                &[vec![
                    dir("a/", 0o755),
                    dir("a/b/", 0o755),
                    file("a/b/f", 0o644, b"data"),
                ]],
                SpecialSetup::host(SpecialBitsPolicy::Strip),
            );
            disarm();
            let e = r.expect_err("swap must be rejected");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "an extraction path changed during extraction");
            assert_eq!(outside_listing(&outside), vec!["b", "x"]);
            assert_eq!(outside_listing(&outside.join("b")), Vec::<String>::new());
            assert_eq!(fs::read(outside.join("x")).unwrap(), b"keep");
        }

        /// OCI-2・SEC-5: whiteout の適用中に親が外向きの symlink に差し替えられても、`root` の外のファイルは消えない。
        #[test]
        fn oci2_whiteout_parent_swapped_to_symlink_does_not_remove_outside() {
            let sb = Sandbox::new();
            let outside = arm(&sb, "d", 2);
            let r = run_trap(
                &sb,
                &[
                    vec![dir("d/", 0o755), file("d/x", 0o644, b"low")],
                    vec![wh("d/.wh.x")],
                ],
                SpecialSetup::host(SpecialBitsPolicy::Strip),
            );
            disarm();
            let e = r.expect_err("swap must be rejected");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(fs::read(outside.join("x")).unwrap(), b"keep");
            assert_eq!(outside_listing(&outside), vec!["b", "x"]);
        }

        /// SEC-5: 不透明ディレクトリの適用中の差し替えでも、外側の中身は消えない。
        #[test]
        fn oci2_opaque_parent_swapped_to_symlink_does_not_remove_outside() {
            let sb = Sandbox::new();
            let outside = arm(&sb, "d", 2);
            let r = run_trap(
                &sb,
                &[
                    vec![dir("d/", 0o755), file("d/y", 0o644, b"low")],
                    vec![wh("d/.wh..wh..opq")],
                ],
                SpecialSetup::host(SpecialBitsPolicy::Strip),
            );
            disarm();
            let e = r.expect_err("swap must be rejected");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(outside_listing(&outside), vec!["b", "x"]);
        }

        /// SEC-5: hardlink の参照先の祖先が確認の後で差し替えられても、リンクは作られず拒否される。
        #[test]
        fn oci1_hardlink_target_parent_swapped_is_rejected() {
            let sb = Sandbox::new();
            let outside = arm(&sb, "a", 2);
            // 差し替え後の `a/t` も通常ファイルに見える（確認は通り、使用の段で拒否される）ようにしておく。
            fs::write(outside.join("t"), b"out").unwrap();
            let r = run_trap(
                &sb,
                &[vec![
                    dir("a/", 0o755),
                    file("a/t", 0o644, b"t"),
                    hardlink("l", "a/t"),
                ]],
                SpecialSetup::host(SpecialBitsPolicy::Strip),
            );
            disarm();
            let e = r.expect_err("swap must be rejected");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert!(fs::symlink_metadata(sb.root.join("l")).is_err());
            assert_eq!(outside_listing(&outside), vec!["b", "t", "x"]);
            assert_eq!(fs::read(outside.join("t")).unwrap(), b"out");
        }

        fn setup_1000() -> SpecialSetup {
            fn owner(m: &fs::Metadata) -> (u32, u32) {
                if m.is_dir() {
                    (ROOT_UID.get(), 1000)
                } else {
                    (1000, 1000)
                }
            }
            SpecialSetup {
                owner_of: owner,
                ..SpecialSetup::host(policy_1000())
            }
        }

        /// SEC-5・#2437: 展開の途中で `root` が 0755 に変わると、以後の特殊ビットはすべて落ちる。
        /// 結果は `RootChangedDuringExtraction` で、落とした件数がビットごとに具体値で合う。
        #[test]
        fn sec5_root_mode_change_before_special_file_strips_remaining() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let root = sb.root.clone();
            ON_FIRST.with_borrow_mut(|f| {
                *f = Some(Box::new(move || {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
                }));
            });
            let r = run_trap(
                &sb,
                &[vec![
                    file_owned("suid", 0o4755, 0, 0, b"a"),
                    file_owned("sgid", 0o2755, 0, 0, b"b"),
                ]],
                setup_1000(),
            );
            disarm();
            let l = single(r.unwrap()).unwrap();
            assert_eq!(
                l.special_bits.decision,
                SpecialBitsDecision::RootChangedDuringExtraction
            );
            assert_eq!(l.special_bits.preserved_files, 0);
            assert_eq!(l.files_with_stripped_special_bits, 2);
            assert_eq!(
                (
                    l.special_bits.stripped_bits.setuid,
                    l.special_bits.stripped_bits.setgid,
                    l.special_bits.stripped_bits.sticky
                ),
                (1, 1, 0)
            );
            assert_eq!(mode_of(&sb.root.join("suid")), 0o755);
            assert_eq!(mode_of(&sb.root.join("sgid")), 0o755);
        }

        /// SEC-5・#2437: `root` の所有者が変わった場合も同様に落とす（所有者の変化は fstat の uid の変化で注入する）。
        #[test]
        fn sec5_root_owner_change_is_detected() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            ON_FIRST.with_borrow_mut(|f| *f = Some(Box::new(|| ROOT_UID.set(2000))));
            ROOT_UID.set(1000);
            let r = run_trap(
                &sb,
                &[vec![file_owned("suid", 0o4755, 0, 0, b"a")]],
                setup_1000(),
            );
            disarm();
            ROOT_UID.set(1000);
            let l = single(r.unwrap()).unwrap();
            assert_eq!(
                l.special_bits.decision,
                SpecialBitsDecision::RootChangedDuringExtraction
            );
            assert_eq!(l.special_bits.stripped_bits.setuid, 1);
            assert_eq!(mode_of(&sb.root.join("suid")), 0o755);
        }

        /// SEC-5・#2437: 保持済みのビットがある状態で `root` が変わったら、終了時に `FailedPrecondition` で拒否する。
        #[test]
        fn sec5_root_mode_change_after_preserved_file_fails_closed() {
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let root = sb.root.clone();
            // 1 件目（特殊ビット付き）を書いた後、2 件目（plain）の確認で `root` を 0755 にする。
            fn lstat_then_open(p: &Path) -> std::io::Result<fs::Metadata> {
                let m = fs::symlink_metadata(p);
                if p.file_name().is_some_and(|n| n == "plain") {
                    let root = p.parent().unwrap();
                    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
                }
                m
            }
            let tars = archive(&[
                file_owned("suid", 0o4755, 0, 0, b"a"),
                file("plain", 0o644, b"b"),
            ]);
            let r = extract_stack(
                &NoopOciOpRecorder,
                [Rewind::new(Cursor::new(tars.as_slice()))],
                &root,
                LIM(),
                lstat_then_open,
                setup_1000(),
            );
            disarm();
            let e = r.expect_err("fail closed");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "the extraction root changed while special mode bits were preserved"
            );
        }

        /// SEC-5・#2437: 要求 06755 のうち setuid だけが残った（setgid は読み戻しで落ちた）場合も保持済みとして数え、
        /// 終了時に `root` が変わっていれば `FailedPrecondition` で拒否する（部分保持の取りこぼしを防ぐ。#2565）。
        #[test]
        fn sec5_partial_preserve_then_root_change_fails_closed() {
            fn without_setgid(f: &fs::File) -> u32 {
                special_bits_of(f) & !S_ISGID
            }
            let sb = Sandbox::new();
            chmod_root(&sb, 0o700);
            let root = sb.root.clone();
            fn lstat_then_open(p: &Path) -> std::io::Result<fs::Metadata> {
                let m = fs::symlink_metadata(p);
                if p.file_name().is_some_and(|n| n == "plain") {
                    let root = p.parent().unwrap();
                    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
                }
                m
            }
            let tars = archive(&[
                file_owned("both", 0o6755, 0, 0, b"a"),
                file("plain", 0o644, b"b"),
            ]);
            let mut setup = setup_1000();
            setup.mode_readback = without_setgid;
            let r = extract_stack(
                &NoopOciOpRecorder,
                [Rewind::new(Cursor::new(tars.as_slice()))],
                &root,
                LIM(),
                lstat_then_open,
                setup,
            );
            disarm();
            let e = r.expect_err("fail closed");
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        }

        fn enosys(
            _d: Option<BorrowedFd<'_>>,
            _p: &std::ffi::CStr,
            _f: u64,
            _m: u64,
            _r: u64,
        ) -> std::io::Result<OwnedFd> {
            Err(std::io::Error::from_raw_os_error(crate::sys::at::ENOSYS))
        }

        /// OCI-1・#2437: `openat2` が使えないカーネルでは、パス起点へ縮退せず `root` に触れる前に `Unimplemented`。
        #[test]
        fn oci1_extract_refuses_when_openat2_unavailable() {
            let sb = Sandbox::new();
            let setup = SpecialSetup {
                anchor: AnchorHooks { openat2: enosys },
                ..SpecialSetup::host(SpecialBitsPolicy::Strip)
            };
            let r = run_trap(&sb, &[vec![file("f", 0o644, b"x")]], setup);
            let e = r.expect_err("must refuse");
            assert_eq!(e.code(), OciErrorCode::Unimplemented);
            assert_eq!(e.message(), "openat2 is not available on this kernel");
            assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
        }

        thread_local! {
            static EAGAIN_LEFT: Cell<u32> = const { Cell::new(0) };
        }

        fn flaky(
            d: Option<BorrowedFd<'_>>,
            p: &std::ffi::CStr,
            f: u64,
            m: u64,
            r: u64,
        ) -> std::io::Result<OwnedFd> {
            if d.is_some() && f & crate::sys::at::O_PATH != 0 && EAGAIN_LEFT.get() > 0 {
                EAGAIN_LEFT.set(EAGAIN_LEFT.get() - 1);
                return Err(std::io::Error::from_raw_os_error(crate::sys::at::EAGAIN));
            }
            crate::sys::at::openat2(d, p, f, m, r)
        }

        /// OCI-1・#2437: `EAGAIN` は上限つきで再試行する（1 回なら成功、無限なら `FailedPrecondition`）。
        #[test]
        fn oci1_eagain_is_retried_with_a_cap() {
            let setup = || SpecialSetup {
                anchor: AnchorHooks { openat2: flaky },
                ..SpecialSetup::host(SpecialBitsPolicy::Strip)
            };
            let sb = Sandbox::new();
            EAGAIN_LEFT.set(1);
            run_trap(&sb, &[vec![file("d/f", 0o644, b"x")]], setup()).unwrap();
            assert_eq!(fs::read(sb.root.join("d/f")).unwrap(), b"x");
            let sb2 = Sandbox::new();
            EAGAIN_LEFT.set(u32::MAX);
            let e = run_trap(&sb2, &[vec![file("d/f", 0o644, b"x")]], setup()).unwrap_err();
            EAGAIN_LEFT.set(0);
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
            assert_eq!(e.message(), "an extraction path changed during extraction");
        }
    }

    // ---- 期限と取り消し（REPAIR-5・CRI-2・#2899） ----

    thread_local! {
        static CLOCK_BASE: Instant = Instant::now();
        static CLOCK_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// 呼ぶたびに 1 秒進む試験用の時計（`ExtractBudget::now` へ注入する）。
    fn tick_clock() -> Instant {
        let n = CLOCK_CALLS.with(|c| {
            let v = c.get();
            c.set(v + 1);
            v
        });
        CLOCK_BASE.with(|b| *b) + std::time::Duration::from_secs(n)
    }

    fn bounded(
        sb: &Sandbox,
        entries: &[Vec<u8>],
        budget: &ExtractBudget<'_>,
    ) -> Result<Vec<ExtractedLayer>, OciError> {
        extract_layers_bounded(
            &NoopOciOpRecorder,
            [Cursor::new(archive(entries))],
            &sb.root,
            LIM(),
            &ExtractOptions::new(),
            budget,
        )
    }

    /// REPAIR-5: 期限がすでに過ぎていれば、最初のエントリより前に止まり rootfs を変えない。
    #[test]
    fn repair5_extract_deadline_elapsed_before_first_entry() {
        let sb = Sandbox::new();
        let budget = ExtractBudget::new().with_deadline(Instant::now());
        let e = bounded(&sb, &[file("a", 0o644, b"A")], &budget).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert_eq!(e.message(), "layer extraction exceeded its deadline");
        assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
        sb.assert_outside_untouched();
    }

    /// REPAIR-5: 期限はパス 3 のエントリごとに確かめる。3 件目の書き込みの前で止まり、先の 2 件は残る
    /// （契約: 呼び出し側が root ごと破棄する）。`remove_extracted_tree` で消えることも確かめる。
    #[test]
    fn repair5_extract_deadline_checked_per_entry() {
        let sb = Sandbox::new();
        CLOCK_CALLS.with(|c| c.set(0));
        // 呼び出し 0 = レイヤー前、1..=5 = パス 1 の 5 エントリ、6.. = パス 3。8 回目の呼び出し（3 件目）で期限。
        let mut budget = ExtractBudget::new()
            .with_deadline(CLOCK_BASE.with(|b| *b) + std::time::Duration::from_secs(8));
        budget.now = tick_clock;
        let entries = [
            file("a", 0o644, b"A"),
            file("b", 0o644, b"B"),
            file("c", 0o644, b"C"),
            file("d", 0o644, b"D"),
            file("e", 0o644, b"E"),
        ];
        let e = bounded(&sb, &entries, &budget).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert_eq!(e.message(), "layer extraction exceeded its deadline");
        let mut names: Vec<_> = fs::read_dir(&sb.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
        remove_extracted_tree(&sb.root).unwrap();
        assert!(!sb.root.exists());
    }

    /// REPAIR-5: 取り消しの旗が立っていれば最初の確認で止まる。
    #[test]
    fn repair5_extract_cancel_flag_stops_at_first_check() {
        let sb = Sandbox::new();
        let flag = AtomicBool::new(true);
        let budget = ExtractBudget::new().with_cancel(&flag);
        let e = bounded(&sb, &[file("a", 0o644, b"A")], &budget).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert_eq!(e.message(), "layer extraction was cancelled");
        assert_eq!(fs::read_dir(&sb.root).unwrap().count(), 0);
    }

    /// REPAIR-5: 空の予算は従来の入口と同じ結果になる。
    #[test]
    fn repair5_extract_empty_budget_matches_unbounded() {
        let sb1 = Sandbox::new();
        let sb2 = Sandbox::new();
        let entries = [dir("d", 0o755), file("d/f", 0o644, b"F")];
        let a = bounded(&sb1, &entries, &ExtractBudget::new()).unwrap();
        let b = extract_layers([Cursor::new(archive(&entries))], &sb2.root, LIM()).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].entries, b[0].entries);
        assert_eq!(fs::read(sb1.root.join("d/f")).unwrap(), b"F");
    }
}
