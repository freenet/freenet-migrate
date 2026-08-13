//! The sans-IO contract backward-probe **decision driver** (plan G1.4/G1.5).
//!
//! # Why sans-IO
//!
//! The crate cannot "drive the loop itself": on the browser target, stdlib's
//! `WebApi` delivers every response through one app-registered handler with no
//! request/response correlation, and each app has its own transport (Dioxus
//! handler, riverctl's tokio loop, Delta's ws). So the crate owns the
//! **decisions** — probe order, what counts as a hit, when to advance, when to
//! stop, what to adopt — and the app pumps I/O through a thin adapter:
//!
//! ```text
//! loop {
//!     match driver.next_action() {
//!         Step::Get(id)      => { send GET(id); arm a timer; }   // app I/O
//!         Step::Done(outcome) => break,                          // adopt it
//!     }
//!     // deliver events as they arrive:
//!     driver.on_response(id, &bytes);   // GET answered with state bytes
//!     driver.on_absent(id);             // GET answered NotFound
//!     driver.on_unknown(id);            // timer fired / send failed: state UNKNOWN
//! }
//! ```
//!
//! The two Delta incident classes are *decision* bugs, and both are
//! inexpressible in the part the driver owns:
//!
//! * **Generation-blind selection** ("rolled back to April"): candidates are
//!   probed strictly newest-first and the first real state wins, so an older
//!   generation can never shadow a newer one. That guarantee needs the newer
//!   generation to have been *ruled out*, not merely skipped: a candidate that
//!   never answered has an **unknown** state, so under
//!   [`SelectionPolicy::NewestFirstWins`] silence stops the probe
//!   ([`Outcome::Indeterminate`]) rather than falling through to an older
//!   generation. Continuing past silence is available, but it forfeits this
//!   guarantee and must be acknowledged
//!   ([`ProbeDriver::continue_past_unknown`]).
//! * **Stale-upgrade-pointer poisoning** (freenet/river#427): the driver
//!   never follows pointers found inside recovered state (newest-first order
//!   subsumes them), and a recovered generation's own pointer — which, PUT
//!   forward verbatim, would point BACKWARD from the current key — is what
//!   the [`ProbeStateOps::prepare_forward`] hook exists to strip.
//!
//! Honest limits — what stays app code the crate cannot verify: the I/O
//! adapter; the actual forward PUT of the outcome (and its subscribe); the
//! app's LOCAL adoption of the outcome (which may have its own
//! placeholder-vs-merge branch, as River's does); the seed decision on
//! [`Outcome::NoLegacy`]; and per-owner dedup of concurrent probes.
//!
//! # Decision semantics (matching River's shipped, field-proven **UI** probe;
//! riverctl's synchronous recovery differs slightly — it walks forward
//! upgrade chains inside its GET and skips the local merge — both of which
//! its adapter expresses via [`ProbeIo::get`] and a pass-through
//! `merge_with_local`)
//!
//! * Probe **newest-first**; stop at the **first real** state
//!   ([`SelectionPolicy::NewestFirstWins`], the default — see the policy
//!   section for why fold-all is opt-in).
//! * A response that fails to decode is a **miss** (a corrupt or
//!   ancient-format generation is skipped, never a panic, never adopted).
//!   (Making a schema break distinguishable from a plain miss is
//!   freenet/freenet-migrate#8, not this seam.)
//! * **Silence is not absence** (freenet/freenet-migrate#19). A candidate is a
//!   miss only when it *answered* — with state that does not decode or is not
//!   real ([`ProbeDriver::on_response`]), or with a positive "there is nothing
//!   here" ([`ProbeAnswer::Absent`] / [`ProbeDriver::on_absent`], e.g. stdlib's
//!   `ContractResponse::NotFound`). A timeout, send failure, or transport loss
//!   is [`ProbeAnswer::Unknown`] ([`ProbeDriver::on_unknown`]): the candidate is
//!   recorded as **unresolved** and the probe never reports a clean result that
//!   silently means "there was nothing to recover".
//! * Responses are **single-shot** per candidate: a late response for a
//!   candidate already advanced past (its timer fired first) is ignored —
//!   matching the shipped `take_probe` race semantics.
//! * A hop cap ([`ProbeDriver::with_max_hops`], default 64) bounds the walk.
//! * On exhaustion with every candidate *answered*, the outcome is **seed-local**
//!   ([`Outcome::SeedLocal`]): the caller's local snapshot goes forward, so
//!   recovery failure never silently discards device-local data. With any
//!   candidate unresolved it is [`Outcome::Indeterminate`] instead — nothing is
//!   adopted, nothing is sealed, and the app retries later.
//! * A hit is merged with the local snapshot via
//!   [`ProbeStateOps::merge_with_local`] **before** being surfaced, so the
//!   adopted state can never lose local-only writes.
//!
//! # Selection policy (G1.5)
//!
//! [`SelectionPolicy::NewestFirstWins`] adopts exactly one generation (the
//! newest with real state) and never reads older ones. This is River's shipped
//! behavior and is safe for delete-by-absence states (e.g. pruned messages):
//! what the newest generation dropped stays dropped.
//!
//! [`SelectionPolicy::FoldAll`] probes *every* candidate and folds all real
//! generations together (each older hit merged into the newest-side
//! accumulator, then the local snapshot). That is
//! only sound where **deletions are explicit (tombstoned)** and the merge is
//! **commutative and idempotent** — otherwise fold-all *resurrects*
//! delete-by-absence data from older generations. It therefore requires the
//! loudly-named [`FoldAllAck`], and the merge should pass the
//! [`policy_check`] property helpers first.

use freenet_stdlib::prelude::ContractInstanceId;

/// Default per-candidate hop cap (defence-in-depth; River ships 64).
pub const DEFAULT_MAX_PROBE_HOPS: usize = 64;

/// Advisory per-candidate timeout the I/O adapter should arm alongside each
/// [`Step::Get`] (River's UI ships 12s). The driver is sans-IO and never
/// sleeps; this is documentation-as-a-constant.
pub const RECOMMENDED_PROBE_TIMEOUT_MS: u64 = 12_000;

/// What a probe of one candidate actually established.
///
/// The three-way split exists because **absence and silence are different
/// facts, and only one of them is safe to act on** (freenet/freenet-migrate#19).
/// A two-way `Option` forces an adapter to encode "I never heard back" as "the
/// predecessor has nothing", which reads as a clean, complete migration while
/// the user's data sits un-recovered under the old key. Absence must be
/// *answered*, never inferred from a deadline.
///
/// `#[non_exhaustive]`: freenet/freenet-migrate#8 wants to tell an *undecodable*
/// answer apart from a plain miss, which is a fourth thing this type will
/// eventually have to carry. Reserving room now costs a wildcard arm in a
/// downstream `match`; not reserving it costs another breaking release.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeAnswer {
    /// The candidate answered with these raw state bytes. Whether they decode,
    /// and whether the decoded state is *real*, is
    /// [`ProbeStateOps`]'s call — an undecodable or placeholder answer is still
    /// an answer, and is a miss.
    State(Vec<u8>),
    /// The candidate answered **positively** that it holds no state — e.g.
    /// stdlib's `ContractResponse::NotFound`. The probe advances, and an
    /// all-`Absent` walk is a clean [`Outcome::SeedLocal`].
    ///
    /// Only return this for an answer you actually received. A deadline that
    /// expired is [`Unknown`](Self::Unknown).
    ///
    /// # `Absent` is the strongest negative Freenet can give. It is not proof.
    ///
    /// Absence is unauthenticated — any responding node can claim "not found" —
    /// and a contract that genuinely exists answers this way while it is
    /// momentarily unfindable. **On the current network that is the common
    /// case, not the corner case:** with the placement migration disabled
    /// (freenet-core#4440), present-but-unfindable dead-ends measured ~99.6% of
    /// all `get_not_found` traffic in production telemetry. A live-network
    /// check independently found 20 of 25 apparent failures had a `NotFound`
    /// logged for a key that exists.
    ///
    /// So `Absent` means **"asked, and told no"** — enough to advance the probe
    /// past a candidate, which is all this crate does with it. It does not
    /// license an irreversible conclusion. Where being wrong is permanent —
    /// sealing a generation as empty forever, or overwriting on the strength of
    /// it — make the operation idempotent so a later run recovers, require the
    /// same answer across separate attempts, or check you have a healthy
    /// connection first. Atlas is the worked example: it reports a not-found
    /// generation loudly, tells the operator to re-run, and keeps its merge
    /// idempotent so re-running works.
    ///
    /// This is a real limit of the network, not of this crate, and it is why
    /// [`Outcome::SeedLocal`] deliberately does not claim to be sealable.
    Absent,
    /// Nothing was established: the request timed out, the send failed, the
    /// transport dropped, the response was unparseable at the transport layer,
    /// or the correlation slot was cancelled.
    ///
    /// **Never treated as absence.** The candidate is recorded unresolved and
    /// surfaces in [`Outcome::Indeterminate`] or
    /// [`Outcome::Recovered::unresolved`], so the app retries instead of
    /// sealing the predecessor as empty.
    Unknown,
}

/// App-supplied state semantics: how to decode, classify, fold, and prepare
/// probe results. These are the pieces the crate *cannot* know — everything
/// else (sequencing) is driver-owned.
pub trait ProbeStateOps {
    /// The app's contract state type.
    type State;

    /// Decode raw GET response bytes. `None` marks the candidate a **miss**
    /// (undecodable generations are skipped defensively, mirroring River).
    fn decode(&self, bytes: &[u8]) -> Option<Self::State>;

    /// Whether a decoded state is *real* (e.g. River: the configuration
    /// signature verifies against the owner) as opposed to an empty/default
    /// placeholder. A non-real state is a miss.
    fn is_real(&self, state: &Self::State) -> bool;

    /// Fold a recovered generation (primary) with the device's local snapshot.
    /// Must never lose local-only writes; on an app-level merge failure,
    /// prefer returning `recovered` (the shipped keep-primary behavior).
    fn merge_with_local(&self, recovered: Self::State, local: &Self::State) -> Self::State;

    /// Fold an older recovered generation into the accumulator — used only by
    /// [`SelectionPolicy::FoldAll`]. Defaults to keeping the accumulator
    /// (i.e. fold-all degenerates to newest-wins) so implementing it is an
    /// explicit choice.
    fn merge_generations(&self, newer: Self::State, _older: Self::State) -> Self::State {
        newer
    }

    /// Last-mile preparation of the state that will be PUT forward under the
    /// current key. This is the seam for freenet/river#427's lesson: strip any
    /// *upgrade pointer* (or other key-relative metadata) carried inside
    /// recovered state, so a forward PUT cannot plant a pointer to an older
    /// generation on the current key. Defaults to identity.
    fn prepare_forward(&self, state: Self::State) -> Self::State {
        state
    }
}

/// Candidate ids proven to be in newest-first probe order — the ordering the
/// whole anti-rollback guarantee rests on, made a type instead of a doc
/// comment. Build it with [`NewestFirst::from_lineage`] (sorts by the
/// registry's `generation` field, descending — robust to a lineage slice
/// authored out of order) or, for lists that are newest-first **by
/// construction** (e.g. River's `legacy_contract_keys_for_owner`), with
/// [`NewestFirst::assume_ordered`].
#[derive(Debug, Clone)]
pub struct NewestFirst(Vec<ContractInstanceId>);

impl NewestFirst {
    /// Derive candidates from a lineage, sorted **descending by
    /// `generation`** — the registry's declared ordering field, not its slice
    /// order. A lineage slice authored out of order (e.g. a newly-discovered
    /// old generation appended last, as the CI guard's advice naturally
    /// invites) still probes newest-first.
    pub fn from_lineage(
        params: &freenet_stdlib::prelude::Parameters<'_>,
        lineage: &[crate::ContractLineageEntry],
    ) -> Self {
        let mut by_generation: Vec<(u32, ContractInstanceId)> = lineage
            .iter()
            .map(|e| {
                (
                    e.generation,
                    crate::contract_id_from_code_hash(&e.code_hash, params),
                )
            })
            .collect();
        by_generation.sort_by_key(|(generation, _)| core::cmp::Reverse(*generation));
        Self(by_generation.into_iter().map(|(_, id)| id).collect())
    }

    /// Wrap a list the caller guarantees is already newest-first. Only for
    /// lists ordered by construction; when in doubt use
    /// [`NewestFirst::from_lineage`], which cannot be handed a wrong order.
    pub fn assume_ordered(candidates_newest_first: Vec<ContractInstanceId>) -> Self {
        Self(candidates_newest_first)
    }

    /// Number of candidates.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no candidates.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// How hits are selected across generations. See the module docs.
#[derive(Debug)]
pub enum SelectionPolicy {
    /// Probe newest-first, adopt the first real state, never read older
    /// generations. The default; matches River's shipped, field-proven probe.
    NewestFirstWins,
    /// Probe every candidate and fold all real generations together
    /// (oldest-to-newest). Resurrects delete-by-absence data unless the state
    /// is fully tombstoned — hence the ack.
    FoldAll(FoldAllAck),
}

impl SelectionPolicy {
    /// Whether an unresolved candidate ([`ProbeAnswer::Unknown`]) terminates the
    /// probe. The delegate half's `SecretSelectionPolicy::unresponsive_terminates`
    /// makes the same call for the same reason: under a newest-wins policy,
    /// walking past an unknown newer generation risks adopting an older snapshot
    /// over a newer one that merely failed to answer. A fold-all sweep wants
    /// every generation anyway and its merge is commutative by precondition, so
    /// it keeps walking and reports the gap instead.
    fn unknown_terminates(&self) -> bool {
        matches!(self, SelectionPolicy::NewestFirstWins)
    }
}

/// Opt-in token for [`ProbeDriver::continue_past_unknown`]. Deliberately not
/// `Default`: holding one acknowledges that a recovered state may be a rollback
/// past a newer generation that was never ruled out.
#[must_use = "a RollbackRiskAck acknowledges that continuing past an unanswered candidate can \
              adopt an OLDER generation over a newer one that merely failed to answer; \
              construct it only if you have another reason to believe the newer generation is gone"]
#[derive(Debug)]
pub struct RollbackRiskAck(());

impl RollbackRiskAck {
    /// Construct the opt-in. The safe default is to stop at the first
    /// unanswered candidate and retry the whole probe later, which is what
    /// [`SelectionPolicy::NewestFirstWins`] does without this token.
    pub fn i_understand_continuing_past_silence_can_roll_back() -> Self {
        Self(())
    }
}

/// Opt-in token for [`SelectionPolicy::FoldAll`]. Deliberately not `Default`:
/// holding one acknowledges the resurrection precondition.
///
/// Two further fold-all consequences of the sequential, per-candidate-timeout
/// driver (vs e.g. Delta's shipped concurrent sweep): the fold surfaces as
/// ONE outcome (one forward PUT, no interim per-generation PUTs), and a
/// generation whose response outruns the app's per-candidate timer is dropped
/// from the fold (pump with a generous timer if that matters).
#[must_use = "a FoldAllAck acknowledges fold-all can resurrect deleted-by-absence data; \
              construct it only if the state is tombstoned and the merge passed policy_check"]
#[derive(Debug)]
pub struct FoldAllAck(());

impl FoldAllAck {
    /// Construct the opt-in. Only sound when deletions are explicit
    /// (tombstoned) and the merge is commutative + idempotent — verify with
    /// [`policy_check`] first.
    pub fn i_understand_fold_all_resurrects_without_tombstones() -> Self {
        Self(())
    }
}

/// What the app should do next. Obtained from [`ProbeDriver::next_action`], or
/// from [`crate::PointerResolver::next_action`] on the forward-discovery path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send a GET for this candidate (with `return_contract_code: true`,
    /// without subscribing — never subscribe to a legacy key), and arm a
    /// timeout (see [`RECOMMENDED_PROBE_TIMEOUT_MS`]). Deliver the result via
    /// [`ProbeDriver::on_response`], [`ProbeDriver::on_absent`] or
    /// [`ProbeDriver::on_unknown`] — an expired timer is `on_unknown`.
    ///
    /// A [`crate::PointerResolver`] emits the same step for the pointer
    /// contract, where the GET needs neither the code nor a subscription — the
    /// 100-byte record is the whole answer.
    Get(ContractInstanceId),
    /// The probe is finished; adopt the outcome. Repeated calls keep
    /// returning this.
    Done,
}

/// Terminal result of a probe, taken once via [`ProbeDriver::take_outcome`].
///
/// `#[non_exhaustive]`: a future variant must not silently join an existing
/// arm. Note the limit of that — it forces a wildcard arm on a `match`, but a
/// `matches!(outcome, Outcome::Recovered { .. })` still absorbs a new variant
/// without complaint, so it protects exhaustive matches only.
#[derive(Debug)]
#[non_exhaustive]
pub enum Outcome<S> {
    /// A predecessor generation had real state. `merged` is
    /// `merge_with_local(recovered, local)` passed through `prepare_forward`
    /// — PUT it under the **current** key (with subscribe) and adopt it
    /// locally. (Note: because one prepared value serves both, an app that
    /// wants River's exact split — adopt the *unstripped* merge locally,
    /// strip only on the PUT — keeps `prepare_forward` as identity and strips
    /// in its own PUT path instead.)
    Recovered {
        /// The prepared state to adopt and PUT forward.
        merged: S,
        /// The candidate that hit (newest real generation).
        source: ContractInstanceId,
        /// `true` when a [`SelectionPolicy::FoldAll`] sweep was cut short by
        /// the hop cap with candidates left unprobed: the fold is missing the
        /// oldest generations. Always `false` for
        /// [`SelectionPolicy::NewestFirstWins`] (stopping at the first hit is
        /// that policy's *definition*, not truncation). A FoldAll caller
        /// should surface or log a truncated fold — it opted into fold-all
        /// precisely because data may be spread across generations.
        truncated_fold: bool,
        /// Candidates that never answered ([`ProbeAnswer::Unknown`]) during
        /// this probe. Empty in the ordinary case.
        ///
        /// **Non-empty means this result is not the whole story.** Under
        /// [`SelectionPolicy::FoldAll`] the fold is missing those generations'
        /// contributions. Under [`SelectionPolicy::NewestFirstWins`] it can
        /// only be non-empty via [`ProbeDriver::continue_past_unknown`], and
        /// then it lists generations *newer* than `source` that were never
        /// ruled out — adopting `merged` may be a rollback past one of them.
        /// Either way the app should PUT forward but keep the migration open
        /// for a retry rather than recording it as finished.
        unresolved: Vec<ContractInstanceId>,
    },
    /// Every candidate was **asked and answered**, and none of the answers
    /// carried real state: seed the local snapshot forward (passed through
    /// `prepare_forward`), so local-only data survives. `local` is the snapshot
    /// handed to the driver.
    ///
    /// A probe that failed to reach a candidate, or never got to one because
    /// the hop cap fired, is [`Indeterminate`](Self::Indeterminate), never
    /// this.
    ///
    /// # This is evidence of nothing-to-recover, not proof of it
    ///
    /// **The crate does not tell you it is safe to record the migration as
    /// finished, because it cannot know that.** Sealing is the app's decision,
    /// and this outcome is the input to it, not the answer. Two reasons the
    /// evidence is weaker than it looks, both live today:
    ///
    /// * **A `NotFound` on Freenet is routinely wrong.** Absence is
    ///   unauthenticated, and a contract that exists answers `NotFound` while
    ///   it is momentarily unfindable. That is not a corner case at the time of
    ///   writing: with the placement migration disabled (freenet-core#4440),
    ///   present-but-unfindable dead-ends were measured at ~99.6% of all
    ///   `get_not_found` traffic. So an all-`Absent` walk is, on the current
    ///   network, more likely to be reporting a routing failure than an empty
    ///   lineage. See [`ProbeAnswer::Absent`].
    /// * **An undecodable answer also lands here.** [`ProbeStateOps::decode`]
    ///   returning `None`, and [`ProbeStateOps::is_real`] returning `false`,
    ///   are both misses — so a schema break across an entire lineage produces
    ///   this outcome with every generation intact underneath it. Making a
    ///   schema break distinguishable is freenet/freenet-migrate#8.
    ///
    /// So read this as **"asked everyone, found nothing this time"**. Seeding
    /// `local` forward is fine — it is your own data and the PUT is
    /// recoverable. Recording the predecessors as permanently empty on the
    /// strength of one such walk is not. See the README's "Upgrading to 0.6.0"
    /// for hardening that actually holds (idempotent re-runs, agreement across
    /// separate attempts, a connectivity witness).
    SeedLocal {
        /// The prepared local snapshot to PUT forward.
        local: S,
    },
    /// At least one candidate never answered ([`ProbeAnswer::Unknown`]) and no
    /// state was recovered, so **whether there is anything to recover is still
    /// unknown** (freenet/freenet-migrate#19).
    ///
    /// Do NOT treat this as [`SeedLocal`](Self::SeedLocal): recording the
    /// migration as done here would seal a predecessor that was merely slow or
    /// temporarily unreachable as permanently empty. Retry the probe on the
    /// next run instead.
    ///
    /// An app that must produce *something* on a first run — no state under the
    /// current key at all, and a predecessor unreachable across many attempts —
    /// can still PUT `local` forward, and for that reason it **is** passed
    /// through [`ProbeStateOps::prepare_forward`] like every other outgoing
    /// snapshot. (It has to be: `prepare_forward` is where an app strips a
    /// stale upgrade pointer out of state before it goes under the current key
    /// — freenet/river#427 — so handing back an unprepared snapshot on the one
    /// path that invites a judgement call would re-plant exactly what the hook
    /// exists to remove.) Seeding it is a deliberate app decision made with the
    /// uncertainty in hand, not a default it gets for free.
    Indeterminate {
        /// The prepared local snapshot. See the note above on why it is
        /// prepared even though this outcome does not ask you to PUT it.
        local: S,
        /// The candidates whose state was not established. Non-empty by
        /// construction. Covers both candidates that were asked and never
        /// answered, and candidates the walk never reached — because the hop
        /// cap fired, or because the policy halted at an earlier unknown.
        unresolved: Vec<ContractInstanceId>,
    },
    /// There were no candidates at all (fresh app / empty lineage): nothing
    /// to recover; proceed with the app's normal first-run path. The unused
    /// local snapshot is handed back untouched (no `prepare_forward` — it
    /// never entered a probe).
    NoLegacy {
        /// The local snapshot passed to the driver, returned unchanged.
        local: S,
    },
}

enum Phase<S> {
    Probing,
    Done(Option<Outcome<S>>),
}

/// The sans-IO backward-probe state machine. One driver instance = one probe
/// (one owner / one lineage). Deduplicating concurrent probes for the same
/// owner is the app's job (River keeps an in-flight map), but because
/// correlation is per-instance there is no cross-probe epoch machinery to get
/// wrong.
pub struct ProbeDriver<O: ProbeStateOps> {
    ops: O,
    policy: SelectionPolicy,
    local: Option<O::State>,
    /// Newest-first candidates not yet probed.
    remaining: Vec<ContractInstanceId>,
    outstanding: Option<ContractInstanceId>,
    hops: usize,
    max_hops: usize,
    /// FoldAll accumulator: (newest-hit source, folded state so far).
    fold_acc: Option<(ContractInstanceId, O::State)>,
    /// Candidates that never answered — the #19 record. Never conflated with a
    /// candidate that answered `Absent`.
    unresolved: Vec<ContractInstanceId>,
    /// Whether an unresolved candidate is allowed to be walked past under a
    /// policy that would otherwise stop (see [`ProbeDriver::continue_past_unknown`]).
    continue_past_unknown: bool,
    phase: Phase<O::State>,
}

impl<O: ProbeStateOps> ProbeDriver<O> {
    /// Start a probe over `candidates_newest_first` (e.g.
    /// [`crate::predecessor_ids`] reversed — the registry is oldest-first).
    /// `local_snapshot` is the device's current in-memory state for this
    /// contract (possibly default/empty).
    pub fn new(
        ops: O,
        local_snapshot: O::State,
        candidates: NewestFirst,
        policy: SelectionPolicy,
    ) -> Self {
        let (phase, local) = if candidates.is_empty() {
            (
                Phase::Done(Some(Outcome::NoLegacy {
                    local: local_snapshot,
                })),
                None,
            )
        } else {
            (Phase::Probing, Some(local_snapshot))
        };
        Self {
            ops,
            policy,
            local,
            remaining: candidates.0,
            outstanding: None,
            hops: 0,
            max_hops: DEFAULT_MAX_PROBE_HOPS,
            fold_acc: None,
            unresolved: Vec::new(),
            continue_past_unknown: false,
            phase,
        }
    }

    /// Override the hop cap (default [`DEFAULT_MAX_PROBE_HOPS`]).
    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = max_hops;
        self
    }

    /// Keep probing older candidates past one that never answered, instead of
    /// stopping with [`Outcome::Indeterminate`].
    ///
    /// Only [`SelectionPolicy::NewestFirstWins`] stops by default;
    /// [`SelectionPolicy::FoldAll`] already continues, so this is a no-op there.
    ///
    /// **This forfeits the anti-rollback guarantee for this probe** — hence the
    /// [`RollbackRiskAck`]. The unanswered candidates are still reported in
    /// [`Outcome::Recovered::unresolved`], so the result is never silently
    /// clean; what you give up is the refusal to adopt an older generation
    /// while a newer one is unaccounted for.
    ///
    /// Prefer wiring a real absence signal (stdlib's `ContractResponse::NotFound`
    /// → [`ProbeAnswer::Absent`]) over reaching for this: a probe whose
    /// candidates answer properly never stops here in the first place.
    pub fn continue_past_unknown(mut self, _ack: RollbackRiskAck) -> Self {
        self.continue_past_unknown = true;
        self
    }

    /// The current instruction. Idempotent: calling it repeatedly without an
    /// intervening event returns the same step (re-asking never advances the
    /// probe).
    pub fn next_action(&mut self) -> Step {
        if matches!(self.phase, Phase::Done(_)) {
            return Step::Done;
        }
        if let Some(id) = self.outstanding {
            return Step::Get(id);
        }
        // Advance to the next candidate, or finish.
        if self.remaining.is_empty() || self.hops >= self.max_hops {
            self.finish_exhausted();
            return Step::Done;
        }
        let id = self.remaining.remove(0);
        self.outstanding = Some(id);
        self.hops += 1;
        Step::Get(id)
    }

    /// Deliver a GET response for candidate `id`. Events for anything other
    /// than the outstanding candidate are ignored (single-shot semantics: the
    /// timeout already advanced past it, or it was never ours).
    pub fn on_response(&mut self, id: ContractInstanceId, bytes: &[u8]) {
        if self.outstanding != Some(id) || matches!(self.phase, Phase::Done(_)) {
            return;
        }
        self.outstanding = None;
        match self.ops.decode(bytes) {
            Some(state) if self.ops.is_real(&state) => self.on_hit(id, state),
            // Empty/default or undecodable → miss; next_action advances.
            _ => {}
        }
    }

    /// Deliver a **positive absence** for candidate `id`: the node answered
    /// that there is no state under that key (stdlib's
    /// `ContractResponse::NotFound`). The probe advances, and an all-absent
    /// walk ends in a clean [`Outcome::SeedLocal`]. See [`ProbeAnswer::Absent`]
    /// for what that answer is and is not worth — it is the strongest negative
    /// the network can give, not proof.
    ///
    /// Do not call this for a deadline that expired; that is
    /// [`on_unknown`](Self::on_unknown). Stale events (for a candidate no
    /// longer outstanding) are ignored.
    pub fn on_absent(&mut self, id: ContractInstanceId) {
        if matches!(self.phase, Phase::Done(_)) {
            return;
        }
        if self.outstanding == Some(id) {
            self.outstanding = None;
        }
    }

    /// Deliver a **non-answer** for candidate `id`: a timeout, a send failure,
    /// a dropped transport, a cancelled correlation slot — anything that leaves
    /// the candidate's state unknown.
    ///
    /// The candidate is recorded as unresolved, never as empty. Under
    /// [`SelectionPolicy::NewestFirstWins`] this ends the probe with
    /// [`Outcome::Indeterminate`] (see [`continue_past_unknown`](Self::continue_past_unknown)
    /// to walk on anyway); under [`SelectionPolicy::FoldAll`] the probe
    /// continues and the id is reported in the terminal outcome. Stale events
    /// are ignored.
    pub fn on_unknown(&mut self, id: ContractInstanceId) {
        if matches!(self.phase, Phase::Done(_)) {
            return;
        }
        if self.outstanding != Some(id) {
            return;
        }
        self.outstanding = None;
        // Two lineage entries can share a code_hash (a re-published identical
        // build), so the same id can come round twice; record it once.
        if !self.unresolved.contains(&id) {
            self.unresolved.push(id);
        }
        if self.policy.unknown_terminates() && !self.continue_past_unknown {
            self.finish_indeterminate();
        }
    }

    /// Deliver a timeout for candidate `id`.
    ///
    /// Renamed to [`on_unknown`](Self::on_unknown) in 0.6.0, which is what this
    /// forwards to: a timeout establishes nothing, and treating it as absence is
    /// the data-loss default freenet/freenet-migrate#19 removed.
    ///
    /// # If you route a real not-found here, recovery stops working
    ///
    /// The forwarding is safe in the sense that matters most — it can never
    /// seal a predecessor as empty. It is **not** a drop-in for a call site that
    /// was also delivering positive absences through this method, and the
    /// failure is not subtle:
    ///
    /// Under [`SelectionPolicy::NewestFirstWins`] an unknown **halts the walk**.
    /// So an app whose only failure path is a watchdog — one that never handles
    /// the network's `NotFound` and lets an absent generation fall through to a
    /// timeout — will, after upgrading, stop at its first empty generation and
    /// never ask the older ones. If the generation holding the user's data is
    /// further down the lineage, it is never probed, and every probe ends in
    /// [`Outcome::Indeterminate`]. That is a recovery **outage**, not a
    /// conservative degradation: it goes from recovering to never recovering.
    ///
    /// River is exactly this shape today, so the upgrade is not optional there.
    /// Wire the real not-found signal to [`on_absent`](Self::on_absent) — see
    /// the README's "Upgrading to 0.6.0" — and the walk advances as before.
    #[deprecated(
        since = "0.6.0",
        note = "silence and absence are different facts: use `on_unknown` for a timeout or \
                transport failure, `on_absent` for an answered NotFound. See freenet-migrate#19."
    )]
    pub fn on_timeout(&mut self, id: ContractInstanceId) {
        self.on_unknown(id);
    }

    /// Take the terminal outcome (once). `None` until [`Step::Done`], or if
    /// already taken.
    pub fn take_outcome(&mut self) -> Option<Outcome<O::State>> {
        match &mut self.phase {
            Phase::Done(outcome) => outcome.take(),
            Phase::Probing => None,
        }
    }

    fn on_hit(&mut self, source: ContractInstanceId, state: O::State) {
        match &self.policy {
            SelectionPolicy::NewestFirstWins => {
                let local = self.local.take().expect("local consumed once");
                let merged = self.ops.merge_with_local(state, &local);
                let prepared = self.ops.prepare_forward(merged);
                self.phase = Phase::Done(Some(Outcome::Recovered {
                    merged: prepared,
                    source,
                    truncated_fold: false,
                    // Only reachable non-empty via `continue_past_unknown`:
                    // these are generations NEWER than `source` that were never
                    // ruled out, so the caller is told this adoption may be a
                    // rollback past one of them.
                    unresolved: core::mem::take(&mut self.unresolved),
                }));
            }
            SelectionPolicy::FoldAll(_) => {
                // Keep probing; fold this (older) hit into the accumulator.
                // Candidates arrive newest-first, so the accumulator is the
                // newer side.
                self.fold_acc = Some(match self.fold_acc.take() {
                    None => (source, state),
                    Some((first_source, acc)) => {
                        (first_source, self.ops.merge_generations(acc, state))
                    }
                });
            }
        }
    }

    fn finish_exhausted(&mut self) {
        let local = self.local.take().expect("local consumed once");
        // Candidates left unprobed means the hop cap fired, not exhaustion.
        let truncated_fold = !self.remaining.is_empty();
        let mut unresolved = core::mem::take(&mut self.unresolved);
        // A candidate the hop cap cut off was never ASKED, which is a stronger
        // form of "we do not know" than one that failed to answer. Folding the
        // unprobed remainder in here is what stops `SeedLocal` claiming "every
        // candidate answered" for candidates the walk never reached.
        for id in self.remaining.drain(..) {
            if !unresolved.contains(&id) {
                unresolved.push(id);
            }
        }
        let outcome = match self.fold_acc.take() {
            Some((source, folded)) => {
                let merged = self.ops.merge_with_local(folded, &local);
                Outcome::Recovered {
                    merged: self.ops.prepare_forward(merged),
                    source,
                    truncated_fold,
                    unresolved,
                }
            }
            // Nothing recovered. Whether that means "there was nothing" or
            // "we never found out" is exactly the #19 distinction: only a
            // walk that asked every candidate AND got an answer from each
            // reaches SeedLocal.
            None if unresolved.is_empty() => Outcome::SeedLocal {
                local: self.ops.prepare_forward(local),
            },
            None => Outcome::Indeterminate {
                local: self.ops.prepare_forward(local),
                unresolved,
            },
        };
        self.phase = Phase::Done(Some(outcome));
    }

    /// End the probe because a candidate never answered and the policy will not
    /// walk past an unknown.
    ///
    /// There is never a partial fold to surface here. Only `NewestFirstWins`
    /// stops on silence ([`SelectionPolicy::unknown_terminates`]), and that
    /// policy never fills `fold_acc` — its `on_hit` finishes the probe outright.
    /// A fold-all sweep that meets silence keeps walking and ends in
    /// [`finish_exhausted`](Self::finish_exhausted), which does surface the
    /// fold. The `debug_assert` pins that; were it ever wrong, dropping to
    /// `Indeterminate` is the fail-safe direction anyway, since it tells the
    /// caller to adopt nothing and retry.
    fn finish_indeterminate(&mut self) {
        debug_assert!(
            self.fold_acc.is_none(),
            "a policy that stops on silence never accumulates a fold"
        );
        let local = self.local.take().expect("local consumed once");
        let mut unresolved = core::mem::take(&mut self.unresolved);
        // Candidates the halt means we will never ask are unknown too.
        for id in self.remaining.drain(..) {
            if !unresolved.contains(&id) {
                unresolved.push(id);
            }
        }
        self.phase = Phase::Done(Some(Outcome::Indeterminate {
            local: self.ops.prepare_forward(local),
            unresolved,
        }));
    }
}

/// Build a probe driver from a lineage: candidates are sorted newest-first
/// **by the `generation` field** (never by slice order — see
/// [`NewestFirst::from_lineage`]). This is the assembly the high-level entry
/// point ([`migrate_contract`]) uses.
///
/// Probing is deliberately **sequential** (one outstanding candidate at a
/// time): bounded, deterministic, and sufficient for the newest-first policy
/// (which usually stops at the first candidate). For fold-all this makes the
/// sweep strictly serial — worst case N × timeout for a lineage of N where
/// the newer generations are gone, vs ~one timeout for a concurrent sweep
/// (what Delta ships today, with interim re-PUTs as generations arrive). A
/// concurrent-sweep mode (multiple outstanding candidates) is an OPEN
/// DECISION explicitly gated on the Delta adoption phase: build it against
/// Delta's real constraints then, or document that Delta accepts the
/// sequential trade. Do not silently widen this driver to concurrency without
/// revisiting the single-shot correlation semantics.
pub fn contract_probe<O: ProbeStateOps>(
    ops: O,
    local_snapshot: O::State,
    params: &freenet_stdlib::prelude::Parameters<'_>,
    lineage: &[crate::ContractLineageEntry],
    policy: SelectionPolicy,
) -> ProbeDriver<O> {
    ProbeDriver::new(
        ops,
        local_snapshot,
        NewestFirst::from_lineage(params, lineage),
        policy,
    )
}

/// The thin per-environment I/O adapter for the pumped entry point
/// ([`migrate_contract`]): one GET, awaited, with the app's own timeout.
///
/// * Return [`ProbeAnswer::State`] with the raw GET response state bytes.
/// * Return [`ProbeAnswer::Absent`] **only** when the node answered that there
///   is no state under the key (stdlib's `ContractResponse::NotFound`).
/// * Return [`ProbeAnswer::Unknown`] for a timeout, a send failure, or anything
///   else that left the candidate's state unestablished. The probe records it
///   as unresolved rather than empty (freenet/freenet-migrate#19), so a slow or
///   temporarily unreachable predecessor is retried instead of sealed.
/// * Return `Err` only for conditions that should **abort** the whole
///   migration (the driver's decisions are lost and the caller sees the
///   error). A per-candidate transport failure is [`ProbeAnswer::Unknown`], not
///   an abort.
///
/// The three-way return is deliberate: an adapter cannot express "I never heard
/// back" as "the predecessor has nothing" without typing
/// [`ProbeAnswer::Absent`] and being wrong on purpose.
pub trait ProbeIo {
    /// The app's transport error type (for the abort path only).
    type Error;

    /// GET the state bytes for `id` — without subscribing, with
    /// `return_contract_code: true`, bounded by a timeout of roughly
    /// [`RECOMMENDED_PROBE_TIMEOUT_MS`]. An expired timeout is
    /// [`ProbeAnswer::Unknown`].
    fn get(
        &mut self,
        id: ContractInstanceId,
    ) -> impl core::future::Future<Output = Result<ProbeAnswer, Self::Error>>;
}

/// High-level contract-migration entry point (G1.7, contract half): drive a
/// backward probe over the lineage to completion, pumping I/O through
/// `io`. The returned [`Outcome`] tells the app what to adopt and PUT forward
/// (see each variant's docs); the PUT itself stays app code.
///
/// Environments without awaitable request/response correlation (the browser's
/// shared-handler `WebApi`) use the [`ProbeDriver`] directly instead and pump
/// events by hand — this wrapper and the raw driver make identical decisions
/// by construction (the wrapper is a trivial loop over the same machine).
///
/// On an `Err` abort from [`ProbeIo::get`], the driver — and the local
/// snapshot moved into it — is dropped; clone the snapshot before calling if
/// you need it on the failure path. (Prefer mapping recoverable conditions to
/// [`ProbeAnswer::Unknown`], which is a per-candidate non-answer, not an abort.)
pub async fn migrate_contract<O, IO>(
    ops: O,
    io: &mut IO,
    local_snapshot: O::State,
    params: &freenet_stdlib::prelude::Parameters<'_>,
    lineage: &[crate::ContractLineageEntry],
    policy: SelectionPolicy,
) -> Result<Outcome<O::State>, IO::Error>
where
    O: ProbeStateOps,
    IO: ProbeIo,
{
    let mut driver = contract_probe(ops, local_snapshot, params, lineage, policy);
    loop {
        match driver.next_action() {
            Step::Get(id) => match io.get(id).await? {
                ProbeAnswer::State(bytes) => driver.on_response(id, &bytes),
                ProbeAnswer::Absent => driver.on_absent(id),
                ProbeAnswer::Unknown => driver.on_unknown(id),
            },
            Step::Done => {
                return Ok(driver
                    .take_outcome()
                    .expect("Step::Done implies an untaken outcome"));
            }
        }
    }
}

/// Property helpers for [`SelectionPolicy::FoldAll`]'s preconditions (G1.5):
/// run these over representative states in the app's tests *before* opting in.
pub mod policy_check {
    /// Assert `merge` is commutative over every pair in `samples`:
    /// `merge(a, b) == merge(b, a)`.
    ///
    /// # Panics
    /// On the first non-commutative pair (this is a test helper).
    pub fn assert_merge_commutative<S, M>(samples: &[S], merge: M)
    where
        S: Clone + PartialEq + core::fmt::Debug,
        M: Fn(S, S) -> S,
    {
        for (i, a) in samples.iter().enumerate() {
            for (j, b) in samples.iter().enumerate() {
                let ab = merge(a.clone(), b.clone());
                let ba = merge(b.clone(), a.clone());
                assert_eq!(ab, ba, "merge is not commutative for samples #{i} and #{j}");
            }
        }
    }

    /// Assert `merge` is idempotent over `samples`: `merge(a, a) == a`.
    ///
    /// # Panics
    /// On the first non-idempotent sample (this is a test helper).
    pub fn assert_merge_idempotent<S, M>(samples: &[S], merge: M)
    where
        S: Clone + PartialEq + core::fmt::Debug,
        M: Fn(S, S) -> S,
    {
        for (i, a) in samples.iter().enumerate() {
            assert_eq!(
                merge(a.clone(), a.clone()),
                a.clone(),
                "merge is not idempotent for sample #{i}"
            );
        }
    }

    /// Assert folding `samples` is order-invariant: folding left-to-right
    /// equals folding right-to-left. Necessary but not sufficient — a
    /// non-associative merge can agree on these two orders by luck; passing
    /// does not *prove* order-invariance (full permutation checking is the
    /// app's prerogative; commutativity + associativity imply it).
    ///
    /// # Panics
    /// If the two fold orders disagree (this is a test helper).
    pub fn assert_fold_order_invariant<S, M>(samples: &[S], merge: M)
    where
        S: Clone + PartialEq + core::fmt::Debug,
        M: Fn(S, S) -> S,
    {
        let Some(first) = samples.first() else { return };
        let forward = samples[1..]
            .iter()
            .fold(first.clone(), |acc, s| merge(acc, s.clone()));
        let last = samples.last().expect("non-empty");
        let backward = samples[..samples.len() - 1]
            .iter()
            .rev()
            .fold(last.clone(), |acc, s| merge(acc, s.clone()));
        assert_eq!(
            forward, backward,
            "fold over samples is order-dependent; fold-all is not sound for this merge"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature "room state": a set of message ids plus a real/placeholder
    /// bit. Delete-by-absence: pruned ids simply vanish — the model for the
    /// resurrection tests.
    #[derive(Debug, Clone, PartialEq)]
    struct MiniState {
        real: bool,
        messages: Vec<u32>,
    }

    impl MiniState {
        fn real(messages: &[u32]) -> Self {
            Self {
                real: true,
                messages: messages.to_vec(),
            }
        }
        fn empty() -> Self {
            Self {
                real: false,
                messages: vec![],
            }
        }
        fn encode(&self) -> Vec<u8> {
            let mut out = vec![u8::from(self.real)];
            for m in &self.messages {
                out.extend_from_slice(&m.to_le_bytes());
            }
            out
        }
    }

    struct MiniOps;

    impl ProbeStateOps for MiniOps {
        type State = MiniState;

        fn decode(&self, bytes: &[u8]) -> Option<MiniState> {
            if bytes.is_empty() || !(bytes.len() - 1).is_multiple_of(4) {
                return None; // undecodable
            }
            let real = bytes[0] == 1;
            let messages = bytes[1..]
                .chunks(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            Some(MiniState { real, messages })
        }

        fn is_real(&self, state: &MiniState) -> bool {
            state.real
        }

        fn merge_with_local(&self, mut recovered: MiniState, local: &MiniState) -> MiniState {
            for m in &local.messages {
                if !recovered.messages.contains(m) {
                    recovered.messages.push(*m);
                }
            }
            recovered.messages.sort_unstable();
            recovered
        }

        fn merge_generations(&self, mut newer: MiniState, older: MiniState) -> MiniState {
            for m in older.messages {
                if !newer.messages.contains(&m) {
                    newer.messages.push(m);
                }
            }
            newer.messages.sort_unstable();
            newer
        }
    }

    fn id(n: u8) -> ContractInstanceId {
        ContractInstanceId::new([n; 32])
    }

    fn driver(candidates: &[u8], local: MiniState) -> ProbeDriver<MiniOps> {
        ProbeDriver::new(
            MiniOps,
            local,
            NewestFirst::assume_ordered(candidates.iter().map(|n| id(*n)).collect()),
            SelectionPolicy::NewestFirstWins,
        )
    }

    #[test]
    fn empty_lineage_is_no_legacy() {
        let mut d = driver(&[], MiniState::empty());
        assert_eq!(d.next_action(), Step::Done);
        assert!(matches!(d.take_outcome(), Some(Outcome::NoLegacy { .. })));
        // Taken once.
        assert!(d.take_outcome().is_none());
    }

    #[test]
    fn first_real_hit_wins_and_merges_local() {
        let local = MiniState::real(&[100]);
        let mut d = driver(&[3, 2, 1], local);
        let Step::Get(first) = d.next_action() else {
            panic!()
        };
        assert_eq!(first, id(3)); // newest first
        d.on_response(first, &MiniState::real(&[1, 2]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { merged, source, .. }) = d.take_outcome() else {
            panic!("expected recovery")
        };
        assert_eq!(source, id(3));
        assert_eq!(merged.messages, vec![1, 2, 100]); // local folded in
    }

    #[test]
    fn generation_blind_selection_is_inexpressible() {
        // The Delta incident class: an OLDER real generation must never be
        // adopted over a NEWER real one. Both gens are real; the driver stops
        // at the newest and never even probes the older.
        let mut d = driver(&[9, 5], MiniState::empty());
        let Step::Get(newest) = d.next_action() else {
            panic!()
        };
        assert_eq!(newest, id(9));
        d.on_response(newest, &MiniState::real(&[2026]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { source, merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(source, id(9), "older generation must not shadow newer");
        assert_eq!(merged.messages, vec![2026]);
    }

    #[test]
    fn newest_first_does_not_resurrect_deletions() {
        // Older gen has messages [1,2,3]; newest gen pruned 3 (delete by
        // absence). NewestFirstWins adopts the newest and never reads the
        // older — 3 stays deleted.
        let mut d = driver(&[8, 4], MiniState::empty());
        let Step::Get(newest) = d.next_action() else {
            panic!()
        };
        d.on_response(newest, &MiniState::real(&[1, 2]).encode());
        let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(merged.messages, vec![1, 2], "pruned message resurrected");
    }

    #[test]
    fn answered_misses_advance_then_exhaustion_seeds_local() {
        let local = MiniState::real(&[7]);
        let mut d = driver(&[3, 2, 1], local);
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::empty().encode()); // empty → miss
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        assert_eq!(b, id(2));
        d.on_absent(b); // answered NotFound → miss
        let Step::Get(c) = d.next_action() else {
            panic!()
        };
        assert_eq!(c, id(1));
        d.on_response(c, b"junk-not-decodable"); // undecodable → miss
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::SeedLocal { local }) = d.take_outcome() else {
            panic!("exhaustion must seed the local snapshot")
        };
        assert_eq!(local.messages, vec![7]);
    }

    #[test]
    fn late_response_after_absent_is_ignored() {
        // The take_probe single-shot race: candidate timed out (we advanced),
        // then its real response arrives late — it must be dropped, matching
        // shipped semantics.
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_absent(a);
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        // Late (stale) response for a — ignored even though it's a hit.
        d.on_response(a, &MiniState::real(&[42]).encode());
        assert_eq!(d.next_action(), Step::Get(b));
        d.on_response(b, &MiniState::empty().encode());
        assert_eq!(d.next_action(), Step::Done);
        assert!(matches!(d.take_outcome(), Some(Outcome::SeedLocal { .. })));
    }

    #[test]
    fn stale_absent_for_advanced_candidate_is_ignored() {
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::empty().encode());
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_absent(a); // stale — must not consume b's slot
        assert_eq!(d.next_action(), Step::Get(b));
        d.on_response(b, &MiniState::real(&[5]).encode());
        assert!(matches!(d.take_outcome(), Some(Outcome::Recovered { .. })));
    }

    #[test]
    fn next_action_is_idempotent_while_outstanding() {
        let mut d = driver(&[3, 2], MiniState::empty());
        let first = d.next_action();
        assert_eq!(d.next_action(), first);
        assert_eq!(d.next_action(), first, "re-asking must not advance");
    }

    /// The hop cap bounds the walk — and the candidates it cut off are
    /// reported, not silently dropped.
    ///
    /// Before this was fixed the cap produced a clean `SeedLocal`, whose own
    /// doc promised "every candidate answered", for seven candidates that were
    /// never asked. That is the #19 shape with the cap as its trigger: an app
    /// reading `SeedLocal` as "the predecessors had nothing" would seal a
    /// lineage most of which it never looked at.
    #[test]
    fn hop_cap_reports_the_candidates_it_never_asked() {
        let candidates: Vec<u8> = (1..=10).rev().collect();
        let mut d = driver(&candidates, MiniState::real(&[1])).with_max_hops(3);
        for _ in 0..3 {
            let Step::Get(g) = d.next_action() else {
                panic!()
            };
            d.on_absent(g);
        }
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { unresolved, .. }) = d.take_outcome() else {
            panic!("a cap-cut walk has not asked every candidate, so it cannot be SeedLocal")
        };
        assert_eq!(
            unresolved.len(),
            7,
            "the 7 candidates the cap cut off must be named"
        );
        // The 3 that were asked and answered Absent are NOT unresolved.
        for probed in [id(10), id(9), id(8)] {
            assert!(!unresolved.contains(&probed), "{probed} answered");
        }
    }

    #[test]
    fn fold_all_probes_everything_and_folds_oldest_into_newest() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[100]),
            NewestFirst::assume_ordered(vec![id(3), id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[1, 2]).encode());
        // FoldAll keeps probing after a hit.
        let Step::Get(b) = d.next_action() else {
            panic!("fold-all must continue probing")
        };
        d.on_response(b, &MiniState::empty().encode());
        let Step::Get(c) = d.next_action() else {
            panic!()
        };
        d.on_response(c, &MiniState::real(&[3]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { merged, source, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(source, id(3), "source is the newest hit");
        // All generations + local folded together — including the older gen's
        // [3] that NewestFirstWins would have (correctly, for River) dropped.
        assert_eq!(merged.messages, vec![1, 2, 3, 100]);
    }

    #[test]
    fn prepare_forward_runs_on_every_outcome_path() {
        struct StripOps;
        impl ProbeStateOps for StripOps {
            type State = MiniState;
            fn decode(&self, bytes: &[u8]) -> Option<MiniState> {
                MiniOps.decode(bytes)
            }
            fn is_real(&self, s: &MiniState) -> bool {
                MiniOps.is_real(s)
            }
            fn merge_with_local(&self, r: MiniState, l: &MiniState) -> MiniState {
                MiniOps.merge_with_local(r, l)
            }
            fn prepare_forward(&self, mut s: MiniState) -> MiniState {
                // Model the #427 pointer strip: message 0 is "the pointer".
                s.messages.retain(|m| *m != 0);
                s
            }
        }
        // Recovered path.
        let mut d = ProbeDriver::new(
            StripOps,
            MiniState::empty(),
            NewestFirst::assume_ordered(vec![id(1)]),
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[0, 9]).encode());
        let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(merged.messages, vec![9], "pointer must be stripped");
        // SeedLocal path.
        let mut d = ProbeDriver::new(
            StripOps,
            MiniState::real(&[0, 5]),
            NewestFirst::assume_ordered(vec![id(1)]),
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_absent(a);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::SeedLocal { local }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(local.messages, vec![5], "pointer must be stripped on seed");
    }

    /// Delta incident regression (bug class B, delta#34 MUST-FIX 1): a
    /// selection rule based on scalar recency (max timestamp) resurrects a
    /// deleted-NEWEST item, because the deletion *lowers* the max. The driver
    /// makes that rule inexpressible: it never compares recency scalars —
    /// selection is structural (newest-first order or app-merge fold), and a
    /// tombstone-aware merge preserves the deletion in BOTH probe orders.
    #[test]
    fn fold_preserves_tombstoned_deletion_scalar_recency_is_inexpressible() {
        // Tombstone-aware mini-state: negative-marker encoding — a tombstone
        // for message m is encoded as the id m with the high bit set.
        #[derive(Debug, Clone, PartialEq)]
        struct TombState {
            live: Vec<u32>,
            tombs: Vec<u32>,
        }
        impl TombState {
            fn encode(&self) -> Vec<u8> {
                let mut out = vec![1u8];
                for m in &self.live {
                    // The high bit is the tombstone marker; a live id using it
                    // would decode as a tombstone and corrupt the model.
                    assert!(*m < 0x8000_0000, "live id collides with tomb marker");
                    out.extend_from_slice(&m.to_le_bytes());
                }
                for t in &self.tombs {
                    out.extend_from_slice(&(t | 0x8000_0000).to_le_bytes());
                }
                out
            }
        }
        struct TombOps;
        impl ProbeStateOps for TombOps {
            type State = TombState;
            fn decode(&self, bytes: &[u8]) -> Option<TombState> {
                if bytes.is_empty() || !(bytes.len() - 1).is_multiple_of(4) {
                    return None;
                }
                let mut s = TombState {
                    live: vec![],
                    tombs: vec![],
                };
                for c in bytes[1..].chunks(4) {
                    let v = u32::from_le_bytes(c.try_into().unwrap());
                    if v & 0x8000_0000 != 0 {
                        s.tombs.push(v & 0x7fff_ffff);
                    } else {
                        s.live.push(v);
                    }
                }
                Some(s)
            }
            fn is_real(&self, s: &TombState) -> bool {
                !s.live.is_empty() || !s.tombs.is_empty()
            }
            fn merge_with_local(&self, r: TombState, l: &TombState) -> TombState {
                self.merge_generations(r, l.clone())
            }
            fn merge_generations(&self, mut a: TombState, b: TombState) -> TombState {
                for t in b.tombs {
                    if !a.tombs.contains(&t) {
                        a.tombs.push(t);
                    }
                }
                for m in b.live {
                    if !a.live.contains(&m) {
                        a.live.push(m);
                    }
                }
                a.live.retain(|m| !a.tombs.contains(m));
                a.live.sort_unstable();
                a.tombs.sort_unstable();
                a
            }
        }
        // Older generation: messages [1, 2, 3] (3 was the newest write).
        // Newer generation: 3 deleted via tombstone — the "max recency"
        // scalar of the newer state is LOWER, the trap that resurrected data.
        let older = TombState {
            live: vec![1, 2, 3],
            tombs: vec![],
        };
        let newer = TombState {
            live: vec![1, 2],
            tombs: vec![3],
        };
        for order in [[newer.clone(), older.clone()], [older, newer]] {
            let mut d = ProbeDriver::new(
                TombOps,
                TombState {
                    live: vec![],
                    tombs: vec![],
                },
                NewestFirst::assume_ordered(vec![id(2), id(1)]),
                SelectionPolicy::FoldAll(
                    FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
                ),
            );
            let Step::Get(a) = d.next_action() else {
                panic!()
            };
            d.on_response(a, &order[0].encode());
            let Step::Get(b) = d.next_action() else {
                panic!()
            };
            d.on_response(b, &order[1].encode());
            assert_eq!(d.next_action(), Step::Done);
            let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
                panic!()
            };
            assert_eq!(
                merged.live,
                vec![1, 2],
                "deleted-newest item resurrected (arrival order {order:?})"
            );
            assert!(merged.tombs.contains(&3), "tombstone must survive the fold");
        }
    }

    /// Scripts one [`ProbeAnswer`] per candidate. Three-way on purpose: the
    /// pre-0.6.0 double keyed a `HashMap<_, Option<Vec<u8>>>`, whose `None`
    /// stood for a timeout AND for "no such contract" at once — so the harness
    /// could not state the fault in freenet/freenet-migrate#19, let alone fail
    /// on it. A double that cannot express the bug cannot catch it.
    struct ScriptIo {
        answers: std::collections::HashMap<ContractInstanceId, ProbeAnswer>,
    }
    impl ScriptIo {
        fn new(answers: &[(ContractInstanceId, ProbeAnswer)]) -> Self {
            Self {
                answers: answers.iter().cloned().collect(),
            }
        }
    }
    impl ProbeIo for ScriptIo {
        type Error = core::convert::Infallible;
        async fn get(&mut self, id: ContractInstanceId) -> Result<ProbeAnswer, Self::Error> {
            // An unscripted candidate is a non-answer, never an absence.
            Ok(self
                .answers
                .get(&id)
                .cloned()
                .unwrap_or(ProbeAnswer::Unknown))
        }
    }

    /// A two-generation lineage plus its ids (oldest-first, as the registry is).
    fn two_generation_lineage() -> (
        freenet_stdlib::prelude::Parameters<'static>,
        [crate::ContractLineageEntry; 2],
        Vec<ContractInstanceId>,
    ) {
        let params = freenet_stdlib::prelude::Parameters::from(b"owner".to_vec());
        let lineage = [
            crate::ContractLineageEntry {
                generation: 0,
                code_hash: [10; 32],
                note: "older",
            },
            crate::ContractLineageEntry {
                generation: 1,
                code_hash: [11; 32],
                note: "newer",
            },
        ];
        let ids = crate::predecessor_ids(&params, &lineage);
        (params, lineage, ids)
    }

    /// THE freenet/freenet-migrate#19 regression, at the pumped entry point.
    ///
    /// The newest generation never answers; the older one holds real state.
    /// Before 0.6.0 the driver walked past the silence and adopted the older
    /// generation — the very "generation-blind selection" rollback the module
    /// docs claim is inexpressible, reachable through one timeout, and pinned
    /// by this test's predecessor as if it were correct. Silence does not rule
    /// the newer generation out, so it must not be walked past.
    #[test]
    fn silence_on_the_newest_generation_does_not_adopt_an_older_one() {
        let (params, lineage, ids) = two_generation_lineage();
        let mut io = ScriptIo::new(&[
            (ids[1], ProbeAnswer::Unknown), // newest: never answered
            (ids[0], ProbeAnswer::State(MiniState::real(&[6]).encode())), // older: real data
        ]);
        let outcome = futures_executor_block_on(migrate_contract(
            MiniOps,
            &mut io,
            MiniState::real(&[100]),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        ))
        .unwrap();
        let Outcome::Indeterminate { local, unresolved } = outcome else {
            panic!("silence on the newest generation must not resolve to a recovery: {outcome:?}")
        };
        assert_eq!(
            unresolved,
            vec![ids[1], ids[0]],
            "both must be named: the newest never answered, and the halt means the \
             older was never asked — neither was ruled out"
        );
        assert_eq!(
            local.messages,
            vec![100],
            "the local snapshot comes back untouched — nothing is adopted or PUT forward"
        );
    }

    /// The same script with the rollback risk explicitly acknowledged: the walk
    /// continues and the older generation IS adopted — but the result carries
    /// the unresolved newer generation, so it is never silently clean.
    #[test]
    fn continue_past_unknown_recovers_but_reports_the_unresolved_generation() {
        let (params, lineage, ids) = two_generation_lineage();
        let mut driver = contract_probe(
            MiniOps,
            MiniState::real(&[100]),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        )
        .continue_past_unknown(
            RollbackRiskAck::i_understand_continuing_past_silence_can_roll_back(),
        );

        let Step::Get(newest) = driver.next_action() else {
            panic!()
        };
        assert_eq!(newest, ids[1]);
        driver.on_unknown(newest);
        let Step::Get(older) = driver.next_action() else {
            panic!("acknowledged risk must let the walk continue")
        };
        driver.on_response(older, &MiniState::real(&[6]).encode());

        let Some(Outcome::Recovered {
            merged,
            source,
            unresolved,
            ..
        }) = driver.take_outcome()
        else {
            panic!()
        };
        assert_eq!(source, ids[0]);
        assert_eq!(merged.messages, vec![6, 100]);
        assert_eq!(
            unresolved,
            vec![ids[1]],
            "a possible rollback past an unanswered newer generation must be reported"
        );
    }

    /// The pumped wrapper and the raw driver still agree, on the path where
    /// every candidate answers: newest is positively absent, older hits.
    #[test]
    fn migrate_contract_pump_reaches_the_same_outcome() {
        let (params, lineage, ids) = two_generation_lineage();
        let mut io = ScriptIo::new(&[
            (ids[1], ProbeAnswer::Absent), // newest: answered "nothing here"
            (ids[0], ProbeAnswer::State(MiniState::real(&[6]).encode())),
        ]);
        let outcome = futures_executor_block_on(migrate_contract(
            MiniOps,
            &mut io,
            MiniState::real(&[100]),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        ))
        .unwrap();
        let Outcome::Recovered {
            merged,
            source,
            unresolved,
            ..
        } = outcome
        else {
            panic!("expected recovery via the older generation")
        };
        assert_eq!(source, ids[0]);
        assert_eq!(merged.messages, vec![6, 100]);
        assert!(
            unresolved.is_empty(),
            "every candidate answered, so nothing is unresolved"
        );
    }

    /// `prepare_forward` must run on the `Indeterminate` snapshot too.
    ///
    /// The docs tell an app it MAY seed `local` forward after enough failed
    /// attempts. `prepare_forward` is where an app strips a stale upgrade
    /// pointer out of state before it goes under the current key
    /// (freenet/river#427). Handing back an unprepared snapshot on the one path
    /// that invites a judgement call would re-plant exactly what the hook
    /// exists to remove — on the path where the app is least sure of itself.
    #[test]
    fn prepare_forward_runs_on_the_indeterminate_snapshot() {
        struct StripOps;
        impl ProbeStateOps for StripOps {
            type State = MiniState;
            fn decode(&self, bytes: &[u8]) -> Option<MiniState> {
                MiniOps.decode(bytes)
            }
            fn is_real(&self, s: &MiniState) -> bool {
                MiniOps.is_real(s)
            }
            fn merge_with_local(&self, r: MiniState, l: &MiniState) -> MiniState {
                MiniOps.merge_with_local(r, l)
            }
            fn prepare_forward(&self, mut s: MiniState) -> MiniState {
                // Message 0 models the #427 upgrade pointer.
                s.messages.retain(|m| *m != 0);
                s
            }
        }
        let mut d = ProbeDriver::new(
            StripOps,
            MiniState::real(&[0, 5]),
            NewestFirst::assume_ordered(vec![id(1)]),
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { local, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(
            local.messages,
            vec![5],
            "the stale pointer must be stripped on the indeterminate path too"
        );
    }

    /// The same guarantee on the **other** site that builds `Indeterminate`.
    ///
    /// `Outcome::Indeterminate` is constructed in two places — `finish_indeterminate`
    /// (the policy halted at an unknown) and `finish_exhausted` (the walk ran
    /// out of candidates without recovering anything). The test above only
    /// reaches the first, so deleting `prepare_forward` from the second failed
    /// nothing.
    ///
    /// That gap was on the branch an adopter actually executes: Delta drives
    /// `FoldAll`, which never halts on an unknown, so **every** indeterminate
    /// outcome it sees comes from the exhaustion path. An unarmed fix on the
    /// live path is the failure mode this whole PR is about.
    #[test]
    fn prepare_forward_runs_on_the_exhausted_indeterminate_path() {
        struct StripOps;
        impl ProbeStateOps for StripOps {
            type State = MiniState;
            fn decode(&self, bytes: &[u8]) -> Option<MiniState> {
                MiniOps.decode(bytes)
            }
            fn is_real(&self, s: &MiniState) -> bool {
                MiniOps.is_real(s)
            }
            fn merge_with_local(&self, r: MiniState, l: &MiniState) -> MiniState {
                MiniOps.merge_with_local(r, l)
            }
            fn prepare_forward(&self, mut s: MiniState) -> MiniState {
                // Message 0 models the #427 upgrade pointer.
                s.messages.retain(|m| *m != 0);
                s
            }
        }
        // FoldAll walks past the unknown to exhaustion, so this lands in
        // `finish_exhausted` rather than `finish_indeterminate`.
        let mut d = ProbeDriver::new(
            StripOps,
            MiniState::real(&[0, 5]),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a);
        let Step::Get(b) = d.next_action() else {
            panic!("fold-all must keep walking past silence")
        };
        d.on_absent(b);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { local, unresolved }) = d.take_outcome() else {
            panic!("one unanswered candidate and no hits is indeterminate")
        };
        assert_eq!(unresolved, vec![id(2)]);
        assert_eq!(
            local.messages,
            vec![5],
            "the stale pointer must be stripped on the EXHAUSTED indeterminate path too"
        );
    }

    /// Two lineage entries can share a `code_hash` (an identical rebuild
    /// re-published), which derives the same contract id twice. It must be
    /// recorded once, or an app deduplicating retries by this list double-counts
    /// a single unreachable generation.
    #[test]
    fn a_repeated_candidate_id_is_recorded_once() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::empty(),
            NewestFirst::assume_ordered(vec![id(7), id(7)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a);
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_unknown(b);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { unresolved, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(unresolved, vec![id(7)], "the duplicate id must appear once");
    }

    /// The pure-#19 shape, with no older generation to fall back to: a lineage
    /// whose only candidate never answers must NOT come back as `SeedLocal`.
    ///
    /// `SeedLocal` is the outcome an app reads as "the predecessors were reached
    /// and had nothing" — the point at which it seeds forward and stops asking.
    /// Reaching it on silence is what makes a slow predecessor permanently
    /// empty.
    #[test]
    fn silence_is_indeterminate_never_a_sealable_seed_local() {
        let mut d = driver(&[3], MiniState::real(&[7]));
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a);
        assert_eq!(d.next_action(), Step::Done);
        match d.take_outcome() {
            Some(Outcome::Indeterminate { local, unresolved }) => {
                assert_eq!(unresolved, vec![id(3)]);
                assert_eq!(local.messages, vec![7], "the snapshot comes back intact");
            }
            other => panic!("silence must not be a clean SeedLocal, got {other:?}"),
        }
    }

    /// The contrast that makes the test above non-vacuous: the SAME lineage,
    /// the SAME empty result, but the candidate ANSWERED. Absence is a real
    /// finding, so this one does seal.
    #[test]
    fn an_answered_absence_is_a_sealable_seed_local() {
        let mut d = driver(&[3], MiniState::real(&[7]));
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_absent(a);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::SeedLocal { local }) = d.take_outcome() else {
            panic!("an answered absence must still seed local")
        };
        assert_eq!(local.messages, vec![7]);
    }

    /// A partially-silent walk under fold-all: the fold keeps going (that is
    /// Union's whole point), but the result names the generations it could not
    /// read, so a caller cannot mistake it for a complete fold.
    #[test]
    fn fold_all_continues_past_silence_and_reports_the_gap() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[100]),
            NewestFirst::assume_ordered(vec![id(3), id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[1]).encode());
        let Step::Get(b) = d.next_action() else {
            panic!("fold-all must keep walking past silence")
        };
        d.on_unknown(b);
        let Step::Get(c) = d.next_action() else {
            panic!()
        };
        d.on_response(c, &MiniState::real(&[3]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered {
            merged, unresolved, ..
        }) = d.take_outcome()
        else {
            panic!()
        };
        assert_eq!(merged.messages, vec![1, 3, 100]);
        assert_eq!(
            unresolved,
            vec![id(2)],
            "the generation that never answered must be named on the fold"
        );
    }

    /// Fold-all that recovers nothing AND had a silent candidate is
    /// indeterminate, not an empty-but-complete sweep.
    #[test]
    fn fold_all_with_silence_and_no_hits_is_indeterminate() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[7]),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a);
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_absent(b);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { unresolved, .. }) = d.take_outcome() else {
            panic!("one unanswered candidate makes the whole sweep inconclusive")
        };
        assert_eq!(unresolved, vec![id(2)]);
    }

    /// A stale non-answer (for a candidate already advanced past) must not
    /// invent an unresolved entry, or an otherwise-clean probe would report a
    /// phantom gap and never settle.
    #[test]
    fn stale_unknown_does_not_pollute_the_unresolved_list() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::empty(),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_absent(a);
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_unknown(a); // stale: `a` was answered and advanced past
        assert_eq!(
            d.next_action(),
            Step::Get(b),
            "stale event must not advance"
        );
        d.on_response(b, &MiniState::real(&[5]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { unresolved, .. }) = d.take_outcome() else {
            panic!()
        };
        assert!(
            unresolved.is_empty(),
            "a stale non-answer must not be recorded, got {unresolved:?}"
        );
    }

    /// `on_timeout` is the deprecated spelling and must forward to `on_unknown`
    /// — not to the pre-0.6.0 "treat it as a miss" behaviour. An adopter that
    /// has not renamed its call site gets the SAFE reading for free, which is
    /// the whole point of the rename.
    #[test]
    #[allow(deprecated)]
    fn deprecated_on_timeout_forwards_to_on_unknown() {
        let mut d = driver(&[3], MiniState::real(&[7]));
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_timeout(a);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Indeterminate { unresolved, .. }) = d.take_outcome() else {
            panic!("on_timeout must mean UNKNOWN, not absent")
        };
        assert_eq!(unresolved, vec![id(3)]);
    }

    /// Minimal single-future block_on (no async runtime dependency): the
    /// ScriptIo futures are always immediately ready.
    fn futures_executor_block_on<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = core::pin::pin!(fut);
        // ScriptIo futures are always immediately Ready (no await points); a
        // ceiling turns any future Pending regression into a fast failure
        // instead of a hung test.
        for _ in 0..10_000 {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
        panic!("future never became ready; ScriptIo must stay awaitless");
    }

    #[test]
    fn contract_probe_probes_newest_predecessor_first() {
        // THE generation-ordering pin at the real entry point: the registry
        // is oldest-first; contract_probe must reverse it. Without the
        // reversal this re-creates the generation-blind incident class with
        // both generations real — so both are real here, with distinct
        // content, making the order observable.
        let params = freenet_stdlib::prelude::Parameters::from(b"owner".to_vec());
        let lineage = [
            crate::ContractLineageEntry {
                generation: 0,
                code_hash: [10; 32],
                note: "older",
            },
            crate::ContractLineageEntry {
                generation: 1,
                code_hash: [11; 32],
                note: "newer",
            },
        ];
        let ids = crate::predecessor_ids(&params, &lineage); // oldest-first
        let mut d = contract_probe(
            MiniOps,
            MiniState::empty(),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(first) = d.next_action() else {
            panic!()
        };
        assert_eq!(first, ids[1], "must probe the NEWEST predecessor first");
        d.on_response(first, &MiniState::real(&[2026]).encode());
        let Some(Outcome::Recovered { merged, source, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(source, ids[1]);
        assert_eq!(merged.messages, vec![2026], "older gen must not be read");
    }

    #[test]
    fn out_of_order_lineage_still_probes_newest_first() {
        // The realistic mis-authoring: a newly-discovered OLD generation
        // appended at the END of the registry (as the CI guard's advice
        // invites). Slice order [gen0, gen2, gen1]; probing must follow the
        // generation FIELD (2 first), not slice order — a blind reversal
        // would probe gen1 first and re-create the rollback incident.
        let params = freenet_stdlib::prelude::Parameters::from(b"owner".to_vec());
        let lineage = [
            crate::ContractLineageEntry {
                generation: 0,
                code_hash: [10; 32],
                note: "oldest",
            },
            crate::ContractLineageEntry {
                generation: 2,
                code_hash: [12; 32],
                note: "newest",
            },
            crate::ContractLineageEntry {
                generation: 1,
                code_hash: [11; 32],
                note: "appended late, out of order",
            },
        ];
        let ids = crate::predecessor_ids(&params, &lineage); // slice order
        let mut d = contract_probe(
            MiniOps,
            MiniState::empty(),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(first) = d.next_action() else {
            panic!()
        };
        assert_eq!(
            first, ids[1],
            "gen 2 must be probed first despite slice order"
        );
        d.on_absent(first);
        let Step::Get(second) = d.next_action() else {
            panic!()
        };
        assert_eq!(second, ids[2], "gen 1 second");
        d.on_response(second, &MiniState::real(&[1]).encode());
        let Some(Outcome::Recovered { source, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(source, ids[2]);
    }

    #[test]
    fn no_legacy_hands_back_the_local_snapshot() {
        let mut d = driver(&[], MiniState::real(&[42]));
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::NoLegacy { local }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(local.messages, vec![42], "snapshot returned untouched");
    }

    #[test]
    fn pump_prefers_newest_when_both_generations_are_real() {
        // Same pin through the pumped entry point: both generations real —
        // the newest must win (a dropped reversal would adopt the older).
        let (params, lineage, ids) = two_generation_lineage();
        let mut io = ScriptIo::new(&[
            (
                ids[0],
                ProbeAnswer::State(MiniState::real(&[1999]).encode()),
            ),
            (
                ids[1],
                ProbeAnswer::State(MiniState::real(&[2026]).encode()),
            ),
        ]);
        let outcome = futures_executor_block_on(migrate_contract(
            MiniOps,
            &mut io,
            MiniState::empty(),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        ))
        .unwrap();
        let Outcome::Recovered { merged, source, .. } = outcome else {
            panic!()
        };
        assert_eq!(source, ids[1], "the newest real generation must win");
        assert_eq!(merged.messages, vec![2026]);
    }

    #[test]
    fn fold_all_all_miss_seeds_local() {
        // Local-snapshot survival under FoldAll exhaustion — the no-silent-
        // data-loss guarantee for the fold policy too.
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[7]),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_absent(a);
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_response(b, &MiniState::empty().encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::SeedLocal { local }) = d.take_outcome() else {
            panic!("all-miss FoldAll must seed local")
        };
        assert_eq!(local.messages, vec![7]);
    }

    #[test]
    fn fold_all_single_hit_still_merges_local() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[100]),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[1]).encode());
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_absent(b);
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered {
            merged,
            truncated_fold,
            ..
        }) = d.take_outcome()
        else {
            panic!()
        };
        assert_eq!(merged.messages, vec![1, 100], "local must be folded in");
        assert!(!truncated_fold, "full sweep completed");
    }

    #[test]
    fn fold_all_hop_cap_marks_fold_truncated() {
        // A hop-cap-cut FoldAll sweep is missing the oldest generations; it
        // must be DISTINGUISHABLE from a complete fold, never a silent
        // success.
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::empty(),
            NewestFirst::assume_ordered(vec![id(3), id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        )
        .with_max_hops(2);
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[1]).encode());
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_response(b, &MiniState::real(&[2]).encode());
        assert_eq!(d.next_action(), Step::Done, "cap must stop the sweep");
        let Some(Outcome::Recovered {
            merged,
            truncated_fold,
            ..
        }) = d.take_outcome()
        else {
            panic!()
        };
        assert!(truncated_fold, "cap-cut fold must be marked truncated");
        assert_eq!(merged.messages, vec![1, 2]);
        // And NewestFirstWins is never "truncated" — stopping is its
        // definition.
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[9]).encode());
        let Some(Outcome::Recovered { truncated_fold, .. }) = d.take_outcome() else {
            panic!()
        };
        assert!(!truncated_fold);
    }

    #[test]
    fn merge_argument_order_is_pinned_newer_first() {
        // An ASYMMETRIC merge (first argument wins conflicts) observes the
        // newer/older argument order — a silent swap would adopt the OLDER
        // side's value in a conflict. Message value = id*1000 + version;
        // conflict on id 1.
        #[derive(Debug, Clone, PartialEq)]
        struct Lww(Vec<(u32, u32)>); // (key, value), first-arg wins conflicts
        impl Lww {
            fn encode(&self) -> Vec<u8> {
                let mut out = vec![1u8];
                for (k, v) in &self.0 {
                    out.extend_from_slice(&k.to_le_bytes());
                    out.extend_from_slice(&v.to_le_bytes());
                }
                out
            }
        }
        struct LwwOps;
        impl ProbeStateOps for LwwOps {
            type State = Lww;
            fn decode(&self, bytes: &[u8]) -> Option<Lww> {
                if bytes.is_empty() || !(bytes.len() - 1).is_multiple_of(8) {
                    return None;
                }
                Some(Lww(bytes[1..]
                    .chunks(8)
                    .map(|c| {
                        (
                            u32::from_le_bytes(c[..4].try_into().unwrap()),
                            u32::from_le_bytes(c[4..].try_into().unwrap()),
                        )
                    })
                    .collect()))
            }
            fn is_real(&self, s: &Lww) -> bool {
                !s.0.is_empty()
            }
            fn merge_with_local(&self, recovered: Lww, local: &Lww) -> Lww {
                // recovered (first arg / primary) wins conflicts with local.
                self.merge_generations(recovered, local.clone())
            }
            fn merge_generations(&self, mut newer: Lww, older: Lww) -> Lww {
                for (k, v) in older.0 {
                    if !newer.0.iter().any(|(nk, _)| *nk == k) {
                        newer.0.push((k, v));
                    }
                }
                newer.0.sort_unstable();
                newer
            }
        }
        // FoldAll: newer gen says key1=v2, older gen says key1=v1.
        let mut d = ProbeDriver::new(
            LwwOps,
            Lww(vec![]),
            NewestFirst::assume_ordered(vec![id(2), id(1)]),
            SelectionPolicy::FoldAll(
                FoldAllAck::i_understand_fold_all_resurrects_without_tombstones(),
            ),
        );
        let Step::Get(newer) = d.next_action() else {
            panic!()
        };
        d.on_response(newer, &Lww(vec![(1, 2)]).encode());
        let Step::Get(older) = d.next_action() else {
            panic!()
        };
        d.on_response(older, &Lww(vec![(1, 1)]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(
            merged.0,
            vec![(1, 2)],
            "the NEWER generation must win the conflict (argument order swapped?)"
        );
        // NewestFirstWins: recovered wins conflicts against local.
        let mut d = ProbeDriver::new(
            LwwOps,
            Lww(vec![(1, 7)]),
            NewestFirst::assume_ordered(vec![id(2)]),
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &Lww(vec![(1, 9)]).encode());
        let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(
            merged.0,
            vec![(1, 9)],
            "recovered must be the primary side of merge_with_local"
        );
    }

    #[test]
    fn max_hops_zero_is_indeterminate_not_a_clean_seed() {
        // Cap 0 asks nobody, so it establishes nothing about the lineage.
        let mut d = driver(&[3, 2], MiniState::real(&[4])).with_max_hops(0);
        assert_eq!(d.next_action(), Step::Done, "cap 0 = no probing at all");
        let Some(Outcome::Indeterminate { local, unresolved }) = d.take_outcome() else {
            panic!("a walk that asked nobody cannot report a clean SeedLocal")
        };
        assert_eq!(local.messages, vec![4], "the snapshot still comes back");
        assert_eq!(unresolved, vec![id(3), id(2)], "both candidates unasked");
    }

    #[test]
    fn events_after_done_are_noops_and_outcome_is_single_shot() {
        let mut d = driver(&[3], MiniState::empty());
        assert!(d.take_outcome().is_none(), "no outcome while probing");
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[1]).encode());
        assert_eq!(d.next_action(), Step::Done);
        // Late events after Done must not disturb the outcome.
        d.on_unknown(a);
        d.on_response(a, &MiniState::real(&[99]).encode());
        assert_eq!(d.next_action(), Step::Done);
        let Some(Outcome::Recovered { merged, .. }) = d.take_outcome() else {
            panic!()
        };
        assert_eq!(merged.messages, vec![1]);
        // Outcome is taken once; the step stays Done.
        assert!(d.take_outcome().is_none());
        assert_eq!(d.next_action(), Step::Done);
    }

    #[test]
    fn real_but_empty_state_is_a_hit() {
        // "Real" is the app's predicate, not non-emptiness: a decodable state
        // flagged real with zero messages is still a hit.
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::real(&[]).encode());
        assert_eq!(d.next_action(), Step::Done);
        assert!(matches!(d.take_outcome(), Some(Outcome::Recovered { .. })));
    }

    #[test]
    fn policy_check_helpers_accept_and_reject() {
        let samples = [
            MiniState::real(&[1]),
            MiniState::real(&[2, 3]),
            MiniState::real(&[1, 3]),
        ];
        let merge = |a: MiniState, b: MiniState| MiniOps.merge_generations(a, b);
        policy_check::assert_merge_commutative(&samples, merge);
        policy_check::assert_merge_idempotent(&samples, merge);
        policy_check::assert_fold_order_invariant(&samples, merge);
        // A last-writer-wins "merge" is order-dependent and must be rejected.
        let lww = |_a: MiniState, b: MiniState| b;
        let caught = std::panic::catch_unwind(|| {
            policy_check::assert_fold_order_invariant(&samples, lww);
        });
        assert!(caught.is_err(), "order-dependent merge must fail the check");
    }
}
