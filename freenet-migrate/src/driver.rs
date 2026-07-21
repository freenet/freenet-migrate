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
//!     driver.on_response(id, &bytes);   // GET response for id
//!     driver.on_timeout(id);            // timer fired / send failed for id
//! }
//! ```
//!
//! The two Delta incident classes are *decision* bugs, and both are
//! inexpressible in the part the driver owns:
//!
//! * **Generation-blind selection** ("rolled back to April"): candidates are
//!   probed strictly newest-first and the first real state wins, so an older
//!   generation can never shadow a newer one.
//! * **Backward-pointer following** (freenet/river#427): the driver never
//!   follows pointers found inside recovered state — newest-first order
//!   subsumes forward pointers, and backward pointers are the poison the
//!   [`ProbeStateOps::prepare_forward`] hook exists to strip.
//!
//! Honest limit: the I/O adapter (and the actual PUT of the outcome) stays app
//! code the crate cannot verify.
//!
//! # Decision semantics (matching River's shipped, field-proven probe)
//!
//! * Probe **newest-first**; stop at the **first real** state
//!   ([`SelectionPolicy::NewestFirstWins`], the default — see the policy
//!   section for why fold-all is opt-in).
//! * A response that fails to decode is a **miss** (a corrupt or
//!   ancient-format generation is skipped, never a panic, never adopted).
//! * A timeout, send failure, or transport loss is a **miss** for that
//!   candidate: the probe advances instead of stalling.
//! * Responses are **single-shot** per candidate: a late response for a
//!   candidate already advanced past (its timer fired first) is ignored —
//!   matching the shipped `take_probe` race semantics.
//! * A hop cap ([`ProbeDriver::with_max_hops`], default 64) bounds the walk.
//! * On exhaustion the outcome is **seed-local** ([`Outcome::SeedLocal`]): the
//!   caller's local snapshot goes forward, so recovery failure never silently
//!   discards device-local data.
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
//! generations together (oldest-to-newest, then the local snapshot). That is
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

/// Opt-in token for [`SelectionPolicy::FoldAll`]. Deliberately not `Default`:
/// holding one acknowledges the resurrection precondition.
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

/// What the app should do next. Obtained from [`ProbeDriver::next_action`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send a GET for this candidate (with `return_contract_code: true`,
    /// without subscribing — never subscribe to a legacy key), and arm a
    /// timeout (see [`RECOMMENDED_PROBE_TIMEOUT_MS`]). Deliver the result via
    /// [`ProbeDriver::on_response`] / [`ProbeDriver::on_timeout`].
    Get(ContractInstanceId),
    /// The probe is finished; adopt the outcome. Repeated calls keep
    /// returning this.
    Done,
}

/// Terminal result of a probe, taken once via [`ProbeDriver::take_outcome`].
#[derive(Debug)]
pub enum Outcome<S> {
    /// A predecessor generation had real state. `merged` is
    /// `merge_with_local(recovered, local)` passed through `prepare_forward`
    /// — PUT it under the **current** key (with subscribe) and adopt it
    /// locally.
    Recovered {
        /// The prepared state to adopt and PUT forward.
        merged: S,
        /// The candidate that hit (newest real generation).
        source: ContractInstanceId,
    },
    /// Every candidate missed (or the hop cap was reached): seed the local
    /// snapshot forward (passed through `prepare_forward`), so local-only
    /// data survives. `local` is the snapshot handed to the driver.
    SeedLocal {
        /// The prepared local snapshot to PUT forward.
        local: S,
    },
    /// There were no candidates at all (fresh app / empty lineage): nothing
    /// to recover, proceed with the app's normal first-run path.
    NoLegacy,
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
        candidates_newest_first: Vec<ContractInstanceId>,
        policy: SelectionPolicy,
    ) -> Self {
        let phase = if candidates_newest_first.is_empty() {
            Phase::Done(Some(Outcome::NoLegacy))
        } else {
            Phase::Probing
        };
        Self {
            ops,
            policy,
            local: Some(local_snapshot),
            remaining: candidates_newest_first,
            outstanding: None,
            hops: 0,
            max_hops: DEFAULT_MAX_PROBE_HOPS,
            fold_acc: None,
            phase,
        }
    }

    /// Override the hop cap (default [`DEFAULT_MAX_PROBE_HOPS`]).
    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = max_hops;
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

    /// Deliver a timeout — or any send/transport failure — for candidate
    /// `id`: a miss for that candidate. Stale timeouts (for a candidate no
    /// longer outstanding) are ignored.
    pub fn on_timeout(&mut self, id: ContractInstanceId) {
        if self.outstanding == Some(id) {
            self.outstanding = None;
        }
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
        let outcome = match self.fold_acc.take() {
            Some((source, folded)) => {
                let merged = self.ops.merge_with_local(folded, &local);
                Outcome::Recovered {
                    merged: self.ops.prepare_forward(merged),
                    source,
                }
            }
            None => Outcome::SeedLocal {
                local: self.ops.prepare_forward(local),
            },
        };
        self.phase = Phase::Done(Some(outcome));
    }
}

/// Build a probe driver from a lineage: candidates are the registry's
/// predecessor ids reversed into newest-first order. This is the assembly the
/// high-level entry point ([`migrate_contract`]) uses.
///
/// Probing is deliberately **sequential** (one outstanding candidate at a
/// time): bounded, deterministic, and sufficient for the newest-first policy
/// (which usually stops at the first candidate). An app that wants Delta-style
/// concurrent sweeps can run the fold-all policy and pump faster; a concurrent
/// driver mode is future work if measured to matter.
pub fn contract_probe<O: ProbeStateOps>(
    ops: O,
    local_snapshot: O::State,
    params: &freenet_stdlib::prelude::Parameters<'_>,
    lineage: &[crate::ContractLineageEntry],
    policy: SelectionPolicy,
) -> ProbeDriver<O> {
    let mut candidates = crate::predecessor_ids(params, lineage);
    candidates.reverse(); // registry is oldest-first; probe newest-first
    ProbeDriver::new(ops, local_snapshot, candidates, policy)
}

/// The thin per-environment I/O adapter for the pumped entry point
/// ([`migrate_contract`]): one GET, awaited, with the app's own timeout.
///
/// * Return `Ok(Some(bytes))` with the raw GET response state bytes.
/// * Return `Ok(None)` for a timeout, a send failure, or any condition the
///   app wants treated as a **miss** (the probe advances — the resilient
///   default; see the driver's decision semantics).
/// * Return `Err` only for conditions that should **abort** the whole
///   migration (the driver's decisions are lost and the caller sees the
///   error).
pub trait ProbeIo {
    /// The app's transport error type (for the abort path only).
    type Error;

    /// GET the state bytes for `id` — without subscribing, with
    /// `return_contract_code: true`, bounded by a timeout of roughly
    /// [`RECOMMENDED_PROBE_TIMEOUT_MS`].
    fn get(
        &mut self,
        id: ContractInstanceId,
    ) -> impl core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>>;
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
                Some(bytes) => driver.on_response(id, &bytes),
                None => driver.on_timeout(id),
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
    /// equals folding right-to-left. (Full permutation checking is the app's
    /// prerogative; commutativity + associativity imply it.)
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
            candidates.iter().map(|n| id(*n)).collect(),
            SelectionPolicy::NewestFirstWins,
        )
    }

    #[test]
    fn empty_lineage_is_no_legacy() {
        let mut d = driver(&[], MiniState::empty());
        assert_eq!(d.next_action(), Step::Done);
        assert!(matches!(d.take_outcome(), Some(Outcome::NoLegacy)));
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
        let Some(Outcome::Recovered { merged, source }) = d.take_outcome() else {
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
        let Some(Outcome::Recovered { source, merged }) = d.take_outcome() else {
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
    fn miss_and_timeout_advance_then_exhaustion_seeds_local() {
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
        d.on_timeout(b); // timeout → miss
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
    fn late_response_after_timeout_is_ignored() {
        // The take_probe single-shot race: candidate timed out (we advanced),
        // then its real response arrives late — it must be dropped, matching
        // shipped semantics.
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_timeout(a);
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
    fn stale_timeout_for_advanced_candidate_is_ignored() {
        let mut d = driver(&[3, 2], MiniState::empty());
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_response(a, &MiniState::empty().encode());
        let Step::Get(b) = d.next_action() else {
            panic!()
        };
        d.on_timeout(a); // stale — must not consume b's slot
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

    #[test]
    fn hop_cap_bounds_the_walk() {
        let candidates: Vec<u8> = (1..=10).rev().collect();
        let mut d = driver(&candidates, MiniState::real(&[1])).with_max_hops(3);
        for _ in 0..3 {
            let Step::Get(g) = d.next_action() else {
                panic!()
            };
            d.on_timeout(g);
        }
        assert_eq!(d.next_action(), Step::Done);
        assert!(matches!(d.take_outcome(), Some(Outcome::SeedLocal { .. })));
    }

    #[test]
    fn fold_all_probes_everything_and_folds_oldest_into_newest() {
        let mut d = ProbeDriver::new(
            MiniOps,
            MiniState::real(&[100]),
            vec![id(3), id(2), id(1)],
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
        let Some(Outcome::Recovered { merged, source }) = d.take_outcome() else {
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
            vec![id(1)],
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
            vec![id(1)],
            SelectionPolicy::NewestFirstWins,
        );
        let Step::Get(a) = d.next_action() else {
            panic!()
        };
        d.on_timeout(a);
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
                vec![id(2), id(1)],
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

    #[test]
    fn migrate_contract_pump_reaches_the_same_outcome() {
        // The async wrapper must make identical decisions to the raw driver:
        // candidate 1 (newest) times out, candidate 2 hits.
        struct ScriptIo {
            responses: std::collections::HashMap<ContractInstanceId, Option<Vec<u8>>>,
        }
        impl ProbeIo for ScriptIo {
            type Error = core::convert::Infallible;
            async fn get(
                &mut self,
                id: ContractInstanceId,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                Ok(self.responses.get(&id).cloned().flatten())
            }
        }
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
        let mut responses = std::collections::HashMap::new();
        responses.insert(ids[1], None); // newest: timeout
        responses.insert(ids[0], Some(MiniState::real(&[6]).encode())); // older: hit
        let mut io = ScriptIo { responses };
        let outcome = futures_executor_block_on(migrate_contract(
            MiniOps,
            &mut io,
            MiniState::real(&[100]),
            &params,
            &lineage,
            SelectionPolicy::NewestFirstWins,
        ))
        .unwrap();
        let Outcome::Recovered { merged, source } = outcome else {
            panic!("expected recovery via the older generation")
        };
        assert_eq!(source, ids[0]);
        assert_eq!(merged.messages, vec![6, 100]);
    }

    /// Minimal single-future block_on (no async runtime dependency): the
    /// ScriptIo futures are always immediately ready.
    fn futures_executor_block_on<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = core::pin::pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
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
