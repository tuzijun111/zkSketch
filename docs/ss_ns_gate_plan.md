# SS (s+1)-th-value subtraction gate — implementation plan

All anchors are verified. The plonky2 leaf's Stage H already does grouped-sum mass conservation (`Σ gscount = Σ old + Σ batch`, lines 227-240) and already imports `is_zero` (line 34), which confirms the cleanest cross-backend mass choice. Here is the merged plan.

{
  "deployed_scope": {
    "must_change_headline_plonky3": {
      "file": "src/sketch/ss_final_full.rs",
      "why": "DEPLOYED plonky3 leaf; ALL headline SS numbers route through it — stream_compose.rs:822 (prove_ss_full_exposed) and :91 (apply_batch_ss_full), families.rs:208-212 (prove_ss_full), dist_compose.rs:206/339, rq1/rq2/casestudy via SsFullParams, expose_forest.rs, examples exp_e1..e3. Produces results/stream_compose*.csv (the file under edit), ss_batch_certified.csv, frame_out_4machine_plonky3.csv.",
      "functions": ["apply_batch_ss_full (native, :491-508)", "build_ss (native, :370-486 — τ read, optional SsBuild.tau field :345-362)", "build_ss_full_leaf (AIR: Stage 8 compaction :933-943, Stage 9 mass :945-971, private-input alloc :640-642)", "prove_epoch (witness packing :1128-1146, native mass sanity assert :1061, alloc-order comment ~:608-610)"]
    },
    "must_change_snark_backend_plonky2": {
      "files": ["plonky2/src/sketch/spacesaving.rs", "plonky2/src/leaf/spacesaving.rs"],
      "why": "ALSO on the eval critical path for the SNARK-backend (plonky2) SS numbers: results/frame_out_4machine_plonky2.csv contains a `plonky2,aol,ss,forest,cap16384` row, and scripts/run_compose.sh EXP_COMPOSE_BACKEND=plonky2 runs plonky2/examples/exp_compose.rs -> dist_compose.rs -> build_spacesaving_leaf + apply_batch. If only plonky3 is fixed the two backends compute a DIFFERENT final_state for the same input — a consistency divergence. Change in lockstep with plonky3 (mirror the same τ=g_sorted[m-1] index).",
      "functions": ["apply_batch (native, :215-222)", "build_spacesaving_leaf final_pre binding (:144-151); Stage H mass (:227-240) needs NO change — already grouped-sum based"]
    },
    "auxiliary_no_structural_change": {
      "src/decode/spacesaving.rs": "DEPLOYED decode leaf but NO constraint change: constant τ-subtraction preserves count order and the dummies-first/actives-suffix layout, so native_select (:123-136) and Checks 2/4/5 hold. Counts returned are now MG under-estimates; update docstring/semantics note (:19-49) only. Existing tests are under-full (τ=0), stay green.",
      "plonky2/src/decode/spacesaving.rs": "Mirror decode; no circuit change, doc note only; tests under-full so unaffected.",
      "src/sketch/spacesaving_naive.rs": "AUXILIARY over-estimate replay oracle (cost baseline); DO NOT change semantics. Note it is now a different summary (over-estimate) than the fixed certified leaf (under-estimate); any parity test must not assert row/count equality across the two.",
      "src/sketch/ss_final.rs": "OLDER incomplete baseline (Steps 2-4 deferred, no top-s compaction); not deployed; leave as-is."
    }
  },
  "design_choice": {
    "recommended": "Mergeable Misra-Gries / Frequent compaction with the (s+1)-th-largest-value subtraction (Agarwal-Cormode-Huang-Phillips-Wei-Yi, 'Mergeable Summaries', 2012), k=s=capacity: union old‖batch, group-sum counts, take τ = the (s+1)-th largest grouped count = g_sorted[m-1].count, subtract τ from every retained counter, clamp non-positive to dummy.",
    "justification": "This is the minimal, circuit-friendly (subtract a public-rank constant, order preserved, clamp in place — no per-counter error state) construction that yields an UNDER-estimate (f_hat ≤ f_true) with deficit ≤ N/s, hence the cross-batch N/s SURFACING guarantee the goal requires: every key with f_true > N/s keeps f_hat > 0 and stays active. Today (keep-top-s-exact, residual discarded, no subtraction) a heavy key thinly spread just below the cut is evicted every batch with UNBOUNDED loss and never surfaces.",
    "over_estimate_alternative": "If the user specifically needs textbook SpaceSaving (Metwally-Agrawal-El Abbadi 2005) OVER-estimate semantics (f_hat ≥ f_true, upper bound, no false negatives from below), that is a DIFFERENT summary: it is not cleanly mergeable and requires carrying a per-counter error/lower-bound column and an add-not-subtract merge (Berinde/Cormode mergeable form) — materially more circuit state, a different mass identity, and a decode change. It also surfaces keys with f_true > N/s but adds complexity with no surfacing gain, so ship MG under-estimate unless an upper bound is explicitly required."
  },
  "steps": [
    {
      "n": 1,
      "layer": "native-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "apply_batch_ss_full (:491-508)",
      "edit": "After `let b = build_ss(...)` (:498) add `let tau = b.g_sorted[m - 1].count;`. Keep `residual = b.g_sorted[..m]` unchanged (:499). Replace the verbatim `s_new` slice (:500) with a map over i in 0..cap, src = b.g_sorted[m+i]: `let c = src.count.saturating_sub(tau); if src.active == 1 && c > 0 { SsFullRow::real(src.key, c) } else { SsFullRow::dummy() }`. Because g_sorted is count-ascending, src.count ≥ g_sorted[m] ≥ tau, so saturating_sub never truncates a real survivor and clamped rows are a low-count prefix — final stays (active asc, count asc)."
    },
    {
      "n": 2,
      "layer": "native-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "build_ss (:370-486) + SsBuild struct (:345-362)",
      "edit": "OPTIONAL convenience for prover/tests: add `tau: u32` to SsBuild and set `tau = g_sorted[m-1].count` after :475. Not required for soundness (circuit reads g_sorted_fields[m-1][2] directly), but lets prove_epoch/tests read τ without recomputing."
    },
    {
      "n": 3,
      "layer": "native-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "prove_epoch mass sanity assert (:1048-1061)",
      "edit": "Replace `assert_eq!(final_mass + residual_mass, init_mass + batch_mass)` (:1061) with the pre-subtraction grouped-sum conservation `assert_eq!(build.g_sorted.iter().map(|r| r.count as u64 * r.active as u64).sum::<u64>(), init_mass + batch_mass)` (grouping is exact). Equivalent alternative if you prefer to keep the output-side identity: `assert_eq!(final_mass + residual_mass + (cap as u64) * tau as u64, init_mass + batch_mass)`."
    },
    {
      "n": 4,
      "layer": "AIR-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "build_ss_full_leaf private-input alloc (:640-642)",
      "edit": "Beside `acc_active_inv`, allocate `let c_new_inv: Vec<ExprId> = (0..cap).map(|_| b.alloc_private_input(\"c_new_inv\")).collect();`. Update the alloc-order comment (~:608-610) so the witness packing order in prove_epoch stays in sync."
    },
    {
      "n": 5,
      "layer": "AIR-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "build_ss_full_leaf Stage 8 compaction (:939-943)",
      "edit": "Keep residual binding (:934-938) unchanged. Replace the verbatim final loop (:939-943). Set `let tau = g_sorted_fields[m-1][2];`. For each i in 0..cap, src = m+i: (a) `let c_new = b.sub(g_sorted_fields[src][2], tau);` (subtraction gate); (b) `let _ = b.add_range_bits::<Val>(c_new, COUNT_DIFF_BITS - 1);` (no-underflow: a wrap ≈p fails, mirrors :886); (c) is-nonzero active via the acc_active gadget pattern (:852-858): `let nz = b.mul(c_new, c_new_inv[i]); let must0 = b.mul(c_new, b.sub(one, nz)); b.connect(must0, zero); bool_check(&mut b, nz);`; (d) bind `b.connect(final_fields[i][2], c_new);` and `b.connect(final_fields[i][3], nz);`; (e) key-gate (mirror :860-863): `b.connect(final_fields[i][0], b.mul(g_sorted_fields[src][0], nz)); b.connect(final_fields[i][1], b.mul(g_sorted_fields[src][1], nz));`."
    },
    {
      "n": 6,
      "layer": "AIR-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "build_ss_full_leaf Stage 9 mass (:945-971)",
      "edit": "The strict `in_mass = final+residual` (:971) is UNSAT after subtraction — do NOT merely delete it, replace it with a sound conservation. RECOMMENDED (matches plonky2 Stage H, cross-backend symmetry): connect in_mass to the pre-subtraction grouped/g_sorted mass — build `gsorted_mass_e = Σ_r b.mul(g_sorted_fields[r][2], g_sorted_fields[r][3])` and `b.connect(in_mass, gsorted_mass_e)`. EQUIVALENT alternative (exact output-side identity): keep final/residual sums, add `let cap_tau = b.mul(tau, b.alloc_const(capacity)); b.connect(in_mass, b.add(b.add(final_mass_e, res_mass_e), cap_tau));`. Both are exact equalities so no soundness gap; the discarded deficit is a deterministic function of τ. Ensure cap·τ < p (cap·2^(COUNT_DIFF_BITS-1) < p — same envelope as today's mass sum)."
    },
    {
      "n": 7,
      "layer": "AIR-plonky3",
      "file": "src/sketch/ss_final_full.rs",
      "function": "prove_epoch witness packing (:1128-1146)",
      "edit": "After packing acc_active_inv, push c_new_inv hints in the SAME order as the alloc: for i in 0..cap, src = m+i, `let diff = build.g_sorted[src].count.saturating_sub(tau_native); c_new_inv[i] = if diff == 0 { Val::ZERO } else { Val::from(diff).inverse() };` where `tau_native = build.g_sorted[m-1].count`. final_state already comes from the fixed apply_batch_ss_full so final_commit is automatically consistent."
    },
    {
      "n": 8,
      "layer": "native-plonky2",
      "file": "plonky2/src/sketch/spacesaving.rs",
      "function": "apply_batch (:215-222)",
      "edit": "Add `let tau = b.g_sorted[m - 1].count;` (m>=1 by SsParams::validate). Replace `s_new` (:221) with a map over r in m..m+cap: `let row = b.g_sorted[r]; let nc = row.count.saturating_sub(tau); if row.active == 1 && nc > 0 { SsRow::real(row.key, nc) } else { SsRow::dummy() }`. residual (:220) unchanged. Update the group_then_topk test comment (:247-248): mass is not conserved into the state for full states."
    },
    {
      "n": 9,
      "layer": "AIR-plonky2",
      "file": "plonky2/src/leaf/spacesaving.rs",
      "function": "build_spacesaving_leaf final_pre binding (:144-151) + Tgt (:83-85) + witness (:320-325)",
      "edit": "Add `surv_inv: Vec<Target>` to Tgt (after :85) and `b.add_virtual_targets(cap)` (after :127); thread it into the field-init tuple at :247. Replace the final_pre loop (:144-151): `let tau = gscount[m - 1];` then for i in 0..cap, r=m+i: `let diff = b.sub(gscount[r], tau); let _ = b.split_le(diff, COUNT_BITS); let z = is_zero(&mut b, diff, surv_inv[i]); let surv = b.sub(one, z); let fk = b.mul(surv, gskey[r]); final_pre.push(fk); final_pre.push(diff); final_pre.push(surv);` then `bind_commit(&mut b, final_pre, &final_commit);`. Stage H mass (:227-240) is UNCHANGED (already Σ gscount = Σ old + Σ batch over the pre-subtraction table — this is exactly the sound grouped conservation; keep it). In prove_timed after :325 set `surv_inv[i] = { let diff = build.g_sorted[r].count - tau_native; if diff==0 {F::ZERO} else {F::from_canonical_u64(diff).inverse()} }`, tau_native = build.g_sorted[m-1].count. Do the same at the second witness site (~:419-421). Update module/Stage-H doc (:12-15): the doc's stale `Σ new + Σ residual = old+batch` claim is now FALSE by the deficit — restate as grouped-table conservation + deliberate deficit discard."
    },
    {
      "n": 10,
      "layer": "decode",
      "file": "src/decode/spacesaving.rs (and plonky2/src/decode/spacesaving.rs)",
      "function": "docstring/semantics note (:19-49)",
      "edit": "NO constraint change. Update the docstring: returned counts / top-c mass are now MG UNDER-estimates (deficit ≤ N/s), not exact grouped sums; top-c ordering is unaffected (constant subtraction preserves order). Flag that any ReleasePolicy::Threshold is now evaluated against under-estimated mass."
    },
    {
      "n": 11,
      "layer": "tests",
      "file": "src/sketch/ss_final_full.rs (tests :1259-1721) + plonky2 mirrors",
      "function": "recompute honest expectations + add surfacing test",
      "edit": "See verification block below for the exact per-test recomputations and the new surfacing/deficit test."
    }
  ],
  "soundness_checklist": [
    "τ correctly selected as the (s+1)-th LARGEST count = g_sorted[m-1].count (the largest residual row, index m-1), NOT g_sorted[m] (smallest retained). It is a fully-pinned committed cell whose rank is fixed by the Stage-6 count-sort PermuteAir + Stage-7 count-monotone sortedness + grouped binding, so it is not a free witness and cannot be re-chosen. An off-by-one to g_sorted[m] over-deletes to ≤ s-1 survivors, inflates the deficit, and silently weakens the bound without failing any existing under-full test — guard against it.",
    "Per-row subtraction is a hard ALU value: c_new = sub(g_sorted[m+i][2], τ) is connected into final_fields[i][2] (which is hashed into final_commit), so a prover cannot skip the subtraction without breaking commit binding.",
    "No negative counts: for every retained i, g_sorted[m+i].count ≥ g_sorted[m].count ≥ g_sorted[m-1].count = τ by the existing Stage-7 count-monotone diff decomposition, so c_new ≥ 0; the added add_range_bits(c_new, COUNT_DIFF_BITS-1) / split_le makes any underflow wrap to ≈p and fail (belt-and-suspenders, mirrors :886).",
    "active = [c_new > 0] is DERIVED not free: nz = c_new·c_new_inv with c_new·(1−nz)=0 and bool_check(nz) forces nz = [c_new≠0]; since c_new ≥ 0 this is exactly [c_new>0]. A prover cannot flag a clamped (c_new=0) slot active nor a survivor inactive.",
    "Key clamp: final.key_{lo,hi} = nz · g_sorted.key so a dropped/zeroed slot cannot smuggle a live key (mirror :860-863).",
    "Mass accounting stays an EXACT equality (either in_mass = Σ g_sorted·active [grouped conservation, recommended] or in_mass = Σfinal + Σresidual + cap·τ [equivalent]); replacing the old strict final+residual identity is mandatory (it is UNSAT post-subtraction) — do NOT just delete it, or a prover could inflate final counts unchecked. cap·τ and the mass sum must stay < p.",
    "Obliviousness / fixed padding: circuit shape is a pure function of public (cap=s, m); the change adds exactly cap subtractions + cap range-checks + cap is-nonzero gadgets + cap c_new_inv witnesses + one mass term — all data-INDEPENDENT counts. No Rust `if` enters the circuit (survivorship decided by the arithmetic is-nonzero gadget); survivor count is never branched on; the final table is always exactly cap rows with clamped dummies in fixed low-count-prefix positions, padded to capacity, preserving the decode's (active asc, count asc) suffix invariant. Under-full states have τ=0 (row m-1 is a dummy) so the merge is a no-op — completeness preserved.",
    "Well-formedness for next epoch: active=0 ⇒ count=0 and active=1 ⇒ count>0 hold by construction, so the next epoch's init checks (:700-709) still pass on clamped dummies."
  ],
  "verification": {
    "new_test_surfacing_deficit": {
      "file": "src/sketch/ss_final_full.rs tests module (after :1650), mirror in plonky2/src/sketch/spacesaving.rs",
      "spec": "Cross-batch thinly-spread heavy key that is currently dropped every epoch (FAILS on old code, PASSES after). capacity=2, batch=4, chain via apply_batch_ss_full: B1 from empty [W1:6, W2:6, H:5, dummy] (old keeps {W1:6,W2:6}, H dropped; MG τ=5 ⇒ S1={W1:1,W2:1}); B2 [H:5, f:1, dummy, dummy] (old: {W1:6,W2:6} still beats H ⇒ H ABSENT; MG: old{W1:1,W2:1}∪{H:5,f:1}, τ=1 ⇒ final {H:4} ⇒ H PRESENT); optional B3 [H:5,…] pushing true(H)=15 strictly above N/s=14 (N=28,s=2). Assertions: `assert!(final.frequency(H) > 0)` (surfacing — returns 0 today, >0 after); `assert!(final.frequency(H) <= true_freq(H))` (under-estimate); `assert!(true_freq(H) - final.frequency(H) <= N / s)` (deficit). ALSO add a property test over a random stream asserting for every key f_hat ≤ f_true, f_true − f_hat ≤ N/s, and f_true > N/s ⇒ f_hat > 0.",
      "tau_gt_0_unit": "Single-epoch τ>0 sanity: cap=2, batch=2, old={A:5,B:5}, batch={C:5,D:0} ⇒ τ = g_sorted[m-1].count = 5, all retained → 0 (all clamp to dummy); assert final counts = window−τ and the mass identity Σ g_sorted·active = in (or Σfinal+Σresidual+cap·τ = in)."
    },
    "existing_tests_to_recompute": [
      "ss_full_top_s_retention (:1304): with cap=2,m=4,weights {1,2,3,4}, τ=g_sorted[3]=2, so kept_counts [3,4] → [1,2] (:1326-1330); replace the final+residual=10 assertion with the grouped-sum conservation Σ g_sorted.count = input mass = 10 (or Σfinal+Σresidual+cap·τ=10).",
      "fragmentation_rejected (:1487): honest branch A:10 → 8..., C:9 → 7... (subtract τ; the retained SET {A,C} is unchanged, only under-estimated — surfacing preserved); the tamper branch (mal.is_err) is unchanged. Re-derive τ for the specific fixture.",
      "tie_break_rejected (:1554): the current fixture (three count-5 keys, cap=2) collapses ALL to 0 under τ=5, DISSOLVING the tie discriminator. REDESIGN the fixture so the tied pair sits strictly above the (s+1)-th value (e.g. add a low-count decoy as the residual so τ is small and both tied survivors remain positive), then keep asserting the tamper is rejected.",
      "count0_active_rejected (:1616): τ=0 here so the A:5 assertion still passes, but note count-0 keys now always clamp to dummy; update the narrative comment (grouped.active binding still rejects the tamper).",
      "ss_full_round_trip (:1260), ss_full_in_circuit_grouping_sums_counts (:1277), decode tests (:471-559): all under-full (distinct keys ≤ cap ⇒ τ=0) ⇒ unchanged, must stay green (confirms completeness).",
      "TAMPER regressions (TAMPER_GSORTED/FRAGMENT/TIE/ACTIVE, count_overflow_rejected :1659, malformed_dummy :1692) still assert REJECTION and remain valid.",
      "plonky2: group_then_topk_keeps_heaviest (:247-248), commit_changes_with_state, leaf spacesaving_round_trip (:350), spacesaving_two_epoch_merge (:366), spacesaving_rejects_wrong_final (:383) all use cap=4 with ≤3 active keys ⇒ τ=0 ⇒ unchanged; add a FULL-state (cap=2) leaf parity test so prove()/verify_node() exercises τ>0 and confirms native subtraction agrees with the in-circuit fk/diff/surv binding."
    ],
    "commands": [
      "cargo test -p zksketch --lib sketch::ss_final_full  (each prove_* self-verifies via verify_all_tables :1170-1172; confirms the proof still verifies and the trace pads to the fixed cap-driven shape)",
      "cargo test -p zksketch --lib decode::spacesaving",
      "plonky2: cargo test in plonky2 crate for sketch::spacesaving, leaf::spacesaving, and plonky2/tests/four_family_forest.rs; check plonky2/tests/cost_shapes.rs degree_bits() did not cross a power-of-two boundary",
      "End-to-end: run the SS leg of src/experiments/stream_compose.rs (regenerate results/stream_compose*.csv) and, for the SNARK backend, EXP_COMPOSE_BACKEND=plonky2 EXP_COMPOSE_FAMILY=ss scripts/run_compose.sh"
    ],
    "csvs_that_will_shift": ["results/stream_compose*.csv (under edit)", "results/ss_batch_certified.csv", "results/frame_out_4machine_plonky3.csv", "results/frame_out_4machine_plonky2.csv (SNARK-backend ss row)", "any case-study / rq2 SS mass figures — retained counts become under-estimates and top-c released mass shrinks by the accumulated deficit; re-baseline. Proof shape/timing changes only by the O(cap) added columns/range rows."]
  },
  "paper_update": "Replace the SS 'Accuracy guarantee' appendix paragraph (currently the retention/keep-top-s version) with: 'Each epoch the leaf performs a mergeable Misra-Gries/Frequent compression [Agarwal, Cormode, Huang, Phillips, Wei, Yi, \"Mergeable Summaries\", PODS 2012 / ACM TODS 2013] with target size s = capacity: it unions the previous summary (≤ s counters) with the batch, sums counts per key, subtracts the (s+1)-th largest counter value τ from every counter, and deletes non-positive counters, retaining ≤ s. Because counters are only ever decremented, the released estimate is a one-sided UNDER-estimate f_hat(x) ≤ f_true(x), and the mergeable Misra-Gries invariant bounds the per-key deficit by f_true(x) − f_hat(x) ≤ N/s over any merge tree of total weight N. Consequently every key with true frequency f_true(x) > N/s retains a strictly positive count and is surfaced in the final summary — the cross-batch N/s heavy-hitter surfacing guarantee. The circuit commits τ as the pinned rank-(m−1) cell of the count-sorted candidate table and enforces the subtraction, the derived active flag active(x)=[f_hat(x)>0], non-negativity, and exact grouped-mass conservation Σ grouped = Σ(old)+Σ(batch), so the discarded deficit is forced to exactly s·τ (plus the residual) per epoch. (The prior construction kept the top-s exact summed counts and discarded the residual whole, which carries no bound relating retained counts to true frequencies: a heavy key thinly spread just below the retention cut is evicted every epoch and never surfaces.)' If the over-estimate direction is chosen instead, cite Metwally-Agrawal-El Abbadi (ICDT 2005) and its mergeable form and note the different (per-counter error, add-not-subtract) construction.",
  "risks_and_open_questions": {
    "design_fork_to_confirm": "Confirm the intended guarantee is Misra-Gries/Frequent UNDER-estimate (this plan) vs textbook SpaceSaving OVER-estimate. They are different summaries with different merges, mass identities, and decode semantics. Recommendation: ship MG under-estimate (clean surfacing, minimal circuit); adopt over-estimate ONLY if an explicit upper bound on frequency is required (then a per-counter error column + add-not-subtract merge is needed — a materially heavier circuit).",
    "two_backend_scope": "Both plonky3 (ss_final_full.rs) AND plonky2 (sketch+leaf spacesaving.rs) are on the eval critical path (plonky3 = headline STARK numbers; plonky2 = SNARK-backend forest numbers, e.g. frame_out_4machine_plonky2.csv cap16384). Fixing only one leaves the other surfacing-broken AND makes the two backends diverge on the same input. Decide up front whether both backends are being claimed; if only plonky3 numbers are reported, plonky2 is parity-only and lower priority but should be explicitly scoped out in writing.",
    "tau_index_off_by_one": "τ must read g_sorted[m-1] (the (s+1)-th largest), not g_sorted[m] (smallest retained). g_sorted[m] over-subtracts, leaves ≤ s−1 survivors, and weakens the bound WITHOUT failing any existing under-full test (τ=0 in those). Pin and code-review this index in BOTH backends.",
    "mass_identity_choice": "Two equivalent sound replacements for the old strict identity: grouped-sum conservation (recommended — matches plonky2's existing Stage H, gives cross-backend symmetry, minimal) or the exact output-side Σfinal+Σresidual+cap·τ. Do NOT merely delete Stage 9. Verify cap·τ and the mass sum stay < p (COUNT_DIFF_BITS bound; latent already, but rq2 sweeps to very large cap/batch should carry an explicit assert).",
    "semantics_drift_and_test_churn": "Retained counts and decode top-c mass become under-estimates; audit stream_compose asserted per-batch answers, E-series examples, and any experiment asserting exact SS masses on an OVER-capacity state. Several honest-path test expectations must be re-derived by hand (risk of masking a real regression) — pin each by recomputing τ and the mass identity; the tie_break fixture must be redesigned so the discriminator does not dissolve under τ. Confirm no test cross-checks the certified leaf against spacesaving_naive for count equality (they share proof/commitment types by design, not frequencies).",
    "cost_obliviousness": "Adds O(cap) columns/range rows (+cap c_new_inv/surv_inv witnesses, +cap subtractions, +cap range-checks, +cap is-nonzero gadgets, +1 mass term) — no asymptotic change, negligible vs the Θ(s) Poseidon2 recommit, and the fixed cap-driven shape + obliviousness proofs are unaffected. For the plonky2 eval shape cap=16384 verify degree_bits() (cost_shapes.rs) does not cross a power-of-two boundary and inflate prove time/RSS (the 4-machine plonky2 ss row already sits near ~9.8 GB).",
    "downstream_invariant_check": "The change removes the strict SS final+residual mass equality; confirm nothing else (recursion/boundary Expose at :597-600, forest merge) relies on SS mass being exactly conserved INTO the state — the new equality conserves grouped mass, not output mass."
  }
}