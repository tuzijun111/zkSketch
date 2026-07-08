# zk1.tex main-body audit (notation · gates · paper-vs-code · DB-reviewer clarity)

> **RESOLUTION STATUS (all findings below addressed).** The findings in this report have been fixed in `latex/zk1.tex`. Note the report's line numbers are stale (the paper has since grown to ~3100 lines).
>
> - **Notation, gates/citations, and DB-clarity issues (Sections A, B, D):** fixed in the paper — symbol overloads renamed (composition-atom split `m→h`, CM challenge `r→α`, CM old/new counter `O/O'→v_old/v_new`, GK prefix mass `P→pm(e)`, GK covered-sets `S_e→C_e`), undefined terms defined at first use (log follower, cold auditor, verification key, band-merge, trace blinding, popcount, `t'`, `≡`, transparency, PLONKish), citations corrected (LogUp→`HabockLogUp2022`, Nova demoted to a folding-scheme footnote, `2^27` cap→`Plonky3_2024`+two-adicity, DataSketches claim dropped), and the garbled abstract/mirror sentences rewritten.
> - **Code-mismatch issues (Section C):** the paper was made **honest against the code** — the composition-atom vk-identity check is now stated as pipeline-fixed/extractor-assumed (not an in-circuit registry check); the interval-proof boundary drops the unimplemented record range; the ordered-batch digest is described as a native 4-element boundary-state hash tree; `§4.4` now discloses the prototype verifies `popcount(t)` peak proofs per query rather than one finalized root; the chain is described as leaf-then-compose; lazy finalization / frozen-snapshot / log-follower are marked design-not-yet-realized. **These softenings could instead be closed by implementing the feature** (as was done for the one exception below).
> - **The one implemented exception:** the SpaceSaving accuracy gap (Section C / D) was fixed **in code, not by softening** — the certified SS update now performs the mergeable Misra-Gries `(s+1)`-th-value subtraction on both backends, so the paper's `N/s` heavy-hitter surfacing guarantee is real (see `docs/ss_ns_gate_plan.md`).
> - **Residual:** the SS evaluation CSVs need a re-run to re-baseline (the SS circuit changed); numbers are otherwise unaffected.

Audit of the main body (everything before `\appendix`) of `latex/zk1.tex`, cross-checked against the implementation in `src/` and the artifacts in `results/`. Every medium/high finding below survived an independent adversarial verification pass (findings that could be refuted were dropped; 4 were). **Line numbers refer to the file as of 2026-07-08** — the file was edited while the audit ran, so treat quotes as authoritative and anchors as ±8 lines.

## What checked out (verified as correct)

- **Both worked examples are arithmetically correct.** The Count-Min Step-5 example and the full GK batch-update example (neighbor inits, both fusion branches, the blocked pair, final state, mass identity) were recomputed by hand and against `apply_batch2` semantics — no errors.
- **The GK circuit matches the paper token-for-token** on the core rules: six-field tuple layout, `(e,t)` sort, `s'(N)=⌈2s ln(N/s+2)+2⌉` (verbatim as `gribelyuk_space_bound`), fresh timestamps `N_{t-1}+ord_p`, neighbor-init copy chains, `θ_t=⌊N_t/s⌋`, `L_f=⌈log₂(s'+m)⌉` parity-0 rounds with per-round resort, both fusion inequalities and survivor updates, compaction with trailing-dummy check, and the mass identity as an actual circuit check (Stage 8 of `prove_gkb2`).
- **The Count-Min pipeline matches on structure**: full-capacity leaves as the footnote states, one Poseidon2 sponge per record with low `log₂w` bits of limb *i* (with `d≤8`, `w` power of two asserted), running-sum segment aggregation, the read/write set check over exactly `dw+md` elements per side with a separate `O'=O+Δ` gate, all three ablations (one-hot / two-sided Merkle / memory-checked) implemented and benchmarked, and no `ρ` in commitments exactly as the eval discloses.
- **The evaluation numbers reconcile with the CSVs almost everywhere** — every spot-checked headline number (113.6 s / 2.6 s / 44×, 56.7 s CM, 28.1 s HLL, 8.7 s SS, 77.1 s GK, all Table 2 cells, 499 KiB / 15–18 ms roots, stream-scaling ratios, query-circuit times) matches `results/*.csv`. The exceptions are provenance issues listed in section C.
- **Forest mechanics** (binary-counter cascade, O(1) amortized insert, parallel leaves, greedy work pool, pinned multi-process methodology, sockets/traffic accounting) match the code.

## Top findings (fix before submission)

1. **§4.4 vs. eval contradiction on query verification** — §4.4 promises "one root check and one query check" after on-demand finalization; the implementation never finalizes at query time and the eval's own `ctx` column reports popcount(t′)=3–5 peak-proof checks per query. Pick one story (lines ~708, ~1564, Table `mixed`).
2. **GK invariant uses a third, undeclared meaning of `t`** — `g₁+Δ₁≤⌊εt⌋` (lines 1098, 1247) needs `t`→`N_t` (=`θ_t`·s); under either declared meaning of `t` the claim "a fusion never breaks the invariant" is false.
3. **LogUp mis-cited** — line 872 cites `thaler2022` (Thaler's textbook); the correct `HabockLogUp2022` is already in the bib, uncited. Also "the same LogUp running sum as Step 3" (~line 993) dangles: Step 3 presented a grand product.
4. **Composition-atom boundary claims not implemented** — record ranges `r_{[i,j]}` and the in-circuit verification-key identity check (Definition 2's stated soundness linchpin) exist nowhere in code; the ordered-batch digest is native-only, binds boundary states rather than batches, and is 4 field elements, not one.
5. **Step 3's multiset encoding as described is not what runs** — the code packs `(counter,value)` deterministically as `combined·2²⁰+v` in one BabyBear element with no value range check; at the deployed `d=7, w=2¹⁴` the packing wraps mod p and loses injectivity, so either fix the code (range-check) or describe/caveat the deployed encoding.
6. **GK's per-round re-sort has no stated binding mechanism** — and "multiset equality is used only for conservation steps" (line ~1119) contradicts what soundness requires (and what the code does with PermuteAir).
7. **Apache DataSketches fidelity claim** — DataSketches is never used in the artifact; the fidelity check is the repo's own plaintext replay (line 1422).
8. **Three of four rows of the mixed-query table are `status=inferred`**, not measured, against "Every number is reproduced by scripts…" (lines ~1381, 1560+). The `s3_mixed_q*.csv` files even contain HLL b=14 query rows the code cannot produce (decode asserts b≤8).
9. **Two garbled abstract sentences** — "for three common families except Greenwald–Khanna" (lines 97, 185) and the final abstract sentence (99–103).
10. **`2²⁷` FRI-domain cap** — never explained, mis-cited to `ZkValue2026`, and not the actual cause of the first CM/HLL one-hot deaths (those hit tunable RAM guards).


## A. Notation: definition-before-use and symbol abuse


### HIGH

### [HIGH] zk1.tex:1556-1557,1572 — technique-consistency (CONFIRMED)

The evaluation's per-query verifier cost is 3-5 root checks (popcount(t') many), contradicting Section 4.4's claim that a query costs the verifier exactly one root check plus one query check against the single finalized root Pi_{[1,t]}. Either the prototype skips finalization and the verifier checks every surviving peak (a different protocol than Section 4 describes), or the eval is measuring something the main body never defines.

**Suggested fix:** Reconcile: if the deployed mode verifies the popcount(t') un-finalized peaks instead of one finalized root, say so explicitly in Section 4.4 or in the eval (e.g., 'the prototype answers against the peak set without finalizing, so a query verifies popcount(t') peak proofs'); otherwise report 1 root check and move peak checks elsewhere. Also state that the ctx column is an average over query instants (its values 3.2, 5.0 are non-integers).

### [HIGH] zk1.tex:1400,1564 — undefined-symbol (CONFIRMED)

HyperLogLog's parameter b (b=14 in Parameter Setting; 'caps $b\le 8$' in the mixed-query section) is never defined anywhere in the paper. Worse, it collides with Count-Min's column index b (lines 745, 797), and the paper's own HLL appendix uses a different convention entirely: s for the register count and b as the register INDEX ('S_{HLL}[b], b in [s]', lines 1795-1798; line 2748: '$s$ the HyperLogLog register count').

**Suggested fix:** Restate the deployed shape in the paper's own notation, e.g. 'HyperLogLog $s=2^{14}$ registers' (matching Appendix D), or define b once ('precision $b$, i.e. $s=2^b$ registers') in Parameter Setting; rename CM's column index or HLL's precision to avoid the b collision.

### [HIGH] zk1.tex:1089-1090 — inconsistent-notation (CONFIRMED (adjusted))

The central GK invariant is stated as g_1+Δ_1 ≤ ⌊εt⌋ and g_2+Δ_2 ≤ ⌊εt⌋ at zk1.tex lines 1097-1098, and repeated at lines 1246-1247. Under the paper's own conventions t is the version index (S_t, B_t), and lines 1093-1094 explicitly introduce a second meaning (per-tuple insertion timestamp, "a tuple field, not the version index t"). The invariant silently uses a third, never-declared meaning — the current population — which is written N_t everywhere else (θ_t = ⌊N_t/s⌋ at lines 1146 and 1203). As written the invariant is wrong under both declared meanings of t: the version-index reading is a meaningless small counter, and the timestamp reading is not preserved by Step 5's own fusion rule (which tests against the current θ_t while the surviving tuple's insertion timestamp is older, so ⌊ε·t_survivor⌋ can be smaller than the post-merge mass), contradicting the "a fusion never breaks the invariant" claim at lines 1245-1247. Fix: replace ⌊εt⌋ with ⌊εN_t⌋ (equivalently θ_t) at lines 1098 and 1247, matching the Step 4 threshold definition, the gatebox (line 1146), and the implementation (src/decode/gk_bandmerge.rs:396, eps_n = st.n / st.params.s).

**Suggested fix:** Replace \lfloor\varepsilon t\rfloor with \lfloor\varepsilon N_t\rfloor (or with \theta_t) at both lines 1090 and 1239, matching the threshold definition in Step 4 and the gatebox.

### [HIGH] zk1.tex:1400 — defined-only-in-appendix (CONFIRMED (adjusted))

SpaceSaving's capacity parameter $s$ is used in the main-body evaluation (line 1408: "SpaceSaving $s=2^{14}$"; lines 1466/1470/1472: $\Theta(s)$, $\Theta(s{+}m)$, "$m$ overtakes $s$") but is defined only in the appendix (lines 2146-2149: "$s$ now denoting the declared number of SpaceSaving slots"; notation paragraph line 2782). In the main body, $s$ has already been bound to Greenwald--Khanna's ACCURACY parameter $s=1/\varepsilon$ (line 1074), with $s'$ reserved for GK's capacity — and the collision occurs inside the very sentence at line 1408, which sets SpaceSaving $s=2^{14}$ (a capacity) next to GK "$s'=2^{11}$ (accuracy $1/\epsilon$ derived from capacity)", where the main body's name for that accuracy is $s$. The paper itself repeatedly has to disambiguate the overload (line 1762: "distinct from the sketch capacity $s$"; line 1811: "not Greenwald--Khanna's accuracy parameter $s=1/\varepsilon$"), evidence that it bites. Fix: define SS's $s$ at first main-body use (e.g., "SpaceSaving with $s=2^{14}$ summary slots, Appendix E") or rename it (e.g., $s_{\mathsf{SS}}$).

**Suggested fix:** Define SS's s at first main-body use ('SpaceSaving with $s=2^{14}$ summary slots, Appendix E') or rename it (e.g., $s_{\mathsf{SS}}$); the appendix itself already has to disambiguate ('distinct from the sketch capacity $s$', line 1747), evidence the overload bites.


### MEDIUM

### [MEDIUM] zk1.tex:184 — undefined-symbol (CONFIRMED)

The contribution bullet uses \Theta(E) with a one-off symbol E for the number of batch proofs. E appears nowhere else in the paper; everywhere else the batch count is t (intro line 135: "trusting the state after t batches requires checking all t transition proofs"; Section 5.1 line 428-434 derives the same cost as \Theta(t)).

**Suggested fix:** Replace E with t for consistency with lines 135 and 434: "against the \Theta(t) cost of checking a chain of t batch proofs".

### [MEDIUM] zk1.tex:184 — undefined-term (CONFIRMED)

The contribution bullet distinguishes two verifier types, a "log-following verifier" and a "cold auditor", neither of which is defined at this point or in the system model (Section 4.1 defines a single verifier role, line 284, and an "audit" mode, line 325). "Cold auditor" never appears again anywhere in the paper; "log follower" resurfaces only at line 636-637 with a functional gloss ("a log follower maintains the forest's peak digests from the public log").

**Suggested fix:** Define both verifier modes where the verifier role is introduced (Section 4.1, around lines 284/325), or rephrase the bullet in terms already defined (the audit/query verifier of line 325).

### [MEDIUM] zk1.tex:95 — claim-consistency (CONFIRMED)

The abstract claims "any verifier checks in O(1), independent of stream length", and line 184 claims O(1) for a log-following verifier; but Section 5.3 charges the verifier nu-1 <= ceil(log2(t+1))-1 peak-chaining hashes at query time to derive the boundary pub_[1,t] (lines 638-640), which grows (logarithmically) with stream length. The O(1) holds only for the proof-verification step, not the boundary derivation the same verifier must perform.

**Suggested fix:** Qualify the O(1) claim (e.g., "one constant-size proof check, plus O(log t) native hashes to derive the public boundary") or state that O(1) counts proof verifications only, matching the parenthetical already given for the cold auditor.

### [MEDIUM] zk1.tex:555 — symbol-overload (CONFIRMED)

Definition 2 (composition atom) uses m as the split batch index (Pi_[i,m], Pi_[m+1,j], com(S_m)), but m was already reserved at line 302 as the public batch buffer capacity ("a batch holds at most m records"), a meaning reused throughout Section 6 (e.g., line 730 "an $m$-record batch", line 1174 "$m$ the declared public per-batch capacity"). Within one definition, m is a batch position; two sections later it is a record count.

**Suggested fix:** Rename the split point in Definition 2 (e.g., use \ell or h or a midpoint symbol like p), keeping m exclusively for the batch capacity.

### [MEDIUM] zk1.tex:341 — defined-late (CONFIRMED)

The problem statement uses the symbol s'(N) ("Greenwald--Khanna's summary capacity $s'(N)$") with no definition of s', s, or bare N at that point; the forward pointer goes only to Appendix app:constraint-budget. The actual definition, $s'(N)=\lceil 2s\ln(N/s+2)+2\rceil$ with $s=1/\varepsilon$, appears 735 lines later at lines 1066-1077 (Section 6.2). Relatedly, bare N (stream length) is used at lines 322-323 and 341 although the streaming model of Section 4.1 only defines the function N(j) (line 291); bare N is introduced only informally in the intro (line 122).

**Suggested fix:** At line 341, either avoid the symbol ("GK's summary capacity, which grows as \Theta(log N)") or add a forward reference to Section 6.2 where s' is defined; define bare N (current record count) alongside N(j) in the streaming model.

### [MEDIUM] zk1.tex:330-331 — definition-drift (CONFIRMED)

The "profile" is defined as "the chosen sketch family together with its batch update UpdateBatch, query function Query, and capacities" (and similarly at line 284). Section 5 then attributes to the profile items outside that definition: the deployment's declared interval-proof circuit verification keys (line 562 "fixed in the profile"), the digest-composition rule (line 585 "declared"), and the canonical finalization bracketing (lines 625, 645 "fixed by the profile" / "the profile declares"). None of these are sketch, update rule, query function, or capacity.

**Suggested fix:** Broaden the profile's definition in the Problem Statement to include the proof-layer declarations (circuit identities/verification keys, digest rule, bracketing), or introduce a separate "deployment declaration" term for them.

### [MEDIUM] zk1.tex:199 — defined-only-in-appendix (CONFIRMED)

Related work asserts that zkSketch "bounds output leakage only when an optional release policy is in force", but the release-policy mechanism (the ans = policy(res; rho) split, release proof, identity vs. non-trivial policy, committed seed) is defined only in the appendix (lines 1663-1670 in Property 3 and lines 2076-2110). No main-body section explains what a release policy is; the closest is the unnamed DP composition remark at lines 383-384.

**Suggested fix:** Either add one sentence in Section 4 (e.g., in the Protection Scope item (ii)) introducing the optional release policy and its proof, or drop the term from related work in favor of the DP-composition phrasing already used at line 384.

### [MEDIUM] zk1.tex:1228-1234 — symbol-overload (CONFIRMED)

Delta with two subscripts has three different meanings inside Section 5. Count-Min defines \Delta_{i,b} = net batch delta at row i, column b (line 873). GK Step 5 writes \Delta_{1,i+1} meaning 'field \Delta_1 of the tuple at position i+1' (lines 1228, 1234) — same visual form, opposite reading. The GK example then silently switches to pair-position subscripts, \Delta_{1,2} and \Delta_{2,1} meaning 'field \Delta_1/\Delta_2 of the second/first pair member' (lines 1325, 1331), a third convention introduced without comment and easily misread since the pair members are the literal values 1 and 3.

**Suggested fix:** Disambiguate: write GK's field-of-tuple access functionally, e.g. \Delta_1(u_i) or \Delta_1^{(i)}, and keep the example in the same convention as Step 5 (i and i+1) instead of renumbering the pair members 1 and 2.

### [MEDIUM] zk1.tex:1346 — undefined-check (CONFIRMED)

The GK example defends against tuple-invention by appealing to 'Step 6's mass identity \sum(g_1+g_2+1)=N_t', but Step 6 (lines 1245-1256) never states any mass identity — its stated checks are that S_t equals the first s' rows of U^{(L_f)}, opens to com(S_t), and the trailing m rows are all-dummy; the gatebox's compaction check is active(U^{(L_f)}) \equiv active(S_t) (line 1141). The mass equation appears only as a descriptive property of the state at line 1083 (there written = N, not = N_t), never as a circuit check in any step.

**Suggested fix:** Either add the mass check \sum_{active}(g_1+g_2+1)=N_t to Step 6's (or the gatebox's) stated constraints, or rewrite the example's cheat argument to invoke the conservation check that is actually stated (active(U^{(L_f)}) \equiv active(S_t) plus Step 2's union conservation).

### [MEDIUM] zk1.tex:1090 — symbol-overload (CONFIRMED)

The symbol t carries three meanings in the main body: (1) the batch/version index (line 301), (2) the GK per-tuple insertion timestamp (lines 1084-1086, explicitly disclaimed against meaning 1), and (3) the current population in the invariant floor(varepsilon*t) (lines 1090, 1239), where t must mean N_t for the claim to be right. Reading (2) — the nearest antecedent, which the text just told the reader to adopt — makes line 1239's 'a fusion never breaks the invariant' false, since the fusion test only bounds sums by theta_t = floor(N_t/s) = floor(varepsilon*N_t), not by floor(varepsilon*t_tuple) of an older timestamp.

**Suggested fix:** Write the invariant as $g_1+\Delta_1\le\lfloor\varepsilon N_t\rfloor$ (N_t is already defined at line 1069), and rename the tuple timestamp (e.g., $\tau$) throughout Steps 2-5 and the sort key $(e,\tau)$.

### [MEDIUM] zk1.tex:555 — symbol-overload (CONFIRMED)

In Definition 4.2 (composition atom) m is the midpoint BATCH INDEX of the split (Pi_{[i,m]}, Pi_{[m+1,j]}, interior commitment com(S_m)), colliding with m = the per-batch record capacity defined in Section 3 (line 302) and used pervasively (eval sweeps m=2^4..2^14). com(S_m) in the atom reads as 'state after m records/batches' under the dominant meaning.

**Suggested fix:** Use a different midpoint letter in Definition 4.2 (e.g., h or mid): Pi_{[i,h]}, Pi_{[h+1,j]}, com(S_h).

### [MEDIUM] zk1.tex:1088 — symbol-overload (CONFIRMED)

P is overloaded within Section 5: the Count-Min patch table P[z] (Pattern A) versus GK's prefix rank mass P (Pattern B), which appears in the rank-interval formula. Both are paper-specific and prominent.

**Suggested fix:** Rename GK's prefix mass (e.g., R(e) or rank mass r(e) — mind the r collision — or $\mathsf{pm}(e)$), keeping P for the patch.

### [MEDIUM] zk1.tex:372-375 — enumeration-inconsistency (CONFIRMED (adjusted))

At zk1.tex lines 376-379 (main body), the sentence "We make these precise as four properties, update, history, and query-prefix soundness together with zero knowledge and circuit obliviousness" enumerates five named concepts under the count "four". It only parses correctly if the reader knows zero knowledge and circuit obliviousness are bundled into a single property, which is stated only in the appendix (line 1691, "Property~4 (zero knowledge and circuit obliviousness)"). Later main-body references ("the obliviousness of Property~4" at lines 738 and 1263) partially hint at the numbering but never mention that zero knowledge shares Property 4, and appear long after this sentence. Suggested fix: make the grouping explicit at lines 376-378, e.g. "four properties: update, history, and query-prefix soundness, plus a combined zero-knowledge-and-circuit-obliviousness property". (The similar sentence at lines 722-723 gives the count without enumerating names and needs no change.)

**Suggested fix:** Make the grouping explicit: "four properties: update, history, and query-prefix soundness, plus a combined zero-knowledge-and-obliviousness property", or punctuate so the count is unambiguous. The same sentence pattern recurs at line 715.

### [MEDIUM] zk1.tex:612-620 — symbol-overload (CONFIRMED (adjusted))

In zk1.tex, $k$ is overloaded within eight lines: line 620 defines $k_1>\cdots>k_\nu\ge 0$ as the exponents of the binary decomposition of $t$ ("writing $t=2^{k_1}+\cdots+2^{k_\nu}$"), and line 628 uses bare $k$ as the prover core count ("$O(k)$ tasks in flight on a $k$-core prover (cores introduced below)"), with an explicit forward reference because the $k$-core prover is only introduced at lines 642-643 ("a $k$-core prover finishes in $O(t/k+\log t)$"). Reading $O(k)$ immediately after the $k_i$ decomposition is confusing at first pass, though the subscripted-vs-bare distinction makes it recoverable. Fix: rename the bit positions (e.g., $t=\sum_i 2^{b_i}$) or introduce the $k$-core prover before line 628 so bare $k$ is defined at first use.

**Suggested fix:** Rename the bit positions (e.g., $t=\sum_i 2^{b_i}$) or introduce the k-core prover before line 620 so the symbol is defined at first use and does not collide.

### [MEDIUM] zk1.tex:482-487 — term-of-art-collision (CONFIRMED (adjusted))

The paper names its chain-extension step "\emph{folding}" (zk1.tex:490-494, not 482-487) while the mechanism described — and implemented (p3_recursion::build_and_prove_aggregation_layer in src/recursion/recursive/countmin_chain.rs) — is full in-circuit recursive proof verification ("a single circuit verifies $\Pi_{[1,t-1]}$ in-circuit"). Line 466 (not 458), 24 lines earlier, cites SettyNova2022 ("Nova: Recursive Zero-Knowledge Arguments from Folding Schemes"), where "folding" is a term of art for combining instances precisely WITHOUT in-circuit verifier execution; the paper never distinguishes its usage from that sense. A ZK-literate reviewer will read "folding" as claiming a Nova-style folding scheme. The term is used pervasively as the operation's name — abstract (line 95), contributions (184), overview (324), chain section (490-515), forest section (652-656), merge schedule (1232-1240), and evaluation (1491-1532) — so renaming (e.g., to "extension" or "recursive composition step") or adding an explicit footnote disclaiming the Nova sense is needed, and a rename would touch all these sites.

**Suggested fix:** Rename the operation (e.g., "extension", "absorption", "recursive composition step") or add a footnote explicitly distinguishing it from folding schemes in the Nova sense.

### [MEDIUM] zk1.tex:583-585 — undefined-rule (CONFIRMED (adjusted))

Definition 2, item 3 (zk1.tex:591-593) requires the parent digest H_[i,j] to be computed from the two child digests "according to the declared digest-composition rule", but this rule is never specified anywhere in the paper: the phrase occurs only at line 593, the appendix Property 2 (line 1660) just says "the declared digest combination", and the leaf digest H_[j,j] (what it binds) is never defined either — even though the history-soundness argument (lines 1662-1664) depends on H_[1,t] binding com(B_1),...,com(B_t) by collision resistance. The implementation does fix a concrete rule (src/recursion/mmr.rs: 2-to-1 hash node_hash(l,r) over Com(B_t) leaf digests, with the root additionally binding the leaf count), so the paper omits a rule the system actually declares. This omission also leaves Definition 1's wording (lines 480-481: H_[i,j] is "a Merkle-style root over B_i,...,B_j") in tension with Section 5.3, where the digest value depends on the composition-tree shape: lines 633-636 say the canonical bracketing "pins ... its digest H_{[1,t]} uniquely for a given t", and lines 654-656 let deployments declare different bracketings (left-to-right vs balanced), which would yield different H_[1,t] for the same batch sequence. Fix: state the rule once (e.g., H_[i,j] = H(H_[i,m], H_[m+1,j]) plus what leaf digests H_[j,j] bind, e.g., com(B_j) and r_j) and note in Definition 1 that the digest is canonical only under the profile's declared tree shape/bracketing.

**Suggested fix:** State the rule once (e.g., $\mathcal{H}_{[i,j]}=\hash(\mathcal{H}_{[i,m]},\mathcal{H}_{[m+1,j]})$ plus what leaf digests bind) and reconcile Definition 1's "Merkle-style root" wording with the bracketing-dependent digest of Section 5.3.

### [MEDIUM] zk1.tex:1081 — undefined-symbol (CONFIRMED (adjusted))

At zk1.tex:1089-1090 (not 1081-1082), the rank-mass fields are defined via sets $S_e$ and $S^{\circ}_e$ that are never defined anywhere in the paper — line 1089 is their sole occurrence in main body and appendix, and no preamble macro or verbal synonym introduces them. Worse, the letter S is the sketch state throughout the paper (S[i,b], and S_{t-1}, S_t appear in the same paragraph at line 1094 and same subsection at line 1130), so $|S_e|$ reads as something about the state table. Fix: define the covered-element sets explicitly with a non-colliding letter (e.g. C_e / C^{\circ}_e), or drop the set notation and define g_1, g_2 purely in words as counts.

**Suggested fix:** Either define the covered-element sets explicitly (e.g. 'let C_e denote the set of stream elements tuple e covers from below and C^{\circ}_e from above') using a letter other than S, or drop the set notation and define g_1, g_2 purely in words as counts.

### [MEDIUM] zk1.tex:912-914 — symbol-overload (CONFIRMED (adjusted))

O and O' are introduced en passant as the old/new counter values at zk1.tex lines 920-922 ("the old counter $O[i_z,b_z]$ ... the new counter $O'[i_z,b_z]=O[i_z,b_z]+\Delta_{i_z,b_z}$") with no formal "let ... denote" definition, first as arrays indexed [i_z,b_z], then silently re-used as scalars in Approach 3 (lines 955-956, 964-968, 977, 994) and in Example 5.1 (line 1059), each use relying only on inline glosses ("its committed old value $O$"). The symbol collides with big-O notation used in the same Section 5 (line 1257: "worst-case $O(\varepsilon^{-1}\log\varepsilon N)$ space bound") and throughout the paper (O(1), O(log t)); the overload also carries into the appendix ($O_b$ at line 1985). Suggested fix unchanged: rename to v_old/v_new or c, c' with an explicit introduction, and keep one arity (scalar at a named cell) throughout.

**Suggested fix:** Rename the old/new counter values, e.g. v_old/v_new or c, c' (or \mathsf{old}, \mathsf{new}), and introduce them with an explicit 'let ... denote'; keep one arity (scalar at a named cell) throughout.

### [MEDIUM] zk1.tex:975 — symbol-overload (CONFIRMED (adjusted))

The verifier challenge r in the cell encoding \phi_cell = addr + r v + \gamma (zk1.tex lines 983-984, repeated in the grand-product identity at lines 989-990) collides with the paper-wide use of r for record ranges: r_t is defined at lines 315-316 and used in the same circuit-walkthrough section at lines 840 and 845 ('match the public record range $r_t$') and again at line 1178, while r_i and r_{[i,j]} pervade Section 4 (lines 424-479, 580-590). The bare r is introduced only at line 984 and nowhere else, so a reader can misparse it as a range. Suggested fix: rename the encoding challenge to \alpha or \eta (both unused in the main body; \gamma at line 866 shows Greek letters are the established convention for challenges) at lines 983, 984, 989, and 990.

**Suggested fix:** Rename the encoding challenge, e.g. \alpha or \eta (\gamma is already established as a challenge at line 858, so a Greek letter is consistent): \phi_cell = addr + \alpha v + \gamma.

### [MEDIUM] zk1.tex:1087-1088 — symbol-overload (CONFIRMED (adjusted))

P is overloaded within Section 5 of zk1.tex: P[z] is the Count-Min patch table (defined at lines 881-882, reused at 919, with the patch discussion running through ~1033), and the bare symbol P reappears in the GK subsection as the prefix mass in the rank interval at lines 1095-1096 ("$[\,P-g_2(e)-\Delta_2(e),\ P+g_1(e^{+})+\Delta_1(e^{+})\,]$ for its prefix mass $P=\sum_{\text{tuples}\le e}(g_1{+}g_2{+}1)$") with only an inline gloss and no acknowledgment of the reuse; the appendix continues the collision (HLL patch P[z]/$P$ at 1960-1964 vs. GK prefix sum P_i at 2575). The same rank-interval sentence is also the first use in the paper of the functional field notation g_2(e), Δ_2(e), g_1(e^+) and of the value-successor e^+ (glossed only as "value-successor"), ~95 lines before the neighbor notation e^- < e < e^+ is properly set up in Step 3 (lines 1189-1197). Suggested fix unchanged: rename the prefix mass (e.g. R_{\le e} or \mathrm{pre}(e)) and forward-reference or relocate the e^-/e^+ neighbor definition so the rank interval is self-contained.

**Suggested fix:** Rename the prefix mass (e.g. R_{\le e}, \mathrm{pre}(e), or \pi_e-style notation avoiding proof symbols), and move or forward-reference the e^-/e^+ neighbor definition so the rank interval is self-contained.

### [MEDIUM] zk1.tex:1135 — undefined-symbol (CONFIRMED (adjusted))

The relation symbol \equiv used for the GK conservation identities (zk1.tex lines 1143, 1149, and repeated at 1353 — not 1135/1141/1345 as originally cited) is never defined anywhere in the paper; it evidently means equality of the multisets of active rows, but the paper only defines \uplus (line 961) and uses plain = for the analogous Count-Min identity (line 959). The usage is also internally inconsistent: line 1143 writes the bare padded table U on the left (U \equiv S_{t-1} \uplus {fresh...}), even though Step 2's prose (lines 1182–1184) states the check is over U's active rows — taken literally over padded tables the identity doesn't balance — while line 1149 wraps both sides in the operator active(\cdot), a notation used only there in the main body and never introduced (the adjective "active rows" is defined at line 833, but the operator form active(T) is not). Suggested fix stands: define once, e.g. "we write X \equiv Y for equality of the multisets of active rows, and active(T) for the multiset of a padded table's active rows," and apply active(\cdot) uniformly (line 1143 should read active(U) \equiv ...), or use plain = as in the Count-Min identity.

**Suggested fix:** Define once, e.g. 'we write X \equiv Y for equality of the multisets of active rows, and active(T) for the multiset of a padded table's active rows', and apply active(\cdot) uniformly (line 1135 should be active(U) \equiv ...), or simply use = as in the Count-Min identity.

### [MEDIUM] zk1.tex:1072-1075 — undefined-term (CONFIRMED (adjusted))

At zk1.tex lines 1079-1083, the sentence justifying the bounded-GK variant uses two terms that are never defined in the paper: 'band-merge' (the word 'band' has no definition anywhere in the file, yet the deployed family is named 'band-merge GK' in the evaluation at line 1473; the only gloss, 'adjacent representatives merge under both the rank-mass threshold and the timestamp direction, not merely when their values coincide', is deferred to the appendix at lines 2692-2695) and the scare-quoted '"hard case"' of one-directional GK (used at lines 1082 and 1248, never explained). Note the variant itself IS described operationally in the main body (two-sided rank masses at 1088-1092, the mirrored FuseTuple rule at 1228-1251), and 'Khanna--Greenwald sketch' is the cited paper's own title terminology (gribelyuk2024simple), not an invented joke. Fix: define 'band-merge' at first use by promoting the appendix gloss into line 1080, and add one sentence saying what the 'hard case' is (the adversarial insertion order that inflates one-directional GK), keeping the citation for the analysis.

**Suggested fix:** Either define 'band' and the hard case in one sentence each (e.g. the adversarial insertion order that inflates one-directional GK), or strip the jargon and describe the variant operationally ('adjacent-pair fusion with two-sided rank masses'), keeping the citation for the analysis.

### [MEDIUM] zk1.tex:785 — definition-before-use (CONFIRMED (adjusted))

The Count-Min gatebox's private-witness description at zk1.tex:793 refers to a bare \Delta ("the counter-grouped aggregation and the patch that together describe \(\Delta\)") — the first occurrence of \Delta in the entire paper, 88 lines before the per-counter delta \Delta_{i,b} is defined in Step 4 (line 881); \Delta as a standalone name for the batch-level effect is never formally defined anywhere in the main body. Bare \Delta then recurs with a different, per-counter (subscript-dropped) meaning in O'=O+\Delta at lines 968, 977, and 994, though those later uses are locally disambiguated by the surrounding "at each touched counter (i,b)" context. Suggested fix unchanged: in the gatebox say "the batch's net effect" in words (or define \Delta=(\Delta_{i,b})_{i,b} there), and optionally keep subscripts (O'=O+\Delta_{i,b}) at lines 968/977/994 so the gate refers to the defined object.

**Suggested fix:** In the gatebox write 'the batch's net effect' in words (or define \Delta = (\Delta_{i,b})_{i,b} explicitly there), and at lines 960/969/986 keep the subscripts, O' = O + \Delta_{i,b}, so the gate refers to the defined object.

### [MEDIUM] zk1.tex:1457-1458 — cross-section-consistency (CONFIRMED (adjusted))

zk1.tex:1465-1466 (not 1457-1458 as originally cited): the Pattern-B eval sentence "The per-record replay pays the whole $\Theta(s)$ summary per record and dies at $m=128$ (SS) and $m=256$ (GK)" charges the GK replay $\Theta(s)$, but per the paper's own notation (line 1074: GK accuracy parameter $s=1/\varepsilon$; lines 1084-1085 and 1408: summary capacity $s'$, deployed $s'=2^{11}$) GK's whole summary is $\Theta(s')$, matching Section 5.2 (lines 1270-1271) and Table tab:gk-update (line 1291). For GK, $\Theta(s)$ would mean $\Theta(1/\varepsilon)\approx 112$ at the deployed shape, ~18x smaller than the $s'=2048$ summary. Fix: "$\Theta(s)$ for SS and $\Theta(s')$ for GK" (or "the whole summary, $\Theta(s)$ resp. $\Theta(s')$").

**Suggested fix:** Write 'Theta(s) for SS and Theta(s') for GK' (or 'the whole summary, Theta(s) resp. Theta(s')'), matching Table 3 and Section 5.2.

### [MEDIUM] zk1.tex:612 — symbol-overload (CONFIRMED (adjusted))

In zk1.tex the letter k carries four meanings in the main body (lines 1-1600): (1) binary-expansion exponents of t at line 620 ("writing $t=2^{k_1}+\cdots+2^{k_\nu}$ with $k_1>\cdots>k_\nu\ge 0$"); (2) the prover core count at lines 628, 642-644, and 656 ("$O(k)$ tasks in flight on a $k$-core prover", "$O(t/k+\log t)$", "keeps $k$ cores busy"); (3) the Count-Min record key, bare $(k,v)$ at line 754 and subscripted $k_p$ at lines 805, 832, 853-854, 859, 866, 881; and (4) the length of a mergeable GK chain at lines 1208-1209 ("a chain of $k$ mergeable tuples collapses in $\lceil\log_2 k\rceil$ rounds"). No convention in the main body reserves k for any one role, and the collision between the subscripted exponents k_1..k_nu and the subscripted keys k_p is especially confusable. Suggested fix unchanged: keep k for keys (most frequent, load-bearing use); rename the core count (e.g., p or c cores) and the chain length (e.g., $\kappa$), and reuse the existing peak/set-bit notation for the exponents of t.

**Suggested fix:** Keep k for keys (its most frequent, load-bearing use); rename the core count (e.g., p or c cores), the chain length (e.g., $\kappa$), and reuse existing exponent notation for the set bits of t.

### [MEDIUM] zk1.tex:1557 — defined-only-in-appendix (CONFIRMED (adjusted))

zk1.tex line 1565 (Section 6.4, "Mixed updates and queries") writes "$3$--$5$ root checks ($\mathrm{popcount}(t')$)" where (a) the symbol $t'$ is used before being pinned down — it is only implicitly identified as the leaf count two lines later (line 1567, "the leaf count is query-bound ($t'\approx N/Q$...)") and in the Table 8 header "leaves $t'$" (line 1584), with no earlier occurrence anywhere in the paper — and (b) the name $\mathrm{popcount}$ is never introduced in active main-body text: the identity $\nu=\operatorname{popcount}(t)$ appears only in the appendix (line 1706) and inside a commented-out table (line 662). Note the underlying quantity nu IS properly defined in the main body (lines 619-621 define it via the binary decomposition $t=2^{k_1}+\cdots+2^{k_\nu}$, one peak per set bit), so the defect is notational: the reader must independently know popcount = number of set bits and infer what t' is. Suggested fix: at line 619-621 add "(so $\nu=\mathrm{popcount}(t)$)" when introducing the peaks, and in Section 6.4 define $t'$ at first use (e.g., "$t'$ leaves — the batch count inflated by query-induced early seals") before invoking $\mathrm{popcount}(t')$.

**Suggested fix:** In Section 4.3, add 'nu = popcount(t)' when introducing the peaks (line 611-613); in Section 6.4, define t' at first use ('t' leaves, i.e., the batch count inflated by query-induced early seals') before invoking popcount(t').

### [MEDIUM] zk1.tex:1272,1409 — defined-only-in-appendix (CONFIRMED (adjusted))

Two tables referenced from the main body are defined only in the appendix, and acmart numbers tables continuously, so the rendered "Table N" gives no signal that the table is not in the main body. (a) zk1.tex:1417 — "(HyperLogLog's replay is its one-hot leaf, Table~\ref{tab:hll-update})" — has no appendix cue at all; the table is defined at line 2044 in Appendix C (app:hll). The fact itself is restated inline and Figure 4's discussion (lines 1449-1454) covers the one-hot replay independently, so the missing cue is a navigation nuisance rather than load-bearing. (b) zk1.tex:1280 — "collected in Table~\ref{tab:amortized-update}, and the full constraint budget in Appendix~\ref{app:constraint-budget}" — the table (line 2907) actually lives inside that cited appendix, so a cue exists but is only implicit; the phrasing reads as two separate destinations. Fix: write "Table~\ref{tab:hll-update} (Appendix~\ref{app:hll})" at line 1417, and at line 1280 rephrase to make containment explicit, e.g. "collected in Table~\ref{tab:amortized-update} in Appendix~\ref{app:constraint-budget}, alongside the full constraint budget." (Note the correct appendix letters are C for app:hll and G for app:constraint-budget, not D and F as the original fix suggested.)

**Suggested fix:** Write 'Table~\ref{tab:amortized-update} (Appendix~F)' and 'Table~\ref{tab:hll-update} (Appendix~D)' or restate the one-line fact inline.


### LOW (polish)

- **zk1.tex:291**: j is overloaded across index spaces: in Section 4.1 it is an event-stream position (q_j, N(j), ver(j), line 291), while in Section 5 it is a batch-interval endpoint (Definition 1, line 465 "batches indexed i,...,j"; line 606 the leaf peak "$\Pi_{[j,j]}$" where j is a batch index). Section 5.4 (line 694) then reverts to j as event time in the same breath as batch version t = ver(j).
- **zk1.tex:702**: The main body cites "the query-prefix soundness of Property~3" using the appendix's property numbering; Properties 1-4 are stated and numbered only in Appendix sec:framework-properties (lines 1633-1687). The inline name makes it readable, but a main-body reader cannot resolve "Property 3" without the appendix (lines 373-375 name the properties but assign no numbers).
- **zk1.tex:151**: The introduction uses S_{t-1} -> S_t and the sequence (S_0, S_1, ..., S_t) (line 158) without introducing S as the sketch state or t as the batch/version index; the formal definitions come only in Section 4.1 (lines 292-303).
- **zk1.tex:698**: The query-function subscript is inconsistent: line 293 writes $\mathsf{Query}_{q_j}$ (subscripted by the query), line 330 bare $\mathsf{Query}$, and line 698 $\mathsf{Query}_q(S_t)$ with an unbound q (the section's query was introduced at time j, so q_j would be expected).
- **zk1.tex:187**: The three composition designs are called "composition schedules" in the contributions, "topologies" in Figure 1's caption and \label (lines 445, 447, 517 \label{sec:topology}), and introduced as strategies/steps in Section 5's overview (line 399 "per-batch strategy"). Also, the per-batch proof chain of Section 5.1 involves no composition at all, making "three composition schedules" slightly inaccurate.
- **zk1.tex:730**: 'Property~4' is cited by number here and at line 1255 (and 'Property~3' at line 702), but the properties are only numbered in the appendix (Property 1-4 at lines 1633, 1646, 1663, 1677); the main body lists them in prose without numbers (lines 372-375), so a main-body reader must guess the numbering.
- **zk1.tex:1272**: Table~\ref{tab:amortized-update} is cited as if nearby, but the table lives in the appendix (label at line 2874); the sentence flags the appendix only for the constraint budget, not for the table.
- **zk1.tex:1137**: The gatebox's verification target uses 'parity-$0$ fuse-and-resort rounds' before the term is defined; the pairing (2i, 2i+1) that gives 'parity-0' its meaning arrives only in Step 4 (line 1196), ~60 lines later.
- **zk1.tex:1174**: The letter M is used for two different kinds of object in the same section: M_{t-1}, M_t are multisets of the dw addressed cells in the Count-Min recommit (line 945), while M_\cup = s'+m is a scalar capacity in GK (line 1174).
- **zk1.tex:1068-1069**: GK introduces the population N (and N_{t-1}, N_t) as 'the record count' without connecting it to the framework's public quantities: Section 3 already defines \ell_t (index of the last record of B_t, line 302) and N(j) (line 293), and N_t = \ell_t. Step 4's gatebox then calls N_t 'public' (line 1145) — true only via the unstated identity with the logged \ell_t.
- **zk1.tex:1199**: The default fusion-round count is written with an unspecified log base, \lceil\log M_\cup\rceil, while the surrounding text uses \log_2 for the same quantity: \lceil\log_2 k\rceil at line 1201 and L_f = \lceil\log_2(s'+m)\rceil at line 1217. Since L_f is an exact public parameter (not asymptotic), the base matters.
- **zk1.tex:1401**: The eval writes accuracy with literal \epsilon, while every other occurrence in the paper is \varepsilon (directly or via the \eps macro): a different glyph for the same quantity, in the very sentence that ties it to GK's s=1/varepsilon.
- **zk1.tex:975**: Bare r is a verifier challenge in the multiset-encoding phi_cell, while r_t / r_{[i,j]} denote record ranges throughout Sections 3-4; subscripts disambiguate, but a bare r near commitments invites a misread.
- **zk1.tex:1080**: e denotes stream events e_1,e_2,... in Section 3 and GK's representative value e (with e^-, e^+, e_p batch values) in Section 5.2; similarly j is both the event/logical-time index (q_j, ver(j)) and the interval right-endpoint in Definitions 4.1-4.2.
- **zk1.tex:1081**: GK's coverage sets S_e and S^o_e reuse the letter S, whose subscripted form S_t means the sketch state everywhere else (S_0, S_t, S_{t-1}); S_e (subscript a value) vs S_t (subscript a version) are typographically indistinguishable.
- **zk1.tex:184**: The contributions bullet measures the chain-verification cost as Theta(E) over E batch proofs — the only use of E in the paper; everywhere else the number of closed batches is t (Theta(t) at lines 428-435, 1422, 1487).
- **zk1.tex:948**: O is a paper-specific variable (old counter value O, table O[i_z,b_z], primed O') in a section that also uses asymptotic big-O in adjacent paragraphs; O appears both as a table (O[i_z,b_z], line 912) and as a bare scalar (R=((i,b),O), line 948).
- **zk1.tex:1380**: M is triple-duty: cell multisets M_{t-1}, M_t in the Pattern-A recommit, the padded-union capacity M_cup = s'+m in GK, and the machine count M in the eval; subscripts mostly disambiguate, but M_{t-1}/M_t use the same version subscripts as states S_t.
- **zk1.tex:873**: Delta serves three roles: CM's net per-cell batch effect (Delta, Delta_{i,b}), GK's per-tuple rank-uncertainty fields Delta_1, Delta_2, and lowercase delta as CM's failure probability; the CM patch rows even carry Delta_{i_z,b_z} while GK tuples carry Delta_1/Delta_2 with structurally different meanings.
- **zk1.tex:1416**: The '2^{27} FRI-domain cap' that determines every infeasibility claim in the eval (and the x markers in Figure 4) appears nowhere before line 1416 and is never derived: the cost model (lines 254-268) and Appendix B's binning discussion (lines 1743-1778) discuss power-of-two domains and blowup but state no cap, so a reader cannot tell whether 2^27 is fundamental, a backend default, or the machine's memory.
- **zk1.tex:1408-1409**: The eval uses 'replay ablations' at line 1357-1358 before the Baselines paragraph defines the ablation axes (1404-1417), and it frames the one-hot encoding both as the per-record 'replay' baseline (lines 1408-1409, 1443 'one-hot replay') and as one of 'three recommit encodings of the same update relation' (line 1441-1442), whereas Section 5.1 introduced one-hot as a Step-5 recommit approach of the certified design (lines 889-891), not as a replay ablation.


## B. Gates and primitives: explanation and citations


### HIGH

### [HIGH] zk1.tex:864 — wrong-citation (CONFIRMED (adjusted))

zk1.tex cites thaler2022 (Justin Thaler's textbook "Proofs, Arguments, and Zero-Knowledge", FnT 2022) as the reference for LogUp in two places: main-body line 872 ("a LogUp lookup~\cite{thaler2022} where the backend provides one", in the Step-3 paragraph starting at line 864) and appendix line 2638 ("a LogUp lookup~\cite{thaler2022} in the Greenwald–Khanna and SpaceSaving circuits"). Thaler's book does not describe LogUp; the correct reference is Haböck, "Multivariate Lookups Based on Logarithmic Derivatives" (ePrint 2022/1530), which already exists in paperBib.bib as HabockLogUp2022 (line 272) but is cited zero times in zk1.tex. Fix: replace \cite{thaler2022} with \cite{HabockLogUp2022} at lines 872 and 2638. The third thaler2022+gabizon2020plookup citation at appendix line 2085 refers to a generic lookup argument (not LogUp) and can stay. Optionally, add one sentence in the main body explaining the LogUp mechanism (a lookup argument whose logarithmic-derivative running sum replaces a bit decomposition for range membership), since the main body names LogUp (lines 872, 993, 1374) without ever describing it.

**Suggested fix:** Replace \cite{thaler2022} with \cite{HabockLogUp2022} at line 864 (and at appendix lines 2604, 2061 where LogUp specifically is meant; keep thaler2022 only for the generic lookup-argument concept). Add one sentence saying what a LogUp lookup is (a lookup argument whose running sum of logarithmic-derivative terms replaces a bit decomposition for range membership).

### [HIGH] zk1.tex:984-985 — inconsistent-explanation (CONFIRMED (adjusted))

At zk1.tex:992-993 (main body), the Step 5 recommit says the circuit enforces the grand-product identity "with a running-product column $Z$ started at $Z_0=1$ and accepted at $Z_{\mathrm{last}}=1$ (equivalently, \sys's backend uses the same LogUp running sum as Step~3)", but Step 3 never presented a LogUp running sum: its multiset-equality argument is presented as a grand product (lines 866-871), and Step 3's only LogUp mention (line 872) is the comparator's range-check lookup, a different gadget. No "LogUp running sum" is defined anywhere in the main body ("LogUp" otherwise appears only in the bare component list at line 1374), the log-derivative equivalence between a running product and a LogUp sum is never stated, and the bib's HabockLogUp2022 entry is never cited. The back-reference is therefore unresolvable — worse, Step 4 (line 878) uses "running sum" for an ordinary additive accumulator, inviting mis-resolution. The text also omits that Z must accumulate the RATIO of the two sides' factors (requiring inverse witnesses) for both boundary conditions Z_0=1 and Z_last=1 to be meaningful. The implementation does realize both Step 3's and Step 5's multiset checks via a LogUp bus (PermuteAir in the Plonky3 circuit crate), so the fix is expository: either present Step 3's check as the LogUp fractional running sum actually used (one sentence plus the Habock citation, already in the bib) and have Step 5 reuse it, or keep both as grand products and state explicitly that the backend realizes them via LogUp's log-derivative encoding, spelling out that Z accumulates the ratio of factors.

**Suggested fix:** Either present Step 3's multiset check as it is actually implemented on Plonky3 (a LogUp fractional running sum, with one sentence and the Habock citation) and then say Step 5 reuses it, or keep both as grand products and state explicitly that the backend realizes the grand product via LogUp's log-derivative encoding, with the running-sum boundary conditions spelled out. Also state that Z accumulates the ratio of the two sides' factors.

### [HIGH] zk1.tex:1111-1113 — unexplained-mechanism (CONFIRMED (adjusted))

GK Steps 4-5 (zk1.tex:1202-1251) perform L_f fuse-and-re-sort rounds over prover-supplied tables U^(1..L_f) (witness list at 1129-1132; Step 5 at 1228-1229), each round "re-sort[ing] the survivors by (e,t)" (1204-1206, 1250-1251), but the main body never gives the mechanism binding each round's re-sorted table U^(r+1) to the previous round's post-fusion output. A re-sort of a prover-supplied table needs a per-round multiset/permutation argument (plus sortedness) to be sound; sortedness and the global Step-6 mass identity alone cannot prevent dropping, duplicating, or altering rows between rounds. This contradicts the claim at 1119-1121 that "Multiset equality is used only for conservation steps": the appendix gate catalog (2631-2636) enumerates the multiset gate as carrying only "the collision fold, the sorted union, the compaction" (no per-round re-sorts), the appendix GK correctness induction (2704-2707) just says "and re-sorts" with no binding mechanism, and the GK cost equation (2810-2815, reiterated at 2839) charges only one sortedness+multiset line, not L_f of them. Notably the paper's own replay baseline (2852-2859) does use permutation arguments for its sorted insert and re-sort, and the implementation (src/sketch/gk_final_full.rs) binds every re-sort with an explicit PermuteAir permutation argument — indeed it abandoned the L_f round schedule as "fragile for completeness" in favor of a single group-by-value pass, while src/sketch/gk_final.rs defers Step 5, so no code realizes the paper's per-round pipeline. Fix: either state that each round's re-sorted table is tied to that round's fusion output by a per-round multiset-equality argument — and correct the "only for conservation steps" sentence and add L_f multiset gates to the cost accounting — or specify a fixed oblivious re-sort mechanism (sorting network / stable-compaction gadget) and cost it; alternatively align the paper with the implemented single-pass group-by design.

**Suggested fix:** State the per-round binding explicitly: either each round's re-sorted table is tied to the round's fusion output by another multiset-equality (permutation) argument -- in which case correct the 'only for conservation steps' sentence and count L_f extra multiset gates in the cost -- or the re-sort is realized by a fixed oblivious mechanism (e.g., a sorting network or stable-compaction gadget), which should then be named and costed.


### MEDIUM

### [MEDIUM] zk1.tex:864 — incomplete-explanation (CONFIRMED)

Sort-order enforcement is invoked on tuples -- (i,b) in Count-Min Step 3 and (e,t) in GK Steps 1/2/5 -- but the comparator's bit-width and the arithmetization of the two-component lexicographic comparison are never specified in the main body. For (i,b) one can guess a packed addr=iw+b of log2(dw) bits, but that packing is only introduced later (Step 5, line 973). For GK, e ranges over 32-bit keys and the tie-breaking timestamp t grows with N (line 1177: t_p = N_{t-1}+ord_p), so the difference width and overflow/wraparound handling matter on a ~31-bit BabyBear field; neither is stated. The appendix sortedness gate (line 2604) also gives no width (the SpaceSaving appendix does, lines 2374-2375: '\lceil\log_2 c_{max}\rceil bits', but GK's does not).

**Suggested fix:** State once (e.g., in CM Step 3 or the appendix gate catalog) the comparator's operand widths: keys/values are range-checked to declared domains (32-bit keys, log2 w columns, timestamp width bounded by log2 N_max), differences are decomposed to that width, and lexicographic (x,y) order is enforced via a packed encoding or an equality-gated second comparison.

### [MEDIUM] zk1.tex:858 — unexplained-mechanism (CONFIRMED (adjusted))

The multiset-argument challenges gamma and r are called 'verifier challenge(s)' at both use sites (zk1.tex:866 for gamma in Step 3, and zk1.tex:983-984 for r,gamma in phi_cell), but the proof is non-interactive: nowhere does the paper say these are Fiat-Shamir-derived, nor that they must be derived AFTER the prover commits to the tables/trace — the soundness-critical ordering for grand-product and memory-checking arguments. The preliminaries mention Fiat-Shamir only generically (lines 212-215), never connecting it to gamma and r, and the appendix gate-correctness sketch (lines 2631-2636) likewise omits the ordering. Moreover, phi at line 866 is 'a random linear combination of its entries' with unspecified coefficients — only gamma is named there; the second challenge r first appears at line 983 for phi_cell, so the reader cannot tell whether Step 3's row-combination coefficients are challenges or fixed constants (the latter would be unsound). Suggested fix unchanged: add one sentence at first use (Step 3, line 866) stating gamma and r (with powers of r as phi's linear-combination coefficients) are Fiat-Shamir challenges derived from the transcript after the witness tables are committed.

**Suggested fix:** Add one sentence at first use (Step 3): gamma and r (powers of r as the linear-combination coefficients of phi) are Fiat-Shamir challenges derived from the transcript after the witness tables are committed, so the prover cannot choose rows as a function of them.

### [MEDIUM] zk1.tex:458 — imprecise-citation (CONFIRMED (adjusted))

At zk1.tex:466 (not 458), Nova (SettyNova2022) is cited as an instance of 'recursive proof composition', defined in the same sentence as making a new proof 'include the verification of an earlier proof as part of its own statement'. Nova is a folding scheme whose defining feature is that it avoids verifying the earlier proof in-circuit (it folds relaxed R1CS instances and defers SNARK verification to the end), so it does not fit the definition given. The paper's own composition atom performs classic in-circuit recursive verification (zk1.tex:492, 562, 1658), matching Valiant2008IVC/BCCT2013Recursive. Fix: drop SettyNova2022 from this cite or move it to a contrast clause (e.g., 'folding schemes~\cite{SettyNova2022} achieve the same effect without in-circuit verification').

**Suggested fix:** Drop SettyNova2022 from this cite or move it to a contrast clause ('folding schemes~\cite{SettyNova2022} achieve the same effect without in-circuit verification'); keep Valiant2008IVC and BCCT2013Recursive as the sources for the technique actually used.

### [MEDIUM] zk1.tex:482 — terminology-collision (CONFIRMED (adjusted))

The paper introduces its own emphasized term 'folding' at zk1.tex:490 for extending the prefix interval proof by one batch via in-circuit recursive verification — 24 lines after citing Nova (SettyNova2022) at line 466, where 'folding' is the established term for a different technique (instance folding specifically designed to avoid in-circuit verification). The overloaded word recurs throughout with no disambiguation anywhere in the paper: abstract line 95, contribution bullet line 184, related work line 199, lines 502-515, lazy finalization lines 652-656, and the evaluation's fold column at lines 1491-1532. The risk is highest in the abstract and introduction, where 'folds' appears with no mechanism attached and a recursion-literate reviewer would read it as Nova-style folding; at the line-490 introduction itself the text does immediately state the fold verifies the prior proof in-circuit. (Aggravating, beyond the original finding: lines 1232-1240 use 'folds' in yet a third sense, for SpaceSaving members merging into neighbors.) Suggested fix unchanged: rename the operation ('extension', 'absorption', 'chaining', or reuse 'composition') or add an explicit disclaimer at line 490 that this fold is in-circuit recursive verification, not a folding scheme in the Nova sense.

**Suggested fix:** Rename the operation ('extension', 'absorption', 'chaining', or reuse 'composition') or add an explicit disclaimer at line 482 that this 'fold' is in-circuit recursive verification, not a folding scheme in the Nova sense.

### [MEDIUM] zk1.tex:552-566 — incomplete-explanation (CONFIRMED (adjusted))

zk1.tex:566-574 (Definition, Composition atom, item (1)): the requirement that each child proof verify "under a verification key checked in-circuit to equal one of the deployment's declared interval-proof circuits (a leaf wrapper or the composition atom itself), fixed in the profile" is self-referential as stated — a fixed circuit that embeds its own verification key as an in-circuit constant is circular, since the key is a function of the circuit description. This is a known bootstrapping problem solved by cyclic-recursion techniques (verifier key passed as a public input and constrained, with the key reaching a fixed point, as in Plonky2's cyclic recursion or Halo), but the paper never names the mechanism or cites it: "circuit-identity binding" appears only here (lines 569-571) with no elaboration, the appendix soundness argument (Property 2, lines 1654-1669) merely restates that children are verified in-circuit, and no occurrence of "cyclic", vk-as-public-input, or fixed-point bootstrapping exists anywhere in the file. The prototype likewise does not demonstrate the self-referential check (each merge rebuilds a per-layer aggregation circuit via p3_recursion::build_and_prove_aggregation_layer). Suggested fix: one or two sentences at the definition stating how the self-referential vk equality is realized (e.g., the backend's cyclic-recursion mechanism with the vk digest as a constrained public input), with a citation (e.g., Plonky2_2022). Note: the broader complaint that the main body never explains or cites in-circuit proof verification is not accurate — Section 4.2 (lines 464-467) explains verification-as-a-circuit and cites Valiant2008IVC/BCCT2013Recursive/SettyNova2022, and the preliminaries (lines 232-241) cite Plonky2/Plonky3; only the FRI-specific verifier details are omitted, which is an abstraction choice rather than a defect.

**Suggested fix:** Add two sentences: (a) child verification means embedding the backend's FRI verifier as a subcircuit (cite Plonky2_2022/Plonky3_2024 recursion here, not only in preliminaries); (b) the self-referential vk equality is realized by the backend's cyclic-recursion mechanism (vk digest passed as a public input and constrained), with a citation.

### [MEDIUM] zk1.tex:1415-1417 — misdirected-citation (CONFIRMED (adjusted))

At zk1.tex:1423-1425 (not 1415-1417), the sentence "Configurations whose padded trace exceeds the backend's $2^{27}$ FRI-domain cap are infeasible and reported as such~\cite{ZkValue2026}" ends with a citation to ZK-Value, a zero-knowledge data-valuation system (paperBib.bib:498-504) that is not the source of the cap. The 2^27 FRI-domain limit is a property of the paper's own backend (BabyBear's two-adicity of 27 / Plonky3's maximum FRI domain), as the paper's own code comments state (src/sketch/countmin_memcheck.rs:17, src/sketch/hll_final_full.rs:105). This is also the paper's only citation of ZkValue2026, so nothing signals a "we follow their reporting convention" intent. Fix: attribute the cap to the backend (cite Plonky3_2024 or state it follows from BabyBear's two-adicity), and if ZkValue2026 is kept, rewrite as "reported as infeasible, following the convention of~\cite{ZkValue2026}".

**Suggested fix:** Attribute the 2^27 cap to the backend (cite Plonky3_2024 or state it follows from BabyBear's two-adicity), and if ZkValue2026 is kept, rewrite as 'reported as infeasible, following the convention of~\cite{ZkValue2026}'.

### [MEDIUM] zk1.tex:1181-1192 — inconsistent-explanation (CONFIRMED (adjusted))

zk1.tex Step 3 (lines 1189-1200) contains an exposition slip, not two incompatible constraint specifications. Line 1196-1197 says "each fresh value's successor e+ and predecessor e- are its adjacent active rows", which literally contradicts the definition at 1190-1191 (e-/e+ = "nearest active old neighbors") whenever fresh rows are adjacent (as with e=5,6 in the example at 1318-1328, where e=6's adjacent active rows are 5 and 7 but its e-/e+ are 3 and 7). The two descriptions are in fact extensionally equivalent — fresh tuples have g1=g2=0, so the right-to-left/left-to-right copy chain through fresh rows transparently propagates the nearest old tuple's g+Delta, exactly as implemented in src/sketch/gk_bandmerge.rs (build_bm2) — but the paper never states this g=0 chaining argument, leaving the reader to derive why the adjacent-row copy certificate enforces the declared old-neighbor rule. Fix: reword 1196-1197 to say the copy equalities run between adjacent rows and chain across consecutive fresh rows (which contribute g=0), so each fresh row's Delta1/Delta2 equal the declared combinations at its nearest old neighbors. Severity: low (clarity/exposition), not medium; the constraint system is well-defined and consistent with both the example and the code.

**Suggested fix:** Fix line 1188-1189 to 'adjacent rows after skipping fresh rows' or, better, spell out the propagation: a right-to-left running copy carries (g1+Delta1) of the nearest old tuple leftward across consecutive fresh rows (mirrored left-to-right for Delta2), one copy equality per adjacent pair, shape fixed by M_union.


### LOW (polish)

- **zk1.tex:850**: gabizon2020plookup is used loosely at two nearby sites. (a) Line 850 claims a backend 'may instead discharge each h_i as a single lookup' citing plookup, but h_i maps an arbitrary key to a column: a committed lookup table would need one row per key in the domain (2^32 for the paper's 32-bit keys), which plookup does not make practical; the claim is not supported as stated. (b) Line 858 cites plookup (alongside PLONK) as a source for the 'multiset-equality argument'; plookup is a lookup argument -- the permutation/multiset grand product used here is PLONK's copy-constraint argument.
- **zk1.tex:743**: CormodeCountMin2005 (line 743) and cormode2005improved (line 758) are two bib keys for the same paper -- Cormode & Muthukrishnan, 'An improved data stream summary: the count-min sketch and its applications', J. Algorithms 55(1):58-75, 2005 -- cited fifteen lines apart in the same subsection. The compiled reference list will contain the work twice.
- **zk1.tex:975**: Step 5 says it 'reuses Step 3's row-encoding at cell granularity', but the two encodings use gamma in different roles: Step 3's factors are (gamma - phi(row)) with gamma an external evaluation point subtracted from the encoding, while Step 5 folds gamma INTO the encoding, phi_cell = addr + r v + gamma, and multiplies the phi_cell values directly. The constructions are equivalent up to sign/renaming, but presenting the second as 'the same' encoding while silently changing gamma's role is the kind of overload a careful reviewer flags.
- **zk1.tex:1137**: The GK gatebox uses 'parity-$0$ fuse-and-resort rounds' (line 1137) before the term is defined (Step 4, lines 1196-1197: 'each a parity-$0$ round that pairs $(2i,2i{+}1)$'), and a source comment at lines 1157-1161 admits Figure 3 panel (d) is labeled 'parity-alternating' while the text specifies parity-0 rounds -- so the compiled figure and the text describe the fusion schedule with two different names.


## C. Technique correctness vs. the implementation


### HIGH

### [HIGH] zk1.tex:858-864 — paper-code-mismatch (CONFIRMED)

Step 3 claims the reordering is certified with an encoding phi() that 'compresses one such row to a single field element by a random linear combination of its entries, and a verifier challenge gamma' via a grand-product identity. The prototype does neither: rows are compressed DETERMINISTICALLY as combined*2^20 + v in a single BabyBear coordinate (SHIFT_VAL = 2^20), and the multiset equality is discharged by a PermuteAir with a prover-supplied permutation hint settled by a LogUp bus. The deterministic packing is not collision-resistant at the paper's deployed shape: with d=7, w=2^14 (line 1399), combined = i*w+b reaches 114687, so combined*2^20 ~ 2^36.8 wraps mod p (BabyBear p ~ 2^31), and the sorted-side witnesses (combined_sorted, val_sorted) are free private inputs constrained only by the mod-p packing equation - val_sorted has no range check anywhere (only the hash limbs and, in omc, the adjacent gap are bit-decomposed). Distinct (counter, value) pairs can therefore alias, undermining the 'holds with overwhelming probability only if the two tables list the same rows' soundness claim for the implemented encoding.

**Suggested fix:** Either state that the prototype packs (counter id, value) as counter*2^20+value with an assumed (currently unenforced) value bound and dw*2^20 < p, and that multiset equality is a LogUp-bus permutation argument, or change the code to range-check val_sorted < 2^20 and combined_sorted < dw (or use per-coordinate packing as Step 5 does). At the deployed d=7, w=2^14 the stated encoding premise (injective single-element compression) does not hold.

### [HIGH] zk1.tex:1400-1402 — paper-code-mismatch (CONFIRMED)

The eval claims all families run on 32-bit keys, but the GK circuit's value domain is 22 bits (top value reserved for dummies) and the harness masks GK keys to 21 bits, so GK's rank/quantile answers are over a truncated domain, not the 32-bit key space. The GK section (line 1080) never states any value-domain bound, even though the circuit's sortedness check depends on it.

**Suggested fix:** State the GK value-domain restriction (e < 2^22, keys mapped/masked to 21 bits in the eval) in the GK section or the parameter-setting paragraph, or change the eval claim to say GK runs on keys projected to its 21-bit domain.

### [HIGH] zk1.tex:467-475 — paper-code-mismatch (CONFIRMED)

The record range r_[i,j] claimed as part of every interval-proof public boundary (and r_i in the leaf boundary, line 416) is not implemented anywhere: no leaf or composed proof carries, checks, or binds a record range.

**Suggested fix:** Either implement record-range fields and the range-adjacency check in the leaf/merge circuits, or rewrite Definition 1 and atom check (2) to state what is actually bound (state-commitment adjacency only) and move record-range binding to the (unimplemented) upload-log layer as future/design work.

### [HIGH] zk1.tex:558-566 — paper-code-mismatch (CONFIRMED)

The in-circuit verification-key identity check — presented as the load-bearing soundness mechanism of the composition atom — is not implemented; no vk registry, no in-circuit vk-equality constraint, and the merge circuit is not a single fixed circuit.

**Suggested fix:** Either add the vk-binding constraint to the recursive merge (or clearly scope it to Appendix assumptions), or soften Definition 2(1) to say circuit identity is fixed by the deployment's proving pipeline and assumed by the extractor, matching what the p3-recursion aggregation actually provides.

### [HIGH] zk1.tex:697-707 — paper-code-mismatch (CONFIRMED)

Section 4.4 claims a query "costs the verifier one root check and one query check" after the prover pays nu-1 on-demand compositions, but the implementation never finalizes at query time: the verifier checks popcount(t') separate peak proofs per query, exactly as the paper's own mixed-query table (ctx = 3.2-5.0) reports — the main body and the eval/code tell contradictory stories.

**Suggested fix:** Pick one story: either implement/measure on-demand finalization per query (one root check, nu-1 merge cost charged to the prover) or rewrite 4.4 to say the verifier checks the popcount(t') live peaks (each an O(1) check), which is what the system does and what Table 'mixed' reports.

### [HIGH] zk1.tex:471-475 — paper-code-mismatch (CONFIRMED)

The ordered-batch digest H_[i,j] as described — a Merkle-style root over batches B_i..B_j binding batches, order, and record ranges, composed inside the atom — does not match any implementation: the digest is computed natively (never in-circuit), binds boundary state commitments rather than batches (batch commitments are explicitly NOT folded in), binds no record ranges, is 4 field elements not one, and is entirely absent from the engine that produced the paper's numbers.

**Suggested fix:** Align the definition with the implementation (a schedule-binding hash over per-epoch boundary digests, checked natively by replaying the canonical schedule) or implement the claimed batch-binding digest; at minimum fix "a single field element" (a single 31-bit BabyBear element would also be insecure) and note the digest is not currently proof-bound.

### [HIGH] zk1.tex:1422-1423 — paper-code-mismatch (CONFIRMED)

The paper claims 'Apache DataSketches~\cite{ApacheDataSketches} provides plaintext answers for the fidelity check', but Apache DataSketches is never used anywhere in the artifact; the fidelity check compares the ZK answer against the repo's own native Rust sketch replay.

**Suggested fix:** Either integrate DataSketches into the e2 fidelity path (or a validation script) or reword to 'the plaintext replay of the same sketch provides reference answers' (optionally noting a one-off offline cross-check against DataSketches if one was actually done).

### [HIGH] zk1.tex:1155-1166 — paper-code-mismatch (CONFIRMED (adjusted))

Figure 3 (zk1.tex:1163-1174, \label{fig:gk-pipeline}, the section's only pipeline figure) contradicts both the main text and the implementation. Its fusion panel is labeled "parity-alternating fusion under θ · Step 5" (confirmed via pdftotext of pics/zkSketch_Figure3.pdf), while the text's Step 4 (zk1.tex:1202-1206: "each a parity-0 round that pairs (2i,2i+1) and re-sorts the survivors by (e,t)") and Step 5 (1228-1229, 1250) describe a parity-0 fuse-and-resort schedule, matching the code (src/sketch/gk_bandmerge.rs fuse_round_fixed2, lines 1064-1124, pairs cur[2i]/cur[2i+1] every round; no parity-alternating fusion is implemented anywhere in src — gk_final.rs:49 mentions it only in a doc comment for an explicitly deferred step). The figure's capacity labels "U sorted union padded to s'(N_{t-1})" and "Snew … padded to s'(N_t)" imply a version-dependent capacity, whereas the text declares s' "a single constant declared per deployment" (1084-1086), says the circuit consumes the fixed public s' rather than evaluating s'(N) in-circuit (1150-1155), gives U the capacity M_∪ = s'+m rather than s'(N_{t-1}) (1182), and the code uses the fixed GkbParams.capacity (gk_bandmerge.rs:87, "fixed constant"). The authors' own LaTeX comment inside the figure environment (zk1.tex:1165-1169) concedes both labels differ from the text ("Two labels are cosmetic … No regen needed"), but the rendered PDF still shows them, so a reviewer comparing figure and text gets two different fusion schedules and two different capacity semantics for the same step. Fix: regenerate the figure with a "parity-0 fuse + re-sort" label and a single constant s' capacity label (and M_∪ = s'+m for U), or add a caption note.

**Suggested fix:** Regenerate the figure with "parity-0 fuse + resort" and a single s' capacity label (or add a caption note); a reviewer comparing figure and text gets two different fusion schedules for the same step.


### MEDIUM

### [MEDIUM] zk1.tex:836-838 — paper-code-mismatch (CONFIRMED)

The Step 1 footnote claims 'the record range $r_t$ is bound in the public upload log and composition metadata (Section 4) rather than re-checked inside the leaf'. Neither binding exists in code. The upload-log MMR stores only the ordered Com(B_t) digests plus a leaf count - no (r_t, Com(B_t)) pairs as Section 3 (line 311-312) promises. The composition metadata binds epoch indices (i, m, j) and a single u64 'descriptor' that the code itself documents as a stand-in for the upload-log slice; experiments set it to the epoch index, not a record range.

**Suggested fix:** Soften the footnote to say the prototype binds batch ORDER (epoch indices in the interval digests and the MMR); with full-capacity batches of public size m the record range is derivable from the index. Or actually append (r_t, Com(B_t)) to the MMR leaves.

### [MEDIUM] zk1.tex:864 — paper-code-mismatch (CONFIRMED)

Step 3 states the comparator/sort-order check is 'a bit decomposition in the prototype's Count-Min update leaves' (plural). Only the memory-checked (omc) leaf implements it - a gap bit-decomposition constraining combined_sorted[r] - combined_sorted[r-1] to [0, 2^ceil(log2(dw))). The one-hot leaf countmin_final.rs, one of the three measured ablations of the same pipeline, has NO sort-order constraint at all: its Stage H enforces only adjacent-equality tags (eq_tag/inv_diff). (It stays sound because duplicate segments still sum correctly through the selector, but the described check is absent.)

**Suggested fix:** Say the comparator is implemented in the memory-checked leaf (where one-entry-per-address canonicity requires it) and note the one-hot leaf omits it because its selector-sum application is order-insensitive; or add the gap check to countmin_final for uniformity.

### [MEDIUM] zk1.tex:1143-1147 — unverified-claim (CONFIRMED)

The gatebox claims s' and L_f are "validated against the public N_t as part of metadata checking", and Step 5 (lines 1240-1242) claims "the threshold and timestamps, not the prover, decide what fuses". In the implementation, theta is a raw public input with no in-circuit or verifier-side check that it equals floor(N_t/s), and I found no metadata-checking code that validates s' >= s'(N_t) or L_f anywhere in the pipeline (the only checks are a native debug_assert in apply_batch2 and a warning print in the experiment harness).

**Suggested fix:** Either implement the metadata check (verifier recomputes theta_t = floor(N_t/s) and s'(N_t) <= s' from public values before accepting) or soften the paper to say these are public-input conventions the verifier is expected to check outside the circuit, as the code comment does.

### [MEDIUM] zk1.tex:1169-1179 — paper-code-mismatch (CONFIRMED)

Step 1 says the batch opens from com(B_t) as rows B[p]=(a_p,e_p) and "match the record range r_t"; Step 2 says fresh tuples carry timestamp t_p=N_{t-1}+ord_p. In code, com(B_t) is a hash of six-field fresh tuples (e,0,0,0,0,t) with the timestamps already baked into the commitment preimage: there is no a_p flag (activity is derived from e != E_MAX), no r_t input to the leaf, and the circuit never checks t_p = N_{t-1}+ord_p — the in-circuit well-formedness checks cover only g1=g2=Delta1=Delta2=0 and the pad coefficients, so the timestamp convention is enforced solely by whoever computes com(B_t).

**Suggested fix:** State that com(B_t) commits the batch in the fresh-tuple encoding (timestamps included, per the upload-log convention) and that the record range is bound via the public (N_{t-1}, N_t) pair at the composition layer, rather than implying the leaf opens (a_p,e_p) rows and checks r_t itself.

### [MEDIUM] zk1.tex:587-589 — paper-code-mismatch (CONFIRMED)

"The parent proof publishes only the outer boundary" with interior commitments as private witness holds in no implementation that also verifies the digest: the digest-checking engine must publish all E-1 interior boundaries (O(t) public data) for the verifier's replay, while the boundary-hiding engine drops the digest and indices entirely.

**Suggested fix:** State which variant the deployed boundary is: either an O(1) in-circuit-bound (Com(S_{i-1}), Com(S_j)) pair without a digest (the measured system), or an O(t)-carried natively-replayed digest — and adjust Definition 2's privacy claim about interior commitments accordingly.

### [MEDIUM] zk1.tex:1560, 1584-1589 — unverified-claim (CONFIRMED)

Three of the four rows of Table tab:mixed (Q=10^3, 10^4, 10^6) come from CSV rows marked status=inferred that no code in the repo can produce; only the Q=10^5 row is a measured run (status=ok). The paper presents the table as a measured sweep ('Table~\ref{tab:mixed} sweeps the query rate') and claims 'Every number is reproduced by scripts...' (lines 1381-1383).

**Suggested fix:** Either measure the Q=10^3/10^4/10^6 points for real, or disclose in the text that per-query costs are measured once (fixed-shape circuits) and the remaining sweep columns are derived analytically.

### [MEDIUM] zk1.tex:1418-1420 — paper-code-mismatch (CONFIRMED)

The claim 'the Count-Min replay even exposes keys and hash positions as public inputs, a concession that only strengthens it' does not describe the benchmarked circuit: the one-hot leaf that produced cm_batch_one_hot.csv keeps keys private and exposes only commitments as public inputs.

**Suggested fix:** Delete or correct the sentence (e.g. 'all ablations keep keys private and derive hash positions in-circuit'), or actually benchmark the public-input strawman if the concession argument is wanted.

### [MEDIUM] zk1.tex:1385-1391 — paper-code-mismatch (CONFIRMED)

The testbed claim that at M=4 the pinned machines share 'no core, cache, or memory controller' is wrong for memory controllers: the box has only two NUMA nodes, so two 32-core 'machines' co-reside on each socket and share that socket's memory controllers (DRAM bandwidth contention the paper claims away).

**Suggested fix:** Weaken to 'sharing no core or L3 cache, with memory bound to the local NUMA node (two machines per socket share its memory controllers)' or run with NPS4 BIOS config to make the claim true.

### [MEDIUM] zk1.tex:1424-1425 — unverified-claim (CONFIRMED)

The 2^27 FRI-domain cap is cited to ZkValue2026 (an arXiv paper on ZK data valuation), but in the artifact the cap is a property of BabyBear's two-adicity in Plonky3, enforced only as a caught panic — nothing in the code or dependencies relates to ZK-Value.

**Suggested fix:** Cite Plonky3/BabyBear (two-adicity of the field, p = 15*2^27+1) or drop the citation; ZkValue2026 does not support this claim.

### [MEDIUM] zk1.tex:1553-1592 — underspecified (CONFIRMED)

The mixed updates-and-queries experiment (Table tab:mixed) never states its dataset; the CSVs show it ran on the synthetic Uniform stream, while the immediately preceding composition experiment (Table tab:compose-scale) used AOL — a reader will assume AOL carries over. Additionally, 'frequency-weighted probe keys' (line 1561) cannot be verified: the code's default is EXP_QUERY_KEY_MODE=first and neither the CSVs nor env.json record the mode used.

**Suggested fix:** State the dataset in the tab:mixed caption ('Uniform stream') and record EXP_QUERY_KEY_MODE in the CSV/env.json so the frequency-weighted claim is auditable.

### [MEDIUM] zk1.tex:996-997 — paper-code-mismatch (CONFIRMED (adjusted))

zk1.tex:1004-1005 and Table 2 (tab:step5-rebind, lines 1012-1025) claim the two-sided Merkle opening costs Θ(d log w) per update "regardless of the batch size m". The Merkle ablation actually benchmarked (countmin_c_merkle with compress:false, group_by:false, t_max=min(m,w) — exp_e1.rs:300-307, e6_forest.rs:152) additionally pays a one-hot routing selector sel[i][k][c] of size m·t_max·d ≈ m²·d (countmin_c_merkle.rs:346-348, 441-473), so its measured per-update cost is Θ(m·d + d·log w), growing linearly in m. results/cm_batch_merkle.csv confirms quadratic total trace growth (4x rows per doubling of m) and the too_large death at m=2^11 that the eval reports; the eval's explanation at line 1456 ("per-record authentication paths grow its per-update cost") mis-attributes this routing-driven growth and contradicts the table's flat per-update model. The O(m·d)-routing merkle_gb variant that would match Θ(d log w) exists (countmin_c_merkle.rs, exp_e1.rs:355-371) but is not the measured "merkle" ablation. The paper footnotes this exact prototype-routing caveat only for the HLL table in the appendix (lines 2034-2039), not for the main-body Count-Min table. Fix: add the routing term to the Merkle row (Θ(m d + d log w) for the measured variant), benchmark merkle_gb as the Merkle ablation, or add a footnote like the HLL one; also correct the eval's "authentication paths" attribution at line 1456.

**Suggested fix:** Either add the routing term to the Merkle row of Table 2 (Theta(m d + d log w) per update for the measured variant), or benchmark merkle_gb (the O(m d)-routing variant) as the Merkle ablation, or footnote that the table gives the hash cost only and the prototype's routing dominates.

### [MEDIUM] zk1.tex:874-876 — paper-code-mismatch (CONFIRMED (adjusted))

zk1.tex describes the two-sided Merkle recommit's capacity as the single public patch capacity T_max = md (lines 882-884) with cost 'set by the public touched-cell capacity T_max' (lines 930-933), but the implemented Merkle leaf (src/sketch/countmin_c_merkle.rs:94-95) is parameterized by an independent PER-ROW capacity t_max (1 <= t_max <= w; total op slots d*t_max), a discrepancy the paper never states. In the reported ablation (Fig. eval-batch, from the exp_e1 sweep) t_max = min(m, w) is public, so the obliviousness claim holds for every number in the paper; however, the forest harness path (src/experiments/e6_forest.rs:327-338, reachable via exp_stream/exp_e6 with EXP_CM_VARIANT=merkle) sizes t_max data-dependently to the exact realized max distinct-touched-cell count, so any future Merkle-variant forest measurement taken from that path would have a data-dependent circuit shape, contradicting the paper's public-capacity framing. No currently reported number is affected (all composition/forest results use the omc leaf per scripts/run_compose.sh and the results CSVs). Suggested fix: state that the Merkle leaf's capacity is per-row (min(m,w) in the circuit-axis sweep), and either make the e6 merkle path use the public per-row bound or document that it is measurement-only sizing that sacrifices obliviousness.

**Suggested fix:** State that the Merkle ablation's capacity is a per-row t_max (min(m,w) in the circuit-axis sweep) and, if the e6 numbers are reported, disclose that its t_max there is sized to the realized batches for measurement purposes, sacrificing the obliviousness property the deployed leaf keeps.

### [MEDIUM] zk1.tex:847-849 — paper-code-mismatch (CONFIRMED (adjusted))

zk1.tex:852-857 (Step 2, main body) claims "row $i$'s column is the low $\log_2 w$ bits of limb $i$", i.e. the circuit forces b_{p,i} = h_i(k_p). The implementing circuit (src/sketch/countmin_final.rs:580-594) derives the bucket from the low w_log2 bits of a 31-bit binary decomposition of each digest limb, but the fork's decompose_to_bits gadget (Plonky3_RangeAir circuit/src/builder/circuit_builder.rs:1264-1303) constrains the prover-supplied bits only to be boolean and to reconstruct the limb modulo p — there is no canonicity (< p) check. For BabyBear (p = 2^31 − 2^27 + 1), any limb whose canonical value is below 2^31 − p = 2^27 − 1 (≈6.7% per limb; ≈ d·6.7% per record across its d rows) admits a second valid decomposition of x + p, whose low bits select bucket b+1 mod w (p ≡ 1 mod 2^27), letting a malicious prover route that row's update to a different bucket than h_i(k) prescribes; no downstream constraint catches this. Fix: add a canonicity/less-than-p constraint on the decomposition (or a range-checked extraction), or hedge the paper text to state the low bits of a prover-chosen (non-canonical) decomposition, enforced only up to the (2^27−1)/p aliasing margin. The same uncanonical gadget is used in the v9h leaf (src/recursion/recursive/countmin_leaf_v9h.rs:593).

**Suggested fix:** Add a canonicity check (e.g. constrain the decomposition < p, or take limbs through a range-checked extraction), or hedge the paper text ('the low bits of a canonical decomposition, enforced up to the p/2^31 aliasing margin').

### [MEDIUM] zk1.tex:1089-1091 — paper-code-mismatch (CONFIRMED (adjusted))

The main invariant is written g1+Delta1 <= floor(eps*t) and g2+Delta2 <= floor(eps*t) at zk1.tex:1097-1098 and repeated at 1246-1247, but t there is neither of the paper's two declared meanings of t: it must denote the current record count, which the paper elsewhere calls N or N_t (defined line 1077). Immediately before the invariant (lines 1092-1094) the paper defines t as the per-tuple insertion timestamp "(a tuple field, not the version index t in S_t,B_t)", making the invariant's t a third, undeclared overload. Under the tuple-timestamp reading, the claim at 1245-1247 that a fusion never breaks the invariant would be false: the fusion gate (lines 1236, 1242) tests sums against theta_t = floor(N_t/s) = floor(eps*N_t), which generally exceeds floor(eps*t_tuple) since the survivor is the older tuple with timestamp <= N_t. The code enforces the N_t semantics (src/sketch/gk_bandmerge.rs:1156 theta = n_t/s with n_t the cumulative count; constraints at 2295/2301; doc comment lines 24-28). Suggested fix: write the invariant as g1+Delta1 <= floor(eps*N_t) (or floor(eps*N)) at lines 1098 and 1247, reserving t for the tuple timestamp and version index as already declared.

**Suggested fix:** Write the invariant as g1+Delta1 <= floor(eps*N_t) (or floor(eps*N)) at lines 1090 and 1239, reserving t for the tuple timestamp and version index as already declared.

### [MEDIUM] zk1.tex:482-488 — paper-code-mismatch (CONFIRMED (adjusted))

§4.2's fold paragraph (zk1.tex:490-496) describes chain extension as a fused fold — "a single circuit verifies Π_[1,t-1] in-circuit and certifies the new transition S_{t-1}→S_t via the per-batch update relation ... the batch is folded in directly, never proved standalone first" (zk1.tex:492-495) — but every implemented chain proves each batch standalone as a leaf and then merges it with the same composition atom the forest uses: CountMinChainStateV9::extend merges the chain root with a pre-proved leaf (src/recursion/recursive/countmin_chain_v9.rs:64-109; countmin_chain.rs and hll_chain.rs are identical in structure); prove_chain_over folds pre-proved exposed leaves (src/recursion/recursive/expose_forest.rs:397-407); src/recursion/chain.rs:31-33 leaves the fused extend as todo!(); and the measured chain mode proves each leaf standalone before folding (src/experiments/dist_compose.rs:525), its module doc conceding "the paper's deployed fused fold is cheaper per step but equally sequential" (dist_compose.rs:46-50), i.e. the fused fold is not deployed. The eval's chain cost model (zk1.tex:1500-1505: chain prove time within 0.3% of the one-machine forest "as both run the same 63 sequential folds") matches the merge-based code, not §4.2's construction, so §4.2 and the eval are inconsistent with each other. Fix: describe the implemented chain (leaf proof + merge per batch) or explicitly present the fused fold as an optimization not used in the prototype.

**Suggested fix:** Describe the implemented chain (leaf proof + merge per batch) or explicitly present the fused fold as an optimization not used in the prototype; as written, 4.2's construction and the eval's chain cost model are inconsistent with each other.

### [MEDIUM] zk1.tex:643-648 — unverified-claim (CONFIRMED (adjusted))

Corrected location: zk1.tex:651-656 ("finalizes lazily ... only on query") and zk1.tex:711-715 ("finalization reads a frozen snapshot of the nu surviving peaks at version t ... later inserts may extend the forest concurrently"). The lazy on-query finalization with frozen-snapshot/concurrent-insert semantics is not implemented in the proof engine: the real recursive provers (prove_countmin_forest_v9 at src/recursion/recursive/countmin_forest_v9.rs:299-303 and prove_forest_over at src/recursion/recursive/expose_forest.rs:381-386) run the peak-chaining finalize loop eagerly and unconditionally at the end of a one-shot prove over a fixed leaf slice; no API retains proof-peaks across queries, no query triggers finalization (the mixed-workload experiment in stream_compose.rs folds the forest once at the end and charges queries popcount(t') separate peak verifications instead, per aggregate_queries at stream_compose.rs:526-541), and no code path supports inserts concurrent with finalization. Only the digest-level simulation StreamingForest::finalize(&self) (src/recursion/framework.rs:330-339) is read-only/on-demand, and it composes native digests, not proofs. Suggested fix unchanged: scope the frozen-snapshot/concurrency claim as a design property of the schedule (peaks are immutable once formed) rather than an implemented mechanism, or add an on-demand finalize API to the recursive forest.

**Suggested fix:** Scope the frozen-snapshot/concurrency claim as a design property of the schedule (peaks are immutable once formed) rather than an implemented mechanism, or add the on-demand finalize API to the recursive forest.

### [MEDIUM] zk1.tex:636-640 — unverified-claim (CONFIRMED (adjusted))

The verifier-side "log follower" the paper claims — maintaining the forest's peak digests from the public append-only log at O(1) amortized native hashes per closed batch and deriving the boundary pub_[1,t] (and H_[1,t]) at query time (zk1.tex:644-648; also zk1.tex:511-515, "the verifier maintains it from the public append-only log rather than being handed it") — has no counterpart in the code. All implemented verifiers take the replay inputs from the proof object itself: verify_forest_countmin_v9 and verify_chain_countmin_v9 recompute the digest from boundary vectors carried inside the proof struct (countmin_forest_v9.rs:339-376, countmin_merge_v9.rs:182-223), and the experiment verifier path (verify_bound_proof/read_exposed_boundary in expose_forest.rs) checks the proof against its own exposed public values. framework.rs's StreamingForest performs exactly the native-hash peak-digest folding described but is used only prover-side in experiments. Note: the MMR in src/recursion/mmr.rs is not dead code — examples/exp_inputfold.rs exercises it — but it is a standalone inclusion-proof upload log deliberately decoupled from the proof, not the claimed log follower. The Implementation paragraph (zk1.tex:1372-1383) does not disclose this gap.

**Suggested fix:** Either implement a minimal log-follower (framework.rs's StreamingForest over EpochLeaf digests is close) and wire it into the verification path, or present the log follower as the intended deployment interface and say the prototype hands the verifier the replay inputs with the proof.

### [MEDIUM] zk1.tex:1570-1573 — paper-code-mismatch (CONFIRMED (adjusted))

The paper's HLL decode cap (zk1.tex:1571-1573, "caps b<=8 in the prototype") matches the code (src/decode/hyperloglog.rs:103 asserts b in [2,8]; prove_hll_decode_omc validates since its first commit), and the paper correctly omits HLL from the mixed sweep — no number in Table tab:mixed depends on HLL. However, all four results/s3_mixed_q*.csv artifacts contain an HLL b14 row with populated query timings that no version of the code could ever have produced (the b<=8 assert predates both prove_hll_decode_omc and the mixed-sweep machinery). Three rows carry status=inferred — a status token emitted nowhere in the codebase, indicating out-of-band synthesis — and all four share the identical query_prove_ms_avg=2424.987, yet the s3_mixed_q100000.csv row is marked status=ok with n_queries=10, falsely presenting synthesized numbers as a measured run. Rerunning would not crash the sweep (default EXP_HLL_B=4 passes validation, and with EXP_HLL_B=14 the panic is caught by the runner's catch_unwind guards, recording status=error), so the paper's cm/ss/gk numbers remain reproducible; the issue is confined to the artifact: drop the HLL query rows from the s3_mixed CSVs or mark the q100000 one inferred/error and document how the inferred rows were derived.

**Suggested fix:** Regenerate the mixed CSVs excluding HLL (EXP_COMPOSE_FAMILY=cm,ss,gk) or make stream_compose skip HLL queries when b>8; drop or explain the b14 HLL query rows in results/.


### LOW (polish)

- **zk1.tex:974-987**: Step 5's realization says a cell is compressed 'to a single field element by a random linear combination of its address and value, phi_cell = addr + r v + gamma' and that the prototype 'packs each (addr,v) with a real/dummy tag into one field element'. In BabyBear (~31 bits) one base element cannot hold addr+value+tag; the code actually packs (addr, v, 1, 0) as the four basis coefficients of ONE degree-4 extension (Challenge) element, with no r or gamma in the leaf - the randomization happens only in the backend PermuteBus/LogUp fingerprint over those coordinates, and there is no in-leaf running-product column Z (the parenthetical at 984-985 partially hedges this). A reviewer reconciling 'one field element' with a 31-bit field will be confused.
- **zk1.tex:1012**: Table 2's one-hot row gives Theta(dw) per update, matching the textbook row-wise scan of lines 889-894, but the measured one-hot ablation is the prototype's FLAT variant that the paper itself (895-897) prices at Theta(md*dw) selector witnesses per batch, i.e. Theta(d*dw) = Theta(d^2 w) per update - a factor-d discrepancy within two adjacent paragraphs, and the table keeps d explicit in the other rows so 'd constant' cannot excuse it.
- **zk1.tex:941-943**: 'This is the recommit \sys runs by default; it keeps the Merkle opening only for the very-sparse corner ($m\ll w/\log w$)' suggests an automatic policy/crossover rule. No such dispatch exists: the CM leaf variant is selected manually per experiment (EXP_CM_VARIANT env token, defaulting to one_hot in the E1 sweep driver), and only the composition/stream experiments hardwire the omc (memory-checked) leaf. 'Default' is a per-experiment choice, not a system rule keyed on m vs w/log w.
- **zk1.tex:848-849**: Step 2 claims 'wider profiles hash again' for d > 8. The code explicitly does not implement multi-invocation hashing: all Count-Min leaves assert 1 <= d <= 8 and the canonical file states additional sponge invocations are 'not implemented here'. The capability is asserted as if available.
- **zk1.tex:1076-1078**: The paper presents the declared capacity as "(the provable worst-case size s'(N)=ceil(2s ln(N/s+2)+2) ..., a single constant declared per deployment)", suggesting s' is set by that formula. The deployment inverts the coupling differently: the eval fixes s'=2048 and derives the accuracy s = floor(cap/(2*ceil(log2 N))) (a conservative log2-based inversion, giving s=51 at N=2^20), so the declared s' (2048) is well above s'(N) (~1015) rather than equal to it. Step 6 (lines 1249-1250) correctly requires only s' >= s'(N), but the line-1077 parenthetical reads as equality.
- **zk1.tex:1255**: The GK section cites "(obliviousness, Property~4; ...)" by number, but the numbered statement "Property 4 (zero knowledge and circuit obliviousness)" appears only in the appendix; the main body (lines 372-375) names the four properties in prose without numbering them. The same numbered reference also appears earlier at line 730.
- **zk1.tex:1221-1222**: Step 5 asserts strict value order within a fused pair, "(so $e_i<e_{i+1}$)", but adjacent active pairs can have e_i = e_{i+1} exactly in the duplicate-value case the paper itself supports two paragraphs earlier (Step 2's (e,t) tie-breaker "even when batch values duplicate an existing e"). The code sorts by (e,t) and fuses equal-value adjacent pairs like any other pair.
- **zk1.tex:1086-1089**: The rank bound is described as "the interval the query circuit reports", but the implemented query circuit computes the interval [r_min, r_max] internally and releases the midpoint floor((r_min+r_max)/2) as the answer (under the release policy), not the interval itself. The interval formula itself matches the code exactly.
- **zk1.tex:583-585**: The "declared digest-composition rule" is left abstract although the code fixes a concrete, security-relevant choice: one Poseidon2 width-16 permutation over ('MRGE' tag, i, m, j, H_left, H_right) with 4-element (~124-bit) digests, making the digest schedule-shape-dependent (chain and tree digests over the same history differ).
- **zk1.tex:646-648**: The balanced-tree finalization bracketing offered as a declarable alternative (folding independent peaks in ceil(log2 nu) depth) is not implemented; every finalize path is hard-coded left-to-right, and there is no profile/declaration mechanism for bracketing.
- **zk1.tex:1545-1551**: A TODO comment block sits in the middle of the evaluation: the dataset-sensitivity sentence for Table tab:compose-scale is unwritten and its supporting experiment (frame_out_4machine_datasets.csv, uniform/gaussian/netflix forest M=4) is still running.
- **zk1.tex:1515-1521**: The stream-scaling paragraph claims prove time is 'linear in $t$, as every leaf and fold is fixed-shape', but GK's derived accuracy parameter s drifts across the N sweep (s=64 at 2^16, 56 at 2^18, 51 at 2^20), so the GK leaves are not strictly fixed-shape/iso-accuracy across the sweep; the scripts themselves warn about this drift.
- **zk1.tex:1401-1404**: 'on inputs identical to S$^3$' overstates: the code reproduces S^3's dataset suite (same distributions, parameters, clamps, keying) but with deterministic seeded generators, and notes S^3's own generators are nondeterministic run-to-run — so the concrete key streams are distribution-identical reproductions, not identical inputs.
- **zk1.tex:1372-1378**: The setup says the companion Plonky2 crate 're-implements the Pattern-A circuits and the aggregation layer', but the crate actually implements all four families (Pattern A and B), the decode circuits, and the distributed compose engine — the text is a stale understatement that a reviewer cross-checking the artifact would flag as inconsistent.
- **zk1.tex:1426-1430**: The Metrics paragraph promises 'peak prover memory' as one of the four reported metrics, but no memory number appears anywhere in the evaluation's main body (the CSVs do record peak_rss_mb, e.g. 144.4 GB for CM one-hot m=16 vs 2.7 GB memory-checked — a strong unreported result).


## D. Readability for database reviewers


### HIGH

### [HIGH] zk1.tex:97 — garbled-sentence (CONFIRMED)

The abstract's cost claim 'constant per-update cost ... for three common families except Greenwald--Khanna' is self-contradictory on first read: the paper has four families, and 'three families except GK' makes the reader ask whether GK is one of the three. The identical phrase recurs in the contribution bullet.

**Suggested fix:** Rewrite both occurrences as: 'this yields constant per-update cost, independent of stream length, for three of the four families; Greenwald--Khanna retains a residual logarithmic factor from its fusion rounds.'

### [HIGH] zk1.tex:99-103 — garbled-sentence (CONFIRMED)

The abstract's final sentence stacks three appositives ('..., for Greenwald--Khanna, whose declared capacity itself grows..., up to that single logarithmic factor') so that on first read the cost shapes appear to hold only for GK, and 'up to that single logarithmic factor' floats with no clear anchor.

**Suggested fix:** Split into two sentences: 'The experiments exhibit the predicted cost shapes: history-independent per-batch proving cost, constant-time audits, and per-batch cost governed by the declared sketch capacity rather than the stream length. The one exception is Greenwald--Khanna, whose declared capacity itself grows logarithmically with the stream; its costs match the prediction up to that single logarithmic factor.'

### [HIGH] zk1.tex:1556-1557 — internal-inconsistency (CONFIRMED)

The evaluation reports 3--5 root checks per query (popcount(t')), but Section 4.4 (lines 699-701) and the workflow (line 325) promise the verifier exactly one root check after finalization. A reviewer cannot tell whether finalization is implemented, whether the prototype verifies peaks instead of a single root, or whether query verification is actually O(1) vs O(log t).

**Suggested fix:** State explicitly in Section 7.3 that the prototype verifies the nu surviving peaks directly instead of running lazy finalization (or run finalization), and reconcile with Section 4.4: e.g. 'the prototype skips on-demand finalization and has the verifier check the popcount(t') peak proofs directly; with finalization this would be one root check as in Section 4.4.' Also rename or gloss the cryptic 'ctx' column header.

### [HIGH] zk1.tex:1069-1075 — garbled-sentence (CONFIRMED)

The sentence introducing the bounded-GK variant is a 60-word chain of two colons and undefined coinages: 'Khanna--Greenwald sketch' (a name that exists nowhere else), 'paired band-merge' ('band' is never defined anywhere in the main body, yet 'band-merge GK' reappears as the circuit's name in the evaluation at line 1465), 'genuine distinct-value fusion', and a scare-quoted 'hard case' that is never described. A DB reviewer who knows GK cannot reconstruct what the mirror actually is from this.

**Suggested fix:** Rewrite in two plain sentences: (1) the variant keeps, for each tuple, rank mass on both sides (g1 from the standard GK direction, g2 from a mirrored GK run over the reversed order); (2) one sentence saying concretely what the 'hard case' of one-directional GK is (adversarial insertion orders that block compaction) and that the two-sided fusion removes it, citing gribelyuk2024simple. Either define 'band-merge' or drop the term here and at line 1465 in favor of 'two-sided fusion'.

### [HIGH] zk1.tex:1372-1373 — missing-definition (CONFIRMED)

'Trace blinding' is used exactly once, undefined, to disclose that the prototype does not actually achieve zero-knowledge (blinding off, commitments not hiding). A DB reviewer will not know what the toggle is, and the consequence — the headline privacy property is neither implemented nor measured, so its cost is unknown — is left implicit in a parenthetical.

**Suggested fix:** Add one line defining trace blinding (randomizing the committed execution trace so the proof leaks nothing about witness values) and state the implication plainly: 'the prototype therefore measures integrity and obliviousness but not the zero-knowledge overhead; enabling blinding adds <X%/is a constant-factor cost in Plonky3'. Cite where the toggle lives.


### MEDIUM

### [MEDIUM] zk1.tex:559-566 — zk-jargon (CONFIRMED)

Definition 2's clause (1) hinges on 'a verification key checked in-circuit to equal one of the deployment's declared interval-proof circuits' — but 'verification key' is never introduced, and a DB reader does not know that a verification key is a short public digest that identifies which circuit a proof attests to. The italicized clause is the soundness-critical part of the definition, and it is unreadable without that fact. 'Leaf wrapper' in the same clause (line 562) is also used before the leaf-lifting is described at line 605.

**Suggested fix:** Before Definition 2 (around line 550), add one sentence: 'Each circuit has a short public verification key that identifies it; verifying a proof means checking it against a key, so pinning the key pins which relation was proved.' Then clause (1) reads correctly, and briefly gloss 'leaf wrapper (the circuit that lifts a transition proof to a size-one interval proof, Definition 1)'.

### [MEDIUM] zk1.tex:325 — internal-inconsistency (CONFIRMED)

The 'audit' verifier mode is defined as 'checking the maintenance history over a window of batches', but the verification material described immediately after is the single history ROOT proof, which certifies the whole prefix — how a verifier audits an arbitrary window in a constant number of checks is never explained, and 'audit' never reappears until the abstract's claim of 'constant-time audits' (line 100), which itself sits in tension with the cold-auditor caveat at line 184 (a one-time log replay that is linear in the log).

**Suggested fix:** Either drop 'window of batches' (audit = check the current root, i.e., the whole prefix) or explain that a window audit checks the O(log) peak/interval proofs covering that window. Also qualify the abstract's 'constant-time audits' as 'constant-time for a log-following verifier' to match line 184.

### [MEDIUM] zk1.tex:184 — zk-jargon (CONFIRMED)

The very first contribution bullet leans on two verifier roles introduced nowhere before — 'log-following verifier' and 'cold auditor' — and on a one-off variable E for the batch count that the rest of the paper calls t. The mechanics that make the distinction meaningful (the verifier maintaining peak digests from the public log, lines 637-640) arrive four sections later.

**Suggested fix:** Gloss inline ('a verifier that has been following the public upload log' / 'a verifier starting from scratch') and replace E with t for consistency with Sections 3-4, or with 'the number of closed batches' in words.

### [MEDIUM] zk1.tex:1416-1417 — zk-jargon (CONFIRMED)

The feasibility cliff that structures the whole evaluation — 'the backend's $2^{27}$ FRI-domain cap' — is never explained. A DB reviewer does not know what an FRI domain is, why it caps trace height at 2^27, or why exceeding it makes a configuration 'infeasible' rather than merely slow; yet every 'x dies at m=...' claim (lines 1447-1449, 1459) and every x-mark in Figure 4 rests on it.

**Suggested fix:** Add one clause at first mention: 'the FRI prover evaluates the trace over a domain whose size the backend's field caps at $2^{27}$ rows, so any circuit whose padded row count exceeds this cannot be proved at all on this backend'; tie it back to the gate-row/binning cost model of Section 2.1.

### [MEDIUM] zk1.tex:93 — garbled-sentence (CONFIRMED)

The abstract's second sentence says 'Zero-knowledge proofs (ZKPs) address this by allowing...', but the first sentence states only that organizations release aggregate statistics — no problem or tension has been posed yet for ZKPs to 'address'. The verifiability-vs-privacy tension the paper actually targets is left for the reader to infer.

**Suggested fix:** Insert the tension before 'address this': e.g. 'Recipients want assurance that each released statistic was computed faithfully, yet the underlying records must stay hidden. Zero-knowledge proofs (ZKPs) reconcile the two by ...'.

### [MEDIUM] zk1.tex:372-375 — garbled-sentence (CONFIRMED (adjusted))

zk1.tex lines 376-379 (not 372-375): the sentence "We make these precise as four properties, update, history, and query-prefix soundness together with zero knowledge and circuit obliviousness, and prove them in Appendix~\ref{sec:framework-properties}..." announces four properties but names five things; that zero knowledge and circuit obliviousness form a single property (Property 4) is made explicit only in the appendix at line 1691 (not 1677). The main body compounds the confusion: lines 738 and 1263 refer to "the obliviousness of Property~4" without mentioning zero knowledge, and lines 710/738/1263 use Property numbers (3, 4) that the main body never assigns. Suggested fix stands: rewrite with explicit grouping, e.g. "four properties -- (1) update soundness, (2) history soundness, (3) query-prefix soundness, and (4) zero knowledge with circuit obliviousness -- and prove them in Appendix~\ref{sec:framework-properties}", which also grounds the later Property~3/Property~4 references.

**Suggested fix:** Rewrite with explicit grouping: 'We make these precise as four properties -- (1) update soundness, (2) history soundness, (3) query-prefix soundness, and (4) zero knowledge with circuit obliviousness -- and prove them in Appendix A.' This also fixes the dangling Property-number references.

### [MEDIUM] zk1.tex:878-943 — signposting (CONFIRMED (adjusted))

zk1.tex Step 5 (lines 886-951, main body): the Step-5 preamble (886-895) states the two recommit obligations but does not enumerate up front that three encodings follow or name the deployed one; the reader must bridge the intro's terminology ("read/write multiset check", lines 170-174, and "multiset-checked patch", abstract line 95) to Section 5's "Approach 3: Set-based memory checking" unaided. Severity low (signposting polish): Approach 1 is already marked as the textbook strawman at its opening (897-898) and Approach 2's supersession is announced at its end (935-936), so the reader is not blind, but a one-sentence roadmap after line 895 would still help — e.g. "We develop three encodings of this check — a one-hot scan, a two-sided Merkle opening, and set-based memory checking (the intro's multiset-checked patch) — of which \sys deploys the third by default, retaining the second for very sparse batches; Section 7 measures all three." Any such sentence must not call Approach 2 a mere ablation, since it remains the deployed recommit for the m << w/log w corner (949-951).

**Suggested fix:** After line 887 ('...the recommitment of the untouched complement.'), add one signpost sentence: 'We develop three encodings of this check -- a one-hot scan, a two-sided Merkle opening, and set-based memory checking -- of which the third is the one zkSketch deploys (the first two survive as ablation baselines in Section 7).'

### [MEDIUM] zk1.tex:832-840 — overlong-footnote (CONFIRMED (adjusted))

zk1.tex:840-848 (footnote attached to the final sentence of Step 1): a single nine-source-line footnote — one sentence with two semicolons and a nested parenthetical — packs three prototype deviations plus a forward contrast with SpaceSaving: (1) the Count-Min leaf runs at full capacity m with zero-mass padding; (2) consequently the active-flag column and dummy-ordering constraints are elided and sorted counter-update rows carry only ((i,b_{p,i}),v_p); and (3) the record range r_t is bound in the public upload log and composition metadata rather than re-checked inside the leaf. Deviations (1)-(2) are causally linked, but (3) is independent, and the footnote is the sole disclosure of a material spec/prototype gap: the Step-1 body (lines 837-840) states the circuit verifies rows match r_t with inactive rows canonical dummies, while the prototype leaf (src/recursion/recursive/countmin_leaf_v9h.rs) implements neither check — confirmed against the code (ss_final.rs implements active flags; the Count-Min leaf does not). Suggested fix: keep one short footnote for the active-flag elision (zero-mass dummies are additive identities for Count-Min; SpaceSaving's are not, see Appendix ref), and move the r_t-binding remark into body text where r_t binding is discussed (e.g., near the upload-log definition at lines 315-316 or the merge-circuit discussion at line 1178).

**Suggested fix:** Split: keep one short footnote here ('the prototype elides the active-flag machinery because Count-Min's zero-mass dummies are additive identities; see Appendix X'), and move the record-range-binding remark to Step 1's body or Section 4 where r_t binding is discussed.

### [MEDIUM] zk1.tex:235-237 — zk-jargon (CONFIRMED (adjusted))

At zk1.tex line 239 (not 235-237), two ZK terms of art are dropped without intuition in the paragraph meant to orient a non-ZK reader: "transparency" (the paper's own gloss, "no trusted setup," appears only in the appendix at lines 1758-1760 and 2784, never in the main body) and "PLONKish constraint system" (no gloss in any main-body occurrence). Suggested fix: add two short parentheticals at line 239 — "transparency (no trusted-setup ceremony)" and "a PLONKish constraint system (a table of gates with wiring constraints between rows)". No change is needed for "AIR" (line 239 expands the acronym and line 268 already gives the table-with-height intuition the cost model uses) or for "plausible post-quantum security" (self-explanatory).

**Suggested fix:** Add three parentheticals: 'transparency (no trusted setup ceremony)'; 'a PLONKish constraint system (a table of gates with wiring constraints between rows)'; 'an AIR (the whole computation laid out as a table whose adjacent rows must satisfy fixed transition polynomials)'. One clause each preserves depth while making the cost model at lines 254-268 land.

### [MEDIUM] zk1.tex:858 — zk-jargon (CONFIRMED (adjusted))

Step 3 (zk1.tex:866, not 858) invokes 'a verifier challenge $\gamma$' and the Step 5 realization (zk1.tex:984, not 975) invokes 'verifier challenges $r,\gamma$' inside a system the paper insists is non-interactive; the mechanism by which a non-interactive proof obtains random challenges (Fiat--Shamir, mentioned once at lines 213-214 without saying what it does) is never connected anywhere in the main body. A careful DB reader will ask who issues gamma and why the prover cannot pick it -- and the soundness claim at line 872 ('holds with overwhelming probability only if the two tables list the same rows') silently depends on gamma being fixed only after both tables are committed. Suggested fix: at line 214 add one line ('Fiat--Shamir derives the verifier's random challenges by hashing the transcript, so the prover cannot choose them'); at line 866 gloss gamma as 'derived by Fiat--Shamir after the tables are committed, so the prover cannot tailor rows to it'.

**Suggested fix:** At line 214 add the one-line mechanism: 'Fiat--Shamir derives the verifier's random challenges by hashing the transcript, so the prover cannot choose them.' At line 858, gloss: 'a verifier challenge $\gamma$ (derived by Fiat--Shamir after the tables are committed, so the prover cannot tailor rows to it)'.

### [MEDIUM] zk1.tex:864 — zk-jargon (CONFIRMED (adjusted))

'LogUp' appears three times in the main body (zk1.tex lines 872, 993, 1374 — not 864/985/1366; the auditor's numbers are off by 8; a fourth occurrence is at appendix line 2638) with no gloss, and the citation is wrong: line 872's 'a LogUp lookup~\cite{thaler2022}' points to Thaler's general textbook while the actual LogUp paper (HabockLogUp2022, paperBib.bib line 272) is never cited. Additionally, line 993's parenthetical '(equivalently, \sys's backend uses the same LogUp running sum as Step~3)' has no referent: Step 3 presented the multiset check as a grand-product identity, and LogUp appeared there only as a range-check option. The underlying fact is true in the code (countmin_leaf_v3.rs enforces multiset equality via a LogUp bus), so the fix is to gloss LogUp at first use, cite HabockLogUp2022, and state at line 993 that the backend realizes the grand-product multiset identity as an equivalent LogUp running sum rather than the running-product column Z shown.

**Suggested fix:** Gloss LogUp on first use ('LogUp, a lookup argument that replaces the grand product with an equivalent sum of logarithmic derivatives') and cite HabockLogUp2022. At line 985 say explicitly that the backend realizes the multiset check as a LogUp running sum rather than the running product Z shown, and that the two are equivalent encodings of the same identity.

### [MEDIUM] zk1.tex:458 — missing-intuition (CONFIRMED (adjusted))

At zk1.tex:466, recursive composition is introduced (verifier-as-circuit) with no feasibility intuition, and at line 651 the claim "a composition is far cheaper than a per-batch proof" is asserted without support until the eval (Section 7.2, Table 2: 103-144 s for 63 folds vs ~28-155 s per leaf). The main body DOES state the composition atom is a fixed recursive-verification circuit whose cost is independent of the history its children certify (lines 550-552, 562), so the fear of history-growing composition cost is dispelled; what is missing is the causal link from succinct (polylog, line 263) verification to why that fixed verifier circuit is SMALL — i.e., why proving "I verified a proof" is far cheaper than the original proof rather than merely constant. Adding one sentence near line 466 (or at line 550) deriving the atom's small fixed size from verifier succinctness, optionally with the ~1.7 s-per-fold vs 30-110 s-per-leaf numbers, would close the gap. Severity: low-to-medium (missing why, not missing what).

**Suggested fix:** Extend line 458 by one sentence: 'Because verification is succinct (Section 2.1's polylogarithmic verifier), this verifier circuit has a small size fixed by the proof system alone, independent of the statement the verified proof certifies -- which is what makes each composition a constant-cost step (about 1.7 s per fold vs 30-110 s per leaf in our prototype, Section 7.2).'

### [MEDIUM] zk1.tex:482-498 — terminology-drift (CONFIRMED (adjusted))

'Fold' carries three meanings in the main body: (a) chain/forest proof composition ('The chain builds the prefix proof by \emph{folding}', line 490; 'the forest's $t{-}1=63$ folds (the fold column)', lines 1491-1492; Table 2's 'fold' column, lines 1527, 1532-1535; also abstract line 95 and intro line 184); (b) GK tuple fusion ('the younger $e_i$ folds right into $e_{i+1}$', lines 1232-1240) — used interchangeably with 'fuse/fusion' for the same operation within the same Step 5 paragraph (header at line 1228 says 'fusion rounds'); and (c) a collision with the literature term 'folding schemes': the paper cites Nova (SettyNova2022, whose title is 'Recursive Zero-Knowledge Arguments from Folding Schemes') at line 466, 24 lines before introducing its own 'folding', with no disambiguation anywhere in the paper. Note that lines 492-494 do explicitly define the paper's fold as in-circuit verification of the previous proof, so the mechanism itself is unambiguous — the Nova collision creates reviewer friction rather than technical ambiguity. Suggested fix stands: reserve 'compose/composition' for proof composition (matching the defined term 'composition atom', lines 560-562), rename the eval column, use 'fuse/merge' exclusively for GK tuples, and add a brief note near line 466 distinguishing full recursive verification from Nova-style accumulation folding.

**Suggested fix:** Reserve 'compose/composition' for proof composition (matching 'composition atom'), rename the eval column 'compositions', use 'fuse/merge' exclusively for GK tuples (Step 5 already says 'fusion'), and add a footnote at line 458 noting that this is full recursive verification, not the accumulation-style 'folding' of Nova, to prevent the literature collision.

### [MEDIUM] zk1.tex:445 — terminology-drift (CONFIRMED (adjusted))

The three composition methods lack one consistent collective name across the reader-visible main body: the contribution bullet (line 187) and the entire evaluation (lines 1366, 1372-1373, 1486, 1490, 1494, 1502, and Table 2's caption at 1528) call them "composition schedules"; Section 4's intro (line 407) calls them a "strategy" and a "method" and Section 4.1 (line 421) a "strategy"; Figure 1's caption (line 453) presents chain and forest as "two topologies". Section 4 additionally uses "schedule" in a different generic sense - the order proofs are generated in (lines 517, 533, 548) - so the evaluation's "the three composition schedules" is a collective term the reader never saw defined and whose key word was already used to mean something else. (The commented-out table caption at line 661 and the internal labels sec:topology/sec:rq-topology do not render and are not part of the drift.) Fix: pick one collective term, introduce it in the contribution bullet and Section 4's intro, use it in the Figure 1 caption and Section 7, and reserve "topology"/"schedule-as-ordering" for describing the shape/ordering of an individual strategy.

**Suggested fix:** Pick one term ('composition strategies' or 'composition schedules') and use it in the contribution bullet, Section 4's intro, Figure 1's caption, and Section 7; 'topology' can survive only as the shape of one strategy (chain vs tree), stated once.

### [MEDIUM] zk1.tex:930 — terminology-drift (CONFIRMED (adjusted))

Terminology drift is confirmed for Pattern A and partially for Pattern B, at corrected locations. Pattern A: the deployed recommit is 'Approach 3: Set-based memory checking' at zk1.tex:938, 'Set-based' in Table 1 (line 1022), but 'memory-checked' throughout the eval (Figure 4 caption line 1436; lines 1453, 1458) — the eval never says 'set-based' and the design/Table 1 never say 'memory-checked', so Figure 4's legend name has no matching row in Table 1; the appendix's consistent 'memory-checked recommit' makes Table 1's label the outlier. Pattern B: the eval's 'certified' does bind verbatim to Table 3's 'Certified pipeline' row (lines 1285/1292, inside the Section 5 GK walk), but the design narrative upstream uses four unfixed phrasings for the same artifact — 'deterministic replacement' (lines 95, 175-176), 'bounded-capacity replacement' (1086), 'whole-summary replacement' (1117), 'whole-state replacement' (1258) — before 'Certified pipeline' appears, and the eval adds the further variant 'certified band-merge GK' (line 1473). Fix one name per artifact at first definition and repeat it verbatim in Table 1, Table 3, Figure 4, and the eval prose.

**Suggested fix:** Fix one name per artifact at first definition and repeat it verbatim in tables and eval: e.g. 'memory-checked recommit' for Approach 3 (align line 930 and Table 1's row label), and 'certified replacement' for Pattern B (align lines 175, 1078, 1109, Table 3, and line 1465).

### [MEDIUM] zk1.tex:1090-1091 — notation-overload (CONFIRMED (adjusted))

At zk1.tex:1097-1098 (main GK invariant, "The summary keeps the main invariant $g_1+\Delta_1\le\lfloor\varepsilon t\rfloor$ and $g_2+\Delta_2\le\lfloor\varepsilon t\rfloor$") and again at 1246-1247, the symbol t denotes the current population count — a third meaning of t, introduced immediately after lines 1092-1094 explicitly disambiguate t as "a tuple field, not the version index $t$ in $S_t,B_t$". Everywhere else the population is written N or N_t (e.g., line 1091 "$\sum(g_1{+}g_2{+}1)=N$", line 1099 "additive $\varepsilon N=N/s$", line 1203 "$\theta_t=\lfloor N_t/s\rfloor$"), and no definition of t as a running count exists in the main body or preamble. The invariant's t cannot be read as the tuple timestamp (old tuples' rank mass grows via merges checked against the current threshold θ_t=⌊εN_t⌋, not their frozen insertion time) nor as the version index. Fix: write the invariant as $g_1+\Delta_1\le\lfloor\varepsilon N\rfloor$ (or, at 1246-1247, $\le\theta_t=\lfloor N_t/s\rfloor$ to match the fusion test it is claimed to be preserved by), at both occurrences.

**Suggested fix:** Write the invariant with N: '$g_1+\Delta_1\le\lfloor\varepsilon N\rfloor$' (or $\lfloor N/s\rfloor$ to match theta), at both occurrences, reserving t for versions and the tuple timestamp already disclaimed.

### [MEDIUM] zk1.tex:1548-1559 — missing-definition (CONFIRMED (adjusted))

Section 7.4 "Mixed updates and queries" (zk1.tex:1553-1573) opens with two genuinely undefined coinages. (1) Line 1556 invokes "the operation-stream model of \S\ref{sec:query-boundaries}", but that reference resolves to §5.4 "Answering Queries During Streaming" (lines 698-723), which never names or defines any stream model; "operation-stream" occurs nowhere else in the paper. The interleaved record/query stream model is actually defined in §4.1 "System Model" (lines 292-300) under the name "event stream". The reference should point at §4.1's event-stream model (or the term should be introduced there). (2) Line 1561's "frequency-weighted probe keys" is the only occurrence of "probe" or "frequency-weighted" in the paper; how query keys are drawn is specified only in code (src/experiments/stream_compose.rs:266-330: keys sampled from the observed stream proportional to frequency). Add half a sentence defining it — note this is a reproducibility gap, not a cost bias, since the decode circuits are fixed-shape and oblivious. The original finding's third item ("freshness premium", line 1566) is not a real defect: the term is introduced with \emph at first use and immediately defined by the following colon clause, with the metric made precise in the Table caption at line 1579.

**Suggested fix:** Point the model reference at Section 3.1's event stream (or add the term there); add half a sentence defining probe keys ('query keys drawn proportional to their stream frequency, so hot keys are probed more often'); introduce the premium explicitly ('the \emph{freshness premium} -- the extra update-side proving caused by early-sealed, padded batches').


### LOW (polish)

- **zk1.tex:1364-1367**: The implementation paragraph opens with an ungloss ed proper-noun parade — 'Plonky3 (BabyBear, FRI, Poseidon2, LogUp)' and 'Plonky2 (Goldilocks, Poseidon, FRI)' — where BabyBear/Goldilocks (fields) are never identified as fields, and 'prove real, self-verifying proofs' uses 'self-verifying' with no definition (presumably: the recursion circuit verifies the backend's own proofs, i.e., end-to-end real recursion rather than mocked verification).
- **zk1.tex:1204-1218**: The L_f soundness/completeness lever discussion is a 15-line digression embedded in Step 4, before the fusion rule itself (Step 5) is presented; it forward-references 'Steps 5-6 still force sortedness, conservation, and the thresholded fusion rule' that the reader has not seen, and restates the conservative default L_f twice (lines 1199 and 1217).
- **zk1.tex:255-257**: The cost unit 'gate rows' quietly conflates two backend notions — PLONKish gates/rows and AIR table rows — and the defining parenthetical equates it to 'constraint count', while the same sentence then says 'summing the cost of every gate it instantiates' without saying that a gate occupies rows. A DB reader can follow the arithmetic but has no picture of what one row physically is.
- **zk1.tex:895-899**: Inside the Approach-1 strawman, the aside 'Our prototype's flat variant goes further still' describes the prototype implementing an even MORE expensive one-hot encoding — before the reader has been told that one-hot exists only as an ablation baseline (revealed at line 1408). On first read it suggests the prototype deploys the worst design.
- **zk1.tex:311-313**: The materialized-view analogy at line 732 works well, but comparable one-clause DB anchors are missing at the two other places a SIGMOD reader would grab them: the append-only upload log (a write-ahead/audit log, lines 311-313) and the streaming forest's carry-cascade of perfect trees (structurally the Merkle-mountain-range construction used by certificate-transparency logs and akin to LSM-style merging, lines 600-615 — only the binary-counter analogy is given).


## Refuted (checked, not problems)

- **zk1.tex:379-387** (notation-prelim): The Protection Scope paragraph announces four out-of-scope concerns but enumerates only three: (i) input authenticity, (ii) output leakage, (iii) real-time freshness. There is no (iv).… — refuted: The Protection Scope paragraph in zk1.tex (lines 381-395, main body) does enumerate all four announced concerns. The sentence "four orthogonal concerns lie outside its scope" (lines 383-384) is followed by (i) Input authenticity (line 384), (ii) Output leakage (line 387), (iii) Real-time freshness (…
- **zk1.tex:352-362** (notation-prelim): The appendix's query-prefix soundness argument relies on "the bulletin-board assumption of Section~\ref{sec:trust-model}" (line 1672-1673: "a prover cannot re-bind $j$ to a different prefix without fo… — refuted: The finding's central claim is contradicted by the current file. Section 4.2 (\subsection{Threat Model and Security Properties}, \label{sec:trust-model}, lines 354-401 — main body) explicitly states the assumption in its "Protection scope" paragraph, item (iv) at lines 392-395: "Log availability: th…
- **zk1.tex:1423-1425** (code-eval): The paper attributes every infeasible sweep point to 'the backend's $2^{27}$ FRI-domain cap' (also fig. caption line 1437 and 'm>=32 is infeasible outright' at 1453-1454), but in the code 'too_large' … — refuted: The auditor's arithmetic is real (bench_guarded does record any caught panic as too_large; CM m=32 does trip COUNTMIN_MAX_SEL_CELLS = 25,690,112 > 16M; HLL b=14 m=128 does pass HLL_FULL_MAX_SEL_CELLS), but the conclusion — that the recorded deaths are attributable to tunable RAM guards rather than t…
- **zk1.tex:702** (db-clarity): The main body cites 'Property~3' (line 702) and 'Property~4' (lines 730, 1255) by number, but the numbered Properties 1-4 are stated only in Appendix A (lines 1633, 1646, 1663, 1677). The main body ne… — refuted: The surface facts check out (main body cites Property~3 at line 710 and Property~4 at lines 738/1263, while the numbered formal statements live only in Appendix A at lines 1641-1691; auditor's line numbers are shifted by ~8), but the claimed defect — that "the references dangle for a main-body-only …