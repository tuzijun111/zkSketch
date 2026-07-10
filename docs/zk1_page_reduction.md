# zk1.tex: cutting the main body to 12 pages

Target: main body (everything before `\bibliography` / `\appendix`) at **12 pages**; references and appendix excluded and the appendix may grow.

**Where we are.** The July 6 build (`paper/zkSketch.pdf`) has References starting on page 23, so the main body is ~22 pages. Roughly **10 pages must go**. Character-count analysis of the current source confirms it: ~15.8 pages of prose + ~2.8 pages of floats + display-math/gatebox overhead. This is a restructuring job, not a tightening job: whole examples, rejected alternatives, and step-by-step expositions move to the appendix; the body keeps definitions, contracts (gateboxes), and headline results.

**How this list was produced.** Seven parallel audits (one per section plus one cross-cutting), followed by adversarial verification of the twelve largest cuts (every one survived, several with required fixes listed below), and a completeness pass that found double-counted overlaps and untargeted blocks. Savings estimates are calibrated to acmart sigconf geometry (~110 text lines/page; measured PDF dimensions for figures). All `\ref`/notation dependencies quoted below were grep-verified against the current source.

**The arithmetic.** Deduplicated, the verified Tier 1 moves give ~3.0 pages, the Tier 2 condensations ~5.0 pages, and the Tier 3 structural demotions ~1.5 pages: ~9.5 pages of identified savings, with float-reflow slack (removing three of four full-width floats frees stranded whitespace) covering the remainder. If the compiled result lands short, Tier 3's GK demotion is the lever with the most headroom.

Line numbers refer to the file as of 2026-07-10 and will drift as cuts are applied; each item carries a text anchor.

---

## Tier 1 — big rocks, adversarially verified (~3.0 pages)

Execute these first, in this order (later items' line numbers shift less).

### T1.1 Move the GK worked example + Figure 3 to the appendix (0.70 p) — VERIFIED

- **What:** the `\begin{example}[Bounded-GK batch update]` block (lines ~1274–1330, "Figure traces this instance across the aligned tables") **and** the full-width `fig:gk-pipeline` figure* (lines ~1127–1139). They are mutually dependent (the caption says "Running example"; the example narrates panels b–e), so move them **jointly** into a new appendix section, e.g. `\section{Worked Example: Bounded-GK Batch Update}\label{app:gk-example}`, placed next to Circuit Correctness and Obliviousness (`app:per-family-correctness`).
- **Verified safe:** the example has no `\label` and no inbound refs; `fig:gk-pipeline` is referenced only at 1125, 1221, and inside the example; panel labels (b)–(e) appear nowhere else.
- **Required fixes:** (1) rewrite the example's deictic opener to stand alone, e.g. "The following instance is the one drawn in Figure~\ref{fig:gk-pipeline}."; (2) retarget line 1125 and the parenthetical at 1221 to "Appendix~\ref{app:gk-example}"; (3) keep the `NOTE(art)` comment block (1129–1133) with the figure.
- Savings: example ~0.45 p + figure ~0.25 p (the figure is wide and short: 1624×419 pt, ~0.24 p rendered).

### T1.2 Move the CM worked example + Figure 2 to the appendix (0.70 p) — VERIFIED

- **What:** `Example ex:cm-rebind` (lines ~1003–1036, "We trace the recommit on row 0") and the full-width `fig:cm-pipeline` figure* (lines ~799–806), into the same appendix area as T1.1 (a "Count-Min Running Example" block inside or beside `app:per-family-correctness`).
- **Verified safe:** `ex:cm-rebind` has exactly one inbound ref (line 948); `fig:cm-pipeline` has four ref sites (796, 830, 948-indirect, 1005), all fixable with one-line edits; no main-body notation or value depends on the figure.
- **Required fixes:** (1) line 796: retarget to "Appendix … walks a six-record instance through all five steps."; (2) line 830: delete the parenthetical "(12 rows for the six-record instance in Figure 2)"; (3) line 948: "Example~\ref{ex:cm-rebind} (Appendix~\ref{...}) traces both cheats on a concrete instance."; (4) example numbering is automatic (`\newtheorem{example}{Example}[section]`), nothing else to fix.
- Savings: figure ~0.45 p (959×569 pt, tall) + example ~0.25 p.

### T1.3 Merge subsections 5.1 + 5.2 into one "From chains to a forest" (0.35 p) — VERIFIED

- **What:** lines ~404–509. Keep: the `pub_i` display, a 3-line Θ(t)-verifier argument, a condensed recursion idea (2 sentences carrying the Valiant/BCCT cites), and **Definition 1 (interval proof) intact**. Delete: the itemized verifier accounting (423–430), the worked 4-batch chain evolution and its displayed Π arrows (490–498), the "cheaper per-step variant" aside (485–488), and the closing paragraphs (500–509).
- **Verified safe:** zero refs to `sec:per-batch-proof` / `sec:recursive-composition`; `def:interval-proof` is kept (needed at line 603 and by Appendix A).
- **Required fixes:** (1) `fig:topologies` sits inside this range and is referenced from 5.3 — the figure block **must survive the merge**; attach "(Figure~\ref{fig:topologies}a)" to the condensed chain sentence since the only panel-(a) ref (490) is deleted; (2) keep the italicized names *per-batch proof chain* and *recursive linear chain* and the term *folding* — the evaluation (1396, 1467–1483) and Appendix A (1657) use them as vocabulary; (3) keep one sentence of leaf-then-compose mechanics (the eval's "both run the same 63 sequential folds" presupposes it); (4) keep one sentence of the verifier-interface point (verifier maintains `pub` from the public log) — line 623 refers back to it.

### T1.4 Condense the intro's solution preview into the contribution bullets (0.30 p) — VERIFIED (sound as proposed)

- **What:** lines ~145–189. The forest and certificate mechanisms are each explained four times before Section 5 (abstract, preview paragraphs, bullets, home sections). Keep the bullets as the single intro home; shrink the two preview paragraph pairs to 3–4 lines each; delete the Roadmap paragraph (188–189).
- **Verified safe:** no `\label` in the range, no inbound refs; the appendix's `\ref{sec:intro}` (line 1788) concerns the record count N, which stays defined earlier in the intro.
- **Required fix:** the condensed text must keep the "we answer this question affirmatively by presenting \sys" lead-in, or the central-question block above it dangles rhetorically.

### T1.5 Condense CM Approaches 1–2 to short paragraphs, mechanics to appendix (0.40 p) — VERIFIED

- **What:** lines ~867–906 ("Approach 1: One-hot state scan…" through Approach 2's crossover paragraph) plus the `t_max`/routing-selector caveat at line ~978. Replace with 3–4 sentences naming each encoding, its Θ cost, and the w/log w crossover; move the two-sided-Merkle opening mechanics to an "Alternative Step-5 recommit encodings" block in `app:per-family-correctness` (near the memory-checked recommit gate, ~line 2721).
- **Verified safe:** no `\label` in the range, no inbound refs; all main-body uses are name/cost-level and already served by Table `tab:step5-rebind`.
- **Required fixes:** (1) the condensed text must retain the exact ablation names one-hot / two-sided Merkle / memory-checked, the costs Θ(dw) and Θ(d log w), and the w/log w crossover — the eval reads them by name; (2) **critical:** after moving the line-978 caveat, add a pointer near `tab:step5-rebind` such as "the measured Merkle leaf adds a per-record routing-selector overhead (Appendix~…)", otherwise the table's batch-independent Θ(d log w) row visibly contradicts the eval figure's growing-with-m curve; (3) rework the "Approach 3" header (line ~908) since headers 1/2 disappear, e.g. "Our recommit: set-based memory checking"; keep 908–921 verbatim, it is the deployed design; (4) keep the Merkle1987 cite.

### T1.6 Move Evaluation 7.4's table to the appendix, keep headline paragraph (0.30 p) — VERIFIED

- **What:** lines ~1540–1586. Keep `\subsection{Mixed updates and queries}` + `\label{sec:rq-mixed}` (referenced from line 689 and the appendix) with a ~10-line paragraph quoting one concrete row (e.g. Q=10⁴: 1.64× update inflation, ≤15% premium at Q≥m, flat 0.36–2.42 s prove / 17–21 ms verify). Move Table `tab:mixed` to `app:eval-details`, placed before the "Per-family query costs" paragraph (~line 3128) so that paragraph's back-reference reads correctly.
- **Required fixes:** (1) change line 1549's ref to "Table~\ref{tab:mixed} (Appendix~\ref{app:eval-details})"; (2) the retained paragraph should avoid the symbol t' or gloss it in one clause; its formal definition travels with the table caption.

### T1.7 Move Definition 2 (composition atom) to Appendix A (0.27 p)

- **What:** lines ~552–587, the formal enumerate of the composition atom plus the trailing prototype-digest-engine paragraph. The informal intro at 542–550 already states all three checks and becomes the main-text description.
- **Why safe:** `def:composition-atom` is `\ref`'d at 566 (inside the box), 1655, 1668, 1723 — all Appendix A, so the move makes those refs intra-appendix. Main-text mentions (604–605, 621) are prose-only.
- **Bonus:** item (1)'s circuit-identity sentences duplicate Appendix A's dedicated paragraph (1667–1681); deduplicate on arrival.

---

## Tier 2 — section-by-section condensation (~5.0 pages)

### Introduction and Related Work (~0.7 p)

| id | target | action | est |
|---|---|---|---|
| INTRO-1 | abstract (92–99): drop the "One recipe spans four sketch families through two forms…" sentence (its coined names appear nowhere else); compress the two-fronts exposition; GK residual-log sentence to a clause | condense to ~180 words | 0.15 |
| INTRO-3 | Challenge 1/2 paragraphs (130–142): each to ~60 words keeping the bolded name + one cost sentence; fold the `\begin{quote}` central question into prose (the quote env alone costs ~7 rendered lines) | condense | 0.15 |
| INTRO-4 | exact-frequency worked example (116–118): one ~90-word paragraph ending at "prohibitively expensive"; N must survive (appendix line 1788 references it) | condense | 0.12 |
| INTRO-5 | "sketches are the standard remedy" (122–125): ~80 words; keep the four sketch citations, first appearance | condense | 0.10 |
| INTRO-6 | intro ZKP primer (112): two sentences naming prover/verifier; full primer lives in 3.1 | condense | 0.08 |
| INTRO-7 | Related Work: drop the "first system" sentence (repeats bullet 1); compress the S³ comparison; keep all citations and the `\ref{sec:scope-and-cost}` pointer | condense | 0.10 |
| INTRO-9 | opening motivation paragraph: trim the advertising-reach example | condense | 0.04 |

### Preliminaries and System Overview (~0.8 p)

| id | target | action | est |
|---|---|---|---|
| P1 | ZKP background (208–225): one ~60-word paragraph; **keep label `sec:zkp`** (six appendix refs) and the words completeness, knowledge soundness, zero-knowledge, Fiat–Shamir | condense | 0.15 |
| P2 | zkSNARK/zkSTARK tutorial (228–231): two sentences; keep PLONKish, AIR, FRI named | condense | 0.05 |
| P3 | commitments (234–246): keep `com(x)=hash(x,ρ)` + binding/hiding + Poseidon instantiation verbatim (lines 817, 1688 depend on them); cut the explanatory sentences | condense | 0.05 |
| P4 | cost model (248–262): three sentences + pointer; the power-of-two binning paragraph is a near line-for-line duplicate of `app:cost-derivations`; keep label `sec:cost-metric` | condense | 0.11 |
| P5 | merge Workflow + Problem Statement (302–337) into one ~180-word paragraph. **Fix required:** the upload log ULog is defined only at 306–307 and used at 467, 574, 1695, 1729 — relocate its one-sentence definition into the Batches paragraph. The profile definition is load-bearing (622, 825, 1116, 1176, 1735) and stays | merge | 0.23 |
| P6 | roles paragraph (273–280): trim verifier-instantiation list | condense | 0.04 |
| P7 | merge threat model + property statements (347–370) into ~140 words; T1/T2/T3 tags are never referenced elsewhere. **Bonus fix:** line 1699 invokes a "bulletin-board assumption of Section sec:trust-model" that the section never states — add the half-clause "public logs are append-only", repairing a pre-existing dangling reference for free. Keep labels `sec:trust-model`, `sec:problem` | merge | 0.10 |
| P8 | protection scope (372–381): ~55 words; the DP sentence + label `sec:scope-and-cost` must survive (Related Work cites it) | condense | 0.03 |
| P9 | streaming model (282–299): drop the query-parameter examples sentence and the strict-ordering parenthetical; keep N(j), ver(j), ℓ_t, m, UpdateBatch, padding-to-m | condense | 0.05 |

### Section 5, composition (~0.5 p beyond Tier 1)

| id | target | action | est |
|---|---|---|---|
| S5-4 | Figure 1: after T1.3 removes the only panel-(a) citation, either stack panels at column width (~0.2 p) or keep only the forest panel (b) (~0.3 p). Requires caption rewrite; test t=11 legibility at column width | shrink float | 0.20 |
| S5-7 | cascade-cost + finalization paragraphs (614–629): three sentences (O(log t) peaks, O(1) amortized, ν−1 on-demand compositions, pointers to Appendices A and B); both appendices already carry the details | condense | 0.10 |
| S5-8 | worked 4-batch parallel schedule (534–540): one sentence anchored to Figure 1b. The key-observation paragraph (524–532) is the section's central insight — do not cut | condense | 0.10 |
| S5-6/XC9 | 5.4 queries: compress the finalized path to ~90 words; delete the Guarantees `\paragraph` (699–702, restates 4.2 nearly verbatim); keep `sec:query-boundaries` label, the ν-peak-check sentence (Table 4's ctx column depends on it), and the three appendix pointers | condense | 0.12 |
| S5-9 | commented-out asymptotics table (631–652) + blank-line run: source hygiene, zero typeset impact | delete | 0.00 |
| critic | 5.3 opening (520–533): make the sequential-state/parallel-proofs observation once in 4–5 lines | condense | 0.10 |
| critic | forest cascade mechanics (597–617): binary-counter arithmetic and the t=11 walk-through can compress toward Appendix B; keep ~6 lines defining peak, cascade, ν (used at 620–625, 684–689; Figure 1b depicts t=11) | condense/move | 0.15 |

### Section 6, Count-Min (~0.95 p beyond Tier 1)

| id | target | action | est |
|---|---|---|---|
| cm-step3 | Step 3 (834–845): three sentences; the grand-product display and LogUp/Fiat–Shamir tutorial are cited standard machinery, re-proven in the appendix. **Keep φ and γ definitions** (reused at 951–954 and disambiguated at appendix 2358) | condense | 0.20 |
| cm-designidea | two cancellation bullets + no-cheating paragraph (931–948): two sentences + appendix pointer; duplicated by the memory-checked recommit gate (2721–2727) and the moved example | condense | 0.20 |
| cm-realization | Realization (950–975): keep `φ_cell = addr + αv + γ` with the Fiat–Shamir clause, the Δ companion gate, and the Θ(dw) claim; cut the second grand-product display (structurally identical to Step 3's) and the prototype packing sentence (fold into `app:constraint-budget` where c_fp is defined). **Opportunistic fix:** appendix line 1982 references "the recommit challenge r of Section pattern-A" which no longer exists — fix while touching this | condense | 0.20 |
| cm-tension | CM cost/obliviousness tension (749–762): two sentences instantiating the section intro's bound as Θ(mdw); keep Θ(mdw) explicit (appendix 2907 cites it) | condense | 0.15 |
| cm-background | CM accuracy/independence facts (738–747): one sentence with the two cites + `app:cm-decode` pointer | condense | 0.10 |
| cm-step1 | Step 1 (810–819): four clauses; keep the a_p active-flag and canonical-dummy definitions (first circuit-side use, consumed by every later step) | condense | 0.10 |
| critic | Section 6 intro (711–719): state the Θ(m·\|S\|) tension once here so both per-family restatements shrink harder; keep "verification over computation", "batch-effect certificate", and the Pattern A/B split sentence | condense | 0.15 |
| critic | Step-5 preamble + gatebox boilerplate (856–865, 766–780, 827–832): keep obligations (i)/(ii) stated once — they are referenced by name at 887, 897, 917 | condense | 0.10 |

### Section 6, Greenwald–Khanna (~0.65 p beyond Tier 1)

The subsection intro (1045–1088) was already rewritten this week; remaining cuts target the steps.

| id | target | action | est |
|---|---|---|---|
| gk-table-move | Table `tab:gk-update` (1255–1267): both closed forms already appear verbatim in the prose at 1247–1249, and three of its four refs live in `app:constraint-budget` — move it there, next to `tab:amortized-update` | move | 0.15 |
| gk-lf-lever | L_f lever discussion (1182–1196): two sentences. **Must keep one sentence naming L_f a completeness lever** — appendix line 3001 says "as Section~\ref{sec:pattern-B} notes, this is a completeness lever" and would dangle | condense | 0.12 |
| gk-gatebox | gatebox verification target (1103–1119): reduce to three prose lines (union conservation, L_f thresholded rounds, compaction); the two displayed multiset equations restate Steps 2 and 6. **Keep the Step-2 equation in Step 2's prose** — the example (moving to appendix) cites it | condense | 0.10 |
| gk-step6 | obliviousness recap + profile boilerplate (1230–1240): one sentence; keep the "unlike Count-Min" contrast clause | condense | 0.07 |
| gk-replay | replay paragraph (1242–1253): ~5 lines; keep the appendix pointer and (post-move) the forward ref to `tab:gk-update` | condense | 0.06 |
| gk-step5-invariant | invariant-preservation analysis (1215–1221): keep only "the threshold and timestamps, not the prover, decide what fuses; each round re-sorts by (e,t)". FuseTuple and both displayed inequalities stay (appendix references them by name) | condense | 0.05 |
| gk-step3-telescope | telescoping justification (1166–1170): one clause; keep the missing-neighbor Δ=0 convention | condense | 0.04 |
| gk-tp-dedup | t_p convention stated in both Step 1 and Step 2: state once, in Step 2 | merge | 0.04 |

### Evaluation (~0.9 p beyond Tier 1)

| id | target | action | est |
|---|---|---|---|
| EV5 | Pattern A per-family walk (1425–1450): one paragraph keeping headline numbers (3.5/1.7 ms per update; 13.7×/16.5×; SS flat 8.7 s); the figure shows every curve | condense | 0.17 |
| EV9 | chain-vs-forest prose (1467–1491): keep every headline number (2.3–8.7% fold overhead, 86–101×, ~90×, 3.5× at 88% efficiency) and the chain's one-machine-floor sentence ("both run the same 63 sequential folds"); cut mechanism restatements and compress communication accounting to one sentence | condense | 0.13 |
| EV1 | Implementation paragraph (1344–1358): delete the FRI security sentence (duplicated verbatim at appendix 1807–1810); keep the one-clause zk-scope caveat or the eval overclaims zero-knowledge | condense | 0.12 |
| EV2 | multi-machine methodology (1360–1371): 2–3 line summary (EPYC 9555, numactl-pinned 32-core process per machine, socket transfers, 200 Mb/s model); move mechanics to `app:eval-details`. Keep label `sec:setup` (ref at 1464) | move | 0.12 |
| EV7 | dataset sensitivity (1506–1516): one sentence + table pointer; causal analysis to the appendix paragraph that already exists for it | move | 0.10 |
| EV6 | stream scaling (1493–1504): 3–4 lines; the appendix carries the full argument twice already | condense | 0.09 |
| EV10 | merge Datasets + Parameter Setting into one paragraph; every deployed value stays; keep "inputs identical to S³" and keep the GK 21-bit masking as a footnote (silently dropping it hides an eval limitation) | merge | 0.06 |
| EV3 | baselines (1387–1401): cut the two-adicity aside to "exceed the backend's 2^27 FRI-domain cap"; the exact term must survive (figure caption references it) | condense | 0.05 |
| EV4 | Metrics paragraph (1403–1406): fold one clause into the Section 7 intro | merge | 0.04 |

---

## Tier 3 — gap closers if compilation still lands over 12 (~1.5 p)

Ordered by preference; take from the top until the page count fits.

1. **Demote GK Steps 1–6 to the appendix (+0.4 p incremental).** Keep in body: the (already shortened) preamble, the gatebox, a one-paragraph six-step outline, and the cost paragraph. Move the step-by-step prose with the neighbor-init display and both fusion inequalities into a "Bounded-GK Update Circuit in Full" appendix beside the moved Figure 3 and example (T1.1), making that appendix self-contained. Keep label `sec:pattern-B` on the surviving subsection (refs at 337, 1850, 2756). This is the single biggest remaining lever; the cost is that Pattern B is no longer fully specified in the body, so take it only if needed.
2. **Move CM Approaches 1–2 wholesale instead of condensing (+0.2 p over T1.5).** Keep ~5 body lines naming both + Table `tab:step5-rebind`.
3. **Fold Related Work into the Introduction (+0.1 p over INTRO-7).** Delete the section heading; the intro already cites vSQL/ZKSQL/PoneglyphDB, halving the static-SQL paragraph by deduplication. `\ref{sec:related}` appears only in the roadmap, which Tier 1 deletes.
4. **Move subsection 5.4 wholesale (+0.13 p over S5-6),** leaving a 5-line paragraph at the end of 5.3. Its two inbound refs (1544, 1555) are inside the 7.4 block that T1.6 moves, so they become appendix-internal.
5. **Push remaining FRI/security parameters and the communication arithmetic to appendix/footnotes (+0.15 p).** Keep one defining sentence for the 2^27 cap in Setup so the figure's infeasibility marks stay explained.

---

## Do-not-cut list (grep-verified load-bearing)

- **Definition 1 (interval proof)** with the displayed `pub_[i,j]` tuple and the ordered-batch digest H: consumed at line 603 and throughout Appendix A.
- **`s'(N) = ⌈2s ln(N/s+2)+2⌉`** in the GK intro: Section 4.1 (line 337) promises it is "defined in Section~\ref{sec:pattern-B}".
- **The profile definition** (declared sketch, update rule, query, capacities): used at 622, 825, 1116, 1176, 1735.
- **ULog** (upload log): if P5 merges its paragraph away, its definition must relocate, not vanish (used at 467, 574, 1695, 1729).
- **Labels with inbound refs:** `sec:zkp`, `sec:cost-metric`, `sec:trust-model`, `sec:problem`, `sec:scope-and-cost`, `sec:batches`, `sec:system`, `sec:topology`, `sec:query-boundaries`, `sec:rq-mixed`, `sec:pattern-B`, `sec:setup`, `def:interval-proof`.
- **Established vocabulary the eval reads by name:** per-batch proof chain, recursive linear chain, fold, one-hot / two-sided Merkle / memory-checked, ν peak checks, L_f completeness lever.
- **The two gateboxes** (CM and GK contracts) stay in the body: they are the specification the correctness appendix discharges.
- **The key-observation paragraph** (524–532, state computation is sequential but the proof schedule is not): the section's central insight.
- **Both symbol definitions φ, γ (Step 3)** and **α (Step 5)**: appendix disambiguation notes reference them by name.

## Execution notes

- Apply Tier 1 in the listed order, recompile, measure; then Tier 2 section by section; take Tier 3 only as needed.
- After each move, run a dangling-ref check: `grep -n "??" build.log` (or `latexmk` warnings for undefined references), plus `grep` the moved labels.
- The float budget after Tier 1: the body keeps Figure 1 (possibly single-column, S5-4), the eval batch-size figure, `tab:step5-rebind`, `tab:compose-scale`, and the amortized-cost table. Everything else lands in the appendix.
- Known stale pre-existing refs to fix opportunistically while editing: appendix line 1982 ("recommit challenge r of Section pattern-A" — no such challenge exists) and line 1699's bulletin-board assumption (repaired by P7).
