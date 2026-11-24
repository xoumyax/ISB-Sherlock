# W1 and W3 plan decisions (brownie)

Recorded as brownie answers each open question in `W1.md` §8 and `W3.md` §8. The
plans are updated to match once every question is answered.

| # | Plan | Question | Decision | Date |
|---|---|---|---|---|
| 1 | W1 | Which clustering gates the family recount | TLSH ≤30, full graph, `tlsh` basis. The confirmed and induced variants are reported alongside | 24 Nov 2026 |
| 2 | W1 | sdhash threshold S: precision target, global or per graph | Target precision 0.95 (a lower bound, because Tier X aliases read as false links); one global S. 21 is the placeholder until calibration runs | 24 Nov 2026 |
| 3 | W1 | The 85 oversized, uninventoried files | Singletons now (reason `oversized_uninventoried`); computing their TLSH is a separate later sbatch job, not on W1's path | 24 Nov 2026 |
| 4 | W1 | Archives (500 malware) in scope? | Own `archive` graph, reported as a finding only; outside the recount and the gate. Members are clustered as ordinary rows | 24 Nov 2026 |
| 5 | W3 | Date precedence when sources disagree | Tier X: MalwareBazaar `first_seen_utc` (one source for all of Tier X). MOTIF dates kept as evidence with a disagreement flag, and used as the date only for non-Tier-X MOTIF rows | 24 Nov 2026 |
| 6 | W3 | The 77,441 malware rows with no source date | Excluded from drift windows and gen/held persistence ordering, flagged `undated`; still usable where no date is needed (FP background, promiscuity). No inherited cluster dates | 24 Nov 2026 |
| 7 | W3 | How E7 measures FP drift (almost no dated goodware in 2020–2026) | Decide when E7 is designed. Recorded gap; the options on file are a fixed G_eval scored per window, dated goodware via W5–W7, and Authenticode countersignature times (with chain checks). W3 records the goodware dates it can, as planned | 24 Nov 2026 |
| 8a | W3 | Windows 8 constant release date (2,867 files, build 6.2.9200) | General availability, 26 Oct 2012 | 24 Nov 2026 |
| 8b | W3 | 12 goodware hashes found in MalwareBazaar's malware dump | Sent to pool review; kept out of G_stats and G_eval until decided | 24 Nov 2026 |
| 8c | W3 | Partial 2026Q4 (34 samples, 11 families) | Merged into 2026Q3, labelled `2026Q3+` | 24 Nov 2026 |
| 8d | W3 | 24 Tier X rows of kind `other` | Excluded from the windows (executables only, matching W1); listed separately | 24 Nov 2026 |
| 8e | W3 | 160 winget goodware files with no date | Left undated (no date in the data; a lookup would be network and collection-time, H6). Revisit with W7 | 24 Nov 2026 |
| 8f | W1, W3 | When enrichment tables may enter the working DB | Only after brownie approves a run's outputs. A separate, tested, idempotent loader writes them to a fresh copy of `manifest.sqlite` (run_id recorded), which brownie swaps in. Until then, files only under `enrich/<W>/<run_id>/` | 24 Nov 2026 |

Settled without a question: W1's README line for `docs/plans/` was added on 23 Nov.
On the schedule slip (corrected 24 Nov: the first wording claimed the conflict list
needs no sdhash, but the list is built from sdhash-confirmed clusters): W1 ships a
**provisional** W2 conflict list from TLSH-30 clusters right after the TLSH stage,
marked provisional, so W2 can start. The **confirmed** list (confirmed, unflagged
T=30 clusters) replaces it when sdhash finishes. The recount gate is TLSH-only and
doesn't wait on sdhash.
