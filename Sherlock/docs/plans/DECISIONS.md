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

## Collection (COLLECT.md), prefix C

Scope questions put to brownie before the plan was drafted (collection session,
24 Nov 2026).

| # | Plan | Question | Decision | Date |
|---|---|---|---|---|
| C1 | COLLECT | Order of work | Goodware (W5–W7) first. The malware collector is built and tested offline; its run waits for W1's recount and a list of families below ten independent samples | 24 Nov 2026 |
| C2 | COLLECT | What "Linux files" means | PE and .NET files shipped in Linux packages (W6) join the Windows pools. ELF goodware stays a separate pool outside the paper's denominators (A8 still open) | 24 Nov 2026 |
| C3 | COLLECT | Freeze | 13 Dec, fallback 20 Dec. Anything feeding `G_stats` or family membership lands before the freeze; after it only new-vendor `G_eval`/`G_ood` goodware and labels grow | 24 Nov 2026 |
| C4 | COLLECT | A1 download cap | Approved: about 100 GiB, budgeted per source, re-budgeted after the first 10% of each pull. To carry to the dashboard | 24 Nov 2026 |
| C5 | COLLECT | Where the collector lives | A new `sherlock/collect/` package (CLI in `sherlock/cli/`); module map and README get a row | 24 Nov 2026 |
| C6 | COLLECT | Web tools for planning | Allowed for documentation pages (APIs, terms, catalogue formats). No hashes, paths or project names in any query; pulls still run from brownie's shell | 24 Nov 2026 |
| C7 | COLLECT | A7 Windows image source | Windows 11 26H2 (current) and Windows 10 22H2, both from Microsoft's consumer ISO pages (24-hour links, per-language SHA-256 published; brownie downloads). No Enterprise or Server evaluation images. Replaces W5's 23H2 / 24H2 / Server 2025 (23H2 is no longer offered by Microsoft). Which build feeds which split: open (COLLECT §8). To carry to the dashboard | 24 Nov 2026 |
| C8 | COLLECT | A8 ELF scope | ELF files that arrive inside packages pulled for PE/.NET keep their bytes in the separate ELF pool, outside the paper's denominators. No pull made only for ELF, Fedora 45 included. To carry to the dashboard | 24 Nov 2026 |
| C9 | COLLECT | How Microsoft goodware is split | By kind of product: OS files (per build), runtimes, apps, libraries, and third-party software signed by Microsoft (where a static signer parse can tell), each kind wholly on one side. One sha256 sits on one side only; no TLSH cluster straddles. A signer is evidence, not proof (forged-signature risk, G0.md §6.1) | 24 Nov 2026 |
| C10 | COLLECT | abuse.ch Terms §7.3 (AI training, high volume) | Option (a): brownie asked Spamhaus for written consent; Spamhaus replied that the request is being processed (25 Nov 2026). No new MalwareBazaar pull until the final answer; goodware work goes ahead meanwhile. The Spamhaus Intelligence API Developer License does not cover MalwareBazaar (IP/domain reputation only). Dashboard risk row to request | 25 Nov 2026 |
| C11 | COLLECT | Malware pull pacing | At most 1,900 downloads per day per egress IP (FAQ: 2,000 per IP per day), counted in a persistent 24-hour ledger, not per process. Run from Slurm by brownie; job shape (daily resubmit vs one long job) open. Prior art: brownie's V1-era fetch kit, read for mechanics only (its family targets and exclude list are V1's) | 25 Nov 2026 |
| C12 | COLLECT | Q2 sandbox and environment | bwrap (`--unshare-net`) for the worker that parses downloads; podman for the third-party unpacking tools. Add `zstandard`, `asn1crypto`, `pyzipper` to the env. Fetch-only stages need neither (stdlib only) | 25 Nov 2026 |
| C13 | COLLECT | Q3 budget split (A1, ~100 GiB) | ISO 16, Microsoft Linux repo 5, apt 7, winget 20, NuGet 18, reserve 34 GiB | 25 Nov 2026 |
| C14 | COLLECT | Q4 apt Release signatures | gpgv on InRelease before its checksums are trusted | 25 Nov 2026 |
| C15 | COLLECT | Q5 which NuGet packages | First 4,000 of an empty search query, sorted locally; Microsoft ownership by the package's listed owner | 25 Nov 2026 |
| C16 | COLLECT | Q6 status of a budget-stopped run | `ok`, with the reason in `stats.stopped` | 25 Nov 2026 |
| C17 | COLLECT | Q7 where kept bytes live | `ISB_WORK/intake/<source>/store/`, content-addressed, read-only once verified | 25 Nov 2026 |
| C18 | COLLECT | 10% checkpoint while brownie is away | Auto-continue: after the seeded 10% sample each pull writes a yield report and goes on only while its projected spend fits that source's budget; otherwise it stops (`stats.stopped`). The 34 GiB reserve is not touched until brownie re-budgets | 25 Nov 2026 |
| C19 | COLLECT | gpgv without keyrings on the node (C14) | The apt job stores the exact InRelease bytes and their sha256 and marks files `release_sig: unverified`; HTTPS and per-file SHA256 are still checked. Nothing is promoted until an offline gpgv passes | 25 Nov 2026 |
| C20 | COLLECT | First unattended chain (25–28 Nov) | Fetch-only (no unpacking). NuGet, then Microsoft repo + apt, then winget only if its tests and an independent review pass tonight. Chained with `afterany`; a smoke run with a few packages per source comes first | 25 Nov 2026 |
