# COLLECT plan: goodware collection for W5–W7, and a malware collector

Status: draft for brownie, 24 Nov 2026, revised after an independent review. Plan
only: no code, no pull, no sbatch. Decisions C1–C9 and 8f (`DECISIONS.md`) are
applied, not reopened. Source facts were checked on 24 Nov 2026 (Appendix C).
**Proposal** marks a number that has no source; each one says why. Open questions are
in §8, ordered by when an answer is needed.

## 1. Purpose and done-criteria
The freeze (13 Dec, fallback 20 Dec; C3) gates on two rows: G_stats ≥25,000
vendor- and build-split goodware without Softonic, and ≥3,000 unique usable .NET
across all splits. G_eval (≥30,000) does not gate and may grow after the freeze with
new vendors. G_stats and G_eval are disjoint, so the total is ≥55,000.
- **Usable today, by flags (never by folder):** 19,887 (19,318 PE + 569 .NET). That
  is ≤19,875 if the 12 MalwareBazaar-hit hashes (8b) stay out.
- **Still to collect:** ≥35,113 files, of them ≥2,431 .NET.

`sherlock/collect/` (C5) pulls only from brownie's shell (R9). It verifies every byte
against its source's checksum chain and writes per-file tables. It never writes the
working DB (8f) and never writes under `ISB_DATA`.
- **W5 done:** each build (Win10 22H2, Win11 26H2; C7) counted, PE and .NET, with
  signer coverage and a cross-build overlap matrix that includes win8.
- **W6 done:** PE and .NET yield counted per source; ELF members inventoried into
  the ELF pool (C8).
- **W7 done:** winget complete at the raised cap; NuGet ingested with owner,
  signature and repository; W5–W7 together reach ≥3,000 .NET.
- **Malware collector done:** built and tested offline (C1). It runs only under an
  approval file (§8 Q16).

## 2. Sources and budget (A1, C4: ~100 GiB; split is a proposal, §8 Q3)
| Source | W | Pulled | Checksum chain | Signatures | GiB |
|---|---|---|---|---|---:|
| Microsoft consumer ISO | W5 | Win10 22H2, Win11 26H2; en-US x64; one image index | Microsoft's per-language SHA-256 → ISO → WIM/ESD → file | Embedded or catalog (.cat); unverified which. If catalog-signed, coverage needs `.cat` parsing | 16 |
| packages.microsoft.com | W6 | dotnet runtime, aspnetcore, SDK, powershell (.deb); which distro repos carry them is unverified | InRelease (gpgv) → Packages SHA256 → .deb | Two repo keys, chosen by repo age | 5 |
| Ubuntu, Debian | W6 | dotnet, mono, wine, signed EFI (shim, grub, fwupd); wine, grub and fwupd are unverified | InRelease → Packages SHA256/SHA512 → .deb | Archive GPG; Authenticode on EFI | 7 |
| winget-pkgs | W7 | Fresh pinned commit; one version per package; ≤2 per publisher | Commit → `InstallerSha256` → installer → members | Authenticode; MSIX signed | 20 |
| nuget.org | W7 | Latest stable `.nupkg` of the chosen set (§8 Q5) | Latest catalog leaf at or before the frozen cursor: `packageHash` (SHA512, base64) + `packageSize` | All repository-signed; author signature optional | 18 |
| Reserve | – | Given out at the batched re-budget (§7) | – | – | 34 |

GiB column = §8 Q3's recommended option (c); it changes if brownie picks another.

**Ledger (per source, keyed by `plan_id`):**
- **Reserve before each request.** The amount is the declared size: NuGet
  `packageSize`, apt `Size`, or HEAD `Content-Length`.
- **Unknown size:** reserve 512 MiB. **Proposal:** the kit's per-file cap. Its
  reservations ate the 8 GiB cap because they were never released. Here the unused
  part is released on success, and a stream that passes the reservation is aborted
  and charged in full.
- **Charges:** charge the bytes read. A failure after the first payload byte keeps
  its reservation. A failure before any payload byte is refunded.
- **Free:** cache replay costs nothing (§3 store).
- **Separate bounds:** the transfer budget is separate from the bounds on disk and
  expanded bytes.

**10% checkpoint:** a seeded random 10% of each plan, not its head, so yield per
GiB is representative. W5's checkpoint is its first ISO. The checkpoint reports new
unique PE and .NET per GiB, pool conflicts and failures.

**Yield (only winget is measured):**
| Source | Order of magnitude | Basis |
|---|---|---|
| winget, no unpacking | 0.7 files/package | **Measured:** 160 files from about 220 packages; bytes per source never recorded |
| winget, with unpacking | 10¹/package | Estimate, unmeasured: installers bundle many DLLs |
| Win10 ISO | 10⁴ files | Estimate, unmeasured: System32 plus WinSxS |
| Win11, Win11-only | 10³–10⁴ | Estimate, unmeasured: depends on the overlap with Win10 |
| NuGet (2,000 packages) | 10³–10⁴ DLLs | Estimate, unmeasured: one or more DLLs per target framework |
| PMC plus apt | 10³ | Estimate, unmeasured: the runtime and SDK each ship hundreds of managed DLLs; mono; wine PE DLLs |

## 3. Method
1. **Plan** (`plan`): catalogues only. It writes a frozen plan (winget commit, apt
   `Date`, NuGet cursor, targets, sizes, checksums, sample seed) under a stable
   `plan_id`, with `plan_sha256`. A resume reloads the plan. Retrying failed
   catalogues gives a new, versioned plan; the old plan is kept.
2. **Run records:** every invocation (plan, each pull leg, verify, report) gets a
   fresh `run_id`. `RunRecord` creates `run.json` exclusively, and only the record
   that created it may rewrite it. Each record's config carries `plan_id`,
   `plan_sha256` and the leg number. No API change.
3. **Pull:**
   - **Scope:** one source per invocation, one request at a time, ≥1 s per host
     (**proposal:** the kit's value).
   - **TLS:** verified. A TLS failure is never bypassed.
   - **Redirects:** cross-host HTTPS redirects are allowed only for payloads
     anchored by a catalogue checksum (winget, NuGet). Catalogue hosts are
     allowlisted.
   - **Streaming:** each download streams to `.part`, hashed and size-checked as it
     arrives, then is renamed. A mismatch rejects the file. Stale `.part` files are
     removed on resume.
4. **Chain:** each hop is checked:
   - InRelease, by gpgv against keyrings pinned by fingerprint (§8 Q4);
   - the winget commit, then the manifest;
   - the NuGet catalog leaf;
   - the Microsoft ISO table.
   SHA512-only catalogues are accepted. MD5 and SHA1 never count.
5. **Store:**
   - **Payloads:** a content-addressed store per source,
     `intake/<source>/store/<sha256[:2]>/<sha256>`, read-only (0440; **proposal:**
     the kit used 0640, and nothing here needs write). So replay works across plans.
   - **Receipts:** per-package atomic receipts under `intake/<source>/<plan_id>/`,
     checked on resume. Re-unpacking runs offline from the store.
6. **Sandboxed worker (CLAUDE §3):**
   - **The whole worker is sandboxed.** That is unpack plus inventory: zstd,
     PKCS#7, pefile, dnfile and magic run on untrusted members.
   - **bwrap:** `--unshare-net`; the input is read-only and the only writable path
     is a fresh, empty `ISB_SCRATCH/collect/<run_id>/<pkg>/`. CPU, memory and time
     limits come from prlimit. Python runs with `-I`.
   - **podman (`--network none`):** runs the third-party tools: wimlib, 7-Zip,
     innoextract and msitools.
   - **On disk here:** bwrap, gpgv and a `podman/4.9.3` module are on this node.
     Compute nodes and user namespaces are unverified (§8 Q2).
7. **Unpack:**
   - **In the worker:** tar (with a `.` root), ar, gz, xz, zstd with unknown size
     (bounded), and ZIP (nupkg, MSIX/AppX).
   - **In containers:** WIM/ESD (wimlib; ESD extraction is implied, not stated),
     ISO, MSI, CAB and NSIS (7-Zip), and Inno ≤6.2.2 (innoextract).
   - **Refused:** traversal, absolute names, symlinks, hard links, devices and FIFOs.
   - **Bounds (proposals):** depth 3, so ISO→WIM→file and ZIP→MSI→file both work;
     ≤100 executable members per package (the kit's cap: one bundle must not
     dominate); member and expanded-byte caps.
   - **Output:** walked with `lstat`; regular files only.
   - **Failed unpacks:** a row with `unpack_status` and a reason, never an empty
     result.
8. **Inventory:** one row per regular member (Appendix B), including `tlsh`. The
   member is copied into the store, and the scratch folder is wiped.
9. **Dedupe:**
   - **Cross-run index:** `ISB_WORK/enrich/collect_index/` is checked by every run
     and every report.
   - **Manifest, both pools:** a hash in the malware pool is a `pool_conflict`. It
     never becomes goodware and goes to W2/pool review.
   - **Softonic:** a hash equal to any `any_softonic` row stays barred.
   - **MalwareBazaar dump:** new hashes are checked offline against the local dump.
     A hit gets `mb_goodware_hit` and goes to pool review (8b).
10. **Kind, vendor and side (C9):**
    - **`product_kind`:** precedence OS build > runtime > library > app >
      `ms_signed_thirdparty` > `third_party` (**proposal:** the most specific
      Microsoft kind wins, so no file is counted twice).
    - **`vendor_key`:** NFKC, lowercase, punctuation stripped, legal suffixes dropped
      (inc, ltd, llc, gmbh, corp, corporation, co), whitespace collapsed. It is
      mapped onto `goodware_meta.vendor`, normalised the same way (41,271 rows, 2,898
      distinct, 4,618 empty; read with `mode=ro&immutable=1`).
    - **Vendor evidence, in order:** for new files, package metadata, then
      VersionInfo, then the signer. The existing 19,887 take theirs from
      `goodware_meta`/NSRL. A distro packager is recorded as `packager`, never as
      the vendor.
    - **Side:** each kind and each vendor sits wholly on one side; one sha256 on one
      side. A file repeated across builds goes to the earliest build's side. A
      TLSH-30 component goes to the side of its earliest-build or earliest-dated
      member (§8 Q14).
    - **Signers:** a signer is a claim (G0 §6 item 1). Sides are only proposed;
      G1 sets them.
11. **Dates (H6):**
    - **NuGet:** `created` (`published` reads 1900 for unlisted packages).
    - **winget:** `ReleaseDate` if present (optional in the schema).
    - **apt:** the Release `Date`, an upper bound.
    - **ISO:** `os_image_lower_bound`, from the build revision and the image creation
      time in `wiminfo`.

## 4. Outputs
- **Payloads:** the store (§3.5), plus receipts and the frozen plan, under
  `ISB_WORK/intake/<source>/`.
- **Tables:** `ISB_WORK/enrich/W5|W6|W7/<plan_id>/`, Parquet keyed by sha256, with
  no absolute paths, plus `report.md`.
- **Run records:** `ISB_WORK/runs/collect/<source>/<run_id>/run.json`.
- **Into the dataset (8f):** files only, until brownie approves. Then the tested,
  idempotent loader writes `goodware_provenance` and related tables into a fresh
  copy of `manifest.sqlite`, and brownie swaps it in. `sherlock_manifest.csv` and
  the `ISB_DATA` DB are never written. How split code reads intake files is §8 Q15.

## 5. Checks
- **Tests first:** offline, with synthetic fixtures and a mocked transport
  (Appendix D).
- **`verify` after each leg (read-only):** re-hashes the store against the plan and
  the members against their rows. It also checks that no output holds an absolute
  path, and that no secret appears in config, `run.json` or the logs.
- **`report`:** counts per source, format and kind; new unique hashes; conflicts;
  failures by reason; GiB spent against the budget.
- **Hand check:** 50 rows per source, against the catalogue entry.

## 6. Commands (shape only; from `Sherlock/`; paths relative to a root)
```
python -m sherlock.cli.collect plan   --source nuget|apt|pmc|winget|winiso --budget-gib N
python -m sherlock.cli.collect pull   --source nuget --plan <plan_id> --checkpoint 10
python -m sherlock.cli.collect pull   --source nuget --plan <plan_id> --budget-gib <new>
python -m sherlock.cli.collect pull   --source winiso --plan <plan_id> --offline   # after brownie's curl
python -m sherlock.cli.collect verify|report --source nuget --plan <plan_id>
```
- **Where outputs go:** `intake/<source>/`, `enrich/W*/<plan_id>/` and
  `runs/collect/<source>/<run_id>/`.
- **ISO:** brownie opens the page in a browser, then curls the 24-hour link into
  `intake/winiso/<plan_id>/`. The link never enters config.
- **Pulls:** brownie runs them, as sbatch jobs if compute nodes have outbound
  network; otherwise from the login shell, with the unpack leg in sbatch
  (`--offline`).

## 7. Schedule and risks
| Dates | Step |
|---|---|
| Nov 25–29 | Pure-Python code and tests first (http, ledger, apt, nuget, inventory), then the sandbox and unpackers; independent review |
| Nov 30–Dec 2 | NuGet and apt/PMC pulls to their 10% checkpoints; sandbox proven on the Win10 ISO |
| Dec 3 | One batched re-budget review for all sources |
| Dec 3–8 | Rest of NuGet and apt/PMC; Win11 ISO; winget with installer unpacking; malware collector last (window per §8 Q16) |
| Dec 6 | §8 Q15 decided (critical path) |
| Dec 9 | Goodware TLSH pass (§8 Q14); **fallback trigger:** if projected G_stats <25,000 or .NET <3,000, brownie calls the 20 Dec freeze |
| Dec 10–11 | Reports, loader approval, swap |
| Dec 12–13 | Split, then G1 |

| Risk | Mitigation |
|---|---|
| R8: pulls slip. After G1 only new-vendor goodware grows, so all Microsoft goodware must land first | Order above; checkpoints; fallback trigger |
| R9: no network from the agent | brownie runs every pull and sbatch |
| R10: Microsoft swamps G_stats | Per-source and per-kind index caps (§8 Q12); FP reported per origin |
| Untrusted parsers and tools | Sandboxed worker (§3.6) |
| Forged or catalog-only signatures | Signer is a claim; source provenance outranks it |
| abuse.ch AI-training clause (whole project) | §8 Q1 |

## 8. Open decisions (by when needed; each: options, recommendation, what it changes)
1. **abuse.ch Terms (effective 4 Nov 2025, updated 21 Oct 2026). Needed now; a
   project-level risk.**
   - **The clauses:** §3.1 allows not-for-profit use. §3.2 sets volume limits. §7.3
     says data "may not be used by users to customise, train, or otherwise improve
     any artificial intelligence model or product … without Spamhaus' express prior
     written consent", and bars "any high volume automatic, electronic or manual
     process to access, search or harvest information from the Platforms".
   - **Why it matters:** this touches the 17,889 Tier X training samples.
   - **Options:** (a) brownie asks Spamhaus now; (b) train only on non-MalwareBazaar
     labels; (c) accept the risk, recorded.
   - **Recommend (a),** with a dashboard risk row now. **Changes:** P4's training
     data, and every MalwareBazaar run.
   - **Decided (C10, 25 Nov):** (a). The request is with Spamhaus; no MalwareBazaar
     pull until it is answered. Goodware pulls go ahead.
2. **Sandbox and environment (Nov 25; gates W5).**
   - **Options:** (a) bwrap for the worker plus podman for the tools; (b) podman
     for everything.
   - **Recommend (a).** Check `bwrap --unshare-net` and `module load podman` on a
     compute node. Add `zstandard` and `asn1crypto` to the env. Build the tool
     images offline from pinned sources.
   - **Changes:** `environment.yml`, `scripts/slurm/`.
3. **Budget split (Nov 25).**
   - **Options:** (a) SHERLOCKED's ~20/~40/rest; (b) 16/36/14/10 + 24 reserve;
     (c) 16/20/18/12 + 34 reserve, because winget has the worst measured yield.
   - **Recommend (c):** let the 10% numbers earn winget its share. **Changes:** A1.
4. **apt Release signatures (Nov 25).**
   - **Options:** (a) checksums only, as the kit did; (b) gpgv with keyrings
     brownie fetches and pins by fingerprint.
   - **Recommend (b).** **Changes:** the chain is anchored.
5. **Which NuGet packages count (Nov 28).**
   - **Fact:** search has no sort; `skip` ≤3,000 and `take` ≤1,000. Registration
     has no download counts, and a full catalog walk is infeasible.
   - **Options:** (a) the first 4,000 of an empty query, sorted locally by
     `totalDownloads`; (b) a fixed list.
   - **Recommend (a),** checked by one search per candidate id.
   - **Microsoft-owned:** an owner from a fixed Microsoft account list, or a
     verified reserved prefix. Such packages are kinds `ms_runtime`/`ms_library`.
   - **Signatures:** signed-only is not required; `author_signed` is recorded.
   - **Note:** NuGet's terms bar harvesting except through Microsoft's publicly
     supported interfaces, which V3 is. Pace the pull.
   - **Changes:** the .NET count.
6. **Run status (Nov 25).**
   - **Options:** (a) a planned stop is `ok` with `stats.stopped` =
     `checkpoint|budget`, and only failures are `failed`; (b) a new `partial`
     status, which is an API change.
   - **Recommend (a).**
7. **Where kept bytes live (Nov 25).**
   - **Options:** (a) store under `ISB_WORK/intake/`; (b) under `ISB_SCRATCH`, which
     is wipeable.
   - **Recommend (a):** unpack in scratch, then copy verified files.
   - **Changes:** README, plus a CLAUDE §3 wording edit.
8. **Windows EULA (Nov 30, before W5).**
   - **Fact:** the site terms defer to the licence; both licence URLs returned 404.
   - **Options:** (a) brownie reads the licence inside the ISO before the pull;
     (b) skip W5.
   - **Recommend (a).**
9. **ISO image index (Dec 1).**
   - **Options:** (a) Pro only; (b) all indexes, deduped.
   - **Recommend (a).** **Changes:** W5's counts.
10. **Which build feeds which side (Dec 1).**
    - **Options:** (a) Win10 22H2 and win8 → G_stats, Win11 26H2 → G_eval; (b) the
      reverse.
    - **Recommend (a):** older to stats, as in gen/held. Under "earliest wins",
      G_eval keeps only Win11-only files.
    - **Changes:** W5's targets and C9's table.
11. **Installer unpacking scope (Dec 2).**
    - **Options:** (a) none; (b) MSI, NSIS, Inno ≤6.2.2, MSIX/AppX, ZIP; (c) (b)
      plus WiX burn (no Linux tool verified).
    - **Recommend (b).**
    - **Vendor rule inside G_ood:** (i) the rule applies and wrappers follow their
      vendor; (ii) it does not apply. Recommend (i).
    - **Changes:** winget yield, the G_ood count.
12. **Counting rules (Dec 3, at the re-budget).**
    - **(a)** Is G_stats ≥25,000 counted before or after the R10 index caps?
      Recommend before, with the cap reported.
    - **(b)** .NET ≥3,000 counts unique sha256 after cross-run dedupe.
    - **(c)** The 12 MalwareBazaar hits are subtracted.
    - **(d)** Do installer wrappers count toward any gate? Recommend no.
    - **Microsoft cap:** ≤25% of NuGet files and per-kind caps (**proposal:** keeps
      R10 visible; revisit with the numbers).
13. **winget past 450 (Dec 3).**
    - **Options:** (a) stop at 450; (b) extend from the same pinned commit until
      the budget or the checkpoint says stop.
    - **Recommend (b).** The old spent budget is not carried over.
    - **Changes:** W7's done row.
14. **Goodware TLSH pass before G1 (Dec 5).**
    - **Options:** (a) COLLECT computes digests, and W1's banded pass is re-run on
      old plus new goodware, coordinated with W1's session; (b) skip it, and risk
      straddlers.
    - **Recommend (a).** **Changes:** the W1 schedule; the straddler rule in §3.10.
15. **How split code reads intake files (needed by 6 Dec; critical path).**
    - **Options:** (a) a resolver over the provenance tables; (b) a new read-only
      dataset generation with a new manifest CSV.
    - **Recommend (a) for G1,** and (b) as brownie's later call.
    - **Changes:** the `Manifest` resolver, README, `download.sh`.
16. **Malware run (window by Dec 2).**
    - **Window options:** (a) a window of Dec 3–12, after W1's recount; (b) slip to
      a v1 refreeze.
    - **Approval:** brownie writes `ISB_WORK/approvals/bazaar/<id>.json`, binding
      the date, the cap and the sha256 of the frozen hash list. The collector
      refuses on any mismatch.
    - **Sources:** hashes come from the local dump (no tags sent); the hourly and
      daily batch exports are an alternative.
    - **Limits (C11):** ≤1,900 downloads per day per egress IP, counted in a
      persistent rolling 24-hour ledger (the FAQ says 2,000 per IP per day but not
      whether that is a rolling or a UTC day). The Auth-Key is read from a mode-0600
      file, never from env, the sbatch script or argv. Run from Slurm; open: one
      daily job that resubmits itself with `--begin` (recommended) or one long job.
      brownie checks that compute nodes reach the API and which egress IP they share.
    - **Files:** they land in a fresh, empty `ISB_SCRATCH` folder. The ZIPs are AES-128
      (API page, password "infected"), so pyzipper or 7-Zip in the sandbox is needed.
    - **CLAUDE §1/§3** say hash requests go out from brownie, not code. Ask brownie
      to amend them for this collector.
    - **Recommend (a)** if W1 lands by Dec 2.
17. **How the existing 19,887 divide (Dec 9).**
    - **Setup:** win8 (2,867) is one block, sent to G_stats per Q10. About 17,020
      others are vendor-split. Gaps are G_stats / G_eval, and approximate.
    - **(a) All to G_stats:** 5,113 / 30,000. Least risk for the gating row.
    - **(b) 25:30 by vendor:** about 14,400 / 20,720.
    - **(c) Ratio fixed at the freeze:** G_stats takes the smallest share of existing
      vendors that reaches 25,000 after the new G_stats files. Vendors are drawn in
      seeded `vendor_key` order, with ≥30% of each origin's vendors on each side
      (**proposal:** keeps every origin on both sides). Gaps about 10,220–17,030 /
      18,090–24,890.
    - **Recommend (c):** its honest case is avoiding an all-new, era-shifted G_eval.
      (a) is the fallback if new G_stats files fall short.

**Dashboard and doc edits to request** (not made here):
- C7 → W5 row, A7, D4.
- C8 → the W6 row (drop Fedora 45).
- C9 → the Definitions' split axis.
- A1 split (C4, Q3).
- W7's "NuGet top 2,000" (Q5).
- README: `intake/`, `runs/collect/`, `enrich/collect_index/`, `approvals/` (README
  is shared).
- CLAUDE §1/§3 (Q7, Q16).
- CLAUDE §7: lessons L13–L20 (Appendix D).

---
## Appendix A: measurements (read-only, 24 Nov 2026)
| Origin (folder) | Files | .NET | Use |
|---|---:|---:|---|
| ucsb | 15,029 | 406 | keep |
| win8 | 2,867 | 26 | keep |
| sourceforge | 1,060 | 67 | keep |
| cnet | 837 | 4 | keep |
| winget | 151 (+9 other) | 66 | keep |
| softonic / selfpacked_upx / ELF | 758 / 100 / 1,470 | – | excluded / ablation / ELF pool |

- **Reconciliation:** the keep rows add up to 19,944. 19,944 − 19,887 = 57: 27
  uninventoried files (sourceforge 17, cnet 10) plus 30 Softonic-flagged files
  outside the softonic folder (cnet 26, ucsb 3, sourceforge 1). Usable is counted by
  flags.
- **Old kit:** run 275 had 450 planned, 320 complete, 66 skipped at the cap, 28
  packages without an executable, and 469 new files. Run 262 gave 21 Windows files
  for 4.84 GB. Its parser errors: tar `.` 108, zstd unknown size 56, and Ubuntu's
  SHA512-only Release.
- **This node:** `/usr/bin/bwrap`, `/usr/bin/gpgv`, and a `podman/4.9.3` module.
  docker is not usable from the agent.
- **Env:** pefile, dnfile, pyarrow, pyyaml, magic and tlsh are present.
  zstandard, asn1crypto and pyzipper are not.

## Appendix B: output tables (Parquet, sha256-keyed, no absolute paths)
| Table | Columns |
|---|---|
| `collect_files` | sha256, size, format (by bytes), tlsh, signer_subject, signer_thumbprint, sig_kind, sig_status (never "trusted"), product_kind, vendor_key, proposed_side, side_reason, dedupe (`new`, `dup_goodware`, `dup_run`, `pool_conflict`, `softonic_barred`, `mb_goodware_hit`), unpack_status, plan_id, run_id |
| `goodware_provenance` | sha256, source, package, version, catalogue_url (the entry, not a file), checksum_alg, checksum_ok, container_sha256, member_name, unpack_tool, unpack_tool_version, os_build_revision, retrieved_at, source_date, source_date_kind, vendor_key, vendor_evidence, packager, licence_note, plan_id, plan_sha256 |
| `collect_failures` | source, package, stage, reason, bytes_charged, refunded, plan_id |
| `build_overlap` | build_a, build_b, n_shared, n_only_a, n_only_b |

## Appendix C: sources checked (24 Nov 2026)
| Source | Fact |
|---|---|
| Microsoft ISO pages | Win11: 26H2 only. Win10: 22H2 only. Both multi-edition, per-language SHA-256, links valid 24 h, no size stated |
| Microsoft ToU (fwlink 206977 → legal/terms-of-use, Feb 2022) | Software is governed by its EULA. The EULA was not read (both URLs 404) |
| wimlib 1.14.5; 7-Zip 26.06; innoextract 1.9 | `wimextract` works without applying; ESD on extract only implied. 7-Zip unpacks ISO/MSI/NSIS/CAB/WIM. innoextract: Inno ≤6.2.2, no code run |
| Debian repository format | Signed InRelease → SHA256/SHA512 → package; MD5/SHA1 never for security |
| packages.microsoft.com | Keys `microsoft-2025.asc` and `microsoft.asc`; parse metadata, since paths change |
| packages.debian.org, launchpad | shim-signed and mono-runtime in trixie; dotnet8 in Ubuntu main. packages.ubuntu.com failed |
| winget (schema 1.12.0 JSON) | InstallerType ∈ msix, msi, appx, exe, zip, inno, nullsoft, wix, burn, pwa, portable, font. `InstallerSha256` required per installer. `ReleaseDate` optional. Repo MIT |
| NuGet API | Flat container; catalog leaf SHA512 `packageHash`, `packageSize`, `created`; search with no sort, skip ≤3,000, take ≤1,000; V3 search not rate-limited; 429/403 |
| NuGet signing, terms | All packages repository-signed. Terms (Jan 2025): harvesting barred outside supported interfaces |
| MalwareBazaar API, FAQ | `Auth-Key` header; tag and signature lookups ≤1,000; 2,000 downloads per IP per day; hourly and daily batches |
| abuse.ch ToU | Effective 4 Nov 2025; §3.1, §3.2, §7.3 (§8 Q1) |
| Not checked | Rate limits of apt, PMC, GitHub and the ISO hosts; wine, grub and fwupd availability |

## Appendix D: modules, lessons, tests
**Modules** (`sherlock/collect/`; frozen `*Config` + `DEFAULT_CONFIG`; library code
silent with an `on_event` callback; logging only in `cli/collect.py`):
- `http.py`: Transport plus a mock.
- `ledger.py`: the budget and checkpoint ledger.
- `plan.py`: the frozen plan.
- `store.py`: the content-addressed store and the cross-run index.
- `catalog/{apt,pmc,winget,nuget,winiso,bazaar}.py`: one verifier per source chain.
- `sandbox.py`: the bwrap and podman command builders.
- `unpack.py`: the safe unpackers.
- `inventory.py`: per-file rows.
- `kinds.py`: product kind, vendor key and side.
- `provenance.py`: provenance rows and the absolute-path guard.
- `bazaar.py`: the malware collector.
- The 8f loader lives with the other enrichment loaders.

**Lessons (the next IDs in CLAUDE §7):**
- L13 tar `.` root;
- L14 zstd with unknown size;
- L15 SHA512-only catalogue;
- L16 cache replay spends nothing;
- L17 refund only pre-payload failures;
- L18 plan frozen and reloaded;
- L19 the MalwareBazaar daily cap and spacing;
- L20 an empty unpack is a recorded failure.

**Tests (written first):**
- **Unpacking:**
  - `test_tar_dot_root_accepted`
  - `test_zstd_unknown_size_bounded`
  - `test_traversal_absolute_symlink_hardlink_device_refused`
  - `test_member_count_and_expanded_bytes_bounded`
  - `test_per_package_member_cap`
  - `test_tool_output_links_dropped`
  - `test_unpack_requires_fresh_empty_scratch_dir`
  - `test_failed_unpack_row_never_silently_empty`
  - `test_container_cmd_has_no_network`
- **Chain:**
  - `test_sha512_only_release_accepted`
  - `test_md5_sha1_never_suffice`
  - `test_nuget_base64_sha512_verified`
  - `test_checksum_mismatch_rejects`
  - `test_inrelease_bad_signature_rejects`
  - `test_tls_failure_never_bypassed`
- **Budget:**
  - `test_cache_replay_spends_no_budget`
  - `test_refund_only_pre_payload_failures`
  - `test_partial_body_charges_reservation`
  - `test_unknown_size_overrun_aborts`
  - `test_checkpoint_is_seeded_random_sample`
  - `test_resume_does_not_recharge_or_duplicate_rows`
  - `test_plan_frozen_and_reloaded`
- **Dedupe and sides:**
  - `test_cross_run_dedupe`
  - `test_pool_conflict_never_goodware`
  - `test_softonic_flag_survives_new_provenance`
  - `test_mb_dump_hit_flagged`
  - `test_one_sha_one_side`
  - `test_earliest_build_wins`
  - `test_straddler_goes_to_earliest`
  - `test_kind_wholly_one_side`
  - `test_multi_kind_precedence`
  - `test_publisher_cap`
  - `test_microsoft_owner_rule`
  - `test_elf_member_to_elf_pool`
- **Records:**
  - `test_never_writes_under_dataset_root`
  - `test_no_absolute_path_in_outputs_or_run_json`
  - `test_secret_never_in_config_or_run_json`
  - `test_secret_never_in_logs`
  - `test_inventory_time_never_source_date`
  - `test_nuget_created_not_published`
- **Malware collector:**
  - `test_approval_binds_list_sha256`
  - `test_mb_daily_cap_and_resume`
  - `test_mb_one_key_no_rotation`
  - `test_mb_refusal_stops_iteration`
  - `test_mb_utc_blackout_and_25h_spacing`
  - `test_mb_aes_zip_extracted_in_scratch_only`
