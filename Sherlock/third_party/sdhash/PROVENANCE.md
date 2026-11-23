# third_party/sdhash

`jc_sdhash` 0.2.1, Botacin's Lab (MIT, see `LICENSE`), from
`github.com/Botacin-s-Lab/SDhash_Python`, commit `7e39811`. It wraps the
`sdhash` 3.4 binary (Vassil Roussev and Candice Quates, sdhash.org).

Copied from the SDhash_Python archive brownie supplied on 22 Nov 2026. Kept:
`LICENSE`, `README.md`, `setup.py`, `jc_sdhash/`. Left out: `.git/`, `build/`,
`dist/`, the egg-info folders, the Docker files and sample `.sdbf` outputs.

| File | sha256 |
|---|---|
| `jc_sdhash/sdhash` | `3b698f063fcb593542cdbe9bbbf0e79e28c725d4ac4a98194a4b8af111943b64` |
| `jc_sdhash/wrapper.py` | `0b917557e0e37bb00fe6002859341381ea695e11c9cb6584bd08049736ffdeac` |
| `jc_sdhash/__init__.py` | `6feef76020114694e816d613b37ad3b1a958c612e23c2f660298700bb369075c` |

The binary is x86-64 Linux and links `libstdc++`, `libgomp` and `libm`.

## How Sherlock should use it

The Python wrapper starts one `sdhash` process per file or per pair. That is
fine for a spot check and far too slow for 95,718 malware files. For W1, call
the binary in bulk mode and parse its output:

```bash
sdhash -f files.txt -o set -p 16                 # one digest set from a list of paths -> set.sdbf
sdhash -c query.sdbf ref.sdbf -t 21 -p 16 --separator csv   # query vs reference, scores >= 21
sdhash -c set.sdbf -t 21 -p 16                   # all pairs within one set
```

Checked on synthetic files on 22 Nov 2026: a file under 512 bytes gets no
digest, an unrelated pair prints nothing, and this build prints two extra
numeric columns after the score (`a|b|095|94.68|97.33`). Parse the first
score column and keep the rest raw until its meaning is confirmed.

The threshold of 21 above is a placeholder. W1 sets the real threshold by
measuring precision against labelled pairs before any label is propagated.
