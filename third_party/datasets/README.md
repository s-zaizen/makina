# third_party/datasets

External datasets used to seed makina's GBDT model via `ml/scripts/bulk_import.py`.

**Nothing here ships with the repository.** Each subdirectory contains a
`README.md` (attribution, license, citation), a `fetch.sh` (downloads the data
from its authoritative source), and a `.gitignore` that excludes the data
artefacts. Run the fetch script once per clone to populate the directory.

## Datasets

| Dataset | License | Authoritative source | Notes |
|---|---|---|---|
| [CVEfixes](cvefixes/) | CC BY 4.0 | [Zenodo 4476563](https://zenodo.org/records/4476563) | SQLite dump, multi-language CVE+commit pairs |
| BigVul (HF) | MIT (scripts), source code under original licenses | [`bstee615/bigvul`](https://huggingface.co/datasets/bstee615/bigvul) | Downloaded at runtime by `datasets.load_dataset`; no local artefact |

## Why the data is not vendored

The datasets are redistributed by their authoritative hosts (Zenodo for
CVEfixes, Hugging Face for BigVul) under terms that require attribution when
shared. We do not mirror them here — users download from the original source,
so the CC BY 4.0 "Share" trigger never fires from makina, and we avoid stale or
mis-licensed copies. Attribution is still preserved in each subdirectory's
`README.md` so that anyone distributing a trained model derived from these
datasets can carry the notice forward.
