# CVEfixes

**CVEfixes** is a dataset of vulnerability-fix commits collected automatically
from open-source projects, keyed by CVE and annotated with CWE and commit
provenance. makina uses it via `ml/scripts/bulk_import.py` to seed the GBDT with
curated TP/FP labels.

## License

The dataset is released under the **Creative Commons Attribution 4.0
International License (CC BY 4.0)**.

- Full text: <https://creativecommons.org/licenses/by/4.0/>
- Copyright: © 2021–2022 Data-Driven Software Engineering Department (dataSED),
  Simula Research Laboratory, Norway.

The collection scripts on GitHub are separately licensed under **MIT**; makina
does not vendor or use those scripts.

## Attribution

If you redistribute this dataset or a model derived from it, you must credit
the original authors. Recommended citation:

```bibtex
@inproceedings{bhandari2021cvefixes,
  title     = {CVEfixes: Automated Collection of Vulnerabilities and Their
               Fixes from Open-Source Software},
  author    = {Bhandari, Guru and Naseer, Amara and Moonen, Leon},
  booktitle = {Proceedings of the 17th International Conference on Predictive
               Models and Data Analytics in Software Engineering (PROMISE '21)},
  pages     = {30--39},
  year      = {2021},
  doi       = {10.1145/3475960.3475985}
}
```

Short form (for README-style notices):

> Training data includes **CVEfixes** (Bhandari, Naseer, Moonen, 2021) —
> <https://github.com/secureIT-project/CVEfixes> — released under CC BY 4.0.

## Authoritative sources

| Source | DOI / URL |
|---|---|
| Zenodo (dataset archive, CC BY 4.0) | [10.5281/zenodo.4476563](https://zenodo.org/records/4476563) |
| GitHub (collection scripts, MIT) | <https://github.com/secureIT-project/CVEfixes> |
| Paper (PROMISE '21) | [10.1145/3475960.3475985](https://doi.org/10.1145/3475960.3475985) |

Published versions on Zenodo:

| Version | Record | Zip size |
|---|---|---|
| v1.0.7 | [zenodo.org/records/7029359](https://zenodo.org/records/7029359) | ~3.9 GB |
| v1.0.8 | [zenodo.org/records/13118970](https://zenodo.org/records/13118970) | ~12 GB |

**Third-party Hugging Face mirrors exist (e.g. `hitoshura25/cvefixes`,
`DetectVul/CVEFixes`) but are not recommended.** Several misdeclare the
license, ship partial subsets, or modify the schema. Prefer Zenodo.

## Usage

### 1. Download

```bash
./fetch.sh              # defaults to v1.0.7 (~3.9 GB zip, ~1 GB extracted .db)
./fetch.sh v1.0.8       # latest, ~12 GB zip
```

After the script completes, `CVEfixes.db` is placed in this directory. The
downloaded zip is kept alongside it so re-runs resume instead of re-downloading
— delete it manually if you need the disk space.

### 2. Import into makina

```bash
# From the repo root, with makina running (docker compose up -d):
python ml/scripts/bulk_import.py \
  --source cvefixes \
  --cvefixes-db third_party/datasets/cvefixes/CVEfixes.db \
  --count 1000 --ratio 0.5
```

See `ml/scripts/bulk_import.py --help` for language filters and tuning.

## What is gitignored here

- `CVEfixes.db` — the extracted SQLite dump (~1 GB)
- `*.zip` — the downloaded archive from Zenodo
- `CVEfixes_v*/` — stray extraction directories

The `README.md`, `fetch.sh`, and `.gitignore` stay tracked.
