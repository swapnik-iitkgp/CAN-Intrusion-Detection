# CAN-Intrusion-Detection

This repository contains **four scripts** plus a reference C program that together
create a compact, hyper‑period–level dataset from the openly available
*OTIDS* Sample‑Two CAN traces and benchmark four classifiers for intrusion
detection.

---

## 0  Prerequisites

| Tool / Library         | Version tested | Notes                                       |
| ---------------------- | -------------- | ------------------------------------------- |
| Python                 |  ≥ 3.9         | stdlib only otherwise                       |
| pandas                 |  2.x           | CSV & Parquet I/O                           |
| numpy                  |  1.26          | numerical ops                               |
| scikit‑learn           |  1.3 – 1.4     | ML models / preprocessing                   |
| tensorflow             |  2.15          | dense MLP (CUDA optional)                   |
| pyarrow OR fastparquet | latest         | **optional** – enables fast Parquet writing |
| gcc / clang (optional) | C17            | compile `new_obfuscation.c`                 |

Create a fresh environment and install the Python bits:

```bash
conda create -n otids python=3.10
conda activate otids
pip install pandas numpy scikit-learn tensorflow pyarrow
```

---

## 1  Download the raw CSV traces

The four original log files (≈ 500 MB total) can be grabbed from the following
Google Drive folder:

[https://drive.google.com/drive/folders/1AJ3PCn4Xv2O2q4O1I1Mu3XTRtAb\_ihp7](https://drive.google.com/drive/folders/1AJ3PCn4Xv2O2q4O1I1Mu3XTRtAb_ihp7)

Place *all four* CSVs inside a single folder, e.g.

```
Processed/
 ├─ Attack_free_dataset_SampleTwo.csv
 ├─ DoS_attack_dataset_SampleTwo.csv
 ├─ Fuzzy_attack_dataset_SampleTwo.csv
 └─ Impersonation_attack_dataset_SampleTwo.csv
```

> **Tip:** Do *not* rename the files – the scripts expect these exact names.

---

## 2  Generate the hyper‑period table (≈ 5 MB)

`make_dataset.py` loads the raw frames, segments them into **5‑second hyper
periods** per CAN Identifier, and saves a highly compact Parquet (or
CSV fallback) file containing 45 features per row.

```bash
python make_dataset.py
```

Edit the two path variables at the top of the script if your dataset lives
elsewhere:

```python
root_dir = pathlib.Path(r"/absolute/path/to/Processed")
out_file = root_dir / "otids_hyper_dataset.parquet"
```

The script prints a quick class summary and an estimated fuzzy‑attack start:

```
✓ saved .../otids_hyper_dataset.parquet → 15 226 rows, 4.8 MB
DoS rows        : 62
Fuzzy rows      : 3,134
Impersonation rows: 306
Estimated FUZZY attack starts at t ≈ 253.0 s
```

---

## 3  Train and evaluate four classifiers

`models.py` consumes `otids_hyper_dataset.parquet`, splits it 80 / 20 with
stratification and evaluates:

1. multinomial Logistic Regression
2. Random Forest (300 trees)
3. Histogram Gradient Boosting
4. a 4‑layer dense MLP (TensorFlow)

Each line of output is also appended to `scores.csv` for easy comparison.

```bash
python models.py
```

Sample console output:

```
logreg,0.973,0.941,0.931,0.947,0.945
rf,0.985,0.962,0.954,0.968,0.965
hgb,0.989,0.971,0.963,0.978,0.973
mlp_dense,0.992,0.979,0.971,0.985,0.981
```

---

## 4  Utility scripts (optional)

| File                   | Purpose                                                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `get_hyper_period.py`  | Quick & dirty LCM‑based estimator for a "natural" CAN hyper period from a single CSV.                                            |
| `get_periodicities.py` | Per‑ID mean/std/min/max **inter‑arrival periods** + dominant period mode. Outputs `id_periodicities.csv`.                        |
| `new_obfuscation.c`    | Research prototype for schedule‑obfuscation of control tasks. Compile with `gcc -std=c11 -O2 new_obfuscation.c -o sched_attack`. |

---

## 5  Folder structure recap

```
.
├─ Processed/                # raw CSVs + produced Parquet/CSV
│   └─ otids_hyper_dataset.parquet
├─ scores.csv                # created by models.py
├─ make_dataset.py
├─ models.py
├─ get_hyper_period.py       # (optional)
├─ get_periodicities.py      # (optional)
└─ Hide-n-Seek/
    └─ new_obfuscation.c         # applying obfuscation
```