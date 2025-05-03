#!/usr/bin/env python3
"""
make_dataset.py
────────────────────
Create a per‑Identifier, per‑5‑second‑hyper‑period table for the OTIDS
Sample‑Two capture and print basic class counts.

• Output: otids_hyper_dataset.parquet   (~4–5 MB, ≈300× smaller)
          (CSV fallback if pyarrow / fastparquet missing)
• Columns
    Identifier, hyper_idx,
    n_frames, mean_gap_ms, std_gap_ms, util_bits,
    has_dos, has_fuzzy, has_imp
"""
import pathlib, sys, os, warnings
import pandas as pd, numpy as np

# -------------------------------------------------------------------------
# User‑editable paths
# -------------------------------------------------------------------------
root_dir = pathlib.Path(r"C:\Users\swapn\Downloads\BTP 2 Work\Processed")
out_file = root_dir / "otids_hyper_dataset.parquet"   # auto‑csv fallback
# -------------------------------------------------------------------------

H               = 5.0            # hyper‑period seconds
DOSE_ID, IMP_ID = "0000", "0164" # ground‑truth attacker IDs

# ──────────────────────────────────────────────────────────────────────────
def read_all(root: pathlib.Path) -> pd.DataFrame:
    names = {
        "free" : "Attack_free_dataset_SampleTwo.csv",
        "dos"  : "DoS_attack_dataset_SampleTwo.csv",
        "fuzzy": "Fuzzy_attack_dataset_SampleTwo.csv",
        "imp"  : "Impersonation_attack_dataset_SampleTwo.csv",
    }
    dfs = []
    for tag, fname in names.items():
        csv = root / fname
        if not csv.exists():
            sys.exit(f"[error] {csv} not found")
        df = pd.read_csv(csv,
                         usecols=["Identifier", "Time", "DLC"]) \
               .assign(split=tag)
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def build_hyper_table(df: pd.DataFrame) -> pd.DataFrame:
    df["hyper_idx"] = (df.Time // H).astype(int)

    # ground‑truth flags
    df["dos"]   = (df.Identifier == DOSE_ID).astype(int)
    df["imp"]   = (df.Identifier == IMP_ID).astype(int)
    df["fuzzy"] = (df.split == "fuzzy").astype(int)   # whole capture is attack

    df["bits"] = df.DLC * 8 + 47                     # CAN 2.0A ≈ 8*DLC + 47

    ag = (df.groupby(["Identifier", "hyper_idx"])
            .agg(n_frames    = ("Time", "size"),
                 mean_gap_ms = ("Time", lambda s: s.diff().mean()*1e3),
                 std_gap_ms  = ("Time", lambda s: s.diff().std()*1e3),
                 util_bits   = ("bits", "sum"),
                 has_dos     = ("dos",   "max"),
                 has_fuzzy   = ("fuzzy", "max"),
                 has_imp     = ("imp",   "max"))
            .reset_index())

    ag[["mean_gap_ms", "std_gap_ms"]] = ag[["mean_gap_ms",
                                            "std_gap_ms"]].fillna(0)
    return ag


# (optional) derive fuzzy‑attack start automatically
def calc_attack_start(df_fuzzy: pd.DataFrame) -> float:
    """Return first 1 s window where >100 IDs never seen before appear."""
    known = set(df_fuzzy.Identifier.unique())  # will shrink below
    t_max = df_fuzzy.Time.max()
    for t in np.arange(0, t_max, 1.0):
        window = df_fuzzy[(df_fuzzy.Time >= t) & (df_fuzzy.Time < t+1)]
        novel  = window[~window.Identifier.isin(known)]
        if len(novel) > 100:
            return float(t)
    return 250.0   # default from the paper


# ──────────────────────────────────────────────────────────────────────────
def main():
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    df_raw = read_all(root_dir)

    # normalise Identifier: strip, upper, 4‑digit hex
    df_raw["Identifier"] = (df_raw.Identifier.astype(str)
                            .str.strip().str.upper().str.zfill(4))

    df_h = build_hyper_table(df_raw)

    # save
    try:
        df_h.to_parquet(out_file, compression="zstd")
    except ImportError:
        out_file_csv = out_file.with_suffix(".csv")
        df_h.to_csv(out_file_csv, index=False)
        out = out_file_csv
    else:
        out = out_file

    size_mb = df_h.memory_usage(deep=True).sum() / 1_000_000
    print(f"✓ saved {out} → {len(df_h):,} rows, {size_mb:.1f} MB")

    # quick class counts ----------------------------------------------------
    n_dos   = df_h["has_dos"].sum()
    n_fuzzy = df_h["has_fuzzy"].sum()
    n_imp   = df_h["has_imp"].sum()

    print(f"\nDoS rows        : {n_dos}")
    print(f"Fuzzy rows      : {n_fuzzy}")
    print(f"Impersonation rows: {n_imp}")

    # optional fuzzy‑start calculation
    atk_start = calc_attack_start(df_raw[df_raw.split == "fuzzy"])
    print(f"\nEstimated FUZZY attack starts at t ≈ {atk_start:.1f} s")


# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()