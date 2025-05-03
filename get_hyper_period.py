import pandas as pd
from collections import Counter
from math import gcd
from functools import reduce

def dominant_gap(series, res=0.001):
    """mode of gaps rounded to 'res' seconds (default 1 ms)"""
    gaps = series.diff().dropna()
    if gaps.empty:
        return None
    rounded = (gaps / res).round().astype(int)
    mode_i  = Counter(rounded).most_common(1)[0][0]
    return mode_i * res

def lcm(a, b): return a * b // gcd(a, b)

def hyper(csv, res=0.0001, max_period=5):
    df = pd.read_csv(csv).sort_values(["Identifier","Time"])
    per = (
        df.groupby("Identifier")["Time"]
          .apply(lambda s: dominant_gap(s, res))
          .dropna()
          .loc[lambda s: s < max_period]      # drop very slow IDs (>5 s)
          .unique()
    )

    print("periods used (s):", per)
    ticks = (per / res).round().astype(int)

    H = reduce(lcm, ticks, 1)
    return H * res

print("≈-hyper:", hyper("./Processed/Fuzzy_attack_dataset_SampleTwo.csv"), "s")