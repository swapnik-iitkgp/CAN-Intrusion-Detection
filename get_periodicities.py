import pandas as pd
from collections import Counter

def periodicities(csv_path):
    df = pd.read_csv(csv_path)
    
    # ensure by-identifier chronological order
    df = df.sort_values(["Identifier", "Time"])
    
    gaps = (
        df.groupby("Identifier")["Time"]
          .apply(lambda s: s.diff().dropna())
          .reset_index()
    )

    # mean / std
    stats = gaps.groupby("Identifier")["Time"].agg(
        mean_period = "mean",
        std_period  = "std",
        min_period  = "min",
        max_period  = "max",
    )

    # most-common gap (mode) – handy when the bus uses 2× periods
    def mode_gap(series):
        cnt = Counter(series.round(5))        # 5 µs resolution
        return cnt.most_common(1)[0][0]
    stats["mode_period"] = gaps.groupby("Identifier")["Time"].apply(mode_gap)

    # frequency in Hz
    stats["freq_hz"] = 1 / stats["mean_period"]
    return stats.reset_index()

if __name__ == "__main__":
    out = periodicities("./Processed/Fuzzy_attack_dataset_SampleTwo.csv")
    print(out.head(12))
    out.to_csv("id_periodicities.csv", index=False)