#!/usr/bin/env python3
# ------------------------------------------------------------
#  run_all.py  –  OTIDS hyper‑period table → 4 models + scores
# ------------------------------------------------------------
import os, warnings
import pandas as pd, numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

from tensorflow.keras import layers, models, regularizers


# ---------- column lists ----------------------------------------------------
CATS   = ["Identifier"]
NUMS   = ["n_frames", "mean_gap_ms", "std_gap_ms", "util_bits", "hyper_idx"]
TARGET = "y"

# ============================================================================#
#                               DATA PREP                                     #
# ============================================================================#
def _ensure_y(df: pd.DataFrame) -> pd.DataFrame:
    """Add integer target 0=normal 1=dos 2=fuzzy 3=imp (precedence dos>imp>fuzzy)."""
    if "y" in df.columns:
        return df                              # already present

    if "label" in df.columns:
        mapping = {"normal": 0, "dos": 1, "fuzzy": 2, "imp": 3}
        df["y"] = df["label"].map(mapping).astype(int)
        return df

    cond_dos   = df["has_dos"]   == 1
    cond_imp   = (df["has_imp"]   == 1) & (~cond_dos)
    cond_fuzzy = (df["has_fuzzy"] == 1) & (~cond_dos) & (~cond_imp)

    df["y"] = 0
    df.loc[cond_fuzzy, "y"] = 2
    df.loc[cond_imp,   "y"] = 3
    df.loc[cond_dos,   "y"] = 1
    return df


def load_dataset(path: str = "Processed/otids_hyper_dataset.parquet") -> pd.DataFrame:
    """Load OTIDS hyper‑period table (parquet preferred, csv fallback)."""
    try:
        df = pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path)
    except (ImportError, ValueError, FileNotFoundError):
        alt = path.replace(".parquet", ".csv")
        df = pd.read_csv(alt)
    df["hyper_idx"] = df["hyper_idx"].astype("int16")
    return _ensure_y(df)


def train_test(df: pd.DataFrame, test_size: float = .20, random_state: int = 42):
    """Return (X_train, X_test, y_train, y_test) plus fitted OneHotEncoder."""
    X_cat_raw = df[CATS].astype(str).values
    try:  # scikit‑learn < 1.4
        enc = OneHotEncoder(handle_unknown="ignore", sparse=False)
    except TypeError:  # ≥ 1.4 renamed arg
        enc = OneHotEncoder(handle_unknown="ignore", sparse_output=False)

    X_cat = enc.fit_transform(X_cat_raw)
    X_num = df[NUMS].values.astype(np.float32)
    X     = np.hstack([X_num, X_cat])
    y     = df[TARGET].values.astype(int)

    return train_test_split(X, y, test_size=test_size,
                            stratify=y, random_state=random_state), enc


# ============================================================================#
#                               REPORT UTILS                                  #
# ============================================================================#
def report(model, X_test, y_test, name: str, score_file: str = "scores.csv"):
    """Print & append one CSV line with accuracy + F1s."""
    y_pred = model.predict(X_test)
    if y_pred.ndim == 2:                 # soft‑max probabilities → argmax
        y_pred = np.argmax(y_pred, axis=1)

    rep = classification_report(
        y_test, y_pred,
        target_names=["normal", "dos", "fuzzy", "imp"],
        output_dict=True,
        zero_division=0)

    line = (f"{name},{rep['accuracy']:.3f},{rep['macro avg']['f1-score']:.3f},"
            f"{rep['dos']['f1-score']:.3f},{rep['fuzzy']['f1-score']:.3f},"
            f"{rep['imp']['f1-score']:.3f}\n")

    need_header = (not os.path.exists(score_file)
                   or os.stat(score_file).st_size == 0)
    with open(score_file, "a", newline="") as f:
        if need_header:
            f.write("model,accuracy,macro_F1,F1_dos,F1_fuzzy,F1_imp\n")
        f.write(line)

    print(line, end="")


# ============================================================================#
#                              MAIN ROUTINE                                   #
# ============================================================================#
def main():
    warnings.filterwarnings("ignore", category=UserWarning)  # silence sklearn

    df = load_dataset()
    (X_train, X_test, y_train, y_test), _ = train_test(df)

    # ---------------- Logistic Regression -----------------
    logreg = LogisticRegression(max_iter=1000,
                                class_weight="balanced",
                                multi_class="multinomial")
    logreg.fit(X_train, y_train)
    report(logreg, X_test, y_test, "logreg")

    # ---------------- Random Forest -----------------------
    rf = RandomForestClassifier(n_estimators=300,
                                max_depth=None,
                                n_jobs=-1,
                                class_weight="balanced")
    rf.fit(X_train, y_train)
    report(rf, X_test, y_test, "rf")

    # ---------------- Histogram Gradient Boosting ---------
    class_counts = np.bincount(y_train)
    sample_wt = np.vectorize(lambda cls: len(y_train)/class_counts[cls])(y_train)

    hgb = HistGradientBoostingClassifier(max_depth=6, max_iter=300)
    hgb.fit(X_train, y_train, sample_weight=sample_wt)
    report(hgb, X_test, y_test, "hgb")

    # ---------------- Dense MLP (Keras) -------------------
    l2 = regularizers.l2(1e-4)
    class_wt = {i: len(y_train)/c for i, c in enumerate(class_counts)}

    inp = layers.Input(shape=(X_train.shape[1],))
    x = layers.Dense(256, activation="relu", kernel_regularizer=l2)(inp)
    x = layers.BatchNormalization()(x); x = layers.Dropout(0.3)(x)
    x = layers.Dense(128, activation="relu", kernel_regularizer=l2)(x)
    x = layers.BatchNormalization()(x); x = layers.Dropout(0.3)(x)
    x = layers.Dense(64, activation="relu", kernel_regularizer=l2)(x)
    x = layers.BatchNormalization()(x); x = layers.Dropout(0.3)(x)
    x = layers.Dense(32, activation="relu", kernel_regularizer=l2)(x)
    x = layers.BatchNormalization()(x)
    out = layers.Dense(4, activation="softmax")(x)

    model = models.Model(inp, out)
    model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])

    model.fit(X_train, y_train,
              epochs=40, batch_size=256,
              class_weight=class_wt,
              validation_split=0.1,
              verbose=0)

    report(model, X_test, y_test, "mlp_dense")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()