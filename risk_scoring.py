def run_risk_scoring_agent(df):
    if df is None or df.empty:
        return None

    df = df.copy()

    # Ensure Total_Events exists
    if "Total_Events" not in df.columns:
        user_stats = df.groupby("User").size().reset_index(name="Total_Events")
        df = df.merge(user_stats, on="User", how="left")

    # Raw risk score formula
    df["Raw_Risk_Score"] = (
        df["Total_Events"] * 0.3 +
        df.get("anomaly", 0) * 50
    )

    # Normalize to 1–100 scale
    min_score = df["Raw_Risk_Score"].min()
    max_score = df["Raw_Risk_Score"].max()

    if max_score == min_score:
        df["Risk_Score"] = 50.0  # fallback default if all values are the same
    else:
        df["Risk_Score"] = 1 + 99 * (df["Raw_Risk_Score"] - min_score) / (max_score - min_score)

    df["Risk_Score"] = df["Risk_Score"].round(1)  # optional: round for display

    # Severity classification
    # Severity classification (NEW LOGIC)
    # Severity classification (FINAL LOGIC)
    def classify(score):
        if score > 60:
            return "Critical"
        elif score > 40:
            return "High"
        elif score > 20:
            return "Medium"
        elif score > 5:
            return "Low"
        else:
            return "Lowest"

    df["Severity"] = df["Risk_Score"].apply(classify)

    return df