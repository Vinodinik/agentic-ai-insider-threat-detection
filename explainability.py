def generate_explainability_layer(df):
    
    if df is None or df.empty:
        return None

    df = df.copy()

    df_top = (
        df.sort_values("Risk_Score", ascending=False)
        .groupby("Severity")
        .head(1)
    )

    explanations = {}

    for row in df_top.itertuples():

        user = row.User
        severity = row.Severity
        risk_score = round(row.Risk_Score, 2)
        hour = getattr(row, "Hour", "unknown")

        if severity == "Critical":
            paragraph = (
                f"User {user} has been classified as Critical with a risk score of {risk_score}. "
                f"System access at {hour}:00 hours significantly deviates from historical baseline patterns. "
                f"Multiple anomaly triggers and contextual amplification factors indicate a high probability "
                f"of insider threat behavior. Immediate SOC intervention and access containment are recommended."
            )

        elif severity == "High":
            paragraph = (
                f"User {user} is categorized under High severity with a risk score of {risk_score}. "
                f"Behavioral deviations exceed acceptable thresholds and show elevated contextual risk. "
                f"This case requires prioritized investigation and controlled monitoring."
            )

        elif severity == "Medium":
            paragraph = (
                f"User {user} falls into the Medium severity category with a risk score of {risk_score}. "
                f"Moderate anomaly signals were observed at {hour}:00 hours. "
                f"While not immediately dangerous, pattern persistence should be monitored."
            )

        elif severity == "Low":
            paragraph = (
                f"User {user} is classified as Low severity with a risk score of {risk_score}. "
                f"Minor deviations from baseline were detected, but contextual risk remains limited. "
                f"Passive monitoring is sufficient at this stage."
            )

        elif severity == "Lowest":
            paragraph = (
                f"User {user} is categorized under the Lowest severity level with a risk score of {risk_score}. "
                f"Observed activity at {hour}:00 hours aligns with established behavioral baselines. "
                f"No anomaly amplification or contextual threat indicators were identified. "
                f"This activity is considered normal operational behavior and requires no action."
            )

        else:
            paragraph = "No explainability data available."

        explanations[severity] = paragraph

    return explanations