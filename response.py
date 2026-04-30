from datetime import datetime

def run_response_agent(df_scored):
    def assign_action(severity, user):
        if severity == "Critical":
            return f"Immediate SOC Alert + Lock Account {user}"
        elif severity == "High":
            return "Security Investigation Required"
        elif severity == "Medium":
            return "Continuous Monitoring"
        elif severity == "Low":
            return "Logged for Review"
        elif severity == "Lowest":
            return "No Action Required (Baseline Behavior)"
        else:
            return "Undefined Action"

    df_scored["Recommended_Action"] = df_scored.apply(
        lambda r: assign_action(r["Severity"], r["User"]), axis=1
    )
    df_scored["Alert_Time"] = datetime.now()
    return df_scored
