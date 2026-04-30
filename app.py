from flask import Flask, request, render_template
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import io
import base64
# Import agent functions
from agents.detection import run_detection_agent
from agents.simulation import run_simulation_agent
from agents.reasoning import run_reasoning_agent
from agents.risk_scoring import run_risk_scoring_agent
from agents.response import run_response_agent
from agents.explainability import generate_explainability_layer

app = Flask(__name__)

# ==============================
# Global State (Agent Storage)
# ==============================
global_state = {
    "raw": None,
    "detected": None,
    "simulated": None,
    "reasoned": None,
    "scored": None,
    "responded": None,
    "explained": None
}

# ==============================
# Utility Function
# ==============================
def enrich_with_user_stats(df_reasoning):

    stats = df_reasoning.groupby("User").agg(
        Total_Events=("Event_Index", "count"),
        Distinct_Devices=("PC", "nunique"),
        After_Hours_Events=("Hour", lambda x: (x < 6).sum() + (x > 22).sum()),
        Average_Access_Hour=("Hour", "mean")
    ).reset_index()

    df_enriched = df_reasoning.merge(stats, on="User", how="left")

    df_enriched["Compliance_Justification"] = (
        "FR-03 (Threat Explanation), UR-03 (Explainable Decisions), BR-03 (Compliance & Auditability)"
    )

    df_enriched["Report_Generated_Time"] = datetime.now()

    return df_enriched


# ==============================
# Home Route
# ==============================
@app.route('/')
def home():
    return render_template('dashboard.html')


# ==============================
# Upload Dataset
# ==============================
@app.route('/upload', methods=['POST'])
def upload():

    if 'file' not in request.files:
        return render_template("dashboard.html", error="No file uploaded")

    file = request.files['file']
    filename = file.filename.lower()

    try:
        if filename.endswith('.xlsx') or filename.endswith('.xls'):
            df = pd.read_excel(file)
        else:
            df = pd.read_csv(file)
    except Exception as e:
        return render_template("dashboard.html", error=f"File read error: {str(e)}")

    if 'date' not in df.columns:
        return render_template("dashboard.html", error="Dataset must contain a 'date' column")

    df['date'] = pd.to_datetime(df['date'], errors='coerce')
    df = df.dropna(subset=['date'])
    df['Hour'] = df['date'].dt.hour

    global_state["raw"] = df

    return render_template("dashboard.html", message="Dataset uploaded successfully.")


# ==============================
# Detection Agent
# ==============================
@app.route('/run_detection')
def run_detection():

    if global_state["raw"] is None:
        return render_template("dashboard.html", error="Upload dataset first.")

    df = run_detection_agent(global_state["raw"])
    global_state["detected"] = df

    total_logs = len(df)
    anomalies = df['anomaly'].sum()
    anomaly_rate = round((anomalies / total_logs) * 100, 2)

    risk_level = "High Risk" if anomaly_rate >= 5 else "Moderate Risk"

    top_users = (
        df[df['anomaly'] == 1]
        .groupby("user")
        .size()
        .sort_values(ascending=False)
        .head(5)
        .to_dict()
    )

    top_pcs = (
        df[df['anomaly'] == 1]
        .groupby("pc")
        .size()
        .sort_values(ascending=False)
        .head(5)
        .to_dict()
    )

    suspicious_activities = (
        df[df['anomaly'] == 1]
        .groupby("activity")
        .size()
        .sort_values(ascending=False)
        .to_dict()
    )

    anomalies_by_hour = (
        df[df['anomaly'] == 1]
        .groupby("Hour")
        .size()
        .to_dict()
    )

    return render_template(
        "agent_detection.html",
        total_logs=total_logs,
        anomalies=anomalies,
        anomaly_rate=anomaly_rate,
        risk_level=risk_level,
        top_users=top_users,
        top_pcs=top_pcs,
        suspicious_activities=suspicious_activities,
        anomalies_by_hour=anomalies_by_hour
    )

# ==============================
# Simulation Agent
# ==============================
@app.route('/run_simulation')
def run_simulation():

    if global_state["detected"] is None:
        return render_template("dashboard.html", error="Run Detection Agent first.")

    df_simulated = run_simulation_agent(global_state["detected"])
    global_state["simulated"] = df_simulated

    original_records = len(global_state["detected"])
    synthetic_events = df_simulated["is_synthetic"].sum()

    detected_synthetic = df_simulated[
        (df_simulated["is_synthetic"] == 1) &
        (df_simulated["anomaly"] == 1)
    ].shape[0]

    missed_synthetic = synthetic_events - detected_synthetic

    detection_rate = 0
    if synthetic_events > 0:
        detection_rate = round((detected_synthetic / synthetic_events) * 100, 2)

    detected_table = df_simulated[
        (df_simulated["is_synthetic"] == 1) &
        (df_simulated["anomaly"] == 1)
    ][["id", "date", "user", "pc", "activity"]].head(20).to_dict(orient="records")

    return render_template(
        "agent_simulation.html",
        original_records=original_records,
        synthetic_events=synthetic_events,
        detected_synthetic=detected_synthetic,
        missed_synthetic=missed_synthetic,
        detection_rate=detection_rate,
        detected_table=detected_table
    )

# ==============================
# Reasoning Agent
# ==============================
@app.route('/run_reasoning')
def run_reasoning():

    if global_state["simulated"] is None:
        return render_template("dashboard.html", error="Run Simulation Agent first.")

    df_reasoned = run_reasoning_agent(global_state["simulated"])
    global_state["reasoned"] = df_reasoned

    total_explained = len(df_reasoned)

    threat_distribution = (
        df_reasoned.groupby("Threat_Type")
        .size()
        .sort_values(ascending=False)
        .to_dict()
    )

    after_hours_count = df_reasoned[
        df_reasoned["Threat_Type"].str.contains("After-Hours", na=False)
    ].shape[0]

    synthetic_count = df_reasoned[
        df_reasoned["Threat_Type"].str.contains("Synthetic", na=False)
    ].shape[0]

    behavioral_count = df_reasoned[
        df_reasoned["Threat_Type"].str.contains("Behavioral", na=False)
    ].shape[0]

    top_users = (
        df_reasoned.groupby("User")
        .size()
        .sort_values(ascending=False)
        .head(5)
        .to_dict()
    )

    return render_template(
        "agent_reasoning.html",
        total_explained=total_explained,
        threat_distribution=threat_distribution,
        after_hours_count=after_hours_count,
        synthetic_count=synthetic_count,
        behavioral_count=behavioral_count,
        top_users=top_users
    )
# ==============================
# Risk Scoring Agent
# ==============================
# ==============================
# Risk Scoring Agent
# ==============================
@app.route('/run_risk')
def run_risk():

    if global_state.get("reasoned") is None:
        return render_template("dashboard.html", error="Run Reasoning Agent first.")

    # Run scoring (severity already assigned inside risk_scoring.py)
    df = global_state["reasoned"].copy()
    df = run_risk_scoring_agent(df)

    global_state["scored"] = df

    # 📊 Count per severity (5 levels including Lowest)
    severity_distribution = (
        df["Severity"]
        .value_counts()
        .reindex(["Critical", "High", "Medium", "Low", "Lowest"], fill_value=0)
        .to_dict()
    )

    # 🔥 PIE CHART
    import matplotlib.pyplot as plt
    import io
    import base64

    labels = ["Critical", "High", "Medium", "Low", "Cosmetic"]
    values = [
        severity_distribution["Critical"],
        severity_distribution["High"],
        severity_distribution["Medium"],
        severity_distribution["Low"],
        severity_distribution["Lowest"],
    ]

    colors = [
        "#ef4444",  # Critical
        "#f97316",  # High
        "#eab308",  # Medium
        "#22c55e",  # Low
        "#64748b"   # Lowest
    ]

    plt.figure()
    plt.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90
    )
    plt.title("Risk Severity Distribution")

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png")
    plt.close()
    buffer.seek(0)

    graph_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return render_template(
        "agent_risk.html",
        severity_distribution=severity_distribution,
        graph_base64=graph_base64
    )
    
@app.route('/run_response')
def run_response():

    try:

        if global_state.get("scored") is None:
            return render_template(
                "dashboard.html",
                error="Run Risk Scoring Agent first."
            )

        df_response = run_response_agent(global_state["scored"])

        global_state["responded"] = df_response

        total_alerts = len(df_response)

        severity_counts = (
            df_response["Severity"]
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low", "Lowest"], fill_value=0)
        )

        return render_template(
            "agent_response.html",
            total_alerts=total_alerts,
            critical_actions=severity_counts["Critical"],
            high_actions=severity_counts["High"],
            medium_actions=severity_counts["Medium"],
            low_actions=severity_counts["Low"],
            lowest_actions=severity_counts["Lowest"]
        )

    except Exception as e:
        return f"ERROR: {str(e)}"
# ==============================
# Explainability Agent
# ==============================
@app.route('/run_explain')
def run_explain():

    if global_state.get("responded") is None:
        return render_template("dashboard.html", error="Run Response Agent first.")

    df = global_state["responded"]

    # Pick best 1 case from each severity
    def get_case(severity):
        subset = df[df["Severity"] == severity]
        if subset.empty:
            return {"user": "N/A", "score": 0, "hour": "N/A"}

        row = subset.sort_values("Risk_Score", ascending=False).iloc[0]

        return {
            "user": row["User"],
            "score": round(row["Risk_Score"], 2),
            "hour": row["Hour"]
        }

    return render_template(
        "agent_explain.html",
        critical_case=get_case("Critical"),
        high_case=get_case("High"),
        medium_case=get_case("Medium"),
        low_case=get_case("Low"),
        lowest_case=get_case("Lowest")
    )

from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import pagesizes
from io import BytesIO
from datetime import datetime

#full pipeline
@app.route("/download_report")
def download_report():

    if global_state.get("responded") is None:
        return render_template("dashboard.html", error="Run full pipeline first.")

    df = global_state["responded"]

    # Get top 1 per severity
    df_top = (
        df.sort_values("Risk_Score", ascending=False)
        .groupby("Severity")
        .head(1)
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4)
    elements = []

    styles = getSampleStyleSheet()

    # Title
    elements.append(
        Paragraph("Agentic AI Insider Threat Detection Report", styles["Heading1"])
    )
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(
        Paragraph("Executive Severity Summary", styles["Heading2"])
    )
    elements.append(Spacer(1, 0.3 * inch))

    # Loop through top severity cases
    for row in df_top.itertuples():

        severity = row.Severity
        display_name = "Cosmetic" if severity == "Lowest" else severity

        user = row.User
        risk_score = round(row.Risk_Score, 2)
        hour = getattr(row, "Hour", "Unknown")

        paragraph = f"""
        Severity: {display_name}<br/>
        User: {user}<br/>
        Risk Score: {risk_score}<br/>
        Access Time: {hour}:00<br/><br/>
        This user was classified under the {display_name} severity level based on abnormal 
        behavioral deviations detected by the anomaly detection engine. 
        Appropriate monitoring and response actions are recommended 
        according to the assessed risk level.
        """

        elements.append(Paragraph(paragraph, styles["BodyText"]))
        elements.append(Spacer(1, 0.4 * inch))

    elements.append(
        Paragraph("Compliance & Governance Statement", styles["Heading2"])
    )
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(
        Paragraph(
            "All classifications are generated through interpretable anomaly detection "
            "and rule-based reasoning layers ensuring transparency and auditability.",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 0.3 * inch))
    elements.append(
        Paragraph(f"Generated on: {datetime.now()}", styles["Normal"])
    )

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="Insider_Threat_Final_Report.pdf",
        mimetype="application/pdf"
    )
    
@app.route('/run_all_agents')
def run_all_agents():

    if global_state.get("raw") is None:
        return render_template("dashboard.html", error="Upload dataset first.")

    df = global_state["raw"]

    # Run pipeline
    df_detected = run_detection_agent(df)
    df_simulated = run_simulation_agent(df_detected)
    df_reasoned = run_reasoning_agent(df_simulated)
    df_scored = run_risk_scoring_agent(df_reasoned)
    df_responded = run_response_agent(df_scored)

    global_state["detected"] = df_detected
    global_state["simulated"] = df_simulated
    global_state["reasoned"] = df_reasoned
    global_state["scored"] = df_scored
    global_state["responded"] = df_responded

    # KPIs
    total_logs = len(df)
    total_anomalies = int(df_detected["anomaly"].sum())
    total_users = df_scored["User"].nunique()
    total_alerts = len(df_responded)

    # USER-LEVEL dataframe (USE RESPONDED DATA)
    user_level_df = (
        df_responded
        .sort_values("Risk_Score", ascending=False)
        .drop_duplicates(subset=["User"])
)

    # User counts
    critical_user_count = user_level_df[user_level_df["Severity"] == "Critical"].shape[0]
    high_user_count = user_level_df[user_level_df["Severity"] == "High"].shape[0]
    medium_user_count = user_level_df[user_level_df["Severity"] == "Medium"].shape[0]
    low_user_count = user_level_df[user_level_df["Severity"] == "Low"].shape[0]
    lowest_user_count = user_level_df[user_level_df["Severity"] == "Lowest"].shape[0]
    
    # Top 10 per severity
    critical = user_level_df[user_level_df["Severity"] == "Critical"]
    high = user_level_df[user_level_df["Severity"] == "High"]
    medium = user_level_df[user_level_df["Severity"] == "Medium"]
    low = user_level_df[user_level_df["Severity"] == "Low"]
    lowest = user_level_df[user_level_df["Severity"] == "Lowest"]

    final_df = pd.concat([critical, high, medium, low, lowest])

    final_table = final_df[
    ["User", "PC", "Hour", "Risk_Score", "Severity", "Recommended_Action"]
].to_dict(orient="records")

    pipeline_summary = [
        {"agent": "Detection Agent", "records": len(df_detected), "status": "Completed"},
        {"agent": "Simulation Agent", "records": len(df_simulated), "status": "Completed"},
        {"agent": "Reasoning Agent", "records": len(df_reasoned), "status": "Completed"},
        {"agent": "Risk Scoring Agent", "records": len(df_scored), "status": "Completed"},
        {"agent": "Response Agent", "records": len(df_responded), "status": "Completed"},
    ]

    return render_template(
        "full_dashboard.html",
        total_logs=total_logs,
        total_anomalies=total_anomalies,
        total_users=total_users,
        total_alerts=total_alerts,
        final_table=final_table,
        pipeline_summary=pipeline_summary,
        critical_user_count=critical_user_count,
        high_user_count=high_user_count,
        medium_user_count=medium_user_count,
        low_user_count=low_user_count,
        lowest_user_count=lowest_user_count,
    )

# ==============================
# FULL DASHBOARD PDF REPORT (EXECUTIVE VERSION)
# ==============================
@app.route("/download_full_dashboard_report")
def download_full_dashboard_report():

    if global_state.get("responded") is None:
        return render_template("dashboard.html", error="Run full pipeline first.")

    df = global_state["responded"].copy()

    user_level_df = (
        df.sort_values("Risk_Score", ascending=False)
          .drop_duplicates(subset=["User"])
    )

    severities = ["Critical", "High", "Medium", "Low", "Lowest"]

    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib import pagesizes
    from io import BytesIO
    from datetime import datetime

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4)
    elements = []

    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph("Executive Threat Intelligence Dashboard Report", styles["Heading1"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(f"Generated on: {datetime.now()}", styles["Normal"]))
    elements.append(Spacer(1, 0.4 * inch))

    # Executive explanation per severity
    severity_explanations = {
        "Critical": "Multiple high-risk anomaly signals detected across users. Behavioral deviations significantly exceed baseline thresholds and require immediate SOC intervention and containment measures.",
        "High": "Strong anomaly patterns observed indicating elevated contextual and behavioral risk. Prioritized investigation is recommended to prevent potential escalation.",
        "Medium": "Moderate deviation from established behavioral baselines detected. Continued monitoring is advised to determine persistence or escalation of risk.",
        "Low": "Minor anomaly signals present with limited contextual impact. Activity remains within acceptable behavioral thresholds and requires passive monitoring.",
        "Lowest": "Baseline-aligned activity detected with no significant anomaly escalation. Events are categorized under Cosmetic risk level for compliance and audit tracking only."
    }

    for severity in severities:

        subset = user_level_df[user_level_df["Severity"] == severity]

        if subset.empty:
            continue

        display_name = "Cosmetic" if severity == "Lowest" else severity
        elements.append(Paragraph(f"{display_name} Users ({len(subset)})", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * inch))

        data = [["User", "PC", "Hour", "Risk Score", "Recommended Action"]]

        for row in subset.itertuples():
            data.append([
                row.User,
                row.PC,
                str(row.Hour),
                str(round(row.Risk_Score, 2)),
                row.Recommended_Action
            ])

        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#03DAC6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 0.25 * inch))

        # Single executive explanation block
        elements.append(
            Paragraph(
                f"<b>Explanation:</b> {severity_explanations[severity]}",
                styles["BodyText"]
            )
        )

        elements.append(Spacer(1, 0.5 * inch))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="Executive_Full_Dashboard_Report.pdf",
        mimetype="application/pdf"
    )
    
if __name__ == "__main__":
    app.run(debug=True)