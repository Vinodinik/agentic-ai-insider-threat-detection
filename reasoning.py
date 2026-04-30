import pandas as pd

def run_reasoning_agent(df):

    reasoning = []

    anomalies = df[df['anomaly'] == 1]

    for idx, row in anomalies.iterrows():

        threat_types = []

        if row['Hour'] < 6 or row['Hour'] > 22:
            threat_types.append("After-Hours Access")

        if row.get('is_synthetic', 0) == 1:
            threat_types.append("Synthetic Insider Scenario")

        if not threat_types:
            threat_types.append("Behavioral Deviation")

        reasoning.append({
            "Event_Index": idx,
            "User": row['user'],
            "PC": row['pc'],
            "Date": row['date'],
            "Hour": row['Hour'],
            "Threat_Type": ", ".join(threat_types)
        })

    return pd.DataFrame(reasoning)