from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pandas as pd

def run_detection_agent(df):
    
    df = df.copy()

    df['Hour'] = pd.to_datetime(df['date']).dt.hour

    le_user = LabelEncoder()
    le_pc = LabelEncoder()
    le_activity = LabelEncoder()

    df['user_enc'] = le_user.fit_transform(df['user'])
    df['pc_enc'] = le_pc.fit_transform(df['pc'])
    df['activity_enc'] = le_activity.fit_transform(df['activity'])

    features = df[['Hour', 'user_enc', 'pc_enc', 'activity_enc']]

    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    # 🔥 Train on subset (faster)
    sample_size = min(100000, len(X))
    X_sample = X[:sample_size]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_sample)  # train on sample only

    # 🔥 Predict on FULL dataset
    df['anomaly'] = model.predict(X)
    df['anomaly'] = df['anomaly'].apply(lambda x: 1 if x == -1 else 0)

    return df