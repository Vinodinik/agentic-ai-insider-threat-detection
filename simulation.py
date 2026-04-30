import pandas as pd

def run_simulation_agent(df):
    df['is_synthetic'] = 0

    synthetic = df[df['anomaly'] == 1].sample(frac=0.1, random_state=42).copy()
    synthetic['is_synthetic'] = 1

    df_augmented = pd.concat([df, synthetic], ignore_index=True)

    return df_augmented