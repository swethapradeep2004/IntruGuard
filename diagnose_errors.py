import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import os

# Define NSL-KDD Columns
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]

def diagnose():
    model_path = "models/network_model.pkl"
    le_path = "models/network_label_encoders.pkl"
    test_path = "uploads/test.csv.csv"

    if not os.path.exists(model_path):
        print("Model not found.")
        return

    model = joblib.load(model_path)
    le_dict = joblib.load(le_path)
    df = pd.read_csv(test_path, header=None)
    
    if df.shape[1] >= 42:
        df = df.iloc[:, :len(columns)]
        df.columns = columns
    
    X_test = df.drop(["label"], axis=1)
    y_test_original = df["label"].astype(str).str.strip()
    
    # Binary ground truth
    y_test_bin = y_test_original.apply(lambda x: 0 if x == "normal" else 1)

    # Encode X
    for col, le in le_dict.items():
        X_test[col] = X_test[col].astype(str).map(
            lambda x: le.transform([x])[0] if x in le.classes_ else -1
        )
    
    # Predict
    preds = model.predict(X_test)
    # Convert preds to binary (model might predict labels or 0/1 depending on how it was saved)
    # If model was trained on labels, it returns strings.
    # Our retrain_model.py trained on train_df["label"] which are strings.
    preds_bin = [0 if str(p).strip().lower() == "normal" else 1 for p in preds]

    print("\n--- Error Analysis by Attack Type ---")
    df['BinaryTarget'] = y_test_bin
    df['BinaryPred'] = preds_bin
    df['Correct'] = df['BinaryTarget'] == df['BinaryPred']

    # Group by original label
    summary = df.groupby('label').agg({
        'Correct': ['count', 'sum', 'mean']
    }).reset_index()
    summary.columns = ['Attack Type', 'Count', 'Correct Predictions', 'Accuracy %']
    summary['Accuracy %'] = summary['Accuracy %'] * 100
    
    # Sort by worst accuracy
    print(summary.sort_values(by='Accuracy %').to_string(index=False))

    print("\n--- Overall Performance ---")
    print(classification_report(y_test_bin, preds_bin, target_names=["Normal", "Attack"]))

if __name__ == "__main__":
    diagnose()
