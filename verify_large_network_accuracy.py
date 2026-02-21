import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, classification_report
import os

# NSL-KDD Column Names
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

def load_and_preprocess(filepath, le_dict):
    """Load NSL-KDD CSV and prepare for prediction using LabelEncoders"""
    print(f"📂 Loading {filepath}...")
    df = pd.read_csv(filepath, header=None)
    
    # NSL-KDD has 42 columns (original) or 43 (with difficulty)
    if df.shape[1] == 42:
        df.columns = columns
    elif df.shape[1] == 43:
        df.columns = columns + ["difficulty"]
    else:
        df = df.iloc[:, :42]
        df.columns = columns
        
    # Process Label (0 = normal, 1 = attack)
    y = df["label"].apply(lambda x: 0 if str(x).strip() == "normal" else 1)
    
    # Drop target and difficulty
    X = df.drop(["label", "difficulty"], axis=1, errors='ignore')
    
    # Apply Label Encoding to string columns
    for col in X.columns:
        if col in le_dict:
            # Handle unknown categories by mapping to a valid one if necessary
            # For simplicity, we assume categories match
            try:
                X[col] = le_dict[col].transform(X[col].astype(str))
            except Exception as e:
                print(f"⚠️ Encoding error in {col}: {e}. Attempting recovery...")
                # Fallback: if category is unknown, use the first class label
                known_classes = le_dict[col].classes_
                X[col] = X[col].apply(lambda x: le_dict[col].transform([x])[0] if x in known_classes else 0)
    
    return X, y

def run_verification():
    print("="*60)
    print("🔍 NETWORK MODEL ACCURACY VERIFICATION")
    print("="*60)
    
    # Paths
    model_path = "models/network_model.pkl"
    le_path = "models/network_label_encoders.pkl"
    train_path = "uploads/train.csv.csv"
    test_path = "uploads/test.csv.csv"
    
    if not os.path.exists(model_path):
        print(f"❌ Error: Model not found at {model_path}")
        return

    # Load Model and Label Encoders
    print("🤖 Loading model and encoders (Scaler skipped - not used in production)...")
    model = joblib.load(model_path)
    le_dict = joblib.load(le_path)
    
    # Verify Accuracy on TRAIN set
    if os.path.exists(train_path):
        X_train, y_train = load_and_preprocess(train_path, le_dict)
        print("🧠 Evaluating on Train dataset...")
        y_train_pred = model.predict(X_train)
        # Convert predictions to 0/1 for comparison
        y_train_pred_bin = [0 if str(p).strip() == "normal" else 1 for p in y_train_pred]
        train_acc = accuracy_score(y_train, y_train_pred_bin)
        print(f"✅ Training Accuracy: {train_acc*100:.2f}%")
    else:
        print(f"⚠️ Warning: Train dataset not found at {train_path}")

    # Verify Accuracy on TEST set
    if os.path.exists(test_path):
        X_test, y_test = load_and_preprocess(test_path, le_dict)
        print("📊 Evaluating on Test dataset...")
        y_test_pred = model.predict(X_test)
        y_test_pred_bin = [0 if str(p).strip() == "normal" else 1 for p in y_test_pred]
        test_acc = accuracy_score(y_test, y_test_pred_bin)
        
        print("\n" + "-"*40)
        print(f"🏆 FINAL TEST ACCURACY: {test_acc*100:.2f}%")
        print("-"*40)
        
        # Assessment
        if test_acc >= 0.80:
            status = "🌟 RESULT: GOOD! High effectiveness."
        elif test_acc >= 0.70:
            status = "🆗 RESULT: FAIR. Decent performance."
        else:
            status = "❌ RESULT: POOR. Needs improvement."
            
        print(status)
        print("\nDetailed Report:")
        print(classification_report(y_test, y_test_pred_bin, target_names=["Normal", "Attack"]))
    else:
        print(f"⚠️ Warning: Test dataset not found at {test_path}")



if __name__ == "__main__":
    run_verification()
