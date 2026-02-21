import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
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

# Path to the uploaded dataset
train_dataset_path = "uploads/train.csv.csv"
test_dataset_path = "uploads/test.csv.csv"

print(f"🔄 Loading full training dataset from {train_dataset_path}...")

try:
    # 1. Load Data
    train_df = pd.read_csv(train_dataset_path, header=None)
    
    # Handle column count
    if train_df.shape[1] == 42:
        train_df.columns = columns
    elif train_df.shape[1] == 43:
        train_df.columns = columns + ["difficulty"]
    else:
        train_df = train_df.iloc[:, :42]
        train_df.columns = columns

    print(f"✅ Loaded {len(train_df)} training rows.")

    # 2. Encoding Categorical Features
    print("💎 Encoding categorical features and preparing dataset...")
    le_dict = {}
    X = train_df.drop(["label", "difficulty"], axis=1, errors='ignore')
    
    categorical_cols = ["protocol_type", "service", "flag"]
    categorical_indices = [X.columns.get_loc(c) for c in categorical_cols if c in X.columns]
    
    for col in categorical_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        le_dict[col] = le
    
    y = train_df["label"]

    # 3. Model Training
    print(f"🚀 Training HistGradientBoosting (300 iterations) on {X.shape[1]} features...")
    # HistGradientBoosting is generally better than RandomForest for accuracy on this dataset
    model = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.05,
        max_leaf_nodes=64,
        categorical_features=categorical_indices,
        random_state=42
    )
    
    # Split for internal validation
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.1, random_state=42, stratify=y)
    
    model.fit(X_train, y_train)

    # 4. Accuracy Check
    val_acc = model.score(X_val, y_val)
    print(f"🏆 Internal Validation Accuracy: {val_acc * 100:.2f}%")

    # 5. Save Model and Encoders
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/network_model.pkl")
    joblib.dump(le_dict, "models/network_label_encoders.pkl")
    print("💾 High-performance model saved.")

    # 6. Final Test
    if os.path.exists(test_dataset_path):
        print("\n📝 Running Final Exam on test.csv.csv...")
        test_df = pd.read_csv(test_dataset_path, header=None)
        if test_df.shape[1] >= 42:
            test_df = test_df.iloc[:, :len(columns)]
            test_df.columns = columns
            X_test = test_df.drop(["label"], axis=1)
            y_test = test_df["label"]
            
            for col, le in le_dict.items():
                X_test[col] = X_test[col].astype(str).map(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
            
            # Evaluate Binary Accuracy (Normal vs Attack) - This is what the dashboard uses
            preds = model.predict(X_test)
            preds_bin = [0 if str(p).strip().lower() == "normal" else 1 for p in preds]
            y_test_bin = y_test.apply(lambda x: 0 if str(x).strip().lower() == "normal" else 1)
            
            from sklearn.metrics import accuracy_score
            test_acc_bin = accuracy_score(y_test_bin, preds_bin)
            
            print(f"🎯 Final Test Accuracy (Multi-class): {model.score(X_test, y_test) * 100:.2f}%")
            print(f"🛡️ Final Test Accuracy (Binary Detection): {test_acc_bin * 100:.2f}%")
            
            if test_acc_bin >= 0.80:
                print("🌟 SUCCESS: Binary Accuracy target reached (>80%)!")


except Exception as e:
    print(f"❌ Error: {e}")


