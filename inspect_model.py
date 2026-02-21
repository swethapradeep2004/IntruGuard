import joblib
import pandas as pd

def inspect():
    model_path = "models/network_model.pkl"
    scaler_path = "models/network_scaler.pkl"
    
    print(f"🔍 Inspecting {model_path}...")
    model = joblib.load(model_path)
    if hasattr(model, "n_features_in_"):
        print(f"✅ Model expects {model.n_features_in_} features.")
    
    print(f"🔍 Inspecting {scaler_path}...")
    scaler = joblib.load(scaler_path)
    if hasattr(scaler, "n_features_in_"):
        print(f"✅ Scaler expects {scaler.n_features_in_} features.")
    if hasattr(scaler, "feature_names_in_"):
        print(f"✅ Scaler feature names: {scaler.feature_names_in_}")

if __name__ == "__main__":
    inspect()
