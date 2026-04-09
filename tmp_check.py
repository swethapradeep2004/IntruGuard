import os
import joblib

network_model = joblib.load(r"c:\Users\SWETHA P KRISHNAN\Downloads\intruguard\models\network_model.pkl")
network_le = joblib.load(r"c:\Users\SWETHA P KRISHNAN\Downloads\intruguard\models\network_label_encoders.pkl")

with open(r"c:\Users\SWETHA P KRISHNAN\Downloads\intruguard\tmp_out.txt", "w") as f:
    f.write(f"Label encoders keys: {network_le.keys()}\n")
    if hasattr(network_model, "feature_names_in_"):
        f.write(f"Model feature names: {network_model.feature_names_in_}\n")
    else:
        f.write("Model does not have feature_names_in_\n")
