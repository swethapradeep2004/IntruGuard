import pandas as pd
import os

# Define NSL-KDD columns
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

input_path = "uploads/temp_web_input.csv"
output_path = "uploads/fixed_network_dataset.csv"

if not os.path.exists(input_path):
    print(f"Error: {input_path} not found.")
    exit(1)

print(f"Reading {input_path}...")
# Read without header
try:
    df = pd.read_csv(input_path, header=None)
except Exception as e:
    print(f"Failed to read CSV: {e}")
    exit(1)

# Assign properly
if len(df.columns) == 42:
    df.columns = columns
    print("✅ Assigned 42 NSL-KDD column headers.")
elif len(df.columns) == 43:
    # Sometimes there is a difficulty level at the end
    columns.append("difficulty")
    df.columns = columns
    print("✅ Assigned 43 NSL-KDD column headers (with difficulty).")
else:
    print(f"Warning: Unexpected column count {len(df.columns)}. Assigning what fits...")
    df.columns = columns[:len(df.columns)]


# Map labels to 0 (Benign) / 1 (Attack) for compatibility
# 'normal' is 0, everything else is 1
print("Mapping labels...")
if "label" in df.columns:
    df["label"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)

# Save
df.to_csv(output_path, index=False)
print(f"✅ Saved fixed dataset to {output_path}")
