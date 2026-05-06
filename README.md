# IntruGuard: ML-Powered Intrusion Detection System

![IntruGuard Banner](https://img.shields.io/badge/IntruGuard-Security-red?style=for-the-badge&logo=shield)
![Status](https://img.shields.io/badge/Status-Active-green?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-Python_Flask_ML-blue?style=for-the-badge)

## 🛡️ Project Overview

**IntruGuard** is a sophisticated, modern Intrusion Detection System (IDS) that leverages Machine Learning to protect network environments and web applications. It provides a real-time monitoring interface and batch analysis capabilities to detect, classify, and visualize potential security threats.

By analyzing patterns in network traffic and web requests, IntruGuard can distinguish between benign user activity and various types of cyber attacks, providing security analysts with a professional SOC (Security Operations Center) dashboard experience.

---

## ✨ Key Features

1. **Dual-Mode Intrusion Detection:**
   - **Network Analysis:** Specialized detection for network-layer threats using features based on the NSL-KDD dataset (e.g., duration, protocol, service, byte counts).
   - **Web Analysis:** Tailored for web application security, analyzing flow durations, packet lengths, and other metrics based on CIC-IDS datasets.
2. **Batch Analysis & PCAP Parsing:** Upload CSV datasets or raw `.pcap` capture files. The system automatically parses raw captures into ML-compatible features.
3. **Live Traffic Monitoring (Admin Mode):** Uses `scapy` to sniff live network packets directly from the local interface and classify them as Benign or Attack in real time, implementing stateful packet flow tracking.
4. **Predictive Threat Sonification:** Translates network traffic anomalies into generative audio using the Web Audio API (experimental).
5. **Simulated Demonstration Mode:** If run without administrative privileges, gracefully falls back to a simulated threat generation mode for safe demonstrations.
6. **Feature Shift Evaluation:** Core models are designed to handle feature shifts and dataset variations, demonstrating model robustness.

---

## 📂 Project Architecture & File Structure

This section outlines the purpose of every major component and file in the project.

### Core Application
- **`app.py`**: The heart of the application. It acts as the Flask web server, defining routes (`/`, `/dashboard`, `/upload`, `/live_monitor`). It integrates the trained Machine Learning models (via `joblib`) to predict attacks on uploaded files. It also runs a background thread utilizing `scapy` for real-time live network packet capture and classification.
- **`pcap_parser.py`**: A robust feature extraction script. It reads uploaded `.pcap` or `.pcapng` files and performs stateful tracking of IPs, Ports, and Protocols to construct 7 critical network features (e.g., `src_bytes`, `dst_bytes`, `logged_in`, `count`, `srv_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`). This allows the system to analyze raw dumps natively.

### Machine Learning Pipeline
- **`retrain_model.py`**: The model training script. It utilizes `scikit-learn`'s `RandomForestClassifier` to train dual models (`network_model.pkl` and `web_model.pkl`). It demonstrates the concept of "Feature Shift" by training on Set A features and testing against Set B features to ensure the model remains robust across differing feature distributions.
- **`regenerate_demo_datasets.py`**: A synthetic data generator script. It programmatically generates realistic network and web demo datasets (`demo_network.csv`, `demo_web.csv`, `train.csv.csv`, `test.csv.csv`). It injects specific signals and noise floors for "Attack" and "Benign" classes to simulate real-world data and validate the feature shift capabilities of the models.

### Directory Structure
- **`models/`**: Stores the pre-trained Machine Learning models (`network_model.pkl`, `web_model.pkl`) and their respective Label Encoders (`network_label_encoders.pkl`, `web_label_encoders.pkl`).
- **`templates/`**: Contains the HTML views for the frontend:
  - `login.html`: Initial authentication portal.
  - `dashboard.html`: Main SOC dashboard.
  - `upload.html`: Interface for uploading CSV or PCAP files.
  - `result.html`: Displays parsed results, predictions, and severity badges with pagination.
  - `live_monitor.html`: The hacker-style live packet sniffing console.
- **`static/`**: Contains client-side assets:
  - `style.css`: Custom vanilla CSS3 styling implementing the premium SOC dark-mode aesthetic.
  - `dashboard.js`, `login.js`, `logs.js`, `detect.js`, `particles.js`: Frontend logic for charts, animations, and real-time live monitoring polling.
- **`uploads/`**: A temporary working directory where user-uploaded CSVs, `.pcap` files, and the output `result_*.csv` files are stored and processed.

---

## 🔬 How The Detection Works

### 1. Network Module
Focuses on tracking connections and overall bandwidth anomalies. The model extracts stateful features:
- `src_bytes` & `dst_bytes`
- `logged_in`
- Stateful Connection Counts: `count`, `srv_count`
- Host Rates: `dst_host_srv_count`, `dst_host_same_srv_rate`

### 2. Web Module
Focuses on detailed flow characteristics indicative of application-layer attacks (SQLi, XSS, etc.). The model uses:
- Flow Timing: `Flow Duration`, `Flow Bytes/s`, `Flow Packets/s`
- Packet Metrics: `Total Fwd Packets`, `Total Length of Fwd Packets`
- Packet Means: `Fwd Packet Length Mean`, `Bwd Packet Length Mean`

### 3. Real-Time Sniffing Engine
When running `app.py`, a background thread uses `scapy.sniff()`. 
- **Admin Privilege:** It captures L2 packets, checks protocols (TCP/UDP), measures payloads, and updates a stateful dictionary (`ip_flows`) to maintain a rolling `count` and `srv_count` per IP, feeding this live into the Random Forest model.
- **Standard Privilege:** Falls back to a simulated packet generator to prevent crashes, producing realistic but synthetic log entries.

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8+
- [Npcap](https://nmap.org/npcap/) (Required for live packet sniffing on Windows)

### Steps
1. **Clone the Repository**
   ```bash
   git clone https://github.com/Rehsana/intruguard.git
   cd intruguard
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train Models / Generate Data (Optional)**
   If you wish to regenerate the demo datasets or retrain the models from scratch:
   ```bash
   python regenerate_demo_datasets.py
   python retrain_model.py
   ```

4. **Run the Application**
   Run the app. To enable real packet sniffing, run your terminal/command prompt as **Administrator**.
   ```bash
   python app.py
   ```
   Access the dashboard at `http://127.0.0.1:5000` (Default Credentials: admin / admin123 or user / user123).

---

## 📄 License
This project is for educational and security research purposes.

---
*Created with ❤️ by the IntruGuard Team*
