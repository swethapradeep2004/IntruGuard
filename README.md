# IntruGuard: ML-Powered Intrusion Detection System

![IntruGuard Banner](https://img.shields.io/badge/IntruGuard-Security-red?style=for-the-badge&logo=shield)
![Status](https://img.shields.io/badge/Status-Active-green?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-Python_Flask_ML-blue?style=for-the-badge)

## 🛡️ Project Overview

**IntruGuard** is a sophisticated, modern Intrusion Detection System (IDS) that leverages Machine Learning to protect network environments and web applications. It provides a real-time monitoring interface and batch analysis capabilities to detect, classify, and visualize potential security threats.

By analyzing patterns in network traffic and web requests, IntruGuard can distinguish between benign user activity and various types of cyber attacks, providing security analysts with a professional SOC (Security Operations Center) dashboard experience.

---

## ✨ Key Features

### 1. Dual-Mode Intrusion Detection
- **Network Analysis:** Specialized detection for network-layer threats using features based on the NSL-KDD dataset (e.g., duration, protocol, service, byte counts).
- **Web Analysis:** Tailored for web application security, analyzing HTTP methods, URL lengths, payload entropy, and malicious signatures.

### 2. Live Traffic Monitoring
- **Real-Time Capture:** Uses `Scapy` to sniff live network packets directly from the interface.
- **Instant Classification:** Every captured packet is scrutinized and classified as "Benign" or "Attack" in real-time.
- **Visual Feedback:** A live-scrolling monitor that highlights suspicious activity as it happens.

### 3. Professional SOC Dashboard
- **Interactive Visualizations:** High-level metrics visualized through dynamic Pie charts (Attack vs. Benign) and Bar charts (Severity Levels).
- **Metric Cards:** At-a-glance view of total packets, attack counts, and system health.
- **Detailed Logs:** Comprehensive table views with severity badges and detailed packet information.

### 4. Advanced ML Pipeline
- **Auto-Detection:** The system intelligently identifies the type of dataset uploaded (Network vs. Web) and adjusts its analysis logic accordingly.
- **Accuracy Benchmarking:** If ground-truth labels are provided, IntruGuard automatically calculates and displays the model's accuracy.
- **Scalability:** Optimized to handle large datasets (tested with 100k+ rows) using pagination and efficient processing.

---

## 🚀 Technology Stack

### Backend
- **Framework:** Python / Flask
- **Data Science:** Pandas, NumPy
- **Machine Learning:** Scikit-learn (Random Forest, Label Encoding)
- **Serialization:** Joblib

### Frontend
- **Structure:** HTML5, Semantic UI
- **Styling:** Vanilla CSS3, Bootstrap 4 (SOC Dashboard Aesthetic)
- **Charts:** Chart.js
- **Animations:** Subtle micro-animations for a premium feel

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

3. **Train Models (Optional - Demo models included)**
   If you wish to retrain the models with fresh data:
   ```bash
   python retrain_model.py
   ```

4. **Run the Application**
   ```bash
   python app.py
   ```
   Access the dashboard at `http://127.0.0.1:5000`

---

## 📂 Project Structure

- `app.py`: The heart of the application; handles routing, ML logic, and packet sniffing.
- `models/`: Stores pre-trained `.pkl` models and label encoders.
- `templates/`: Contains HTML files for Dashboard, Live Monitor, and Login.
- `static/`: CSS and JS assets for the frontend experience.
- `uploads/`: Temporary storage for processed analysis results.

---

## 📊 Sample Visuals

> [!TIP]
> **Dashboard View:** The main dashboard features solid-colored metric cards and a gradient-style chart system for maximum readability.
> **Live Monitoring:** The live monitor uses a sleek "hacker-style" terminal output alongside structured data tables.

---

## 🛠️ Performance Tuning

To improve model accuracy for your specific environment, use the `retrain_model.py` script with your own datasets. The system is designed to achieve 95%+ accuracy on standard NIDS benchmarks.

---

## 📄 License
This project is for educational and security research purposes.

---
*Created with ❤️ by the IntruGuard Team*
