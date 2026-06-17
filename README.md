# Explainable-Intrusion-Detection-System
An Explainable Multi-Class Intrusion Detection System using XGBoost and SHAP for cyber attack classification.

# 🛡️ Explainable Intrusion Detection System

An Explainable Multi-Class Intrusion Detection System built using XGBoost and SHAP for cyber attack classification on the UNSW-NB15 dataset.

## 📌 Project Overview

Cyber attacks continue to evolve and pose significant threats to modern networks. Traditional Intrusion Detection Systems often lack transparency and explainability.

This project combines Machine Learning and Explainable AI to classify network traffic into multiple attack categories while also identifying the key features responsible for predictions.

The system predicts:

* Analysis
* Backdoor
* DoS
* Exploits
* Fuzzers
* Generic
* Normal
* Reconnaissance
* Shellcode
* Worms

---

## 🚀 Features

* Multi-Class Cyber Attack Classification
* XGBoost Classifier
* SHAP Explainability
* Interactive Streamlit Dashboard
* Confidence Score Prediction
* Risk Level Assessment
* Cybersecurity-Oriented User Interface

---

## 📊 Dataset

Dataset Used:

UNSW-NB15 Dataset

The dataset contains network traffic records with features such as:

* Protocol Type
* Service
* State
* Source Bytes
* Destination Bytes
* Source TTL
* Destination TTL
* Connection Statistics

---

## 🧠 Machine Learning Pipeline

1. Data Preprocessing
2. Label Encoding
3. Train-Test Split
4. Random Forest Baseline
5. XGBoost Training
6. Model Evaluation
7. SHAP Explainability
8. Streamlit Deployment

---

## 📈 Model Performance

### XGBoost

* Accuracy: 87.96%
* Macro F1 Score: 0.58
* Weighted F1 Score: 0.88

---

## 🔍 Important Features

SHAP analysis identified the following important features:

1. dttl
2. sttl
3. sbytes
4. service
5. ct_srv_dst

These features significantly influence cyber attack classification.

---

## 🖥️ Streamlit Application

The dashboard allows users to:

* Input network traffic features
* Predict attack categories
* View confidence scores
* Assess threat severity
* Understand attack descriptions

---

## 🛠️ Tech Stack

* Python
* Pandas
* NumPy
* Scikit-Learn
* XGBoost
* SHAP
* Streamlit
* Matplotlib

---

## ▶️ Run Locally

```bash
pip install -r requirements.txt

streamlit run app.py
```

---

## 👨‍💻 Author

Devam Dadhia

B.Tech Computer Science & Engineering (Cyber Security)

Thakur College of Engineering & Technology

Mumbai, India
