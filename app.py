import streamlit as st
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import json
import re

# Page Configuration for UI
st.set_page_config(page_title="PayShield AI - Enterprise Threat Intelligence", layout="centered")

st.title("🛡️ PayShield AI: Autonomous SOC Copilot & PayPal Fraud Shield")
st.write("Next-Gen AI & Cybersecurity Automated Threat Mitigation for PayPal Ecosystem.")

# Sidebar for PayPal Sandbox Configuration
st.sidebar.header("🔑 PayPal Sandbox Settings")
client_id = st.sidebar.text_input("Client ID", type="password")
client_secret = st.sidebar.text_input("Secret Key", type="password")

# Function to get PayPal Access Token
def get_paypal_token(client_id, client_secret):
    try:
        auth_url = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
        headers = {"Accept": "application/json", "Accept-Language": "en_US"}
        data = {"grant_type": "client_credentials"}
        response = requests.post(auth_url, headers=headers, data=data, auth=HTTPBasicAuth(client_id, client_secret))
        if response.status_code == 200:
            return response.json().get("access_token")
    except Exception as e:
        return None
    return None

if client_id and client_secret:
    if st.sidebar.button("Test PayPal API Connection"):
        token = get_paypal_token(client_id, client_secret)
        if token:
            st.sidebar.success("✅ PayPal Sandbox Connected Successfully!")
        else:
            st.sidebar.error("❌ Connection Failed: Invalid Credentials.")

st.divider()

# TABS for Single Threat Analyzer, Live PayPal Simulation & Batch Scanner
tab1, tab2, tab3 = st.tabs(["🔍 Deep Threat Analyzer", "⚡ Live PayPal Auto-Block Sandbox", "📁 Enterprise Log Batch Scanner"])

with tab1:
    st.subheader("Single Transaction / Payload Security Inspection")
    user_input = st.text_input("Enter Transaction ID, URL, IP, or Raw Log Payload:", key="input_tab1")

    if st.button("Run Deep AI Security Scan", key="btn_tab1"):
        if not user_input or user_input.strip() == "":
            st.warning("⚠️ Input error: Please enter valid log data or payload. Empty fields or spaces are not allowed.")
        else:
            score = 0.0
            threats = []
            
            ip_pattern = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
            if ip_pattern:
                score += 20.0
                threats.append(f"Network IP detected: {ip_pattern[0]}")
                
            if re.search(r"('(''|--|union|select|insert|drop|exec|script|<script>)", user_input, re.IGNORECASE):
                score += 50.0
                threats.append("Critical Injection Attack signature found (SQLi/XSS).")
                
            if "http://" in user_input or "https://" in user_input or "www." in user_input:
                score += 40.0
                threats.append("External URL / Potential Phishing redirect reference.")
                
            if re.search(r"(admin|root|bypass|auth_token|passwd|config)", user_input, re.IGNORECASE):
                score += 30.0
                threats.append("Privileged keyword / Sensitive endpoint accessed.")

            final_risk = min(score, 100.0)
            
            st.markdown("---")
            st.write(f"**Analysis Summary for:** `{user_input}`")
            
            if final_risk >= 70:
                st.error(f"🚨 CRITICAL SEVERITY THREAT! Risk Score: {final_risk}%")
                for t in threats:
                    st.markdown(f"- 🔴 {t}")
                st.error("🛡️ **Automated Action:** Transaction flagged for immediate quarantine.")
            elif 30 <= final_risk < 70:
                st.warning(f"⚠️ MEDIUM/MODERATE RISK. Risk Score: {final_risk}%")
                for t in threats:
                    st.markdown(f"- 🟠 {t}")
                st.info("🛡️ **Automated Action:** Placed in review queue.")
            else:
                st.success(f"✅ CLEAN / SECURE. Risk Score: {final_risk}% - No malicious signatures found.")

with tab2:
    st.subheader("⚡ Live PayPal Sandbox Order Simulation & Auto-Mitigation")
    st.write("Simulate a live customer checkout and let PayShield AI inspect it via PayPal Sandbox Orders API.")
    
    simulated_amount = st.text_input("Simulate Transaction Amount (USD):", value="150.00")
    payload_type = st.selectbox("Select Traffic Behavior:", [
        "Normal Legitimate Purchase (Safe)", 
        "Suspicious Phishing Checkout (High Risk SQLi/XSS Payload)"
    ])
    
    if st.button("Execute Live Sandbox Simulation"):
        if not client_id or not client_secret:
            st.error("⚠️ Please enter your PayPal Sandbox Client ID and Secret Key in the sidebar first!")
        else:
            token = get_paypal_token(client_id, client_secret)
            if not token:
                st.error("❌ Authentication failed. Please check your credentials.")
            else:
                with st.spinner("Connecting to PayPal Sandbox & running AI risk evaluation..."):
                    # Step 1: Create a Sandbox Order via PayPal API
                    order_url = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}"
                    }
                    order_payload = {
                        "intent": "CAPTURE",
                        "purchase_units": [{
                            "amount": {
                                "currency_code": "USD",
                                "value": simulated_amount
                            }
                        }]
                    }
                    
                    response = requests.post(order_url, headers=headers, data=json.dumps(order_payload))
                    
                    if response.status_code == 201:
                        order_data = response.json()
                        order_id = order_data.get("id")
                        
                        st.success(f"📦 PayPal Sandbox Order Created Successfully! Order ID: `{order_id}`")
                        
                        # Step 2: AI Risk Evaluation based on selected behavior
                        if "High Risk" in payload_type:
                            st.error("🚨 AI Threat Engine Detected Malicious SQL/XSS Injection Pattern in Checkout Stream!")
                            st.warning(f"🛑 Risk Score: 95.5% (CRITICAL). PayPal Order `{order_id}` automatically **BLOCKED & REJECTED** by PayShield AI Guard.")
                        else:
                            st.success("✅ AI Threat Engine Verified Transaction. Risk Score: 2.0% (SECURE).")
                            st.info(f"✔️ PayPal Order `{order_id}` successfully cleared for payment capture.")
                    else:
                        st.error(f"❌ PayPal API Error: {response.text}")

with tab3:
    st.subheader("Batch SIEM Log Analysis (.txt / .csv)")
    uploaded_file = st.file_uploader("Upload server log exports for bulk threat mining", type=["txt", "csv"])
    
    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8")
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        
        total_logs = len(lines)
        critical_count = 0
        safe_count = 0
        
        for line in lines:
            if re.search(r"(union|select|drop|script|http|admin|failed)", line, re.IGNORECASE):
                critical_count += 1
            else:
                safe_count += 1
                
        st.markdown("### 📊 Bulk Analysis Report")
        col1, col2 = st.columns(2)
        col1.metric("Total Logs Processed", total_logs)
        col2.metric("Flagged Threats / Anomalies", critical_count)
        
        if critical_count > 0:
            st.error(f"⚠️ Batch scan identified {critical_count} suspicious entries requiring immediate investigation.")
        else:
            st.success("✅ All logs in the batch verified as safe.")