import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

# Load the model and scaler
model = joblib.load('random_forest_model.pkl')
scaler = joblib.load('scaler.pkl')

# Define a preprocessing function
def preprocess_data(data):
    data = data.copy()
    data['log_srcbytes'] = np.log1p(data['srcbytes'])
    data['log_dstbytes'] = np.log1p(data['dstbytes'])
    data.drop(['srcbytes', 'dstbytes'], axis=1, inplace=True)
    return data

# Streamlit app
def main():
    st.title("Network Anomaly Detection")

    # Protocols
    protocols = ['tcp', 'udp', 'icmp']
    # Services
    services = [
        'ftp_data', 'other', 'private', 'http', 'remote_job', 'name', 'netbios_ns',
        'eco_i', 'mtp', 'telnet', 'finger', 'domain_u', 'supdup', 'uucp_path',
        'Z39_50', 'smtp', 'csnet_ns', 'uucp', 'netbios_dgm', 'urp_i', 'auth',
        'domain', 'ftp', 'bgp', 'ldap', 'ecr_i', 'gopher', 'vmnet', 'systat',
        'http_443', 'efs', 'whois', 'imap4', 'iso_tsap', 'echo', 'klogin', 'link',
        'sunrpc', 'login', 'kshell', 'sql_net', 'time', 'hostnames', 'exec',
        'ntp_u', 'discard', 'nntp', 'courier', 'ctf', 'ssh', 'daytime', 'shell',
        'netstat', 'pop_3', 'nnsp', 'IRC', 'pop_2', 'printer', 'tim_i', 'pm_dump',
        'red_i', 'netbios_ssn', 'rje', 'X11', 'urh_i', 'http_8001', 'aol',
        'http_2784', 'tftp_u', 'harvest'
    ]
    # Flags
    flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'S2', 'OTH']

    # User input fields
    srcbytes = st.number_input('Source Bytes', min_value=0.0, step=1.0)
    dstbytes = st.number_input('Destination Bytes', min_value=0.0, step=1.0)
    protocoltype = st.selectbox('Protocol Type', protocols)
    dsthostsrvcount = st.number_input('Destination Host Service Count', min_value=0, max_value=255, step=1)
    service = st.selectbox('Service', services)
    flag = st.selectbox('Flag', flags)

    # Create a DataFrame from user inputs
    input_data = pd.DataFrame({
        'srcbytes': [srcbytes],
        'dstbytes': [dstbytes],
        'protocoltype_' + protocoltype: [1],
        'service_' + service: [1],
        'flag_' + flag: [1]
    })

    # Fill missing dummy columns with 0
    expected_columns = model.feature_importances_.shape[0]  # or you can use a predefined list
    missing_cols = set(expected_columns) - set(input_data.columns)
    for c in missing_cols:
        input_data[c] = 0

    # Preprocess the input data
    preprocessed_data = preprocess_data(input_data)

    # Scale the data
    preprocessed_data_scaled = scaler.transform(preprocessed_data)

    # Make prediction
    prediction = model.predict(preprocessed_data_scaled)

    # Display the prediction
    st.write("Predicted Attack Type:", prediction[0])

if __name__ == "__main__":
    main()
