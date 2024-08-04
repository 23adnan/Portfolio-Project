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
    col1, col2, col3 = st.columns(3)
    with col1:
        protocoltype = st.selectbox('Protocol Type', protocols)
    with col2:
        service = st.selectbox('Service', services)
    with col3:
        flag = st.selectbox('Flag', flags)

    duration = st.number_input('Duration', min_value=0, max_value=42908, step=1)
    srcbytes = st.number_input('Source Bytes', min_value=0, step=1)
    dstbytes = st.number_input('Destination Bytes', min_value=0, step=1)

    dsthostsrvcount = st.number_input('Dst Host Srv Count', min_value=0, max_value=255, step=1)
    loggedin = st.selectbox('Logged In', [0, 1])
    dsthostdiffsrvrate = st.slider('Dst Host Diff Srv Rate', min_value=0.0, max_value=1.0, step=0.01)
    dsthostserrorrate = st.slider('Dst Host Serror Rate', min_value=0.0, max_value=1.0, step=0.01)

    count = st.number_input('Count', min_value=0, max_value=1000, step=1)
    srvcount = st.number_input('Srv Count', min_value=0, max_value=511, step=1)
    dsthostsamesrcportrate = st.slider('Dst Host Same Src Port Rate', min_value=0.0, max_value=1.0, step=0.01)

    serrorrate = st.slider('Serror Rate', min_value=0.0, max_value=1.0, step=0.01)
    dsthostcount = st.number_input('Dst Host Count', min_value=0, max_value=255, step=1)
    dsthostsamesrvrate = st.slider('Dst Host Same Srv Rate', min_value=0.0, max_value=1.0, step=0.01)

    dsthostsrvserrorrate = st.slider('Dst Host Srv Serror Rate', min_value=0.0, max_value=1.0, step=0.01)
    numaccessfiles = st.number_input('Num Access Files', min_value=0, max_value=10, step=1)
    numfailedlogins = st.number_input('Num Failed Logins', min_value=0, max_value=5, step=1)

    wrongfragment = st.number_input('Wrong Fragment', min_value=0, max_value=3, step=1)
    numroot = st.number_input('Num Root', min_value=0, max_value=10000, step=1)
    srvrerrorrate = st.slider('Srv Rerror Rate', min_value=0.0, max_value=1.0, step=0.01)

    srvdiffhostrate = st.slider('Srv Diff Host Rate', min_value=0.0, max_value=1.0, step=0.01)
    lastflag = st.number_input('Last Flag', min_value=0, max_value=21, step=1)
    hot = st.number_input('Hot', min_value=0, max_value=100, step=1)

    numcompromised = st.number_input('Num Compromised', min_value=0, max_value=10000, step=1)
    isguestlogin = st.selectbox('Is Guest Login', [0, 1])
    rootshell = st.selectbox('Root Shell', [0, 1])
    dsthostsrvrerrorrate = st.slider('Dst Host Srv Rerror Rate', min_value=0.0, max_value=1.0, step=0.01)

    # Create a DataFrame from user inputs
    input_data = pd.DataFrame({
        'duration': [duration],
        'srcbytes': [srcbytes],
        'dstbytes': [dstbytes],
        'dsthostsrvcount': [dsthostsrvcount],
        'loggedin': [loggedin],
        'dsthostdiffsrvrate': [dsthostdiffsrvrate],
        'dsthostserrorrate': [dsthostserrorrate],
        'count': [count],
        'srvcount': [srvcount],
        'dsthostsamesrcportrate': [dsthostsamesrcportrate],
        'serrorrate': [serrorrate],
        'dsthostcount': [dsthostcount],
        'dsthostsamesrvrate': [dsthostsamesrvrate],
        'dsthostsrvserrorrate': [dsthostsrvserrorrate],
        'numaccessfiles': [numaccessfiles],
        'numfailedlogins': [numfailedlogins],
        'wrongfragment': [wrongfragment],
        'numroot': [numroot],
        'srvrerrorrate': [srvrerrorrate],
        'srvdiffhostrate': [srvdiffhostrate],
        'lastflag': [lastflag],
        'hot': [hot],
        'numcompromised': [numcompromised],
        'isguestlogin': [isguestlogin],
        'rootshell': [rootshell],
        'protocoltype_' + protocoltype: [1],
        'service_' + service: [1],
        'flag_' + flag: [1],
        'dsthostsrvrerrorrate': [dsthostsrvrerrorrate]
    })

    # Fill missing dummy columns with 0
    expected_columns = set(X_train.columns)  # Replace with your actual feature names if needed
    missing_cols = expected_columns - set(input_data.columns)
    for c in missing_cols:
        input_data[c] = 0

    # Reorder columns to match training set order
    input_data = input_data[X_train.columns]

    # Preprocess the input data
    preprocessed_data = preprocess_data(input_data)

    # Scale the data
    preprocessed_data_scaled = scaler.transform(preprocessed_data)

    # Predict button
    if st.button('Predict'):
        # Make prediction
        prediction = model.predict(preprocessed_data_scaled)

        # Display the prediction
        st.write("Predicted Attack Type:", prediction[0])

if __name__ == "__main__":
    main()
