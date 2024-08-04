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
    col1, col2, col3 = st.columns(3)  # Create three columns for Protocol Type, Service, and Flag
    with col1:
        protocoltype = st.selectbox('Protocol Type', protocols, help="Type of protocol used in the connection.")
    with col2:
        service = st.selectbox('Service', services, help="Network service on the destination, e.g., http, ftp, smtp, etc.")
    with col3:
        flag = st.selectbox('Flag', flags, help="Normal or error status of the connection.")

    col4, col5, col6 = st.columns(3)  # Split the layout into three columns for duration, source, and destination bytes
    with col4:
        duration = st.number_input('Duration', min_value=0, max_value=42908, step=1, help="Length of time duration of the connection.")
    with col5:
        srcbytes = st.number_input('Source Bytes', min_value=0.0, step=1.0, help="Total number of data bytes from source to destination.")
    with col6:
        dstbytes = st.number_input('Destination Bytes', min_value=0.0, step=1.0, help="Total number of data bytes from destination to source.")

    dsthostsrvcount = st.number_input('Destination Host Service Count', min_value=0, max_value=255, step=1, help="Number of connections having the same port number.")
    loggedin = st.selectbox('Logged In', [0, 1], format_func=lambda x: 'No' if x == 0 else 'Yes', help="Indicates if the connection is from a logged-in user.")
    dsthostdiffsrvrate = st.number_input('Destination Host Different Server Rate', min_value=0.0, max_value=1.0, step=0.01, help="Rate of connections to different services on the same host.")
    dsthostserrorrate = st.number_input('Destination Host Error Rate', min_value=0.0, max_value=1.0, step=0.01, help="Rate of connections with errors to the same destination host.")
    count = st.number_input('Count', min_value=0, max_value=1000, step=1, help="Number of connections to the same destination host as the current connection in the past two seconds.")
    srvcount = st.number_input('Service Count', min_value=0, max_value=1000, step=1, help="Number of connections to the same service as the current connection in the past two seconds.")
    dsthostsamesrcportrate = st.number_input('Destination Host Same Source Port Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections that were to the same source port, among the connections aggregated in dst_host_srv_count.")
    serrorrate = st.number_input('Serror Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections with the flag s0, s1, s2, or s3 among connections aggregated in count.")
    dsthostcount = st.number_input('Destination Host Count', min_value=0, max_value=255, step=1, help="Number of connections with the same destination host IP address.")
    dsthostsamesrvrate = st.number_input('Destination Host Same Service Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections to the same service among connections aggregated in dst_host_count.")
    dsthostsrvserrorrate = st.number_input('Destination Host Service Error Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections with the flag s0, s1, s2, or s3 among connections aggregated in dst_host_srv_count.")
    numaccessfiles = st.number_input('Number of Access Files', min_value=0, max_value=10, step=1, help="Number of operations on access control files.")
    numfailedlogins = st.number_input('Number of Failed Logins', min_value=0, max_value=5, step=1, help="Count of failed login attempts.")
    wrongfragment = st.number_input('Wrong Fragment', min_value=0, max_value=3, step=1, help="Total number of wrong fragments in this connection.")
    numroot = st.number_input('Number of Root Accesses', min_value=0, max_value=10000, step=1, help="Number of 'root' accesses or operations performed as root in the connection.")
    srvrerrorrate = st.number_input('Server Error Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections that have activated the flag REJ, among the connections aggregated in srv_count.")
    srvdiffhostrate = st.number_input('Server Different Host Rate', min_value=0.0, max_value=1.0, step=0.01, help="Percentage of connections that were to different destination machines, among the connections aggregated in srv_count.")
    lastflag = st.number_input('Last Flag', min_value=0, max_value=21, step=1, help="Total number of last flags in this connection.")

    # Create a DataFrame from user inputs
    input_data = pd.DataFrame({
        'srcbytes': [srcbytes],
        'dstbytes': [dstbytes],
        'duration': [duration],
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
