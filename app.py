import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

# Load the model and scaler
model = joblib.load('best_rf_model.pkl')
scaler = joblib.load('scaler.pkl')

# Define a preprocessing function
def preprocess_data(data):
    """
    Preprocess the incoming data by applying log transformation to srcbytes and dstbytes.
    """
    data = data.copy()
    data['log_srcbytes'] = np.log1p(data['srcbytes'])
    data['log_dstbytes'] = np.log1p(data['dstbytes'])
    data.drop(['srcbytes', 'dstbytes'], axis=1, inplace=True)
    return data

# Streamlit app
def main():
    st.title("Network Anomaly Detection")

    # User input fields
    srcbytes = st.number_input('Source Bytes')
    dstbytes = st.number_input('Destination Bytes')
    protocoltype = st.selectbox('Protocol Type', ['tcp', 'udp', 'icmp'])
    service = st.selectbox('Service', ['http', 'ftp', 'smtp', 'dns', 'other'])
    flag = st.selectbox('Flag', ['SF', 'S1', 'REJ', 'RSTO', 'other'])

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
