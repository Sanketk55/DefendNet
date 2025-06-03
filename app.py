import streamlit
import streamlit as slt
import pickle
import pickle
from preprocess_url import FeatureExtraction  # Import your FeatureExtraction class

# Load the trained model
# Load the model
with open('voting_model.pkl', 'rb') as f:
    model = pickle.load(f)


# Function to extract features from URL
def extract_features(url):
    obj = FeatureExtraction(url)
    result = dict(obj.getFeaturesDict())
    
    # Ensure all 26 features are returned in the correct order
    features = [
        result['having_IP_Address'],
        result['URL_Length'],
        result['Shortining_Service'],
        result['having_At_Symbol'],
        result['double_slash_redirecting'],
        result['Prefix_Suffix'],
        result['having_Sub_Domain'],
        result['URL_Depth'],
        result['Domain_registeration_length'],
        result['Favicon'],
        result['port'],
        result['HTTPS_token'],
        result['Request_URL'],
        result['URL_of_Anchor'],
        result['Links_in_tags'],
        result['SFH'],
        result['Submitting_to_email'],
        result['Abnormal_URL'],
        result['Redirect'],
        result['on_mouseover'],
        result['RightClick'],
        result['popUpWidnow'],
        result['Iframe'],
        result['age_of_domain'],
        result['DNSRecord'],
        result['web_traffic']
    ]
    
    return features

# Streamlit App
slt.title("Malicious URL Classifier")
input_url = slt.text_area("Enter the URL")

if slt.button('Predict'):
    # Step 1: Extract Features
    features = extract_features(input_url)
    
    # Step 2: Predict
    result = model.predict([features])[0]
    
    # Step 3: Display Result
    print(result)
    if result == 0:
        slt.header('Legitimate URL')
    else:
        slt.header('Malicious URL')