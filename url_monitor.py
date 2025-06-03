import time
import tkinter as tk
from selenium import webdriver
import joblib
from preprocess_url import FeatureExtraction

# Load the trained model
model = joblib.load('malicious_url_classifier.pkl')

# Function to extract features
def extraction(url):
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

# Function to classify the URL
def classify_url(url):
    features = extraction(url)
    features = [features]  # Reshape for the model
    prediction = model.predict(features)
    return "malicious" if prediction == 1 else "legitimate"

# Function to display a warning popup
def show_warning(url):
    root = tk.Tk()
    root.title("Warning!")
    root.geometry("300x100")
    label = tk.Label(root, text=f"Malicious URL detected:\n{url}", fg="red", font=("Arial", 12))
    label.pack(pady=20)
    root.mainloop()

# Main function to monitor the browser URL
def monitor_browser():
    # Initialize the browser (e.g., Chrome)
    driver = webdriver.Chrome()  # Make sure you have the ChromeDriver installed
    driver.get("https://www.google.com")  # Start with a default page

    previous_url = ""
    while True:
        current_url = driver.current_url
        if current_url != previous_url:
            print(f"Current URL: {current_url}")
            result = classify_url(current_url)
            print(f"Classification: {result}")

            if result == "malicious":
                show_warning(current_url)

            previous_url = current_url

        time.sleep(2)  # Check the URL every 2 seconds

# Run the monitor
monitor_browser()