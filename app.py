#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)

def normalize_url(url):
    """Normalize URL to ensure consistent format"""
    if not url.startswith(('http://', 'https://')):
        # Try https first, then http if https fails
        try:
            import requests
            test_url = f"https://{url}"
            response = requests.head(test_url, timeout=5, allow_redirects=True)
            return test_url
        except:
            return f"http://{url}"
    return url

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            url = request.form["url"]
            # Normalize URL format
            normalized_url = normalize_url(url)
            print(f"Original URL: {url}")
            print(f"Normalized URL: {normalized_url}")
            
            obj = FeatureExtraction(normalized_url)
            x = np.array(obj.getFeaturesList()).reshape(1,30) 

            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0,0]
            y_pro_non_phishing = gbc.predict_proba(x)[0,1]
            
            print(f"URL: {normalized_url}")
            print(f"Prediction: {y_pred}")
            print(f"Phishing probability: {y_pro_phishing}")
            print(f"Non-phishing probability: {y_pro_non_phishing}")
            
            # According to training data label definition:
            # y_pred = 1 means safe website
            # y_pred = -1 means phishing website
            # Safe probability should be non-phishing probability
            safe_probability = y_pro_non_phishing
                
            print(f"Safe probability: {safe_probability}")
            return render_template('index.html', xx=round(safe_probability,2), url=normalized_url)
        except Exception as e:
            print(f"Error processing URL: {e}")
            return render_template('index.html', xx=-1, url="")
    return render_template("index.html", xx=-1)


if __name__ == "__main__":
    app.run(debug=True)
