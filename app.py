from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import numpy as np
import joblib
import pefile
import pickle
import os
import json
import datetime

app = Flask(__name__, template_folder='templates', static_folder='static')

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'classifier.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'features.pkl')
RESULTS_FILE = os.path.join(os.path.dirname(__file__), 'past_results.json')
ZIP_FILE = 'AI-Based-Malware-Detection.zip'

try:
    clf = joblib.load(MODEL_PATH)
except FileNotFoundError:
    clf = None
    print("[ERROR] Model file 'classifier.pkl' not found!")

try:
    with open(FEATURES_PATH, 'rb') as f:
        features = pickle.load(f)
except FileNotFoundError:
    features = []
    print("[ERROR] Features file 'features.pkl' not found!")

@app.route('/')
def home():
    return render_template('dashboard.html', result=None, filename=None)

@app.route('/home')
def dashboard():
    return render_template('dashboard.html')

@app.route('/index')
def index():
    return render_template('index.html', result=None, filename=None)

@app.route('/predict', methods=['POST'])  
def predict():
    result = None
    filename = None

    if request.method == 'POST':
        if clf is None or not features:
            return render_template('index.html', result="Error: Model or features not loaded!", filename=None)

        file = request.files['file']
        if file:
            filename = file.filename
            try:
                pe = pefile.PE(data=file.read())
                extracted_features = []

                for feature in features:
                    try:
                        if feature == 'Machine':
                            extracted_features.append(pe.FILE_HEADER.Machine)
                        elif feature == 'SizeOfOptionalHeader':
                            extracted_features.append(pe.FILE_HEADER.SizeOfOptionalHeader)
                        elif feature == 'Characteristics':
                            extracted_features.append(pe.FILE_HEADER.Characteristics)
                        elif feature == 'DllCharacteristics':
                            extracted_features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
                        elif feature == 'MajorSubsystemVersion':
                            extracted_features.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
                        elif feature == 'Subsystem':
                            extracted_features.append(pe.OPTIONAL_HEADER.Subsystem)
                        elif feature == 'ImageBase':
                            extracted_features.append(pe.OPTIONAL_HEADER.ImageBase)
                        elif feature == 'SectionsMaxEntropy':
                            extracted_features.append(max((section.get_entropy() for section in pe.sections), default=0))
                        elif feature == 'ResourcesMaxEntropy' and hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                            extracted_features.append(max((entry.directory.get_entropy() for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries), default=0))
                        elif feature == 'ResourcesMinEntropy' and hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                            extracted_features.append(min((entry.directory.get_entropy() for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries), default=0))
                        elif feature == 'SectionsMinEntropy':
                            extracted_features.append(min((section.get_entropy() for section in pe.sections), default=0))
                        elif feature == 'VersionInformationSize' and hasattr(pe, 'VS_VERSIONINFO'):
                            extracted_features.append(len(pe.VS_VERSIONINFO))
                        elif feature == 'MajorOperatingSystemVersion':
                            extracted_features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
                        else:
                            extracted_features.append(0)
                    except AttributeError:
                        extracted_features.append(0)  

                extracted_features = np.array(extracted_features).reshape(1, -1)
                
                prediction = clf.predict(extracted_features)
                result = "Malicious" if prediction[0] == 0 else "Legitimate"
                
                # Save the result
                save_result(filename, result)
            except Exception as e:
                result = f"Error processing file: {str(e)}"

    return render_template('index.html', result=result, filename=filename)

def save_result(filename, result):
    past_results = load_past_results()
    past_results.append({
        'filename': filename,
        'result': result,
        'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    with open(RESULTS_FILE, 'w') as f:
        json.dump(past_results, f)

def load_past_results():
    if not os.path.exists(RESULTS_FILE):
        return []
    try:
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

@app.route('/past_reports')
def past_reports():
    past_results = load_past_results()
    return render_template('past_reports.html', results=past_results)

@app.route('/download')
def download():
    return send_from_directory(directory=os.path.dirname(__file__), path=ZIP_FILE, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
