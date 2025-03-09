
# AI-Based Malware Detector

## Overview
This is an AI-based malware detection application that uses machine learning to classify PE (Portable Executable) files (such as .exe and .dll) as either malware or legitimate. The application is built using Python and integrates a graphical user interface (GUI) created with PyQt5.

## Features
- Upload PE files or scan a folder for PE files.
- Predict whether the uploaded files are malicious or legitimate using a pre-trained machine learning model.
- View past scan reports.
- Clear scanning history.

## Requirements
- Python 3.x
- PyQt5
- scikit-learn
- joblib
- pefile
- numpy
- matplotlib

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/malware-detector.git
   cd malware-detector
   ```

2. Install the required Python packages:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
1. Run the application:
   ```sh
   python main.py
   ```

2. Use the graphical interface to upload files, scan folders, and view results.

## Building Executable
To create a standalone executable for Windows:
1. Install `auto-py-to-exe`:
   ```sh
   pip install auto-py-to-exe
   ```

2. Run `auto-py-to-exe`:
   ```sh
   auto-py-to-exe
   ```

3. Configure the conversion in the GUI:
   - Select `main.py` as the script location.
   - Choose "Onefile" and "Window Based" options.
   - Add any additional files (e.g., `classifier.pkl`, `features.pkl`).
   - Specify the output directory and other settings as needed.

4. Click the "CONVERT .PY TO .EXE" button to generate the executable.

## Files
- `main.py`: The main script that runs the application.
- `classifier.pkl`: The pre-trained machine learning model.
- `features.pkl`: The feature set used by the model.
- `past_results.json`: JSON file to store past scan results.

## Logging
The application logs its activities to a file named `malware_detector.log`.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements
- [PEfile](https://github.com/erocarrera/pefile): A Python module to read and work with PE (Portable Executable) files.
- [scikit-learn](https://scikit-learn.org/): A machine learning library for Python.
- [PyQt5](https://riverbankcomputing.com/software/pyqt/intro): A set of Python bindings for Qt libraries, used to create the GUI.
