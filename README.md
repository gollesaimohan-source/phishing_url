# Phishing URL Detector

A machine learning-based application to detect phishing URLs using Random Forest.

## Project Structure
- `data/`: Contains the datasets.
- `models/`: Contains the trained models.
- `docs/`: Feature documentation.
- `train_model.py`: Script to train the model.
- `app.py`: Flask application for serving API.
- `detector.py`: Feature extraction logic.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Train the model (optional, pretrained models are in `models/`):
   ```bash
   python train_model.py
   ```

3. Run the API:
   ```bash
   python app.py
   ```
