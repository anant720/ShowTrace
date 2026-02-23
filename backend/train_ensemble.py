import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import recall_score, precision_score
import joblib
import logging
try:
    from app.ml.features import FeatureEngineer
except ImportError:
    # Local fallback for standalone training
    pass

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shadowtrace.ml.trainer")

class EnterpriseTrainer:
    """
    ShadowTrace Autonomous Trainer v1.0
    Automates the calibration of Layer 1 (XGBoost) and Layer 4 (Anomaly) engines.
    """

    def __init__(self, data_path: str = "backend/data/phishing_dataset.csv"):
        self.data_path = data_path
        self.model_dir = "app/ml/models"
        os.makedirs(self.model_dir, exist_ok=True)

    def load_and_preprocess(self):
        logger.info(f"Loading dataset from {self.data_path}...")
        if not os.path.exists(self.data_path):
            logger.error(f"Dataset not found at {self.data_path}. Please provide a valid CSV.")
            return None
        try:
            df = pd.read_csv(self.data_path)
            return df
        except Exception as e:
            logger.error(f"Failed to load data: {e}")
            return None

    def train_ensemble(self):
        df = self.load_and_preprocess()
        if df is None: return

        # Validate core columns
        if 'label' not in df.columns:
            logger.error("Dataset must contain a 'label' column (1 for phishing, 0 for safe).")
            return

        target = 'label'
        features = [col for col in df.columns if col != target]

        X = df[features]
        y = df[target]

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # --- Layer 1: XGBoost ---
        logger.info("Training Layer 1: XGBoost (Lexical High-Precision)...")
        l1_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            objective='binary:logistic',
            random_state=42
        )
        l1_model.fit(X_train, y_train)

        # --- Layer 4: Isolation Forest ---
        logger.info("Training Layer 4: Isolation Forest (Anomaly Context)...")
        l4_model = IsolationForest(contamination=0.03, random_state=42)
        l4_model.fit(X_train[y_train == 0])

        # Serialization
        joblib.dump(l1_model, os.path.join(self.model_dir, "l1_xgb.joblib"))
        joblib.dump(l4_model, os.path.join(self.model_dir, "l4_iso.joblib"))
        logger.info("Models serialized to app/ml/models/")

if __name__ == "__main__":
    trainer = EnterpriseTrainer()
    trainer.train_ensemble()
