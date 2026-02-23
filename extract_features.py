import pandas as pd
import os
import tqdm
from app.ml.features import FeatureEngineer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shadowtrace.ml.extractor")

def run_extraction():
    raw_path = 'backend/data/phishing_dataset_raw.csv'
    out_path = 'backend/data/phishing_dataset.csv'
    
    if not os.path.exists(raw_path):
        logger.error(f"Raw dataset not found at {raw_path}")
        return

    logger.info("Loading raw dataset...")
    df = pd.read_csv(raw_path)
    
    features_list = []
    logger.info(f"Extracting features for {len(df)} URLs...")
    
    for _, row in tqdm.tqdm(df.iterrows(), total=len(df)):
        url = row['url']
        label = row['label']
        
        # We pass an empty dict for domain_sigs as we are focusing on Lexical signals here
        # In production, we'd enrich this with live WHOIS data.
        try:
            feats = FeatureEngineer.lexical_features(url, {})
            feats['brand_similarity'] = FeatureEngineer.calculate_brand_similarity(url)
            feats['label'] = label
            features_list.append(feats)
        except Exception as e:
            logger.warn(f"Failed to extract features for {url}: {e}")

    final_df = pd.DataFrame(features_list)
    final_df.to_csv(out_path, index=False)
    logger.info(f"Feature dataset saved to {out_path} with {len(final_df)} samples.")

if __name__ == "__main__":
    run_extraction()
