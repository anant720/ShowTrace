import requests
import os
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shadowtrace.data.sourcer")

DATA_DIR = "backend/data"
MIRRORS = [
    "https://raw.githubusercontent.com/clarkzjw/phishing-urls/master/phishing-urls.txt",
    "https://raw.githubusercontent.com/openphish/feed/master/feed.txt"
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

def download_active_phishes():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    for url in MIRRORS:
        logger.info(f"Attempting download from {url}...")
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
            response.raise_for_status()
            
            ext = ".txt" if ".txt" in url else ".csv"
            save_path = os.path.join(DATA_DIR, f"raw_phish{ext}")
            
            with open(save_path, 'wb') as f:
                f.write(response.content)
            logger.info(f"Phish data saved to {save_path}")
            return save_path
        except Exception as e:
            logger.error(f"Download from {url} failed: {e}")
    return None

def bootstrap_dataset():
    phish_file = download_active_phishes()
    if not phish_file:
        logger.error("All mirrors failed. Manual dataset intervention required.")
        return
    
    if phish_file.endswith('.txt'):
        with open(phish_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        phish_df = pd.DataFrame({'url': urls, 'label': 1})
    else:
        phish_df = pd.read_csv(phish_file)
        # Handle PhishTank CSV format if it was the .gz or .csv
        if 'url' in phish_df.columns:
            phish_df = phish_df[['url']]
        phish_df['label'] = 1
    
    # Standard Safe Baseline
    safe_urls = [
        "https://www.google.com", "https://www.microsoft.com", "https://www.apple.com",
        "https://www.github.com", "https://www.amazon.com", "https://www.facebook.com",
        "https://www.netflix.com", "https://www.paypal.com", "https://www.cnn.com",
        "https://www.wikipedia.org", "https://www.duckduckgo.com", "https://www.reddit.com",
        "https://www.linkedin.com", "https://www.twitter.com", "https://www.instagram.com"
    ]
    safe_df = pd.DataFrame({'url': safe_urls, 'label': 0})
    
    dataset = pd.concat([phish_df.head(5000), safe_df], ignore_index=True) # Limit to 5k for bootstrap
    dataset_path = os.path.join(DATA_DIR, "phishing_dataset_raw.csv")
    dataset.to_csv(dataset_path, index=False)
    logger.info(f"Bootstrap dataset created at {dataset_path} with {len(dataset)} entries.")

if __name__ == "__main__":
    bootstrap_dataset()
