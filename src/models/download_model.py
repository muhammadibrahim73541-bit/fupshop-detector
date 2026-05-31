import os
import requests
from huggingface_hub import hf_hub_download

def download_model():
    """Download model from Hugging Face Hub at runtime"""
    repo_id = "mibrahimalpha/fupshop-detector"
    model_dir = os.path.dirname(os.path.abspath(__file__))
    
    files = [
        "src/models/fupshop_model.pkl",
        "src/models/fupshop_model_features.json",
        "src/models/fupshop_model_metrics.json"
    ]
    
    for file in files:
        local_path = os.path.join(model_dir, os.path.basename(file))
        if not os.path.exists(local_path):
            print(f"Downloading {file}...")
            try:
                downloaded = hf_hub_download(
                    repo_id=repo_id,
                    filename=file,
                    repo_type="space",
                    local_dir=model_dir,
                    local_dir_use_symlinks=False
                )
                print(f"✅ Downloaded to {downloaded}")
            except Exception as e:
                print(f"❌ Failed to download {file}: {e}")
                # Fallback: use dummy model or raise error
                raise

if __name__ == "__main__":
    download_model()
