import os
from dotenv import load_dotenv

load_dotenv()

def get_otx_key() -> str:
    key = os.getenv("OTX_API_KEY")
    if not key:
        raise EnvironmentError("OTX_API_KEY is not set in .env")
    return key



