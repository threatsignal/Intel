import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    TELEGRAM_API_ID = os.getenv("TELEGRAM_API_ID")
    TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
    
    # Parse target channels into a list
    channels_env = os.getenv("TARGET_CHANNELS", "")
    TARGET_CHANNELS = [ch.strip() for ch in channels_env.split(",")] if channels_env else []

    @classmethod
    def validate(cls):
        missing = []
        if not cls.TELEGRAM_API_ID: missing.append("TELEGRAM_API_ID")
        if not cls.TELEGRAM_API_HASH: missing.append("TELEGRAM_API_HASH")
        if not cls.GEMINI_API_KEY: missing.append("GEMINI_API_KEY")
        
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
