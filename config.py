import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class Config:
    # General Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    DB_HOST = os.getenv('DB_HOST')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_NAME = os.getenv('DB_NAME')
    DB_PORT = os.getenv('DB_PORT')

    # Paystack and WhatsApp
    PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY')
    PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
    WHATSAPP_LINK = os.getenv('WHATSAPP_LINK')

    # Email (SMTP) Configuration - Default Email
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv("EMAIL_USER_1")
    MAIL_PASSWORD = os.getenv("EMAIL_PASS_1")

    # Added for compatibility
    EMAIL_HOST_USER = MAIL_USERNAME
    EMAIL_HOST_PASSWORD = MAIL_PASSWORD


# List of all available email accounts for switching/rotation
    EMAIL_ACCOUNTS = [
    {
        "EMAIL_HOST_USER": os.getenv("EMAIL_USER_1"),
        "EMAIL_HOST_PASSWORD": os.getenv("EMAIL_PASS_1")
    },
    {
        "EMAIL_HOST_USER": os.getenv("EMAIL_USER_2"),
        "EMAIL_HOST_PASSWORD": os.getenv("EMAIL_PASS_2")
    },
    {
        "EMAIL_HOST_USER": os.getenv("EMAIL_USER_5"),
        "EMAIL_HOST_PASSWORD": os.getenv("EMAIL_PASS_5")
    }
]
# adrena_ai
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    WOLFRAM_APP_ID = os.getenv("WOLFRAM_APP_ID")