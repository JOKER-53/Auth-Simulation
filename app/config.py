import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-auth-simulation-secret-key-2026')
    SIMULATION_MODE = os.environ.get('SIMULATION_MODE', 'vulnerable')  # 'vulnerable' or 'secure'
    TOKEN_TTL_SECONDS = int(os.environ.get('TOKEN_TTL_SECONDS', 180))  # 3 minutes for demo
