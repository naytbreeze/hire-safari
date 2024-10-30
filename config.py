import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration with shared settings"""
    # Use environment variables with fallbacks
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', 'dev-csrf-key-change-in-production')
    
    # Database configuration - using absolute paths
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(basedir, "instance", "users.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload configuration - using absolute paths
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size 16MB
    
    # Flask configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }