import os
from datetime import timedelta

# Base directory path
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration with shared settings"""
    # Production-ready secret keys
    SECRET_KEY = 'xj7ah8n2k9p5v3m4q6w8t2z5y8n9c4p6'  
    WTF_CSRF_SECRET_KEY = 'r9t6m2k5n8p3v6b9c4x7q2z5'  
    
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size 16MB
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Your existing email configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'naturebreeze@gmail.com'
    MAIL_PASSWORD = 'jiun qvrt kqek jbna'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEFAULT_SENDER = 'naturebreeze@gmail.com'
    
    # SQLAlchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True

class DevelopmentConfig(Config):
    """Development configuration for local SQLite database"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(basedir, "instance", "users.db")}'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'connect_args': {'check_same_thread': False}
    }

class ProductionConfig(Config):
    """Production configuration for MySQL database"""
    DEBUG = False
    
    # Your existing MySQL database URI
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://upfpvglyifsay:1yyjibjraeok@localhost/dbfnuy3kxunopd'
    
    # Database connection pool settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }

# Environment configuration mapping for easier management
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig
}