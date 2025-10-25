"""
Flask application configuration.
"""

import os
import secrets
import logging

# Load environment variables from .env file
try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass  # dotenv is optional, continue without it

logger = logging.getLogger(__name__)


def configure_app(app):
    """Configure Flask application settings."""
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'security_finder:'
    
    # Session security
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Google OAuth settings
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    if not app.config['GOOGLE_CLIENT_ID']:
        logger.warning("GOOGLE_CLIENT_ID not set. Google Sign-In will not work.")
    
    logger.info("Flask application configured successfully")
