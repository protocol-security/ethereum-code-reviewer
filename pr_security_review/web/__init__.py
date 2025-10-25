"""
Flask web application package with modular structure.
"""

import os
import secrets
import logging
from flask import Flask
from flask_session import Session

logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """Create and configure the Flask application."""
    from .config import configure_app
    from .routes import register_blueprints
    
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Configure the app
    configure_app(app)
    
    # Initialize Flask-Session
    Session(app)
    
    # Register all blueprints
    register_blueprints(app)
    
    logger.info("Flask web application created successfully")
    
    return app
