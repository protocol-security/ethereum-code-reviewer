"""
Flask web application entry point.

This file serves as a compatibility layer and entry point.

For the modular structure, see:
- pr_security_review/web/__init__.py - Application factory
- pr_security_review/web/config.py - Configuration
- pr_security_review/web/auth.py - Authentication service
- pr_security_review/web/services.py - Business logic services
- pr_security_review/web/routes/ - Route blueprints
- pr_security_review/web/decorators.py - Route decorators
- pr_security_review/web/utils.py - Utility functions
"""

import os
import logging

# Load environment variables from .env file
try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    pass  # dotenv is optional, continue without it

logger = logging.getLogger(__name__)


def create_app():
    """
    Create and configure the Flask application.
    
    This is the main entry point that uses the modular structure.
    """
    from .web import create_app as create_modular_app
    return create_modular_app()


class SecurityFinderApp:
    """
    Legacy class wrapper for backwards compatibility.
    
    This class maintains the same interface as the original web_app.py
    but delegates to the new modular structure.
    """
    
    def __init__(self):
        """Initialize the application using the new modular structure."""
        self.app = create_app()
        logger.info("Security Finder web app initialized (using modular structure)")
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the Flask application."""
        logger.info(f"Starting Security Finder web app on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


# Maintain backwards compatibility
if __name__ == '__main__':
    app = SecurityFinderApp()
    port = int(os.getenv('WEB_APP_PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(port=port, debug=debug)
