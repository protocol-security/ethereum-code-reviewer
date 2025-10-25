"""
Route blueprints package.
"""

from flask import Flask


def register_blueprints(app: Flask):
    """Register all blueprints with the Flask app."""
    from .main import main_bp
    from .auth import auth_bp
    from .findings import findings_bp
    from .repositories import repositories_bp
    from .admin import admin_bp
    from .api import api_bp
    from .public_api import public_api_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(findings_bp)
    app.register_blueprint(repositories_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(public_api_bp)  # Public API with /api/v1 prefix
