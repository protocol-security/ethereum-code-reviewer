"""
Admin routes package with sub-blueprints for different admin functions.
"""

from flask import Blueprint

# Create the main admin blueprint
admin_bp = Blueprint('admin_bp', __name__)

# Import and register sub-blueprints
from .dashboard import dashboard_bp
from .users import users_bp
from .repositories import repositories_bp

# Register sub-blueprints
admin_bp.register_blueprint(dashboard_bp)
admin_bp.register_blueprint(users_bp, url_prefix='/users')
admin_bp.register_blueprint(repositories_bp, url_prefix='/repositories')
