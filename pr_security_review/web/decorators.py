"""
Decorators for authentication and authorization checks.
"""

from functools import wraps
from flask import redirect, url_for, flash, jsonify, request
from .auth import get_auth_service


def login_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_service = get_auth_service()
        if not auth_service.is_authenticated():
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            # For regular routes, redirect to login
            return redirect(url_for('auth_bp.login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_service = get_auth_service()
        if not auth_service.is_authenticated():
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('auth_bp.login'))
        
        if not auth_service.is_admin():
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Access denied'}), 403
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('main_bp.index'))
        return f(*args, **kwargs)
    return decorated_function


def owner_required(f):
    """Decorator to require owner privileges for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_service = get_auth_service()
        if not auth_service.is_authenticated():
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('auth_bp.login'))
        
        if not auth_service.is_owner():
            # For API routes, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Access denied. Owner privileges required'}), 403
            flash('Access denied. Owner privileges required.', 'error')
            return redirect(url_for('main_bp.index'))
        return f(*args, **kwargs)
    return decorated_function
