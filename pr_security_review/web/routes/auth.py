"""
Authentication routes blueprint.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, current_app
from google.auth.exceptions import GoogleAuthError
from ..auth import get_auth_service

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth_bp', __name__)


@auth_bp.route('/login')
def login():
    """Login page."""
    auth_service = get_auth_service()
    if auth_service.is_authenticated():
        return redirect(url_for('main_bp.index'))
    
    return render_template('login.html', 
                         google_client_id=current_app.config.get('GOOGLE_CLIENT_ID'))


@auth_bp.route('/google', methods=['POST'])
def google_auth():
    """Handle Google Sign-In authentication."""
    try:
        auth_service = get_auth_service()
        
        # Get the ID token from the request
        token = request.json.get('idToken')
        if not token:
            return jsonify({'error': 'No ID token provided'}), 400
        
        # Get the redirect URL from the request (optional)
        redirect_url = request.json.get('redirectUrl')
        
        # Verify the token and get user info
        user_info = auth_service.verify_google_token(token)
        
        # Check if user is authorized
        if not auth_service.is_user_authorized(user_info['email']):
            logger.warning(f"Unauthorized login attempt from: {user_info['email']}")
            return jsonify({'error': 'Unauthorized email address'}), 403
        
        # Create or update user in database
        auth_service.create_or_update_user(user_info)
        
        # Create session
        auth_service.create_session(user_info)
        
        # Determine redirect URL - use provided redirect_url if it's safe, otherwise default to index
        final_redirect = url_for('main_bp.index')  # Default fallback
        
        if redirect_url:
            # Basic security check - ensure redirect URL is for this app
            from urllib.parse import urlparse
            parsed_redirect = urlparse(redirect_url)
            request_host = request.headers.get('Host', '')
            
            # Allow relative URLs (no scheme/netloc) or URLs to the same host
            if not parsed_redirect.netloc or parsed_redirect.netloc == request_host:
                final_redirect = redirect_url
            else:
                logger.warning(f"Rejected redirect to external host: {redirect_url}")
        
        logger.info(f"User authenticated: {user_info['email']}, redirecting to: {final_redirect}")
        return jsonify({'success': True, 'redirect': final_redirect})
        
    except GoogleAuthError as e:
        logger.error(f"Google authentication error: {e}")
        return jsonify({'error': 'Invalid Google token'}), 401
    except ValueError as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return jsonify({'error': 'Authentication failed'}), 500


@auth_bp.route('/logout')
def logout():
    """Logout user."""
    auth_service = get_auth_service()
    auth_service.destroy_session()
    return redirect(url_for('main_bp.index'))
