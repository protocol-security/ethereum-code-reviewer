"""
Authentication module for handling Google OAuth and user authentication.
"""

import os
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from flask import session, current_app
from google.oauth2 import id_token
from google.auth.transport import requests
from google.auth.exceptions import GoogleAuthError

logger = logging.getLogger(__name__)

# Import database layer
try:
    from ..database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


class AuthService:
    """Service for handling authentication logic."""
    
    def __init__(self):
        self.authorized_emails = self._load_authorized_emails()
    
    def _load_authorized_emails(self) -> List[str]:
        """Load authorized email addresses from environment or config."""
        # Check environment variable first
        emails_env = os.getenv('AUTHORIZED_EMAILS', '')
        if emails_env:
            return [email.strip() for email in emails_env.split(',') if email.strip()]
        
        # Default whitelist if none provided
        default_emails = ['']
        
        # Try to load from config file
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    if 'authorized_emails' in config:
                        return config['authorized_emails']
        except Exception as e:
            logger.warning(f"Could not load authorized emails from config: {e}")
        
        return default_emails
    
    def verify_google_token(self, token: str) -> Dict[str, Any]:
        """
        Verify Google ID token and return user info.
        
        Args:
            token: Google ID token
            
        Returns:
            Dictionary with user info (email, name, picture)
            
        Raises:
            GoogleAuthError: If token verification fails
            ValueError: If token is missing required fields
        """
        google_client_id = current_app.config.get('GOOGLE_CLIENT_ID')
        if not google_client_id:
            raise ValueError("GOOGLE_CLIENT_ID not configured")
        
        # Verify the token
        id_info = id_token.verify_oauth2_token(
            token, requests.Request(), google_client_id
        )
        
        # Extract user info
        email = id_info.get('email')
        if not email:
            raise ValueError('No email in token')
        
        return {
            'email': email,
            'name': id_info.get('name', ''),
            'picture': id_info.get('picture', '')
        }
    
    def is_user_authorized(self, email: str) -> bool:
        """
        Check if user is authorized to access the application.
        
        Args:
            email: User's email address
            
        Returns:
            True if user is authorized, False otherwise
        """
        # Check if email is in authorized_emails
        if email in self.authorized_emails:
            return True
        
        # Check if user exists in database and is active
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_in_db = db_manager.get_user(email)
                if user_in_db and user_in_db.is_active:
                    return True
            except Exception as e:
                logger.error(f"Error checking database for user authorization: {e}")
        
        return False
    
    def create_or_update_user(self, user_info: Dict[str, Any]) -> bool:
        """
        Create or update user in database after successful authentication.
        
        Args:
            user_info: Dictionary with user information (email, name, picture)
            
        Returns:
            True if operation succeeded, False otherwise
        """
        if not DATABASE_AVAILABLE:
            return True  # Skip if database not available
        
        try:
            db_manager = get_database_manager()
            email = user_info['email']
            user_in_db = db_manager.get_user(email)
            
            if not user_in_db:
                # Create new user - if they're in authorized_emails, make them admin
                is_admin = email in self.authorized_emails
                # Make fredrik.svantes@ethereum.org an owner who can't be deleted
                is_owner = email == 'fredrik.svantes@ethereum.org'
                success = db_manager.create_user(
                    email=email,
                    name=user_info.get('name', ''),
                    is_admin=is_admin,
                    repository_access=None,  # Admin users get all access
                    created_by='system',
                    is_owner=is_owner
                )
                if success:
                    logger.info(f"Created new user in database: {email} (admin: {is_admin}, owner: {is_owner})")
                return success
            else:
                # Update last login
                db_manager.update_last_login(email)
                logger.info(f"Updated last login for user: {email}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to create/update user in database: {e}")
            return False
    
    def create_session(self, user_info: Dict[str, Any]) -> None:
        """
        Create user session after successful authentication.
        
        Args:
            user_info: Dictionary with user information (email, name, picture)
        """
        session['user'] = {
            'email': user_info['email'],
            'name': user_info['name'],
            'picture': user_info['picture'],
            'authenticated': True,
            'login_time': datetime.now(timezone.utc).isoformat()
        }
        logger.info(f"User session created: {user_info['email']}")
    
    def destroy_session(self) -> Optional[str]:
        """
        Destroy user session on logout.
        
        Returns:
            Email of logged out user, or None if no user was logged in
        """
        if 'user' in session:
            email = session['user']['email']
            session.pop('user', None)
            logger.info(f"User logged out: {email}")
            return email
        return None
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if not ('user' in session and session['user'].get('authenticated', False)):
            return False
        
        email = session['user'].get('email')
        if not email:
            return False
        
        return self.is_user_authorized(email)
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current authenticated user."""
        if self.is_authenticated():
            return session['user']
        return None
    
    def is_admin(self) -> bool:
        """Check if current user is an admin."""
        if not self.is_authenticated():
            return False
        
        # Check if user is admin in the database
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_email = self.get_current_user()['email']
                return db_manager.is_admin(user_email)
            except Exception as e:
                logger.error(f"Error checking admin status: {e}")
                return False
        
        # Fallback to environmental variable check
        return self.get_current_user()['email'] in self.authorized_emails
    
    def is_owner(self) -> bool:
        """Check if current user is an owner."""
        if not self.is_authenticated():
            return False
        
        # Check if user is owner in the database
        if DATABASE_AVAILABLE:
            try:
                db_manager = get_database_manager()
                user_email = self.get_current_user()['email']
                return db_manager.is_owner(user_email)
            except Exception as e:
                logger.error(f"Error checking owner status: {e}")
                return False
        
        # Fallback to environmental variable check for owner
        return self.get_current_user()['email'] == 'fredrik.svantes@ethereum.org'


# Global auth service instance
_auth_service = None


def get_auth_service() -> AuthService:
    """Get or create the global auth service instance."""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
