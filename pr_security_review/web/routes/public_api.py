"""
Public API routes for external integrations.
This includes endpoints that use API key authentication.
"""

import logging
from flask import Blueprint, jsonify, request
from functools import wraps

logger = logging.getLogger(__name__)

public_api_bp = Blueprint('public_api_bp', __name__, url_prefix='/api/v1')

# Import database layer
try:
    from ...database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not DATABASE_AVAILABLE:
            return jsonify({'error': 'Service temporarily unavailable'}), 503
        
        # Get API key from Authorization header
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header. Format: Bearer <api_key>'}), 401
        
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        
        if not api_key:
            return jsonify({'error': 'API key is required'}), 401
        
        # Validate the API key
        db_manager = get_database_manager()
        user_email = db_manager.validate_api_key(api_key)
        
        if not user_email:
            return jsonify({'error': 'Invalid or revoked API key'}), 401
        
        # Store user_email in request context for use in the endpoint
        request.user_email = user_email
        
        return f(*args, **kwargs)
    
    return decorated_function


@public_api_bp.route('/alerts', methods=['POST'])
@require_api_key
def submit_alert():
    """
    Submit a new vulnerability alert via API.
    
    This endpoint allows external tools (like fuzzers) to submit vulnerability findings.
    
    Required headers:
    - Authorization: Bearer <api_key>
    - Content-Type: application/json
    
    Request body:
    {
        "repository": "ethereum/go-ethereum",  # Required
        "title": "Vulnerability title",         # Required
        "description": "Detailed description",  # Required
        "severity": "high",                     # Required: critical, high, medium, low, info
        "file_path": "path/to/file.sol",       # Optional
        "line_number": 42,                      # Optional
        "commit_sha": "abc123...",             # Optional
        "cve_id": "CVE-2024-1234",             # Optional
        "tool_name": "MyFuzzer v1.0",          # Optional
        "additional_data": {}                   # Optional: any additional metadata
    }
    """
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Service temporarily unavailable'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400
        
        # Validate required fields
        required_fields = ['repository', 'title', 'description', 'severity']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Validate severity
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        severity = data.get('severity', '').lower()
        if severity not in valid_severities:
            return jsonify({
                'error': f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
            }), 400
        
        # Get database manager and user info
        db_manager = get_database_manager()
        user_email = request.user_email
        
        # Check if user has access to this repository
        accessible_repos = db_manager.get_user_repository_access(user_email)
        repository = data.get('repository')
        
        if accessible_repos and repository not in accessible_repos:
            return jsonify({
                'error': f'You do not have access to repository: {repository}'
            }), 403
        
        # Create a pseudo-commit info object
        class AlertCommitInfo:
            def __init__(self, data):
                self.sha = data.get('commit_sha', 'api-submitted')
                self.url = data.get('commit_url', '')
                self.message = f"API Alert: {data.get('title')}"
                self.author = data.get('tool_name', 'External Tool')
                self.date = None
                self.branch = data.get('branch', 'unknown')
        
        commit_info = AlertCommitInfo(data)
        
        # Build analysis data structure
        analysis = {
            'has_vulnerabilities': True,
            'confidence_score': 100,  # API submissions are assumed to be manually verified
            'summary': data.get('description'),
            'findings': [{
                'severity': severity,
                'description': data.get('description'),
                'recommendation': 'Review and address this vulnerability',
                'confidence': 100,
                'file_path': data.get('file_path'),
                'line_number': data.get('line_number'),
                'cve_id': data.get('cve_id')
            }],
            'source': 'api'
        }
        
        # Generate HTML content
        html_content = f"""
        <h1>Security Alert for {repository}</h1>
        <div style="background: #fed7d7; border: 1px solid #fc8181; padding: 1rem; border-radius: 8px; margin: 1rem 0;">
            <h2 style="margin: 0 0 0.5rem 0; color: #c53030;">
                <i class="fas fa-exclamation-triangle"></i> {data.get('title')}
            </h2>
            <p style="margin: 0;"><strong>Severity:</strong> <span style="text-transform: uppercase;">{severity}</span></p>
        </div>
        
        <h3>Description</h3>
        <p>{data.get('description')}</p>
        """
        
        if data.get('file_path'):
            html_content += f"""
            <h3>Location</h3>
            <ul>
                <li><strong>File:</strong> {data.get('file_path')}</li>
                {f'<li><strong>Line:</strong> {data.get("line_number")}</li>' if data.get('line_number') else ''}
            </ul>
            """
        
        if data.get('cve_id'):
            html_content += f"""
            <h3>CVE Information</h3>
            <p><strong>CVE ID:</strong> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={data.get('cve_id')}" target="_blank">{data.get('cve_id')}</a></p>
            """
        
        if data.get('commit_sha'):
            html_content += f"""
            <h3>Commit Information</h3>
            <p><strong>Commit SHA:</strong> <code>{data.get('commit_sha')}</code></p>
            """
        
        html_content += f"""
        <hr>
        <p style="color: #718096; font-size: 0.875rem;">
            <strong>Submitted via API</strong><br>
            Tool: {data.get('tool_name', 'Unknown')}<br>
            Submitted by: {user_email}
        </p>
        """
        
        # Prepare metadata
        metadata = {
            'submitted_by': user_email,
            'tool_name': data.get('tool_name'),
            'api_version': 'v1',
            'additional_data': data.get('additional_data', {})
        }
        
        # Store the finding
        finding_uuid = db_manager.store_finding(
            html_content=html_content,
            repo_name=repository,
            commit_info=commit_info,
            analysis=analysis,
            metadata=metadata
        )
        
        logger.info(f"API alert submitted by {user_email} for {repository}: {finding_uuid}")
        
        # Return success response with finding UUID
        return jsonify({
            'success': True,
            'message': 'Vulnerability alert submitted successfully',
            'finding_uuid': finding_uuid,
            'repository': repository,
            'severity': severity
        }), 201
        
    except Exception as e:
        logger.error(f"Error submitting API alert: {e}", exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@public_api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    if not DATABASE_AVAILABLE:
        return jsonify({
            'status': 'unhealthy',
            'database': 'unavailable'
        }), 503
    
    try:
        db_manager = get_database_manager()
        db_healthy = db_manager.health_check()
        
        if db_healthy:
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'version': 'v1'
            }), 200
        else:
            return jsonify({
                'status': 'unhealthy',
                'database': 'connection_failed'
            }), 503
            
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503
