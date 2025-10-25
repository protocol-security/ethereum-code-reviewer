"""
API routes blueprint for AJAX endpoints.
"""

import logging
from flask import Blueprint, jsonify, request
from ..auth import get_auth_service
from ..decorators import login_required, admin_required
from ..services import FindingsService

logger = logging.getLogger(__name__)

api_bp = Blueprint('api_bp', __name__)

# Import database layer
try:
    from ...database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@api_bp.route('/findings')
@login_required
def api_findings():
    """API endpoint for findings list (authenticated users only)."""
    try:
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        findings = FindingsService.get_all_findings(user_email=user_email)
        return jsonify({
            'success': True,
            'findings': findings,
            'total': len(findings)
        })
    except Exception as e:
        logger.error(f"Error fetching findings: {e}")
        return jsonify({'error': 'Failed to fetch findings'}), 500


@api_bp.route('/triage/<finding_uuid>', methods=['POST'])
@login_required
def update_triage(finding_uuid):
    """Update triage status of a finding (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        new_status = data.get('status')
        notes = data.get('notes')
        completion_classification = data.get('completion_classification')
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        # Validate status
        valid_statuses = ['unassigned', 'reviewing', 'escalated_to_client', 'completed']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Validate completion classification if status is completed
        if new_status == 'completed':
            if not completion_classification:
                return jsonify({'error': 'Completion classification required for completed status'}), 400
            if completion_classification not in ['true_positive', 'false_positive']:
                return jsonify({'error': 'Invalid completion classification'}), 400
        
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        db_manager = get_database_manager()
        success = db_manager.update_triage_status(
            finding_uuid=finding_uuid,
            new_status=new_status,
            user_email=user_email,
            notes=notes,
            completion_classification=completion_classification
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Triage status updated successfully'})
        else:
            return jsonify({'error': 'Failed to update triage status'}), 500
        
    except Exception as e:
        logger.error(f"Error updating triage status for {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/notes/<finding_uuid>', methods=['GET', 'POST', 'DELETE'])
@login_required
def handle_notes(finding_uuid):
    """Handle notes operations (GET, POST, DELETE)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        if request.method == 'GET':
            notes = db_manager.get_notes(finding_uuid)
            return jsonify({'success': True, 'notes': notes})
        
        elif request.method == 'POST':
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            note_text = data.get('note')
            if not note_text or not note_text.strip():
                return jsonify({'error': 'Note text is required'}), 400
            
            success = db_manager.add_note(
                finding_uuid=finding_uuid,
                note_text=note_text.strip(),
                user_email=user_email
            )
            
            if success:
                return jsonify({'success': True, 'message': 'Note added successfully'})
            else:
                return jsonify({'error': 'Failed to add note'}), 500
        
    except Exception as e:
        logger.error(f"Error handling notes for {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/notes/<finding_uuid>/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(finding_uuid, note_id):
    """Delete a note from a finding (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        auth_service = get_auth_service()
        user_email = auth_service.get_current_user()['email']
        
        db_manager = get_database_manager()
        success = db_manager.delete_note(
            finding_uuid=finding_uuid,
            note_id=note_id,
            user_email=user_email
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Note deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete note'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting note {note_id} from {finding_uuid}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/triage/statistics')
@login_required
def triage_statistics():
    """Get triage statistics (authenticated users only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        stats = db_manager.get_triage_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error fetching triage statistics: {e}")
        return jsonify({'error': 'Failed to fetch statistics'}), 500
