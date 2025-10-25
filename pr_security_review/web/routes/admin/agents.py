"""
Admin agent management routes.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from ...auth import get_auth_service
from ...decorators import admin_required

logger = logging.getLogger(__name__)

agents_bp = Blueprint('agents_bp', __name__)

# Import database layer
try:
    from ....database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


@agents_bp.route('/')
@admin_required
def list_agents():
    """Agent management page (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        agents = db_manager.get_all_agents()
        
        return render_template('admin/agents.html',
                             agents=agents,
                             user=auth_service.get_current_user(),
                             is_owner=auth_service.is_owner())
        
    except Exception as e:
        logger.error(f"Error loading agents: {e}")
        flash('Error loading agents', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))


@agents_bp.route('/create', methods=['GET', 'POST'])
@admin_required
def create():
    """Create a new agent (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        
        if request.method == 'GET':
            main_agent = db_manager.get_main_agent()
            
            return render_template('admin/create_agent.html',
                                 main_agent=main_agent.to_dict() if main_agent else None,
                                 user=auth_service.get_current_user())
        
        # Handle POST request
        name = request.form.get('name', '').strip()
        
        if not name:
            flash('Agent name is required', 'error')
            return redirect(url_for('admin_bp.agents_bp.create'))
        
        # Build prompts dictionary from form data
        prompts = {
            'security': {
                'intro': request.form.get('security_intro', '').strip(),
                'focus_areas': request.form.get('security_focus_areas', '').strip(),
                'important_notes': request.form.get('security_important_notes', '').strip(),
                'examples': request.form.get('security_examples', '').strip(),
                'response_format': request.form.get('security_response_format', '').strip(),
                'no_vulns_response': request.form.get('security_no_vulns_response', '').strip()
            },
            'skeptical_verification': {
                'intro': request.form.get('skeptical_intro', '').strip(),
                'critical_questions': request.form.get('skeptical_critical_questions', '').strip(),
                'be_critical': request.form.get('skeptical_be_critical', '').strip(),
                'only_confirm': request.form.get('skeptical_only_confirm', '').strip(),
                'response_format': request.form.get('skeptical_response_format', '').strip()
            },
            'synthesis': {
                'intro': request.form.get('synthesis_intro', '').strip(),
                'instruction': request.form.get('synthesis_instruction', '').strip()
            },
            'system_prompts': {
                'default': request.form.get('system_default', '').strip(),
                'anthropic': request.form.get('system_anthropic', '').strip(),
                'synthesize': request.form.get('system_synthesize', '').strip()
            }
        }
        
        # Create agent
        current_user = auth_service.get_current_user()
        agent_id = db_manager.create_agent(
            name=name,
            prompts=prompts,
            created_by=current_user['email'],
            is_main=False
        )
        
        if agent_id:
            flash(f'Agent "{name}" created successfully', 'success')
            return redirect(url_for('admin_bp.agents_bp.list_agents'))
        else:
            flash('Failed to create agent', 'error')
            return redirect(url_for('admin_bp.agents_bp.create'))
        
    except Exception as e:
        logger.error(f"Error creating agent: {e}")
        flash('Error creating agent', 'error')
        return redirect(url_for('admin_bp.agents_bp.create'))


@agents_bp.route('/<int:agent_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit(agent_id):
    """Edit an agent (admin only, owner for main agent)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        agent = db_manager.get_agent(agent_id)
        
        if not agent:
            flash('Agent not found', 'error')
            return redirect(url_for('admin_bp.agents_bp.list_agents'))
        
        # Check permissions - only owners can edit main agent
        if agent.is_main and not auth_service.is_owner():
            flash('Only owners can edit the main agent', 'error')
            return redirect(url_for('admin_bp.agents_bp.view', agent_id=agent_id))
        
        if request.method == 'GET':
            return render_template('admin/edit_agent.html',
                                 agent=agent.to_dict(),
                                 user=auth_service.get_current_user())
        
        # Handle POST request
        name = request.form.get('name', '').strip()
        
        if not name and not agent.is_main:
            flash('Agent name is required', 'error')
            return redirect(url_for('admin_bp.agents_bp.edit', agent_id=agent_id))
        
        # Build prompts dictionary from form data
        prompts = {
            'security': {
                'intro': request.form.get('security_intro', '').strip(),
                'focus_areas': request.form.get('security_focus_areas', '').strip(),
                'important_notes': request.form.get('security_important_notes', '').strip(),
                'examples': request.form.get('security_examples', '').strip(),
                'response_format': request.form.get('security_response_format', '').strip(),
                'no_vulns_response': request.form.get('security_no_vulns_response', '').strip()
            },
            'skeptical_verification': {
                'intro': request.form.get('skeptical_intro', '').strip(),
                'critical_questions': request.form.get('skeptical_critical_questions', '').strip(),
                'be_critical': request.form.get('skeptical_be_critical', '').strip(),
                'only_confirm': request.form.get('skeptical_only_confirm', '').strip(),
                'response_format': request.form.get('skeptical_response_format', '').strip()
            },
            'synthesis': {
                'intro': request.form.get('synthesis_intro', '').strip(),
                'instruction': request.form.get('synthesis_instruction', '').strip()
            },
            'system_prompts': {
                'default': request.form.get('system_default', '').strip(),
                'anthropic': request.form.get('system_anthropic', '').strip(),
                'synthesize': request.form.get('system_synthesize', '').strip()
            }
        }
        
        # Update agent
        current_user = auth_service.get_current_user()
        success = db_manager.update_agent(
            agent_id=agent_id,
            name=name if not agent.is_main else None,  # Don't update name for main agent
            prompts=prompts,
            updated_by=current_user['email']
        )
        
        if success:
            flash(f'Agent updated successfully', 'success')
            return redirect(url_for('admin_bp.agents_bp.list_agents'))
        else:
            flash('Failed to update agent', 'error')
            return redirect(url_for('admin_bp.agents_bp.edit', agent_id=agent_id))
        
    except Exception as e:
        logger.error(f"Error editing agent {agent_id}: {e}")
        flash('Error editing agent', 'error')
        return redirect(url_for('admin_bp.agents_bp.list_agents'))


@agents_bp.route('/<int:agent_id>/view')
@admin_required
def view(agent_id):
    """View an agent (admin only)."""
    if not DATABASE_AVAILABLE:
        flash('Database not available', 'error')
        return redirect(url_for('admin_bp.dashboard_bp.admin_dashboard'))
    
    try:
        auth_service = get_auth_service()
        db_manager = get_database_manager()
        agent = db_manager.get_agent(agent_id)
        
        if not agent:
            flash('Agent not found', 'error')
            return redirect(url_for('admin_bp.agents_bp.list_agents'))
        
        return render_template('admin/view_agent.html',
                             agent=agent.to_dict(),
                             user=auth_service.get_current_user())
        
    except Exception as e:
        logger.error(f"Error viewing agent {agent_id}: {e}")
        flash('Error viewing agent', 'error')
        return redirect(url_for('admin_bp.agents_bp.list_agents'))


@agents_bp.route('/<int:agent_id>/delete', methods=['POST'])
@admin_required
def delete(agent_id):
    """Delete an agent (admin only)."""
    if not DATABASE_AVAILABLE:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        db_manager = get_database_manager()
        
        # Check if agent is main before attempting deletion
        agent = db_manager.get_agent(agent_id)
        if agent and agent.is_main:
            return jsonify({'error': 'Cannot delete main agent'}), 400
        
        success = db_manager.delete_agent(agent_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Agent deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete agent or agent not found'}), 500
        
    except Exception as e:
        logger.error(f"Error deleting agent {agent_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500
