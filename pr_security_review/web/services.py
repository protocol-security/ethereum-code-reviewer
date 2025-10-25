"""
Business logic services for the web application.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# Import database layer
try:
    from ..database import get_database_manager, SecurityFinding
    DATABASE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Database not available: {e}")
    DATABASE_AVAILABLE = False


class FindingsService:
    """Service for handling findings-related business logic."""
    
    @staticmethod
    def get_all_findings(triage_status: Optional[str] = None, user_email: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all security findings with optional filtering.
        
        Args:
            triage_status: Optional triage status filter
            user_email: Optional user email for repository access filtering
            
        Returns:
            List of findings dictionaries
        """
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            
            if triage_status:
                findings = db_manager.get_findings_by_status(triage_status=triage_status)
            else:
                session_db = db_manager.get_session()
                findings_query = session_db.query(SecurityFinding).order_by(SecurityFinding.created_at.desc()).all()
                
                result = []
                for finding in findings_query:
                    result.append({
                        'uuid': str(finding.uuid),
                        'repo_name': finding.repo_name,
                        'commit_sha': finding.commit_sha,
                        'commit_url': finding.commit_url,
                        'branch': finding.branch,
                        'author': finding.author,
                        'commit_date': finding.commit_date.isoformat() if finding.commit_date else None,
                        'commit_message': finding.commit_message,
                        'has_vulnerabilities': finding.has_vulnerabilities,
                        'confidence_score': finding.confidence_score,
                        'summary': finding.summary,
                        'findings_count': finding.findings_count,
                        'created_at': finding.created_at.isoformat() if finding.created_at else None,
                        'expires_at': finding.expires_at.isoformat() if finding.expires_at else None,
                        'triage_status': finding.triage_status,
                        'assigned_to': finding.assigned_to,
                        'completion_classification': finding.completion_classification,
                        'completed_at': finding.completed_at.isoformat() if finding.completed_at else None,
                        'completed_by': finding.completed_by,
                        'priority': finding.priority,
                        'severity': finding.severity,
                    })
                
                session_db.close()
                findings = result
            
            # Apply repository access filtering if user_email provided
            if user_email:
                findings = db_manager.filter_findings_by_user_access(findings, user_email)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error fetching findings: {e}")
            return []
    
    @staticmethod
    def apply_filters(findings: List[Dict[str, Any]], vulnerability_filter: str, 
                     repository_filter: str, status_filter: str, classification_filter: str,
                     user_filter: str = '') -> List[Dict[str, Any]]:
        """Apply filters to findings list."""
        filtered_findings = findings.copy()
        
        # Apply vulnerability filter
        if vulnerability_filter == 'vulnerable':
            filtered_findings = [f for f in filtered_findings if f.get('has_vulnerabilities')]
        elif vulnerability_filter == 'safe':
            filtered_findings = [f for f in filtered_findings if not f.get('has_vulnerabilities')]
        
        # Apply repository filter
        if repository_filter:
            filtered_findings = [f for f in filtered_findings if f.get('repo_name', '').lower() == repository_filter.lower()]
        
        # Apply status filter
        if status_filter:
            filtered_findings = [f for f in filtered_findings if (f.get('triage_status') or 'unassigned') == status_filter]
        
        # Apply classification filter
        if status_filter == 'completed' and classification_filter:
            filtered_findings = [f for f in filtered_findings if f.get('completion_classification') == classification_filter]
        
        # Apply user filter
        if user_filter:
            filtered_findings = [f for f in filtered_findings if 
                               f.get('assigned_to') == user_filter or 
                               f.get('completed_by') == user_filter]
        
        return filtered_findings
    
    @staticmethod
    def calculate_statistics(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics for findings."""
        vulnerable_count = len([f for f in findings if f.get('has_vulnerabilities')])
        safe_count = len([f for f in findings if not f.get('has_vulnerabilities')])
        
        # Get unique repositories
        unique_repos = set(f.get('repo_name') for f in findings if f.get('repo_name'))
        repo_count = len(unique_repos)
        
        # Get recent findings (last 24 hours)
        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(hours=24)
        
        recent_24h_count = 0
        for finding in findings:
            if finding.get('created_at'):
                try:
                    created_at = datetime.fromisoformat(finding['created_at'].replace('Z', '+00:00'))
                    if created_at > recent_cutoff:
                        recent_24h_count += 1
                except Exception:
                    pass
        
        return {
            'vulnerable': vulnerable_count,
            'safe': safe_count,
            'repositories': repo_count,
            'recent_24h': recent_24h_count,
            'total': len(findings)
        }


class RepositoryService:
    """Service for handling repository-related business logic."""
    
    @staticmethod
    def load_repositories() -> List[Dict[str, Any]]:
        """Load repository configuration from database."""
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            repositories = db_manager.get_all_repositories(include_inactive=True)
            
            # Convert database format to expected format
            repo_list = []
            for repo in repositories:
                repo_list.append({
                    'name': repo['name'],
                    'url': repo['url'],
                    'branches': repo['branches'],
                    'telegram_channel_id': repo.get('telegram_channel_id'),
                    'notify_default_channel': repo.get('notify_default_channel', False),
                    'is_active': repo.get('is_active', True),
                    'created_at': repo.get('created_at'),
                    'created_by': repo.get('created_by'),
                    'updated_at': repo.get('updated_at'),
                    'updated_by': repo.get('updated_by')
                })
            
            # Sort by active status first (active=True first), then by name
            return sorted(repo_list, key=lambda x: (not x.get('is_active', True), x['name'].lower()))
            
        except Exception as e:
            logger.warning(f"Could not load repositories from database: {e}")
            
        return []
    
    @staticmethod
    def get_unique_users(user_accessible_repos: List[str] = None) -> List[str]:
        """Get unique users who have worked on findings."""
        if not DATABASE_AVAILABLE:
            return []
        
        try:
            db_manager = get_database_manager()
            session_db = db_manager.get_session()
            
            unique_users = set()
            
            # Build query with repository filter if user has restricted access
            query_filter = []
            if user_accessible_repos:
                query_filter.append(SecurityFinding.repo_name.in_(user_accessible_repos))
            
            # Get users who have been assigned to findings
            assigned_query = session_db.query(SecurityFinding.assigned_to).filter(
                SecurityFinding.assigned_to.isnot(None)
            )
            if query_filter:
                assigned_query = assigned_query.filter(*query_filter)
            
            assigned_users = assigned_query.distinct().all()
            for (user,) in assigned_users:
                if user:
                    unique_users.add(user)
            
            # Get users who have completed findings
            completed_query = session_db.query(SecurityFinding.completed_by).filter(
                SecurityFinding.completed_by.isnot(None)
            )
            if query_filter:
                completed_query = completed_query.filter(*query_filter)
            
            completed_users = completed_query.distinct().all()
            for (user,) in completed_users:
                if user:
                    unique_users.add(user)
            
            session_db.close()
            return sorted(list(unique_users))
            
        except Exception as e:
            logger.error(f"Error fetching unique users: {e}")
            return []


class PaginationService:
    """Service for handling pagination logic."""
    
    @staticmethod
    def paginate(items: List[Any], page: int, per_page: int) -> tuple:
        """
        Paginate a list of items.
        
        Args:
            items: List of items to paginate
            page: Current page number (1-indexed)
            per_page: Number of items per page
            
        Returns:
            Tuple of (paginated_items, pagination_info)
        """
        total = len(items)
        total_pages = (total + per_page - 1) // per_page if total > 0 else 0
        
        # Get items for current page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_items = items[start_idx:end_idx]
        
        # Create pagination info
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': total_pages,
            'has_prev': page > 1,
            'prev_num': page - 1 if page > 1 else None,
            'has_next': page < total_pages,
            'next_num': page + 1 if page < total_pages else None,
            'iter_pages': PaginationService._get_pagination_range(page, total_pages)
        }
        
        return paginated_items, pagination
    
    @staticmethod
    def _get_pagination_range(page: int, total_pages: int, window: int = 5) -> List[int]:
        """Generate pagination range for template."""
        if total_pages <= window:
            return list(range(1, total_pages + 1))
        
        # Calculate start and end of the window
        start = max(1, page - window // 2)
        end = min(total_pages, start + window - 1)
        
        # Adjust start if we're near the end
        if end - start < window - 1:
            start = max(1, end - window + 1)
        
        return list(range(start, end + 1))
