"""
PostgreSQL database layer for storing security findings.
"""

import os
import json
import uuid
import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy import (
    create_engine, 
    Column, 
    String, 
    Text, 
    DateTime, 
    Boolean, 
    Integer,
    JSON,
    Index,
    text,
    Enum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
import logging
from .findings_deduplication import (
    DUPLICATE_FINDING_WINDOW_SECONDS,
    find_duplicate_finding_uuids,
)

logger = logging.getLogger(__name__)

Base = declarative_base()


class Repository(Base):
    """Database model for repository configuration."""
    
    __tablename__ = 'repositories'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Repository information
    name = Column(String(255), unique=True, nullable=False)  # e.g., "ethereum/go-ethereum"
    url = Column(String(500), nullable=False)  # Full GitHub URL
    branches = Column(JSON, nullable=False)  # Array of branch names
    
    # Review configuration
    agent_file_path = Column(String(500), nullable=True)  # Relative path to AGENT.md/AGENTS.md under ./agents
    
    # Telegram notification settings
    telegram_channel_id = Column(String(255))  # Optional telegram channel ID
    notify_default_channel = Column(Boolean, default=False, nullable=False)
    
    # Status and metadata
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    created_by = Column(String(255), nullable=False)  # Email of admin who created it
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_by = Column(String(255), nullable=False)  # Email of admin who last updated it
    
    def __repr__(self):
        return f"<Repository(id={self.id}, name={self.name}, url={self.url})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        branch_configs = getattr(self, 'branch_configs_data', None)
        if branch_configs is None:
            branch_configs = [
                {
                    'branch_name': branch,
                    'starting_commit_sha': None,
                    'hardfork_name': None,
                    'last_seen_head_sha': None,
                    'last_reviewed_head_sha': None,
                    'local_sync_status': 'pending',
                    'last_sync_error': None,
                    'last_synced_at': None,
                }
                for branch in (self.branches or [])
            ]

        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'branches': [config['branch_name'] for config in branch_configs],
            'branch_configs': branch_configs,
            'agent_file_path': self.agent_file_path,
            'telegram_channel_id': self.telegram_channel_id,
            'notify_default_channel': self.notify_default_channel,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by,
        }
    
    @staticmethod
    def extract_repo_name_from_url(url: str) -> str:
        """Extract repository name from GitHub URL."""
        if url.endswith('/'):
            url = url[:-1]
        parts = url.split('/')
        if len(parts) >= 2:
            return '/'.join(parts[-2:])
        return url


class RepositoryBranchConfig(Base):
    """Database model for branch-specific review configuration and runtime state."""

    __tablename__ = 'repository_branch_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    repository_name = Column(String(255), nullable=False)
    branch_name = Column(String(255), nullable=False)
    starting_commit_sha = Column(String(64), nullable=True)
    hardfork_name = Column(String(255), nullable=True)
    last_seen_head_sha = Column(String(64), nullable=True)
    last_reviewed_head_sha = Column(String(64), nullable=True)
    local_sync_status = Column(String(50), nullable=False, default='pending')
    last_sync_error = Column(Text, nullable=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index('idx_repository_branch_configs_repo_name', 'repository_name'),
        Index('idx_repository_branch_configs_repo_branch', 'repository_name', 'branch_name', unique=True),
        Index('idx_repository_branch_configs_status', 'local_sync_status'),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'branch_name': self.branch_name,
            'starting_commit_sha': self.starting_commit_sha,
            'hardfork_name': self.hardfork_name,
            'last_seen_head_sha': self.last_seen_head_sha,
            'last_reviewed_head_sha': self.last_reviewed_head_sha,
            'local_sync_status': self.local_sync_status,
            'last_sync_error': self.last_sync_error,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class User(Base):
    """Database model for users with repository access control."""
    
    __tablename__ = 'users'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User information
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    is_owner = Column(Boolean, default=False, nullable=False)  # Owner can't be removed
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Repository access control
    # If None or empty, user has access to all repositories
    # If contains data, user only has access to specified repositories
    repository_access = Column(JSON)  # List of repository names user can access
    
    # Email notification preferences
    email_notifications_enabled = Column(Boolean, default=True, nullable=False)  # Enabled by default
    
    # Metadata
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    created_by = Column(String(255), nullable=False)  # Email of admin who created the user
    last_login = Column(DateTime(timezone=True))
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, is_admin={self.is_admin})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'is_admin': self.is_admin,
            'is_owner': self.is_owner,
            'is_active': self.is_active,
            'repository_access': self.repository_access,
            'email_notifications_enabled': self.email_notifications_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
    
    def has_repository_access(self, repo_name: str) -> bool:
        """Check if user has access to a specific repository."""
        # Admin users have access to all repositories
        if self.is_admin:
            return True
        
        # If no repository_access is set, user has access to all repositories
        if not self.repository_access:
            return True
        
        # Check if repository is in user's access list
        return repo_name in self.repository_access
    
    def get_accessible_repositories(self) -> List[str]:
        """Get list of repositories the user can access."""
        # Admin users have access to all repositories
        if self.is_admin:
            return []  # Empty list means all repositories
        
        # Return the specific repositories the user can access
        return self.repository_access or []


class ApiKey(Base):
    """Database model for user API keys."""
    
    __tablename__ = 'api_keys'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User association
    user_email = Column(String(255), nullable=False)
    
    # API key (hashed)
    key_hash = Column(String(255), nullable=False, unique=True)
    
    # Key metadata
    name = Column(String(255), nullable=False)  # User-friendly name for the key
    key_prefix = Column(String(20), nullable=False)  # First few characters for identification
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Usage tracking
    last_used_at = Column(DateTime(timezone=True))
    usage_count = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    revoked_at = Column(DateTime(timezone=True))
    
    # Indexing for performance
    __table_args__ = (
        Index('idx_api_keys_user_email', 'user_email'),
        Index('idx_api_keys_key_hash', 'key_hash'),
        Index('idx_api_keys_is_active', 'is_active'),
    )
    
    def __repr__(self):
        return f"<ApiKey(id={self.id}, user={self.user_email}, name={self.name}, active={self.is_active})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'user_email': self.user_email,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'is_active': self.is_active,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
        }


class FindingNote(Base):
    """Database model for finding notes."""
    
    __tablename__ = 'finding_notes'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to security finding
    finding_uuid = Column(UUID(as_uuid=True), nullable=False)
    
    # Note content
    note_text = Column(Text, nullable=False)
    
    # User information
    created_by = Column(String(255), nullable=False)  # Email of user who created the note
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    
    def __repr__(self):
        return f"<FindingNote(id={self.id}, finding_uuid={self.finding_uuid}, created_by={self.created_by})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'finding_uuid': str(self.finding_uuid),
            'note_text': self.note_text,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SecurityFinding(Base):
    """Database model for security findings."""
    
    __tablename__ = 'security_findings'
    
    # Primary key - UUID for external access
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Repository information
    repo_name = Column(String(255), nullable=False)
    commit_sha = Column(String(40), nullable=False)
    commit_url = Column(String(500))
    branch = Column(String(255))
    author = Column(String(255))
    commit_date = Column(DateTime(timezone=True))
    commit_message = Column(Text)
    
    # PR information (optional - only set if this is a PR scan)
    pr_number = Column(Integer)  # PR number if this is a PR scan
    pr_title = Column(Text)  # PR title
    pr_state = Column(String(20))  # open, closed, merged
    
    # Analysis results  
    html_content = Column(Text, nullable=False)
    has_vulnerabilities = Column(Boolean, nullable=False, default=False)
    confidence_score = Column(Integer)
    summary = Column(Text)
    findings_count = Column(Integer, default=0)
    
    # Analysis metadata
    analysis_data = Column(JSON)  # Store full analysis results as JSON
    extra_metadata = Column(JSON)  # Additional metadata
    
    # Triage and workflow management
    triage_status = Column(Enum('unassigned', 'reviewing', 'escalated_to_client', 'completed', 
                                name='triage_status_enum'), nullable=False, default='unassigned')
    assigned_to = Column(String(255))  # Email of assigned user
    assigned_at = Column(DateTime(timezone=True))  # When it was assigned
    
    # Completion details (only set when status is 'completed')
    completion_classification = Column(Enum('true_positive', 'false_positive', 
                                          name='completion_classification_enum'))
    completed_at = Column(DateTime(timezone=True))
    completed_by = Column(String(255))  # Email of user who completed it
    
    # Triage notes and history
    triage_notes = Column(Text)  # Current notes
    status_history = Column(JSON)  # History of status changes with timestamps
    
    # Priority and severity (industry standard fields)
    priority = Column(Enum('critical', 'high', 'medium', 'low', name='priority_enum'))
    severity = Column(Enum('critical', 'high', 'medium', 'low', 'info', name='severity_enum'))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    expires_at = Column(DateTime(timezone=True))
    last_updated = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    
    # Indexing for performance
    __table_args__ = (
        Index('idx_repo_commit', 'repo_name', 'commit_sha'),
        Index('idx_created_at', 'created_at'),
        Index('idx_expires_at', 'expires_at'),
        Index('idx_has_vulnerabilities', 'has_vulnerabilities'),
    )
    
    def __repr__(self):
        return f"<SecurityFinding(uuid={self.uuid}, repo={self.repo_name}, sha={self.commit_sha[:7]})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'uuid': str(self.uuid),
            'repo_name': self.repo_name,
            'commit_sha': self.commit_sha,
            'commit_url': self.commit_url,
            'branch': self.branch,
            'author': self.author,
            'commit_date': self.commit_date.isoformat() if self.commit_date else None,
            'commit_message': self.commit_message,
            'pr_number': self.pr_number,
            'pr_title': self.pr_title,
            'pr_state': self.pr_state,
            'html_content': self.html_content,
            'has_vulnerabilities': self.has_vulnerabilities,
            'confidence_score': self.confidence_score,
            'summary': self.summary,
            'findings_count': self.findings_count,
            'analysis_data': self.analysis_data,
            'metadata': self.extra_metadata,
            # Triage fields
            'triage_status': self.triage_status,
            'assigned_to': self.assigned_to,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'completion_classification': self.completion_classification,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'completed_by': self.completed_by,
            'triage_notes': self.triage_notes,
            'status_history': self.status_history,
            'priority': self.priority,
            'severity': self.severity,
            # Timestamps
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
        }


class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, database_url: Optional[str] = None, expiration_hours: int = 168, check_expiration: bool = False):  # 7 days default
        """
        Initialize database manager.
        
        Args:
            database_url: PostgreSQL connection URL. If None, will use DATABASE_URL env var
            expiration_hours: Hours after which findings expire (default: 7 days)
            check_expiration: Whether to check expiration when retrieving findings (default: False)
        """
        self.database_url = database_url or os.getenv('DATABASE_URL')
        if not self.database_url:
            raise ValueError(
                "Database URL not provided. Set DATABASE_URL environment variable or pass database_url parameter."
            )
        
        self.expiration_hours = expiration_hours
        self.check_expiration = check_expiration or os.getenv('CHECK_EXPIRATION', '').lower() == 'true'
        self.engine = None
        self.SessionLocal = None
        self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine and session factory."""
        try:
            # Configure engine with connection pooling
            self.engine = create_engine(
                self.database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,  # Verify connections before use
                echo=os.getenv('SQL_DEBUG', '').lower() == 'true'  # Enable SQL logging if SQL_DEBUG=true
            )
            
            # Create session factory
            self.SessionLocal = sessionmaker(bind=self.engine)
            
            logger.info("Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def create_tables(self):
        """Create database tables if they don't exist."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get a new database session."""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()
    
    def store_finding(
        self, 
        html_content: str, 
        repo_name: str,
        commit_info: Any,
        analysis: Dict,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store a security finding in the database.
        
        Args:
            html_content: HTML content of the finding report
            repo_name: Repository name
            commit_info: Commit information object
            analysis: Analysis results dictionary
            metadata: Additional metadata
            
        Returns:
            str: UUID of the stored finding
        """
        session = self.get_session()
        try:
            # Set expiration to 100 years in the future (effectively never expires)
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=36500)  # 100 years
            combined_metadata = dict(metadata or {})
            if analysis.get('_reasoning_log') and 'reasoning_log' not in combined_metadata:
                combined_metadata['reasoning_log'] = analysis['_reasoning_log']
            commit_date = getattr(commit_info, 'date', None)
            if isinstance(commit_date, str) and commit_date:
                try:
                    commit_date = datetime.datetime.fromisoformat(commit_date.replace('Z', '+00:00'))
                except ValueError:
                    commit_date = None
            
            # Create finding record
            finding = SecurityFinding(
                repo_name=repo_name,
                commit_sha=commit_info.sha,
                commit_url=getattr(commit_info, 'url', None),
                branch=getattr(commit_info, 'branch', None),
                author=getattr(commit_info, 'author', None),
                commit_date=commit_date,
                commit_message=getattr(commit_info, 'message', None),
                html_content=html_content,
                has_vulnerabilities=analysis.get('has_vulnerabilities', False),
                confidence_score=analysis.get('confidence_score'),
                summary=analysis.get('summary'),
                findings_count=len(analysis.get('findings', [])),
                analysis_data=analysis,
                extra_metadata=combined_metadata,
                expires_at=expires_at
            )
            
            session.add(finding)
            session.commit()
            
            finding_uuid = str(finding.uuid)
            logger.info(f"Stored security finding with UUID: {finding_uuid}")
            
            # Send email notification for new finding (only if vulnerabilities found)
            if analysis.get('has_vulnerabilities', False):
                try:
                    from .email_notifications import get_email_service
                    email_service = get_email_service()
                    if email_service.is_enabled():
                        finding_dict = finding.to_dict()
                        email_service.send_new_finding_notification(self, finding_dict)
                except Exception as email_error:
                    logger.error(f"Failed to send email notification for new finding {finding_uuid}: {email_error}")
                    # Don't fail the entire operation if email fails
            
            return finding_uuid
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store security finding: {e}")
            raise
        finally:
            session.close()
    
    def get_finding(self, finding_uuid: str) -> Optional[Dict]:
        """
        Retrieve a security finding by UUID.
        
        Args:
            finding_uuid: UUID of the finding
            
        Returns:
            Dict containing finding data or None if not found/expired
        """
        session = self.get_session()
        try:
            finding = session.query(SecurityFinding).filter(
                SecurityFinding.uuid == finding_uuid
            ).first()
            
            if not finding:
                logger.debug(f"Finding not found: {finding_uuid}")
                return None
            
            # Check if finding has expired (only if expiration checking is enabled)
            if self.check_expiration and finding.expires_at and finding.expires_at < datetime.datetime.now(datetime.timezone.utc):
                logger.debug(f"Finding expired: {finding_uuid}")
                return None
            
            # Convert to format expected by the findings server
            return {
                'html_content': finding.html_content,
                'created_at': finding.created_at,
                'metadata': finding.extra_metadata or {}
            }
            
        except Exception as e:
            logger.error(f"Failed to retrieve finding {finding_uuid}: {e}")
            return None
        finally:
            session.close()
    
    def get_findings_by_repo(
        self, 
        repo_name: str, 
        limit: int = 100,
        include_expired: bool = False
    ) -> List[Dict]:
        """
        Get findings for a specific repository.
        
        Args:
            repo_name: Repository name
            limit: Maximum number of findings to return
            include_expired: Whether to include expired findings
            
        Returns:
            List of finding dictionaries
        """
        session = self.get_session()
        try:
            query = session.query(SecurityFinding).filter(
                SecurityFinding.repo_name == repo_name
            )
            
            # Only apply expiration filtering if check_expiration is enabled and include_expired is False
            if self.check_expiration and not include_expired:
                query = query.filter(
                    SecurityFinding.expires_at > datetime.datetime.now(datetime.timezone.utc)
                )
            
            findings = query.order_by(
                SecurityFinding.created_at.desc()
            ).limit(limit).all()
            
            return [finding.to_dict() for finding in findings]
            
        except Exception as e:
            logger.error(f"Failed to retrieve findings for repo {repo_name}: {e}")
            return []
        finally:
            session.close()
    
    def cleanup_expired_findings(self) -> int:
        """
        Remove expired findings from the database.
        
        Returns:
            int: Number of findings removed
        """
        session = self.get_session()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Count expired findings first
            expired_count = session.query(SecurityFinding).filter(
                SecurityFinding.expires_at < now
            ).count()
            
            if expired_count > 0:
                # Delete expired findings
                session.query(SecurityFinding).filter(
                    SecurityFinding.expires_at < now
                ).delete()
                
                session.commit()
                logger.info(f"Cleaned up {expired_count} expired findings")
            
            return expired_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to cleanup expired findings: {e}")
            return 0
        finally:
            session.close()

    def cleanup_duplicate_findings(
        self,
        repo_name: Optional[str] = None,
        dry_run: bool = False,
        duplicate_window_seconds: int = DUPLICATE_FINDING_WINDOW_SECONDS
    ) -> Dict[str, Any]:
        """
        Remove duplicate findings created by the same scan being stored twice.

        Args:
            repo_name: Optional repository filter
            dry_run: When True, only report what would be deleted
            duplicate_window_seconds: Max time gap between duplicate rows

        Returns:
            Summary of removed or matched duplicate rows
        """
        session = self.get_session()
        try:
            query = session.query(SecurityFinding).order_by(SecurityFinding.created_at.desc())

            if repo_name:
                query = query.filter(SecurityFinding.repo_name == repo_name)

            findings = query.all()
            duplicate_uuids = find_duplicate_finding_uuids(
                findings,
                duplicate_window_seconds=duplicate_window_seconds
            )

            summary = {
                'scanned_count': len(findings),
                'duplicate_count': len(duplicate_uuids),
                'deleted_count': 0,
                'dry_run': dry_run,
                'repo_name': repo_name,
                'duplicate_uuids': duplicate_uuids,
            }

            if not duplicate_uuids or dry_run:
                return summary

            deleted_count = session.query(SecurityFinding).filter(
                SecurityFinding.uuid.in_(duplicate_uuids)
            ).delete(synchronize_session=False)
            session.commit()

            summary['deleted_count'] = deleted_count
            logger.info(f"Deleted {deleted_count} duplicate finding(s)")
            return summary

        except Exception as e:
            session.rollback()
            logger.error(f"Failed to cleanup duplicate findings: {e}")
            raise
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dict containing statistics about stored findings
        """
        session = self.get_session()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Total findings
            total_findings = session.query(SecurityFinding).count()
            
            # Active (non-expired) findings
            active_findings = session.query(SecurityFinding).filter(
                SecurityFinding.expires_at > now
            ).count()
            
            # Findings with vulnerabilities
            vulnerable_findings = session.query(SecurityFinding).filter(
                SecurityFinding.has_vulnerabilities == True
            ).count()
            
            # Repositories with findings
            repo_count = session.query(SecurityFinding.repo_name).distinct().count()
            
            # Recent findings (last 24 hours)
            recent_cutoff = now - datetime.timedelta(hours=24)
            recent_findings = session.query(SecurityFinding).filter(
                SecurityFinding.created_at > recent_cutoff
            ).count()
            
            return {
                'total_findings': total_findings,
                'active_findings': active_findings,
                'expired_findings': total_findings - active_findings,
                'vulnerable_findings': vulnerable_findings,
                'unique_repositories': repo_count,
                'recent_findings_24h': recent_findings,
                'last_updated': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get database statistics: {e}")
            return {}
        finally:
            session.close()
    
    def get_finding_full(self, finding_uuid: str) -> Optional[SecurityFinding]:
        """
        Retrieve a complete security finding by UUID (including triage data).
        
        Args:
            finding_uuid: UUID of the finding
            
        Returns:
            SecurityFinding object or None if not found/expired
        """
        session = self.get_session()
        try:
            finding = session.query(SecurityFinding).filter(
                SecurityFinding.uuid == finding_uuid
            ).first()
            
            if not finding:
                logger.debug(f"Finding not found: {finding_uuid}")
                return None
            
            # Check if finding has expired (only if expiration checking is enabled)
            if self.check_expiration and finding.expires_at and finding.expires_at < datetime.datetime.now(datetime.timezone.utc):
                logger.debug(f"Finding expired: {finding_uuid}")
                return None
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to retrieve finding {finding_uuid}: {e}")
            return None
        finally:
            session.close()
    
    def update_triage_status(
        self, 
        finding_uuid: str, 
        new_status: str, 
        user_email: str,
        notes: Optional[str] = None,
        priority: Optional[str] = None,
        severity: Optional[str] = None,
        completion_classification: Optional[str] = None
    ) -> bool:
        """
        Update the triage status of a finding.
        
        Args:
            finding_uuid: UUID of the finding
            new_status: New status ('unassigned', 'reviewing', 'escalated_to_client', 'completed')
            user_email: Email of the user making the change
            notes: Optional notes to add
            priority: Optional priority to set
            severity: Optional severity to set
            completion_classification: Required when status is 'completed' ('true_positive' or 'false_positive')
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        session = self.get_session()
        try:
            finding = session.query(SecurityFinding).filter(
                SecurityFinding.uuid == finding_uuid
            ).first()
            
            if not finding:
                logger.warning(f"Finding not found for triage update: {finding_uuid}")
                return False
            
            now = datetime.datetime.now(datetime.timezone.utc)
            old_status = finding.triage_status
            
            # Validate completion classification
            if new_status == 'completed' and not completion_classification:
                logger.error("Completion classification required when marking as completed")
                return False
            
            # Update status history
            history_entry = {
                'timestamp': now.isoformat(),
                'old_status': old_status,
                'new_status': new_status,
                'changed_by': user_email,
                'notes': notes
            }
            
            if finding.status_history:
                finding.status_history.append(history_entry)
            else:
                finding.status_history = [history_entry]
            
            # Update the finding
            finding.triage_status = new_status
            finding.last_updated = now
            
            # Handle assignment
            if new_status in ['reviewing', 'escalated_to_client'] and finding.assigned_to != user_email:
                finding.assigned_to = user_email
                finding.assigned_at = now
            elif new_status == 'unassigned':
                finding.assigned_to = None
                finding.assigned_at = None
            
            # Handle completion
            if new_status == 'completed':
                finding.completion_classification = completion_classification
                finding.completed_at = now
                finding.completed_by = user_email
            else:
                finding.completion_classification = None
                finding.completed_at = None
                finding.completed_by = None
            
            # Update optional fields
            if notes:
                finding.triage_notes = notes
            if priority:
                finding.priority = priority
            if severity:
                finding.severity = severity
            
            session.commit()
            logger.info(f"Updated triage status for {finding_uuid}: {old_status} -> {new_status} by {user_email}")
            
            # Send email notification for status change
            try:
                from .email_notifications import get_email_service
                email_service = get_email_service()
                if email_service.is_enabled():
                    finding_dict = finding.to_dict()
                    email_service.send_status_change_notification(self, finding_dict, old_status, new_status, user_email)
            except Exception as email_error:
                logger.error(f"Failed to send email notification for status change {finding_uuid}: {email_error}")
                # Don't fail the entire operation if email fails
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update triage status for {finding_uuid}: {e}")
            return False
        finally:
            session.close()
    
    def get_findings_by_status(
        self, 
        triage_status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        repo_name: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get findings filtered by triage status and other criteria.
        
        Args:
            triage_status: Filter by triage status
            assigned_to: Filter by assigned user email
            repo_name: Filter by repository name
            limit: Maximum number of findings to return
            
        Returns:
            List of finding dictionaries
        """
        session = self.get_session()
        try:
            query = session.query(SecurityFinding)
            
            # Apply filters
            if triage_status:
                query = query.filter(SecurityFinding.triage_status == triage_status)
            if assigned_to:
                query = query.filter(SecurityFinding.assigned_to == assigned_to)
            if repo_name:
                query = query.filter(SecurityFinding.repo_name == repo_name)
            
            # Only active (non-expired) findings (only if expiration checking is enabled)
            if self.check_expiration:
                query = query.filter(
                    SecurityFinding.expires_at > datetime.datetime.now(datetime.timezone.utc)
                )
            
            findings = query.order_by(
                SecurityFinding.created_at.desc()
            ).limit(limit).all()
            
            return [finding.to_dict() for finding in findings]
            
        except Exception as e:
            logger.error(f"Failed to retrieve findings by status: {e}")
            return []
        finally:
            session.close()
    
    def get_triage_statistics(self) -> Dict[str, Any]:
        """
        Get triage-related statistics.
        
        Returns:
            Dict containing triage statistics
        """
        session = self.get_session()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Count by triage status
            status_counts = {}
            for status in ['unassigned', 'reviewing', 'escalated_to_client', 'completed']:
                query = session.query(SecurityFinding).filter(
                    SecurityFinding.triage_status == status
                )
                
                # Only filter by expiration if expiration checking is enabled
                if self.check_expiration:
                    query = query.filter(SecurityFinding.expires_at > now)
                
                count = query.count()
                status_counts[status] = count
            
            # Count by completion classification
            completion_counts = {}
            for classification in ['true_positive', 'false_positive']:
                query = session.query(SecurityFinding).filter(
                    SecurityFinding.completion_classification == classification
                )
                
                # Only filter by expiration if expiration checking is enabled
                if self.check_expiration:
                    query = query.filter(SecurityFinding.expires_at > now)
                
                count = query.count()
                completion_counts[classification] = count
            
            # Count assigned findings per user
            assigned_counts = {}
            query = session.query(SecurityFinding.assigned_to).filter(
                SecurityFinding.assigned_to.isnot(None)
            )
            
            # Only filter by expiration if expiration checking is enabled
            if self.check_expiration:
                query = query.filter(SecurityFinding.expires_at > now)
                
            assigned_findings = query.all()
            
            for (assigned_to,) in assigned_findings:
                assigned_counts[assigned_to] = assigned_counts.get(assigned_to, 0) + 1
            
            return {
                'status_counts': status_counts,
                'completion_counts': completion_counts,
                'assigned_counts': assigned_counts,
                'last_updated': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get triage statistics: {e}")
            return {}
        finally:
            session.close()
    
    def add_note(self, finding_uuid: str, note_text: str, user_email: str) -> bool:
        """
        Add a note to a finding.
        
        Args:
            finding_uuid: UUID of the finding
            note_text: Text content of the note
            user_email: Email of the user adding the note
            
        Returns:
            bool: True if note was added successfully, False otherwise
        """
        session = self.get_session()
        try:
            # Verify the finding exists
            finding = session.query(SecurityFinding).filter(
                SecurityFinding.uuid == finding_uuid
            ).first()
            
            if not finding:
                logger.warning(f"Finding not found for note addition: {finding_uuid}")
                return False
            
            # Create the note
            note = FindingNote(
                finding_uuid=finding_uuid,
                note_text=note_text,
                created_by=user_email
            )
            
            session.add(note)
            session.commit()
            
            logger.info(f"Added note to finding {finding_uuid} by {user_email}")
            
            # Send email notification for comment
            try:
                from .email_notifications import get_email_service
                email_service = get_email_service()
                if email_service.is_enabled():
                    finding_dict = finding.to_dict()
                    email_service.send_comment_notification(self, finding_dict, note_text, user_email)
            except Exception as email_error:
                logger.error(f"Failed to send email notification for comment {finding_uuid}: {email_error}")
                # Don't fail the entire operation if email fails
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to add note to finding {finding_uuid}: {e}")
            return False
        finally:
            session.close()
    
    def get_notes(self, finding_uuid: str) -> List[Dict[str, Any]]:
        """
        Get all notes for a finding.
        
        Args:
            finding_uuid: UUID of the finding
            
        Returns:
            List of note dictionaries ordered by creation time (newest first)
        """
        session = self.get_session()
        try:
            notes = session.query(FindingNote).filter(
                FindingNote.finding_uuid == finding_uuid
            ).order_by(FindingNote.created_at.desc()).all()
            
            return [note.to_dict() for note in notes]
            
        except Exception as e:
            logger.error(f"Failed to retrieve notes for finding {finding_uuid}: {e}")
            return []
        finally:
            session.close()
    
    def delete_note(self, finding_uuid: str, note_id: int, user_email: str) -> bool:
        """
        Delete a note from a finding.
        
        Args:
            finding_uuid: UUID of the finding
            note_id: ID of the note to delete
            user_email: Email of the user attempting to delete the note
            
        Returns:
            bool: True if note was deleted successfully, False otherwise
        """
        session = self.get_session()
        try:
            # Get the note
            note = session.query(FindingNote).filter(
                FindingNote.id == note_id,
                FindingNote.finding_uuid == finding_uuid
            ).first()
            
            if not note:
                logger.warning(f"Note not found for deletion: {note_id} in finding {finding_uuid}")
                return False
            
            # Verify the finding exists
            finding = session.query(SecurityFinding).filter(
                SecurityFinding.uuid == finding_uuid
            ).first()
            
            if not finding:
                logger.warning(f"Finding not found for note deletion: {finding_uuid}")
                return False
            
            # Delete the note
            session.delete(note)
            session.commit()
            
            logger.info(f"Deleted note {note_id} from finding {finding_uuid} by {user_email}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete note {note_id} from finding {finding_uuid}: {e}")
            return False
        finally:
            session.close()

    def health_check(self) -> bool:
        """
        Check database connectivity and health.
        
        Returns:
            bool: True if database is healthy, False otherwise
        """
        try:
            session = self.get_session()
            # Simple query to test connectivity
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    # User management methods
    def create_user(self, email: str, name: str, is_admin: bool, repository_access: Optional[List[str]], created_by: str, is_owner: bool = False) -> bool:
        """
        Create a new user.
        
        Args:
            email: User's email address
            name: User's display name
            is_admin: Whether the user is an admin
            repository_access: List of repository names the user can access (None for all)
            created_by: Email of the admin creating the user
            is_owner: Whether the user is an owner (owners can't be deleted)
            
        Returns:
            bool: True if user was created successfully, False otherwise
        """
        session = self.get_session()
        try:
            # Check if user already exists
            existing_user = session.query(User).filter(User.email == email).first()
            if existing_user:
                logger.warning(f"User already exists: {email}")
                return False
            
            # Create new user
            user = User(
                email=email,
                name=name,
                is_admin=is_admin,
                is_owner=is_owner,
                repository_access=repository_access,
                created_by=created_by
            )
            
            session.add(user)
            session.commit()
            
            logger.info(f"Created user: {email} by {created_by} (owner: {is_owner})")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create user {email}: {e}")
            return False
        finally:
            session.close()
    
    def get_user(self, email: str) -> Optional[User]:
        """
        Get a user by email.
        
        Args:
            email: User's email address
            
        Returns:
            User object or None if not found
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            return user
            
        except Exception as e:
            logger.error(f"Failed to retrieve user {email}: {e}")
            return None
        finally:
            session.close()
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """
        Get all users.
        
        Returns:
            List of user dictionaries
        """
        session = self.get_session()
        try:
            users = session.query(User).filter(User.is_active == True).order_by(User.created_at.desc()).all()
            return [user.to_dict() for user in users]
            
        except Exception as e:
            logger.error(f"Failed to retrieve all users: {e}")
            return []
        finally:
            session.close()
    
    def update_user(self, email: str, name: Optional[str] = None, is_admin: Optional[bool] = None, 
                   repository_access: Optional[List[str]] = None, is_active: Optional[bool] = None,
                   email_notifications_enabled: Optional[bool] = None) -> bool:
        """
        Update a user's information.
        
        Args:
            email: User's email address
            name: Updated display name
            is_admin: Updated admin status
            repository_access: Updated repository access list
            is_active: Updated active status
            email_notifications_enabled: Updated email notifications preference
            
        Returns:
            bool: True if user was updated successfully, False otherwise
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                logger.warning(f"User not found for update: {email}")
                return False
            
            # Update fields if provided
            if name is not None:
                user.name = name
            if is_admin is not None:
                user.is_admin = is_admin
            if repository_access is not None:
                user.repository_access = repository_access
            if is_active is not None:
                user.is_active = is_active
            if email_notifications_enabled is not None:
                user.email_notifications_enabled = email_notifications_enabled
            
            session.commit()
            logger.info(f"Updated user: {email}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update user {email}: {e}")
            return False
        finally:
            session.close()
    
    def delete_user(self, email: str) -> bool:
        """
        Delete a user (soft delete by setting is_active = False).
        
        Args:
            email: User's email address
            
        Returns:
            bool: True if user was deleted successfully, False otherwise
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                logger.warning(f"User not found for deletion: {email}")
                return False
            
            # Prevent deletion of owner users
            if user.is_owner:
                logger.warning(f"Cannot delete owner user: {email}")
                return False
            
            user.is_active = False
            session.commit()
            
            logger.info(f"Deleted user: {email}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete user {email}: {e}")
            return False
        finally:
            session.close()
    
    def update_last_login(self, email: str) -> bool:
        """
        Update user's last login timestamp.
        
        Args:
            email: User's email address
            
        Returns:
            bool: True if updated successfully, False otherwise
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                logger.warning(f"User not found for last login update: {email}")
                return False
            
            user.last_login = datetime.datetime.now(datetime.timezone.utc)
            session.commit()
            
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update last login for user {email}: {e}")
            return False
        finally:
            session.close()
    
    def is_admin(self, email: str) -> bool:
        """
        Check if a user is an admin.
        
        Args:
            email: User's email address
            
        Returns:
            bool: True if user is admin, False otherwise
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email, User.is_active == True).first()
            return user.is_admin if user else False
            
        except Exception as e:
            logger.error(f"Failed to check admin status for user {email}: {e}")
            return False
        finally:
            session.close()
    
    def is_owner(self, email: str) -> bool:
        """
        Check if a user is an owner.
        
        Args:
            email: User's email address
            
        Returns:
            bool: True if user is owner, False otherwise
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email, User.is_active == True).first()
            return user.is_owner if user else False
            
        except Exception as e:
            logger.error(f"Failed to check owner status for user {email}: {e}")
            return False
        finally:
            session.close()
    
    def get_user_repository_access(self, email: str) -> List[str]:
        """
        Get repositories a user has access to.
        
        Args:
            email: User's email address
            
        Returns:
            List of repository names (empty list means all repositories)
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email, User.is_active == True).first()
            if not user:
                return []
            
            return user.get_accessible_repositories()
            
        except Exception as e:
            logger.error(f"Failed to get repository access for user {email}: {e}")
            return []
        finally:
            session.close()
    
    def filter_findings_by_user_access(self, findings: List[Dict[str, Any]], user_email: str) -> List[Dict[str, Any]]:
        """
        Filter findings based on user's repository access.
        
        Args:
            findings: List of finding dictionaries
            user_email: User's email address
            
        Returns:
            Filtered list of findings
        """
        try:
            # Get user's repository access
            accessible_repos = self.get_user_repository_access(user_email)
            
            # If empty list, user has access to all repositories
            if not accessible_repos:
                return findings
            
            # Filter findings by accessible repositories
            filtered_findings = []
            for finding in findings:
                repo_name = finding.get('repo_name', '')
                if repo_name in accessible_repos:
                    filtered_findings.append(finding)
            
            return filtered_findings
            
        except Exception as e:
            logger.error(f"Failed to filter findings by user access for {user_email}: {e}")
            return findings  # Return all findings on error

    def _normalize_branch_configs(
        self,
        branch_configs: Optional[List[Dict[str, Any]]] = None,
        branches: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Normalize legacy branch lists or structured branch configs."""
        raw_configs = branch_configs
        if raw_configs is None:
            raw_configs = [{'branch_name': branch} for branch in (branches or [])]

        normalized: List[Dict[str, Any]] = []
        seen = set()
        for config in raw_configs:
            branch_name = (config.get('branch_name') or '').strip()
            if not branch_name or branch_name in seen:
                continue

            starting_commit_sha = (config.get('starting_commit_sha') or '').strip() or None
            hardfork_name = (config.get('hardfork_name') or '').strip() or None

            normalized.append({
                'branch_name': branch_name,
                'starting_commit_sha': starting_commit_sha,
                'hardfork_name': hardfork_name,
                'last_seen_head_sha': config.get('last_seen_head_sha'),
                'last_reviewed_head_sha': config.get('last_reviewed_head_sha'),
                'local_sync_status': config.get('local_sync_status') or 'pending',
                'last_sync_error': config.get('last_sync_error'),
                'last_synced_at': config.get('last_synced_at'),
            })
            seen.add(branch_name)

        return normalized

    def _load_branch_configs(self, session: Session, repository_name: str) -> List[Dict[str, Any]]:
        configs = session.query(RepositoryBranchConfig).filter(
            RepositoryBranchConfig.repository_name == repository_name
        ).order_by(RepositoryBranchConfig.branch_name).all()
        return [config.to_dict() for config in configs]

    def _attach_branch_configs(self, session: Session, repository: Optional[Repository]) -> Optional[Repository]:
        if repository is None:
            return None
        repository.branch_configs_data = self._load_branch_configs(session, repository.name)
        return repository

    def _replace_branch_configs(
        self,
        session: Session,
        repository_name: str,
        branch_configs: List[Dict[str, Any]],
        preserve_runtime_state: bool = True
    ) -> None:
        existing_configs = {
            config.branch_name: config
            for config in session.query(RepositoryBranchConfig).filter(
                RepositoryBranchConfig.repository_name == repository_name
            ).all()
        }

        session.query(RepositoryBranchConfig).filter(
            RepositoryBranchConfig.repository_name == repository_name
        ).delete()

        for config in branch_configs:
            existing = existing_configs.get(config['branch_name'])
            preserve_state = (
                preserve_runtime_state
                and existing is not None
                and existing.starting_commit_sha == config.get('starting_commit_sha')
                and existing.hardfork_name == config.get('hardfork_name')
            )

            session.add(RepositoryBranchConfig(
                repository_name=repository_name,
                branch_name=config['branch_name'],
                starting_commit_sha=config.get('starting_commit_sha'),
                hardfork_name=config.get('hardfork_name'),
                last_seen_head_sha=existing.last_seen_head_sha if preserve_state else config.get('last_seen_head_sha'),
                last_reviewed_head_sha=existing.last_reviewed_head_sha if preserve_state else config.get('last_reviewed_head_sha'),
                local_sync_status=existing.local_sync_status if preserve_state else (config.get('local_sync_status') or 'pending'),
                last_sync_error=existing.last_sync_error if preserve_state else config.get('last_sync_error'),
                last_synced_at=existing.last_synced_at if preserve_state else config.get('last_synced_at'),
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            ))

    # Repository management methods
    def create_repository(self, name: str, url: str, branches: Optional[List[str]] = None,
                         branch_configs: Optional[List[Dict[str, Any]]] = None,
                         agent_file_path: Optional[str] = None,
                         telegram_channel_id: Optional[str] = None,
                         notify_default_channel: bool = False,
                         created_by: str = 'system') -> bool:
        """
        Create a new repository configuration.
        
        Args:
            name: Repository name (e.g., "ethereum/go-ethereum")
            url: Full GitHub URL
            branches: Legacy list of branch names to monitor
            branch_configs: Structured branch review configuration
            agent_file_path: Relative path to AGENT.md/AGENTS.md
            telegram_channel_id: Optional Telegram channel ID
            notify_default_channel: Whether to notify default channel
            created_by: Email of admin who created it
            
        Returns:
            bool: True if repository was created successfully, False otherwise
        """
        session = self.get_session()
        try:
            # Check if repository already exists
            existing_repo = session.query(Repository).filter(Repository.name == name).first()
            if existing_repo:
                logger.warning(f"Repository already exists: {name}")
                return False
            
            normalized_branch_configs = self._normalize_branch_configs(branch_configs=branch_configs, branches=branches)
            if not normalized_branch_configs:
                logger.warning(f"Repository {name} requires at least one branch configuration")
                return False

            repository = Repository(
                name=name,
                url=url,
                branches=[config['branch_name'] for config in normalized_branch_configs],
                agent_file_path=agent_file_path,
                telegram_channel_id=telegram_channel_id,
                notify_default_channel=notify_default_channel,
                created_by=created_by,
                updated_by=created_by
            )
            
            session.add(repository)
            session.flush()
            self._replace_branch_configs(session, name, normalized_branch_configs, preserve_runtime_state=False)
            session.commit()
            
            logger.info(f"Created repository: {name} by {created_by}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create repository {name}: {e}")
            return False
        finally:
            session.close()

    def get_repository(self, name: str) -> Optional[Repository]:
        """
        Get a repository by name.
        
        Args:
            name: Repository name
            
        Returns:
            Repository object or None if not found
        """
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.name == name).first()
            return self._attach_branch_configs(session, repository)
            
        except Exception as e:
            logger.error(f"Failed to retrieve repository {name}: {e}")
            return None
        finally:
            session.close()

    def get_repository_by_id(self, repository_id: int) -> Optional[Repository]:
        """Get a repository by numeric database ID."""
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.id == repository_id).first()
            return self._attach_branch_configs(session, repository)
        except Exception as e:
            logger.error(f"Failed to retrieve repository {repository_id}: {e}")
            return None
        finally:
            session.close()

    def get_all_repositories(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """
        Get all repositories.
        
        Args:
            include_inactive: Whether to include inactive repositories
            
        Returns:
            List of repository dictionaries
        """
        session = self.get_session()
        try:
            query = session.query(Repository)
            if not include_inactive:
                query = query.filter(Repository.is_active == True)
            
            repositories = query.order_by(Repository.name).all()
            return [self._attach_branch_configs(session, repo).to_dict() for repo in repositories]
            
        except Exception as e:
            logger.error(f"Failed to retrieve all repositories: {e}")
            return []
        finally:
            session.close()

    def update_repository(self, name: str, url: Optional[str] = None,
                         branches: Optional[List[str]] = None,
                         branch_configs: Optional[List[Dict[str, Any]]] = None,
                         agent_file_path: Optional[str] = None,
                         telegram_channel_id: Optional[str] = None,
                         notify_default_channel: Optional[bool] = None,
                         is_active: Optional[bool] = None,
                         updated_by: str = 'system') -> bool:
        """
        Update a repository's configuration.
        
        Args:
            name: Repository name
            url: Updated URL
            branches: Legacy updated branches list
            branch_configs: Updated structured branch configs
            agent_file_path: Updated agent file path
            telegram_channel_id: Updated Telegram channel ID
            notify_default_channel: Updated notification setting
            is_active: Updated active status
            updated_by: Email of admin who updated it
            
        Returns:
            bool: True if repository was updated successfully, False otherwise
        """
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.name == name).first()
            if not repository:
                logger.warning(f"Repository not found for update: {name}")
                return False
            
            # Update fields if provided
            if url is not None:
                repository.url = url
            normalized_branch_configs = None
            if branch_configs is not None or branches is not None:
                normalized_branch_configs = self._normalize_branch_configs(branch_configs=branch_configs, branches=branches)
                if not normalized_branch_configs:
                    logger.warning(f"Repository {name} update requires at least one branch configuration")
                    return False
                repository.branches = [config['branch_name'] for config in normalized_branch_configs]
            if agent_file_path is not None:
                repository.agent_file_path = agent_file_path
            if telegram_channel_id is not None:
                repository.telegram_channel_id = telegram_channel_id
            if notify_default_channel is not None:
                repository.notify_default_channel = notify_default_channel
            if is_active is not None:
                repository.is_active = is_active
            
            repository.updated_by = updated_by
            repository.updated_at = datetime.datetime.now(datetime.timezone.utc)

            if normalized_branch_configs is not None:
                self._replace_branch_configs(session, name, normalized_branch_configs)
            
            session.commit()
            logger.info(f"Updated repository: {name} by {updated_by}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update repository {name}: {e}")
            return False
        finally:
            session.close()

    def delete_repository(self, name: str) -> bool:
        """
        Delete a repository (soft delete by setting is_active = False).
        
        Args:
            name: Repository name
            
        Returns:
            bool: True if repository was deleted successfully, False otherwise
        """
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.name == name).first()
            if not repository:
                logger.warning(f"Repository not found for deletion: {name}")
                return False
            
            repository.is_active = False
            repository.updated_at = datetime.datetime.now(datetime.timezone.utc)
            session.commit()
            
            logger.info(f"Deleted repository: {name}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete repository {name}: {e}")
            return False
        finally:
            session.close()

    def get_repositories_for_monitoring(self) -> List[Dict[str, Any]]:
        """
        Get active repositories formatted for the monitoring system.
        
        Returns:
            List of repositories in the format expected by the monitoring system
        """
        session = self.get_session()
        try:
            repositories = session.query(Repository).filter(Repository.is_active == True).all()
            
            result = []
            for repo in repositories:
                branch_configs = self._load_branch_configs(session, repo.name)
                repo_config = {
                    'name': repo.name,
                    'url': repo.url,
                    'branches': [config['branch_name'] for config in branch_configs],
                    'branch_configs': branch_configs,
                    'agent_file_path': repo.agent_file_path,
                }
                
                # Add telegram settings if available
                if repo.telegram_channel_id:
                    repo_config['telegram_channel_id'] = repo.telegram_channel_id
                if repo.notify_default_channel:
                    repo_config['notify_default_channel'] = repo.notify_default_channel
                
                result.append(repo_config)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get repositories for monitoring: {e}")
            return []
        finally:
            session.close()

    def update_repository_branch_runtime_state(
        self,
        repository_name: str,
        branch_name: str,
        *,
        last_seen_head_sha: Optional[str] = None,
        last_reviewed_head_sha: Optional[str] = None,
        local_sync_status: Optional[str] = None,
        last_sync_error: Optional[str] = None,
        last_synced_at: Optional[datetime.datetime] = None
    ) -> bool:
        """Update runtime sync/review state for a monitored branch."""
        session = self.get_session()
        try:
            branch_config = session.query(RepositoryBranchConfig).filter(
                RepositoryBranchConfig.repository_name == repository_name,
                RepositoryBranchConfig.branch_name == branch_name
            ).first()
            if not branch_config:
                logger.warning(f"Repository branch config not found for {repository_name}:{branch_name}")
                return False

            if last_seen_head_sha is not None:
                branch_config.last_seen_head_sha = last_seen_head_sha
            if last_reviewed_head_sha is not None:
                branch_config.last_reviewed_head_sha = last_reviewed_head_sha
            if local_sync_status is not None:
                branch_config.local_sync_status = local_sync_status
            if last_sync_error is not None or local_sync_status in {'ready', 'reviewed', 'syncing'}:
                branch_config.last_sync_error = last_sync_error
            if last_synced_at is not None:
                branch_config.last_synced_at = last_synced_at
            branch_config.updated_at = datetime.datetime.now(datetime.timezone.utc)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update runtime state for {repository_name}:{branch_name}: {e}")
            return False
        finally:
            session.close()

    def get_repository_branch_configs(self, repository_name: str) -> List[Dict[str, Any]]:
        """Return structured branch configs for a repository."""
        session = self.get_session()
        try:
            return self._load_branch_configs(session, repository_name)
        except Exception as e:
            logger.error(f"Failed to load branch configs for {repository_name}: {e}")
            return []
        finally:
            session.close()

    def migrate_repositories_from_config(self, config_file_path: str, created_by: str = 'migration') -> bool:
        """
        Migrate repository configurations from config.json to database.
        
        Args:
            config_file_path: Path to config.json file
            created_by: Email of admin performing migration
            
        Returns:
            bool: True if migration was successful, False otherwise
        """
        try:
            import json
            
            with open(config_file_path, 'r') as f:
                config = json.load(f)
            
            repositories = config.get('repositories', [])
            
            migrated_count = 0
            for repo_config in repositories:
                url = repo_config.get('url', '')
                if not url:
                    continue
                
                # Extract repository name from URL
                name = Repository.extract_repo_name_from_url(url)
                branches = repo_config.get('branches', [])
                telegram_channel_id = repo_config.get('telegram_channel_id')
                notify_default_channel = repo_config.get('notify_default_channel', False)
                
                # Check if repository already exists
                if self.get_repository(name):
                    logger.info(f"Repository {name} already exists in database, skipping")
                    continue
                
                # Create repository
                success = self.create_repository(
                    name=name,
                    url=url,
                    branches=branches,
                    agent_file_path=repo_config.get('agent_file_path'),
                    telegram_channel_id=telegram_channel_id,
                    notify_default_channel=notify_default_channel,
                    created_by=created_by
                )
                
                if success:
                    migrated_count += 1
                    logger.info(f"Migrated repository: {name}")
                else:
                    logger.error(f"Failed to migrate repository: {name}")
            
            logger.info(f"Repository migration completed: {migrated_count} repositories migrated")
            return True
            
        except Exception as e:
            logger.error(f"Failed to migrate repositories from config: {e}")
            return False

    # API key management methods
    def create_api_key(self, user_email: str, name: str) -> Optional[str]:
        """
        Create a new API key for a user.
        
        Args:
            user_email: User's email address
            name: User-friendly name for the key
            
        Returns:
            str: The generated API key (plaintext, only shown once), or None if creation failed
        """
        import secrets
        import hashlib
        
        session = self.get_session()
        try:
            # Verify user exists
            user = session.query(User).filter(User.email == user_email, User.is_active == True).first()
            if not user:
                logger.warning(f"User not found for API key creation: {user_email}")
                return None
            
            # Generate a secure random API key
            api_key = f"etr_{secrets.token_urlsafe(32)}"
            
            # Hash the key for storage
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Store first 8 characters as prefix for identification
            key_prefix = api_key[:12]
            
            # Create API key record
            api_key_record = ApiKey(
                user_email=user_email,
                key_hash=key_hash,
                name=name,
                key_prefix=key_prefix
            )
            
            session.add(api_key_record)
            session.commit()
            
            logger.info(f"Created API key '{name}' for user {user_email}")
            
            # Return the plaintext key (this is the only time it will be available)
            return api_key
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create API key for {user_email}: {e}")
            return None
        finally:
            session.close()
    
    def get_user_api_keys(self, user_email: str) -> List[Dict[str, Any]]:
        """
        Get all API keys for a user.
        
        Args:
            user_email: User's email address
            
        Returns:
            List of API key dictionaries (without the actual keys)
        """
        session = self.get_session()
        try:
            api_keys = session.query(ApiKey).filter(
                ApiKey.user_email == user_email
            ).order_by(ApiKey.created_at.desc()).all()
            
            return [key.to_dict() for key in api_keys]
            
        except Exception as e:
            logger.error(f"Failed to retrieve API keys for {user_email}: {e}")
            return []
        finally:
            session.close()
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """
        Validate an API key and return the associated user email.
        
        Args:
            api_key: The API key to validate
            
        Returns:
            str: User email if valid, None otherwise
        """
        import hashlib
        
        session = self.get_session()
        try:
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Look up the key
            api_key_record = session.query(ApiKey).filter(
                ApiKey.key_hash == key_hash,
                ApiKey.is_active == True
            ).first()
            
            if not api_key_record:
                logger.debug("Invalid or inactive API key")
                return None
            
            # Verify user is still active
            user = session.query(User).filter(
                User.email == api_key_record.user_email,
                User.is_active == True
            ).first()
            
            if not user:
                logger.warning(f"API key belongs to inactive user: {api_key_record.user_email}")
                return None
            
            # Update usage statistics
            api_key_record.last_used_at = datetime.datetime.now(datetime.timezone.utc)
            api_key_record.usage_count += 1
            session.commit()
            
            logger.debug(f"Validated API key for user {user.email}")
            return user.email
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to validate API key: {e}")
            return None
        finally:
            session.close()
    
    def revoke_api_key(self, key_id: int, user_email: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: ID of the API key to revoke
            user_email: Email of the user revoking the key (must be the owner)
            
        Returns:
            bool: True if revoked successfully, False otherwise
        """
        session = self.get_session()
        try:
            api_key = session.query(ApiKey).filter(
                ApiKey.id == key_id,
                ApiKey.user_email == user_email
            ).first()
            
            if not api_key:
                logger.warning(f"API key not found or doesn't belong to user: {key_id}")
                return False
            
            api_key.is_active = False
            api_key.revoked_at = datetime.datetime.now(datetime.timezone.utc)
            session.commit()
            
            logger.info(f"Revoked API key {key_id} ({api_key.name}) for user {user_email}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to revoke API key {key_id}: {e}")
            return False
        finally:
            session.close()
    
    def delete_api_key(self, key_id: int, user_email: str) -> bool:
        """
        Delete an API key permanently.
        
        Args:
            key_id: ID of the API key to delete
            user_email: Email of the user deleting the key (must be the owner)
            
        Returns:
            bool: True if deleted successfully, False otherwise
        """
        session = self.get_session()
        try:
            api_key = session.query(ApiKey).filter(
                ApiKey.id == key_id,
                ApiKey.user_email == user_email
            ).first()
            
            if not api_key:
                logger.warning(f"API key not found or doesn't belong to user: {key_id}")
                return False
            
            session.delete(api_key)
            session.commit()
            
            logger.info(f"Deleted API key {key_id} ({api_key.name}) for user {user_email}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete API key {key_id}: {e}")
            return False
        finally:
            session.close()


# Global database manager instance
_db_manager = None

def get_database_manager() -> DatabaseManager:
    """
    Get the global database manager instance.
    
    Returns:
        DatabaseManager: The database manager instance
    """
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        # Ensure tables exist
        _db_manager.create_tables()
        # Run migration to add triage fields if needed
        try:
            migrate_database_schema(_db_manager)
        except Exception as e:
            logger.warning(f"Database migration failed during initialization: {e}")
    return _db_manager


def migrate_database_schema(db_manager: DatabaseManager):
    """
    Migrate existing database schema to add triage fields.
    This function safely adds the new columns if they don't exist.
    
    Args:
        db_manager: DatabaseManager instance to use for migration
    """
    
    # SQL commands to add new columns
    migration_commands = [
        # Add triage status enum if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'triage_status_enum') THEN
                CREATE TYPE triage_status_enum AS ENUM ('unassigned', 'reviewing', 'escalated_to_client', 'completed');
            END IF;
        END$$;
        """,
        
        # Add completion classification enum if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'completion_classification_enum') THEN
                CREATE TYPE completion_classification_enum AS ENUM ('true_positive', 'false_positive');
            END IF;
        END$$;
        """,
        
        # Add priority enum if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'priority_enum') THEN
                CREATE TYPE priority_enum AS ENUM ('critical', 'high', 'medium', 'low');
            END IF;
        END$$;
        """,
        
        # Add severity enum if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'severity_enum') THEN
                CREATE TYPE severity_enum AS ENUM ('critical', 'high', 'medium', 'low', 'info');
            END IF;
        END$$;
        """,
        
        # Add triage_status column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'triage_status') THEN
                ALTER TABLE security_findings ADD COLUMN triage_status triage_status_enum NOT NULL DEFAULT 'unassigned';
            END IF;
        END$$;
        """,
        
        # Add assigned_to column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'assigned_to') THEN
                ALTER TABLE security_findings ADD COLUMN assigned_to VARCHAR(255);
            END IF;
        END$$;
        """,
        
        # Add assigned_at column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'assigned_at') THEN
                ALTER TABLE security_findings ADD COLUMN assigned_at TIMESTAMP WITH TIME ZONE;
            END IF;
        END$$;
        """,
        
        # Add completion_classification column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'completion_classification') THEN
                ALTER TABLE security_findings ADD COLUMN completion_classification completion_classification_enum;
            END IF;
        END$$;
        """,
        
        # Add completed_at column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'completed_at') THEN
                ALTER TABLE security_findings ADD COLUMN completed_at TIMESTAMP WITH TIME ZONE;
            END IF;
        END$$;
        """,
        
        # Add completed_by column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'completed_by') THEN
                ALTER TABLE security_findings ADD COLUMN completed_by VARCHAR(255);
            END IF;
        END$$;
        """,
        
        # Add triage_notes column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'triage_notes') THEN
                ALTER TABLE security_findings ADD COLUMN triage_notes TEXT;
            END IF;
        END$$;
        """,
        
        # Add status_history column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'status_history') THEN
                ALTER TABLE security_findings ADD COLUMN status_history JSON;
            END IF;
        END$$;
        """,
        
        # Add priority column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'priority') THEN
                ALTER TABLE security_findings ADD COLUMN priority priority_enum;
            END IF;
        END$$;
        """,
        
        # Add severity column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'severity') THEN
                ALTER TABLE security_findings ADD COLUMN severity severity_enum;
            END IF;
        END$$;
        """,
        
        # Add last_updated column
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'last_updated') THEN
                ALTER TABLE security_findings ADD COLUMN last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
            END IF;
        END$$;
        """,
        
        # Add PR columns
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'pr_number') THEN
                ALTER TABLE security_findings ADD COLUMN pr_number INTEGER;
            END IF;
        END$$;
        """,
        
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'pr_title') THEN
                ALTER TABLE security_findings ADD COLUMN pr_title TEXT;
            END IF;
        END$$;
        """,
        
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'security_findings' AND column_name = 'pr_state') THEN
                ALTER TABLE security_findings ADD COLUMN pr_state VARCHAR(20);
            END IF;
        END$$;
        """,
        
        # Create finding_notes table
        """
        CREATE TABLE IF NOT EXISTS finding_notes (
            id SERIAL PRIMARY KEY,
            finding_uuid UUID NOT NULL,
            note_text TEXT NOT NULL,
            created_by VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
        """,
        
        # Create index on finding_uuid for performance
        """
        CREATE INDEX IF NOT EXISTS idx_finding_notes_finding_uuid ON finding_notes(finding_uuid);
        """,
        
        # Create index on created_at for performance  
        """
        CREATE INDEX IF NOT EXISTS idx_finding_notes_created_at ON finding_notes(created_at);
        """,
        
        # Create users table
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            is_owner BOOLEAN NOT NULL DEFAULT FALSE,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            repository_access JSON,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            created_by VARCHAR(255) NOT NULL,
            last_login TIMESTAMP WITH TIME ZONE
        );
        """,
        
        # Add is_owner column if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'is_owner') THEN
                ALTER TABLE users ADD COLUMN is_owner BOOLEAN NOT NULL DEFAULT FALSE;
            END IF;
        END$$;
        """,
        
        # Create index on email for performance
        """
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """,
        
        # Create index on is_active for performance
        """
        CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
        """,
        
        # Add email_notifications_enabled column if it doesn't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_notifications_enabled') THEN
                ALTER TABLE users ADD COLUMN email_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE;
            END IF;
        END$$;
        """,
        
        # Create repositories table
        """
        CREATE TABLE IF NOT EXISTS repositories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            url VARCHAR(500) NOT NULL,
            branches JSON NOT NULL,
            agent_file_path VARCHAR(500),
            telegram_channel_id VARCHAR(255),
            notify_default_channel BOOLEAN NOT NULL DEFAULT FALSE,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            created_by VARCHAR(255) NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_by VARCHAR(255) NOT NULL
        );
        """,
        
        # Create index on repository name for performance
        """
        CREATE INDEX IF NOT EXISTS idx_repositories_name ON repositories(name);
        """,
        
        # Create index on is_active for performance
        """
        CREATE INDEX IF NOT EXISTS idx_repositories_is_active ON repositories(is_active);
        """,
        
        # Add agent_file_path column to repositories table
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'repositories' AND column_name = 'agent_file_path') THEN
                ALTER TABLE repositories ADD COLUMN agent_file_path VARCHAR(500);
            END IF;
        END$$;
        """,

        # Create repository branch config table
        """
        CREATE TABLE IF NOT EXISTS repository_branch_configs (
            id SERIAL PRIMARY KEY,
            repository_name VARCHAR(255) NOT NULL,
            branch_name VARCHAR(255) NOT NULL,
            starting_commit_sha VARCHAR(64),
            hardfork_name VARCHAR(255),
            last_seen_head_sha VARCHAR(64),
            last_reviewed_head_sha VARCHAR(64),
            local_sync_status VARCHAR(50) NOT NULL DEFAULT 'pending',
            last_sync_error TEXT,
            last_synced_at TIMESTAMP WITH TIME ZONE,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
        """,

        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_repository_branch_configs_repo_branch
        ON repository_branch_configs(repository_name, branch_name);
        """,

        """
        CREATE INDEX IF NOT EXISTS idx_repository_branch_configs_repo_name
        ON repository_branch_configs(repository_name);
        """,

        """
        CREATE INDEX IF NOT EXISTS idx_repository_branch_configs_status
        ON repository_branch_configs(local_sync_status);
        """,
        
        # Create api_keys table
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255) NOT NULL,
            key_hash VARCHAR(255) NOT NULL UNIQUE,
            name VARCHAR(255) NOT NULL,
            key_prefix VARCHAR(20) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            last_used_at TIMESTAMP WITH TIME ZONE,
            usage_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMP WITH TIME ZONE
        );
        """,
        
        # Create indexes on api_keys table
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_user_email ON api_keys(user_email);
        """,
        
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
        """,
        
        """
        CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
        """
    ]
    
    session = db_manager.get_session()
    try:
        for command in migration_commands:
            session.execute(text(command))
        session.commit()

        # Backfill branch configs from the legacy repositories.branches JSON field.
        repositories_without_configs = session.query(Repository).all()
        for repository in repositories_without_configs:
            existing_count = session.query(RepositoryBranchConfig).filter(
                RepositoryBranchConfig.repository_name == repository.name
            ).count()
            if existing_count > 0:
                continue

            for branch_name in repository.branches or []:
                if not branch_name:
                    continue
                session.add(RepositoryBranchConfig(
                    repository_name=repository.name,
                    branch_name=branch_name,
                    local_sync_status='pending',
                    updated_at=datetime.datetime.now(datetime.timezone.utc),
                ))
        session.commit()
        logger.info("Database schema migration completed successfully")
        return True
    except Exception as e:
        session.rollback()
        logger.error(f"Database migration failed: {e}")
        return False
    finally:
        session.close()


def initialize_database(database_url: Optional[str] = None, expiration_hours: int = 168, check_expiration: bool = False):
    """
    Initialize the database with custom settings.
    
    Args:
        database_url: PostgreSQL connection URL
        expiration_hours: Hours after which findings expire
        check_expiration: Whether to check expiration when retrieving findings
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url, expiration_hours, check_expiration)
    _db_manager.create_tables()
    
    # Run migration to add triage fields
    migrate_database_schema(_db_manager)
    
    logger.info("Database initialized with custom settings")
