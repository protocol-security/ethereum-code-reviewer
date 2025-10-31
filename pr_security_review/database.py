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
    
    # Agent assignment
    agent_id = Column(Integer, nullable=True)  # ID of the agent to use for this repository (NULL = use main agent)
    
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
        return {
            'id': self.id,
            'name': self.name,
            'url': self.url,
            'branches': self.branches,
            'agent_id': self.agent_id,
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


class Agent(Base):
    """Database model for AI agents with customizable prompts."""
    
    __tablename__ = 'agents'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Agent information
    name = Column(String(255), nullable=False)
    is_main = Column(Boolean, default=False, nullable=False)  # Main agent (from agent.json)
    
    # Agent prompts (stored as JSON)
    prompts = Column(JSON, nullable=False)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    created_by = Column(String(255), nullable=False)  # Email of user who created it
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_by = Column(String(255), nullable=False)  # Email of user who last updated it
    
    # Indexing for performance
    __table_args__ = (
        Index('idx_agents_name', 'name'),
        Index('idx_agents_is_main', 'is_main'),
    )
    
    def __repr__(self):
        return f"<Agent(id={self.id}, name={self.name}, is_main={self.is_main})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'is_main': self.is_main,
            'prompts': self.prompts,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by,
        }


class RepositoryDocument(Base):
    """Database model for repository-specific documentation with embeddings."""
    
    __tablename__ = 'repository_documents'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Repository association
    repository_name = Column(String(255), nullable=False)  # Repository name this document belongs to
    
    # Document information
    filename = Column(String(500), nullable=False)  # Original filename
    content = Column(Text, nullable=False)  # Document text content
    file_type = Column(String(50), nullable=False)  # File extension (pdf, md, txt)
    file_size = Column(Integer, nullable=False)  # File size in bytes
    
    # Embedding information
    embedding = Column(JSON, nullable=False)  # Vector embedding as JSON array
    embedding_model = Column(String(100), nullable=False, default='voyage-code-3')
    
    # Metadata
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    created_by = Column(String(255), nullable=False)  # Email of user who uploaded
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    
    # Indexing for performance
    __table_args__ = (
        Index('idx_repo_docs_repo_name', 'repository_name'),
        Index('idx_repo_docs_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<RepositoryDocument(id={self.id}, repo={self.repository_name}, filename={self.filename})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'repository_name': self.repository_name,
            'filename': self.filename,
            'content': self.content,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'embedding': self.embedding,
            'embedding_model': self.embedding_model,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
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
            
            # Create finding record
            finding = SecurityFinding(
                repo_name=repo_name,
                commit_sha=commit_info.sha,
                commit_url=getattr(commit_info, 'url', None),
                branch=getattr(commit_info, 'branch', None),
                author=getattr(commit_info, 'author', None),
                commit_date=getattr(commit_info, 'date', None),
                commit_message=getattr(commit_info, 'message', None),
                html_content=html_content,
                has_vulnerabilities=analysis.get('has_vulnerabilities', False),
                confidence_score=analysis.get('confidence_score'),
                summary=analysis.get('summary'),
                findings_count=len(analysis.get('findings', [])),
                analysis_data=analysis,
                extra_metadata=metadata or {},
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

    # Repository management methods
    def create_repository(self, name: str, url: str, branches: List[str], 
                         telegram_channel_id: Optional[str] = None, 
                         notify_default_channel: bool = False, 
                         created_by: str = 'system') -> bool:
        """
        Create a new repository configuration.
        
        Args:
            name: Repository name (e.g., "ethereum/go-ethereum")
            url: Full GitHub URL
            branches: List of branch names to monitor
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
            
            # Create new repository
            repository = Repository(
                name=name,
                url=url,
                branches=branches,
                telegram_channel_id=telegram_channel_id,
                notify_default_channel=notify_default_channel,
                created_by=created_by,
                updated_by=created_by
            )
            
            session.add(repository)
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
            return repository
            
        except Exception as e:
            logger.error(f"Failed to retrieve repository {name}: {e}")
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
            return [repo.to_dict() for repo in repositories]
            
        except Exception as e:
            logger.error(f"Failed to retrieve all repositories: {e}")
            return []
        finally:
            session.close()

    def update_repository(self, name: str, url: Optional[str] = None, 
                         branches: Optional[List[str]] = None,
                         telegram_channel_id: Optional[str] = None,
                         notify_default_channel: Optional[bool] = None,
                         is_active: Optional[bool] = None,
                         updated_by: str = 'system') -> bool:
        """
        Update a repository's configuration.
        
        Args:
            name: Repository name
            url: Updated URL
            branches: Updated branches list
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
            if branches is not None:
                repository.branches = branches
            if telegram_channel_id is not None:
                repository.telegram_channel_id = telegram_channel_id
            if notify_default_channel is not None:
                repository.notify_default_channel = notify_default_channel
            if is_active is not None:
                repository.is_active = is_active
            
            repository.updated_by = updated_by
            repository.updated_at = datetime.datetime.now(datetime.timezone.utc)
            
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
                repo_config = {
                    'url': repo.url,
                    'branches': repo.branches,
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

    # Repository document management methods
    def create_repository_document(
        self,
        repository_name: str,
        filename: str,
        content: str,
        file_type: str,
        file_size: int,
        embedding: List[float],
        created_by: str,
        embedding_model: str = 'voyage-code-3'
    ) -> bool:
        """
        Create a new repository document with embedding.
        
        Args:
            repository_name: Name of the repository
            filename: Original filename
            content: Document text content
            file_type: File extension (pdf, md, txt)
            file_size: File size in bytes
            embedding: Vector embedding as list of floats
            created_by: Email of user who uploaded
            embedding_model: Model used for embedding
            
        Returns:
            bool: True if document was created successfully, False otherwise
        """
        session = self.get_session()
        try:
            document = RepositoryDocument(
                repository_name=repository_name,
                filename=filename,
                content=content,
                file_type=file_type,
                file_size=file_size,
                embedding=embedding,
                embedding_model=embedding_model,
                created_by=created_by
            )
            
            session.add(document)
            session.commit()
            
            logger.info(f"Created document {filename} for repository {repository_name}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create document {filename}: {e}")
            return False
        finally:
            session.close()

    def get_repository_documents(self, repository_name: str) -> List[Dict[str, Any]]:
        """
        Get all documents for a repository.
        
        Args:
            repository_name: Name of the repository
            
        Returns:
            List of document dictionaries
        """
        session = self.get_session()
        try:
            documents = session.query(RepositoryDocument).filter(
                RepositoryDocument.repository_name == repository_name
            ).order_by(RepositoryDocument.created_at.desc()).all()
            
            return [doc.to_dict() for doc in documents]
            
        except Exception as e:
            logger.error(f"Failed to retrieve documents for repository {repository_name}: {e}")
            return []
        finally:
            session.close()

    def get_repository_document(self, document_id: int) -> Optional[RepositoryDocument]:
        """
        Get a specific document by ID.
        
        Args:
            document_id: ID of the document
            
        Returns:
            RepositoryDocument object or None if not found
        """
        session = self.get_session()
        try:
            document = session.query(RepositoryDocument).filter(
                RepositoryDocument.id == document_id
            ).first()
            
            return document
            
        except Exception as e:
            logger.error(f"Failed to retrieve document {document_id}: {e}")
            return None
        finally:
            session.close()

    def delete_repository_document(self, document_id: int) -> bool:
        """
        Delete a repository document.
        
        Args:
            document_id: ID of the document to delete
            
        Returns:
            bool: True if document was deleted successfully, False otherwise
        """
        session = self.get_session()
        try:
            document = session.query(RepositoryDocument).filter(
                RepositoryDocument.id == document_id
            ).first()
            
            if not document:
                logger.warning(f"Document not found for deletion: {document_id}")
                return False
            
            session.delete(document)
            session.commit()
            
            logger.info(f"Deleted document {document_id} ({document.filename})")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete document {document_id}: {e}")
            return False
        finally:
            session.close()

    def get_document_count_by_repository(self, repository_name: str) -> int:
        """
        Get count of documents for a repository.
        
        Args:
            repository_name: Name of the repository
            
        Returns:
            int: Number of documents
        """
        session = self.get_session()
        try:
            count = session.query(RepositoryDocument).filter(
                RepositoryDocument.repository_name == repository_name
            ).count()
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to get document count for repository {repository_name}: {e}")
            return 0
        finally:
            session.close()
    
    # Agent management methods
    def create_agent(self, name: str, prompts: Dict, created_by: str, is_main: bool = False) -> Optional[int]:
        """
        Create a new agent.
        
        Args:
            name: Agent name
            prompts: Agent prompts as dictionary
            created_by: Email of user who created it
            is_main: Whether this is the main agent
            
        Returns:
            int: Agent ID if successful, None otherwise
        """
        session = self.get_session()
        try:
            # If this is being set as main, unset any existing main agent
            if is_main:
                existing_main = session.query(Agent).filter(Agent.is_main == True).first()
                if existing_main:
                    existing_main.is_main = False
            
            agent = Agent(
                name=name,
                is_main=is_main,
                prompts=prompts,
                created_by=created_by,
                updated_by=created_by
            )
            
            session.add(agent)
            session.commit()
            
            logger.info(f"Created agent: {name} (id={agent.id}, main={is_main}) by {created_by}")
            return agent.id
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create agent {name}: {e}")
            return None
        finally:
            session.close()
    
    def get_agent(self, agent_id: int) -> Optional[Agent]:
        """
        Get an agent by ID.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Agent object or None if not found
        """
        session = self.get_session()
        try:
            agent = session.query(Agent).filter(Agent.id == agent_id).first()
            return agent
            
        except Exception as e:
            logger.error(f"Failed to retrieve agent {agent_id}: {e}")
            return None
        finally:
            session.close()
    
    def get_all_agents(self) -> List[Dict[str, Any]]:
        """
        Get all agents.
        
        Returns:
            List of agent dictionaries
        """
        session = self.get_session()
        try:
            agents = session.query(Agent).order_by(Agent.is_main.desc(), Agent.name).all()
            return [agent.to_dict() for agent in agents]
            
        except Exception as e:
            logger.error(f"Failed to retrieve all agents: {e}")
            return []
        finally:
            session.close()
    
    def get_main_agent(self) -> Optional[Agent]:
        """
        Get the main agent.
        
        Returns:
            Agent object or None if not found
        """
        session = self.get_session()
        try:
            agent = session.query(Agent).filter(Agent.is_main == True).first()
            return agent
            
        except Exception as e:
            logger.error(f"Failed to retrieve main agent: {e}")
            return None
        finally:
            session.close()
    
    def update_agent(self, agent_id: int, name: Optional[str] = None, prompts: Optional[Dict] = None, 
                    updated_by: str = 'system') -> bool:
        """
        Update an agent.
        
        Args:
            agent_id: Agent ID
            name: Updated name
            prompts: Updated prompts
            updated_by: Email of user who updated it
            
        Returns:
            bool: True if successful, False otherwise
        """
        session = self.get_session()
        try:
            agent = session.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                logger.warning(f"Agent not found for update: {agent_id}")
                return False
            
            # Update fields if provided
            if name is not None:
                agent.name = name
            if prompts is not None:
                agent.prompts = prompts
            
            agent.updated_by = updated_by
            agent.updated_at = datetime.datetime.now(datetime.timezone.utc)
            
            session.commit()
            logger.info(f"Updated agent {agent_id} by {updated_by}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update agent {agent_id}: {e}")
            return False
        finally:
            session.close()
    
    def delete_agent(self, agent_id: int) -> bool:
        """
        Delete an agent.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        session = self.get_session()
        try:
            agent = session.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                logger.warning(f"Agent not found for deletion: {agent_id}")
                return False
            
            # Prevent deletion of main agent
            if agent.is_main:
                logger.warning(f"Cannot delete main agent: {agent_id}")
                return False
            
            # Update any repositories using this agent to use NULL (main agent)
            repositories = session.query(Repository).filter(Repository.agent_id == agent_id).all()
            for repo in repositories:
                repo.agent_id = None
            
            session.delete(agent)
            session.commit()
            
            logger.info(f"Deleted agent {agent_id}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete agent {agent_id}: {e}")
            return False
        finally:
            session.close()
    
    def import_agent_from_file(self, agent_file_path: str, created_by: str = 'system') -> Optional[int]:
        """
        Import the main agent from agent.json file.
        
        Args:
            agent_file_path: Path to agent.json file
            created_by: Email of user performing import
            
        Returns:
            int: Agent ID if successful, None otherwise
        """
        try:
            with open(agent_file_path, 'r') as f:
                agent_data = json.load(f)
            
            prompts = agent_data.get('prompts', {})
            
            # Check if main agent already exists
            existing_main = self.get_main_agent()
            if existing_main:
                # Update existing main agent
                success = self.update_agent(
                    agent_id=existing_main.id,
                    prompts=prompts,
                    updated_by=created_by
                )
                if success:
                    logger.info(f"Updated main agent from {agent_file_path}")
                    return existing_main.id
                else:
                    logger.error(f"Failed to update main agent from {agent_file_path}")
                    return None
            else:
                # Create new main agent
                agent_id = self.create_agent(
                    name="Main Agent",
                    prompts=prompts,
                    created_by=created_by,
                    is_main=True
                )
                if agent_id:
                    logger.info(f"Imported main agent from {agent_file_path}")
                else:
                    logger.error(f"Failed to import main agent from {agent_file_path}")
                return agent_id
                
        except Exception as e:
            logger.error(f"Failed to import agent from {agent_file_path}: {e}")
            return None
    
    def update_repository_agent(self, repo_name: str, agent_id: Optional[int], updated_by: str = 'system') -> bool:
        """
        Update the agent assigned to a repository.
        
        Args:
            repo_name: Repository name
            agent_id: Agent ID (None for main agent)
            updated_by: Email of user who updated it
            
        Returns:
            bool: True if successful, False otherwise
        """
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.name == repo_name).first()
            if not repository:
                logger.warning(f"Repository not found for agent update: {repo_name}")
                return False
            
            repository.agent_id = agent_id
            repository.updated_by = updated_by
            repository.updated_at = datetime.datetime.now(datetime.timezone.utc)
            
            session.commit()
            logger.info(f"Updated agent for repository {repo_name} to agent_id={agent_id} by {updated_by}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update repository agent for {repo_name}: {e}")
            return False
        finally:
            session.close()
    
    def get_repository_agent(self, repo_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the agent for a specific repository.
        
        Args:
            repo_name: Repository name
            
        Returns:
            Agent dictionary or None if not found
        """
        session = self.get_session()
        try:
            repository = session.query(Repository).filter(Repository.name == repo_name).first()
            if not repository:
                logger.warning(f"Repository not found: {repo_name}")
                return None
            
            if repository.agent_id:
                agent = session.query(Agent).filter(Agent.id == repository.agent_id).first()
                if agent:
                    return agent.to_dict()
            
            # Return main agent if no specific agent assigned
            main_agent = session.query(Agent).filter(Agent.is_main == True).first()
            if main_agent:
                return main_agent.to_dict()
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get agent for repository {repo_name}: {e}")
            return None
        finally:
            session.close()
    
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
        
        # Import main agent from agent.json if not already imported
        try:
            agent_file_path = os.path.join(os.path.dirname(__file__), '..', 'agent.json')
            if os.path.exists(agent_file_path):
                _db_manager.import_agent_from_file(agent_file_path, created_by='system')
                logger.info("Main agent imported/updated from agent.json")
            else:
                logger.warning(f"agent.json not found at {agent_file_path}")
        except Exception as e:
            logger.warning(f"Failed to import main agent from agent.json: {e}")
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
        
        # Create repository_documents table
        """
        CREATE TABLE IF NOT EXISTS repository_documents (
            id SERIAL PRIMARY KEY,
            repository_name VARCHAR(255) NOT NULL,
            filename VARCHAR(500) NOT NULL,
            content TEXT NOT NULL,
            file_type VARCHAR(50) NOT NULL,
            file_size INTEGER NOT NULL,
            embedding JSON NOT NULL,
            embedding_model VARCHAR(100) NOT NULL DEFAULT 'voyage-code-3',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            created_by VARCHAR(255) NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
        """,
        
        # Create index on repository_name for performance
        """
        CREATE INDEX IF NOT EXISTS idx_repo_docs_repo_name ON repository_documents(repository_name);
        """,
        
        # Create index on created_at for performance
        """
        CREATE INDEX IF NOT EXISTS idx_repo_docs_created_at ON repository_documents(created_at);
        """,
        
        # Create agents table
        """
        CREATE TABLE IF NOT EXISTS agents (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            is_main BOOLEAN NOT NULL DEFAULT FALSE,
            prompts JSON NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            created_by VARCHAR(255) NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_by VARCHAR(255) NOT NULL
        );
        """,
        
        # Create indexes on agents table
        """
        CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name);
        """,
        
        """
        CREATE INDEX IF NOT EXISTS idx_agents_is_main ON agents(is_main);
        """,
        
        # Add agent_id column to repositories table
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'repositories' AND column_name = 'agent_id') THEN
                ALTER TABLE repositories ADD COLUMN agent_id INTEGER;
            END IF;
        END$$;
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
