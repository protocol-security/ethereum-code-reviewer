"""
Email notification service using Amazon SES for security findings.
"""

import os
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

class EmailNotificationService:
    """Service for sending email notifications via Amazon SES."""
    
    def __init__(self, region_name: Optional[str] = None, from_email: Optional[str] = None):
        """
        Initialize the email notification service.
        
        Args:
            region_name: AWS region name for SES (defaults to environment variable or us-east-1)
            from_email: From email address (defaults to environment variable)
        """
        self.region_name = region_name or os.getenv('AWS_SES_REGION', 'us-east-1')
        self.from_email = from_email or os.getenv('SES_FROM_EMAIL', 'security-findings@ethereum.org')
        
        # Initialize SES client
        try:
            self.ses_client = boto3.client('ses', region_name=self.region_name)
            self.enabled = True
            logger.info(f"Email notification service initialized with SES in region: {self.region_name}")
        except (NoCredentialsError, Exception) as e:
            logger.warning(f"Failed to initialize SES client: {e}. Email notifications will be disabled.")
            self.ses_client = None
            self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if email notifications are enabled."""
        return self.enabled and self.ses_client is not None
    
    def get_users_for_repository(self, db_manager, repo_name: str) -> List[Dict[str, Any]]:
        """
        Get all users who have access to a repository and have email notifications enabled.
        
        Args:
            db_manager: Database manager instance
            repo_name: Repository name
            
        Returns:
            List of user dictionaries
        """
        try:
            all_users = db_manager.get_all_users()
            eligible_users = []
            
            for user in all_users:
                # Skip users without email notifications enabled
                if not user.get('email_notifications_enabled', True):
                    continue
                
                # Check if user has access to this repository
                user_obj = db_manager.get_user(user['email'])
                if user_obj and user_obj.has_repository_access(repo_name):
                    eligible_users.append(user)
            
            logger.info(f"Found {len(eligible_users)} users eligible for notifications for repo: {repo_name}")
            return eligible_users
            
        except Exception as e:
            logger.error(f"Error getting users for repository {repo_name}: {e}")
            return []
    
    def send_new_finding_notification(self, db_manager, finding: Dict[str, Any]) -> bool:
        """
        Send email notification when a new security finding is created.
        
        Args:
            db_manager: Database manager instance
            finding: Finding dictionary
            
        Returns:
            bool: True if emails were sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping new finding notification")
            return False
        
        try:
            repo_name = finding.get('repo_name', '')
            finding_uuid = finding.get('uuid', '')
            
            # Get users who should be notified
            users = self.get_users_for_repository(db_manager, repo_name)
            
            if not users:
                logger.info(f"No users to notify for new finding in repo: {repo_name}")
                return True
            
            # Prepare email content
            subject = f"New Security Finding: {repo_name}"
            
            # Generate finding URL
            finding_url = os.getenv('BASE_URL', '')
            if not finding_url.endswith('/'):
                finding_url += '/'
            finding_url += f"triage/{finding_uuid}"
            
            # Create email body
            html_body = self._create_new_finding_email_html(finding, finding_url)
            text_body = self._create_new_finding_email_text(finding, finding_url)
            
            # Send emails
            success = self._send_bulk_emails(
                users=[user['email'] for user in users],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent new finding notifications to {len(users)} users for finding {finding_uuid}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending new finding notification: {e}")
            return False
    
    def send_status_change_notification(self, db_manager, finding: Dict[str, Any], 
                                      old_status: str, new_status: str, changed_by: str) -> bool:
        """
        Send email notification when a finding's status changes.
        
        Args:
            db_manager: Database manager instance
            finding: Finding dictionary
            old_status: Previous status
            new_status: New status
            changed_by: Email of user who made the change
            
        Returns:
            bool: True if emails were sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping status change notification")
            return False
        
        try:
            repo_name = finding.get('repo_name', '')
            finding_uuid = finding.get('uuid', '')
            
            # Get users who should be notified
            users = self.get_users_for_repository(db_manager, repo_name)
            
            # Filter out the user who made the change
            users = [user for user in users if user['email'] != changed_by]
            
            if not users:
                logger.info(f"No users to notify for status change in finding {finding_uuid}")
                return True
            
            # Prepare email content
            subject = f"Status Changed: {repo_name} - {new_status.replace('_', ' ').title()}"
            
            # Generate finding URL
            finding_url = os.getenv('BASE_URL', '')
            if not finding_url.endswith('/'):
                finding_url += '/'
            finding_url += f"triage/{finding_uuid}"
            
            # Create email body
            html_body = self._create_status_change_email_html(
                finding, old_status, new_status, changed_by, finding_url
            )
            text_body = self._create_status_change_email_text(
                finding, old_status, new_status, changed_by, finding_url
            )
            
            # Send emails
            success = self._send_bulk_emails(
                users=[user['email'] for user in users],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent status change notifications to {len(users)} users for finding {finding_uuid}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending status change notification: {e}")
            return False
    
    def send_comment_notification(self, db_manager, finding: Dict[str, Any], 
                                comment: str, commented_by: str) -> bool:
        """
        Send email notification when a comment is added to a finding.
        
        Args:
            db_manager: Database manager instance
            finding: Finding dictionary
            comment: Comment text
            commented_by: Email of user who added the comment
            
        Returns:
            bool: True if emails were sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping comment notification")
            return False
        
        try:
            repo_name = finding.get('repo_name', '')
            finding_uuid = finding.get('uuid', '')
            
            # Get users who should be notified
            users = self.get_users_for_repository(db_manager, repo_name)
            
            # Filter out the user who made the comment
            users = [user for user in users if user['email'] != commented_by]
            
            if not users:
                logger.info(f"No users to notify for comment in finding {finding_uuid}")
                return True
            
            # Prepare email content
            subject = f"New Comment: {repo_name}"
            
            # Generate finding URL
            finding_url = os.getenv('BASE_URL', '')
            if not finding_url.endswith('/'):
                finding_url += '/'
            finding_url += f"triage/{finding_uuid}"
            
            # Create email body
            html_body = self._create_comment_email_html(
                finding, comment, commented_by, finding_url
            )
            text_body = self._create_comment_email_text(
                finding, comment, commented_by, finding_url
            )
            
            # Send emails
            success = self._send_bulk_emails(
                users=[user['email'] for user in users],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent comment notifications to {len(users)} users for finding {finding_uuid}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending comment notification: {e}")
            return False
    
    def send_repository_deletion_notification(self, db_manager, repository_data: Dict[str, Any], 
                                            deleted_by: str) -> bool:
        """
        Send email notification to the owner when a repository is deleted.
        
        Args:
            db_manager: Database manager instance
            repository_data: Repository data dictionary
            deleted_by: Email of user who deleted the repository
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping repository deletion notification")
            return False
        
        try:
            # Get the owner email (fredrik.svantes@ethereum.org)
            owner_email = 'fredrik.svantes@ethereum.org'
            
            # Don't send email to the person who deleted it if they are the owner
            if deleted_by == owner_email:
                logger.info(f"Repository deleted by owner, skipping notification")
                return True
            
            repo_name = repository_data.get('name', 'Unknown Repository')
            
            # Prepare email content
            subject = f"Repository Deleted: {repo_name}"
            
            # Create email body
            html_body = self._create_repository_deletion_email_html(repository_data, deleted_by)
            text_body = self._create_repository_deletion_email_text(repository_data, deleted_by)
            
            # Send email
            success = self._send_bulk_emails(
                users=[owner_email],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent repository deletion notification to owner for repository {repo_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending repository deletion notification: {e}")
            return False
    
    def send_repository_creation_notification(self, db_manager, repository_data: Dict[str, Any], 
                                            created_by: str) -> bool:
        """
        Send email notification to the owner when a repository is created.
        
        Args:
            db_manager: Database manager instance
            repository_data: Repository data dictionary
            created_by: Email of user who created the repository
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping repository creation notification")
            return False
        
        try:
            # Get the owner email (fredrik.svantes@ethereum.org)
            owner_email = 'fredrik.svantes@ethereum.org'
            
            # Don't send email to the person who created it if they are the owner
            if created_by == owner_email:
                logger.info(f"Repository created by owner, skipping notification")
                return True
            
            repo_name = repository_data.get('name', 'Unknown Repository')
            
            # Prepare email content
            subject = f"Repository Created: {repo_name}"
            
            # Create email body
            html_body = self._create_repository_creation_email_html(repository_data, created_by)
            text_body = self._create_repository_creation_email_text(repository_data, created_by)
            
            # Send email
            success = self._send_bulk_emails(
                users=[owner_email],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent repository creation notification to owner for repository {repo_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending repository creation notification: {e}")
            return False
    
    def send_repository_modification_notification(self, db_manager, old_repository_data: Dict[str, Any],
                                                new_repository_data: Dict[str, Any], modified_by: str) -> bool:
        """
        Send email notification to the owner when a repository is modified.
        
        Args:
            db_manager: Database manager instance
            old_repository_data: Repository data before modification
            new_repository_data: Repository data after modification
            modified_by: Email of user who modified the repository
            
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        if not self.is_enabled():
            logger.debug("Email notifications disabled, skipping repository modification notification")
            return False
        
        try:
            # Get the owner email (fredrik.svantes@ethereum.org)
            owner_email = 'fredrik.svantes@ethereum.org'
            
            # Don't send email to the person who modified it if they are the owner
            if modified_by == owner_email:
                logger.info(f"Repository modified by owner, skipping notification")
                return True
            
            repo_name = new_repository_data.get('name', 'Unknown Repository')
            
            # Prepare email content
            subject = f"Repository Modified: {repo_name}"
            
            # Create email body
            html_body = self._create_repository_modification_email_html(
                old_repository_data, new_repository_data, modified_by
            )
            text_body = self._create_repository_modification_email_text(
                old_repository_data, new_repository_data, modified_by
            )
            
            # Send email
            success = self._send_bulk_emails(
                users=[owner_email],
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            if success:
                logger.info(f"Sent repository modification notification to owner for repository {repo_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending repository modification notification: {e}")
            return False
    
    def _send_bulk_emails(self, users: List[str], subject: str, 
                         html_body: str, text_body: str) -> bool:
        """
        Send bulk emails using SES.
        
        Args:
            users: List of email addresses
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body
            
        Returns:
            bool: True if all emails were sent successfully, False otherwise
        """
        if not self.is_enabled():
            return False
        
        try:
            # Send emails in batches to avoid SES limits
            batch_size = 50  # SES limit is 50 per batch
            success_count = 0
            total_count = len(users)
            
            for i in range(0, total_count, batch_size):
                batch = users[i:i + batch_size]
                
                for email in batch:
                    try:
                        response = self.ses_client.send_email(
                            Source=self.from_email,
                            Destination={'ToAddresses': [email]},
                            Message={
                                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                                'Body': {
                                    'Html': {'Data': html_body, 'Charset': 'UTF-8'},
                                    'Text': {'Data': text_body, 'Charset': 'UTF-8'}
                                }
                            }
                        )
                        
                        success_count += 1
                        logger.debug(f"Email sent successfully to {email}, MessageId: {response.get('MessageId')}")
                        
                    except ClientError as e:
                        error_code = e.response['Error']['Code']
                        logger.error(f"Failed to send email to {email}: {error_code} - {e.response['Error']['Message']}")
                    except Exception as e:
                        logger.error(f"Unexpected error sending email to {email}: {e}")
            
            logger.info(f"Sent {success_count}/{total_count} emails successfully")
            return success_count == total_count
            
        except Exception as e:
            logger.error(f"Error in bulk email sending: {e}")
            return False
    
    def _create_new_finding_email_html(self, finding: Dict[str, Any], finding_url: str) -> str:
        """Create HTML email body for new finding notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        author = finding.get('author', 'Unknown')
        has_vulnerabilities = finding.get('has_vulnerabilities', False)
        summary = finding.get('summary', 'No summary available')
        created_at = finding.get('created_at', '')
        
        vulnerability_status = "🔴 Vulnerabilities Found" if has_vulnerabilities else "🟢 No Vulnerabilities"
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>New Security Finding</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #667eea; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .status {{ display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; margin: 10px 0; }}
        .vulnerable {{ background-color: #fee; color: #c53030; }}
        .safe {{ background-color: #f0fff4; color: #22543d; }}
        .button {{ display: inline-block; background-color: #667eea; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin: 20px 0; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .info-row {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #4a5568; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>New Security Finding</h1>
        </div>
        
        <div class="content">
            <div class="status {'vulnerable' if has_vulnerabilities else 'safe'}">
                {vulnerability_status}
            </div>
            
            <div class="info-row">
                <span class="label">Repository:</span> {repo_name}
            </div>
            <div class="info-row">
                <span class="label">Commit:</span> {commit_sha}
            </div>
            <div class="info-row">
                <span class="label">Author:</span> {author}
            </div>
            <div class="info-row">
                <span class="label">Date:</span> {created_at}
            </div>
            
            <h3>Summary</h3>
            <p>{summary}</p>
            
            <a href="{finding_url}" class="button">View Full Report</a>
        </div>
        
        <div class="footer">
            <p>This is an automated notification from the Protocol Security Review System</p>
            <p>To manage your notification preferences, please log in to the dashboard.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_new_finding_email_text(self, finding: Dict[str, Any], finding_url: str) -> str:
        """Create plain text email body for new finding notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        author = finding.get('author', 'Unknown')
        has_vulnerabilities = finding.get('has_vulnerabilities', False)
        summary = finding.get('summary', 'No summary available')
        created_at = finding.get('created_at', '')
        
        vulnerability_status = "VULNERABILITIES FOUND" if has_vulnerabilities else "NO VULNERABILITIES"
        
        return f"""
NEW SECURITY FINDING

Status: {vulnerability_status}

Repository: {repo_name}
Commit: {commit_sha}
Author: {author}
Date: {created_at}

Summary:
{summary}

View full report: {finding_url}

---
This is an automated notification from the Protocol Security Review System
To manage your notification preferences, please log in to the dashboard.
"""
    
    def _create_status_change_email_html(self, finding: Dict[str, Any], old_status: str, 
                                       new_status: str, changed_by: str, finding_url: str) -> str:
        """Create HTML email body for status change notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        
        # Format status names
        old_status_display = old_status.replace('_', ' ').title()
        new_status_display = new_status.replace('_', ' ').title()
        
        # Status colors
        status_colors = {
            'unassigned': '#718096',
            'reviewing': '#3182ce',
            'escalated_to_client': '#d69e2e',
            'completed': '#38a169'
        }
        
        new_status_color = status_colors.get(new_status, '#718096')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Status Changed</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #4a5568; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .status-change {{ text-align: center; margin: 20px 0; }}
        .status {{ display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; margin: 0 10px; }}
        .arrow {{ font-size: 24px; margin: 0 10px; }}
        .button {{ display: inline-block; background-color: #667eea; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin: 20px 0; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .info-row {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #4a5568; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Status Updated</h1>
        </div>
        
        <div class="content">
            <div class="info-row">
                <span class="label">Repository:</span> {repo_name}
            </div>
            <div class="info-row">
                <span class="label">Commit:</span> {commit_sha}
            </div>
            <div class="info-row">
                <span class="label">Changed by:</span> {changed_by}
            </div>
            
            <div class="status-change">
                <span class="status" style="background-color: #e2e8f0; color: #4a5568;">{old_status_display}</span>
                <span class="arrow">→</span>
                <span class="status" style="background-color: {new_status_color}; color: white;">{new_status_display}</span>
            </div>
            
            <a href="{finding_url}" class="button">View Finding</a>
        </div>
        
        <div class="footer">
            <p>This is an automated notification from the Protocol Security Review System</p>
            <p>To manage your notification preferences, please log in to the dashboard.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_status_change_email_text(self, finding: Dict[str, Any], old_status: str, 
                                       new_status: str, changed_by: str, finding_url: str) -> str:
        """Create plain text email body for status change notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        
        old_status_display = old_status.replace('_', ' ').title()
        new_status_display = new_status.replace('_', ' ').title()
        
        return f"""
STATUS UPDATED

Repository: {repo_name}
Commit: {commit_sha}
Changed by: {changed_by}

Status changed from: {old_status_display}
Status changed to: {new_status_display}

View finding: {finding_url}

---
This is an automated notification from the Protocol Security Review System
To manage your notification preferences, please log in to the dashboard.
"""
    
    def _create_comment_email_html(self, finding: Dict[str, Any], comment: str, 
                                 commented_by: str, finding_url: str) -> str:
        """Create HTML email body for comment notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        
        # Truncate long comments for email
        display_comment = comment[:300] + "..." if len(comment) > 300 else comment
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>New Comment</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #38a169; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .comment {{ background-color: #f7fafc; border-left: 4px solid #38a169; padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }}
        .button {{ display: inline-block; background-color: #667eea; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin: 20px 0; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .info-row {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #4a5568; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>New Comment</h1>
        </div>
        
        <div class="content">
            <div class="info-row">
                <span class="label">Repository:</span> {repo_name}
            </div>
            <div class="info-row">
                <span class="label">Commit:</span> {commit_sha}
            </div>
            <div class="info-row">
                <span class="label">Commented by:</span> {commented_by}
            </div>
            
            <div class="comment">
                <p>{display_comment}</p>
            </div>
            
            <a href="{finding_url}" class="button">View Full Discussion</a>
        </div>
        
        <div class="footer">
            <p>This is an automated notification from the Protocol Security Review System</p>
            <p>To manage your notification preferences, please log in to the dashboard.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_comment_email_text(self, finding: Dict[str, Any], comment: str, 
                                 commented_by: str, finding_url: str) -> str:
        """Create plain text email body for comment notification."""
        repo_name = finding.get('repo_name', 'Unknown Repository')
        commit_sha = finding.get('commit_sha', '')[:8] if finding.get('commit_sha') else 'Unknown'
        
        # Truncate long comments for email
        display_comment = comment[:300] + "..." if len(comment) > 300 else comment
        
        return f"""
NEW COMMENT

Repository: {repo_name}
Commit: {commit_sha}
Commented by: {commented_by}

Comment:
{display_comment}

View full discussion: {finding_url}

---
This is an automated notification from the Protocol Security Review System
To manage your notification preferences, please log in to the dashboard.
"""
    
    def _create_repository_deletion_email_html(self, repository_data: Dict[str, Any], deleted_by: str) -> str:
        """Create HTML email body for repository deletion notification."""
        repo_name = repository_data.get('name', 'Unknown Repository')
        repo_url = repository_data.get('url', 'Unknown URL')
        branches = repository_data.get('branches', [])
        branches_str = ', '.join(branches) if branches else 'Unknown'
        telegram_channel_id = repository_data.get('telegram_channel_id', 'None')
        notify_default_channel = repository_data.get('notify_default_channel', False)
        was_active = repository_data.get('is_active', True)
        created_at = repository_data.get('created_at', 'Unknown')
        created_by = repository_data.get('created_by', 'Unknown')
        updated_at = repository_data.get('updated_at', 'Unknown')
        updated_by = repository_data.get('updated_by', 'Unknown')
        deletion_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Repository Deleted</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 700px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #e53e3e; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .alert {{ background-color: #fed7d7; border-left: 4px solid #e53e3e; padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }}
        .info-section {{ background-color: #f7fafc; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }}
        .info-item {{ }}
        .info-label {{ font-weight: bold; color: #4a5568; display: block; margin-bottom: 5px; }}
        .info-value {{ color: #2d3748; background-color: #edf2f7; padding: 8px 12px; border-radius: 4px; font-family: monospace; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .status-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .active {{ background-color: #c6f6d5; color: #22543d; }}
        .inactive {{ background-color: #fed7d7; color: #c53030; }}
        h2 {{ color: #2d3748; margin-bottom: 15px; }}
        h3 {{ color: #4a5568; margin-top: 20px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗑️ Repository Deleted</h1>
        </div>
        
        <div class="content">
            <div class="alert">
                <strong>AUDIT ALERT:</strong> A repository has been deleted from the security monitoring system.
            </div>
            
            <h2>Deletion Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Repository Name:</span>
                    <div class="info-value">{repo_name}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Deleted By:</span>
                    <div class="info-value">{deleted_by}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Deletion Time:</span>
                    <div class="info-value">{deletion_time}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Status Before Deletion:</span>
                    <div class="info-value">
                        <span class="status-badge {'active' if was_active else 'inactive'}">
                            {'Active' if was_active else 'Inactive'}
                        </span>
                    </div>
                </div>
            </div>
            
            <div class="info-section">
                <h3>Repository Configuration</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">URL:</span>
                        <div class="info-value">{repo_url}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Monitored Branches:</span>
                        <div class="info-value">{branches_str}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Telegram Channel ID:</span>
                        <div class="info-value">{telegram_channel_id or 'None'}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Notify Default Channel:</span>
                        <div class="info-value">{'Yes' if notify_default_channel else 'No'}</div>
                    </div>
                </div>
            </div>
            
            <div class="info-section">
                <h3>Historical Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Originally Created:</span>
                        <div class="info-value">{created_at}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Created By:</span>
                        <div class="info-value">{created_by}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Last Updated:</span>
                        <div class="info-value">{updated_at}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Last Updated By:</span>
                        <div class="info-value">{updated_by}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Security Audit Notification</strong></p>
            <p>This is an automated audit notification from the Protocol Security Review System</p>
            <p>If this deletion was unauthorized, please contact the system administrator immediately.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_repository_deletion_email_text(self, repository_data: Dict[str, Any], deleted_by: str) -> str:
        """Create plain text email body for repository deletion notification."""
        repo_name = repository_data.get('name', 'Unknown Repository')
        repo_url = repository_data.get('url', 'Unknown URL')
        branches = repository_data.get('branches', [])
        branches_str = ', '.join(branches) if branches else 'Unknown'
        telegram_channel_id = repository_data.get('telegram_channel_id', 'None')
        notify_default_channel = repository_data.get('notify_default_channel', False)
        was_active = repository_data.get('is_active', True)
        created_at = repository_data.get('created_at', 'Unknown')
        created_by = repository_data.get('created_by', 'Unknown')
        updated_at = repository_data.get('updated_at', 'Unknown')
        updated_by = repository_data.get('updated_by', 'Unknown')
        deletion_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return f"""
REPOSITORY DELETED - AUDIT ALERT

A repository has been deleted from the security monitoring system.

DELETION DETAILS:
Repository Name: {repo_name}
Deleted By: {deleted_by}
Deletion Time: {deletion_time}
Status Before Deletion: {'Active' if was_active else 'Inactive'}

REPOSITORY CONFIGURATION:
URL: {repo_url}
Monitored Branches: {branches_str}
Telegram Channel ID: {telegram_channel_id or 'None'}
Notify Default Channel: {'Yes' if notify_default_channel else 'No'}

HISTORICAL INFORMATION:
Originally Created: {created_at}
Created By: {created_by}
Last Updated: {updated_at}
Last Updated By: {updated_by}

---
SECURITY AUDIT NOTIFICATION
This is an automated audit notification from the Protocol Security Review System
If this deletion was unauthorized, please contact the system administrator immediately.
"""
    
    def _create_repository_creation_email_html(self, repository_data: Dict[str, Any], created_by: str) -> str:
        """Create HTML email body for repository creation notification."""
        repo_name = repository_data.get('name', 'Unknown Repository')
        repo_url = repository_data.get('url', 'Unknown URL')
        branches = repository_data.get('branches', [])
        branches_str = ', '.join(branches) if branches else 'Unknown'
        telegram_channel_id = repository_data.get('telegram_channel_id', 'None')
        notify_default_channel = repository_data.get('notify_default_channel', False)
        is_active = repository_data.get('is_active', True)
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Repository Created</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 700px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #38a169; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .alert {{ background-color: #c6f6d5; border-left: 4px solid #38a169; padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }}
        .info-section {{ background-color: #f7fafc; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }}
        .info-item {{ }}
        .info-label {{ font-weight: bold; color: #4a5568; display: block; margin-bottom: 5px; }}
        .info-value {{ color: #2d3748; background-color: #edf2f7; padding: 8px 12px; border-radius: 4px; font-family: monospace; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .status-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .active {{ background-color: #c6f6d5; color: #22543d; }}
        .inactive {{ background-color: #fed7d7; color: #c53030; }}
        h2 {{ color: #2d3748; margin-bottom: 15px; }}
        h3 {{ color: #4a5568; margin-top: 20px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 Repository Created</h1>
        </div>
        
        <div class="content">
            <div class="alert">
                <strong>AUDIT NOTIFICATION:</strong> A new repository has been added to the security monitoring system.
            </div>
            
            <h2>Creation Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Repository Name:</span>
                    <div class="info-value">{repo_name}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Created By:</span>
                    <div class="info-value">{created_by}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Creation Time:</span>
                    <div class="info-value">{creation_time}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Initial Status:</span>
                    <div class="info-value">
                        <span class="status-badge {'active' if is_active else 'inactive'}">
                            {'Active' if is_active else 'Inactive'}
                        </span>
                    </div>
                </div>
            </div>
            
            <div class="info-section">
                <h3>Repository Configuration</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">URL:</span>
                        <div class="info-value">{repo_url}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Monitored Branches:</span>
                        <div class="info-value">{branches_str}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Telegram Channel ID:</span>
                        <div class="info-value">{telegram_channel_id or 'None'}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Notify Default Channel:</span>
                        <div class="info-value">{'Yes' if notify_default_channel else 'No'}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Security Audit Notification</strong></p>
            <p>This is an automated audit notification from the Protocol Security Review System</p>
            <p>The repository is now being monitored for security findings.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_repository_creation_email_text(self, repository_data: Dict[str, Any], created_by: str) -> str:
        """Create plain text email body for repository creation notification."""
        repo_name = repository_data.get('name', 'Unknown Repository')
        repo_url = repository_data.get('url', 'Unknown URL')
        branches = repository_data.get('branches', [])
        branches_str = ', '.join(branches) if branches else 'Unknown'
        telegram_channel_id = repository_data.get('telegram_channel_id', 'None')
        notify_default_channel = repository_data.get('notify_default_channel', False)
        is_active = repository_data.get('is_active', True)
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return f"""
REPOSITORY CREATED - AUDIT NOTIFICATION

A new repository has been added to the security monitoring system.

CREATION DETAILS:
Repository Name: {repo_name}
Created By: {created_by}
Creation Time: {creation_time}
Initial Status: {'Active' if is_active else 'Inactive'}

REPOSITORY CONFIGURATION:
URL: {repo_url}
Monitored Branches: {branches_str}
Telegram Channel ID: {telegram_channel_id or 'None'}
Notify Default Channel: {'Yes' if notify_default_channel else 'No'}

---
SECURITY AUDIT NOTIFICATION
This is an automated audit notification from the Protocol Security Review System
The repository is now being monitored for security findings.
"""
    
    def _create_repository_modification_email_html(self, old_repository_data: Dict[str, Any], 
                                                  new_repository_data: Dict[str, Any], modified_by: str) -> str:
        """Create HTML email body for repository modification notification."""
        repo_name = new_repository_data.get('name', 'Unknown Repository')
        modification_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Compare old vs new data to show changes
        changes = []
        
        # Check URL change
        old_url = old_repository_data.get('url', '')
        new_url = new_repository_data.get('url', '')
        if old_url != new_url:
            changes.append(('URL', old_url, new_url))
        
        # Check branches change
        old_branches = old_repository_data.get('branches', [])
        new_branches = new_repository_data.get('branches', [])
        old_branches_str = ', '.join(old_branches) if old_branches else 'None'
        new_branches_str = ', '.join(new_branches) if new_branches else 'None'
        if old_branches != new_branches:
            changes.append(('Monitored Branches', old_branches_str, new_branches_str))
        
        # Check Telegram channel change
        old_telegram = old_repository_data.get('telegram_channel_id', '')
        new_telegram = new_repository_data.get('telegram_channel_id', '')
        if old_telegram != new_telegram:
            changes.append(('Telegram Channel ID', old_telegram or 'None', new_telegram or 'None'))
        
        # Check notify default channel change
        old_notify = old_repository_data.get('notify_default_channel', False)
        new_notify = new_repository_data.get('notify_default_channel', False)
        if old_notify != new_notify:
            changes.append(('Notify Default Channel', 'Yes' if old_notify else 'No', 'Yes' if new_notify else 'No'))
        
        # Check active status change
        old_active = old_repository_data.get('is_active', True)
        new_active = new_repository_data.get('is_active', True)
        if old_active != new_active:
            changes.append(('Status', 'Active' if old_active else 'Inactive', 'Active' if new_active else 'Inactive'))
        
        # Generate changes HTML
        changes_html = ""
        if changes:
            changes_html = """
            <div class="info-section">
                <h3>Changes Made</h3>
                <div class="changes-list">
            """
            for field, old_value, new_value in changes:
                changes_html += f"""
                <div class="change-item">
                    <div class="change-field">{field}</div>
                    <div class="change-values">
                        <span class="old-value">{old_value}</span>
                        <span class="arrow">→</span>
                        <span class="new-value">{new_value}</span>
                    </div>
                </div>
                """
            changes_html += """
                </div>
            </div>
            """
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Repository Modified</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 700px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background-color: #3182ce; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .alert {{ background-color: #bee3f8; border-left: 4px solid #3182ce; padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }}
        .info-section {{ background-color: #f7fafc; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }}
        .info-item {{ }}
        .info-label {{ font-weight: bold; color: #4a5568; display: block; margin-bottom: 5px; }}
        .info-value {{ color: #2d3748; background-color: #edf2f7; padding: 8px 12px; border-radius: 4px; font-family: monospace; }}
        .footer {{ background-color: #f7fafc; padding: 15px; text-align: center; font-size: 12px; color: #718096; }}
        .changes-list {{ margin-top: 15px; }}
        .change-item {{ margin-bottom: 15px; padding: 15px; background-color: #edf2f7; border-radius: 6px; }}
        .change-field {{ font-weight: bold; color: #2d3748; margin-bottom: 8px; }}
        .change-values {{ display: flex; align-items: center; gap: 10px; }}
        .old-value {{ background-color: #fed7d7; color: #c53030; padding: 4px 8px; border-radius: 4px; font-family: monospace; }}
        .new-value {{ background-color: #c6f6d5; color: #22543d; padding: 4px 8px; border-radius: 4px; font-family: monospace; }}
        .arrow {{ color: #4a5568; font-weight: bold; }}
        h2 {{ color: #2d3748; margin-bottom: 15px; }}
        h3 {{ color: #4a5568; margin-top: 20px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📝 Repository Modified</h1>
        </div>
        
        <div class="content">
            <div class="alert">
                <strong>AUDIT NOTIFICATION:</strong> A repository configuration has been modified in the security monitoring system.
            </div>
            
            <h2>Modification Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Repository Name:</span>
                    <div class="info-value">{repo_name}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Modified By:</span>
                    <div class="info-value">{modified_by}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Modification Time:</span>
                    <div class="info-value">{modification_time}</div>
                </div>
                <div class="info-item">
                    <span class="info-label">Changes Made:</span>
                    <div class="info-value">{len(changes)} field(s)</div>
                </div>
            </div>
            
            {changes_html}
        </div>
        
        <div class="footer">
            <p><strong>Security Audit Notification</strong></p>
            <p>This is an automated audit notification from the Protocol Security Review System</p>
            <p>Repository monitoring will continue with the updated configuration.</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _create_repository_modification_email_text(self, old_repository_data: Dict[str, Any], 
                                                  new_repository_data: Dict[str, Any], modified_by: str) -> str:
        """Create plain text email body for repository modification notification."""
        repo_name = new_repository_data.get('name', 'Unknown Repository')
        modification_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Compare old vs new data to show changes
        changes = []
        
        # Check URL change
        old_url = old_repository_data.get('url', '')
        new_url = new_repository_data.get('url', '')
        if old_url != new_url:
            changes.append(f"URL: {old_url} → {new_url}")
        
        # Check branches change
        old_branches = old_repository_data.get('branches', [])
        new_branches = new_repository_data.get('branches', [])
        old_branches_str = ', '.join(old_branches) if old_branches else 'None'
        new_branches_str = ', '.join(new_branches) if new_branches else 'None'
        if old_branches != new_branches:
            changes.append(f"Monitored Branches: {old_branches_str} → {new_branches_str}")
        
        # Check Telegram channel change
        old_telegram = old_repository_data.get('telegram_channel_id', '')
        new_telegram = new_repository_data.get('telegram_channel_id', '')
        if old_telegram != new_telegram:
            changes.append(f"Telegram Channel ID: {old_telegram or 'None'} → {new_telegram or 'None'}")
        
        # Check notify default channel change
        old_notify = old_repository_data.get('notify_default_channel', False)
        new_notify = new_repository_data.get('notify_default_channel', False)
        if old_notify != new_notify:
            changes.append(f"Notify Default Channel: {'Yes' if old_notify else 'No'} → {'Yes' if new_notify else 'No'}")
        
        # Check active status change
        old_active = old_repository_data.get('is_active', True)
        new_active = new_repository_data.get('is_active', True)
        if old_active != new_active:
            changes.append(f"Status: {'Active' if old_active else 'Inactive'} → {'Active' if new_active else 'Inactive'}")
        
        changes_text = "\n".join([f"- {change}" for change in changes]) if changes else "No changes detected"
        
        return f"""
REPOSITORY MODIFIED - AUDIT NOTIFICATION

A repository configuration has been modified in the security monitoring system.

MODIFICATION DETAILS:
Repository Name: {repo_name}
Modified By: {modified_by}
Modification Time: {modification_time}
Changes Made: {len(changes)} field(s)

CHANGES:
{changes_text}

---
SECURITY AUDIT NOTIFICATION
This is an automated audit notification from the Protocol Security Review System
Repository monitoring will continue with the updated configuration.
"""
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test the SES connection and configuration.
        
        Returns:
            Dict containing test results
        """
        if not self.is_enabled():
            return {
                'success': False,
                'error': 'Email service not enabled or SES client not initialized'
            }
        
        try:
            # Test by getting send quota
            response = self.ses_client.get_send_quota()
            
            return {
                'success': True,
                'region': self.region_name,
                'from_email': self.from_email,
                'send_quota': response.get('Max24HourSend', 0),
                'sent_last_24h': response.get('SentLast24Hours', 0),
                'max_send_rate': response.get('MaxSendRate', 0)
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            return {
                'success': False,
                'error': f"SES ClientError: {error_code} - {e.response['Error']['Message']}"
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Unexpected error: {str(e)}"
            }


# Global email service instance
_email_service = None

def get_email_service() -> EmailNotificationService:
    """
    Get the global email notification service instance.
    
    Returns:
        EmailNotificationService: The email service instance
    """
    global _email_service
    if _email_service is None:
        _email_service = EmailNotificationService()
    return _email_service
