#!/usr/bin/env python3
"""
Database utility script for managing security findings database.
"""

import os
import sys
import argparse
from datetime import datetime, timedelta
from typing import Optional

def setup_logging():
    """Setup basic logging configuration."""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def check_database_connection() -> bool:
    """Check if database connection is working."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        if db_manager.health_check():
            print("✅ Database connection successful")
            return True
        else:
            print("❌ Database connection failed")
            return False
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

def initialize_database():
    """Initialize database tables."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        db_manager.create_tables()
        print("✅ Database tables initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        return False

def show_statistics():
    """Display database statistics."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        stats = db_manager.get_statistics()
        
        if not stats:
            print("❌ Failed to retrieve database statistics")
            return
        
        print("\n📊 Database Statistics:")
        print("=" * 50)
        print(f"Total findings: {stats['total_findings']}")
        print(f"Active findings: {stats['active_findings']}")
        print(f"Expired findings: {stats['expired_findings']}")
        print(f"Vulnerable findings: {stats['vulnerable_findings']}")
        print(f"Unique repositories: {stats['unique_repositories']}")
        print(f"Recent findings (24h): {stats['recent_findings_24h']}")
        print(f"Last updated: {stats['last_updated']}")
        
    except Exception as e:
        print(f"❌ Failed to get statistics: {e}")

def cleanup_expired():
    """Clean up expired findings."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        removed_count = db_manager.cleanup_expired_findings()
        print(f"✅ Cleaned up {removed_count} expired findings")
        return True
    except Exception as e:
        print(f"❌ Failed to cleanup expired findings: {e}")
        return False

def list_findings(repo_name: Optional[str] = None, limit: int = 10):
    """List recent findings."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        
        if repo_name:
            findings = db_manager.get_findings_by_repo(repo_name, limit=limit)
            print(f"\n📋 Recent findings for {repo_name}:")
        else:
            # Get all findings across repositories (we need to implement this)
            print(f"\n📋 Recent findings (last {limit}):")
            findings = []  # Placeholder - would need to implement get_all_findings method
            
        if not findings:
            print("No findings found")
            return
            
        print("=" * 80)
        for finding in findings:
            status = "🔴 VULNERABLE" if finding['has_vulnerabilities'] else "🟢 CLEAN"
            print(f"{status} | {finding['repo_name']} | {finding['commit_sha'][:7]} | {finding['created_at']}")
            if finding['summary']:
                print(f"  Summary: {finding['summary'][:100]}...")
            print("-" * 80)
            
    except Exception as e:
        print(f"❌ Failed to list findings: {e}")

def show_finding_details(finding_uuid: str):
    """Show details of a specific finding."""
    try:
        from .database import get_database_manager
        db_manager = get_database_manager()
        finding_data = db_manager.get_finding(finding_uuid)
        
        if not finding_data:
            print(f"❌ Finding with UUID {finding_uuid} not found or expired")
            return
            
        print(f"\n🔍 Finding Details: {finding_uuid}")
        print("=" * 50)
        print(f"Created: {finding_data['created_at']}")
        print(f"Metadata: {finding_data.get('metadata', {})}")
        print("\nHTML content length:", len(finding_data['html_content']))
        
    except Exception as e:
        print(f"❌ Failed to get finding details: {e}")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Database utility for security findings")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Check connection
    subparsers.add_parser('check', help='Check database connection')
    
    # Initialize database
    subparsers.add_parser('init', help='Initialize database tables') 
    
    # Show statistics
    subparsers.add_parser('stats', help='Show database statistics')
    
    # Cleanup expired
    subparsers.add_parser('cleanup', help='Clean up expired findings')
    
    # List findings
    list_parser = subparsers.add_parser('list', help='List recent findings')
    list_parser.add_argument('--repo', help='Filter by repository name')
    list_parser.add_argument('--limit', type=int, default=10, help='Number of findings to show')
    
    # Show finding details
    details_parser = subparsers.add_parser('details', help='Show finding details')
    details_parser.add_argument('uuid', help='Finding UUID')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    setup_logging()
    
    # Check for required environment variable
    if not os.getenv('DATABASE_URL'):
        print("❌ DATABASE_URL environment variable not set")
        print("Please set DATABASE_URL to your PostgreSQL connection string")
        print("Example: postgresql://username:password@localhost:5432/database_name")
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == 'check':
            success = check_database_connection()
            sys.exit(0 if success else 1)
            
        elif args.command == 'init':
            success = initialize_database()
            sys.exit(0 if success else 1)
            
        elif args.command == 'stats':
            show_statistics()
            
        elif args.command == 'cleanup':
            success = cleanup_expired()
            sys.exit(0 if success else 1)
            
        elif args.command == 'list':
            list_findings(args.repo, args.limit)
            
        elif args.command == 'details':
            show_finding_details(args.uuid)
            
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
