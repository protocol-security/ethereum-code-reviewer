"""
Flask web application package with modular structure.
"""

import os
import secrets
import logging
import threading
from flask import Flask
from flask_session import Session

logger = logging.getLogger(__name__)

def create_app() -> Flask:
    """Create and configure the Flask application."""
    from .config import configure_app
    from .routes import register_blueprints
    
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Configure the app
    configure_app(app)
    
    # Initialize Flask-Session
    Session(app)
    
    # Register all blueprints
    register_blueprints(app)
    
    # Start background monitoring if MONITOR_CONTINUOUS is enabled
    if os.environ.get('MONITOR_CONTINUOUS', '').lower() in ('true', 'yes', '1'):
        start_monitoring_service()
    
    logger.info("Flask web application created successfully")
    
    return app


def start_monitoring_service():
    """Start the commit monitoring service in a background thread."""
    import time
    
    logger.info("🚀 Starting background commit monitoring service...")
    
    # Import dependencies
    from ..commit_monitor import CommitMonitor
    from ..telegram_notifier import TelegramNotifier
    from ..__main__ import SecurityReview, run_commit_monitor_callback
    from ..config_loader import load_agent_config
    
    try:
        # Load agent configuration
        load_agent_config()
        
        # Get configuration from environment
        github_token = os.environ.get('GITHUB_TOKEN')
        if not github_token:
            logger.error("❌ GITHUB_TOKEN not set, monitoring disabled")
            return
        
        monitor_interval = int(os.environ.get('MONITOR_INTERVAL', 300))
        notify_clean_commits = os.environ.get('NOTIFY_CLEAN_COMMITS', '').lower() in ('true', 'yes', '1')
        
        # Initialize commit monitor (will load repositories from database)
        monitor = CommitMonitor(github_token)
        
        # Initialize security reviewer
        provider_name = os.environ.get('LLM_PROVIDER', 'anthropic')
        provider_kwargs = {}
        
        if provider_name == 'anthropic':
            if model := os.environ.get('CLAUDE_MODEL'):
                provider_kwargs['model'] = model
        elif provider_name == 'openai':
            if model := os.environ.get('GPT_MODEL'):
                provider_kwargs['model'] = model
        
        docs_dir = os.path.abspath(os.environ.get('DOCS_DIR')) if os.environ.get('DOCS_DIR') else None
        
        # Check for multi-judge mode
        multi_judge = os.environ.get('MULTI_JUDGE', '').lower() in ('true', 'yes', '1')
        
        reviewer = SecurityReview(
            provider_name,
            provider_kwargs,
            docs_dir=docs_dir,
            voyage_key=os.environ.get('VOYAGE_API_KEY'),
            voyage_model=os.environ.get('VOYAGE_MODEL'),
            multi_judge=multi_judge,
            gemini_key=os.environ.get('GEMINI_API_KEY')
        )
        
        # Initialize Telegram notifier if configured
        telegram_notifier = None
        telegram_bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        telegram_chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        
        if telegram_bot_token and telegram_chat_id:
            try:
                telegram_notifier = TelegramNotifier(
                    telegram_bot_token,
                    telegram_chat_id,
                    github_token=github_token
                )
                logger.info("✅ Telegram notifications enabled")
                
                # Start polling for commands
                telegram_notifier.start_polling()
                logger.info("✅ Telegram bot is now listening for commands")
            except Exception as e:
                logger.warning(f"⚠️ Telegram notifications disabled: {e}")
        else:
            logger.info("ℹ️ Telegram notifications not configured")
        
        # Define monitoring callback
        def monitoring_callback(monitored_repo, commits):
            run_commit_monitor_callback(
                reviewer, 
                monitored_repo, 
                commits, 
                telegram_notifier, 
                notify_clean_commits=notify_clean_commits
            )
        
        # Define monitoring loop
        def monitoring_loop():
            logger.info(f"🤖 Monitoring service started (checking every {monitor_interval} seconds)")
            
            while True:
                try:
                    logger.info(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Checking for new commits...")
                    new_commits = monitor.get_new_commits()
                    
                    if new_commits:
                        for monitored_repo, commits in new_commits:
                            monitoring_callback(monitored_repo, commits)
                    else:
                        logger.info("No new commits found.")
                    
                except Exception as e:
                    logger.error(f"❌ Error during monitoring: {e}", exc_info=True)
                
                # Wait before next check
                time.sleep(monitor_interval)
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        
        logger.info("✅ Background monitoring service started successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to start monitoring service: {e}", exc_info=True)
