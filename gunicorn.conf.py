"""
Gunicorn configuration file for the Security Review application.
"""

import os

# Server socket
bind = f"{os.environ.get('WEB_APP_HOST', '0.0.0.0')}:{os.environ.get('WEB_APP_PORT', 5000)}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('WEB_APP_WORKERS', 4))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Restart workers after this many requests, with up to this much jitter
max_requests = 1000
max_requests_jitter = 100

# Load application code before the worker processes are forked
preload_app = True

# Logging
accesslog = '-'
errorlog = '-'
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'security-review-web'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Enable forwarded headers for proxy setups
forwarded_allow_ips = '*'

# Graceful shutdown
graceful_timeout = 30

# SSL (if using SSL termination at Gunicorn level)
# keyfile = 'path/to/keyfile'
# certfile = 'path/to/certfile'


def post_fork(server, worker):
    """
    Called after a worker process is forked.
    
    This is used to start the monitoring service only in the first worker
    to avoid duplicate monitoring across multiple workers.
    """
    # Only start monitoring in worker 1 to avoid duplicates
    if worker.age == 0 and os.environ.get('MONITOR_CONTINUOUS', '').lower() in ('true', 'yes', '1'):
        # Get the worker number (workers are numbered starting from 1)
        worker_num = worker.pid % workers
        
        if worker_num == 1:  # Start monitoring only in the first worker
            server.log.info(f"🤖 Worker {worker.pid}: Starting monitoring service")
            
            # Import and start monitoring
            try:
                from pr_security_review.web import start_monitoring_service
                start_monitoring_service()
            except Exception as e:
                server.log.error(f"❌ Failed to start monitoring in worker {worker.pid}: {e}")
        else:
            server.log.info(f"ℹ️ Worker {worker.pid}: Monitoring handled by worker 1")


def when_ready(server):
    """Called just after the server is started."""
    server.log.info("🚀 Gunicorn server is ready to handle requests")
    
    if os.environ.get('MONITOR_CONTINUOUS', '').lower() in ('true', 'yes', '1'):
        server.log.info("🔄 Monitoring service will start in worker process")
    else:
        server.log.info("ℹ️ Monitoring service disabled (MONITOR_CONTINUOUS not set)")
