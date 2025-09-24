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
