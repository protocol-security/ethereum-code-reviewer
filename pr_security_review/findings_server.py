"""
Simple HTTP server to serve security findings via UUID links.
"""

import os
import uuid
import json
import threading
import time
import datetime
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional
import markdown
from markdown.extensions.fenced_code import FencedCodeExtension
import logging
from urllib.parse import urlparse

# Import database layer
try:
    from .database import get_database_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"Database not available, falling back to in-memory storage: {e}")
    DATABASE_AVAILABLE = False

# Fallback in-memory storage for findings if database is not available
# UUID -> {finding_data, created_at, markdown_content}
FINDINGS_STORAGE = {}

# Expiration time for findings in hours (default: 7 days)
EXPIRATION_TIME_HOURS = 7 * 24

logger = logging.getLogger(__name__)


class FindingsRequestHandler(BaseHTTPRequestHandler):
    """Handler for serving security findings by UUID."""
    
    def do_GET(self):
        """Handle GET requests to access findings."""
        # Check if path starts with /finding/
        if not self.path.startswith('/finding/'):
            self.send_error(404)
            return
            
        # Extract UUID from path
        try:
            finding_uuid = self.path.split('/finding/')[1]
            if not finding_uuid or '/' in finding_uuid:  # No UUID or contains other path parts
                self.send_error(404)
                return
                
            # Check if this is a request for the example report
            if finding_uuid == 'example-report':
                finding_data = self._generate_example_report()
            else:
                # Look up finding by UUID - try database first, fallback to in-memory
                finding_data = None
                if DATABASE_AVAILABLE:
                    try:
                        db_manager = get_database_manager()
                        finding_data = db_manager.get_finding(finding_uuid)
                    except Exception as e:
                        logger.error(f"Database lookup failed, falling back to in-memory: {e}")
                
                # Fallback to in-memory storage if database not available or failed
                if not finding_data:
                    finding_data = FINDINGS_STORAGE.get(finding_uuid)
                
                if not finding_data:
                    self.send_error(404, "Finding not found or has expired")
                    return
                
            # Serve the finding
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Finding Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: #f8fafc;
            min-height: 100vh;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }}
        
        .header h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .header h1 i {{
            font-size: 1.75rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .main-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        
        .card-header {{
            background: #f7fafc;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .card-content {{
            padding: 2rem;
        }}
        
        .repo-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .info-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            overflow: hidden;
        }}
        
        .info-item i {{
            color: #667eea;
            width: 20px;
            text-align: center;
            flex-shrink: 0;
        }}
        
        .info-label {{
            font-weight: 500;
            color: #4a5568;
            min-width: 80px;
            flex-shrink: 0;
        }}
        
        .info-value {{
            color: #1a202c;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            flex: 1;
        }}
        
        .info-value a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .info-value a:hover {{
            text-decoration: underline;
        }}
        
        .commit-message {{
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 1rem 1.5rem;
            border-radius: 0 8px 8px 0;
            margin: 1.5rem 0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9rem;
        }}
        
        .score-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}
        
        .score-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .score-card.safe {{
            background: linear-gradient(135deg, #d4fc79 0%, #96e6a1 100%);
        }}
        
        .score-card.vulnerable {{
            background: linear-gradient(135deg, #fc466b 0%, #3f5efb 100%);
            color: white;
        }}
        
        .score-value {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        .score-label {{
            font-size: 0.875rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .summary-section {{
            background: #edf2f7;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 2rem 0;
        }}
        
        .findings-section {{
            margin-top: 2rem;
        }}
        
        .finding-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }}
        
        .finding-header {{
            padding: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .finding-header.high {{
            background: #fff5f5;
            border-left: 4px solid #fc8181;
        }}
        
        .finding-header.medium {{
            background: #fffaf0;
            border-left: 4px solid #f6ad55;
        }}
        
        .finding-header.low {{
            background: #fffff0;
            border-left: 4px solid #f6e05e;
        }}
        
        .severity-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-badge.high {{
            background: #fc8181;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #f6ad55;
            color: white;
        }}
        
        .severity-badge.low {{
            background: #f6e05e;
            color: #744210;
        }}
        
        .confidence-badge {{
            background: #e2e8f0;
            color: #4a5568;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }}
        
        .finding-content {{
            padding: 1.5rem;
        }}
        
        .finding-content h4 {{
            color: #2d3748;
            margin-bottom: 0.75rem;
            font-size: 1.125rem;
        }}
        
        .finding-content p {{
            color: #4a5568;
            margin-bottom: 1rem;
        }}
        
        .recommendation {{
            background: #e6fffa;
            border-left: 4px solid #4fd1c5;
            padding: 1rem;
            border-radius: 0 8px 8px 0;
            margin: 1rem 0;
        }}
        
        .details-box {{
            margin-top: 1.5rem;
        }}
        
        .details-toggle {{
            background: #667eea;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: background 0.2s;
        }}
        
        .details-toggle:hover {{
            background: #5a67d8;
        }}
        
        .details-content {{
            display: none;
            margin-top: 1rem;
            padding: 1.5rem;
            background: #f7fafc;
            border-radius: 8px;
        }}
        
        .details-content.show {{
            display: block;
        }}
        
        .details-content h4 {{
            color: #2d3748;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .details-content h4:first-child {{
            margin-top: 0;
        }}
        
        .details-content h4 i {{
            color: #667eea;
            font-size: 0.875rem;
        }}
        
        pre {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.875rem;
            line-height: 1.5;
            margin: 1rem 0;
        }}
        
        code {{
            background: #edf2f7;
            color: #e53e3e;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        
        pre code {{
            background: transparent;
            color: inherit;
            padding: 0;
        }}
        
        .multi-judge {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            padding: 2rem;
            margin: 2rem 0;
        }}
        
        .multi-judge h3 {{
            color: #2d3748;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .judge-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #f7fafc;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #2d3748;
        }}
        
        .stat-label {{
            font-size: 0.75rem;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        
        th {{
            background: #f7fafc;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #4a5568;
            border-bottom: 2px solid #e2e8f0;
        }}
        
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        .footer {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 2rem 0;
            margin-top: 4rem;
        }}
        
        .footer-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            text-align: center;
        }}
        
        .metadata {{
            font-size: 0.875rem;
            color: #a0aec0;
        }}
        
        .metadata p {{
            margin: 0.25rem 0;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.5rem;
            }}
            
            .container {{
                padding: 1rem;
            }}
            
            .card-content {{
                padding: 1rem;
            }}
            
            .repo-info {{
                grid-template-columns: 1fr;
                gap: 1rem;
            }}
            
            .info-item {{
                flex-wrap: wrap;
            }}
            
            .info-value {{
                white-space: normal;
                word-break: break-word;
            }}
            
            table {{
                font-size: 0.875rem;
            }}
            
            th, td {{
                padding: 0.5rem;
            }}
            
            .score-section {{
                grid-template-columns: 1fr;
            }}
            
            .judge-stats {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1><i class="fas fa-shield-alt"></i> Security Finding Report</h1>
        </div>
    </div>
    
    <div class="container">
        {finding_data['html_content']}
    </div>
    
    <div class="footer">
        <div class="footer-content">
            <div class="metadata">
                <p><i class="far fa-clock"></i> Generated on: {finding_data['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><i class="far fa-calendar-times"></i> This link will expire in {EXPIRATION_TIME_HOURS // 24} days</p>
            </div>
        </div>
    </div>
    
    <script>
        // Toggle details sections
        document.querySelectorAll('.details-toggle').forEach(button => {{
            button.addEventListener('click', function() {{
                const content = this.nextElementSibling;
                content.classList.toggle('show');
                const icon = this.querySelector('i');
                if (content.classList.contains('show')) {{
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                }} else {{
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                }}
            }});
        }});
    </script>
</body>
</html>"""
            
            self.wfile.write(html_content.encode())
            
        except Exception as e:
            print(f"Error serving finding: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def _generate_example_report(self) -> Dict:
        """Generate an example security report for demonstration purposes."""
        import datetime
        import os
        
        # Load example report from external file
        example_path = os.path.join(os.path.dirname(__file__), 'example_report.html')
        try:
            with open(example_path, 'r') as f:
                example_html = f.read()
        except FileNotFoundError:
            # Fallback if file not found
            example_html = """
    <div class="main-card">
        <div class="card-header">
            <h2><i class="fas fa-code-branch"></i> Repository: ethereum/example-contract</h2>
        </div>
        <div class="card-content">
            <p>Example report file not found. Please ensure example_report.html exists in the pr_security_review directory.</p>
        </div>
    </div>
"""
        
        return {
            'html_content': example_html,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'metadata': {
                'is_example': True,
                'repo_name': 'ethereum/example-contract'
            }
        }


def store_finding(html_content: str, metadata: Optional[Dict] = None) -> str:
    """
    Store a finding and return a UUID for accessing it.
    
    Args:
        html_content: HTML content of the finding
        metadata: Optional metadata about the finding
        
    Returns:
        str: UUID for accessing the finding
    """
    finding_uuid = str(uuid.uuid4())
    
    # Store finding with creation timestamp
    FINDINGS_STORAGE[finding_uuid] = {
        'html_content': html_content,
        'metadata': metadata or {},
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    
    return finding_uuid


def cleanup_expired_findings():
    """Remove expired findings from storage."""
    removed_count = 0
    
    # Try database cleanup first
    if DATABASE_AVAILABLE:
        try:
            db_manager = get_database_manager()
            removed_count = db_manager.cleanup_expired_findings()
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
    
    # Also cleanup in-memory storage
    now = datetime.datetime.now(datetime.timezone.utc)
    expiration_delta = datetime.timedelta(hours=EXPIRATION_TIME_HOURS)
    
    expired_uuids = [
        uuid_key for uuid_key, data in FINDINGS_STORAGE.items()
        if (now - data['created_at']) > expiration_delta
    ]
    
    for uuid_key in expired_uuids:
        if uuid_key in FINDINGS_STORAGE:
            del FINDINGS_STORAGE[uuid_key]
    
    removed_count += len(expired_uuids)
    return removed_count


class FindingsServer:
    """Server for hosting security findings via UUID links."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8000):
        """
        Initialize the findings server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False
        # self.cleanup_interval = 3600  # Cleanup every 1 hour (3600 seconds)
        self.cleanup_thread = None
        
    def get_url_base(self) -> str:
        """
        Get the base URL for the findings server.
        
        Returns:
            str: Base URL for accessing findings
        """
        # Try to determine public URL
        # Prefer explicit findings server URL, then fallback to BASE_URL for compatibility
        url = os.environ.get('FINDINGS_SERVER_URL') or os.environ.get('BASE_URL')
        if url:
            # Keep the configured URL as-is, but ensure it's absolute and normalized
            url = url.rstrip('/')
            if not re.match(r'^https?://', url):
                url = f"https://{url}"

            parsed = urlparse(url)
            host = parsed.hostname or ''
            # Make sure localhost-style URLs include the findings port if not already present
            if host in ('localhost', '127.0.0.1', '0.0.0.0') and parsed.port is None:
                url = f"{url}:{self.port}"

            return url
            
        # Otherwise use local URL (will only work for local access)
        # Use 'localhost' instead of the binding IP for better client compatibility
        host = 'localhost' if self.host in ('0.0.0.0', '127.0.0.1') else self.host
        return f"http://{host}:{self.port}"
        
    def get_finding_url(self, finding_uuid: str) -> str:
        """
        Get the URL for a stored finding.
        
        Args:
            finding_uuid: UUID of the stored finding
            
        Returns:
            str: URL for accessing the finding
        """
        base_url = self.get_url_base()
        return f"{base_url}/finding/{finding_uuid}"
        
    def start(self):
        """Start the findings server in a background thread."""
        if self.running:
            return
            
        self.server = HTTPServer((self.host, self.port), FindingsRequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.running = True
        
        # Start cleanup thread
        # self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        # self.cleanup_thread.daemon = True
        # self.cleanup_thread.start()
        
        print(f"Findings server running at http://{self.host}:{self.port}")
        
    def stop(self):
        """Stop the findings server."""
        if not self.running:
            return
            
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
            
        print("Findings server stopped")
        
    def _cleanup_loop(self):
        """Periodically clean up expired findings."""
        while self.running:
            time.sleep(self.cleanup_interval)
            try:
                removed_count = cleanup_expired_findings()
                if removed_count > 0:
                    print(f"Cleaned up {removed_count} expired findings")
            except Exception as e:
                print(f"Error during findings cleanup: {e}")


# Singleton instance
_server_instance = None

def get_server() -> FindingsServer:
    """
    Get the singleton FindingsServer instance.
    
    Returns:
        FindingsServer: The server instance
    """
    global _server_instance
    if _server_instance is None:
        # Get port from environment variable or use default
        port = int(os.environ.get('FINDINGS_SERVER_PORT', 8000))
        _server_instance = FindingsServer(port=port)
    return _server_instance


def store_security_finding(repo_name: str, commit_info, analysis: Dict) -> str:
    """
    Store a security finding and return a URL for accessing it.
    
    Args:
        repo_name: Repository name
        commit_info: Commit information
        analysis: Security analysis results
        
    Returns:
        str: URL for accessing the finding
    """
    # Ensure server is running
    server = get_server()
    if not server.running:
        server.start()
    
    # Generate HTML content for the finding
    html_content = f"""
    <div class="main-card">
        <div class="card-header">
            <h2><i class="fas fa-code-branch"></i> Repository: {repo_name}</h2>
        </div>
        <div class="card-content">
            <div class="repo-info">
                <div class="info-item">
                    <i class="fas fa-code-branch"></i>
                    <span class="info-label">Branch:</span>
                    <span class="info-value">{commit_info.branch}</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-code-commit"></i>
                    <span class="info-label">Commit:</span>
                    <span class="info-value">
                        <a href="{commit_info.url}" target="_blank">{commit_info.sha[:7]}</a>
                    </span>
                </div>
                <div class="info-item">
                    <i class="fas fa-user"></i>
                    <span class="info-label">Author:</span>
                    <span class="info-value">{commit_info.author}</span>
                </div>
                <div class="info-item">
                    <i class="far fa-calendar"></i>
                    <span class="info-label">Date:</span>
                    <span class="info-value">{commit_info.date}</span>
                </div>
            </div>
            
            <h3><i class="fas fa-comment-dots"></i> Commit Message</h3>
            <div class="commit-message">
                {commit_info.message}
            </div>
            
            <div class="score-section">
                <div class="score-card">
                    <div class="score-value">{analysis['confidence_score']}%</div>
                    <div class="score-label">Confidence Score</div>
                </div>
                <div class="score-card {'vulnerable' if analysis['has_vulnerabilities'] else 'safe'}">
                    <div class="score-value">
                        {'<i class="fas fa-exclamation-triangle"></i>' if analysis['has_vulnerabilities'] else '<i class="fas fa-shield-alt"></i>'}
                    </div>
                    <div class="score-label">
                        {'Vulnerabilities Detected' if analysis['has_vulnerabilities'] else 'No Vulnerabilities Found'}
                    </div>
                </div>
            </div>
        </div>
    </div>
"""

    # Add multi-judge voting details if available
    if 'multi_judge_details' in analysis and analysis['multi_judge_details'].get('enabled'):
        details = analysis['multi_judge_details']
        html_content += f"""
    <div class="multi-judge">
        <h3><i class="fas fa-robot"></i> Multi-Judge Analysis</h3>
        <p>This analysis was performed using <strong>{len(details['providers'])} LLM judges</strong> with weighted voting.</p>
        
        <div class="judge-stats">
            <div class="stat-card">
                <div class="stat-value">{details['total_weight']:.1f}</div>
                <div class="stat-label">Total Weight</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{details['vote_threshold']:.2f}</div>
                <div class="stat-label">Required Threshold</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{details['weighted_score']:.2f}</div>
                <div class="stat-label">Actual Vote Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">
                    {'<i class="fas fa-exclamation-triangle" style="color: #fc8181;"></i>' if details['has_vulnerabilities'] else '<i class="fas fa-check-circle" style="color: #48bb78;"></i>'}
                </div>
                <div class="stat-label">
                    {'Vulnerabilities Detected' if details['has_vulnerabilities'] else 'No Vulnerabilities'}
                </div>
            </div>
        </div>
        
        <h4>Individual LLM Results</h4>
        <table>
            <thead>
                <tr>
                    <th>LLM Provider</th>
                    <th>Weight</th>
                    <th>Vote</th>
                    <th>Confidence</th>
                    <th>Issues Found</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for provider, result in details['individual_results'].items():
            vote_icon = '<i class="fas fa-exclamation-triangle" style="color: #fc8181;"></i> YES' if result['has_vulnerabilities'] else '<i class="fas fa-check-circle" style="color: #48bb78;"></i> NO'
            issues = f"{result['findings_count']} issue(s)" if result['findings_count'] > 0 else "None"
            
            # Add severity breakdown if issues found
            if result['findings_count'] > 0 and result.get('findings_severity'):
                severity_parts = []
                for sev in ['HIGH', 'MEDIUM', 'LOW']:
                    count = result['findings_severity'].get(sev, 0)
                    if count > 0:
                        severity_parts.append(f"{count} {sev}")
                if severity_parts:
                    issues += f"<br><small>({', '.join(severity_parts)})</small>"
            
            summary = result['summary'][:60] + '...' if len(result['summary']) > 60 else result['summary']
            weight = details['weights'].get(provider, 0)
            
            html_content += f"""
                <tr>
                    <td><strong>{provider.capitalize()}</strong></td>
                    <td>{weight}</td>
                    <td>{vote_icon}</td>
                    <td>{result['confidence_score']}%</td>
                    <td>{issues}</td>
                    <td>{summary}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
"""
    
    # Add summary section
    html_content += f"""
    <div class="main-card">
        <div class="card-header">
            <h3><i class="fas fa-clipboard-check"></i> Analysis Summary</h3>
        </div>
        <div class="card-content">
            <div class="summary-section">
                <p>{analysis['summary']}</p>
            </div>
        </div>
    </div>
"""

    if analysis['findings']:
        html_content += """
    <div class="main-card">
        <div class="card-header">
            <h3><i class="fas fa-bug"></i> Detailed Findings</h3>
        </div>
        <div class="card-content findings-section">
"""
        
        for i, finding in enumerate(analysis['findings']):
            severity_class = finding['severity'].lower()
            severity_icon = {
                'high': 'fas fa-exclamation-circle',
                'medium': 'fas fa-exclamation-triangle', 
                'low': 'fas fa-info-circle'
            }.get(severity_class, 'fas fa-info-circle')
            
            html_content += f"""
            <div class="finding-card">
                <div class="finding-header {severity_class}">
                    <div>
                        <span class="severity-badge {severity_class}">
                            <i class="{severity_icon}"></i> {finding['severity']} Severity
                        </span>
                    </div>
                    <span class="confidence-badge">
                        {finding['confidence']}% Confidence
                    </span>
                </div>
                <div class="finding-content">
                    <h4>Description</h4>
                    <p>{finding['description']}</p>
                    
                    <div class="recommendation">
                        <h4><i class="fas fa-lightbulb"></i> Recommendation</h4>
                        <p>{finding['recommendation']}</p>
                    </div>
                    
                    <div class="details-box">
                        <button class="details-toggle">
                            <i class="fas fa-chevron-down"></i>
                            View Detailed Explanation
                        </button>
                        <div class="details-content">
"""
            
            # Add detailed explanation sections
            what_is_issue = finding.get('detailed_explanation', 'No detailed explanation provided.')
            html_content += f"""
                            <h4><i class="fas fa-question-circle"></i> What is the issue?</h4>
                            <p>{what_is_issue}</p>
"""
            
            impact = finding.get('impact_explanation', 
                               'The security implications of this vulnerability could lead to unauthorized access, data exposure, or system compromise depending on the specific implementation.')
            html_content += f"""
                            <h4><i class="fas fa-exclamation-triangle"></i> What can happen?</h4>
                            <p>{impact}</p>
"""
            
            fix = finding.get('detailed_recommendation', finding['recommendation'])
            html_content += f"""
                            <h4><i class="fas fa-wrench"></i> How to fix it?</h4>
                            <p>{fix}</p>
"""
            
            code_example = finding.get('code_example', '// Example fix not available')
            # Escape HTML in code example
            code_example = code_example.replace('<', '&lt;').replace('>', '&gt;')
            html_content += f"""
                            <h4><i class="fas fa-code"></i> Code example</h4>
                            <pre><code>{code_example}</code></pre>
"""
            
            # Only add resources section if resources are actually available
            if 'additional_resources' in finding and finding['additional_resources']:
                resources = finding['additional_resources']
                # Convert markdown links to HTML
                resources_html = markdown.markdown(resources, extensions=['fenced_code'])
                html_content += f"""
                            <h4><i class="fas fa-book"></i> Additional resources</h4>
                            {resources_html}
"""
            
            html_content += """
                        </div>
                    </div>
                </div>
            </div>
"""
        
        html_content += """
        </div>
    </div>
"""

    # Store the finding and get UUID - try database first, fallback to in-memory
    finding_uuid = None
    if DATABASE_AVAILABLE:
        try:
            db_manager = get_database_manager()
            finding_uuid = db_manager.store_finding(
                html_content=html_content,
                repo_name=repo_name,
                commit_info=commit_info,
                analysis=analysis,
                metadata={
                    'repo_name': repo_name,
                    'commit_sha': commit_info.sha,
                    'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
            )
            logger.info(f"Stored finding in database with UUID: {finding_uuid}")
        except Exception as e:
            logger.error(f"Database storage failed, falling back to in-memory: {e}")
    
    # Fallback to in-memory storage if database not available or failed
    if not finding_uuid:
        finding_uuid = store_finding(html_content, {
            'repo_name': repo_name,
            'commit_sha': commit_info.sha,
            'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        logger.info(f"Stored finding in memory with UUID: {finding_uuid}")
    
    # Return the URL for accessing the finding
    return server.get_finding_url(finding_uuid)
