"""
Utility functions for rendering pages and generating reports.
"""

import os
import logging
from typing import Dict, Any
from datetime import datetime, timezone
from flask import render_template

logger = logging.getLogger(__name__)


def generate_example_report() -> Dict[str, Any]:
    """Generate an example security report for demonstration purposes."""
    # Load example report from external file
    example_path = os.path.join(os.path.dirname(__file__), '..', 'example_report.html')
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
        'created_at': datetime.now(timezone.utc),
        'metadata': {
            'is_example': True,
            'repo_name': 'ethereum/example-contract'
        }
    }


def render_finding_page(finding_data: Dict, finding_uuid: str, is_authenticated: bool = False) -> str:
    """Render a finding page with full styling."""
    
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
            padding: 1rem 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .header h1 i {{
            font-size: 1.5rem;
        }}
        
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        
        .dashboard-btn {{
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: background 0.2s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .dashboard-btn:hover {{
            background: rgba(255, 255, 255, 0.3);
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
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
        
        /* Include minimal styles for content */
        .main-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.5rem;
            }}
            
            .container {{
                padding: 1rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>
                <i class="fas fa-shield-alt"></i>
                Security Finding Report
            </h1>
            
            {'<div class="header-actions"><a href="/" class="dashboard-btn"><i class="fas fa-home"></i>Back to Dashboard</a></div>' if is_authenticated else ''}
        </div>
    </div>
    
    <div class="container">
        {finding_data['html_content']}
    </div>
    
    <div class="footer">
        <div class="footer-content">
            <div class="metadata">
                <p><i class="far fa-clock"></i> Generated on: {finding_data['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
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
    
    return html_content


def render_error_page(message: str, status_code: int = 404):
    """Render an error page."""
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Security Findings</title>
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
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        
        .error-container {{
            text-align: center;
            padding: 2rem;
            max-width: 600px;
        }}
        
        .error-icon {{
            font-size: 4rem;
            color: #fc8181;
            margin-bottom: 1rem;
        }}
        
        .error-title {{
            font-size: 2rem;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 1rem;
        }}
        
        .error-message {{
            font-size: 1.125rem;
            color: #4a5568;
            margin-bottom: 2rem;
        }}
        
        .back-link {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            transition: background 0.2s;
        }}
        
        .back-link:hover {{
            background: #5a67d8;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">
            <i class="fas fa-exclamation-triangle"></i>
        </div>
        <h1 class="error-title">Error {status_code}</h1>
        <p class="error-message">{message}</p>
        <a href="/" class="back-link">
            <i class="fas fa-home"></i>
            Back to Home
        </a>
    </div>
</body>
</html>"""
    
    return html_content, status_code
