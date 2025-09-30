"""
Configuration loader for agent prompts.
"""

import os
import json
from typing import Dict, Any

class AgentConfig:
    """Singleton class to load and store agent configuration."""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load(self, config_path: str) -> None:
        """
        Load configuration from JSON file.
        
        Args:
            config_path: Path to the JSON configuration file
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
            KeyError: If required config keys are missing
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Agent config file not found: {config_path}")
            
        with open(config_path, 'r') as f:
            self._config = json.load(f)
            
        # Validate required keys
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate that all required configuration keys are present."""
        required_paths = [
            ['prompts', 'security', 'intro'],
            ['prompts', 'security', 'focus_areas'],
            ['prompts', 'security', 'important_notes'],
            ['prompts', 'security', 'examples'],
            ['prompts', 'security', 'response_format'],
            ['prompts', 'security', 'no_vulns_response'],
            ['prompts', 'skeptical_verification', 'intro'],
            ['prompts', 'skeptical_verification', 'critical_questions'],
            ['prompts', 'skeptical_verification', 'be_critical'],
            ['prompts', 'skeptical_verification', 'only_confirm'],
            ['prompts', 'skeptical_verification', 'response_format'],
            ['prompts', 'synthesis', 'intro'],
            ['prompts', 'synthesis', 'instruction'],
            ['prompts', 'system_prompts', 'default'],
            ['prompts', 'system_prompts', 'anthropic'],
            ['prompts', 'system_prompts', 'synthesize']
        ]
        
        for path in required_paths:
            current = self._config
            for key in path:
                if key not in current:
                    raise KeyError(f"Missing required config key: {'.'.join(path)}")
                current = current[key]
    
    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Get a configuration value by key path.
        
        Args:
            *keys: Path to the configuration value (e.g., 'prompts', 'security', 'intro')
            default: Default value if key doesn't exist
            
        Returns:
            The configuration value or default
        """
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load() first or set AGENT_CONFIG environment variable.")
            
        current = self._config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current
    
    @property
    def is_loaded(self) -> bool:
        """Check if configuration has been loaded."""
        return self._config is not None

# Global config instance
agent_config = AgentConfig()

def load_agent_config(config_path: str = None) -> None:
    """
    Load agent configuration from file.
    
    Args:
        config_path: Path to configuration file. If None, will check:
                    1. AGENT_CONFIG environment variable
                    2. Default to 'agent.json'
    
    Raises:
        RuntimeError: If no valid configuration path is found
    """
    if config_path is None:
        # Check environment variable
        config_path = os.environ.get('AGENT_CONFIG')
        
        if config_path is None:
            # Try default location
            default_path = 'agent.json'
            if os.path.exists(default_path):
                config_path = default_path
            else:
                raise RuntimeError(
                    "No agent configuration specified. "
                    "Please provide --agent flag, set AGENT_CONFIG environment variable, "
                    "or create 'agent.json' in the current directory."
                )
    
    agent_config.load(config_path)
    print(f"Loaded agent configuration from: {config_path}")
