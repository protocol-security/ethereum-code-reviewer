"""
Base class for LLM providers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Tuple
from dataclasses import dataclass
from ..config_loader import agent_config

@dataclass
class CostInfo:
    """Cost information for an LLM request."""
    total_cost: float
    input_tokens: int
    output_tokens: int
    model: str
    provider: str
    
    def __str__(self) -> str:
        return f"${self.total_cost:.6f} ({self.input_tokens} input + {self.output_tokens} output tokens, {self.model})"

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the LLM provider.
        
        Args:
            api_key: API key for the LLM service
            **kwargs: Additional provider-specific configuration
        """
        pass
    
    @abstractmethod
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """
        Calculate the cost for a request.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model used for the request
            
        Returns:
            float: Total cost in USD
        """
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """
        Get the provider name.
        
        Returns:
            str: Provider name (e.g., 'openai', 'anthropic')
        """
        pass
    
    def validate_response(self, response: Dict) -> Dict:
        """
        Validate and normalize the response to ensure consistent confidence scores.
        
        Args:
            response: The analysis response to validate
            
        Returns:
            Dict: Validated and normalized response
        """
        if not response['has_vulnerabilities']:
            response['confidence_score'] = 100
            return response
            
        # If there are findings, overall confidence should match highest finding confidence
        if response['findings']:
            max_confidence = max(finding['confidence'] for finding in response['findings'])
            response['confidence_score'] = max_confidence
            
        return response

    @abstractmethod
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes for security vulnerabilities.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            Tuple containing:
            - Dict with the following structure:
            {
                "confidence_score": int (0-100),
                "has_vulnerabilities": bool,
                "findings": [
                    {
                        "severity": "HIGH|MEDIUM|LOW",
                        "description": str,
                        "recommendation": str,
                        "confidence": int (0-100)
                    }
                ],
                "summary": str
            }
            - CostInfo: Cost information for the request
        """
        pass
    
    @staticmethod
    def get_security_prompt(code_changes: str, context: str = "") -> str:
        """
        Get the base security analysis prompt.
        
        Args:
            code_changes: The code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            str: The formatted prompt for security analysis
        """
        # Load prompt components from agent configuration
        intro = agent_config.get('prompts', 'security', 'intro')
        focus_areas = agent_config.get('prompts', 'security', 'focus_areas')
        important_notes = agent_config.get('prompts', 'security', 'important_notes')
        examples = agent_config.get('prompts', 'security', 'examples')
        response_format = agent_config.get('prompts', 'security', 'response_format')
        no_vulns_response = agent_config.get('prompts', 'security', 'no_vulns_response')
        
        # Build the prompt
        prompt = f"""{intro}
        
        {focus_areas}"""

        if context:
            prompt += f"""

        Here is relevant context about previously discovered vulnerabilities and specifications:

        {context}"""

        prompt += f"""

        Code changes to analyze:

        {code_changes}

        {important_notes}

        {examples}

        {response_format}

        {no_vulns_response}"""

        return prompt
