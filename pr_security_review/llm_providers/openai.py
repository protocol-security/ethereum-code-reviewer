"""
OpenAI GPT provider implementation.
"""

import os
import json
import re
from typing import Dict, Tuple
from openai import OpenAI
from .base import LLMProvider, CostInfo

class GPTProvider(LLMProvider):
    """GPT provider for security analysis."""
    
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the GPT provider.
        
        Args:
            api_key: OpenAI API key
            **kwargs: Additional configuration options
                - model: GPT model to use (default: gpt-4.1)
                - max_tokens: Maximum tokens for response (default: 4096)
                - temperature: Sampling temperature (default: 0)
        """
        self.api_key = api_key
        self._client = None
        self.model = kwargs.get('model', 'gpt-4.1')
        self.max_tokens = kwargs.get('max_tokens', 4096)
        self.temperature = kwargs.get('temperature', 0)
        
    @property
    def client(self):
        """Lazy initialization of OpenAI client."""
        if self._client is None:
            self._client = OpenAI(api_key=self.api_key)
        return self._client
    
    @client.setter
    def client(self, value):
        """Allow setting client for testing."""
        self._client = value
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """
        Calculate the cost for an OpenAI request.
        
        Pricing as of late 2024 (per 1M tokens):
        - gpt-4o: $5.00 input, $15.00 output
        - gpt-4-turbo: $10.00 input, $30.00 output
        - gpt-3.5-turbo: $0.50 input, $1.50 output
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model used for the request
            
        Returns:
            float: Total cost in USD
        """
        # Cost per 1M tokens (input, output)
        model_pricing = {
            'gpt-4o': (5.00, 15.00),
            'gpt-4.1': (2.00, 8.00),
            'gpt-4-turbo': (10.00, 30.00),
            'gpt-4-turbo-preview': (10.00, 30.00),
            'gpt-3.5-turbo': (0.50, 1.50),
            'gpt-3.5-turbo-0125': (0.50, 1.50),
        }

        # Default to gpt-4.1 pricing if model not found
        input_price, output_price = model_pricing.get(model, (0.15, 0.60))
        
        # Calculate cost (price is per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * input_price
        output_cost = (output_tokens / 1_000_000) * output_price
        
        return input_cost + output_cost
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "openai"
        
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes using GPT.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            Tuple containing:
            - Dict: Security analysis results
            - CostInfo: Cost information for the request
        """
        try:
            system_prompt = os.getenv('LLM_SYNTHESIS_SYSTEM_PROMPT')
            if not system_prompt:
                raise ValueError("LLM_SYNTHESIS_SYSTEM_PROMPT environment variable is not set.")
            
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": self.get_security_prompt(code_changes, context)
                    }
                ]
            )
            
            # Extract token usage and calculate cost
            usage = response.usage
            input_tokens = usage.prompt_tokens
            output_tokens = usage.completion_tokens
            total_cost = self.calculate_cost(input_tokens, output_tokens, self.model)
            
            cost_info = CostInfo(
                total_cost=total_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=self.model,
                provider=self.get_provider_name()
            )
            
            content = response.choices[0].message.content
            try:
                # Simple direct JSON parsing
                result = json.loads(content.strip())
                return self.validate_response(result), cost_info
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse GPT's response as JSON:\n{content}")
                print(f"JSON Error: {str(e)}")
                return {
                    "confidence_score": 0,
                    "has_vulnerabilities": False,
                    "findings": [],
                    "summary": "Failed to analyze security implications"
                }, cost_info
        except Exception as e:
            print(f"Error during GPT analysis: {str(e)}")
            # Return zero cost info for failed requests
            zero_cost = CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
            return {
                "confidence_score": 0,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": f"Analysis failed: {str(e)}"
            }, zero_cost
