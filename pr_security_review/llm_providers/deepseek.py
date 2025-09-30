"""
Deepseek provider implementation.
"""

import json
from typing import Dict, Tuple
from openai import OpenAI
from .base import LLMProvider, CostInfo
from ..config_loader import agent_config

class DeepseekProvider(LLMProvider):
    """Deepseek provider for security analysis."""
    
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the Deepseek provider.
        
        Args:
            api_key: Deepseek API key
            **kwargs: Additional configuration options
                - model: Deepseek model to use (default: deepseek-reasoner)
                - max_tokens: Maximum tokens for response (default: 4096)
                - temperature: Sampling temperature (default: 0)
        """
        self.api_key = api_key
        self._client = None
        self.base_url = "https://api.deepseek.com"
        self.model = kwargs.get('model', 'deepseek-reasoner')
        self.max_tokens = kwargs.get('max_tokens', 65536)
        self.temperature = kwargs.get('temperature', 0)
        
    @property
    def client(self):
        """Lazy initialization of OpenAI client with Deepseek endpoint."""
        if self._client is None:
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url
            )
        return self._client
    
    @client.setter
    def client(self, value):
        """Allow setting client for testing."""
        self._client = value
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """
        Calculate the cost for a Deepseek request.
                
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model used for the request
            
        Returns:
            float: Total cost in USD
        """
        # Estimated cost per 1M tokens (input, output)
        model_pricing = {
            'deepseek-reasoner': (0.56, 1.68)
        }

        # Default pricing if model not found
        input_price, output_price = model_pricing.get(model, (0.56, 1.68))
        
        # Calculate cost (price is per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * input_price
        output_cost = (output_tokens / 1_000_000) * output_price
        
        return input_cost + output_cost
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "deepseek"
        
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes using Deepseek.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            Tuple containing:
            - Dict: Security analysis results
            - CostInfo: Cost information for the request
        """
        # context = ""
        try:
            # Prepare the messages
            system_prompt = agent_config.get('prompts', 'system_prompts', 'default')
            
            messages = [
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": self.get_security_prompt(code_changes, context)
                }
            ]
            
            # Estimate input tokens (rough approximation: 1 token ≈ 4 characters)
            total_input_text = messages[0]["content"] + messages[1]["content"]
            estimated_input_tokens = len(total_input_text) // 4
            
            # Calculate available tokens for completion with safety buffer
            context_limit = 65536  # deepseek-reasoner context limit
            safety_buffer = 1000   # Reserve buffer for safety
            available_tokens = context_limit - estimated_input_tokens - safety_buffer
            
            # Ensure we have a reasonable minimum for output
            max_completion_tokens = max(available_tokens, 4096)
            
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_completion_tokens,
                temperature=self.temperature,
                messages=messages,
                stream=False
            )
            
            # Handle case where response is returned as JSON string instead of object
            if isinstance(response, str):
                try:
                    response = json.loads(response)
                except json.JSONDecodeError as e:
                    print(f"Failed to parse API response as JSON: {e}")
                    raise Exception(f"Invalid API response format: {response[:200]}...")
            
            # Extract token usage and calculate cost
            # Handle potential custom API response format differences
            input_tokens = 0
            output_tokens = 0
            
            if hasattr(response, 'usage') and response.usage:
                usage = response.usage
                # Handle both object and string usage formats
                if hasattr(usage, 'prompt_tokens'):
                    input_tokens = usage.prompt_tokens
                    output_tokens = usage.completion_tokens
                elif isinstance(usage, str):
                    # If usage is a string, try to parse it
                    try:
                        usage_dict = json.loads(usage)
                        input_tokens = usage_dict.get('prompt_tokens', 0)
                        output_tokens = usage_dict.get('completion_tokens', 0)
                    except:
                        # Estimate tokens if parsing fails
                        input_tokens = len(self.get_security_prompt(code_changes, context)) // 4
                        try:
                            if hasattr(response, 'choices'):
                                output_tokens = len(response.choices[0].message.content) // 4
                            elif isinstance(response, dict) and 'choices' in response:
                                output_tokens = len(response['choices'][0]['message']['content']) // 4
                            else:
                                output_tokens = 0
                        except:
                            output_tokens = 0
                else:
                    # Estimate tokens if usage format is unexpected
                    input_tokens = len(self.get_security_prompt(code_changes, context)) // 4
                    try:
                        if hasattr(response, 'choices'):
                            output_tokens = len(response.choices[0].message.content) // 4
                        elif isinstance(response, dict) and 'choices' in response:
                            output_tokens = len(response['choices'][0]['message']['content']) // 4
                        else:
                            output_tokens = 0
                    except:
                        output_tokens = 0
            else:
                # Estimate tokens if no usage info available
                input_tokens = len(self.get_security_prompt(code_changes, context)) // 4
                try:
                    if hasattr(response, 'choices'):
                        output_tokens = len(response.choices[0].message.content) // 4
                    elif isinstance(response, dict) and 'choices' in response:
                        output_tokens = len(response['choices'][0]['message']['content']) // 4
                    else:
                        output_tokens = 0
                except:
                    output_tokens = 0
            
            total_cost = self.calculate_cost(input_tokens, output_tokens, self.model)
            
            cost_info = CostInfo(
                total_cost=total_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=self.model,
                provider=self.get_provider_name()
            )
            
            # Extract content from response, handling both object and dict formats
            if hasattr(response, 'choices'):
                content = response.choices[0].message.content
            elif isinstance(response, dict) and 'choices' in response:
                content = response['choices'][0]['message']['content']
            else:
                raise Exception(f"Unexpected response format: {type(response)}")
            try:
                # Extract JSON from markdown code blocks if present
                content_clean = content.strip()
                if content_clean.startswith('```json'):
                    # Find the JSON content between ```json and ```
                    start_idx = content_clean.find('```json') + 7
                    end_idx = content_clean.rfind('```')
                    if end_idx > start_idx:
                        content_clean = content_clean[start_idx:end_idx].strip()
                elif content_clean.startswith('```'):
                    # Handle generic code blocks
                    start_idx = content_clean.find('```') + 3
                    end_idx = content_clean.rfind('```')
                    if end_idx > start_idx:
                        content_clean = content_clean[start_idx:end_idx].strip()
                
                # Parse the cleaned JSON content
                result = json.loads(content_clean)
                return self.validate_response(result), cost_info
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse Deepseek's response as JSON:\n{content}")
                print(f"JSON Error: {str(e)}")
                return {
                    "confidence_score": 0,
                    "has_vulnerabilities": False,
                    "findings": [],
                    "summary": "Failed to analyze security implications"
                }, cost_info
        except Exception as e:
            print(f"Error during Deepseek analysis: {str(e)}")
            # Return zero cost info for failed requests
            zero_cost = CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
            return {
                "confidence_score": 0,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": f"Analysis failed: {str(e)}"
            }, zero_cost
