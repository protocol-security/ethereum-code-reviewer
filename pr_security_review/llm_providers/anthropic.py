"""
Anthropic Claude provider implementation.
"""

import json
import re
from typing import Dict, Tuple, List
import anthropic
from .base import LLMProvider, CostInfo
from ..config_loader import agent_config

class ClaudeProvider(LLMProvider):
    """Claude provider for security analysis."""
    
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the Claude provider.
        
        Args:
            api_key: Anthropic API key
            **kwargs: Additional configuration options
                - model: Claude model to use (default: claude-sonnet-4-20250514)
                - max_tokens: Maximum tokens for response (default: 4096)
                - temperature: Sampling temperature (default: 0)
        """
        self.api_key = api_key
        self._client = None
        self.model = kwargs.get('model', 'claude-sonnet-4-20250514')
        self.max_tokens = kwargs.get('max_tokens', 4096)
        self.temperature = kwargs.get('temperature', 0)
        
    @property
    def client(self):
        """Lazy initialization of Anthropic client."""
        if self._client is None:
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client
    
    @client.setter
    def client(self, value):
        """Allow setting client for testing."""
        self._client = value
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """
        Calculate the cost for an Anthropic request.
       
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model used for the request
            
        Returns:
            float: Total cost in USD
        """
        # Cost per 1M tokens (input, output)
        model_pricing = {
            'claude-opus-4-20250514': (15.00, 75.00),
            'claude-sonnet-4-20250514': (3.00, 15.00),
            'claude-3-7-sonnet-latest': (3.00, 15.00),
            'claude-3-5-sonnet-20241022': (3.00, 15.00),
            'claude-3-5-sonnet-latest': (3.00, 15.00),
            'claude-3-5-haiku-20241022': (1.00, 5.00),
            'claude-3-5-haiku-latest': (1.00, 5.00),
            'claude-3-opus-20240229': (15.00, 75.00),
            'claude-3-sonnet-20240229': (3.00, 15.00),
            'claude-3-haiku-20240307': (0.25, 1.25),
        }
        
        # Default to sonnet pricing if model not found
        input_price, output_price = model_pricing.get(model, (3.00, 15.00))
        
        # Calculate cost (price is per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * input_price
        output_cost = (output_tokens / 1_000_000) * output_price
        
        return input_cost + output_cost
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "anthropic"
    
    def get_skeptical_verification_prompt(self, code_changes: str, findings: List[Dict]) -> str:
        """
        Get a skeptical verification prompt to double-check findings.
        
        Args:
            code_changes: The code changes to analyze
            findings: The initial findings to verify
            
        Returns:
            str: The formatted skeptical verification prompt
        """
        findings_text = "\n\n".join([
            f"Finding {i+1}:\n"
            f"Severity: {finding['severity']}\n"
            f"Description: {finding['description']}\n"
            f"Confidence: {finding['confidence']}%"
            for i, finding in enumerate(findings)
        ])
        
        # Load prompt components from agent configuration
        intro = agent_config.get('prompts', 'skeptical_verification', 'intro')
        critical_questions = agent_config.get('prompts', 'skeptical_verification', 'critical_questions')
        be_critical = agent_config.get('prompts', 'skeptical_verification', 'be_critical')
        only_confirm = agent_config.get('prompts', 'skeptical_verification', 'only_confirm')
        response_format = agent_config.get('prompts', 'skeptical_verification', 'response_format')
        
        prompt = f"""{intro}
        
        Another security expert has identified the following potential vulnerabilities:
        
        {findings_text}
        
        Now, review the actual code changes and BE EXTREMELY SKEPTICAL:
        
        {code_changes}
        
        {critical_questions}
        
        {be_critical}
        
        {only_confirm}
        
        {response_format}"""
        
        return prompt
    
    def verify_findings(self, code_changes: str, initial_result: Dict) -> Tuple[Dict, CostInfo]:
        """
        Perform skeptical verification of initial findings.
        
        Args:
            code_changes: The code changes to analyze
            initial_result: The initial analysis result with findings
            
        Returns:
            Tuple containing verified findings and cost info
        """
        if not initial_result.get('has_vulnerabilities') or not initial_result.get('findings'):
            # No findings to verify
            return initial_result, CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
        
        try:
            system_prompt = agent_config.get('prompts', 'system_prompts', 'anthropic')
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[{
                    "role": "user",
                    "content": self.get_skeptical_verification_prompt(code_changes, initial_result['findings'])
                }]
            )
            
            # Extract token usage and calculate cost
            usage = response.usage
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
            verification_cost = self.calculate_cost(input_tokens, output_tokens, self.model)
            
            cost_info = CostInfo(
                total_cost=verification_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=self.model,
                provider=self.get_provider_name()
            )
            
            try:
                if not response.content or not hasattr(response.content[0], 'text'):
                    raise ValueError("Invalid response format")
                
                response_text = response.content[0].text.strip() if response.content[0].text else ""
                
                if not response_text:
                    raise ValueError("Empty verification response")
                
                # Try to extract JSON from the response (in case there's extra text)
                # Look for JSON object pattern
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(0)
                
                # Clean up common issues
                response_text = response_text.strip()
                if response_text.startswith('```json'):
                    response_text = response_text[7:]
                if response_text.startswith('```'):
                    response_text = response_text[3:]
                if response_text.endswith('```'):
                    response_text = response_text[:-3]
                response_text = response_text.strip()
                
                verification_result = json.loads(response_text)
                
                # Filter findings based on verification
                verified_findings = []
                for verification in verification_result.get('verified_findings', []):
                    if verification.get('is_real_vulnerability', False):
                        original_index = verification.get('original_index', -1)
                        if 0 <= original_index < len(initial_result['findings']):
                            finding = initial_result['findings'][original_index].copy()
                            # Adjust confidence based on verification
                            original_confidence = finding.get('confidence', 50)
                            verification_confidence = verification.get('verification_confidence', 50)
                            finding['confidence'] = min(original_confidence, verification_confidence)
                            finding['verification_note'] = verification.get('reason', '')
                            verified_findings.append(finding)
                
                # Create the final result
                final_result = {
                    "confidence_score": max([f['confidence'] for f in verified_findings]) if verified_findings else 100,
                    "has_vulnerabilities": len(verified_findings) > 0,
                    "findings": verified_findings,
                    "summary": f"After verification: {len(verified_findings)} confirmed vulnerabilities out of {len(initial_result['findings'])} initially found."
                }
                
                return final_result, cost_info
                
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                print(f"Warning: Failed to parse verification response: {str(e)}")
                if response_text and len(response_text) < 500:
                    print(f"Response text was: {response_text}")
                elif response_text:
                    print(f"Response text (first 500 chars): {response_text[:500]}")
                # If verification fails, return original findings but with reduced confidence
                reduced_findings = []
                for finding in initial_result['findings']:
                    reduced_finding = finding.copy()
                    reduced_finding['confidence'] = max(30, finding.get('confidence', 50) - 20)
                    reduced_findings.append(reduced_finding)
                
                return {
                    "confidence_score": max([f['confidence'] for f in reduced_findings]) if reduced_findings else 100,
                    "has_vulnerabilities": len(reduced_findings) > 0,
                    "findings": reduced_findings,
                    "summary": initial_result.get('summary', '') + " (Verification partially failed, confidence reduced)"
                }, cost_info
                
        except Exception as e:
            print(f"Error during verification: {str(e)}")
            # Return original result if verification completely fails
            return initial_result, CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
        
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes using Claude with double-check verification for findings.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional context from vulnerability documentation
            
        Returns:
            Tuple containing:
            - Dict: Security analysis results (verified if vulnerabilities found)
            - CostInfo: Total cost information for all requests
        """
        try:
            # First analysis
            system_prompt = agent_config.get('prompts', 'system_prompts', 'default')
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[{
                    "role": "user",
                    "content": self.get_security_prompt(code_changes, context)
                }]
            )
            
            # Extract token usage and calculate cost for initial analysis
            usage = response.usage
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
            initial_cost = self.calculate_cost(input_tokens, output_tokens, self.model)
            
            initial_cost_info = CostInfo(
                total_cost=initial_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=self.model,
                provider=self.get_provider_name()
            )
            
            try:
                # Parse Claude's response
                if not response.content or not hasattr(response.content[0], 'text'):
                    raise ValueError("Invalid response format")
                
                initial_result = json.loads(response.content[0].text.strip())
                initial_result = self.validate_response(initial_result)
                
                # If vulnerabilities were found, verify them
                if initial_result.get('has_vulnerabilities', False):
                    print(f"Initial analysis found {len(initial_result.get('findings', []))} potential vulnerabilities. Performing verification...")
                    verified_result, verification_cost_info = self.verify_findings(code_changes, initial_result)
                    
                    # Combine costs
                    total_cost_info = CostInfo(
                        total_cost=initial_cost_info.total_cost + verification_cost_info.total_cost,
                        input_tokens=initial_cost_info.input_tokens + verification_cost_info.input_tokens,
                        output_tokens=initial_cost_info.output_tokens + verification_cost_info.output_tokens,
                        model=self.model,
                        provider=self.get_provider_name()
                    )
                    
                    return verified_result, total_cost_info
                else:
                    # No vulnerabilities found, no need to verify
                    return initial_result, initial_cost_info
                    
            except (json.JSONDecodeError, IndexError, ValueError, AttributeError) as e:
                print(f"Warning: Failed to parse Claude's response as JSON:\n{response.content}")
                print(f"Error: {str(e)}")
                return {
                    "confidence_score": 0,
                    "has_vulnerabilities": False,
                    "findings": [],
                    "summary": "Failed to analyze security implications"
                }, initial_cost_info
                
        except Exception as e:
            print(f"Error during Claude analysis: {str(e)}")
            # Return zero cost info for failed requests
            zero_cost = CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
            return {
                "confidence_score": 0,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": f"Analysis failed: {str(e)}"
            }, zero_cost
