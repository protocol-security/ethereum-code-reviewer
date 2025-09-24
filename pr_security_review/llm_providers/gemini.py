"""
Google Gemini provider implementation.
"""

import os
import json
import re
from typing import Dict, Tuple
import google.generativeai as genai
from .base import LLMProvider, CostInfo

class GeminiProvider(LLMProvider):
    """Gemini provider for security analysis."""
    
    def __init__(self, api_key: str, **kwargs):
        """
        Initialize the Gemini provider.
        
        Args:
            api_key: Google API key
            **kwargs: Additional configuration options
                - model: Gemini model to use (default: gemini-2.5-pro-preview-06-05)
                - max_tokens: Maximum tokens for response (default: 4096)
                - temperature: Sampling temperature (default: 0)
        """
        self.api_key = api_key
        self._client = None
        self.model = kwargs.get('model', 'gemini-2.5-pro-preview-06-05')
        self.max_tokens = kwargs.get('max_tokens', 4096)
        self.temperature = kwargs.get('temperature', 0)
        genai.configure(api_key=api_key)
        
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """
        Calculate the cost for a Gemini request.
        
        Pricing as of 2025 (per 1M tokens):
        - gemini-2.5-pro-preview-06-05: $1.25 input, $10 output

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model used for the request
            
        Returns:
            float: Total cost in USD
        """
        # Cost per 1M tokens (input, output)
        model_pricing = {
            'gemini-2.5-pro-preview-06-05': (1.25, 10),
        }
        
        # Default to gemini-2.5-pro-preview-06-05 pricing if model not found
        input_price, output_price = model_pricing.get(model, (1.25, 10))

        # Calculate cost (price is per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * input_price
        output_cost = (output_tokens / 1_000_000) * output_price
        
        return input_cost + output_cost
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "gemini"
        
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes using Gemini.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            Tuple containing:
            - Dict: Security analysis results
            - CostInfo: Cost information for the request
        """
        try:
            # Generate the model
            generation_config = {
                "temperature": self.temperature,
                "max_output_tokens": self.max_tokens,
                "response_mime_type": "application/json",
            }
            
            system_prompt = os.getenv('LLM_SYNTHESIS_SYSTEM_PROMPT')
            if not system_prompt:
                raise ValueError("LLM_SYNTHESIS_SYSTEM_PROMPT environment variable is not set.")
            
            model = genai.GenerativeModel(
                model_name=self.model,
                generation_config=generation_config,
                system_instruction=system_prompt
            )
            
            prompt = self.get_security_prompt(code_changes, context)
            response = model.generate_content(prompt)
            
            # Extract token usage - Gemini response structure is different
            input_tokens = 0
            output_tokens = 0
            
            # Try to get usage metadata if available
            if hasattr(response, 'usage_metadata'):
                usage = response.usage_metadata
                input_tokens = getattr(usage, 'prompt_token_count', 0)
                output_tokens = getattr(usage, 'candidates_token_count', 0)
            elif hasattr(response, '_result') and hasattr(response._result, 'usage_metadata'):
                # Sometimes the usage is in the internal result object
                usage = response._result.usage_metadata
                input_tokens = getattr(usage, 'prompt_token_count', 0)
                output_tokens = getattr(usage, 'candidates_token_count', 0)
            else:
                # If we can't get token counts, estimate from text length
                # Rough estimate: ~1 token per 4 characters
                input_tokens = len(prompt) // 4
                if hasattr(response, 'text'):
                    output_tokens = len(response.text) // 4
            
            # Calculate cost
            total_cost = self.calculate_cost(input_tokens, output_tokens, self.model)
            
            cost_info = CostInfo(
                total_cost=total_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=self.model,
                provider=self.get_provider_name()
            )
            
            try:
                # Check if response has valid candidates
                if not response.candidates:
                    print("Warning: Gemini returned no response candidates")
                    return {
                        "confidence_score": 0,
                        "has_vulnerabilities": False,
                        "findings": [],
                        "summary": "Gemini returned no response candidates"
                    }, cost_info
                
                # Get the first candidate
                candidate = response.candidates[0]
                
                # Check if content was blocked by safety filters
                if hasattr(candidate, 'finish_reason') and candidate.finish_reason.name == 'SAFETY':
                    print("Warning: Gemini response was blocked by safety filters")
                    if hasattr(candidate, 'safety_ratings'):
                        print(f"Safety ratings: {candidate.safety_ratings}")
                    return {
                        "confidence_score": 0,
                        "has_vulnerabilities": False,
                        "findings": [],
                        "summary": "Response blocked by Gemini safety filters"
                    }, cost_info
                
                # Check if candidate has content
                if not hasattr(candidate, 'content') or not candidate.content:
                    print("Warning: Gemini candidate has no content")
                    return {
                        "confidence_score": 0,
                        "has_vulnerabilities": False,
                        "findings": [],
                        "summary": "Gemini returned empty content"
                    }, cost_info
                
                # Extract text from content parts
                text_parts = []
                for part in candidate.content.parts:
                    if hasattr(part, 'text') and part.text:
                        text_parts.append(part.text)
                
                if not text_parts:
                    print("Warning: No text found in Gemini response parts")
                    # Debug: Print available attributes
                    try:
                        print(f"Debug: Candidate finish_reason: {candidate.finish_reason}")
                        if hasattr(candidate, 'content') and candidate.content:
                            print(f"Debug: Content parts count: {len(candidate.content.parts)}")
                            for i, part in enumerate(candidate.content.parts):
                                part_attrs = [attr for attr in dir(part) if not attr.startswith('_')]
                                print(f"Debug: Part {i} attributes: {part_attrs}")
                                if hasattr(part, 'text'):
                                    print(f"Debug: Part {i} text length: {len(part.text) if part.text else 0}")
                    except Exception as e:
                        print(f"Debug: Error while inspecting response: {e}")
                    
                    return {
                        "confidence_score": 0,
                        "has_vulnerabilities": False,
                        "findings": [],
                        "summary": "No text content in Gemini response"
                    }, cost_info
                
                # Join all text parts
                content = ''.join(text_parts).strip()
                
                # Additional validation for empty content
                if not content:
                    print("Warning: Gemini returned empty content after joining text parts")
                    return {
                        "confidence_score": 0,
                        "has_vulnerabilities": False,
                        "findings": [],
                        "summary": "Gemini returned empty response content"
                    }, cost_info
                
                # Parse response
                result = json.loads(content.strip())
                return self.validate_response(result), cost_info
                
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Warning: Failed to parse Gemini's response as JSON")
                if 'content' in locals():
                    print(f"Response content: {content}")
                print(f"Error: {str(e)}")
                return {
                    "confidence_score": 0,
                    "has_vulnerabilities": False,
                    "findings": [],
                    "summary": "Failed to parse response as valid JSON"
                }, cost_info
            except AttributeError as e:
                print(f"Warning: Unexpected Gemini response structure")
                print(f"Error: {str(e)}")
                return {
                    "confidence_score": 0,
                    "has_vulnerabilities": False,
                    "findings": [],
                    "summary": f"Unexpected response structure: {str(e)}"
                }, cost_info
        except Exception as e:
            print(f"Error during Gemini analysis: {str(e)}")
            # Return zero cost info for failed requests
            zero_cost = CostInfo(0.0, 0, 0, self.model, self.get_provider_name())
            return {
                "confidence_score": 0,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": f"Analysis failed: {str(e)}"
            }, zero_cost
