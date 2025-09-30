"""
Multi-LLM judge system with weighted voting.
"""

import json
from typing import Dict, Tuple, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import LLMProvider, CostInfo
from .anthropic import ClaudeProvider
from .openai import GPTProvider
from .gemini import GeminiProvider
from .deepseek import DeepseekProvider
from .llama import LlamaProvider
from ..config_loader import agent_config


class MultiJudgeProvider(LLMProvider):
    """Multi-LLM judge system that uses weighted voting to determine vulnerabilities."""
    
    # Default weights for each provider
    DEFAULT_WEIGHTS = {
        'anthropic': 1.0,
        'gemini': 0.1,
        'openai': 0.1,
        'deepseek': 0.1,
        'llama': 0.1
    }
    
    def __init__(self, api_keys: Dict[str, str], **kwargs):
        """
        Initialize the multi-judge provider.
        
        Args:
            api_keys: Dictionary mapping provider names to API keys
                     e.g., {'anthropic': 'key1', 'openai': 'key2', 'gemini': 'key3'}
            **kwargs: Additional configuration options
                - weights: Custom weights for providers (default: DEFAULT_WEIGHTS)
                - threshold: Weighted vote threshold for vulnerability detection (default: 0.5)
                - parallel: Whether to run analyses in parallel (default: True)
                - models: Dict of model names for each provider
        """
        self.api_keys = api_keys
        self.weights = kwargs.get('weights', self.DEFAULT_WEIGHTS.copy())
        self.threshold = kwargs.get('threshold', 0.5)  # 50% of total weight
        self.parallel = kwargs.get('parallel', True)
        self.models = kwargs.get('models', {})
        
        # Initialize providers
        self.providers = {}
        provider_classes = {
            'anthropic': ClaudeProvider,
            'openai': GPTProvider,
            'gemini': GeminiProvider,
            'deepseek': DeepseekProvider,
            'llama': LlamaProvider
        }
        
        for provider_name, api_key in api_keys.items():
            if provider_name in provider_classes and api_key:
                provider_kwargs = {}
                if provider_name in self.models:
                    provider_kwargs['model'] = self.models[provider_name]
                self.providers[provider_name] = provider_classes[provider_name](api_key, **provider_kwargs)
        
        # Calculate total weight
        self.total_weight = sum(self.weights.get(p, 0) for p in self.providers)
        
        # Ensure we have Anthropic for synthesis
        if 'anthropic' not in self.providers:
            raise ValueError("Anthropic provider is required for report synthesis")
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, model: str) -> float:
        """Not used directly - costs are tracked per provider."""
        return 0.0
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "multi-judge"
    
    def _run_single_analysis(self, provider_name: str, provider: LLMProvider, code_changes: str, context: str) -> Tuple[str, Dict, CostInfo]:
        """Run analysis with a single provider."""
        try:
            print(f"Running analysis with {provider_name}...")
            result, cost_info = provider.analyze_security(code_changes, context)
            return provider_name, result, cost_info
        except Exception as e:
            print(f"Error running {provider_name} analysis: {str(e)}")
            return provider_name, {
                "confidence_score": 0,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": f"Analysis failed: {str(e)}"
            }, CostInfo(0.0, 0, 0, "unknown", provider_name)
    
    def _synthesize_report(self, all_results: Dict[str, Dict], vote_result: Dict, code_changes: str) -> Tuple[Dict, CostInfo]:
        """Use Anthropic to synthesize a combined report from all analyses."""
        anthropic = self.providers['anthropic']
        
        # Load synthesis intro from agent configuration
        synthesis_intro = agent_config.get('prompts', 'synthesis', 'intro')
        
        # Create a synthesis prompt
        synthesis_prompt = f"""{synthesis_intro}

Multiple AI models have analyzed the following code changes:

{code_changes}

Here are their individual analyses:

"""
        
        for provider_name, result in all_results.items():
            weight = self.weights.get(provider_name, 0)
            synthesis_prompt += f"\n{provider_name.upper()} Analysis (weight: {weight}):\n"
            synthesis_prompt += f"- Detected vulnerabilities: {'Yes' if result['has_vulnerabilities'] else 'No'}\n"
            synthesis_prompt += f"- Confidence: {result['confidence_score']}%\n"
            synthesis_prompt += f"- Summary: {result['summary']}\n"
            
            if result['findings']:
                synthesis_prompt += "- Findings:\n"
                for finding in result['findings']:
                    synthesis_prompt += f"  * {finding['severity']}: {finding['description']}\n"
        
        synthesis_instruction = agent_config.get('prompts', 'synthesis', 'instruction')
        
        synthesis_prompt += f"""

Based on weighted voting (threshold: {self.threshold * self.total_weight:.2f}/{self.total_weight:.2f}):
- Total weighted vote: {vote_result['weighted_score']:.2f}
- Consensus: {'Vulnerabilities detected' if vote_result['has_vulnerabilities'] else 'No vulnerabilities detected'}

{synthesis_instruction}

CRITICAL: Your response must be ONLY the following JSON object, with no additional text, explanation, or markdown formatting:
{{
    "confidence_score": <overall confidence based on the analyses>,
    "has_vulnerabilities": {str(vote_result['has_vulnerabilities']).lower()},
    "findings": [
        {{
            "severity": "<HIGH|MEDIUM|LOW>",
            "description": "<specific vulnerability with exact code location>",
            "recommendation": "<precise fix required>",
            "confidence": <0-100>,
            "detailed_explanation": "<comprehensive explanation>",
            "impact_explanation": "<impact if exploited>",
            "detailed_recommendation": "<detailed fix explanation>",
            "code_example": "<the existing problematic code block, with proposed changes highlighted using html-style comments>",
            "additional_resources": "<links to documentation>"
        }}
    ],
    "summary": "<synthesized summary incorporating insights from all models>"
}}
"""
        
        try:
            # Use a fresh Claude instance for synthesis to avoid token limit issues
            system_prompt = agent_config.get('prompts', 'system_prompts', 'synthesize')
            
            response = anthropic.client.messages.create(
                model=anthropic.model,
                max_tokens=anthropic.max_tokens,
                temperature=0,
                system=system_prompt,
                messages=[{
                    "role": "user",
                    "content": synthesis_prompt
                }]
            )
            
            # Extract token usage and calculate cost
            usage = response.usage
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
            total_cost = anthropic.calculate_cost(input_tokens, output_tokens, anthropic.model)
            
            cost_info = CostInfo(
                total_cost=total_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model=anthropic.model,
                provider="anthropic (synthesis)"
            )
            
            # Parse response
            result = json.loads(response.content[0].text.strip())
            return anthropic.validate_response(result), cost_info
            
        except Exception as e:
            print(f"Error during synthesis: {str(e)}")
            # Fallback to the best individual result
            best_result = max(all_results.items(), key=lambda x: x[1]['confidence_score'] if x[1]['has_vulnerabilities'] else 0)
            return best_result[1], CostInfo(0.0, 0, 0, "fallback", "multi-judge")
    
    def analyze_security(self, code_changes: str, context: str = "") -> Tuple[Dict, CostInfo]:
        """
        Analyze code changes using multiple LLMs with weighted voting.
        
        Args:
            code_changes: String containing the code changes to analyze
            context: Optional historical vulnerability context
            
        Returns:
            Tuple containing:
            - Dict: Synthesized security analysis results
            - CostInfo: Combined cost information for all requests
        """
        all_results = {}
        all_costs = []
        provider_costs = {}  # Track costs per provider
        
        if self.parallel:
            # Run analyses in parallel
            with ThreadPoolExecutor(max_workers=len(self.providers)) as executor:
                future_to_provider = {
                    executor.submit(self._run_single_analysis, name, provider, code_changes, context): name
                    for name, provider in self.providers.items()
                }
                
                for future in as_completed(future_to_provider):
                    provider_name, result, cost_info = future.result()
                    all_results[provider_name] = result
                    all_costs.append(cost_info)
                    provider_costs[provider_name] = cost_info
        else:
            # Run analyses sequentially
            for provider_name, provider in self.providers.items():
                _, result, cost_info = self._run_single_analysis(provider_name, provider, code_changes, context)
                all_results[provider_name] = result
                all_costs.append(cost_info)
                provider_costs[provider_name] = cost_info
        
        # Print multi-judge header
        print(f"\n{'='*60}")
        print("🤖 MULTI-JUDGE SECURITY ANALYSIS")
        print(f"{'='*60}")
        print(f"Using {len(self.providers)} LLM judges with weighted voting:")
        for provider_name in self.providers:
            weight = self.weights.get(provider_name, 0)
            print(f"  • {provider_name.capitalize()}: weight {weight}")
        print(f"\nThreshold for vulnerability detection: {self.threshold * 100}% of total weight")
        print(f"{'='*60}\n")
        
        # Calculate weighted vote and show individual results
        print("Individual LLM Results:")
        print("-" * 60)
        weighted_score = 0.0
        for provider_name, result in all_results.items():
            weight = self.weights.get(provider_name, 0)
            print(f"\n{provider_name.upper()}:")
            print(f"  • Vulnerabilities detected: {'YES' if result['has_vulnerabilities'] else 'NO'}")
            print(f"  • Confidence: {result['confidence_score']}%")
            print(f"  • Weight: {weight}")
            
            if result['has_vulnerabilities']:
                weighted_score += weight
                print(f"  • Vote contribution: +{weight} (voted YES)")
                # Show summary of findings
                if result['findings']:
                    print(f"  • Found {len(result['findings'])} issue(s):")
                    severity_counts = {}
                    for finding in result['findings']:
                        severity = finding.get('severity', 'UNKNOWN')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    for severity, count in severity_counts.items():
                        print(f"    - {count} {severity} severity")
            else:
                print(f"  • Vote contribution: 0 (voted NO)")
            
            # Show first line of summary
            summary_lines = result.get('summary', '').split('\n')
            if summary_lines and summary_lines[0]:
                print(f"  • Summary: {summary_lines[0][:100]}{'...' if len(summary_lines[0]) > 100 else ''}")
        
        # Determine if vulnerabilities exist based on weighted vote
        vote_threshold = self.threshold * self.total_weight
        has_vulnerabilities = weighted_score >= vote_threshold
        
        print(f"\n{'-'*60}")
        print("Weighted Voting Results:")
        print(f"  • Total weighted vote: {weighted_score:.2f}/{self.total_weight:.2f}")
        print(f"  • Required threshold: {vote_threshold:.2f} ({self.threshold * 100}% of {self.total_weight:.2f})")
        print(f"  • Consensus decision: {'VULNERABILITIES DETECTED ⚠️' if has_vulnerabilities else 'NO VULNERABILITIES FOUND ✅'}")
        print(f"{'='*60}\n")
        
        vote_result = {
            'weighted_score': weighted_score,
            'total_weight': self.total_weight,
            'threshold': vote_threshold,
            'has_vulnerabilities': has_vulnerabilities
        }
        
        # If vulnerabilities detected, synthesize report
        if has_vulnerabilities:
            synthesized_result, synthesis_cost = self._synthesize_report(all_results, vote_result, code_changes)
            all_costs.append(synthesis_cost)
        else:
            # No vulnerabilities - return standard response
            synthesized_result = {
                "confidence_score": 100,
                "has_vulnerabilities": False,
                "findings": [],
                "summary": "No concrete vulnerabilities identified in the changed code by consensus of multiple AI models."
            }
        
        # Add multi-judge voting details to the result
        synthesized_result['multi_judge_details'] = {
            'enabled': True,
            'providers': list(self.providers.keys()),
            'weights': self.weights,
            'threshold': self.threshold,
            'total_weight': self.total_weight,
            'vote_threshold': vote_threshold,
            'weighted_score': weighted_score,
            'has_vulnerabilities': has_vulnerabilities,
            'individual_results': {
                provider: {
                    'has_vulnerabilities': result['has_vulnerabilities'],
                    'confidence_score': result['confidence_score'],
                    'summary': result['summary'].split('\n')[0][:200] + '...' if len(result['summary']) > 200 else result['summary'],
                    'findings_count': len(result.get('findings', [])),
                    'findings_severity': {
                        severity: sum(1 for f in result.get('findings', []) if f.get('severity') == severity)
                        for severity in ['HIGH', 'MEDIUM', 'LOW']
                    } if result.get('findings') else {},
                    'cost': provider_costs.get(provider).total_cost if provider in provider_costs else 0.0
                }
                for provider, result in all_results.items()
            }
        }
        
        # Combine all costs
        total_cost = sum(c.total_cost for c in all_costs)
        total_input_tokens = sum(c.input_tokens for c in all_costs)
        total_output_tokens = sum(c.output_tokens for c in all_costs)
        
        combined_cost = CostInfo(
            total_cost=total_cost,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            model="multi-judge",
            provider=f"multi-judge ({len(self.providers)} providers)"
        )
        
        return synthesized_result, combined_cost
