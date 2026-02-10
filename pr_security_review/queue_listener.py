"""
Queue listener module for processing security analysis requests via RabbitMQ/AMQP.
"""

import json
import os
import sys
import time
import traceback
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlparse

import pika
import pika.exceptions


class QueueListener:
    """Handles RabbitMQ/AMQP queue listening and message processing for security analysis."""
    
    def __init__(self, amqp_url: str, queue_name: str, response_queue_name: str = None):
        """
        Initialize the queue listener.
        
        Args:
            amqp_url: AMQP connection URL (e.g., amqps://user:pass@host/vhost)
            queue_name: Name of the queue to listen to
            response_queue_name: Name of the queue to send responses to (defaults to {queue_name}_response)
        """
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self.response_queue_name = response_queue_name or f"{queue_name}_response"
        self.connection = None
        self.channel = None
        self.security_reviewer = None
        
    def connect(self):
        """Establish connection to RabbitMQ."""
        try:
            # Parse the AMQP URL and create connection parameters
            params = pika.URLParameters(self.amqp_url)
            
            # Establish connection
            self.connection = pika.BlockingConnection(params)
            self.channel = self.connection.channel()
            
            # Declare the queues (they will be created if they don't exist)
            self.channel.queue_declare(queue=self.queue_name, durable=True)
            self.channel.queue_declare(queue=self.response_queue_name, durable=True)
            
            # Set QoS to process one message at a time
            self.channel.basic_qos(prefetch_count=1)
            
            print(f"✅ Connected to RabbitMQ")
            print(f"📥 Listening on queue: {self.queue_name}")
            print(f"📤 Response queue: {self.response_queue_name}")
            
        except Exception as e:
            print(f"❌ Failed to connect to RabbitMQ: {str(e)}")
            raise
            
    def disconnect(self):
        """Close the RabbitMQ connection."""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            print("🔌 Disconnected from RabbitMQ")
            
    def set_security_reviewer(self, reviewer):
        """
        Set the security reviewer instance to use for analysis.
        
        Args:
            reviewer: SecurityReview instance
        """
        self.security_reviewer = reviewer
        
    def process_message(self, ch, method, properties, body):
        """
        Process an incoming message from the queue.
        
        Args:
            ch: Channel
            method: Method frame
            properties: Properties
            body: Message body
        """
        try:
            # Parse the incoming message
            raw_message = json.loads(body.decode('utf-8'))
            
            # Handle nested message structure
            if 'message' in raw_message:
                message = raw_message['message']
                # Type might be at the root level
                if 'type' not in message and 'type' in raw_message:
                    message['type'] = raw_message['type']
            else:
                message = raw_message
            
            # Check message type first - only process GitHubPullRequest or GitHubPush
            message_type = message.get('type')
            if message_type not in ['GitHubPullRequest', 'GitHubPush']:
                # Not our message type - reject but requeue for other processes
                print(f"\n⏭️ Skipping message with type '{message_type}' (not GitHubPullRequest or GitHubPush)")
                print(f"  Message will remain in queue for other processes")
                # Reject the message and requeue it
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                return
            
            print(f"\n📨 Received message:")
            print(f"  Type: {message_type}")
            print(f"  Organization ID: {message.get('oId')}")
            print(f"  Repository ID: {message.get('repoId')}")
            print(f"  PR ID: {message.get('prId', 'N/A')}")
            print(f"  Head Sha: {message.get('headSha', 'N/A')}")
            print(f"  Base Sha: {message.get('baseSha', 'N/A')}")
            print(f"  Available Tokens: {message.get('availableTokens')}")
            
            # Validate required fields (prId and headSha are optional, but at least one should be present)
            required_fields = ['oId', 'repoId', 'content', 'type']
            missing_fields = [field for field in required_fields if field not in message]
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
            
            # At least one of prId or headSha should be present
            if 'prId' not in message and 'headSha' not in message:
                raise ValueError("Either prId or headSha must be present")
            
            # Extract fields
            oId = message['oId']
            repoId = message['repoId']
            content = message['content']
            availableTokens = message.get('availableTokens', 100000)  # Default if not provided
            baseSha = message.get('baseSha')  # Optional
            headSha = message.get('headSha')  # Optional
            prId = message.get('prId')  # Optional

            # Analyze the content
            print(f"🔍 Analyzing content ({len(content)} characters)...")
            
            if not self.security_reviewer:
                raise RuntimeError("Security reviewer not initialized")
            
            # Track time for analysis
            start_time = time.time()
            
            # Perform security analysis
            analysis, cost_info = self.security_reviewer.analyze_security(content)
            
            # Calculate time spent in seconds
            end_time = time.time()
            timeSpent = int(end_time - start_time)
            
            # Calculate token cost
            tokensUsed = 0
            if cost_info:
                total_tokens = cost_info.input_tokens + cost_info.output_tokens
                print(f"💰 Token usage: {total_tokens} tokens (${cost_info.total_cost:.4f})")
            
            # Check if we exceeded token budget
            if tokensUsed > availableTokens:
                print(f"⚠️ Warning: Token usage ({tokensUsed}) exceeded budget ({availableTokens})")
            
            # Prepare the response message
            response_type = 'GitHubPRAnalyzeCompleted' if message_type == 'GitHubPullRequest' else 'GitHubPushAnalyzeCompleted'
            
            # Format the analysis report
            report = self._format_security_report(analysis, cost_info)
            
            response_message = {
                'oId': oId,
                'repoId': repoId,
                'content': report,
                'tokenCost': total_tokens,
                'timeSpent': timeSpent,
                'type': response_type,
                'hasVulnerabilities': analysis.get('has_vulnerabilities', False),
                'confidenceScore': analysis.get('confidence_score', 0),
                'summary': analysis.get('summary', '')
            }
            
            # Include prId or headSha based on what was provided
            if prId is not None:
                response_message['prId'] = prId
            if headSha is not None:
                response_message['headSha'] = headSha
            if baseSha is not None:
                response_message['baseSha'] = baseSha

            # Send response to the response queue
            self.channel.basic_publish(
                exchange='',
                routing_key=self.response_queue_name,
                body=json.dumps(response_message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    content_type='application/json'
                )
            )
            
            print(f"✅ Sent response to queue: {self.response_queue_name}")
            print(f"  Response type: {response_type}")
            print(f"  Vulnerabilities found: {'Yes' if analysis.get('has_vulnerabilities') else 'No'}")
            print(f"  Time spent: {timeSpent} seconds")
            
            # Acknowledge the message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            print(f"✅ Message acknowledged")
            
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON message: {str(e)}")
            # Reject the message and don't requeue (message is malformed)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            
        except ValueError as e:
            print(f"❌ Invalid message format: {str(e)}")
            # Reject the message and don't requeue (message is invalid)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            
        except Exception as e:
            print(f"❌ Error processing message: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            
            # Send error response if possible
            try:
                if 'message' in locals():
                    error_response = {
                        'oId': message.get('oId'),
                        'repoId': message.get('repoId'),
                        'content': f"Error during security analysis: {str(e)}",
                        'tokenCost': 0,
                        'type': 'GitHubAnalysisError',
                        'error': str(e)
                    }
                    
                    # Include prId or headSha if they were present
                    if message.get('prId') is not None:
                        error_response['prId'] = message.get('prId')
                    if message.get('headSha') is not None:
                        error_response['headSha'] = message.get('headSha')
                    if message.get('baseSha') is not None:
                        error_response['baseSha'] = message.get('baseSha')
                    
                    self.channel.basic_publish(
                        exchange='',
                        routing_key=self.response_queue_name,
                        body=json.dumps(error_response),
                        properties=pika.BasicProperties(
                            delivery_mode=2,
                            content_type='application/json'
                        )
                    )
            except:
                pass  # Best effort error reporting
            
            # Reject and requeue the message (might be a temporary error)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            
    def _format_security_report(self, analysis: Dict, cost_info: Any) -> str:
        """
        Format the security analysis results into a report string.
        
        Args:
            analysis: Security analysis results
            cost_info: Cost information
            
        Returns:
            Formatted report string
        """
        report = f"""## Security Analysis Report

### Summary
{analysis.get('summary', 'No summary available')}

"""
        
        if analysis.get('findings'):
            report += "### Detailed Findings\n"
            for i, finding in enumerate(analysis['findings'], 1):
                report += f"""
#### Finding #{i}: {finding.get('severity', 'Unknown')} Severity

**Description:** {finding.get('description', 'No description')}

**Recommendation:** {finding.get('recommendation', 'No recommendation')}

**Confidence:** {finding.get('confidence', 0)}%
"""
                
                if finding.get('detailed_explanation'):
                    report += f"""
**Detailed Explanation:**
{finding['detailed_explanation']}
"""
                
                if finding.get('impact_explanation'):
                    report += f"""
**Impact:**
{finding['impact_explanation']}
"""
                
                if finding.get('detailed_recommendation'):
                    report += f"""
**Detailed Fix:**
{finding['detailed_recommendation']}
"""
                
                if finding.get('code_example'):
                    report += f"""
**Code Example:**
```
{finding['code_example']}
```
"""
                
                if finding.get('additional_resources'):
                    report += f"""
**Additional Resources:**
{finding['additional_resources']}
"""
                
                report += "\n---\n"
        else:
            report += "\n✅ No security vulnerabilities detected in the analyzed code.\n"
            
        return report
        
    def start_listening(self):
        """Start listening to the queue for messages."""
        try:
            # Set up the consumer
            self.channel.basic_consume(
                queue=self.queue_name,
                on_message_callback=self.process_message,
                auto_ack=False  # Manual acknowledgment
            )
            
            print(f"\n🎧 Listening for messages on queue '{self.queue_name}'...")
            print("Press CTRL+C to stop\n")
            
            # Start consuming messages
            self.channel.start_consuming()
            
        except KeyboardInterrupt:
            print("\n⏹️ Stopping queue listener...")
            self.channel.stop_consuming()
            self.disconnect()
            
        except Exception as e:
            print(f"❌ Error while listening: {str(e)}")
            self.disconnect()
            raise
            
    def run_with_reconnect(self, max_retries: int = 5, retry_delay: int = 5):
        """
        Run the listener with automatic reconnection on failure.
        
        Args:
            max_retries: Maximum number of reconnection attempts
            retry_delay: Delay in seconds between reconnection attempts
        """
        retries = 0
        
        while retries < max_retries:
            try:
                # Connect and start listening
                self.connect()
                self.start_listening()
                break  # Exit if stopped normally
                
            except pika.exceptions.AMQPConnectionError as e:
                retries += 1
                print(f"❌ Connection failed (attempt {retries}/{max_retries}): {str(e)}")
                
                if retries < max_retries:
                    print(f"🔄 Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    
            except Exception as e:
                print(f"❌ Unexpected error: {str(e)}")
                break
                
        if retries >= max_retries:
            print(f"❌ Failed to connect after {max_retries} attempts")
            sys.exit(1)
