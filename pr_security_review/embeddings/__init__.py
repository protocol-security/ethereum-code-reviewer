"""
Embeddings providers for document retrieval.
"""

from abc import ABC, abstractmethod
import numpy as np
from typing import List
from openai import OpenAI
import requests

class EmbeddingsProvider(ABC):
    """Abstract base class for embeddings providers."""
    
    @abstractmethod
    def get_embedding(self, text: str) -> List[float]:
        """Get embedding for a text string."""
        pass

class OpenAIEmbeddings(EmbeddingsProvider):
    """OpenAI embeddings provider."""
    
    def __init__(self, api_key: str):
        """Initialize the OpenAI embeddings provider."""
        self.api_key = api_key
        self._client = None
        
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
        
    def get_embedding(self, text: str) -> List[float]:
        """Get embedding for text using OpenAI API."""
        response = self.client.embeddings.create(
            model="text-embedding-3-small",
            input=text
        )
        return response.data[0].embedding

    def normalize_embedding(self, embedding: List[float]) -> List[float]:
        """Normalize an embedding vector."""
        norm = np.linalg.norm(embedding)
        return [x/norm for x in embedding] if norm > 0 else embedding

class VoyageEmbeddings(EmbeddingsProvider):
    """Voyage AI embeddings provider, required when using Claude together with docs-dir."""
    
    def __init__(self, api_key: str, model: str = "voyage-3-large"):
        """
        Initialize the Voyage embeddings provider.
        
        Args:
            api_key: Voyage AI API key
            model: Model to use (default: voyage-3-large)
        """
        self.api_key = api_key
        self.model = model
        self.api_url = "https://api.voyageai.com/v1/embeddings"
        
    def get_embedding(self, text: str) -> List[float]:
        """Get embedding for a text string."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "input": text
        }
        
        response = requests.post(self.api_url, headers=headers, json=data)
        response.raise_for_status()
        
        return response.json()["data"][0]["embedding"]
