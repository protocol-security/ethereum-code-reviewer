"""
Voyage AI vector store for repository-specific document management.
"""

import os
import logging
from typing import List, Dict, Optional, Any
import voyageai
from pathlib import Path
import PyPDF2

logger = logging.getLogger(__name__)


class VoyageVectorStore:
    """Manages document storage and retrieval using Voyage AI embeddings."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Voyage vector store.
        
        Args:
            api_key: Voyage AI API key. If None, will use VOYAGE_API_KEY env var
        """
        self.api_key = api_key or os.getenv('VOYAGE_API_KEY')
        if not self.api_key:
            raise ValueError("Voyage AI API key not provided. Set VOYAGE_API_KEY environment variable.")
        
        self.client = voyageai.Client(api_key=self.api_key)
        self.model = "voyage-code-3"  # Optimized for code
        
    def extract_text_from_pdf(self, file_path: str) -> str:
        """
        Extract text from a PDF file.
        
        Args:
            file_path: Path to the PDF file
            
        Returns:
            str: Extracted text content
        """
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = []
                for page in pdf_reader.pages:
                    text.append(page.extract_text())
                return '\n'.join(text)
        except Exception as e:
            logger.error(f"Failed to extract text from PDF {file_path}: {e}")
            raise
    
    def read_file_content(self, file_path: str) -> str:
        """
        Read content from a file (supports .txt, .md, .pdf).
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: File content
        """
        file_path_obj = Path(file_path)
        suffix = file_path_obj.suffix.lower()
        
        if suffix == '.pdf':
            return self.extract_text_from_pdf(file_path)
        elif suffix in ['.txt', '.md', '.markdown']:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            raise ValueError(f"Unsupported file type: {suffix}")
    
    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for text using Voyage AI.
        
        Args:
            text: Text to embed
            
        Returns:
            List[float]: Embedding vector
        """
        try:
            result = self.client.embed(
                texts=[text],
                model=self.model,
                input_type="document"
            )
            return result.embeddings[0]
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            raise
    
    def generate_query_embedding(self, query: str) -> List[float]:
        """
        Generate embedding for a query using Voyage AI.
        
        Args:
            query: Query text to embed
            
        Returns:
            List[float]: Embedding vector
        """
        try:
            result = self.client.embed(
                texts=[query],
                model=self.model,
                input_type="query"
            )
            return result.embeddings[0]
        except Exception as e:
            logger.error(f"Failed to generate query embedding: {e}")
            raise
    
    def calculate_similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """
        Calculate cosine similarity between two embeddings.
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
            
        Returns:
            float: Cosine similarity score (0-1)
        """
        import numpy as np
        
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)
        
        # Normalize vectors
        vec1_norm = vec1 / np.linalg.norm(vec1)
        vec2_norm = vec2 / np.linalg.norm(vec2)
        
        # Calculate cosine similarity
        similarity = np.dot(vec1_norm, vec2_norm)
        
        return float(similarity)
    
    def search_similar_documents(
        self,
        query_text: str,
        document_embeddings: List[Dict[str, Any]],
        top_k: int = 3,
        min_similarity: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Search for similar documents based on query text.
        
        Args:
            query_text: Query text to search for
            document_embeddings: List of documents with embeddings
                Each dict should have: {'id', 'filename', 'embedding', 'content'}
            top_k: Number of top results to return
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of relevant documents with similarity scores
        """
        if not document_embeddings:
            return []
        
        # Generate query embedding
        query_embedding = self.generate_query_embedding(query_text)
        
        # Calculate similarities
        results = []
        for doc in document_embeddings:
            similarity = self.calculate_similarity(query_embedding, doc['embedding'])
            
            if similarity >= min_similarity:
                results.append({
                    'id': doc['id'],
                    'filename': doc['filename'],
                    'content': doc.get('content', ''),
                    'similarity': similarity
                })
        
        # Sort by similarity and return top_k
        results.sort(key=lambda x: x['similarity'], reverse=True)
        return results[:top_k]
    
    def format_context_for_llm(self, relevant_docs: List[Dict[str, Any]]) -> str:
        """
        Format relevant documents into context for LLM.
        
        Args:
            relevant_docs: List of relevant documents with content and similarity
            
        Returns:
            str: Formatted context string
        """
        if not relevant_docs:
            return ""
        
        context_parts = []
        context_parts.append("# Relevant Documentation Context\n")
        
        for i, doc in enumerate(relevant_docs, 1):
            context_parts.append(f"\n## Document {i}: {doc['filename']} (Similarity: {doc['similarity']:.2f})\n")
            context_parts.append(doc['content'])
            context_parts.append("\n" + "-" * 80 + "\n")
        
        return '\n'.join(context_parts)


def get_voyage_vector_store() -> Optional[VoyageVectorStore]:
    """
    Get a VoyageVectorStore instance if API key is available.
    
    Returns:
        VoyageVectorStore instance or None if API key not available
    """
    try:
        return VoyageVectorStore()
    except ValueError as e:
        logger.warning(f"Voyage AI not available: {e}")
        return None
