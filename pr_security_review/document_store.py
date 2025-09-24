"""
Document store for vulnerability documentation using embeddings for retrieval.
"""

import os
from typing import List, Dict, Optional
import json
from pathlib import Path
import numpy as np
from .embeddings import EmbeddingsProvider, OpenAIEmbeddings

class DocumentStore:
    """Manages storage and retrieval of vulnerability documentation."""
    
    def __init__(self, docs_dir: str, embeddings_provider: EmbeddingsProvider):
        """
        Initialize the document store.
        
        Args:
            docs_dir: Directory containing vulnerability documentation files
            embeddings_provider: Provider for generating embeddings
        """
        self.docs_dir = Path(docs_dir)
        self.embeddings_provider = embeddings_provider
        self.docs: List[Dict] = []
        self.embeddings: Optional[np.ndarray] = None
        self.embedding_file = self.docs_dir / "embeddings.npy"
        self.docs_file = self.docs_dir / "docs.json"
        
    def load_documents(self) -> None:
        """Load and process all markdown (.md) files in the docs directory."""
        if not self.docs_dir.exists():
            print(f"\n⚠️ Documentation directory not found!")
            return

        # Get current list of markdown files
        current_files = set(str(f.relative_to(self.docs_dir)) for f in self.docs_dir.glob("**/*.md"))
        
        # Check if we can use cache
        use_cache = False
        if self.docs_file.exists() and self.embedding_file.exists():
            try:
                with open(self.docs_file, 'r') as f:
                    cached_docs = json.load(f)
                cached_files = set(doc['file'] for doc in cached_docs)
                
                if current_files == cached_files:
                    print("\n📚 Loading cached vulnerability documentation...")
                    # Load cached embeddings and docs
                    try:
                        self.embeddings = np.load(str(self.embedding_file))
                        self.docs = cached_docs
                        print(f"✅ Loaded {len(self.docs)} documents from cache")
                        use_cache = True
                    except (FileNotFoundError, EOFError):
                        # If embeddings file can't be loaded, invalidate cache
                        use_cache = False
            except (FileNotFoundError, json.JSONDecodeError):
                # If docs file can't be loaded, invalidate cache
                use_cache = False
            else:
                new_files = current_files - cached_files
                removed_files = cached_files - current_files
                print("\n📚 Changes detected in documentation:")
                if new_files:
                    print("New files:")
                    for f in sorted(new_files):
                        print(f"  + {f}")
                if removed_files:
                    print("Removed files:")
                    for f in sorted(removed_files):
                        print(f"  - {f}")
                print("\nCache invalidated due to file changes, regenerating embeddings...")
                # Delete cache files to force regeneration
                try:
                    if self.embedding_file.exists():
                        self.embedding_file.unlink()
                    if self.docs_file.exists():
                        self.docs_file.unlink()
                except FileNotFoundError:
                    # Files might have been deleted between exists() check and unlink()
                    pass

        if not use_cache:
            print("\n📚 Processing vulnerability documentation...")
            # Process all markdown files in the docs directory
            docs = []
            for file in self.docs_dir.glob("**/*.md"):
                with open(file, 'r') as f:
                    content = f.read()
                    docs.append({
                        "content": content,
                        "file": str(file.relative_to(self.docs_dir))
                    })
                print(f"📄 Loaded {file.name}")
            
            if not docs:
                print("⚠️ No documentation files found")
                print("\nDirectory contents:")
                for file in self.docs_dir.rglob("*"):
                    rel_path = file.relative_to(self.docs_dir)
                    prefix = "  " * (len(rel_path.parts) - 1)
                    print(f"{prefix}- {file.name}")
                return
                
            print("\nGenerating embeddings...")
            # Generate embeddings for all docs
            embeddings = []
            for i, doc in enumerate(docs, 1):
                print(f"⏳ Processing document {i}/{len(docs)}: {doc['file']}")
                embedding = self.embeddings_provider.get_embedding(doc["content"])
                if hasattr(self.embeddings_provider, 'normalize_embedding'):
                    embedding = self.embeddings_provider.normalize_embedding(embedding)
                embeddings.append(embedding)
            
            self.docs = docs
            self.embeddings = np.array(embeddings)
            
            # Cache the results
            print("\n💾 Caching embeddings for future use...")
            np.save(str(self.embedding_file), self.embeddings)
            with open(self.docs_file, 'w') as f:
                json.dump(self.docs, f)
            print("✅ Embeddings cached successfully")
                
    def get_relevant_context(self, code_changes: str, max_docs: int = 3) -> str:
        """
        Find relevant vulnerability documentation for the given code changes.
        
        Args:
            code_changes: The code changes to find context for
            max_docs: Maximum number of relevant documents to return
            
        Returns:
            str: Concatenated relevant documentation
        """
        if not self.docs or self.embeddings is None:
            return ""
            
        print("\nFinding relevant vulnerability context...")
        #print("\nCode changes to match:")
        #print(code_changes)
        # Get embedding for the code changes
        query_embedding = self.embeddings_provider.get_embedding(code_changes)
        if hasattr(self.embeddings_provider, 'normalize_embedding'):
            query_embedding = self.embeddings_provider.normalize_embedding(query_embedding)
        query_embedding = np.array(query_embedding)
        
        # Calculate cosine similarity with all docs
        # Since vectors are normalized, dot product equals cosine similarity
        similarities = np.dot(self.embeddings, query_embedding)

        print("\nDocument similarities (sorted):")
        sorted_indices = np.argsort(similarities)[::-1]
        for i in sorted_indices:
            print(f"  {self.docs[i]['file']}: {similarities[i]:.2f}")
        
        # Get the most relevant docs (using already sorted indices)
        most_relevant = sorted_indices[:max_docs]
        
        # Combine the relevant docs into context
        context = []
        relevant_count = 0
        for idx in most_relevant:
            if similarities[idx] > 0.5:  # How similar the doc is to the code changes
                doc = self.docs[idx]
                context.append(f"From {doc['file']}:\n{doc['content']}\n")
                print(f"📄 Using {doc['file']} (similarity: {similarities[idx]:.2f})")
                relevant_count += 1
        
        if relevant_count > 0:
            print(f"✅ Found {relevant_count} relevant document(s)")
        else:
            print("ℹ️ No highly relevant documentation found")
                
        return "\n".join(context)
