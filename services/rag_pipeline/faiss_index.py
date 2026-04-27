# services/rag_pipeline/faiss_index.py
"""
FAISS vector index builder and manager.

Builds and maintains IndexFlatIP (inner product) for semantic similarity
retrieval over threat intelligence documents (CVE descriptions, ATT&CK techniques, etc.)

Uses sentence-transformers/all-MiniLM-L6-v2 for 384-dimensional embeddings.
"""

import json
import os
from typing import Dict, List, Optional, Tuple

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


class FAISSIndex:
    """
    FAISS vector index for threat intelligence retrieval.
    """

    EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
    EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 output dimension
    INDEX_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss_indexes")

    def __init__(self):
        """Initialize FAISS index and embedding model."""
        self.embedding_model = SentenceTransformer(self.EMBEDDING_MODEL)
        self.index: Optional[faiss.IndexFlatIP] = None
        self.documents: List[Dict[str, str]] = []  # Metadata for each indexed document
        self._ensure_index_dir()

    def _ensure_index_dir(self):
        """Ensure index directory exists."""
        os.makedirs(self.INDEX_PATH, exist_ok=True)

    def build_index(self, documents: List[Dict[str, str]]) -> bool:
        """
        Build FAISS index from documents.

        Args:
            documents: List of {"id": str, "text": str, "source": str} dicts

        Returns:
            True if successful
        """
        try:
            # Generate embeddings
            texts = [doc["text"] for doc in documents]
            embeddings = self.embedding_model.encode(texts, convert_to_numpy=True)

            # Normalize for inner product (IP) similarity
            embeddings = embeddings / (
                np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-8
            )

            # Create index
            self.index = faiss.IndexFlatIP(self.EMBEDDING_DIM)
            self.index.add(embeddings.astype(np.float32))

            # Store documents
            self.documents = documents

            # Persist
            self._save_index()
            self._save_metadata()

            return True

        except Exception as e:
            print(f"Index build failed: {e}")
            return False

    def search(
        self, query: str, k: int = 5, use_mmr: bool = True
    ) -> List[Tuple[str, float]]:
        """
        Search for similar documents.

        Args:
            query: Search query text
            k: Number of results
            use_mmr: Use Maximal Marginal Relevance to reduce redundancy

        Returns:
            List of (document_id, similarity_score) tuples
        """
        if not self.index or not self.documents:
            return []

        try:
            # Embed query
            query_embedding = self.embedding_model.encode(
                [query], convert_to_numpy=True
            )
            query_embedding = query_embedding / (
                np.linalg.norm(query_embedding, axis=1, keepdims=True) + 1e-8
            )

            # Search
            distances, indices = self.index.search(
                query_embedding.astype(np.float32), k
            )

            # Map indices to document IDs
            results = [
                (self.documents[idx]["id"], float(dist))
                for idx, dist in zip(indices[0], distances[0])
                if idx < len(self.documents)
            ]

            return results

        except Exception as e:
            print(f"Search failed: {e}")
            return []

    def load_index(self, index_name: str = "threat_intel") -> bool:
        """
        Load persisted FAISS index.

        Args:
            index_name: Index file name (without extension)

        Returns:
            True if successful
        """
        try:
            index_path = os.path.join(self.INDEX_PATH, f"{index_name}.index")
            metadata_path = os.path.join(self.INDEX_PATH, f"{index_name}.json")

            if not os.path.exists(index_path):
                return False

            self.index = faiss.read_index(index_path)

            with open(metadata_path, "r") as f:
                self.documents = json.load(f)

            return True

        except Exception as e:
            print(f"Index load failed: {e}")
            return False

    def _save_index(self, index_name: str = "threat_intel"):
        """Save FAISS index to disk."""
        index_path = os.path.join(self.INDEX_PATH, f"{index_name}.index")
        faiss.write_index(self.index, index_path)

    def _save_metadata(self, index_name: str = "threat_intel"):
        """Save document metadata to JSON."""
        metadata_path = os.path.join(self.INDEX_PATH, f"{index_name}.json")
        with open(metadata_path, "w") as f:
            json.dump(self.documents, f)

    def get_index_stats(self) -> dict:
        """Get index statistics."""
        return {
            "embedding_model": self.EMBEDDING_MODEL,
            "embedding_dim": self.EMBEDDING_DIM,
            "num_documents": len(self.documents) if self.index else 0,
            "index_type": "IndexFlatIP",
        }


# Singleton
_faiss_index: Optional[FAISSIndex] = None


def get_faiss_index() -> FAISSIndex:
    """Get or create FAISS index singleton."""
    global _faiss_index
    if _faiss_index is None:
        _faiss_index = FAISSIndex()
    return _faiss_index
