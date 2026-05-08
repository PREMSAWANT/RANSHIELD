import numpy as np
import os
from typing import Dict

# InMemory cache to keep track of previous file entropies for "entropy_before" calculation
_entropy_cache: Dict[str, float] = {}

def compute_entropy(path: str, sample: int = 4096) -> float:
    """
    Compute Shannon entropy (bits/byte) of a 4KB file sample.
    Returns 0.0 on error or if the file is empty.
    Matches Listing 1 from the paper.
    """
    try:
        if not os.path.exists(path) or os.path.isdir(path):
            return 0.0
        
        file_size = os.path.getsize(path)
        if file_size == 0:
            return 0.0
            
        with open(path, 'rb') as f:
            data = f.read(sample)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0
        
    if not data:
        return 0.0
        
    # Vectorized computation using NumPy's bincount
    counts = np.bincount(
        np.frombuffer(data, dtype=np.uint8),
        minlength=256
    )
    p = counts / len(data)
    p = p[p > 0]  # Mask zero-probability bytes
    return float(-np.sum(p * np.log2(p)))

def get_entropy_before_and_after(path: str) -> tuple[float, float]:
    """
    Retrieves the cached pre-modification entropy (or calculates/guesses if missing),
    calculates the current post-modification entropy, and updates the cache.
    """
    entropy_before = _entropy_cache.get(path, 0.0)
    
    # Calculate current entropy (after)
    entropy_after = compute_entropy(path)
    
    # Update cache
    if entropy_after > 0.0:
        _entropy_cache[path] = entropy_after
        
    # If entropy_before is 0.0 but entropy_after is computed, let's assume pre-entropy
    # was something standard (or just 0.0 if it's a new file)
    return entropy_before, entropy_after

def pre_populate_entropy_cache(directory: str):
    """Scan directory and cache initial entropy values for existing files."""
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            _entropy_cache[full_path] = compute_entropy(full_path)
