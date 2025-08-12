"""
Cryptographic functions for GhostVault
Uses Argon2 for key derivation and AES-GCM for authenticated encryption
"""

import os
import secrets
from typing import Dict, Any, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
import json
import logging

logger = logging.getLogger(__name__)

# Argon2 parameters - recommended secure defaults
ARGON2_TIME_COST = 3        # Number of iterations
ARGON2_MEMORY_COST = 65536  # Memory usage in KiB (64 MB)
ARGON2_PARALLELISM = 4      # Number of parallel threads
ARGON2_HASH_LEN = 32        # Output hash length in bytes

# AES-GCM parameters
AES_KEY_SIZE = 32  # 256-bit key
GCM_NONCE_SIZE = 12  # 96-bit nonce (recommended for GCM)

def generate_salt(size: int = 32) -> bytes:
    """Generate a cryptographically secure random salt"""
    return secrets.token_bytes(size)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive encryption key from password using Argon2
    
    Args:
        password: User password
        salt: Random salt (32 bytes recommended)
    
    Returns:
        32-byte derived key suitable for AES-256
    """
    try:
        # Create Argon2 hasher with secure parameters
        ph = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST, 
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            salt_len=len(salt)
        )
        
        # Hash the password with the salt
        # Note: We use raw=True to get the hash without encoding
        hash_result = ph.hash(password, salt=salt)
        
        # Extract just the hash portion (after the parameters)
        # Argon2 output format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
        hash_only = hash_result.split('$')[-1]
        
        # Decode from base64 and ensure we have 32 bytes
        import base64
        key = base64.b64decode(hash_only + '==')  # Add padding if needed
        
        if len(key) >= AES_KEY_SIZE:
            return key[:AES_KEY_SIZE]
        else:
            # If hash is shorter, use HKDF to expand it
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=salt,
                info=b'GhostVault-Key-Expansion'
            )
            return hkdf.derive(key)
            
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise ValueError(f"Key derivation failed: {str(e)}")

def encrypt_blob(key: bytes, plaintext: bytes) -> Dict[str, Any]:
    """
    Encrypt data using AES-GCM authenticated encryption
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
    
    Returns:
        Dictionary containing nonce, ciphertext, and authentication tag
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    try:
        # Generate random nonce
        nonce = secrets.token_bytes(GCM_NONCE_SIZE)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt and authenticate
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Return package with all components
        return {
            'nonce': nonce,
            'ciphertext': ciphertext,
            'version': '1.0'
        }
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_blob(key: bytes, package: Dict[str, Any]) -> bytes:
    """
    Decrypt AES-GCM encrypted data
    
    Args:
        key: 32-byte decryption key
        package: Dictionary containing nonce, ciphertext, and tag
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If decryption fails or authentication check fails
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    try:
        # Extract components
        nonce = package['nonce']
        ciphertext = package['ciphertext']
        
        # Validate nonce size
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(nonce)}")
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
        
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise ValueError(f"Decryption/authentication failed")

def create_hmac_signature(key: bytes, data: bytes) -> bytes:
    """Create HMAC-SHA256 signature for data integrity"""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac_signature(key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify HMAC-SHA256 signature"""
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        h.verify(signature)
        return True
    except:
        return False

def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    return secrets.compare_digest(a, b)

def zero_memory(data: bytearray):
    """
    Attempt to zero sensitive data in memory
    Note: This is best-effort in Python due to garbage collection
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0

def benchmark_encryption(data_size: int = 1024 * 1024) -> Dict[str, float]:
    """
    Benchmark encryption/decryption performance
    
    Args:
        data_size: Size of test data in bytes (default 1MB)
    
    Returns:
        Dictionary with timing results
    """
    import time
    
    # Generate test data
    test_data = secrets.token_bytes(data_size)
    password = "test_password"
    salt = generate_salt()
    
    # Benchmark key derivation
    start_time = time.time()
    key = derive_key(password, salt)
    kdf_time = time.time() - start_time
    
    # Benchmark encryption
    start_time = time.time()
    encrypted = encrypt_blob(key, test_data)
    encrypt_time = time.time() - start_time
    
    # Benchmark decryption
    start_time = time.time()
    decrypted = decrypt_blob(key, encrypted)
    decrypt_time = time.time() - start_time
    
    # Verify correctness
    assert decrypted == test_data
    
    return {
        'data_size_mb': data_size / (1024 * 1024),
        'kdf_time_ms': kdf_time * 1000,
        'encrypt_time_ms': encrypt_time * 1000,
        'decrypt_time_ms': decrypt_time * 1000,
        'encrypt_throughput_mbps': (data_size / (1024 * 1024)) / encrypt_time,
        'decrypt_throughput_mbps': (data_size / (1024 * 1024)) / decrypt_time
    }

if __name__ == "__main__":
    # Run benchmark
    print("Running encryption benchmark...")
    results = benchmark_encryption()
    print(f"Performance for {results['data_size_mb']:.1f}MB:")
    print(f"  Key derivation: {results['kdf_time_ms']:.1f}ms")
    print(f"  Encryption: {results['encrypt_time_ms']:.1f}ms ({results['encrypt_throughput_mbps']:.1f} MB/s)")
    print(f"  Decryption: {results['decrypt_time_ms']:.1f}ms ({results['decrypt_throughput_mbps']:.1f} MB/s)")
