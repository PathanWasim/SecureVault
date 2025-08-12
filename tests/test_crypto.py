"""
Unit tests for cryptographic functions in GhostVault
Tests KDF, encryption/decryption, and security properties
"""

import pytest
import secrets
import time
from unittest.mock import patch

import crypto


class TestKeyDerivation:
    """Test Argon2 key derivation functionality"""
    
    def test_derive_key_basic(self):
        """Test basic key derivation with valid inputs"""
        password = "test_password_123"
        salt = crypto.generate_salt()
        
        key = crypto.derive_key(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == crypto.AES_KEY_SIZE
    
    def test_derive_key_consistency(self):
        """Test that same password+salt produces same key"""
        password = "consistent_password"
        salt = crypto.generate_salt()
        
        key1 = crypto.derive_key(password, salt)
        key2 = crypto.derive_key(password, salt)
        
        assert key1 == key2
    
    def test_derive_key_different_salts(self):
        """Test that different salts produce different keys"""
        password = "same_password"
        salt1 = crypto.generate_salt()
        salt2 = crypto.generate_salt()
        
        key1 = crypto.derive_key(password, salt1)
        key2 = crypto.derive_key(password, salt2)
        
        assert key1 != key2
    
    def test_derive_key_different_passwords(self):
        """Test that different passwords produce different keys"""
        salt = crypto.generate_salt()
        password1 = "password_one"
        password2 = "password_two"
        
        key1 = crypto.derive_key(password1, salt)
        key2 = crypto.derive_key(password2, salt)
        
        assert key1 != key2
    
    def test_derive_key_empty_password(self):
        """Test key derivation with empty password"""
        salt = crypto.generate_salt()
        
        # Should work but produce different key than non-empty
        key_empty = crypto.derive_key("", salt)
        key_normal = crypto.derive_key("password", salt)
        
        assert isinstance(key_empty, bytes)
        assert len(key_empty) == crypto.AES_KEY_SIZE
        assert key_empty != key_normal
    
    def test_derive_key_unicode_password(self):
        """Test key derivation with unicode characters"""
        password = "pássw🔐rd_ünïc😎de"
        salt = crypto.generate_salt()
        
        key = crypto.derive_key(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == crypto.AES_KEY_SIZE
    
    def test_derive_key_invalid_salt_size(self):
        """Test error handling for invalid salt size"""
        password = "test_password"
        short_salt = b"short"  # Too short
        
        # Should still work but produce valid key
        key = crypto.derive_key(password, short_salt)
        assert isinstance(key, bytes)
        assert len(key) == crypto.AES_KEY_SIZE


class TestEncryption:
    """Test AES-GCM encryption functionality"""
    
    def test_encrypt_decrypt_basic(self):
        """Test basic encryption and decryption"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"Hello, secure world!"
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        decrypted = crypto.decrypt_blob(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_blob_structure(self):
        """Test encrypted blob has correct structure"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"test data"
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        
        assert isinstance(encrypted, dict)
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted
        assert 'version' in encrypted
        
        assert isinstance(encrypted['nonce'], bytes)
        assert isinstance(encrypted['ciphertext'], bytes)
        assert len(encrypted['nonce']) == crypto.GCM_NONCE_SIZE
    
    def test_encrypt_different_nonces(self):
        """Test that encryption produces different nonces"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"same plaintext"
        
        enc1 = crypto.encrypt_blob(key, plaintext)
        enc2 = crypto.encrypt_blob(key, plaintext)
        
        assert enc1['nonce'] != enc2['nonce']
        assert enc1['ciphertext'] != enc2['ciphertext']
    
    def test_encrypt_large_data(self):
        """Test encryption of large data"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        # 1MB of data
        plaintext = secrets.token_bytes(1024 * 1024)
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        decrypted = crypto.decrypt_blob(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_encrypt_empty_data(self):
        """Test encryption of empty data"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b""
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        decrypted = crypto.decrypt_blob(key, encrypted)
        
        assert decrypted == plaintext
    
    def test_decrypt_wrong_key(self):
        """Test decryption with wrong key fails"""
        key1 = secrets.token_bytes(crypto.AES_KEY_SIZE)
        key2 = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"secret message"
        
        encrypted = crypto.encrypt_blob(key1, plaintext)
        
        with pytest.raises(ValueError, match="Decryption/authentication failed"):
            crypto.decrypt_blob(key2, encrypted)
    
    def test_decrypt_corrupted_data(self):
        """Test decryption with corrupted data fails"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"secret message"
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        
        # Corrupt the ciphertext
        encrypted['ciphertext'] = encrypted['ciphertext'][:-1] + b'\x00'
        
        with pytest.raises(ValueError, match="Decryption/authentication failed"):
            crypto.decrypt_blob(key, encrypted)
    
    def test_decrypt_invalid_nonce(self):
        """Test decryption with invalid nonce size"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"test"
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        encrypted['nonce'] = b"short"  # Invalid nonce size
        
        with pytest.raises(ValueError, match="Invalid nonce size"):
            crypto.decrypt_blob(key, encrypted)
    
    def test_encrypt_invalid_key_size(self):
        """Test encryption with invalid key size"""
        short_key = b"short_key"
        plaintext = b"test data"
        
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            crypto.encrypt_blob(short_key, plaintext)


class TestUtilityFunctions:
    """Test utility cryptographic functions"""
    
    def test_generate_salt(self):
        """Test salt generation"""
        salt = crypto.generate_salt()
        
        assert isinstance(salt, bytes)
        assert len(salt) == 32  # Default size
        
        # Test custom size
        salt_16 = crypto.generate_salt(16)
        assert len(salt_16) == 16
    
    def test_generate_salt_uniqueness(self):
        """Test that generated salts are unique"""
        salts = [crypto.generate_salt() for _ in range(100)]
        
        assert len(set(salts)) == 100  # All should be unique
    
    def test_hmac_signature(self):
        """Test HMAC signature creation and verification"""
        key = secrets.token_bytes(32)
        data = b"data to sign"
        
        signature = crypto.create_hmac_signature(key, data)
        
        assert isinstance(signature, bytes)
        assert len(signature) == 32  # SHA256 output size
        
        # Test verification
        assert crypto.verify_hmac_signature(key, data, signature) is True
        
        # Test with wrong key
        wrong_key = secrets.token_bytes(32)
        assert crypto.verify_hmac_signature(wrong_key, data, signature) is False
        
        # Test with wrong data
        assert crypto.verify_hmac_signature(key, b"wrong data", signature) is False
    
    def test_secure_compare(self):
        """Test constant-time comparison"""
        data1 = b"same_data"
        data2 = b"same_data"
        data3 = b"different"
        
        assert crypto.secure_compare(data1, data2) is True
        assert crypto.secure_compare(data1, data3) is False
    
    def test_zero_memory(self):
        """Test memory zeroing function"""
        data = bytearray(b"sensitive_data")
        original_data = bytes(data)
        
        crypto.zero_memory(data)
        
        # Should be zeroed
        assert data == bytearray(len(original_data))
        assert bytes(data) != original_data
    
    def test_zero_memory_non_bytearray(self):
        """Test zero_memory with non-bytearray (should not crash)"""
        data = b"not_bytearray"
        crypto.zero_memory(data)  # Should not raise exception


class TestPerformanceBenchmark:
    """Test performance benchmarking functionality"""
    
    def test_benchmark_encryption(self):
        """Test encryption benchmark function"""
        # Use small data size for fast testing
        results = crypto.benchmark_encryption(1024)  # 1KB
        
        assert isinstance(results, dict)
        assert 'data_size_mb' in results
        assert 'kdf_time_ms' in results
        assert 'encrypt_time_ms' in results
        assert 'decrypt_time_ms' in results
        assert 'encrypt_throughput_mbps' in results
        assert 'decrypt_throughput_mbps' in results
        
        # Validate result types
        assert isinstance(results['data_size_mb'], float)
        assert isinstance(results['kdf_time_ms'], float)
        assert isinstance(results['encrypt_time_ms'], float)
        assert isinstance(results['decrypt_time_ms'], float)
        
        # Results should be positive
        assert results['kdf_time_ms'] > 0
        assert results['encrypt_time_ms'] > 0
        assert results['decrypt_time_ms'] > 0
        assert results['encrypt_throughput_mbps'] > 0
        assert results['decrypt_throughput_mbps'] > 0


class TestSecurityProperties:
    """Test security properties of the cryptographic implementation"""
    
    def test_key_derivation_timing_consistency(self):
        """Test that key derivation timing is consistent for same parameters"""
        password = "timing_test_password"
        salt = crypto.generate_salt()
        
        times = []
        for _ in range(5):
            start = time.time()
            crypto.derive_key(password, salt)
            end = time.time()
            times.append(end - start)
        
        # Times should be relatively consistent (within 50% variance)
        avg_time = sum(times) / len(times)
        for t in times:
            assert abs(t - avg_time) / avg_time < 0.5
    
    def test_encryption_randomness(self):
        """Test that encryption output appears random"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"A" * 1000  # Repeated pattern
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        ciphertext = encrypted['ciphertext']
        
        # Ciphertext should not contain obvious patterns
        assert b"AAA" not in ciphertext
        assert len(set(ciphertext)) > 50  # Good byte distribution
    
    def test_authentication_integrity(self):
        """Test that authentication prevents tampering"""
        key = secrets.token_bytes(crypto.AES_KEY_SIZE)
        plaintext = b"authenticated message"
        
        encrypted = crypto.encrypt_blob(key, plaintext)
        
        # Modify each component and verify failure
        test_cases = [
            ('nonce', encrypted['nonce'][:-1] + b'\x00'),
            ('ciphertext', encrypted['ciphertext'][:-1] + b'\x00')
        ]
        
        for field, modified_value in test_cases:
            tampered = encrypted.copy()
            tampered[field] = modified_value
            
            with pytest.raises(ValueError):
                crypto.decrypt_blob(key, tampered)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
