"""
Integration tests for GhostVault
Tests complete workflows and system interactions
"""

import pytest
import os
import tempfile
import shutil
import json
from unittest.mock import patch, Mock

import crypto
import storage
import wipe
import audit


class TestCompleteVaultWorkflow:
    """Test complete vault creation and unlock workflow"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Set up storage paths
        storage.STATE_FILE = 'test_state.json'
        storage.HEADERS_DIR = 'headers'
        storage.VAULTS_DIR = 'vaults'
        audit.AUDIT_LOG_PATH = 'logs/audit.log.enc'
        audit.AUDIT_KEY_PATH = 'logs/audit.key'
        
        # Create directories
        os.makedirs('headers', exist_ok=True)
        os.makedirs('vaults', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('storage.load_sample_files')
    def test_complete_workflow_real_vault(self, mock_load_sample_files):
        """Test complete workflow: create vault -> unlock real vault -> access files"""
        # Mock sample file data
        mock_load_sample_files.side_effect = [
            {'secret_doc.txt': b'Top secret information'},
            {'homework.txt': b'Math homework due tomorrow'},
            {'recipes.txt': b'Chocolate chip cookies recipe'}
        ]
        
        # Step 1: Create vault system
        real_password = 'my_real_password_123'
        panic_password = 'DESTROY_EVERYTHING'
        decoy_passwords = ['homework_pass', 'cooking_pass']
        
        system_id = storage.create_vault_system(
            real_password=real_password,
            panic_password=panic_password,
            decoy_passwords=decoy_passwords,
            real_files=[],
            decoy_files=[[], []]
        )
        
        assert isinstance(system_id, str)
        
        # Step 2: Unlock real vault
        result = storage.attempt_unlock(real_password)
        assert result is not None
        
        vault_type, blob_id, metadata = result
        assert vault_type == 'real'
        
        # Step 3: Access vault contents
        contents = storage.get_vault_contents(blob_id)
        assert 'secret_doc.txt' in contents
        
        # Step 4: Verify audit logging
        audit_entries = audit.get_audit_log()
        assert len(audit_entries) >= 1
        
        successful_entries = [e for e in audit_entries if e['success']]
        assert len(successful_entries) >= 1
        assert successful_entries[0]['vault_type'] == 'real'
    
    @patch('storage.load_sample_files')
    def test_complete_workflow_decoy_vault(self, mock_load_sample_files):
        """Test complete workflow with decoy vault access"""
        mock_load_sample_files.side_effect = [
            {'real_secret.txt': b'Actual secret data'},
            {'homework.txt': b'Assignment 1: Calculate derivatives'},
            {'shopping.txt': b'Milk, bread, eggs'}
        ]
        
        # Create vault system
        system_id = storage.create_vault_system(
            real_password='real_pass',
            panic_password='panic_pass',
            decoy_passwords=['student_pass', 'family_pass'],
            real_files=[],
            decoy_files=[[], []]
        )
        
        # Unlock decoy vault
        result = storage.attempt_unlock('student_pass')
        assert result is not None
        
        vault_type, blob_id, metadata = result
        assert vault_type == 'decoy'
        
        # Access decoy contents
        contents = storage.get_vault_contents(blob_id)
        assert 'homework.txt' in contents
        
        # Verify audit entry
        audit_entries = audit.get_audit_log()
        decoy_entries = [e for e in audit_entries if e['vault_type'] == 'decoy']
        assert len(decoy_entries) >= 1
    
    def test_failed_unlock_attempts_and_self_destruct(self):
        """Test failed unlock attempts leading to self-destruct"""
        # Create vault system first
        with patch('storage.load_sample_files') as mock_load:
            mock_load.side_effect = [
                {'real.txt': b'real'},
                {'decoy.txt': b'decoy'},
                {}
            ]
            
            storage.create_vault_system(
                real_password='correct_pass',
                panic_password='panic_pass',
                decoy_passwords=['decoy_pass'],
                real_files=[],
                decoy_files=[[]]
            )
        
        # Make multiple failed attempts
        wrong_passwords = ['wrong1', 'wrong2', 'wrong3', 'wrong4']
        
        for password in wrong_passwords:
            result = storage.attempt_unlock(password)
            assert result is None
        
        # Check that failed attempts were recorded
        state = storage.get_state()
        assert state['failed_attempts'] == len(wrong_passwords)
        
        # One more failed attempt should trigger self-destruct
        with patch('wipe.self_destruct') as mock_self_destruct:
            with pytest.raises(storage.SelfDestructException):
                storage.attempt_unlock('wrong5')
            
            mock_self_destruct.assert_called_once()
    
    @patch('storage.load_sample_files')
    @patch('wipe.zero_sensitive_variables')
    @patch('wipe.create_post_wipe_decoys')
    def test_panic_password_workflow(self, mock_create_decoys, mock_zero_vars, mock_load):
        """Test panic password activation workflow"""
        mock_load.side_effect = [
            {'real_data.txt': b'sensitive information'},
            {'homework.txt': b'school work'},
            {}
        ]
        
        # Create vault system
        panic_password = 'EMERGENCY_WIPE_NOW'
        storage.create_vault_system(
            real_password='real_pass',
            panic_password=panic_password,
            decoy_passwords=['decoy_pass'],
            real_files=[],
            decoy_files=[[]]
        )
        
        # Verify vaults exist before panic
        assert os.path.exists('vaults')
        assert os.path.exists('headers')
        
        # Unlock with panic password
        result = storage.attempt_unlock(panic_password)
        assert result is not None
        
        vault_type, blob_id, metadata = result
        assert vault_type == 'panic'
        
        # Trigger panic wipe (normally done by the web interface)
        wipe.panic_wipe()
        
        # Verify system was wiped
        assert not os.path.exists('vaults')
        assert not os.path.exists('headers')
        
        mock_zero_vars.assert_called_once()
        mock_create_decoys.assert_called_once()


class TestCryptographicIntegration:
    """Test integration of cryptographic components"""
    
    def test_end_to_end_encryption_workflow(self):
        """Test complete encryption workflow from password to data recovery"""
        # User data
        password = "user_secure_password_123"
        plaintext_data = b"This is sensitive user data that needs protection"
        
        # Step 1: Generate salt and derive key
        salt = crypto.generate_salt()
        key = crypto.derive_key(password, salt)
        
        # Step 2: Encrypt data
        encrypted_package = crypto.encrypt_blob(key, plaintext_data)
        
        # Step 3: Simulate storage and retrieval (like headers)
        # Convert to format that would be stored on disk
        stored_data = {
            'nonce': encrypted_package['nonce'].hex(),
            'ciphertext': encrypted_package['ciphertext'].hex(),
            'version': encrypted_package['version']
        }
        
        # Step 4: Retrieve and decrypt (like unlock process)
        retrieved_package = {
            'nonce': bytes.fromhex(stored_data['nonce']),
            'ciphertext': bytes.fromhex(stored_data['ciphertext']),
            'version': stored_data['version']
        }
        
        # Re-derive key from password
        recovered_key = crypto.derive_key(password, salt)
        
        # Decrypt data
        decrypted_data = crypto.decrypt_blob(recovered_key, retrieved_package)
        
        # Verify complete workflow
        assert decrypted_data == plaintext_data
        assert key == recovered_key
    
    def test_multiple_vault_encryption_uniqueness(self):
        """Test that multiple vaults with same password have different ciphertexts"""
        password = "shared_password"
        data = b"same data in different vaults"
        
        # Create two encrypted packages with same password but different salts
        salt1 = crypto.generate_salt()
        salt2 = crypto.generate_salt()
        
        key1 = crypto.derive_key(password, salt1)
        key2 = crypto.derive_key(password, salt2)
        
        encrypted1 = crypto.encrypt_blob(key1, data)
        encrypted2 = crypto.encrypt_blob(key2, data)
        
        # Keys should be different due to different salts
        assert key1 != key2
        
        # Encrypted data should be different
        assert encrypted1['nonce'] != encrypted2['nonce']
        assert encrypted1['ciphertext'] != encrypted2['ciphertext']
        
        # But both should decrypt correctly with their respective keys
        decrypted1 = crypto.decrypt_blob(key1, encrypted1)
        decrypted2 = crypto.decrypt_blob(key2, encrypted2)
        
        assert decrypted1 == data
        assert decrypted2 == data


class TestAuditIntegration:
    """Test audit logging integration with other components"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        audit.AUDIT_LOG_PATH = 'logs/audit.log.enc'
        audit.AUDIT_KEY_PATH = 'logs/audit.key'
        os.makedirs('logs', exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_audit_log_encryption_integrity(self):
        """Test that audit logs are properly encrypted and maintain integrity"""
        # Log several attempts
        audit.log_attempt('user****', True, 'real', 'blob123')
        audit.log_attempt('wrong****', False, None, None)
        audit.log_attempt('decoy****', True, 'decoy', 'blob456')
        
        # Verify audit log file is encrypted (not plaintext)
        with open(audit.AUDIT_LOG_PATH, 'r') as f:
            encrypted_content = f.read()
        
        # Should be JSON with hex-encoded encrypted data
        encrypted_data = json.loads(encrypted_content)
        assert 'nonce' in encrypted_data
        assert 'ciphertext' in encrypted_data
        
        # Verify we can read back the log entries
        entries = audit.get_audit_log()
        assert len(entries) == 3
        
        # Verify entry contents
        real_entries = [e for e in entries if e['vault_type'] == 'real']
        decoy_entries = [e for e in entries if e['vault_type'] == 'decoy']
        failed_entries = [e for e in entries if not e['success']]
        
        assert len(real_entries) == 1
        assert len(decoy_entries) == 1
        assert len(failed_entries) == 1
    
    def test_audit_log_survives_key_rotation(self):
        """Test audit log handling when audit key changes"""
        # Log initial entry
        audit.log_attempt('initial****', True, 'real', 'blob1')
        
        # Force audit key regeneration by removing key file
        if os.path.exists(audit.AUDIT_KEY_PATH):
            os.remove(audit.AUDIT_KEY_PATH)
        
        # This should create a new key and start fresh log
        audit.log_attempt('new****', True, 'decoy', 'blob2')
        
        # Should be able to read the new entry
        entries = audit.get_audit_log()
        assert len(entries) >= 1  # At least the new entry


class TestStorageIntegration:
    """Test storage system integration with other components"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        storage.STATE_FILE = 'state.json'
        storage.HEADERS_DIR = 'headers'
        storage.VAULTS_DIR = 'vaults'
        
        os.makedirs('headers', exist_ok=True)
        os.makedirs('vaults', exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_storage_crypto_integration(self):
        """Test that storage properly uses crypto functions"""
        # Create header with crypto integration
        blob_id = 'test_blob_123'
        vault_type = 'real'
        metadata = {'name': 'Test Integration Vault'}
        
        # Use actual crypto functions
        password = 'integration_test_password'
        salt = crypto.generate_salt()
        key = crypto.derive_key(password, salt)
        
        # Create encrypted header
        encrypted_header = storage.create_header(blob_id, vault_type, metadata, key)
        
        # Save and load header
        header_id = 'integration_test_header'
        storage.save_header(header_id, encrypted_header)
        loaded_header = storage.load_header(header_id)
        
        # Decrypt and verify content
        decrypted_data = crypto.decrypt_blob(key, loaded_header)
        header_content = json.loads(decrypted_data.decode('utf-8'))
        
        assert header_content['blob_id'] == blob_id
        assert header_content['vault_type'] == vault_type
        assert header_content['metadata'] == metadata
    
    @patch('storage.load_sample_files')
    def test_storage_state_consistency(self, mock_load_sample_files):
        """Test that storage maintains consistent state across operations"""
        mock_load_sample_files.side_effect = [
            {'file1.txt': b'content1'},
            {'file2.txt': b'content2'}
        ]
        
        # Create vault system
        system_id = storage.create_vault_system(
            real_password='test_pass',
            panic_password='panic_pass',
            decoy_passwords=['decoy_pass'],
            real_files=[],
            decoy_files=[[]]
        )
        
        # Verify state was updated
        state = storage.get_state()
        assert system_id in state.get('systems', {})
        
        # Verify files were created
        header_count = len([f for f in os.listdir('headers') if f.endswith('.hdr')])
        vault_count = len([d for d in os.listdir('vaults') if os.path.isdir(os.path.join('vaults', d))])
        
        assert header_count > 0
        assert vault_count > 0
        
        # Verify system status reflects reality
        status = storage.get_system_status()
        assert status['header_count'] == header_count
        assert status['vault_count'] == vault_count


class TestErrorHandlingIntegration:
    """Test error handling across component integration"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        os.makedirs('headers', exist_ok=True)
        os.makedirs('vaults', exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_corrupted_header_handling(self):
        """Test system behavior with corrupted vault headers"""
        # Create a corrupted header file
        corrupted_header_path = os.path.join('headers', 'corrupted.hdr')
        with open(corrupted_header_path, 'w') as f:
            f.write('{"invalid": "json content that cannot be decrypted"}')
        
        # Attempt unlock should handle corruption gracefully
        result = storage.attempt_unlock('any_password')
        assert result is None
        
        # Failed attempt counter should be incremented
        state = storage.get_state()
        assert state['failed_attempts'] > 0
    
    def test_missing_vault_blob_handling(self):
        """Test handling of missing vault blob files"""
        # Create valid header that points to nonexistent blob
        blob_id = 'nonexistent_blob'
        password = 'test_password'
        salt = crypto.generate_salt()
        key = crypto.derive_key(password, salt)
        
        encrypted_header = storage.create_header(
            blob_id=blob_id,
            vault_type='real',
            metadata={'test': 'metadata'},
            key=key
        )
        
        storage.save_header('test_header', encrypted_header)
        
        # Mock the state to include our system
        state = {
            'systems': {
                'test_system': {
                    'salts': {
                        'real': salt.hex(),
                        'decoy': [],
                        'panic': crypto.generate_salt().hex()
                    }
                }
            },
            'failed_attempts': 0
        }
        storage.save_state(state)
        
        # Unlock should work (header decrypts)
        result = storage.attempt_unlock(password)
        assert result is not None
        
        # But getting vault contents should raise appropriate error
        vault_type, blob_id, metadata = result
        with pytest.raises(FileNotFoundError):
            storage.get_vault_contents(blob_id)


class TestPerformanceIntegration:
    """Test performance characteristics of integrated system"""
    
    def test_large_vault_system_performance(self):
        """Test system performance with larger data sets"""
        import time
        
        # Create larger test data
        large_content = b'x' * (100 * 1024)  # 100KB per file
        
        # Mock large file set
        with patch('storage.load_sample_files') as mock_load:
            mock_load.side_effect = [
                {f'real_file_{i}.bin': large_content for i in range(5)},
                {f'decoy1_file_{i}.bin': large_content for i in range(3)},
                {f'decoy2_file_{i}.bin': large_content for i in range(3)}
            ]
            
            start_time = time.time()
            
            # Create vault system
            storage.create_vault_system(
                real_password='performance_test',
                panic_password='panic_test',
                decoy_passwords=['decoy1', 'decoy2'],
                real_files=[],
                decoy_files=[[], []]
            )
            
            creation_time = time.time() - start_time
            
            # Reasonable performance expectation (should complete in under 10 seconds)
            assert creation_time < 10.0
            
            # Test unlock performance
            start_time = time.time()
            result = storage.attempt_unlock('performance_test')
            unlock_time = time.time() - start_time
            
            # Unlock should be fast (under 5 seconds)
            assert unlock_time < 5.0
            assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
