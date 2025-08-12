"""
Unit tests for storage management in GhostVault
Tests vault creation, header management, and unlock attempts
"""

import pytest
import os
import json
import tempfile
import shutil
import uuid
from unittest.mock import patch, Mock, MagicMock

import storage
import crypto
import wipe


class TestStateManagement:
    """Test system state management"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_state_file = storage.STATE_FILE
        storage.STATE_FILE = os.path.join(self.test_dir, 'test_state.json')
        
        # Create test directories
        storage.HEADERS_DIR = os.path.join(self.test_dir, 'headers')
        storage.VAULTS_DIR = os.path.join(self.test_dir, 'vaults')
        os.makedirs(storage.HEADERS_DIR, exist_ok=True)
        os.makedirs(storage.VAULTS_DIR, exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        storage.STATE_FILE = self.original_state_file
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_get_state_default(self):
        """Test getting default state when file doesn't exist"""
        state = storage.get_state()
        
        assert isinstance(state, dict)
        assert 'failed_attempts' in state
        assert 'last_attempt' in state
        assert 'salt' in state
        assert 'created' in state
        assert 'vault_count' in state
        
        assert state['failed_attempts'] == 0
        assert state['vault_count'] == 0
    
    def test_save_load_state(self):
        """Test saving and loading state"""
        test_state = {
            'failed_attempts': 3,
            'last_attempt': 1234567890,
            'salt': 'test_salt_hex',
            'created': 1234567890,
            'vault_count': 2
        }
        
        storage.save_state(test_state)
        loaded_state = storage.get_state()
        
        assert loaded_state == test_state
    
    def test_increment_failed_attempts(self):
        """Test failed attempt counter increment"""
        # Start with clean state
        initial_state = storage.get_state()
        initial_attempts = initial_state['failed_attempts']
        
        storage.increment_failed_attempts()
        
        updated_state = storage.get_state()
        assert updated_state['failed_attempts'] == initial_attempts + 1
        assert updated_state['last_attempt'] > initial_state.get('last_attempt', 0)
    
    @patch('storage.wipe.self_destruct')
    def test_increment_failed_attempts_self_destruct(self, mock_self_destruct):
        """Test self-destruct trigger on max failed attempts"""
        # Set attempts to just below threshold
        state = storage.get_state()
        state['failed_attempts'] = storage.MAX_FAILED_ATTEMPTS - 1
        storage.save_state(state)
        
        with pytest.raises(storage.SelfDestructException):
            storage.increment_failed_attempts()
        
        mock_self_destruct.assert_called_once()
    
    def test_reset_failed_attempts(self):
        """Test resetting failed attempt counter"""
        # Set some failed attempts
        state = storage.get_state()
        state['failed_attempts'] = 3
        storage.save_state(state)
        
        storage.reset_failed_attempts()
        
        updated_state = storage.get_state()
        assert updated_state['failed_attempts'] == 0


class TestHeaderManagement:
    """Test vault header creation and management"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        storage.HEADERS_DIR = os.path.join(self.test_dir, 'headers')
        os.makedirs(storage.HEADERS_DIR, exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_create_header(self):
        """Test header creation"""
        blob_id = str(uuid.uuid4())
        vault_type = 'real'
        metadata = {'name': 'Test Vault', 'file_count': 3}
        key = crypto.generate_salt(32)  # 32-byte key
        
        encrypted_header = storage.create_header(blob_id, vault_type, metadata, key)
        
        assert isinstance(encrypted_header, dict)
        assert 'nonce' in encrypted_header
        assert 'ciphertext' in encrypted_header
        assert 'version' in encrypted_header
    
    def test_save_load_header(self):
        """Test saving and loading headers"""
        header_id = str(uuid.uuid4())
        key = crypto.generate_salt(32)
        
        # Create test header
        encrypted_header = storage.create_header(
            blob_id="test_blob",
            vault_type="decoy",
            metadata={"test": "data"},
            key=key
        )
        
        # Save header
        storage.save_header(header_id, encrypted_header)
        
        # Load header
        loaded_header = storage.load_header(header_id)
        
        assert loaded_header['nonce'] == encrypted_header['nonce']
        assert loaded_header['ciphertext'] == encrypted_header['ciphertext']
        assert loaded_header['version'] == encrypted_header['version']
    
    def test_load_nonexistent_header(self):
        """Test loading nonexistent header raises error"""
        with pytest.raises(Exception):
            storage.load_header("nonexistent_header")


class TestVaultBlobManagement:
    """Test vault data blob management"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        storage.VAULTS_DIR = os.path.join(self.test_dir, 'vaults')
        os.makedirs(storage.VAULTS_DIR, exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_save_load_vault_blob(self):
        """Test saving and loading vault blobs"""
        blob_id = str(uuid.uuid4())
        test_files = {
            'file1.txt': b'Content of file 1',
            'file2.txt': b'Content of file 2',
            'document.pdf': b'PDF content here'
        }
        
        # Save vault blob
        storage.save_vault_blob(blob_id, test_files)
        
        # Load vault blob
        loaded_files = storage.load_vault_blob(blob_id)
        
        assert loaded_files == test_files
    
    def test_load_nonexistent_vault_blob(self):
        """Test loading nonexistent vault blob raises error"""
        with pytest.raises(FileNotFoundError):
            storage.load_vault_blob("nonexistent_blob")
    
    def test_save_vault_blob_creates_metadata(self):
        """Test that saving vault blob creates metadata"""
        blob_id = str(uuid.uuid4())
        test_files = {'test.txt': b'test content'}
        
        storage.save_vault_blob(blob_id, test_files)
        
        # Check metadata file exists
        metadata_path = os.path.join(storage.VAULTS_DIR, blob_id, '_metadata.json')
        assert os.path.exists(metadata_path)
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        assert 'files' in metadata
        assert 'created' in metadata
        assert 'total_size' in metadata
        assert metadata['files'] == ['test.txt']


class TestFileProcessing:
    """Test file processing functions"""
    
    def test_process_uploaded_files(self):
        """Test processing Flask uploaded files"""
        # Mock Flask file objects
        mock_file1 = Mock()
        mock_file1.filename = 'test1.txt'
        mock_file1.read.return_value = b'content1'
        
        mock_file2 = Mock()
        mock_file2.filename = 'test2.txt'
        mock_file2.read.return_value = b'content2'
        
        files = [mock_file1, mock_file2]
        result = storage.process_uploaded_files(files)
        
        assert result == {
            'test1.txt': b'content1',
            'test2.txt': b'content2'
        }
        
        # Verify seek was called to reset file pointer
        mock_file1.seek.assert_called_with(0)
        mock_file2.seek.assert_called_with(0)
    
    def test_process_uploaded_files_empty(self):
        """Test processing empty file list"""
        result = storage.process_uploaded_files([])
        assert result == {}
    
    def test_process_uploaded_files_no_filename(self):
        """Test processing files without filename"""
        mock_file = Mock()
        mock_file.filename = None
        
        result = storage.process_uploaded_files([mock_file])
        assert result == {}
    
    def test_load_sample_files(self):
        """Test loading sample files from disk"""
        # Create temporary test files
        test_dir = tempfile.mkdtemp()
        try:
            file1_path = os.path.join(test_dir, 'file1.txt')
            file2_path = os.path.join(test_dir, 'file2.txt')
            
            with open(file1_path, 'wb') as f:
                f.write(b'sample content 1')
            
            with open(file2_path, 'wb') as f:
                f.write(b'sample content 2')
            
            result = storage.load_sample_files([file1_path, file2_path])
            
            assert result == {
                'file1.txt': b'sample content 1',
                'file2.txt': b'sample content 2'
            }
        
        finally:
            shutil.rmtree(test_dir)
    
    def test_load_sample_files_nonexistent(self):
        """Test loading nonexistent sample files"""
        result = storage.load_sample_files(['nonexistent.txt'])
        assert result == {}


class TestVaultSystem:
    """Test complete vault system creation"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        storage.STATE_FILE = os.path.join(self.test_dir, 'test_state.json')
        storage.HEADERS_DIR = os.path.join(self.test_dir, 'headers')
        storage.VAULTS_DIR = os.path.join(self.test_dir, 'vaults')
        os.makedirs(storage.HEADERS_DIR, exist_ok=True)
        os.makedirs(storage.VAULTS_DIR, exist_ok=True)
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('storage.load_sample_files')
    def test_create_vault_system(self, mock_load_sample_files):
        """Test creating a complete vault system"""
        # Mock sample file loading
        mock_load_sample_files.side_effect = [
            {'real_file.txt': b'real content'},
            {'decoy1_file.txt': b'decoy 1 content'},
            {'decoy2_file.txt': b'decoy 2 content'}
        ]
        
        system_id = storage.create_vault_system(
            real_password='real_pass',
            panic_password='panic_pass',
            decoy_passwords=['decoy1_pass', 'decoy2_pass'],
            real_files=[],
            decoy_files=[[], []]
        )
        
        assert isinstance(system_id, str)
        assert len(system_id) > 0
        
        # Verify state was updated
        state = storage.get_state()
        assert 'systems' in state
        assert system_id in state['systems']
        
        # Verify headers were created
        header_files = os.listdir(storage.HEADERS_DIR)
        assert len(header_files) == 4  # real + 2 decoys + panic
    
    def test_create_vault_system_with_flask_files(self):
        """Test creating vault system with Flask uploaded files"""
        # Mock Flask file objects
        real_file = Mock()
        real_file.filename = 'real.txt'
        real_file.read.return_value = b'real content'
        real_file.seek = Mock()
        
        decoy_file = Mock()
        decoy_file.filename = 'decoy.txt'
        decoy_file.read.return_value = b'decoy content'
        decoy_file.seek = Mock()
        
        system_id = storage.create_vault_system(
            real_password='real_pass',
            panic_password='panic_pass',
            decoy_passwords=['decoy_pass'],
            real_files=[real_file],
            decoy_files=[[decoy_file]]
        )
        
        assert isinstance(system_id, str)
        
        # Verify files were processed
        real_file.read.assert_called()
        decoy_file.read.assert_called()


class TestUnlockAttempts:
    """Test vault unlock functionality"""
    
    def setup_method(self):
        """Set up test environment with a test vault system"""
        self.test_dir = tempfile.mkdtemp()
        storage.STATE_FILE = os.path.join(self.test_dir, 'test_state.json')
        storage.HEADERS_DIR = os.path.join(self.test_dir, 'headers')
        storage.VAULTS_DIR = os.path.join(self.test_dir, 'vaults')
        os.makedirs(storage.HEADERS_DIR, exist_ok=True)
        os.makedirs(storage.VAULTS_DIR, exist_ok=True)
        
        # Create a test vault system
        self.real_password = 'test_real_pass'
        self.decoy_password = 'test_decoy_pass'
        self.panic_password = 'test_panic_pass'
        
        with patch('storage.load_sample_files') as mock_load:
            mock_load.side_effect = [
                {'real.txt': b'real data'},
                {'decoy.txt': b'decoy data'},
                {}
            ]
            
            self.system_id = storage.create_vault_system(
                real_password=self.real_password,
                panic_password=self.panic_password,
                decoy_passwords=[self.decoy_password],
                real_files=[],
                decoy_files=[[]]
            )
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_attempt_unlock_real_vault(self):
        """Test unlocking real vault"""
        result = storage.attempt_unlock(self.real_password)
        
        assert result is not None
        vault_type, blob_id, metadata = result
        assert vault_type == 'real'
        assert isinstance(blob_id, str)
        assert isinstance(metadata, dict)
    
    def test_attempt_unlock_decoy_vault(self):
        """Test unlocking decoy vault"""
        result = storage.attempt_unlock(self.decoy_password)
        
        assert result is not None
        vault_type, blob_id, metadata = result
        assert vault_type == 'decoy'
        assert isinstance(blob_id, str)
        assert isinstance(metadata, dict)
    
    def test_attempt_unlock_panic_vault(self):
        """Test unlocking panic vault"""
        result = storage.attempt_unlock(self.panic_password)
        
        assert result is not None
        vault_type, blob_id, metadata = result
        assert vault_type == 'panic'
        assert isinstance(blob_id, str)
        assert isinstance(metadata, dict)
    
    def test_attempt_unlock_wrong_password(self):
        """Test unlocking with wrong password"""
        result = storage.attempt_unlock('wrong_password')
        
        assert result is None
        
        # Verify failed attempts were incremented
        state = storage.get_state()
        assert state['failed_attempts'] > 0


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_get_vault_contents(self):
        """Test getting vault contents information"""
        test_dir = tempfile.mkdtemp()
        try:
            storage.VAULTS_DIR = test_dir
            blob_id = 'test_blob'
            
            # Create test vault
            vault_dir = os.path.join(test_dir, blob_id)
            os.makedirs(vault_dir)
            
            with open(os.path.join(vault_dir, 'test.txt'), 'wb') as f:
                f.write(b'test content')
            
            contents = storage.get_vault_contents(blob_id)
            
            assert 'test.txt' in contents
            assert 'size' in contents['test.txt']
            assert 'size_human' in contents['test.txt']
            assert 'type' in contents['test.txt']
            
        finally:
            shutil.rmtree(test_dir)
    
    def test_format_bytes(self):
        """Test byte size formatting"""
        assert storage.format_bytes(100) == "100.0 B"
        assert storage.format_bytes(1024) == "1.0 KB"
        assert storage.format_bytes(1024 * 1024) == "1.0 MB"
        assert storage.format_bytes(1024 * 1024 * 1024) == "1.0 GB"
    
    def test_get_file_type(self):
        """Test file type detection"""
        assert storage.get_file_type('document.txt') == 'text'
        assert storage.get_file_type('image.png') == 'image'
        assert storage.get_file_type('document.pdf') == 'document'
        assert storage.get_file_type('unknown.xyz') == 'unknown'
        assert storage.get_file_type('no_extension') == 'unknown'
    
    def test_get_system_status(self):
        """Test getting system status"""
        test_dir = tempfile.mkdtemp()
        try:
            storage.VAULTS_DIR = os.path.join(test_dir, 'vaults')
            storage.HEADERS_DIR = os.path.join(test_dir, 'headers')
            os.makedirs(storage.VAULTS_DIR)
            os.makedirs(storage.HEADERS_DIR)
            
            status = storage.get_system_status()
            
            assert isinstance(status, dict)
            assert 'failed_attempts' in status
            assert 'max_attempts' in status
            assert 'vault_count' in status
            assert 'header_count' in status
            
        finally:
            shutil.rmtree(test_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
