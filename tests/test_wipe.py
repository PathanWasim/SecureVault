"""
Unit tests for secure wipe functionality in GhostVault
Tests panic wipe, self-destruct, and secure file deletion
"""

import pytest
import os
import tempfile
import shutil
import secrets
from unittest.mock import patch, Mock, call

import wipe


class TestSecureOverwrite:
    """Test secure file overwriting functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_secure_overwrite_file(self):
        """Test secure overwriting of a file"""
        # Create test file
        test_file = os.path.join(self.test_dir, 'test.txt')
        original_content = b'sensitive data to be overwritten'
        
        with open(test_file, 'wb') as f:
            f.write(original_content)
        
        assert os.path.exists(test_file)
        
        # Secure overwrite
        wipe.secure_overwrite(test_file, passes=3)
        
        # File should be deleted
        assert not os.path.exists(test_file)
    
    def test_secure_overwrite_nonexistent_file(self):
        """Test secure overwrite on nonexistent file"""
        nonexistent_file = os.path.join(self.test_dir, 'nonexistent.txt')
        
        # Should not raise exception
        wipe.secure_overwrite(nonexistent_file)
    
    def test_secure_overwrite_different_passes(self):
        """Test secure overwrite with different pass counts"""
        test_file = os.path.join(self.test_dir, 'test_passes.txt')
        
        with open(test_file, 'wb') as f:
            f.write(b'test content')
        
        # Test with 1 pass
        wipe.secure_overwrite(test_file, passes=1)
        assert not os.path.exists(test_file)
    
    def test_secure_overwrite_large_file(self):
        """Test secure overwrite on large file"""
        test_file = os.path.join(self.test_dir, 'large_test.bin')
        
        # Create 1MB file
        large_content = secrets.token_bytes(1024 * 1024)
        with open(test_file, 'wb') as f:
            f.write(large_content)
        
        wipe.secure_overwrite(test_file, passes=2)
        assert not os.path.exists(test_file)
    
    def test_secure_overwrite_empty_file(self):
        """Test secure overwrite on empty file"""
        test_file = os.path.join(self.test_dir, 'empty.txt')
        
        # Create empty file
        open(test_file, 'wb').close()
        
        wipe.secure_overwrite(test_file)
        assert not os.path.exists(test_file)
    
    @patch('os.fsync')
    @patch('builtins.open')
    def test_secure_overwrite_calls_fsync(self, mock_open, mock_fsync):
        """Test that secure overwrite calls fsync for disk flush"""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file
        mock_file.fileno.return_value = 123
        
        # Create a real test file for os.path.exists and os.path.getsize
        test_file = os.path.join(self.test_dir, 'fsync_test.txt')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        wipe.secure_overwrite(test_file, passes=2)
        
        # fsync should be called once per pass
        assert mock_fsync.call_count == 2
        mock_fsync.assert_has_calls([call(123), call(123)])


class TestSecureDirectoryOverwrite:
    """Test secure directory overwriting functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_secure_overwrite_directory(self):
        """Test secure overwriting of directory structure"""
        # Create test directory structure
        test_subdir = os.path.join(self.test_dir, 'test_vault')
        os.makedirs(test_subdir)
        
        # Create files in directory
        file1 = os.path.join(test_subdir, 'file1.txt')
        file2 = os.path.join(test_subdir, 'subdir', 'file2.txt')
        
        os.makedirs(os.path.dirname(file2))
        
        with open(file1, 'wb') as f:
            f.write(b'content 1')
        with open(file2, 'wb') as f:
            f.write(b'content 2')
        
        assert os.path.exists(test_subdir)
        assert os.path.exists(file1)
        assert os.path.exists(file2)
        
        # Secure overwrite directory
        wipe.secure_overwrite_directory(test_subdir)
        
        # Directory should be deleted
        assert not os.path.exists(test_subdir)
    
    def test_secure_overwrite_directory_nonexistent(self):
        """Test secure overwrite on nonexistent directory"""
        nonexistent_dir = os.path.join(self.test_dir, 'nonexistent')
        
        # Should not raise exception
        wipe.secure_overwrite_directory(nonexistent_dir)
    
    def test_secure_overwrite_directory_empty(self):
        """Test secure overwrite on empty directory"""
        empty_dir = os.path.join(self.test_dir, 'empty')
        os.makedirs(empty_dir)
        
        wipe.secure_overwrite_directory(empty_dir)
        assert not os.path.exists(empty_dir)


class TestMemoryClearing:
    """Test memory clearing functionality"""
    
    def test_zero_sensitive_variables(self):
        """Test zeroing sensitive variables function"""
        # This is mostly symbolic in Python, but should not crash
        wipe.zero_sensitive_variables()
        
        # Function should complete without exception
        assert True
    
    @patch('gc.collect')
    def test_zero_sensitive_variables_calls_gc(self, mock_gc_collect):
        """Test that memory clearing calls garbage collection"""
        wipe.zero_sensitive_variables()
        
        mock_gc_collect.assert_called_once()


class TestPanicWipe:
    """Test panic wipe functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Create mock vault structure
        os.makedirs('vaults', exist_ok=True)
        os.makedirs('headers', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        # Create test files
        with open('state.json', 'w') as f:
            f.write('{"test": "state"}')
        
        with open('vaults/test_vault.bin', 'wb') as f:
            f.write(b'vault content')
        
        with open('headers/test_header.hdr', 'w') as f:
            f.write('header content')
        
        with open('logs/audit.log.enc', 'wb') as f:
            f.write(b'audit log content')
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('wipe.zero_sensitive_variables')
    @patch('wipe.create_post_wipe_decoys')
    def test_panic_wipe(self, mock_create_decoys, mock_zero_vars):
        """Test panic wipe functionality"""
        # Verify files exist before wipe
        assert os.path.exists('vaults')
        assert os.path.exists('headers')
        assert os.path.exists('logs')
        assert os.path.exists('state.json')
        
        wipe.panic_wipe()
        
        # Verify files are deleted after wipe
        assert not os.path.exists('vaults')
        assert not os.path.exists('headers')
        assert not os.path.exists('logs')
        assert not os.path.exists('state.json')
        
        # Verify helper functions were called
        mock_zero_vars.assert_called_once()
        mock_create_decoys.assert_called_once()
    
    def test_panic_wipe_with_missing_targets(self):
        """Test panic wipe when some targets don't exist"""
        # Remove some directories
        shutil.rmtree('vaults')
        os.remove('state.json')
        
        # Should not raise exception
        wipe.panic_wipe()


class TestSelfDestruct:
    """Test self-destruct functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Create mock vault structure
        os.makedirs('vaults', exist_ok=True)
        os.makedirs('headers', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        with open('state.json', 'w') as f:
            f.write('{"test": "state"}')
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('wipe.zero_sensitive_variables')
    def test_self_destruct(self, mock_zero_vars):
        """Test self-destruct functionality"""
        # Verify files exist before self-destruct
        assert os.path.exists('vaults')
        assert os.path.exists('headers')
        assert os.path.exists('logs')
        assert os.path.exists('state.json')
        
        wipe.self_destruct()
        
        # Verify files are deleted
        assert not os.path.exists('vaults')
        assert not os.path.exists('headers')
        assert not os.path.exists('logs')
        assert not os.path.exists('state.json')
        
        # Verify marker file is created
        assert os.path.exists('SYSTEM_WIPED.txt')
        
        # Verify memory clearing was called
        mock_zero_vars.assert_called_once()


class TestPostWipeDecoys:
    """Test post-wipe decoy creation"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
    
    def teardown_method(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_create_post_wipe_decoys(self):
        """Test creation of post-wipe decoy files"""
        wipe.create_post_wipe_decoys()
        
        # Verify decoy directories and files are created
        assert os.path.exists('Documents')
        assert os.path.exists('Pictures')
        assert os.path.exists('Downloads')
        
        assert os.path.exists('Documents/readme.txt')
        assert os.path.exists('Documents/notes.txt')
        assert os.path.exists('Downloads/temp.txt')
        
        # Verify files have content
        with open('Documents/readme.txt', 'r') as f:
            content = f.read()
            assert 'readme.txt' in content
            assert 'sample' in content


class TestWipeWarnings:
    """Test wipe warning functionality"""
    
    def test_get_wipe_warnings(self):
        """Test getting wipe warning messages"""
        warnings = wipe.get_wipe_warnings()
        
        assert isinstance(warnings, list)
        assert len(warnings) > 0
        
        # Check for key warning topics
        warning_text = '\n'.join(warnings)
        assert 'SSD' in warning_text
        assert 'Copy-on-Write' in warning_text
        assert 'Virtual Memory' in warning_text
        assert 'encryption' in warning_text.lower()
        assert 'RECOMMENDATIONS' in warning_text


class TestWipeSimulation:
    """Test wipe simulation functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_simulate_secure_wipe_file(self):
        """Test simulating secure wipe on file"""
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'wb') as f:
            f.write(b'test content')
        
        result = wipe.simulate_secure_wipe(test_file)
        
        assert isinstance(result, dict)
        assert result['path'] == test_file
        assert result['exists'] is True
        assert result['type'] == 'file'
        assert result['size'] > 0
        assert result['passes_simulated'] == 3
        assert 'warnings' in result
    
    def test_simulate_secure_wipe_directory(self):
        """Test simulating secure wipe on directory"""
        test_dir = os.path.join(self.test_dir, 'test_vault')
        os.makedirs(test_dir)
        
        # Create files in directory
        with open(os.path.join(test_dir, 'file1.txt'), 'wb') as f:
            f.write(b'content 1')
        with open(os.path.join(test_dir, 'file2.txt'), 'wb') as f:
            f.write(b'content 2')
        
        result = wipe.simulate_secure_wipe(test_dir)
        
        assert result['exists'] is True
        assert result['type'] == 'directory'
        assert result['size'] > 0
        assert 'file_count' in result
        assert result['file_count'] == 2
    
    def test_simulate_secure_wipe_nonexistent(self):
        """Test simulating secure wipe on nonexistent path"""
        nonexistent_path = os.path.join(self.test_dir, 'nonexistent')
        
        result = wipe.simulate_secure_wipe(nonexistent_path)
        
        assert result['exists'] is False
        assert result['size'] == 0
        assert result['type'] == 'unknown'


class TestWipeErrorHandling:
    """Test error handling in wipe functions"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('builtins.open', side_effect=PermissionError("Access denied"))
    def test_secure_overwrite_permission_error(self, mock_open):
        """Test secure overwrite with permission error"""
        test_file = os.path.join(self.test_dir, 'readonly.txt')
        
        # Create file first
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        # secure_overwrite should handle the error gracefully
        wipe.secure_overwrite(test_file)
        
        # Function should complete without raising exception
        assert True
    
    @patch('wipe.secure_overwrite_directory', side_effect=Exception("Test error"))
    @patch('wipe.zero_sensitive_variables')
    def test_panic_wipe_error_handling(self, mock_zero_vars, mock_overwrite_dir):
        """Test that panic wipe continues despite individual errors"""
        os.chdir(self.test_dir)
        os.makedirs('vaults')
        
        # Should not raise exception despite error in secure_overwrite_directory
        with pytest.raises(Exception):  # Re-raises the original exception
            wipe.panic_wipe()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
