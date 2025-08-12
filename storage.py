"""
Storage management for GhostVault
Handles vault creation, header management, and unlock attempts
"""

import os
import json
import uuid
import time
import shutil
from typing import Dict, List, Optional, Tuple, Any, Union
import logging
from pathlib import Path

import crypto
import wipe

logger = logging.getLogger(__name__)

# Configuration
MAX_FAILED_ATTEMPTS = 5
STATE_FILE = 'state.json'
HEADERS_DIR = 'headers'
VAULTS_DIR = 'vaults'

class SelfDestructException(Exception):
    """Raised when too many failed attempts trigger self-destruct"""
    pass

def get_state() -> Dict[str, Any]:
    """Load system state from file"""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading state: {str(e)}")
    
    # Return default state
    return {
        'failed_attempts': 0,
        'last_attempt': 0,
        'salt': crypto.generate_salt().hex(),
        'created': time.time(),
        'vault_count': 0
    }

def save_state(state: Dict[str, Any]):
    """Save system state to file"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving state: {str(e)}")

def increment_failed_attempts():
    """Increment failed attempt counter and check for self-destruct"""
    state = get_state()
    state['failed_attempts'] += 1
    state['last_attempt'] = time.time()
    save_state(state)
    
    logger.warning(f"Failed attempt #{state['failed_attempts']}/{MAX_FAILED_ATTEMPTS}")
    
    if state['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
        logger.critical("Too many failed attempts - triggering self-destruct")
        wipe.self_destruct()
        raise SelfDestructException("System wiped due to too many failed attempts")

def reset_failed_attempts():
    """Reset failed attempt counter on successful unlock"""
    state = get_state()
    state['failed_attempts'] = 0
    save_state(state)

def create_header(blob_id: str, vault_type: str, metadata: Dict[str, Any], key: bytes) -> Dict[str, Any]:
    """
    Create and encrypt a vault header
    
    Args:
        blob_id: Unique identifier for the vault data
        vault_type: Type of vault ('real', 'decoy', 'panic')
        metadata: Additional vault metadata
        key: Encryption key derived from password
    
    Returns:
        Encrypted header data
    """
    # Create header structure
    header = {
        'version': '1.0',
        'blob_id': blob_id,
        'vault_type': vault_type,
        'metadata': metadata,
        'created': time.time(),
        'salt': crypto.generate_salt().hex()
    }
    
    # Serialize header
    header_json = json.dumps(header, sort_keys=True).encode('utf-8')
    
    # Encrypt header
    encrypted_header = crypto.encrypt_blob(key, header_json)
    
    return encrypted_header

def save_header(header_id: str, encrypted_header: Dict[str, Any]):
    """Save encrypted header to disk"""
    header_path = os.path.join(HEADERS_DIR, f"{header_id}.hdr")
    
    try:
        with open(header_path, 'w') as f:
            json.dump({
                'nonce': encrypted_header['nonce'].hex(),
                'ciphertext': encrypted_header['ciphertext'].hex(),
                'version': encrypted_header['version']
            }, f)
        logger.debug(f"Header saved: {header_path}")
    except Exception as e:
        logger.error(f"Error saving header {header_id}: {str(e)}")
        raise

def load_header(header_id: str) -> Dict[str, Any]:
    """Load encrypted header from disk"""
    header_path = os.path.join(HEADERS_DIR, f"{header_id}.hdr")
    
    try:
        with open(header_path, 'r') as f:
            data = json.load(f)
            return {
                'nonce': bytes.fromhex(data['nonce']),
                'ciphertext': bytes.fromhex(data['ciphertext']),
                'version': data['version']
            }
    except Exception as e:
        logger.error(f"Error loading header {header_id}: {str(e)}")
        raise

def save_vault_blob(blob_id: str, files_data: Dict[str, bytes]):
    """Save vault data blob to disk"""
    vault_dir = os.path.join(VAULTS_DIR, blob_id)
    os.makedirs(vault_dir, exist_ok=True)
    
    try:
        # Save each file in the vault
        for filename, file_data in files_data.items():
            file_path = os.path.join(vault_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(file_data)
        
        # Save metadata about the vault contents
        metadata_path = os.path.join(vault_dir, '_metadata.json')
        metadata = {
            'files': list(files_data.keys()),
            'created': time.time(),
            'total_size': sum(len(data) for data in files_data.values())
        }
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
            
        logger.debug(f"Vault blob saved: {vault_dir} ({len(files_data)} files)")
        
    except Exception as e:
        logger.error(f"Error saving vault blob {blob_id}: {str(e)}")
        raise

def load_vault_blob(blob_id: str) -> Dict[str, bytes]:
    """Load vault data blob from disk"""
    vault_dir = os.path.join(VAULTS_DIR, blob_id)
    
    if not os.path.exists(vault_dir):
        raise FileNotFoundError(f"Vault {blob_id} not found")
    
    try:
        files_data = {}
        
        # Load all files except metadata
        for filename in os.listdir(vault_dir):
            if filename.startswith('_'):
                continue  # Skip metadata files
                
            file_path = os.path.join(vault_dir, filename)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    files_data[filename] = f.read()
        
        return files_data
        
    except Exception as e:
        logger.error(f"Error loading vault blob {blob_id}: {str(e)}")
        raise

def process_uploaded_files(files: List) -> Dict[str, bytes]:
    """Process uploaded files and return file data dictionary"""
    files_data = {}
    
    for file in files:
        if file and file.filename:
            filename = file.filename
            # Read file data
            file_data = file.read()
            files_data[filename] = file_data
            
            # Reset file pointer for potential reuse
            file.seek(0)
    
    return files_data

def load_sample_files(file_paths: List[str]) -> Dict[str, bytes]:
    """Load sample files from disk for CLI usage"""
    files_data = {}
    
    for file_path in file_paths:
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                filename = os.path.basename(file_path)
                files_data[filename] = f.read()
        else:
            logger.warning(f"Sample file not found: {file_path}")
    
    return files_data

def create_vault_system(real_password: str, panic_password: str, 
                       decoy_passwords: List[str], real_files: Union[List, List[str]], 
                       decoy_files: List[Union[List, List[str]]]) -> str:
    """
    Create a complete vault system with real, decoy, and panic vaults
    
    Args:
        real_password: Password for the real vault
        panic_password: Password that triggers wipe
        decoy_passwords: List of passwords for decoy vaults
        real_files: Files for real vault (Flask files or paths for CLI)
        decoy_files: List of file lists for each decoy vault
    
    Returns:
        System ID for the created vault system
    """
    system_id = str(uuid.uuid4())
    
    try:
        # Process real files
        if real_files and hasattr(real_files[0], 'filename'):
            # Flask uploaded files
            real_files_data = process_uploaded_files(real_files)
        else:
            # CLI file paths or sample data
            if not real_files:
                real_files = ['sample_data/real_vault/document1.txt', 'sample_data/real_vault/secret_notes.txt']
            real_files_data = load_sample_files(real_files)
        
        # Process decoy files
        decoy_files_data = []
        for i, decoy_file_list in enumerate(decoy_files):
            if decoy_file_list and hasattr(decoy_file_list[0], 'filename'):
                # Flask uploaded files
                files_data = process_uploaded_files(decoy_file_list)
            else:
                # CLI file paths or sample data
                if not decoy_file_list:
                    if i == 0:
                        decoy_file_list = ['sample_data/decoy1/homework.txt', 'sample_data/decoy1/class_schedule.txt']
                    else:
                        decoy_file_list = ['sample_data/decoy2/recipes.txt', 'sample_data/decoy2/shopping_list.txt']
                files_data = load_sample_files(decoy_file_list)
            decoy_files_data.append(files_data)
        
        # Create blob IDs
        real_blob_id = str(uuid.uuid4())
        decoy_blob_ids = [str(uuid.uuid4()) for _ in decoy_passwords]
        panic_blob_id = str(uuid.uuid4())
        
        # Save vault blobs
        save_vault_blob(real_blob_id, real_files_data)
        for i, (blob_id, files_data) in enumerate(zip(decoy_blob_ids, decoy_files_data)):
            save_vault_blob(blob_id, files_data)
        
        # Create empty panic blob
        save_vault_blob(panic_blob_id, {})
        
        # Create and save headers
        # Real vault header
        real_salt = crypto.generate_salt()
        real_key = crypto.derive_key(real_password, real_salt)
        real_header_id = str(uuid.uuid4())
        real_metadata = {'name': 'Real Vault', 'file_count': len(real_files_data)}
        real_header = create_header(real_blob_id, 'real', real_metadata, real_key)
        save_header(real_header_id, real_header)
        
        # Decoy vault headers
        decoy_header_ids = []
        for i, (password, blob_id, files_data) in enumerate(zip(decoy_passwords, decoy_blob_ids, decoy_files_data)):
            salt = crypto.generate_salt()
            key = crypto.derive_key(password, salt)
            header_id = str(uuid.uuid4())
            metadata = {'name': f'Decoy Vault {i+1}', 'file_count': len(files_data)}
            header = create_header(blob_id, 'decoy', metadata, key)
            save_header(header_id, header)
            decoy_header_ids.append(header_id)
        
        # Panic vault header
        panic_salt = crypto.generate_salt()
        panic_key = crypto.derive_key(panic_password, panic_salt)
        panic_header_id = str(uuid.uuid4())
        panic_metadata = {'name': 'Panic Vault'}
        panic_header = create_header(panic_blob_id, 'panic', panic_metadata, panic_key)
        save_header(panic_header_id, panic_header)
        
        # Update system state
        state = get_state()
        state['vault_count'] += 1
        state['systems'] = state.get('systems', {})
        state['systems'][system_id] = {
            'created': time.time(),
            'real_header': real_header_id,
            'decoy_headers': decoy_header_ids,
            'panic_header': panic_header_id,
            'salts': {
                'real': real_salt.hex(),
                'decoy': [crypto.generate_salt().hex() for _ in decoy_passwords],
                'panic': panic_salt.hex()
            }
        }
        save_state(state)
        
        logger.info(f"Vault system created: {system_id}")
        return system_id
        
    except Exception as e:
        logger.error(f"Error creating vault system: {str(e)}")
        # Clean up partial creation
        cleanup_partial_system(system_id)
        raise

def cleanup_partial_system(system_id: str):
    """Clean up partially created vault system"""
    # This would remove any created files for the failed system
    # Implementation depends on tracking what was created
    pass

def attempt_unlock(password: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
    """
    Attempt to unlock a vault with the given password
    
    Args:
        password: Password to try
    
    Returns:
        Tuple of (vault_type, blob_id, metadata) if successful, None if failed
        
    Raises:
        SelfDestructException: If too many failed attempts
    """
    # Try to decrypt all headers to find a match
    header_files = [f for f in os.listdir(HEADERS_DIR) if f.endswith('.hdr')]
    
    for header_file in header_files:
        header_id = header_file[:-4]  # Remove .hdr extension
        
        try:
            # Load encrypted header
            encrypted_header = load_header(header_id)
            
            # Try multiple salt combinations (we need to store/derive salts properly)
            # For now, we'll try to decrypt and see if we get valid JSON
            
            # We need to iterate through possible salts
            # This is a simplified approach - in production, we'd store salt with header
            state = get_state()
            systems = state.get('systems', {})
            
            for system_id, system_info in systems.items():
                # Try real vault salt
                real_salt = bytes.fromhex(system_info['salts']['real'])
                try:
                    key = crypto.derive_key(password, real_salt)
                    header_data = crypto.decrypt_blob(key, encrypted_header)
                    header = json.loads(header_data.decode('utf-8'))
                    
                    if header['vault_type'] in ['real', 'decoy', 'panic']:
                        reset_failed_attempts()
                        logger.info(f"Unlocked {header['vault_type']} vault: {header['blob_id']}")
                        return header['vault_type'], header['blob_id'], header['metadata']
                except:
                    pass
                
                # Try decoy vault salts
                for decoy_salt_hex in system_info['salts']['decoy']:
                    decoy_salt = bytes.fromhex(decoy_salt_hex)
                    try:
                        key = crypto.derive_key(password, decoy_salt)
                        header_data = crypto.decrypt_blob(key, encrypted_header)
                        header = json.loads(header_data.decode('utf-8'))
                        
                        if header['vault_type'] in ['real', 'decoy', 'panic']:
                            reset_failed_attempts()
                            logger.info(f"Unlocked {header['vault_type']} vault: {header['blob_id']}")
                            return header['vault_type'], header['blob_id'], header['metadata']
                    except:
                        pass
                
                # Try panic vault salt
                panic_salt = bytes.fromhex(system_info['salts']['panic'])
                try:
                    key = crypto.derive_key(password, panic_salt)
                    header_data = crypto.decrypt_blob(key, encrypted_header)
                    header = json.loads(header_data.decode('utf-8'))
                    
                    if header['vault_type'] in ['real', 'decoy', 'panic']:
                        reset_failed_attempts()
                        logger.info(f"Unlocked {header['vault_type']} vault: {header['blob_id']}")
                        return header['vault_type'], header['blob_id'], header['metadata']
                except:
                    pass
                
        except Exception as e:
            logger.debug(f"Failed to decrypt header {header_id}: {str(e)}")
            continue
    
    # No header could be decrypted - increment fail counter
    increment_failed_attempts()
    return None

def get_vault_contents(blob_id: str) -> Dict[str, Any]:
    """Get contents of a vault blob"""
    try:
        files_data = load_vault_blob(blob_id)
        
        # Convert bytes to file info for display
        contents = {}
        for filename, data in files_data.items():
            contents[filename] = {
                'size': len(data),
                'size_human': format_bytes(len(data)),
                'type': get_file_type(filename)
            }
        
        return contents
        
    except Exception as e:
        logger.error(f"Error getting vault contents: {str(e)}")
        raise

def get_file_path(blob_id: str, filename: str) -> str:
    """Get full path to a file in a vault"""
    vault_dir = os.path.join(VAULTS_DIR, blob_id)
    file_path = os.path.join(vault_dir, filename)
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {filename} not found in vault {blob_id}")
    
    return file_path

def format_bytes(size: int) -> str:
    """Format byte size in human readable format"""
    size_float = float(size)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_float < 1024:
            return f"{size_float:.1f} {unit}"
        size_float /= 1024
    return f"{size_float:.1f} TB"

def get_file_type(filename: str) -> str:
    """Determine file type from extension"""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    type_map = {
        'txt': 'text',
        'pdf': 'document',
        'doc': 'document',
        'docx': 'document',
        'png': 'image',
        'jpg': 'image',
        'jpeg': 'image',
        'gif': 'image'
    }
    
    return type_map.get(ext, 'unknown')

def get_system_status() -> Dict[str, Any]:
    """Get current system status"""
    state = get_state()
    
    # Count existing vaults and headers
    vault_count = len([d for d in os.listdir(VAULTS_DIR) if os.path.isdir(os.path.join(VAULTS_DIR, d))])
    header_count = len([f for f in os.listdir(HEADERS_DIR) if f.endswith('.hdr')])
    
    return {
        'failed_attempts': state.get('failed_attempts', 0),
        'max_attempts': MAX_FAILED_ATTEMPTS,
        'vault_count': vault_count,
        'header_count': header_count,
        'system_created': state.get('created'),
        'last_attempt': state.get('last_attempt'),
        'systems_created': len(state.get('systems', {}))
    }

# Initialize directories
os.makedirs(HEADERS_DIR, exist_ok=True)
os.makedirs(VAULTS_DIR, exist_ok=True)
