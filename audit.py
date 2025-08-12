"""
Audit logging system for GhostVault
Maintains encrypted logs of all access attempts
"""

import os
import json
import time
import secrets
from typing import List, Dict, Any, Optional
import logging

import crypto

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = 'logs/audit.log.enc'
AUDIT_KEY_PATH = 'logs/audit.key'

def get_audit_key() -> bytes:
    """Get or create the audit log encryption key"""
    if os.path.exists(AUDIT_KEY_PATH):
        try:
            with open(AUDIT_KEY_PATH, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading audit key: {str(e)}")
    
    # Create new audit key
    key = crypto.generate_salt(32)  # 32-byte key
    try:
        os.makedirs(os.path.dirname(AUDIT_KEY_PATH), exist_ok=True)
        with open(AUDIT_KEY_PATH, 'wb') as f:
            f.write(key)
        logger.info("Created new audit key")
    except Exception as e:
        logger.error(f"Error saving audit key: {str(e)}")
        # Use in-memory key as fallback
    
    return key

def log_attempt(password_token: str, success: bool, vault_type: Optional[str], 
               blob_id: Optional[str] = None):
    """
    Log an unlock attempt to the encrypted audit log
    
    Args:
        password_token: Partial password for identification (first few chars + ***)
        success: Whether the attempt was successful
        vault_type: Type of vault unlocked (if successful)
        blob_id: Vault blob ID (if successful)
    """
    try:
        # Create log entry
        entry = {
            'timestamp': time.time(),
            'datetime': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'password_token': password_token,
            'success': success,
            'vault_type': vault_type,
            'blob_id': blob_id,
            'ip_address': 'local',  # Would be request.remote_addr in web context
            'user_agent': 'GhostVault'
        }
        
        # Load existing log entries
        entries = load_audit_log()
        entries.append(entry)
        
        # Save updated log
        save_audit_log(entries)
        
        logger.debug(f"Logged audit entry: success={success}, type={vault_type}")
        
    except Exception as e:
        logger.error(f"Error logging audit entry: {str(e)}")

def load_audit_log() -> List[Dict[str, Any]]:
    """Load and decrypt the audit log"""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    
    try:
        key = get_audit_key()
        
        with open(AUDIT_LOG_PATH, 'r') as f:
            encrypted_data = json.load(f)
        
        # Convert hex back to bytes
        encrypted_package = {
            'nonce': bytes.fromhex(encrypted_data['nonce']),
            'ciphertext': bytes.fromhex(encrypted_data['ciphertext']),
            'version': encrypted_data['version']
        }
        
        # Decrypt log data
        decrypted_data = crypto.decrypt_blob(key, encrypted_package)
        entries = json.loads(decrypted_data.decode('utf-8'))
        
        return entries
        
    except Exception as e:
        logger.error(f"Error loading audit log: {str(e)}")
        return []

def save_audit_log(entries: List[Dict[str, Any]]):
    """Encrypt and save the audit log"""
    try:
        key = get_audit_key()
        
        # Serialize entries
        log_data = json.dumps(entries, sort_keys=True).encode('utf-8')
        
        # Encrypt log data
        encrypted_package = crypto.encrypt_blob(key, log_data)
        
        # Convert bytes to hex for JSON storage
        encrypted_data = {
            'nonce': encrypted_package['nonce'].hex(),
            'ciphertext': encrypted_package['ciphertext'].hex(),
            'version': encrypted_package['version']
        }
        
        # Save encrypted log
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        with open(AUDIT_LOG_PATH, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
            
    except Exception as e:
        logger.error(f"Error saving audit log: {str(e)}")

def get_audit_log() -> List[Dict[str, Any]]:
    """Get audit log entries for display (only available after real vault unlock)"""
    try:
        entries = load_audit_log()
        
        # Sort by timestamp (newest first)
        entries.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return entries
        
    except Exception as e:
        logger.error(f"Error getting audit log: {str(e)}")
        return []

def clear_audit_log():
    """Clear the audit log (called during panic wipe)"""
    try:
        if os.path.exists(AUDIT_LOG_PATH):
            # Overwrite with random data before deletion
            file_size = os.path.getsize(AUDIT_LOG_PATH)
            with open(AUDIT_LOG_PATH, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
            os.remove(AUDIT_LOG_PATH)
        
        if os.path.exists(AUDIT_KEY_PATH):
            # Overwrite key file
            key_size = os.path.getsize(AUDIT_KEY_PATH)
            with open(AUDIT_KEY_PATH, 'wb') as f:
                f.write(secrets.token_bytes(key_size))
            os.remove(AUDIT_KEY_PATH)
            
        logger.info("Audit log cleared")
        
    except Exception as e:
        logger.error(f"Error clearing audit log: {str(e)}")

def export_audit_log(format: str = 'json') -> str:
    """Export audit log in specified format"""
    entries = get_audit_log()
    
    if format == 'json':
        return json.dumps(entries, indent=2)
    elif format == 'csv':
        import csv
        import io
        
        output = io.StringIO()
        if entries:
            fieldnames = entries[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entries)
        
        return output.getvalue()
    else:
        raise ValueError(f"Unsupported export format: {format}")

def get_audit_stats() -> Dict[str, Any]:
    """Get audit log statistics"""
    entries = load_audit_log()
    
    total_attempts = len(entries)
    successful_attempts = sum(1 for e in entries if e['success'])
    failed_attempts = total_attempts - successful_attempts
    
    # Count by vault type
    vault_types = {}
    for entry in entries:
        if entry['success'] and entry['vault_type']:
            vault_type = entry['vault_type']
            vault_types[vault_type] = vault_types.get(vault_type, 0) + 1
    
    # Recent activity (last 24 hours)
    recent_time = time.time() - (24 * 60 * 60)
    recent_attempts = sum(1 for e in entries if e['timestamp'] > recent_time)
    
    return {
        'total_attempts': total_attempts,
        'successful_attempts': successful_attempts,
        'failed_attempts': failed_attempts,
        'success_rate': successful_attempts / total_attempts if total_attempts > 0 else 0,
        'vault_types_accessed': vault_types,
        'recent_attempts_24h': recent_attempts,
        'first_attempt': min(e['timestamp'] for e in entries) if entries else None,
        'last_attempt': max(e['timestamp'] for e in entries) if entries else None
    }
