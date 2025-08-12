"""
Secure file wiping and system destruction for GhostVault
Implements panic wipe and self-destruct functionality
"""

import os
import secrets
import shutil
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def secure_overwrite(file_path: str, passes: int = 3):
    """
    Securely overwrite a file with random data multiple times
    
    Note: This provides best-effort secure deletion. On SSDs and modern
    filesystems with wear leveling, data may still be recoverable.
    
    Args:
        file_path: Path to file to overwrite
        passes: Number of overwrite passes (default 3)
    """
    if not os.path.exists(file_path):
        logger.warning(f"File not found for secure overwrite: {file_path}")
        return
    
    try:
        file_size = os.path.getsize(file_path)
        logger.info(f"Securely overwriting {file_path} ({file_size} bytes, {passes} passes)")
        
        with open(file_path, 'r+b') as f:
            for pass_num in range(passes):
                logger.debug(f"Overwrite pass {pass_num + 1}/{passes}")
                f.seek(0)
                
                # Write random data
                remaining = file_size
                while remaining > 0:
                    chunk_size = min(remaining, 64 * 1024)  # 64KB chunks
                    random_data = secrets.token_bytes(chunk_size)
                    f.write(random_data)
                    remaining -= chunk_size
                
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        # Finally, delete the file
        os.remove(file_path)
        logger.info(f"File securely deleted: {file_path}")
        
    except Exception as e:
        logger.error(f"Error securely overwriting {file_path}: {str(e)}")
        # Try regular deletion as fallback
        try:
            os.remove(file_path)
            logger.warning(f"File deleted (but not securely): {file_path}")
        except:
            logger.error(f"Could not delete file: {file_path}")

def secure_overwrite_directory(dir_path: str, passes: int = 3):
    """
    Securely overwrite all files in a directory recursively
    
    Args:
        dir_path: Directory to overwrite
        passes: Number of overwrite passes
    """
    if not os.path.exists(dir_path):
        logger.warning(f"Directory not found for secure overwrite: {dir_path}")
        return
    
    try:
        logger.info(f"Securely overwriting directory: {dir_path}")
        
        # Walk through all files in directory
        for root, dirs, files in os.walk(dir_path, topdown=False):
            # Overwrite all files
            for file in files:
                file_path = os.path.join(root, file)
                secure_overwrite(file_path, passes)
            
            # Remove empty directories
            for dir in dirs:
                dir_path_full = os.path.join(root, dir)
                try:
                    os.rmdir(dir_path_full)
                    logger.debug(f"Removed directory: {dir_path_full}")
                except OSError:
                    logger.warning(f"Could not remove directory: {dir_path_full}")
        
        # Remove the root directory
        try:
            os.rmdir(dir_path)
            logger.info(f"Directory securely deleted: {dir_path}")
        except OSError:
            logger.warning(f"Could not remove root directory: {dir_path}")
            
    except Exception as e:
        logger.error(f"Error securely overwriting directory {dir_path}: {str(e)}")

def zero_sensitive_variables():
    """
    Attempt to zero out sensitive variables in memory
    
    Note: This is best-effort in Python due to immutable strings and
    garbage collection. More effective in languages like C.
    """
    import gc
    
    logger.info("Attempting to clear sensitive data from memory")
    
    # Force garbage collection
    gc.collect()
    
    # Clear any cached secrets (this is largely symbolic in Python)
    try:
        import sys
        # Clear module-level variables that might contain secrets
        for module_name in list(sys.modules.keys()):
            if 'crypto' in module_name or 'storage' in module_name:
                module = sys.modules.get(module_name)
                if module and hasattr(module, '__dict__'):
                    for attr_name in list(module.__dict__.keys()):
                        if 'key' in attr_name.lower() or 'password' in attr_name.lower():
                            try:
                                delattr(module, attr_name)
                            except:
                                pass
    except Exception as e:
        logger.debug(f"Error clearing module variables: {str(e)}")
    
    logger.debug("Memory clearing attempt completed")

def panic_wipe():
    """
    Perform panic wipe - securely delete all vault data and keys
    Called when panic password is used
    """
    logger.critical("PANIC WIPE INITIATED")
    
    try:
        # List of critical directories/files to wipe
        targets = [
            'vaults',
            'headers', 
            'logs',
            'state.json'
        ]
        
        # Securely overwrite all targets
        for target in targets:
            if os.path.isfile(target):
                logger.info(f"Panic wipe: overwriting file {target}")
                secure_overwrite(target, passes=5)  # Extra passes for panic wipe
            elif os.path.isdir(target):
                logger.info(f"Panic wipe: overwriting directory {target}")
                secure_overwrite_directory(target, passes=5)
        
        # Clear memory
        zero_sensitive_variables()
        
        # Create decoy files to hide that a wipe occurred (optional)
        create_post_wipe_decoys()
        
        logger.critical("PANIC WIPE COMPLETED")
        
    except Exception as e:
        logger.error(f"Error during panic wipe: {str(e)}")
        raise

def self_destruct():
    """
    Perform self-destruct due to too many failed attempts
    Similar to panic wipe but may leave different traces
    """
    logger.critical("SELF-DESTRUCT INITIATED - TOO MANY FAILED ATTEMPTS")
    
    try:
        # Same as panic wipe but with different logging
        targets = [
            'vaults',
            'headers',
            'logs', 
            'state.json'
        ]
        
        for target in targets:
            if os.path.isfile(target):
                logger.info(f"Self-destruct: overwriting file {target}")
                secure_overwrite(target, passes=3)
            elif os.path.isdir(target):
                logger.info(f"Self-destruct: overwriting directory {target}")
                secure_overwrite_directory(target, passes=3)
        
        # Clear memory
        zero_sensitive_variables()
        
        # Leave a marker indicating self-destruct occurred
        try:
            with open('SYSTEM_WIPED.txt', 'w') as f:
                f.write("GhostVault system wiped due to excessive failed login attempts.\n")
                f.write(f"Timestamp: {os.times()}\n")
        except:
            pass
        
        logger.critical("SELF-DESTRUCT COMPLETED")
        
    except Exception as e:
        logger.error(f"Error during self-destruct: {str(e)}")
        raise

def create_post_wipe_decoys():
    """
    Create innocent-looking files after wipe to maintain plausible deniability
    """
    try:
        logger.debug("Creating post-wipe decoy files")
        
        # Create some innocent directories and files
        decoy_structure = {
            'Documents': ['readme.txt', 'notes.txt'],
            'Pictures': [],
            'Downloads': ['temp.txt']
        }
        
        for dir_name, files in decoy_structure.items():
            os.makedirs(dir_name, exist_ok=True)
            
            for file_name in files:
                file_path = os.path.join(dir_name, file_name)
                with open(file_path, 'w') as f:
                    f.write(f"This is a sample {file_name} file.\n")
                    f.write("Created automatically.\n")
        
        logger.debug("Post-wipe decoy files created")
        
    except Exception as e:
        logger.error(f"Error creating post-wipe decoys: {str(e)}")

def get_wipe_warnings() -> List[str]:
    """
    Get list of warnings about secure deletion limitations
    
    Returns:
        List of warning messages
    """
    return [
        "SECURE DELETION LIMITATIONS:",
        "",
        "1. SSD Storage: Modern SSDs use wear leveling and over-provisioning.",
        "   Data may remain on unmapped sectors and be recoverable with",
        "   specialized tools.",
        "",
        "2. Copy-on-Write Filesystems: Systems like ZFS, Btrfs may keep",
        "   copies of data in snapshots or due to CoW behavior.",
        "",  
        "3. Virtual Memory: Sensitive data may have been swapped to disk",
        "   and remain in swap files or hibernation files.",
        "",
        "4. System RAM: Data may remain in RAM after deletion until",
        "   overwritten by other processes.",
        "",
        "5. Filesystem Journals: Some filesystems maintain journals that",
        "   may contain copies of deleted data.",
        "",
        "RECOMMENDATIONS:",
        "- Use full-disk encryption (BitLocker, LUKS, FileVault)",
        "- Disable swap files or use encrypted swap",
        "- Use secure erase commands for SSD (ATA SECURE ERASE)",
        "- Consider physical destruction for highly sensitive data",
        "",
        "This tool provides best-effort deletion but cannot guarantee",
        "complete data destruction on modern storage systems."
    ]

def simulate_secure_wipe(file_path: str) -> Dict[str, Any]:
    """
    Simulate secure wipe for demonstration/testing purposes
    Returns information about what would be wiped
    
    Args:
        file_path: Path to simulate wiping
        
    Returns:
        Dictionary with simulation results
    """
    simulation_result = {
        'path': file_path,
        'exists': os.path.exists(file_path),
        'size': 0,
        'type': 'unknown',
        'passes_simulated': 3,
        'warnings': get_wipe_warnings()
    }
    
    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            simulation_result['size'] = os.path.getsize(file_path)
            simulation_result['type'] = 'file'
        elif os.path.isdir(file_path):
            # Calculate directory size
            total_size = 0
            file_count = 0
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    file_path_full = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path_full)
                        file_count += 1
                    except:
                        pass
            
            simulation_result['size'] = total_size
            simulation_result['type'] = 'directory'
            simulation_result['file_count'] = file_count
    
    return simulation_result
