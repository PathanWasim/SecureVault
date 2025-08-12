# Overview

GhostVault is a secure vault system designed for educational purposes, demonstrating modern cryptographic practices and security architecture. It supports multiple vault types including a real vault for sensitive data, decoy vaults for plausible deniability, and panic password functionality for emergency data destruction. The system implements brute-force protection, encrypted audit logging, and secure file wiping capabilities using industry-standard cryptographic primitives like Argon2 and AES-GCM.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Web Application Framework
- **Flask-based web interface** with Bootstrap dark theme for modern UI
- Single-page application flow with create/unlock workflows
- Session-based authentication after successful vault unlock
- File upload support with configurable size limits and allowed extensions

## Cryptographic Foundation
- **Argon2id password-based key derivation** with secure parameters (64MB memory, 3 iterations, 4 parallel threads)
- **AES-256-GCM authenticated encryption** for all vault data and headers
- **Cryptographically secure random salt generation** (32 bytes per vault)
- Constant-time comparison functions to prevent timing attacks

## Storage Architecture
- **Headers directory**: Contains encrypted vault metadata and access information
- **Vaults directory**: Stores encrypted file blobs for each vault type
- **Logs directory**: Encrypted audit trail of all access attempts
- **State management**: JSON-based system state tracking with failure counters

## Multi-Vault System
- **Real vault**: Contains actual sensitive data, accessible with primary password
- **Decoy vaults**: Multiple fake vaults with believable content for plausible deniability
- **Panic vault**: Special vault type that triggers secure data destruction when accessed
- Each vault has independent encryption keys derived from respective passwords

## Security Features
- **Brute-force protection**: Configurable failed attempt counter (default: 5 attempts)
- **Self-destruct mechanism**: Automatic system wipe after excessive failed attempts
- **Secure file deletion**: Multi-pass overwriting with random data before file removal
- **Encrypted audit logging**: All access attempts logged with encrypted timestamps and outcomes

## Failure Recovery and Panic Modes
- **Panic password activation**: Secure deletion of key material and optional decoy display
- **Self-destruct trigger**: Comprehensive system wipe including headers, vaults, and logs
- **Secure overwrite procedures**: Multiple-pass random data overwriting for sensitive files

# External Dependencies

## Core Libraries
- **Flask**: Web framework for user interface and request handling
- **cryptography**: Industry-standard library providing AES-GCM encryption primitives
- **argon2-cffi**: Argon2 password hashing implementation for secure key derivation
- **werkzeug**: Secure filename handling and HTTP utilities

## Development and Testing
- **pytest**: Unit testing framework for cryptographic functions and system workflows
- **unittest.mock**: Mocking capabilities for isolated testing of components

## Frontend Resources
- **Bootstrap Agent Dark Theme**: CDN-delivered styling framework for consistent UI
- **Font Awesome**: Icon library for enhanced user interface elements

## File System Dependencies
- **Standard Python libraries**: os, json, secrets, shutil for file operations and secure random generation
- **Path management**: pathlib for cross-platform file path handling
- **Logging system**: Python logging module for debug and error tracking