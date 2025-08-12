// GhostVault Interactive JavaScript Features
document.addEventListener('DOMContentLoaded', function() {
    initializePasswordStrengthChecker();
    initializeFileUploadEnhancements();
    initializeSystemMonitoring();
    initializeSecurityFeatures();
});

// Password Strength Checking
function initializePasswordStrengthChecker() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    passwordFields.forEach(field => {
        // Create strength indicator elements
        const strengthContainer = document.createElement('div');
        strengthContainer.className = 'mt-2';
        
        const strengthBar = document.createElement('div');
        strengthBar.className = 'password-strength-bar';
        strengthBar.style.width = '0%';
        
        const strengthText = document.createElement('div');
        strengthText.className = 'password-feedback text-muted';
        
        strengthContainer.appendChild(strengthBar);
        strengthContainer.appendChild(strengthText);
        field.parentNode.insertBefore(strengthContainer, field.nextSibling);
        
        // Add event listener for real-time checking
        field.addEventListener('input', function() {
            checkPasswordStrength(this.value, strengthBar, strengthText);
        });
    });
}

function checkPasswordStrength(password, strengthBar, strengthText) {
    if (!password) {
        strengthBar.style.width = '0%';
        strengthBar.className = 'password-strength-bar';
        strengthText.textContent = '';
        return;
    }
    
    let score = 0;
    let feedback = [];
    
    // Length check
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    else feedback.push('Use at least 8 characters');
    
    // Character variety checks
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Include uppercase letters');
    
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Include lowercase letters');
    
    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Include numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Include special characters');
    
    // Determine strength
    let strength, className, width;
    if (score >= 6) {
        strength = 'Strong';
        className = 'password-strength-strong';
        width = '100%';
    } else if (score >= 4) {
        strength = 'Good';
        className = 'password-strength-good';
        width = '75%';
    } else if (score >= 2) {
        strength = 'Fair';
        className = 'password-strength-fair';
        width = '50%';
    } else {
        strength = 'Weak';
        className = 'password-strength-weak';
        width = '25%';
    }
    
    // Update UI
    strengthBar.className = `password-strength-bar ${className}`;
    strengthBar.style.width = width;
    strengthText.innerHTML = `<strong>${strength}</strong>` + 
        (feedback.length ? ': ' + feedback.join(', ') : '');
}

// File Upload Enhancements
function initializeFileUploadEnhancements() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        const container = document.createElement('div');
        container.className = 'file-upload-enhanced mt-2';
        
        const dropZone = document.createElement('div');
        dropZone.className = 'file-drop-zone';
        dropZone.innerHTML = `
            <i class="fas fa-cloud-upload-alt fa-2x text-muted mb-2"></i>
            <p>Drag files here or click to browse</p>
            <small class="text-muted">Supported: .txt, .pdf, .png, .jpg, .gif, .doc, .docx</small>
        `;
        
        const fileList = document.createElement('div');
        fileList.className = 'file-list mt-2';
        
        container.appendChild(dropZone);
        container.appendChild(fileList);
        input.parentNode.insertBefore(container, input.nextSibling);
        
        // Hide original input
        input.style.display = 'none';
        
        // Drag and drop functionality
        dropZone.addEventListener('click', () => input.click());
        dropZone.addEventListener('dragover', handleDragOver);
        dropZone.addEventListener('drop', (e) => handleDrop(e, input));
        
        // File selection handling
        input.addEventListener('change', () => updateFileList(input, fileList));
    });
}

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('dragover');
}

function handleDrop(e, input) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
    
    const files = Array.from(e.dataTransfer.files);
    input.files = e.dataTransfer.files;
    
    // Trigger change event
    const event = new Event('change', { bubbles: true });
    input.dispatchEvent(event);
}

function updateFileList(input, container) {
    container.innerHTML = '';
    
    if (input.files.length === 0) return;
    
    Array.from(input.files).forEach((file, index) => {
        const item = document.createElement('div');
        item.className = 'file-list-item';
        item.innerHTML = `
            <div>
                <i class="fas fa-file me-2"></i>
                <strong>${file.name}</strong>
                <small class="text-muted ms-2">(${formatFileSize(file.size)})</small>
            </div>
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeFile(this, ${index})">
                <i class="fas fa-times"></i>
            </button>
        `;
        container.appendChild(item);
    });
}

function removeFile(button, index) {
    // This would need more complex implementation to actually remove from FileList
    button.parentElement.remove();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// System Monitoring
function initializeSystemMonitoring() {
    // Auto-refresh system status every 30 seconds
    if (window.location.pathname.includes('status') || 
        window.location.pathname === '/' || 
        window.location.pathname.includes('audit')) {
        setInterval(updateSystemStatus, 30000);
    }
}

function updateSystemStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            // Update failed attempts counter
            const failedElements = document.querySelectorAll('[data-failed-attempts]');
            failedElements.forEach(el => {
                el.textContent = `${data.failed_attempts}/${data.max_attempts}`;
                el.className = el.className.replace(/text-(success|warning|danger)/, 
                    data.failed_attempts > 3 ? 'text-danger' : 
                    data.failed_attempts > 0 ? 'text-warning' : 'text-success');
            });
            
            // Update vault count
            const vaultElements = document.querySelectorAll('[data-vault-count]');
            vaultElements.forEach(el => {
                el.textContent = data.vault_count;
            });
        })
        .catch(error => console.log('Status update failed:', error));
}

// Security Features
function initializeSecurityFeatures() {
    // Add confirmation dialogs for dangerous actions
    const dangerButtons = document.querySelectorAll('[data-confirm]');
    dangerButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
    
    // Session timeout warning
    let lastActivity = Date.now();
    const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
    const WARNING_TIME = 5 * 60 * 1000; // 5 minutes before timeout
    
    document.addEventListener('click', () => lastActivity = Date.now());
    document.addEventListener('keypress', () => lastActivity = Date.now());
    
    setInterval(() => {
        const timeLeft = SESSION_TIMEOUT - (Date.now() - lastActivity);
        if (timeLeft <= WARNING_TIME && timeLeft > 0) {
            showSessionWarning(Math.floor(timeLeft / 1000 / 60));
        } else if (timeLeft <= 0) {
            window.location.href = '/logout';
        }
    }, 60000); // Check every minute
}

function showSessionWarning(minutesLeft) {
    // Only show once per session timeout cycle
    if (document.querySelector('.session-warning')) return;
    
    const warning = document.createElement('div');
    warning.className = 'alert alert-warning alert-dismissible fade show session-warning position-fixed';
    warning.style.cssText = 'top: 20px; right: 20px; z-index: 1050; min-width: 300px;';
    warning.innerHTML = `
        <i class="fas fa-clock me-2"></i>
        <strong>Session Warning:</strong> You will be logged out in ${minutesLeft} minutes due to inactivity.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(warning);
    
    // Auto-dismiss after 10 seconds
    setTimeout(() => {
        if (warning.parentNode) {
            warning.remove();
        }
    }, 10000);
}

// Form Validation Enhancements
function validateVaultForm() {
    const form = document.getElementById('vaultForm');
    if (!form) return true;
    
    const passwords = [
        'real_password',
        'panic_password',
        'decoy1_password',
        'decoy2_password'
    ];
    
    const values = passwords.map(id => document.getElementById(id)?.value || '');
    
    // Check for duplicate passwords
    const unique = new Set(values);
    if (unique.size !== values.length) {
        alert('All passwords must be unique');
        return false;
    }
    
    // Check password strength
    for (const value of values) {
        if (value.length < 8) {
            alert('All passwords must be at least 8 characters long');
            return false;
        }
    }
    
    return true;
}

// Export functions for global access
window.GhostVault = {
    validateVaultForm,
    updateSystemStatus,
    showSessionWarning
};