import os
import logging
import json
import argparse
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
import storage
import crypto
import audit
import wipe
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure required directories exist
os.makedirs('vaults', exist_ok=True)
os.makedirs('headers', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_password_strength(password):
    """Check password strength and return score and feedback"""
    if not password:
        return 0, "Password is required"
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ recommended)")
    
    # Character variety checks
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Include uppercase letters")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Include lowercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Include numbers")
    
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    else:
        feedback.append("Include special characters")
    
    # Common password checks
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if password.lower() in common_passwords:
        score = max(0, score - 3)
        feedback.append("Avoid common passwords")
    
    # Strength levels
    if score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Good"
    elif score >= 2:
        strength = "Fair"
    else:
        strength = "Weak"
    
    return score, strength, feedback

@app.route('/check-password-strength', methods=['POST'])
def check_password_api():
    """API endpoint for password strength checking"""
    password = request.json.get('password', '') if request.json else ''
    result = check_password_strength(password)
    if len(result) == 2:
        score, message = result
        return {
            'score': score,
            'strength': 'Weak',
            'feedback': [message],
            'max_score': 6
        }
    else:
        score, strength, feedback = result
        return {
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'max_score': 6
        }

@app.route('/')
def index():
    """Main page with options to create or unlock vault"""
    # Get system status for dashboard
    try:
        system_status = storage.get_system_status()
        return render_template('index.html', system_status=system_status)
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        return render_template('index.html', system_status=None)

@app.route('/system-status')
def system_status():
    """System status and monitoring page"""
    try:
        status = storage.get_system_status()
        audit_stats = audit.get_audit_stats()
        return render_template('system_status.html', status=status, audit_stats=audit_stats)
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        flash(f'Error getting system status: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/create', methods=['GET', 'POST'])
def create_vault():
    """Create a new vault system with real, decoy, and panic passwords"""
    if request.method == 'POST':
        try:
            # Get form data
            real_password = request.form.get('real_password')
            panic_password = request.form.get('panic_password')
            decoy1_password = request.form.get('decoy1_password')
            decoy2_password = request.form.get('decoy2_password')
            
            if not all([real_password, panic_password, decoy1_password, decoy2_password]):
                flash('All passwords are required', 'error')
                return render_template('create.html')
            
            # Ensure we have strings (type safety)
            real_password = str(real_password)
            panic_password = str(panic_password)
            decoy1_password = str(decoy1_password)
            decoy2_password = str(decoy2_password)
            
            # Check for password uniqueness
            passwords = [real_password, panic_password, decoy1_password, decoy2_password]
            if len(set(passwords)) != len(passwords):
                flash('All passwords must be unique', 'error')
                return render_template('create.html')
            
            # Handle file uploads for real vault
            real_files = request.files.getlist('real_files')
            decoy1_files = request.files.getlist('decoy1_files')
            decoy2_files = request.files.getlist('decoy2_files')
            
            # Create vault system
            vault_id = storage.create_vault_system(
                real_password=real_password,
                panic_password=panic_password,
                decoy_passwords=[decoy1_password, decoy2_password],
                real_files=real_files,
                decoy_files=[decoy1_files, decoy2_files]
            )
            
            audit.log_attempt('system', True, 'vault_created', vault_id)
            flash(f'Vault system created successfully! Vault ID: {vault_id}', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            logger.error(f"Error creating vault: {str(e)}")
            flash(f'Error creating vault: {str(e)}', 'error')
    
    return render_template('create.html')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock_vault():
    """Unlock a vault with password"""
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash('Password is required', 'error')
            return render_template('unlock.html')
        
        try:
            result = storage.attempt_unlock(password)
            
            if result is None:
                flash('Invalid password. Attempt recorded.', 'error')
                return render_template('unlock.html')
            
            vault_type, blob_id, metadata = result
            
            # Store unlock info in session
            session['unlocked'] = True
            session['vault_type'] = vault_type
            session['blob_id'] = blob_id
            session['metadata'] = metadata
            
            audit.log_attempt(password[:4] + "****", True, vault_type, blob_id)
            
            if vault_type == 'panic':
                # Perform panic wipe
                wipe.panic_wipe()
                flash('Panic mode activated. System wiped.', 'warning')
                return redirect(url_for('index'))
            
            return redirect(url_for('vault_view'))
            
        except storage.SelfDestructException:
            flash('Too many failed attempts. System has been wiped for security.', 'error')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error unlocking vault: {str(e)}")
            flash(f'Error unlocking vault: {str(e)}', 'error')
    
    return render_template('unlock.html')

@app.route('/vault')
def vault_view():
    """View unlocked vault contents"""
    if not session.get('unlocked'):
        flash('Please unlock a vault first', 'error')
        return redirect(url_for('unlock_vault'))
    
    vault_type = session.get('vault_type')
    blob_id = session.get('blob_id')
    metadata = session.get('metadata', {})
    
    if not blob_id:
        flash('Invalid vault session', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get vault contents
        contents = storage.get_vault_contents(str(blob_id))
        
        # Get audit log if this is the real vault
        audit_entries = []
        if vault_type == 'real':
            audit_entries = audit.get_audit_log()
        
        return render_template('vault_view.html', 
                             vault_type=vault_type,
                             contents=contents,
                             metadata=metadata,
                             audit_entries=audit_entries)
    
    except Exception as e:
        logger.error(f"Error viewing vault: {str(e)}")
        flash(f'Error viewing vault: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download/<blob_id>/<filename>')
def download_file(blob_id, filename):
    """Download a file from the vault"""
    if not session.get('unlocked') or session.get('blob_id') != blob_id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        file_path = storage.get_file_path(blob_id, filename)
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('vault_view'))

@app.route('/logout')
def logout():
    """Clear session and logout"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/export-audit')
def export_audit():
    """Export audit log in various formats"""
    if not session.get('unlocked') or session.get('vault_type') != 'real':
        flash('Only available for real vault access', 'error')
        return redirect(url_for('index'))
    
    format_type = request.args.get('format', 'json')
    try:
        audit_data = audit.export_audit_log(format_type)
        if format_type == 'json':
            return audit_data, 200, {'Content-Type': 'application/json'}
        elif format_type == 'csv':
            from flask import Response
            return Response(audit_data, 
                          mimetype='text/csv',
                          headers={'Content-Disposition': 'attachment; filename=audit_log.csv'})
    except Exception as e:
        flash(f'Export failed: {str(e)}', 'error')
        return redirect(url_for('vault_view'))

@app.route('/wipe-system', methods=['POST'])
def wipe_system():
    """Emergency system wipe (requires confirmation)"""
    if request.method == 'POST':
        confirm = request.form.get('confirm_wipe')
        if confirm != 'WIPE':
            flash('Confirmation required to wipe system', 'error')
            return redirect(url_for('system_status'))
        
        try:
            wipe.self_destruct()
            session.clear()
            flash('System has been completely wiped', 'warning')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Wipe failed: {str(e)}', 'error')
            return redirect(url_for('system_status'))

@app.route('/benchmark')
def crypto_benchmark():
    """Run cryptographic performance benchmarks"""
    try:
        from crypto_benchmarks import generate_comprehensive_report
        report = generate_comprehensive_report()
        return render_template('benchmark_results.html', report=report)
    except Exception as e:
        flash(f'Benchmark failed: {str(e)}', 'error')
        return redirect(url_for('system_status'))

@app.route('/security-audit')  
def security_audit():
    """Comprehensive security audit page"""
    try:
        # Get system security metrics
        system_status = storage.get_system_status()
        audit_stats = audit.get_audit_stats()
        
        # Calculate security score
        security_score = calculate_security_score(system_status, audit_stats)
        
        return render_template('security_audit.html', 
                             system_status=system_status,
                             audit_stats=audit_stats,
                             security_score=security_score)
    except Exception as e:
        flash(f'Security audit failed: {str(e)}', 'error')
        return redirect(url_for('system_status'))

def calculate_security_score(system_status: dict, audit_stats: dict) -> dict:
    """Calculate overall security score based on various metrics"""
    score = 100
    issues = []
    
    # Check failed attempts
    failed_ratio = system_status.get('failed_attempts', 0) / max(system_status.get('max_attempts', 5), 1)
    if failed_ratio > 0.8:
        score -= 20
        issues.append("High number of failed attempts detected")
    elif failed_ratio > 0.5:
        score -= 10
        issues.append("Moderate failed attempt rate")
    
    # Check vault configuration
    if system_status.get('vault_count', 0) == 0:
        score -= 30
        issues.append("No vaults configured")
    
    # Check audit log health
    if audit_stats.get('total_attempts', 0) == 0:
        score -= 10
        issues.append("No audit entries (system unused)")
    
    # Success rate analysis
    if audit_stats.get('total_attempts', 0) > 0:
        success_rate = audit_stats.get('successful_attempts', 0) / audit_stats.get('total_attempts', 1)
        if success_rate < 0.3:
            score -= 25
            issues.append("Very low success rate - possible brute force attack")
        elif success_rate < 0.5:
            score -= 15
            issues.append("Low success rate detected")
    
    # Determine rating
    if score >= 90:
        rating = "Excellent"
        color = "success"
    elif score >= 75:
        rating = "Good" 
        color = "info"
    elif score >= 60:
        rating = "Fair"
        color = "warning"
    else:
        rating = "Poor"
        color = "danger"
    
    return {
        'score': max(0, score),
        'rating': rating,
        'color': color,
        'issues': issues
    }

@app.route('/api/status')
def api_status():
    """API endpoint for system status including fail counter"""
    try:
        status = storage.get_system_status()
        return json.dumps(status, indent=2)
    except Exception as e:
        return f"Error getting status: {str(e)}", 500

def cli():
    """Command line interface"""
    parser = argparse.ArgumentParser(description='GhostVault CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create vault command
    create_parser = subparsers.add_parser('create-vault', help='Create a new vault system')
    create_parser.add_argument('--real-password', required=True, help='Real vault password')
    create_parser.add_argument('--panic-password', required=True, help='Panic password')
    create_parser.add_argument('--decoy-passwords', nargs='+', required=True, help='Decoy passwords')
    create_parser.add_argument('--real-files', nargs='*', default=[], help='Files for real vault')
    create_parser.add_argument('--decoy-files', nargs='*', default=[], help='Files for decoy vaults')
    
    # Unlock command
    unlock_parser = subparsers.add_parser('unlock', help='Unlock a vault')
    unlock_parser.add_argument('--password', required=True, help='Vault password')
    
    # Panic simulation
    panic_parser = subparsers.add_parser('panic-sim', help='Simulate panic wipe')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    
    args = parser.parse_args()
    
    if args.command == 'create-vault':
        try:
            # For CLI, use sample data files
            vault_id = storage.create_vault_system(
                real_password=args.real_password,
                panic_password=args.panic_password,
                decoy_passwords=args.decoy_passwords,
                real_files=args.real_files or ['sample_data/real_vault/document1.txt'],
                decoy_files=[args.decoy_files[:len(args.decoy_files)//2] or ['sample_data/decoy1/homework.txt'],
                           args.decoy_files[len(args.decoy_files)//2:] or ['sample_data/decoy2/recipes.txt']]
            )
            print(f"Vault system created successfully! ID: {vault_id}")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    elif args.command == 'unlock':
        try:
            result = storage.attempt_unlock(args.password)
            if result:
                vault_type, blob_id, metadata = result
                print(f"Unlocked {vault_type} vault: {blob_id}")
                contents = storage.get_vault_contents(blob_id)
                print(f"Contents: {list(contents.keys())}")
            else:
                print("Invalid password")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    elif args.command == 'panic-sim':
        try:
            wipe.panic_wipe()
            print("Panic wipe completed")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    elif args.command == 'status':
        try:
            status = storage.get_system_status()
            print(json.dumps(status, indent=2))
        except Exception as e:
            print(f"Error: {str(e)}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        cli()
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)
