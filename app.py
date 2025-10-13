#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from werkzeug.middleware.proxy_fix import ProxyFix
import ssl
import subprocess
import os
from datetime import timedelta
import logging
from config import Config

app = Flask(__name__)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Proxy configuration - IMPORTANT for reverse proxy setups
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_prefix=1
)

# Application path configuration
if hasattr(Config, 'APP_BASE_PATH') and Config.APP_BASE_PATH:
    app.config['APPLICATION_ROOT'] = Config.APP_BASE_PATH
    logger.info(f"App configured with base path: {Config.APP_BASE_PATH}")

# Session configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def get_ldap_server():
    """Create LDAP server with TLS configuration"""
    tls_configuration = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
        ca_certs_file='/etc/pki/tls/certs/ca-bundle.crt'
    )
    
    server = Server(
        Config.LDAP_SERVICE_URL,
        use_ssl=True,
        tls=tls_configuration,
        get_info=ALL
    )
    return server

def authenticate_user(username, password):
    """
    Authenticate user against LDAP using their credentials
    Returns (success, user_dn, error_message)
    """
    try:
        server = get_ldap_server()
        
        # First, search for the user to get their DN
        # Use service account for initial search
        search_conn = Connection(
            server,
            user=Config.LDAP_SERVICE_DN,
            password=Config.LDAP_SERVICE_PASSWORD,
            auto_bind=True,
            raise_exceptions=True
        )
        
        # Find user's DN
        user_filter = f'(uid={username})'
        search_conn.search(
            search_base='dc=root',
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'memberOf']
        )
        
        if not search_conn.entries:
            search_conn.unbind()
            return False, None, "User not found"
        
        user_entry = search_conn.entries[0]
        user_dn = user_entry.entry_dn
        search_conn.unbind()
        
        # Now try to bind as the user with their password
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            raise_exceptions=True
        )
        
        if not user_conn.bind():
            return False, None, "Invalid password"
        
        user_conn.unbind()
        logger.info(f"User {username} authenticated successfully")
        return True, user_dn, None
        
    except Exception as e:
        logger.error(f"Authentication failed for {username}: {str(e)}")
        return False, None, str(e)

def get_user_details(username):
    """Get user's details and roles from LDAP"""
    try:
        server = get_ldap_server()
        conn = Connection(
            server,
            user=Config.LDAP_SERVICE_DN,
            password=Config.LDAP_SERVICE_PASSWORD,
            auto_bind=True,
            raise_exceptions=True
        )
        
        user_filter = f'(uid={username})'
        conn.search(
            search_base='dc=root',
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'memberOf', 'employeeType']
        )
        
        if not conn.entries:
            conn.unbind()
            return None
        
        user_entry = conn.entries[0]
        roles = []
        
        # Extract roles from memberOf
        if hasattr(user_entry, 'memberOf'):
            for group_dn in user_entry.memberOf:
                group_cn = str(group_dn).split(',')[0].replace('cn=', '').replace('CN=', '')
                roles.append(group_cn)
        
        conn.unbind()
        
        user_data = {
            'username': username,
            'email': user_entry.mail.value if hasattr(user_entry, 'mail') else None,
            'full_name': user_entry.cn.value if hasattr(user_entry, 'cn') else username,
            'roles': roles
        }
        
        logger.info(f"User {username} has roles: {roles}")
        return user_data
        
    except Exception as e:
        logger.error(f"Failed to get user details for {username}: {str(e)}")
        return None

def check_user_permissions(roles):
    """Determine user's permissions based on LDAP roles"""
    permissions = {
        'can_read': False,
        'can_write': False,
        'allowed_commands': []
    }
    
    # Check read permissions
    for role in roles:
        if role in Config.LDAP_DEFAULT_READ_ROLES:
            permissions['can_read'] = True
            permissions['allowed_commands'].extend(['status', 'list'])
            break
    
    # Check write permissions
    for role in roles:
        if role in Config.LDAP_DEFAULT_WRITE_ROLES:
            permissions['can_write'] = True
            permissions['allowed_commands'].extend(['dobackpopulation', 'status', 'list'])
            break
    
    # Remove duplicates
    permissions['allowed_commands'] = list(set(permissions['allowed_commands']))
    
    return permissions

def login_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            if request.method == 'POST':
                return jsonify({'error': 'Authentication required'}), 401
            else:
                return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def write_permission_required(f):
    """Decorator for routes requiring write permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user', {}).get('permissions', {}).get('can_write'):
            return jsonify({'error': 'Write permission required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login form"""
    # Log request details for debugging
    logger.info(f"Login request - Method: {request.method}, Path: {request.path}, "
                f"Full URL: {request.url}, Headers: {dict(request.headers)}")
    
    if request.method == 'GET':
        # Already logged in?
        if 'user' in session:
            logger.info(f"User already logged in, redirecting to index")
            return redirect(url_for('index'))
        
        next_url = request.args.get('next', url_for('index'))
        logger.info(f"Showing login page, next_url: {next_url}")
        return render_template('login.html', next_url=next_url)
    
    # POST - process login
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return render_template('login.html', 
                             error='Username and password required',
                             username=username)
    
    # Authenticate
    success, user_dn, error = authenticate_user(username, password)
    
    if not success:
        logger.warning(f"Login failed for {username}: {error}")
        return render_template('login.html', 
                             error='Invalid username or password',
                             username=username)
    
    # Get user details and roles
    user_data = get_user_details(username)
    if not user_data:
        return render_template('login.html',
                             error='Failed to retrieve user information',
                             username=username)
    
    # Check permissions
    permissions = check_user_permissions(user_data['roles'])
    
    if not permissions['can_read'] and not permissions['can_write']:
        logger.warning(f"User {username} has no permissions")
        return render_template('login.html',
                             error='Access denied: No permissions assigned',
                             username=username)
    
    # Create session
    session['user'] = {
        'username': user_data['username'],
        'email': user_data['email'],
        'full_name': user_data['full_name'],
        'roles': user_data['roles'],
        'permissions': permissions,
        'allowed_commands': permissions['allowed_commands']
    }
    session.permanent = True
    
    logger.info(f"User {username} logged in successfully with permissions: {permissions}")
    
    # Redirect to next URL or home
    next_url = request.args.get('next', url_for('index'))
    return redirect(next_url)

@app.route('/logout')
@login_required
def logout():
    """Handle logout"""
    username = session.get('user', {}).get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main application page"""
    user = session.get('user', {})
    return render_template('index.html', 
                         commands=user.get('allowed_commands', []),
                         user=user)

@app.route('/execute', methods=['POST'])
@login_required
def execute():
    """Execute command"""
    data = request.json
    command = data.get('command')
    args = data.get('args', [])
    
    user = session['user']
    
    # Verify command permission
    if command not in user.get('allowed_commands', []):
        logger.warning(f"User {user['username']} attempted unauthorized command: {command}")
        return jsonify({'error': f'Command {command} not allowed for your roles'}), 403
    
    # Log execution
    logger.info(f"User {user['username']} (roles: {user['roles']}) executing: {command} {' '.join(args)}")
    
    cmd = [Config.TASK_ADMIN_PATH, '-c', Config.TASK_CONFIG_PATH, command] + args
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        return jsonify({
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'executed_by': user['username']
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/debug-proxy')
def debug_proxy():
    """Debug endpoint to check proxy configuration"""
    return jsonify({
        'request_url': request.url,
        'request_path': request.path,
        'base_url': request.base_url,
        'url_root': request.url_root,
        'script_root': request.script_root,
        'application_root': app.config.get('APPLICATION_ROOT'),
        'headers': dict(request.headers),
        'remote_addr': request.remote_addr,
        'scheme': request.scheme
    })

if __name__ == '__main__':
    # Validate configuration
    if not Config.LDAP_SERVICE_PASSWORD:
        print("Warning: LDAP_SERVICE_PASSWORD not set!")
    
    if not Config.LDAP_DEFAULT_READ_ROLES and not Config.LDAP_DEFAULT_WRITE_ROLES:
        print("Warning: No LDAP roles configured for access!")
    
    print(f"\nStarting Flask app...")
    print(f"Base path: {app.config.get('APPLICATION_ROOT', '/')}")
    print(f"Access directly at: http://localhost:8059/login")
    if hasattr(Config, 'WEB_PROXY_ALIAS'):
        print(f"Access via proxy at: {Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH if hasattr(Config, 'APP_BASE_PATH') else ''}/login")
    print(f"\nDebug proxy config at: /debug-proxy\n")
    
    app.run(host='0.0.0.0', port=8059, debug=True)
