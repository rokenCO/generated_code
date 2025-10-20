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

# CRITICAL: Set the base path so Flask knows about it
if hasattr(Config, 'APP_BASE_PATH') and Config.APP_BASE_PATH:
    # Strip trailing slash to be consistent
    base_path = Config.APP_BASE_PATH.rstrip('/')
    app.config['APPLICATION_ROOT'] = base_path
    logger.info(f"App configured with base path: {base_path}")
else:
    base_path = ''
    logger.info("App configured at root path")

# Helper function to build URLs with base path
def build_url(path):
    """Build URL with base path prefix"""
    if not path.startswith('/'):
        path = '/' + path
    if base_path:
        return base_path + path
    return path

# Make base_path available to all templates
@app.context_processor
def inject_base_path():
    return {'base_path': base_path}

# ============================================
# Command History Management
# ============================================

# History file location - can be configured via environment
HISTORY_FILE = os.environ.get('HISTORY_FILE', 
                               Path.cwd().parent / 'logs' / 'command_history.json')
HISTORY_MAX_ENTRIES = 100  # Keep last 100 commands

def ensure_history_file():
    """Ensure history file and directory exist"""
    history_path = Path(HISTORY_FILE)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not history_path.exists():
        history_path.write_text('[]')
        logger.info(f"Created history file: {history_path}")

def load_command_history():
    """Load command history from file"""
    try:
        ensure_history_file()
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
            # Return most recent first
            return history[::-1]
    except Exception as e:
        logger.error(f"Failed to load history: {e}")
        return []

def save_command_to_history(command, args, success, username):
    """Append command to history file"""
    try:
        ensure_history_file()
        
        # Load existing history
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
        
        # Add new entry
        entry = {
            'command': command,
            'args': args,
            'success': success,
            'username': username,
            'timestamp': datetime.now().isoformat()
        }
        history.append(entry)
        
        # Keep only last N entries
        history = history[-HISTORY_MAX_ENTRIES:]
        
        # Save back
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
        
        logger.debug(f"Saved command to history: {command} by {username}")
        
    except Exception as e:
        logger.error(f"Failed to save command to history: {e}")

# ============================================

# Session configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_PATH'] = base_path if base_path else '/'

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
                # Use build_url to ensure base path is included
                next_path = request.path if request.path != build_url('/login') else build_url('/')
                return redirect(build_url('/login') + f'?next={next_path}')
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
                f"Full URL: {request.url}, Base path: {base_path}")
    
    if request.method == 'GET':
        # Already logged in?
        if 'user' in session:
            logger.info(f"User already logged in, redirecting to index")
            return redirect(build_url('/'))
        
        next_url = request.args.get('next', build_url('/'))
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
    
    # Filter roles to only show relevant ones (that grant permissions)
    relevant_roles = [
        role for role in user_data['roles'] 
        if role in Config.LDAP_DEFAULT_READ_ROLES or role in Config.LDAP_DEFAULT_WRITE_ROLES
    ]
    
    # Create session
    session['user'] = {
        'username': user_data['username'],
        'email': user_data['email'],
        'full_name': user_data['full_name'],
        'roles': user_data['roles'],  # All roles for backend logic
        'relevant_roles': relevant_roles,  # Only permission-granting roles for display
        'permissions': permissions,
        'allowed_commands': permissions['allowed_commands']
    }
    session.permanent = True
    
    logger.info(f"User {username} logged in successfully with permissions: {permissions}")
    
    # Redirect to next URL or home
    # Get next_url from form data, not query string (since this is POST)
    next_url = request.form.get('next', '').strip()
    
    # Validate next_url to prevent open redirects
    if next_url and (next_url.startswith('/') or next_url.startswith(base_path)):
        # Internal redirect - use as-is
        logger.info(f"Redirecting to next_url: {next_url}")
        return redirect(next_url)
    else:
        # Default to index
        logger.info(f"Redirecting to index: {build_url('/')}")
        return redirect(build_url('/'))

@app.route('/history')
def get_history():
    """Get command history - requires authentication"""
    if 'user' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    history = load_command_history()
    return jsonify({'history': history[:50]})  # Return last 50

@app.route('/logout')
def logout():
    """Handle logout"""
    username = session.get('user', {}).get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(build_url('/login'))

@app.route('/')
def index():
    """Root/main application page"""
    # If not logged in, redirect to login
    if 'user' not in session:
        return redirect(build_url('/login'))
    
    # User is logged in, show the main page
    user = session.get('user', {})
    
    # Load command history
    history = load_command_history()
    
    return render_template('index.html', 
                         commands=user.get('allowed_commands', []),
                         user=user,
                         initial_history=history[:20])  # Pass last 20 to template

@app.route('/execute', methods=['POST'])
def execute():
    """Execute command"""
    # Check authentication
    if 'user' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
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
        
        # Save to command history
        save_command_to_history(command, args, result.returncode == 0, user['username'])
        
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
        'configured_base_path': base_path,
        'request_url': request.url,
        'request_path': request.path,
        'base_url': request.base_url,
        'url_root': request.url_root,
        'script_root': request.script_root,
        'application_root': app.config.get('APPLICATION_ROOT'),
        'session_cookie_path': app.config.get('SESSION_COOKIE_PATH'),
        'headers': dict(request.headers),
        'remote_addr': request.remote_addr,
        'scheme': request.scheme,
        'test_urls': {
            'login': build_url('/login'),
            'index': build_url('/'),
            'logout': build_url('/logout'),
            'execute': build_url('/execute')
        }
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