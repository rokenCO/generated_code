#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from functools import wraps
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
import ssl
import subprocess
import os
import json
from datetime import timedelta
import logging
from config import Config
from saml_config import generate_saml_settings

app = Flask(__name__)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Session configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Load SAML settings from your existing metadata
SAML_SETTINGS = generate_saml_settings()

def get_ldap_connection():
    """Create LDAP connection using your service account"""
    # Configure TLS for LDAPS
    tls_configuration = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
        ca_certs_file='/etc/pki/tls/certs/ca-bundle.crt'  # RHEL CA bundle location
    )
    
    server = Server(
        Config.LDAP_SERVICE_URL,
        use_ssl=True,
        tls=tls_configuration,
        get_info=ALL
    )
    
    conn = Connection(
        server,
        user=Config.LDAP_SERVICE_DN,
        password=Config.LDAP_SERVICE_PASSWORD,
        auto_bind=True,
        raise_exceptions=True
    )
    
    return conn

def get_user_ldap_roles(username):
    """Get user's LDAP roles/groups"""
    try:
        conn = get_ldap_connection()
        
        # Search for user - adjust based on your LDAP schema
        # Your LDAP likely uses 'uid' for username
        user_filter = f'(uid={username})'
        
        conn.search(
            search_base='dc=root',  # From your config
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'memberOf', 'employeeType']
        )
        
        if not conn.entries:
            logger.warning(f"User {username} not found in LDAP")
            return []
        
        user_entry = conn.entries[0]
        roles = []
        
        # Extract roles from memberOf attribute
        if hasattr(user_entry, 'memberOf'):
            for group_dn in user_entry.memberOf:
                # Extract CN from DN (e.g., "cn=admin,ou=groups,dc=root" -> "admin")
                group_cn = str(group_dn).split(',')[0].replace('cn=', '').replace('CN=', '')
                roles.append(group_cn)
        
        conn.unbind()
        
        logger.info(f"User {username} has roles: {roles}")
        return roles
        
    except Exception as e:
        logger.error(f"LDAP query failed for {username}: {str(e)}")
        return []

def check_user_permissions(roles):
    """Determine user's permission level based on LDAP roles"""
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

def init_saml_auth(req):
    """Initialize SAML auth with your settings"""
    auth = OneLogin_Saml2_Auth(req, SAML_SETTINGS)
    return auth

def prepare_flask_request(request):
    """Prepare request for SAML"""
    # Handle proxy setup
    return {
        'https': 'on',  # Your proxy handles HTTPS
        'http_host': Config.WEB_PROXY_ALIAS.replace('https://', '').replace('http://', ''),
        'server_port': '443',
        'script_name': Config.APP_BASE_PATH,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': request.query_string.decode('utf-8')
    }

def login_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            if request.method == 'POST':
                return jsonify({'error': 'Authentication required'}), 401
            else:
                return redirect(url_for('saml_login', next=request.url))
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

@app.route('/saml/login')
def saml_login():
    """Initiate SAML login"""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    
    if request.args.get('next'):
        session['next_url'] = request.args.get('next')
    
    sso_url = auth.login()
    logger.info(f"Redirecting to SSO: {sso_url}")
    return redirect(sso_url)

@app.route(Config.SAML_ASC_PATH, methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service - matches your existing path"""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    
    auth.process_response()
    errors = auth.get_errors()
    
    if not errors:
        # Extract username from SAML response
        saml_attributes = auth.get_attributes()
        username = auth.get_nameid()
        
        # Try common attribute names for username
        for attr in ['uid', 'username', 'sAMAccountName']:
            if attr in saml_attributes and saml_attributes[attr]:
                username = saml_attributes[attr][0]
                break
        
        # Remove domain if present (DOMAIN\user or user@domain)
        if '\\' in username:
            username = username.split('\\')[1]
        elif '@' in username:
            username = username.split('@')[0]
        
        logger.info(f"User {username} authenticated via SSO")
        
        # Get LDAP roles
        roles = get_user_ldap_roles(username)
        permissions = check_user_permissions(roles)
        
        # Check if user has any permissions
        if not permissions['can_read'] and not permissions['can_write']:
            logger.warning(f"User {username} has no permissions")
            return "Access Denied: No permissions assigned to your roles", 403
        
        # Create session
        session['user'] = {
            'username': username,
            'email': saml_attributes.get('email', [None])[0],
            'roles': roles,
            'permissions': permissions,
            'allowed_commands': permissions['allowed_commands']
        }
        session['samlSessionIndex'] = auth.get_session_index()
        
        logger.info(f"User {username} logged in with permissions: {permissions}")
        
        # Redirect
        if 'next_url' in session:
            return redirect(session.pop('next_url'))
        return redirect(url_for('index'))
        
    else:
        error_reason = auth.get_last_error_reason()
        logger.error(f"SAML auth failed: {', '.join(errors)}")
        return f"Authentication failed: {error_reason}", 400

@app.route('/')
@login_required
def index():
    user = session.get('user', {})
    return render_template('index.html', 
                         commands=user.get('allowed_commands', []),
                         user=user)

@app.route('/execute', methods=['POST'])
@login_required
def execute():
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

@app.route('/logout')
@login_required
def logout():
    """SAML logout"""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    
    name_id = session.get('samlNameId')
    session_index = session.get('samlSessionIndex')
    
    return redirect(auth.logout(
        name_id=name_id,
        session_index=session_index
    ))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    # Add service password to environment if not set
    if not Config.LDAP_SERVICE_PASSWORD:
        print("Warning: LDAP_SERVICE_PASSWORD not set!")
    
    app.run(host='0.0.0.0', port=8059, debug=True)
