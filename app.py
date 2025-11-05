#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from functools import wraps
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime, timedelta
import ssl
import subprocess
import os
import sys
import json
import logging
from config import Config

app = Flask(__name__)

# Check if SAML is enabled - requires multiple config values
SAML_ENABLED = False
saml_config_issues = []

# Check all required SAML config
if not hasattr(Config, 'SAML_IDP_METADATA_FILE'):
    saml_config_issues.append("SAML_IDP_METADATA_FILE not set")
elif not Config.SAML_IDP_METADATA_FILE:
    saml_config_issues.append("SAML_IDP_METADATA_FILE is empty")

if not hasattr(Config, 'WEB_PROXY_ALIAS'):
    saml_config_issues.append("WEB_PROXY_ALIAS not set")
elif not Config.WEB_PROXY_ALIAS:
    saml_config_issues.append("WEB_PROXY_ALIAS is empty")

if not hasattr(Config, 'SAML_ACS_PATH'):
    saml_config_issues.append("SAML_ACS_PATH not set")
elif not Config.SAML_ACS_PATH:
    saml_config_issues.append("SAML_ACS_PATH is empty")

if not hasattr(Config, 'APP_BASE_PATH'):
    saml_config_issues.append("APP_BASE_PATH not set (required for SAML)")

# Only enable SAML if all config is present
if not saml_config_issues:
    SAML_ENABLED = True

# Logging setup needs to happen early
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import SAML dependencies only if enabled
if SAML_ENABLED:
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from saml_config import get_saml_settings
        logger.info("âœ“ SAML SSO is ENABLED")
        logger.info(f"  - IdP Metadata: {Config.SAML_IDP_METADATA_FILE}")
        logger.info(f"  - ACS URL: {Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}{Config.SAML_ACS_PATH}")
    except ImportError as e:
        logger.warning(f"âœ— SAML libraries not found: {e}")
        logger.warning("  Install with: pip install python3-saml")
        SAML_ENABLED = False
    except Exception as e:
        logger.error(f"âœ— SAML configuration error: {e}")
        SAML_ENABLED = False
else:
    logger.info("âœ— SAML SSO is DISABLED")
    for issue in saml_config_issues:
        logger.info(f"  - {issue}")

# Corporate Actions Integration
ca_db = None
CA_ENABLED = False
try:
    if hasattr(Config, 'PKS_DB_HOST') and hasattr(Config, 'PDS_DB_HOST') and hasattr(Config, 'FOST_DB_HOST'):
        from ca_database import CADatabase
        from ca_routes import ca_bp
        
        # Initialize CA database
        pks_config = {
            'host': Config.PKS_DB_HOST,
            'port': getattr(Config, 'PKS_DB_PORT', 5432),
            'database': getattr(Config, 'PKS_DB_NAME', 'pks'),
            'user': Config.PKS_DB_USER,
            'password': Config.PKS_DB_PASSWORD
        }
        pds_config = {
            'host': Config.PDS_DB_HOST,
            'port': getattr(Config, 'PDS_DB_PORT', 5432),
            'database': getattr(Config, 'PDS_DB_NAME', 'pds'),
            'user': Config.PDS_DB_USER,
            'password': Config.PDS_DB_PASSWORD
        }
        fost_config = {
            'host': Config.FOST_DB_HOST,
            'port': getattr(Config, 'FOST_DB_PORT', 5432),
            'database': getattr(Config, 'FOST_DB_NAME', 'fost'),
            'user': Config.FOST_DB_USER,
            'password': Config.FOST_DB_PASSWORD
        }
        
        ca_db = CADatabase(pks_config, pds_config, fost_config)
        CA_ENABLED = True
        logger.info("Corporate Actions feature is ENABLED")
    else:
        logger.info("Corporate Actions feature is DISABLED (database configs not found)")
except ImportError as e:
    logger.warning(f"Corporate Actions feature disabled: {e}")
except Exception as e:
    logger.error(f"Failed to initialize Corporate Actions: {e}")

# File upload configuration
UPLOAD_FOLDER = Path('/tmp/task_admin_uploads')
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {'csv', 'txt'}
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# Register Corporate Actions blueprint if enabled
if CA_ENABLED:
    app.register_blueprint(ca_bp)
    logger.info(f"Registered Corporate Actions blueprint at {base_path}/api/ca")

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

# ============================================
# SAML SSO Functions (if enabled)
# ============================================

def prepare_flask_request(request):
    """Prepare request for SAML (handle proxy setup)"""
    # When behind a reverse proxy, we need to use the configured public URL
    # instead of the internal request URL that Flask sees
    
    # Use configured values to build the correct URL
    if hasattr(Config, 'WEB_PROXY_ALIAS') and Config.WEB_PROXY_ALIAS:
        # Parse the public URL to extract components
        from urllib.parse import urlparse
        parsed = urlparse(Config.WEB_PROXY_ALIAS)
        
        # Determine protocol (HTTPS vs HTTP)
        is_https = parsed.scheme == 'https'
        
        # Extract host and port from the configured URL
        # netloc includes both: "staging.echonet" or "staging.echonet:8443"
        public_host = parsed.netloc
        
        # Check if a non-standard port is specified in the URL
        if ':' in public_host:
            # Port explicitly specified: https://example.com:8443
            # Extract port and remove it from host
            public_host, public_port = public_host.split(':', 1)
        else:
            # No port specified: https://example.com
            # Use standard ports that browsers assume:
            # - HTTPS uses port 443 (browsers don't show it in URLs)
            # - HTTP uses port 80 (browsers don't show it in URLs)
            public_port = '443' if is_https else '80'
        
        # Build the request object for SAML library
        # This tells the SAML library what PUBLIC URL to expect/generate
        return {
            'https': 'on' if is_https else 'off',
            'http_host': public_host,           # e.g., "staging.echonet"
            'server_port': public_port,         # e.g., "443" for standard HTTPS
            'script_name': Config.APP_BASE_PATH if hasattr(Config, 'APP_BASE_PATH') else '',
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            'query_string': request.query_string.decode('utf-8')
        }
    else:
        # Fallback: No WEB_PROXY_ALIAS configured
        # Try to use request headers (works if app is directly accessible)
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': request.environ.get('SERVER_PORT', '443' if request.scheme == 'https' else '80'),
            'script_name': Config.APP_BASE_PATH if hasattr(Config, 'APP_BASE_PATH') else '',
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            'query_string': request.query_string.decode('utf-8')
        }

def init_saml_auth(req):
    """Initialize SAML auth with settings"""
    if not SAML_ENABLED:
        return None
    auth = OneLogin_Saml2_Auth(req, get_saml_settings())
    return auth

# ============================================

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
    """Handle LDAP login form"""
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
        return render_template('login.html', 
                             next_url=next_url,
                             saml_enabled=SAML_ENABLED,
                             saml_login_url=build_url('/saml/login'))
    
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
    
@app.route('/saml/login')
def saml_login():
    """Initiate SAML SSO login"""
    if not SAML_ENABLED:
        return "SSO is not enabled", 403
    
    # Store next URL in session
    if request.args.get('next'):
        session['next_url'] = request.args.get('next')
    
    # Get IdP SSO URL from metadata
    try:
        from saml_config import get_saml_settings
        settings = get_saml_settings()
        idp_sso_url = settings['idp']['singleSignOnService']['url']
        entity_id = settings['sp']['entityId']
    except Exception as e:
        logger.error(f"Failed to get SAML settings: {e}")
        return "SSO configuration error", 500
    
    # Build the redirect URL with SPID paramete
    if '?' in idp_sso_url:
        sso_redirect_url = f"{idp_sso_url}&SPID={entity_id}"
    else:
        sso_redirect_url = f"{idp_sso_url}?SPID={entity_id}"
    
    logger.info(f"Redirecting to SSO: {sso_redirect_url}")
    logger.info(f"Entity ID (SPID): {entity_id}")
    
    return redirect(sso_redirect_url)


@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service - handles SSO response"""
    if not SAML_ENABLED:
        return "SSO is not enabled", 403
    
    req = prepare_flask_request(request)
    
    # Log the URL information for debugging
    logger.info(f"SAML ACS called - Request details:")
    logger.info(f"  - HTTPS: {req['https']}")
    logger.info(f"  - Host: {req['http_host']}")
    logger.info(f"  - Port: {req['server_port']}")
    logger.info(f"  - Script Name: {req['script_name']}")
    logger.info(f"  - Expected ACS URL: https://{req['http_host']}{req['script_name']}/saml/acs")
    
    auth = init_saml_auth(req)
    
    # Log the expected Entity ID and store it for comparison
    expected_entity_id = None
    try:
        settings = auth.get_settings()
        expected_entity_id = settings.get_sp_data().get('entityId')
        logger.info(f"  - Expected Entity ID (Audience): {expected_entity_id}")
        print(f"\nExpected Entity ID (Audience): {expected_entity_id}", file=sys.stderr)
    except Exception as e:
        logger.warning(f"Could not get expected Entity ID: {e}")
    
    # ALWAYS try to extract and log the Audience from raw SAML response
    # This runs BEFORE processing, so we can see what was sent even if validation fails
    extracted_audiences = []
    try:
        import xml.etree.ElementTree as ET
        import base64
        
        saml_response = request.form.get('SAMLResponse', '')
        if saml_response:
            decoded = base64.b64decode(saml_response)
            logger.info("=" * 70)
            logger.info("SAML RESPONSE RECEIVED")
            logger.info("=" * 70)
            logger.info(f"Response size: {len(decoded)} bytes")
            
            # Try to parse and find Audience
            root = ET.fromstring(decoded)
            namespaces = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
            }
            
            # Find all Audience elements
            audiences = root.findall('.//saml:Audience', namespaces)
            if audiences:
                logger.info("AUDIENCE(S) IN SAML RESPONSE:")
                print("\n" + "=" * 70, file=sys.stderr)
                print("AUDIENCE(S) IN SAML RESPONSE:", file=sys.stderr)
                for i, aud in enumerate(audiences, 1):
                    logger.info(f"  [{i}] {aud.text}")
                    print(f"  [{i}] {aud.text}", file=sys.stderr)
                    extracted_audiences.append(aud.text)
                print("=" * 70 + "\n", file=sys.stderr)
            else:
                logger.warning("âš ï¸  NO AUDIENCE FOUND IN SAML RESPONSE!")
                print("âš ï¸  NO AUDIENCE FOUND IN SAML RESPONSE!", file=sys.stderr)
            
            # Also log the Issuer for reference
            issuers = root.findall('.//saml:Issuer', namespaces)
            if issuers:
                logger.info(f"Issuer: {issuers[0].text}")
            
            # Log NameID if present
            name_ids = root.findall('.//saml:NameID', namespaces)
            if name_ids:
                logger.info(f"NameID: {name_ids[0].text}")
            
            logger.info("=" * 70)
        else:
            logger.error("NO SAMLResponse IN POST DATA!")
            logger.error(f"POST data keys: {list(request.form.keys())}")
    except Exception as parse_error:
        logger.error(f"FAILED TO PARSE SAML RESPONSE: {parse_error}", exc_info=True)
    
    # Now process the response
    try:
        auth.process_response()
        logger.info("SAML response processed successfully")
    except Exception as e:
        logger.error(f"SAML response processing exception: {e}", exc_info=True)
        return f"SSO Authentication failed: {str(e)}", 400
    
    errors = auth.get_errors()
    
    # Log all SAML processing details for debugging
    if errors:
        logger.error("=" * 70)
        logger.error("SAML VALIDATION FAILED")
        logger.error("=" * 70)
        logger.error(f"Errors: {errors}")
        error_reason = auth.get_last_error_reason() if hasattr(auth, 'get_last_error_reason') else 'Unknown'
        logger.error(f"Error reason: {error_reason}")
        
        # Show comparison if we extracted audiences
        if extracted_audiences:
            logger.error("AUDIENCE COMPARISON:")
            logger.error(f"  Expected: {expected_entity_id}")
            logger.error(f"  Received: {extracted_audiences[0] if extracted_audiences else 'NONE'}")
            
            print("\n" + "=" * 70, file=sys.stderr)
            print("AUDIENCE COMPARISON:", file=sys.stderr)
            print(f"  Expected: {expected_entity_id}", file=sys.stderr)
            print(f"  Received: {extracted_audiences[0]}", file=sys.stderr)
            
            if extracted_audiences and expected_entity_id != extracted_audiences[0]:
                logger.error("  âŒ MISMATCH!")
                logger.error("")
                logger.error("TO FIX: Your SSO team needs to configure the IdP with:")
                logger.error(f"  Entity ID: {expected_entity_id}")
                logger.error(f"  (Currently using: {extracted_audiences[0]})")
                
                print("  âŒ MISMATCH!", file=sys.stderr)
                print("", file=sys.stderr)
                print("TO FIX: Your SSO team needs to configure the IdP with:", file=sys.stderr)
                print(f"  Entity ID: {expected_entity_id}", file=sys.stderr)
                print(f"  (Currently using: {extracted_audiences[0]})", file=sys.stderr)
            else:
                logger.error("  âœ“ Match - error is something else")
                print("  âœ“ Match - error is something else", file=sys.stderr)
            
            print("=" * 70 + "\n", file=sys.stderr)
        
        logger.error("=" * 70)
    else:
        logger.info("âœ“ No SAML processing errors")
    
    logger.info(f"SAML is_authenticated: {auth.is_authenticated()}")
    
    # Check if authenticated - this is more reliable than checking errors
    if auth.is_authenticated():
        # PRIMARY: Extract username from NameID (this is what SSO sends)
        username = auth.get_nameid()
        
        if not username:
            logger.error("SAML response missing NameID")
            return "SSO Authentication failed: No NameID in response", 400
        
        logger.info(f"SAML NameID received: {username}")
        
        # OPTIONAL: Try to get attributes if they exist (but don't require them)
        try:
            saml_attributes = auth.get_attributes()
            if saml_attributes:
                logger.info(f"SAML attributes received: {list(saml_attributes.keys())}")
                
                # Try common attribute names for username (override NameID if found)
                for attr in ['uid', 'username', 'sAMAccountName', 'email', 'mail']:
                    if attr in saml_attributes and saml_attributes[attr]:
                        username = saml_attributes[attr][0]
                        logger.info(f"Using username from attribute '{attr}': {username}")
                        break
            else:
                logger.info("No SAML attributes in response (using NameID only)")
        except Exception as e:
            # If getting attributes fails, just log and continue with NameID
            logger.warning(f"Could not retrieve SAML attributes: {e}. Using NameID only.")
        
        # Clean username (remove domain if present)
        if '\\' in username:
            username = username.split('\\')[1]
        elif '@' in username:
            username = username.split('@')[0]
        
        logger.info(f"User {username} authenticated via SSO")
        
        # Get user details from LDAP
        user_data = get_user_details(username)
        if not user_data:
            logger.error(f"User {username} not found in LDAP")
            return f"Access Denied: User {username} not found in LDAP directory", 403
        
        # Check permissions
        permissions = check_user_permissions(user_data['roles'])
        
        if not permissions['can_read'] and not permissions['can_write']:
            logger.warning(f"User {username} has no permissions")
            return "Access Denied: No permissions assigned to your roles", 403
        
        # Filter roles to only show relevant ones
        relevant_roles = [
            role for role in user_data['roles']
            if role in Config.LDAP_DEFAULT_READ_ROLES or role in Config.LDAP_DEFAULT_WRITE_ROLES
        ]
        
        # Create session
        session['user'] = {
            'username': user_data['username'],
            'email': user_data.get('email'),
            'full_name': user_data.get('full_name', username),
            'roles': user_data['roles'],
            'relevant_roles': relevant_roles,
            'permissions': permissions,
            'allowed_commands': permissions['allowed_commands'],
            'auth_method': 'saml'
        }
        session['samlSessionIndex'] = auth.get_session_index()
        session['samlNameId'] = username
        session.permanent = True
        
        logger.info(f"User {username} logged in via SSO with permissions: {permissions}")
        
        # Redirect to next URL or home
        next_url = session.pop('next_url', None)
        if next_url:
            return redirect(next_url)
        return redirect(build_url('/'))
        
    else:
        # Authentication failed
        error_reason = auth.get_last_error_reason() if hasattr(auth, 'get_last_error_reason') else 'Unknown error'
        
        # Log detailed error information
        logger.error(f"SAML auth failed. Errors: {errors}")
        logger.error(f"Error reason: {error_reason}")
        
        # Check if it's just a missing AttributeStatement (which we don't need)
        if errors and any('AttributeStatement' in str(err) for err in errors):
            logger.warning("AttributeStatement missing but this is expected. Checking if NameID exists...")
            
            # Try to get NameID anyway
            try:
                username = auth.get_nameid()
                if username:
                    logger.info(f"NameID found despite AttributeStatement error: {username}")
                    # Continue with authentication using NameID
                    # Clean username
                    if '\\' in username:
                        username = username.split('\\')[1]
                    elif '@' in username:
                        username = username.split('@')[0]
                    
                    # Get user from LDAP
                    user_data = get_user_details(username)
                    if not user_data:
                        return f"Access Denied: User {username} not found in LDAP", 403
                    
                    permissions = check_user_permissions(user_data['roles'])
                    if not permissions['can_read'] and not permissions['can_write']:
                        return "Access Denied: No permissions", 403
                    
                    relevant_roles = [
                        role for role in user_data['roles']
                        if role in Config.LDAP_DEFAULT_READ_ROLES or role in Config.LDAP_DEFAULT_WRITE_ROLES
                    ]
                    
                    session['user'] = {
                        'username': user_data['username'],
                        'email': user_data.get('email'),
                        'full_name': user_data.get('full_name', username),
                        'roles': user_data['roles'],
                        'relevant_roles': relevant_roles,
                        'permissions': permissions,
                        'allowed_commands': permissions['allowed_commands'],
                        'auth_method': 'saml'
                    }
                    session['samlSessionIndex'] = auth.get_session_index()
                    session['samlNameId'] = username
                    session.permanent = True
                    
                    logger.info(f"User {username} logged in via SSO (bypassed AttributeStatement check)")
                    
                    next_url = session.pop('next_url', None)
                    if next_url:
                        return redirect(next_url)
                    return redirect(build_url('/'))
            except Exception as e:
                logger.error(f"Could not extract NameID: {e}")
        
        return f"SSO Authentication failed: {error_reason}", 400



@app.route('/saml/info')
def saml_info():
    """Show SAML configuration info in human-readable format"""
    if not SAML_ENABLED:
        return """
        <html>
        <head><title>SAML Not Enabled</title></head>
        <body>
        <h1>❌ SAML SSO is NOT ENABLED</h1>
        <p>Check your configuration and application logs.</p>
        <p><a href="/saml/debug">/saml/debug</a> for JSON details</p>
        </body>
        </html>
        """, 503
    
    try:
        from saml_config import get_saml_settings
        settings = get_saml_settings()
        
        entity_id = settings['sp']['entityId']
        acs_url = settings['sp']['assertionConsumerService']['url']
        sls_url = settings['sp']['singleLogoutService']['url']
        
        # Get SSO redirect URL from metadata
        idp_sso_url = settings['idp']['singleSignOnService']['url']
        
        if '?' in idp_sso_url:
            sso_redirect_url = f"{idp_sso_url}&SPID={entity_id}"
        else:
            sso_redirect_url = f"{idp_sso_url}?SPID={entity_id}"
        
        html = f"""
        <html>
        <head>
            <title>SAML Configuration</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .box {{ background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                .success {{ background: #d4edda; border-left: 4px solid #28a745; }}
                .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
                .info {{ background: #d1ecf1; border-left: 4px solid #0dcaf0; }}
                code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
                h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
                .copy-btn {{ margin-left: 10px; padding: 5px 10px; cursor: pointer; }}
            </style>
        </head>
        <body>
            <h1>SAML SSO Configuration</h1>
            
            <div class="box info">
                <h2 SSO Login Flow</h2>
                <p><strong>When user clicks "Sign in with SSO", they are redirected to:</strong></p>
                <p><code id="sso-redirect" style="display: block; margin: 10px 0; padding: 10px; background: white;">{sso_redirect_url}</code>
                <button class="copy-btn" onclick="copyToClipboard('sso-redirect')">ðŸ"‹ Copy</button>
                </p>
                <p style="font-size: 13px; color: #666;">
                    <strong>Source:</strong> IdP metadata file (SingleSignOnService Location)<br>
                    <strong>SPID Parameter:</strong> {entity_id}
                </p>
            </div>
            
            <div class="box success">
                <h2>Your Service Provider (SP) Details</h2>
                <p><strong>Entity ID (Audience):</strong><br>
                <code id="entity-id">{entity_id}</code>
                <button class="copy-btn" onclick="copyToClipboard('entity-id')">📋 Copy</button>
                </p>
                
                <p><strong>ACS URL (where IdP sends response):</strong><br>
                <code id="acs-url">{acs_url}</code>
                <button class="copy-btn" onclick="copyToClipboard('acs-url')">📋 Copy</button>
                </p>
                
                <p><strong>SLS URL (single logout):</strong><br>
                <code id="sls-url">{sls_url}</code>
                <button class="copy-btn" onclick="copyToClipboard('sls-url')">📋 Copy</button>
                </p>
            </div>
            
            <div class="box warning">
                <h2>⚠️ Important for SSO Team</h2>
                <p>Your IdP <strong>MUST</strong> be configured with:</p>
                <ul>
                    <li><strong>Entity ID:</strong> <code>{entity_id}</code> (EXACT match, case-sensitive)</li>
                    <li><strong>ACS URL:</strong> <code>{acs_url}</code></li>
                    <li><strong>SAML Response Audience:</strong> Must be <code>{entity_id}</code></li>
                    <li><strong>NameID:</strong> Send username (we don't need attributes)</li>
                </ul>
            </div>
            
            <div class="box">
                <h2>📥 Download Your SP Metadata</h2>
                <p>Send this file to your SSO team:</p>
                <p><a href="/saml/metadata" target="_blank">Download SP Metadata XML</a></p>
                <p><small>Right-click → Save as → sp-metadata.xml</small></p>
            </div>
            
            <div class="box">
                <h2>🔧 Configuration Check</h2>
                <p><strong>WEB_PROXY_ALIAS:</strong> {Config.WEB_PROXY_ALIAS if hasattr(Config, 'WEB_PROXY_ALIAS') else 'NOT SET'}</p>
                <p><strong>APP_BASE_PATH:</strong> {Config.APP_BASE_PATH if hasattr(Config, 'APP_BASE_PATH') else 'NOT SET'}</p>
                <p><strong>SAML_ACS_PATH:</strong> {Config.SAML_ACS_PATH if hasattr(Config, 'SAML_ACS_PATH') else 'NOT SET'}</p>
            </div>
            
            <div class="box">
                <h2>🧪 Test SAML Login</h2>
                <p><a href="/saml/login">Click here to test SAML SSO login</a></p>
                <p><small>This will redirect you to your IdP for authentication</small></p>
            </div>
            
            <div class="box">
                <h2>📊 Debug Information</h2>
                <p><a href="/saml/debug">JSON Debug Output</a> - Technical details</p>
                <p><a href="/debug-proxy">Proxy Configuration</a> - Proxy setup details</p>
            </div>
            
            <script>
                function copyToClipboard(elementId) {{
                    const text = document.getElementById(elementId).textContent;
                    navigator.clipboard.writeText(text).then(() => {{
                        alert('Copied to clipboard: ' + text);
                    }});
                }}
            </script>
        </body>
        </html>
        """
        return html
    except Exception as e:
        return f"""
        <html>
        <head><title>SAML Configuration Error</title></head>
        <body>
        <h1>❌ Error Loading SAML Configuration</h1>
        <p>{str(e)}</p>
        <p><a href="/saml/debug">/saml/debug</a> for more details</p>
        </body>
        </html>
        """, 500


@app.route('/saml/metadata')
def saml_metadata():
    """Provide SP metadata for IdP configuration"""
    if not SAML_ENABLED:
        return "SSO is not enabled", 403
    
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    
    if len(errors) == 0:
        return metadata, 200, {'Content-Type': 'text/xml'}
    else:
        return ', '.join(errors), 500


@app.route('/saml/debug')
def saml_debug():
    """Debug endpoint to check SAML configuration"""
    debug_info = {
        'saml_enabled': SAML_ENABLED,
        'saml_config_issues': saml_config_issues if not SAML_ENABLED else [],
        'config_values': {},
        'url_construction': {},
        'sso_redirect': {}
    }
    
    # Check each config value
    config_checks = [
        'SAML_IDP_METADATA_FILE',
        'WEB_PROXY_ALIAS',
        'SAML_ACS_PATH',
        'APP_BASE_PATH',
        'SSO_SAML_IDP'
    ]
    
    for key in config_checks:
        if hasattr(Config, key):
            value = getattr(Config, key)
            # Don't expose full file paths or sensitive data
            if 'FILE' in key or 'PATH' in key:
                debug_info['config_values'][key] = 'SET' if value else 'EMPTY'
            else:
                debug_info['config_values'][key] = value if value else 'EMPTY'
        else:
            debug_info['config_values'][key] = 'NOT SET'
    
    # Show how URLs will be constructed
    if hasattr(Config, 'WEB_PROXY_ALIAS') and Config.WEB_PROXY_ALIAS:
        from urllib.parse import urlparse
        parsed = urlparse(Config.WEB_PROXY_ALIAS)
        
        debug_info['url_construction'] = {
            'web_proxy_alias': Config.WEB_PROXY_ALIAS,
            'parsed_scheme': parsed.scheme,
            'parsed_netloc': parsed.netloc,
            'app_base_path': getattr(Config, 'APP_BASE_PATH', ''),
            'saml_acs_path': getattr(Config, 'SAML_ACS_PATH', '/saml/acs'),
            'constructed_acs_url': f"{Config.WEB_PROXY_ALIAS}{getattr(Config, 'APP_BASE_PATH', '')}{getattr(Config, 'SAML_ACS_PATH', '/saml/acs')}"
        }
    
    # If SAML is enabled, show the settings
    if SAML_ENABLED:
        try:
            from saml_config import get_saml_settings
            settings = get_saml_settings()
            debug_info['saml_settings'] = {
                'acs_url': settings['sp']['assertionConsumerService']['url'],
                'entity_id': settings['sp']['entityId'],
                'idp_entity_id': settings['idp']['entityId'],
                'idp_sso_url': settings['idp']['singleSignOnService']['url'],
                'security': {
                    'wantAttributeStatement': settings['security']['wantAttributeStatement'],
                    'wantAssertionsSigned': settings['security']['wantAssertionsSigned'],
                    'wantNameId': settings['security']['wantNameId']
                }
            }
            
            # Show what SSO redirect URL will be used
            entity_id = settings['sp']['entityId']
            idp_sso_url = settings['idp']['singleSignOnService']['url']
            
            if '?' in idp_sso_url:
                sso_redirect_url = f"{idp_sso_url}&SPID={entity_id}"
            else:
                sso_redirect_url = f"{idp_sso_url}?SPID={entity_id}"
            
            debug_info['sso_redirect'] = {
                'entity_id': entity_id,
                'idp_sso_url': idp_sso_url,
                'idp_sso_url_source': 'metadata',
                'full_redirect_url': sso_redirect_url
            }
        except Exception as e:
            debug_info['settings_error'] = str(e)
    
    return jsonify(debug_info)


@app.route('/saml/sls')
def saml_sls():
    """SAML Single Logout Service"""
    if not SAML_ENABLED:
        return "SSO is not enabled", 403
    
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    
    url = auth.process_slo()
    errors = auth.get_errors()
    
    if len(errors) == 0:
        if url is not None:
            return redirect(url)
        else:
            session.clear()
            return redirect(build_url('/login'))
    else:
        return "Error processing logout", 400

@app.route('/history')
def get_history():
    """Get command history - requires authentication"""
    if 'user' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    history = load_command_history()
    return jsonify({'history': history[:50]})  # Return last 50

@app.route('/logout')
def logout():
    """Handle logout (both LDAP and SAML)"""
    username = session.get('user', {}).get('username', 'unknown')
    auth_method = session.get('user', {}).get('auth_method', 'ldap')
    
    logger.info(f"User {username} logging out (auth method: {auth_method})")
    
    # If logged in via SAML, do SAML logout
    if auth_method == 'saml' and SAML_ENABLED:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        
        name_id = session.get('samlNameId')
        session_index = session.get('samlSessionIndex')
        
        session.clear()
        
        # Redirect to IdP logout
        return redirect(auth.logout(
            name_id=name_id,
            session_index=session_index
        ))
    else:
        # LDAP logout - just clear session
        session.clear()
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
    
@app.route('/upload', methods=['POST'])
@login_required
@write_permission_required
def upload_file():
    """Handle CSV file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Only CSV and TXT files are allowed'}), 400
    
    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        user = session['user']['username']
        safe_filename = f"{user}_{timestamp}_{filename}"
        
        filepath = UPLOAD_FOLDER / safe_filename
        file.save(str(filepath))
        
        logger.info(f"User {user} uploaded file: {safe_filename}")
        
        return jsonify({
            'success': True,
            'filename': safe_filename,
            'original_filename': filename,
            'size': filepath.stat().st_size
        })
    
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/console-execute', methods=['POST'])
@login_required
@write_permission_required
def console_execute():
    """Execute console control command with uploaded CSV"""
    data = request.json
    csv_filename = data.get('csv_filename')
    
    if not csv_filename:
        return jsonify({'error': 'No CSV file specified'}), 400
    
    user = session['user']
    filepath = UPLOAD_FOLDER / csv_filename
    
    if not filepath.exists():
        return jsonify({'error': 'CSV file not found'}), 404
    
    if 'console_control' not in user.get('allowed_commands', []):
        logger.warning(f"User {user['username']} attempted unauthorized command: console_control")
        return jsonify({'error': 'Console control command not allowed for your roles'}), 403
    
    logger.info(f"User {user['username']} executing console_control with {csv_filename}")
    
    try:
        console_script = getattr(Config, 'CONSOLE_CONTROL_PATH', '/path/to/console_control.sh')
        cmd = [console_script, 'booking_load', str(filepath)]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300,
            cwd=filepath.parent
        )
        
        save_command_to_history(
            'console_control', 
            ['booking_load', csv_filename], 
            result.returncode == 0, 
            user['username']
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'executed_by': user['username'],
            'csv_file': csv_filename
        })
    
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timeout (max 5 minutes)'}), 408
    except Exception as e:
        logger.error(f"Console control execution failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    """Download uploaded file (for verification)"""
    user = session['user']['username']
    if not filename.startswith(user + '_'):
        return jsonify({'error': 'Access denied'}), 403
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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