"""
SAML Configuration Generator
Reads yours IdP metadata and generates SAML settings
"""

import xml.etree.ElementTree as ET
from config import Config

def generate_saml_settings():
    """Generate SAML settings from IdP metadata file"""
    
    if not hasattr(Config, 'SAML_IDP_METADATA_FILE'):
        raise ValueError("SAML_IDP_METADATA_FILE not configured")
    
    # Parse IdP metadata XML
    tree = ET.parse(Config.SAML_IDP_METADATA_FILE)
    root = tree.getroot()
    
    # Find SSO Service URL (where to redirect for login)
    sso_service = None
    for elem in root.iter():
        if elem.tag.endswith('SingleSignOnService'):
            binding = elem.get('Binding', '')
            if 'HTTP-Redirect' in binding or 'HTTP-POST' in binding:
                sso_service = elem
                break
    
    sso_url = sso_service.get('Location') if sso_service is not None else ''
    
    # Find SLO Service URL (where to redirect for logout)
    slo_service = None
    for elem in root.iter():
        if elem.tag.endswith('SingleLogoutService'):
            binding = elem.get('Binding', '')
            if 'HTTP-Redirect' in binding:
                slo_service = elem
                break
    
    slo_url = slo_service.get('Location') if slo_service is not None else ''
    
    # Find X509 Certificate (to verify SAML assertions)
    cert_elem = None
    for elem in root.iter():
        if elem.tag.endswith('X509Certificate'):
            cert_elem = elem
            break
    
    idp_cert = cert_elem.text.strip() if cert_elem is not None else ''
    
    # Get EntityID (IdP identifier)
    entity_id = Config.SSO_SAML_IDP
    for elem in root.iter():
        if elem.tag.endswith('EntityDescriptor'):
            entity_id = elem.get('entityID', Config.SSO_SAML_IDP)
            break
    
    print(f"[SAML] Found SSO URL: {sso_url}")
    print(f"[SAML] Found SLO URL: {slo_url}")
    print(f"[SAML] Found EntityID: {entity_id}")
    print(f"[SAML] Certificate: {'Found' if idp_cert else 'Missing!'}")
    
    # Build SAML settings for python3-saml library
    settings = {
        "strict": True,
        "debug": Config.DEBUG if hasattr(Config, 'DEBUG') else False,
        "sp": {
            "entityId": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}",
            "assertionConsumerService": {
                "url": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}{Config.SAML_ACS_PATH}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}/saml/sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "x509cert": "",  # SP doesn't need cert if not signing requests
            "privateKey": ""
        },
        "idp": {
            "entityId": entity_id,
            "singleSignOnService": {
                "url": sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": idp_cert
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": False,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantAssertionsSigned": False,  # Don't require - many IdPs don't sign
            "wantAssertionsEncrypted": False,
            "wantNameId": True,  # We NEED NameID since there are no attributes
            "wantNameIdEncrypted": False,
            "wantAttributeStatement": False,  # IdP doesn't send attributes - use NameID only
            "requestedAuthnContext": False,  # More lenient - don't require specific auth context
            "requestedAuthnContextComparison": "exact",
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "rejectUnsolicitedResponsesWithInResponseTo": False  # Allow unsolicited responses
        }
    }
    
    return settings


def get_saml_settings():
    """Get SAML settings (cached)"""
    if not hasattr(get_saml_settings, '_settings'):
        get_saml_settings._settings = generate_saml_settings()
    return get_saml_settings._settings