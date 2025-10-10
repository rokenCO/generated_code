# saml_config.py
import xml.etree.ElementTree as ET
import json
from config import Config

def generate_saml_settings():
    """Generate SAML settings from your existing IDP metadata"""
    
    # Parse your existing IDP metadata
    tree = ET.parse(Config.SAML_IDP_METADATA_FILE)
    root = tree.getroot()
    
    # First, let's detect what namespaces are actually used in your file
    # This will handle any prefix (ns2, ns4, md, etc.)
    namespaces = dict([
        node for _, node in ET.iterparse(
            Config.SAML_IDP_METADATA_FILE, 
            events=['start-ns']
        )
    ])
    
    # Common SAML namespace URIs (the prefixes might be different)
    SAML_METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata'
    XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#'
    
    # Find the actual prefixes used in your file
    md_prefix = None
    ds_prefix = None
    
    for prefix, uri in namespaces.items():
        if uri == SAML_METADATA_NS:
            md_prefix = prefix
        elif uri == XMLDSIG_NS:
            ds_prefix = prefix
    
    # Build namespace map with actual prefixes
    ns = {}
    if md_prefix is not None:
        ns['md'] = SAML_METADATA_NS
    if ds_prefix is not None:
        ns['ds'] = XMLDSIG_NS
    
    # Alternative approach - find elements without relying on prefixes
    # This is more robust and works regardless of namespace prefixes
    
    # Find SSO Service URL
    sso_service = None
    for elem in root.iter():
        if elem.tag.endswith('SingleSignOnService'):
            binding = elem.get('Binding', '')
            if 'HTTP-Redirect' in binding or 'HTTP-POST' in binding:
                sso_service = elem
                break
    
    sso_url = sso_service.get('Location') if sso_service is not None else ''
    
    # Find SLO Service URL
    slo_service = None
    for elem in root.iter():
        if elem.tag.endswith('SingleLogoutService'):
            binding = elem.get('Binding', '')
            if 'HTTP-Redirect' in binding:
                slo_service = elem
                break
    
    slo_url = slo_service.get('Location') if slo_service is not None else ''
    
    # Find X509 Certificate
    cert_elem = None
    for elem in root.iter():
        if elem.tag.endswith('X509Certificate'):
            cert_elem = elem
            break
    
    idp_cert = cert_elem.text.strip() if cert_elem is not None else ''
    
    # Get EntityID (usually an attribute of the root or EntityDescriptor element)
    entity_id = Config.SSO_SAML_IDP  # Use from environment
    for elem in root.iter():
        if elem.tag.endswith('EntityDescriptor'):
            entity_id = elem.get('entityID', Config.SSO_SAML_IDP)
            break
    
    print(f"Found SSO URL: {sso_url}")
    print(f"Found SLO URL: {slo_url}")
    print(f"Found EntityID: {entity_id}")
    print(f"Certificate found: {'Yes' if idp_cert else 'No'}")
    
    # Build settings compatible with python3-saml
    settings = {
        "sp": {
            "entityId": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}",
            "assertionConsumerService": {
                "url": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}{Config.SAML_ASC_PATH}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": f"{Config.WEB_PROXY_ALIAS}{Config.APP_BASE_PATH}/saml/sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "x509cert": "",
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
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": False,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAttributeStatement": True,
            "requestedAuthnContext": True,
            "requestedAuthnContextComparison": "exact",
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
        }
    }
    
    return settings

def inspect_metadata_file():
    """Helper function to inspect your metadata file structure"""
    tree = ET.parse(Config.SAML_IDP_METADATA_FILE)
    root = tree.getroot()
    
    print("\n=== Metadata File Structure ===")
    print(f"Root tag: {root.tag}")
    print(f"Root attributes: {root.attrib}")
    
    print("\n=== Namespaces in use ===")
    for prefix, uri in root.nsmap.items() if hasattr(root, 'nsmap') else []:
        print(f"  {prefix}: {uri}")
    
    print("\n=== Key elements found ===")
    for elem in root.iter():
        if any(key in elem.tag for key in ['SingleSignOn', 'SingleLogout', 'X509', 'EntityDescriptor']):
            print(f"  Tag: {elem.tag}")
            print(f"  Attributes: {elem.attrib}")
            if elem.text and elem.tag.endswith('X509Certificate'):
                print(f"  Certificate: {elem.text[:50]}...")
    
    return root

# If you want to debug/inspect your metadata file
if __name__ == "__main__":
    # This will help you see the structure of your metadata
    inspect_metadata_file()
    
    # Generate and print settings
    settings = generate_saml_settings()
    print("\n=== Generated SAML Settings ===")
    print(json.dumps(settings, indent=2))
