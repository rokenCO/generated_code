#!/usr/bin/env python3
"""
LDAP Connection Test Script
Run this before deploying to verify LDAP connectivity and configuration
"""

from ldap3 import Server, Connection, ALL, SUBTREE, Tls
import ssl
import sys
from config import Config

def test_ldap_connection():
    """Test LDAP connection and service account"""
    print("=" * 60)
    print("LDAP CONNECTION TEST")
    print("=" * 60)
    
    # Display configuration
    print("\n[1] Configuration:")
    print(f"   LDAP URL: {Config.LDAP_SERVICE_URL}")
    print(f"   Service DN: {Config.LDAP_SERVICE_DN}")
    print(f"   Search Base: dc=root")
    print(f"   Password set: {'Yes' if Config.LDAP_SERVICE_PASSWORD else 'No'}")
    
    if not Config.LDAP_SERVICE_PASSWORD:
        print("\n❌ ERROR: LDAP_SERVICE_PASSWORD not set!")
        return False
    
    # Test connection
    print("\n[2] Testing LDAP Connection...")
    try:
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
        
        print(f"   Server: {server}")
        
        conn = Connection(
            server,
            user=Config.LDAP_SERVICE_DN,
            password=Config.LDAP_SERVICE_PASSWORD,
            auto_bind=True,
            raise_exceptions=True
        )
        
        print("   ✅ Connection successful!")
        print(f"   Bound as: {conn.extend.standard.who_am_i()}")
        
    except Exception as e:
        print(f"   ❌ Connection failed: {str(e)}")
        return False
    
    # Test search capability
    print("\n[3] Testing Search Capability...")
    try:
        # Search for all users (limit to 5 for testing)
        conn.search(
            search_base='dc=root',
            search_filter='(objectClass=person)',
            search_scope=SUBTREE,
            attributes=['cn', 'uid', 'mail', 'memberOf'],
            size_limit=5
        )
        
        print(f"   ✅ Search successful! Found {len(conn.entries)} users (max 5)")
        
        if conn.entries:
            print("\n   Sample users:")
            for entry in conn.entries[:3]:
                uid = entry.uid.value if hasattr(entry, 'uid') else 'N/A'
                cn = entry.cn.value if hasattr(entry, 'cn') else 'N/A'
                print(f"      - {uid} ({cn})")
        else:
            print("   ⚠️  Warning: No users found. Check search base 'dc=root'")
            
    except Exception as e:
        print(f"   ❌ Search failed: {str(e)}")
        conn.unbind()
        return False
    
    # Test specific user lookup
    print("\n[4] Testing User Lookup...")
    test_username = input("   Enter a username to test (or press Enter to skip): ").strip()
    
    if test_username:
        try:
            user_filter = f'(uid={test_username})'
            conn.search(
                search_base='dc=root',
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=['cn', 'mail', 'memberOf', 'employeeType', 'uid']
            )
            
            if conn.entries:
                print(f"   ✅ User '{test_username}' found!")
                user = conn.entries[0]
                
                print("\n   User Details:")
                print(f"      DN: {user.entry_dn}")
                print(f"      CN: {user.cn.value if hasattr(user, 'cn') else 'N/A'}")
                print(f"      Email: {user.mail.value if hasattr(user, 'mail') else 'N/A'}")
                
                if hasattr(user, 'memberOf'):
                    print(f"      Groups:")
                    for group_dn in user.memberOf:
                        group_cn = str(group_dn).split(',')[0].replace('cn=', '').replace('CN=', '')
                        print(f"         - {group_cn}")
                    
                    # Check permissions
                    roles = [str(g).split(',')[0].replace('cn=', '').replace('CN=', '') 
                             for g in user.memberOf]
                    
                    can_read = any(role in Config.LDAP_DEFAULT_READ_ROLES for role in roles)
                    can_write = any(role in Config.LDAP_DEFAULT_WRITE_ROLES for role in roles)
                    
                    print("\n   Permission Check:")
                    print(f"      Read permission: {'✅ Yes' if can_read else '❌ No'}")
                    print(f"      Write permission: {'✅ Yes' if can_write else '❌ No'}")
                    
                    if not can_read and not can_write:
                        print(f"      ⚠️  User has no permissions (not in any authorized groups)")
                        print(f"      Read roles: {Config.LDAP_DEFAULT_READ_ROLES}")
                        print(f"      Write roles: {Config.LDAP_DEFAULT_WRITE_ROLES}")
                else:
                    print("      Groups: None (no memberOf attribute)")
                    print("      ⚠️  Warning: User has no group memberships")
                    
            else:
                print(f"   ❌ User '{test_username}' not found")
                print(f"   Search filter used: {user_filter}")
                
        except Exception as e:
            print(f"   ❌ User lookup failed: {str(e)}")
    
    # Cleanup
    conn.unbind()
    
    print("\n[5] Testing Authorization Configuration...")
    print(f"   Read roles: {Config.LDAP_DEFAULT_READ_ROLES}")
    print(f"   Write roles: {Config.LDAP_DEFAULT_WRITE_ROLES}")
    
    if not Config.LDAP_DEFAULT_READ_ROLES and not Config.LDAP_DEFAULT_WRITE_ROLES:
        print("   ⚠️  Warning: No roles configured for access!")
        return False
    
    print("\n" + "=" * 60)
    print("✅ LDAP CONNECTION TEST COMPLETED SUCCESSFULLY")
    print("=" * 60)
    return True

def main():
    try:
        success = test_ldap_connection()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
