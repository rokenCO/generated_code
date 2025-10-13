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
    
    # Test search capability with indexed attribute
    print("\n[3] Testing Search Capability...")
    print("   Trying different search strategies...")
    
    search_successful = False
    search_strategies = [
        {
            'name': 'Search by uid (indexed)',
            'filter': '(uid=*)',
            'attributes': ['uid', 'cn', 'mail'],
            'size_limit': 5
        },
        {
            'name': 'Search by cn (indexed)',
            'filter': '(cn=*)',
            'attributes': ['uid', 'cn', 'mail'],
            'size_limit': 5
        },
        {
            'name': 'Search by mail (indexed)',
            'filter': '(mail=*)',
            'attributes': ['uid', 'cn', 'mail'],
            'size_limit': 5
        },
        {
            'name': 'Search organizational units',
            'filter': '(objectClass=organizationalUnit)',
            'attributes': ['ou'],
            'size_limit': 10
        }
    ]
    
    for strategy in search_strategies:
        try:
            print(f"\n   Trying: {strategy['name']}...")
            conn.search(
                search_base='dc=root',
                search_filter=strategy['filter'],
                search_scope=SUBTREE,
                attributes=strategy['attributes'],
                size_limit=strategy['size_limit']
            )
            
            if conn.entries:
                print(f"   ✅ {strategy['name']} successful! Found {len(conn.entries)} entries")
                
                if 'uid' in strategy['attributes']:
                    print("\n   Sample entries:")
                    for entry in conn.entries[:3]:
                        uid = entry.uid.value if hasattr(entry, 'uid') else 'N/A'
                        cn = entry.cn.value if hasattr(entry, 'cn') else 'N/A'
                        print(f"      - uid: {uid}, cn: {cn}")
                    search_successful = True
                    break
                elif 'ou' in strategy['attributes']:
                    print("   Organizational units found:")
                    for entry in conn.entries[:5]:
                        ou = entry.ou.value if hasattr(entry, 'ou') else 'N/A'
                        print(f"      - ou: {ou}")
            else:
                print(f"   ⚠️  No entries found with this search")
                
        except Exception as e:
            print(f"   ❌ {strategy['name']} failed: {str(e)}")
            continue
    
    if not search_successful:
        print("\n   ⚠️  Warning: Could not find users with standard searches")
        print("   This might be normal - let's try a specific user lookup")
    
    # Test specific user lookup
    print("\n[4] Testing Specific User Lookup...")
    test_username = input("   Enter a username to test (or press Enter to skip): ").strip()
    
    if test_username:
        # Try multiple search patterns
        search_patterns = [
            f'(uid={test_username})',
            f'(sAMAccountName={test_username})',
            f'(cn={test_username})',
            f'(userPrincipalName={test_username}@*)'
        ]
        
        user_found = False
        for pattern in search_patterns:
            try:
                print(f"\n   Trying search filter: {pattern}")
                conn.search(
                    search_base='dc=root',
                    search_filter=pattern,
                    search_scope=SUBTREE,
                    attributes=['cn', 'mail', 'memberOf', 'employeeType', 'uid', 'dn']
                )
                
                if conn.entries:
                    print(f"   ✅ User '{test_username}' found!")
                    user = conn.entries[0]
                    user_found = True
                    
                    print("\n   User Details:")
                    print(f"      DN: {user.entry_dn}")
                    
                    # Display all available attributes
                    for attr in ['cn', 'uid', 'mail', 'employeeType']:
                        if hasattr(user, attr):
                            print(f"      {attr}: {getattr(user, attr).value}")
                    
                    if hasattr(user, 'memberOf'):
                        print(f"      Groups:")
                        roles = []
                        for group_dn in user.memberOf:
                            group_cn = str(group_dn).split(',')[0].replace('cn=', '').replace('CN=', '')
                            roles.append(group_cn)
                            print(f"         - {group_cn}")
                        
                        # Check permissions
                        can_read = any(role in Config.LDAP_DEFAULT_READ_ROLES for role in roles)
                        can_write = any(role in Config.LDAP_DEFAULT_WRITE_ROLES for role in roles)
                        
                        print("\n   Permission Check:")
                        print(f"      Read permission: {'✅ Yes' if can_read else '❌ No'}")
                        print(f"      Write permission: {'✅ Yes' if can_write else '❌ No'}")
                        
                        if not can_read and not can_write:
                            print(f"      ⚠️  User has no permissions")
                            print(f"      Configured read roles: {Config.LDAP_DEFAULT_READ_ROLES}")
                            print(f"      Configured write roles: {Config.LDAP_DEFAULT_WRITE_ROLES}")
                    else:
                        print("      Groups: None (no memberOf attribute)")
                        print("      ⚠️  Warning: User has no group memberships")
                    
                    break
                    
            except Exception as e:
                print(f"   ❌ Search with {pattern} failed: {str(e)}")
                continue
        
        if not user_found:
            print(f"\n   ❌ User '{test_username}' not found with any search pattern")
            print("   Possible issues:")
            print("   - Username might be incorrect")
            print("   - User might be in a different OU not under dc=root")
            print("   - LDAP schema might use different attribute names")
    
    # Test authentication simulation
    print("\n[5] Testing Authentication Pattern...")
    print("   This simulates how the app will authenticate users")
    
    if test_username and user_found:
        user_dn = conn.entries[0].entry_dn
        print(f"   Found user DN: {user_dn}")
        
        test_password = input("   Enter password to test bind (or Enter to skip): ").strip()
        if test_password:
            try:
                # Create new connection with user credentials
                test_conn = Connection(
                    server,
                    user=user_dn,
                    password=test_password,
                    raise_exceptions=True
                )
                
                if test_conn.bind():
                    print("   ✅ User authentication successful!")
                    print("   The application will be able to authenticate this user")
                    test_conn.unbind()
                else:
                    print("   ❌ Authentication failed - incorrect password")
                    
            except Exception as e:
                print(f"   ❌ Authentication test failed: {str(e)}")
    
    # Cleanup
    conn.unbind()
    
    print("\n[6] Testing Authorization Configuration...")
    print(f"   Read roles: {Config.LDAP_DEFAULT_READ_ROLES}")
    print(f"   Write roles: {Config.LDAP_DEFAULT_WRITE_ROLES}")
    
    if not Config.LDAP_DEFAULT_READ_ROLES and not Config.LDAP_DEFAULT_WRITE_ROLES:
        print("   ⚠️  Warning: No roles configured for access!")
        return False
    
    print("\n" + "=" * 60)
    print("✅ LDAP CONNECTION TEST COMPLETED")
    print("=" * 60)
    print("\nKey Findings:")
    print(f"  - LDAP connection: ✅ Working")
    print(f"  - Search capability: {'✅ Working' if search_successful or user_found else '⚠️  Limited (but may be sufficient)'}")
    print(f"  - User lookup: {'✅ Tested' if user_found else '⚠️  Not tested'}")
    print("\nThe application should work if:")
    print("  1. Users provide valid usernames")
    print("  2. The service account can search for uid={username}")
    print("  3. Users are in configured role groups")
    
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
