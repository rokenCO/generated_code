#!/usr/bin/env python3
"""
Database Connection Test Script
Tests connections to PKS, PDS, and FOST databases for Corporate Actions feature
"""

import os
import sys

# Check if psycopg2 is installed
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    print("✓ psycopg2 is installed")
except ImportError:
    print("✗ psycopg2 not found. Install with: pip install psycopg2-binary")
    sys.exit(1)

# Database configurations from environment variables
DB_CONFIGS = {
    'PKS': {
        'host': os.environ.get('PKS_DB_HOST', ''),
        'port': int(os.environ.get('PKS_DB_PORT', 5432)),
        'database': os.environ.get('PKS_DB_NAME', 'pks'),
        'user': os.environ.get('PKS_DB_USER', ''),
        'password': os.environ.get('PKS_DB_PASSWORD', ''),
    },
    'PDS': {
        'host': os.environ.get('PDS_DB_HOST', ''),
        'port': int(os.environ.get('PDS_DB_PORT', 5432)),
        'database': os.environ.get('PDS_DB_NAME', 'pds'),
        'user': os.environ.get('PDS_DB_USER', ''),
        'password': os.environ.get('PDS_DB_PASSWORD', ''),
    },
    'FOST': {
        'host': os.environ.get('FOST_DB_HOST', ''),
        'port': int(os.environ.get('FOST_DB_PORT', 5432)),
        'database': os.environ.get('FOST_DB_NAME', 'fost'),
        'user': os.environ.get('FOST_DB_USER', ''),
        'password': os.environ.get('FOST_DB_PASSWORD', ''),
    }
}

# Required tables for each database (schema-qualified)
REQUIRED_TABLES = {
    'PKS': ['pks.booking_leg'],
    'PDS': ['pds.symbol'],
    'FOST': ['fost.bloomberg_cax_2025', 'fost.bloomberg_varfields_2025']
}

# Test queries for each database (with schema-qualified table names)
TEST_QUERIES = {
    'PKS': {
        'active_bookings': """
            SELECT COUNT(*) as count 
            FROM pks.booking_leg 
            WHERE to_ts > CURRENT_TIMESTAMP
        """,
        'unique_instruments': """
            SELECT COUNT(DISTINCT instr_id) as count 
            FROM pks.booking_leg 
            WHERE to_ts > CURRENT_TIMESTAMP
        """
    },
    'PDS': {
        'total_symbols': """
            SELECT COUNT(*) as count 
            FROM pds.symbol 
            WHERE to_ts > CURRENT_TIMESTAMP
        """,
        'unique_instruments': """
            SELECT COUNT(DISTINCT id) as count 
            FROM pds.symbol 
            WHERE to_ts > CURRENT_TIMESTAMP
        """
    },
    'FOST': {
        'total_cas': """
            SELECT COUNT(*) as count 
            FROM fost.bloomberg_cax_2025
        """,
        'future_cas': """
            SELECT COUNT(*) as count 
            FROM fost.bloomberg_cax_2025 
            WHERE bceffdate >= CURRENT_DATE
        """,
        'ca_types': """
            SELECT bcmnemonic, COUNT(*) as count 
            FROM fost.bloomberg_cax_2025 
            WHERE bceffdate >= CURRENT_DATE 
            GROUP BY bcmnemonic 
            ORDER BY count DESC 
            LIMIT 5
        """
    }
}


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def test_connection(db_name, config):
    """Test database connection"""
    print(f"\n[{db_name}] Testing connection...")
    
    # Check if credentials are provided
    if not config['host']:
        print(f"  ✗ {db_name}_DB_HOST not set")
        return None
    if not config['user']:
        print(f"  ✗ {db_name}_DB_USER not set")
        return None
    if not config['password']:
        print(f"  ⚠ {db_name}_DB_PASSWORD not set (may be optional)")
    
    print(f"  Host: {config['host']}:{config['port']}")
    print(f"  Database: {config['database']}")
    print(f"  User: {config['user']}")
    
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            database=config['database'],
            user=config['user'],
            password=config['password'],
            connect_timeout=5
        )
        print(f"  ✓ Connection successful")
        return conn
    except psycopg2.OperationalError as e:
        print(f"  ✗ Connection failed: {e}")
        return None
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return None


def check_table_exists(conn, db_name, table_name):
    """Check if a table exists"""
    query = """
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = SPLIT_PART(%s, '.', 1)
              AND table_name = SPLIT_PART(%s, '.', 2)
        );
    """
    
    try:
        with conn.cursor() as cur:
            # Handle schema.table format
            if '.' in table_name:
                schema, table = table_name.split('.')
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = %s AND table_name = %s
                    );
                """, (schema, table))
            else:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = %s
                    );
                """, (table_name,))
            
            exists = cur.fetchone()[0]
            return exists
    except Exception as e:
        print(f"    Error checking table {table_name}: {e}")
        return False


def check_tables(conn, db_name):
    """Check if required tables exist"""
    print(f"\n[{db_name}] Checking required tables...")
    
    all_exist = True
    for table in REQUIRED_TABLES[db_name]:
        exists = check_table_exists(conn, db_name, table)
        if exists:
            print(f"  ✓ Table '{table}' exists")
        else:
            print(f"  ✗ Table '{table}' NOT FOUND")
            all_exist = False
    
    return all_exist


def run_test_queries(conn, db_name):
    """Run diagnostic queries"""
    print(f"\n[{db_name}] Running diagnostic queries...")
    
    queries = TEST_QUERIES.get(db_name, {})
    
    for query_name, query in queries.items():
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query)
                results = cur.fetchall()
                
                if query_name == 'ca_types':
                    print(f"\n  {query_name}:")
                    for row in results:
                        print(f"    {row['bcmnemonic']}: {row['count']}")
                else:
                    count = results[0]['count'] if results else 0
                    print(f"  {query_name}: {count:,}")
        except Exception as e:
            print(f"  ✗ Query '{query_name}' failed: {e}")


def check_permissions(conn, db_name):
    """Check SELECT permissions on tables"""
    print(f"\n[{db_name}] Checking permissions...")
    
    for table in REQUIRED_TABLES[db_name]:
        try:
            # Try to query the table
            with conn.cursor() as cur:
                cur.execute(f"SELECT 1 FROM {table} LIMIT 1")
                cur.fetchone()
            print(f"  ✓ SELECT permission on '{table}'")
        except psycopg2.Error as e:
            print(f"  ✗ No SELECT permission on '{table}': {e}")


def test_data_flow():
    """Test the complete data flow across all databases"""
    print_section("Testing Complete Data Flow")
    
    print("\nThis will test the full pipeline:")
    print("  PKS (bookings) → PDS (symbols) → FOST (corporate actions)")
    
    # Check if all connections are available
    conns = {}
    for db_name, config in DB_CONFIGS.items():
        conn = test_connection(db_name, config)
        if not conn:
            print(f"\n✗ Cannot test data flow - {db_name} connection failed")
            return
        conns[db_name] = conn
    
    print("\n✓ All database connections available")
    
    # Get sample instrument from bookings
    print("\nStep 1: Getting sample instrument from bookings...")
    try:
        with conns['PKS'].cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT instr_id, COUNT(*) as booking_count
                FROM pks.booking_leg
                WHERE to_ts > CURRENT_TIMESTAMP
                GROUP BY instr_id
                ORDER BY COUNT(*) DESC
                LIMIT 1
            """)
            result = cur.fetchone()
            if result:
                sample_instr_id = result['instr_id']
                print(f"  ✓ Found sample instrument: {sample_instr_id} ({result['booking_count']} bookings)")
            else:
                print("  ✗ No active bookings found")
                return
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return
    
    # Map to symbol
    print("\nStep 2: Mapping instrument ID to symbol...")
    try:
        with conns['PDS'].cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, code, symbol_type_id
                FROM pds.symbol
                WHERE id = %s AND to_ts > CURRENT_TIMESTAMP
                ORDER BY to_ts DESC
                LIMIT 1
            """, (sample_instr_id,))
            result = cur.fetchone()
            if result:
                symbol_code = result['code']
                print(f"  ✓ Mapped to symbol: {symbol_code}")
            else:
                print(f"  ✗ No symbol found for instrument {sample_instr_id}")
                return
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return
    
    # Check for CAs
    print("\nStep 3: Checking for corporate actions...")
    try:
        with conns['FOST'].cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    bcticker_exch_code,
                    bccompanyname,
                    bcmnemonic,
                    bceffdate,
                    bceffdate - CURRENT_DATE as days_until
                FROM fost.bloomberg_cax_2025
                WHERE bcticker_exch_code = %s
                  AND bceffdate >= CURRENT_DATE
                ORDER BY bceffdate
                LIMIT 5
            """, (symbol_code,))
            results = cur.fetchall()
            if results:
                print(f"  ✓ Found {len(results)} upcoming corporate action(s):")
                for ca in results:
                    print(f"    - {ca['bcmnemonic']}: {ca['bccompanyname']} on {ca['bceffdate']} ({ca['days_until']} days)")
            else:
                print(f"  ℹ No upcoming corporate actions for {symbol_code}")
                print("    This is normal - not all instruments have upcoming CAs")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return
    
    print("\n✓ Data flow test complete!")
    
    # Close all connections
    for conn in conns.values():
        conn.close()


def main():
    """Main test function"""
    print_section("Corporate Actions Database Connection Test")
    
    print("\nChecking environment variables...")
    env_vars = [
        'PKS_DB_HOST', 'PKS_DB_USER', 'PKS_DB_PASSWORD',
        'PDS_DB_HOST', 'PDS_DB_USER', 'PDS_DB_PASSWORD',
        'FOST_DB_HOST', 'FOST_DB_USER', 'FOST_DB_PASSWORD'
    ]
    
    missing = [var for var in env_vars if not os.environ.get(var)]
    if missing:
        print(f"\n⚠ Warning: The following environment variables are not set:")
        for var in missing:
            print(f"  - {var}")
        print("\nYou can set them with:")
        print("  export VAR_NAME=value")
    else:
        print("✓ All environment variables are set")
    
    # Test each database
    results = {}
    for db_name, config in DB_CONFIGS.items():
        print_section(f"{db_name} Database")
        
        conn = test_connection(db_name, config)
        if conn:
            tables_ok = check_tables(conn, db_name)
            if tables_ok:
                check_permissions(conn, db_name)
                run_test_queries(conn, db_name)
            results[db_name] = conn
        else:
            results[db_name] = None
    
    # Summary
    print_section("Summary")
    
    success = all(results.values())
    
    for db_name, conn in results.items():
        status = "✓ Connected" if conn else "✗ Failed"
        print(f"{db_name:8} {status}")
    
    if success:
        print("\n✓ All databases are accessible!")
        print("\nYou can proceed with deploying the Corporate Actions feature.")
        
        # Run data flow test
        try:
            test_data_flow()
        except Exception as e:
            print(f"\n⚠ Data flow test encountered an error: {e}")
    else:
        print("\n✗ Some databases are not accessible.")
        print("\nPlease fix the connection issues before deploying.")
    
    # Close connections
    for conn in results.values():
        if conn:
            conn.close()
    
    print("\n" + "="*70)


if __name__ == '__main__':
    main()