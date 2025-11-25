#!/usr/bin/env python3
"""
Corporate Actions Database Module
Handles queries for Bloomberg corporate actions data
WITH SCHEMA-QUALIFIED TABLE NAMES AND BLOOMBERG SUFFIX STRIPPING
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Bloomberg security type suffixes that need to be stripped
BLOOMBERG_SUFFIXES = [
    ' Equity',
    ' Comdty',
    ' Curncy',
    ' Index',
    ' Corp',
    ' Govt',
    ' Mtge',
    ' M-Mkt',
    ' Muni',
    ' Pfd',
]

def strip_bloomberg_suffix(symbol_code):
    """
    Strip Bloomberg security type suffix from symbol
    
    Examples:
        'OSWED S1 Equity' -> 'OSWED S1'
        'GC1 Comdty' -> 'GC1'
        'EURUSD Curncy' -> 'EURUSD'
    
    Args:
        symbol_code: Full Bloomberg symbol code
        
    Returns:
        Symbol code with suffix stripped
    """
    if not symbol_code:
        return symbol_code
    
    for suffix in BLOOMBERG_SUFFIXES:
        if symbol_code.endswith(suffix):
            return symbol_code[:-len(suffix)].strip()
    
    return symbol_code


class CADatabase:
    """Database handler for Corporate Actions queries"""
    
    def __init__(self, pks_config, pds_config, fost_config):
        """
        Initialize with database configurations
        
        Args:
            pks_config: Dict with connection params for pks database
            pds_config: Dict with connection params for pds database
            fost_config: Dict with connection params for fost database
        """
        self.pks_config = pks_config
        self.pds_config = pds_config
        self.fost_config = fost_config
    
    def _get_connection(self, db_config):
        """Create database connection"""
        return psycopg2.connect(
            host=db_config['host'],
            port=db_config.get('port', 5432),
            database=db_config['database'],
            user=db_config['user'],
            password=db_config['password']
        )
    
    def get_current_booking_instruments(self):
        """
        Get unique instruments from current booking positions
        
        Returns:
            List of dicts with instr_id and count of bookings
        """
        query = """
        SELECT 
            instr_id,
            COUNT(*) as booking_count,
            SUM(quantity) as total_quantity
        FROM pks.booking_leg
        WHERE to_ts > CURRENT_TIMESTAMP
        GROUP BY instr_id
        ORDER BY booking_count DESC
        """
        
        try:
            with self._get_connection(self.pks_config) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query)
                    results = cur.fetchall()
                    logger.info(f"Found {len(results)} unique instruments in current bookings")
                    return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Error fetching booking instruments: {e}")
            return []
    
    def map_instr_ids_to_symbols(self, instr_ids):
        """
        Map instrument IDs to their symbol codes (stripped of Bloomberg suffixes)
        
        Args:
            instr_ids: List of integer instrument IDs
            
        Returns:
            Dict mapping instr_id -> symbol_code (with Bloomberg suffix stripped)
        """
        if not instr_ids:
            return {}
        
        # Get current symbol mappings (where to_ts is in the future or max)
        query = """
        WITH ranked_symbols AS (
            SELECT 
                id,
                code,
                symbol_type_id,
                from_ts,
                to_ts,
                ROW_NUMBER() OVER (PARTITION BY id ORDER BY to_ts DESC) as rn
            FROM pds.symbol
            WHERE id = ANY(%s)
              AND to_ts > CURRENT_TIMESTAMP
        )
        SELECT id, code, symbol_type_id
        FROM ranked_symbols
        WHERE rn = 1
        """
        
        try:
            with self._get_connection(self.pds_config) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, (instr_ids,))
                    results = cur.fetchall()
                    
                    # Strip Bloomberg suffixes from symbol codes
                    mapping = {}
                    stripped_count = 0
                    for row in results:
                        original_code = row['code']
                        stripped_code = strip_bloomberg_suffix(original_code)
                        mapping[row['id']] = stripped_code
                        
                        # Count if we stripped a suffix
                        if original_code != stripped_code:
                            stripped_count += 1
                            logger.debug(f"Stripped symbol: '{original_code}' -> '{stripped_code}'")
                    
                    logger.info(f"Mapped {len(mapping)} instruments to symbols ({stripped_count} suffixes stripped)")
                    return mapping
        except Exception as e:
            logger.error(f"Error mapping instrument IDs: {e}")
            return {}
    
    def get_corporate_actions(self, days_ahead=7, symbols=None, search_term=None):
        """
        Get corporate actions for specified date range
        
        Args:
            days_ahead: Number of days to look ahead (default 7)
            symbols: Optional list of symbols to filter by (should already be stripped)
            search_term: Optional search term for ticker/company name
            
        Returns:
            List of corporate actions with details
        """
        # Build WHERE conditions
        conditions = ["bc.bceffdate BETWEEN CURRENT_DATE AND CURRENT_DATE + %s"]
        params = [days_ahead]
        
        if symbols:
            conditions.append("bc.bcticker_exch_code = ANY(%s)")
            params.append(symbols)
        
        if search_term:
            conditions.append(
                "(bc.bcticker_exch_code ILIKE %s OR bc.bccompanyname ILIKE %s)"
            )
            search_pattern = f"%{search_term}%"
            params.extend([search_pattern, search_pattern])
        
        where_clause = " AND ".join(conditions)
        
        # Main query - get corporate actions with key fields
        query = f"""
        SELECT 
            bc.bcticker_exch_code as ticker,
            bc.bccompanyname as company_name,
            bc.bcmnemonic as ca_type,
            bc.bceffdate as effective_date,
            bc.bcanndate as announcement_date,
            bc.bcactionid as action_id,
            bc.bccurrency as currency,
            bc.bcmarketsectordescription as sector,
            bc.bcflag as flag,
            bc.bcsecidtype as sec_id_type,
            bc.bcsecid as sec_id,
            bc.bceffdate - CURRENT_DATE as days_until
        FROM fost.bloomberg_cax_2025 bc
        WHERE {where_clause}
        ORDER BY bc.bceffdate ASC, bc.bcticker_exch_code
        LIMIT 1000
        """
        
        try:
            with self._get_connection(self.fost_config) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, params)
                    results = cur.fetchall()
                    
                    # Convert to list of dicts and format dates
                    cas = []
                    for row in results:
                        ca = dict(row)
                        # Format dates as strings
                        if ca['effective_date']:
                            ca['effective_date'] = ca['effective_date'].isoformat()
                        if ca['announcement_date']:
                            ca['announcement_date'] = ca['announcement_date'].isoformat()
                        cas.append(ca)
                    
                    logger.info(f"Found {len(cas)} corporate actions")
                    return cas
        except Exception as e:
            logger.error(f"Error fetching corporate actions: {e}")
            return []
    
    def get_ca_details(self, action_id, ticker):
        """
        Get detailed information for a specific corporate action
        including variable fields
        
        Args:
            action_id: Bloomberg action ID
            ticker: Ticker/exchange code
            
        Returns:
            Dict with CA details and variable fields
        """
        # Get main CA info
        main_query = """
        SELECT *
        FROM fost.bloomberg_cax_2025
        WHERE bcactionid = %s AND bcticker_exch_code = %s
        """
        
        # Get variable fields
        varfields_query = """
        SELECT 
            bvfieldid as field_id,
            bvvalue as value,
            bveffdate as eff_date
        FROM fost.bloomberg_varfields_2025
        WHERE bvactionid = %s AND bvticker_exch_code = %s
        ORDER BY bvfieldid
        """
        
        try:
            with self._get_connection(self.fost_config) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Get main info
                    cur.execute(main_query, (action_id, ticker))
                    main_data = cur.fetchone()
                    
                    if not main_data:
                        return None
                    
                    # Get variable fields
                    cur.execute(varfields_query, (action_id, ticker))
                    varfields = cur.fetchall()
                    
                    result = dict(main_data)
                    result['variable_fields'] = [dict(row) for row in varfields]
                    
                    # Format dates
                    for key in result:
                        if isinstance(result[key], datetime):
                            result[key] = result[key].isoformat()
                    
                    return result
        except Exception as e:
            logger.error(f"Error fetching CA details: {e}")
            return None
    
    def get_ca_types_summary(self, days_ahead=7, symbols=None):
        """
        Get summary of CA types in the date range
        
        Returns:
            Dict with CA type counts
        """
        conditions = ["bc.bceffdate BETWEEN CURRENT_DATE AND CURRENT_DATE + %s"]
        params = [days_ahead]
        
        if symbols:
            conditions.append("bc.bcticker_exch_code = ANY(%s)")
            params.append(symbols)
        
        where_clause = " AND ".join(conditions)
        
        query = f"""
        SELECT 
            bc.bcmnemonic as ca_type,
            COUNT(*) as count
        FROM fost.bloomberg_cax_2025 bc
        WHERE {where_clause}
        GROUP BY bc.bcmnemonic
        ORDER BY count DESC
        """
        
        try:
            with self._get_connection(self.fost_config) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, params)
                    results = cur.fetchall()
                    return {row['ca_type']: row['count'] for row in results}
        except Exception as e:
            logger.error(f"Error fetching CA types summary: {e}")
            return {}


# CA Type descriptions for display
CA_TYPE_DESCRIPTIONS = {
    'DIV': 'Dividend',
    'SPL': 'Stock Split',
    'M&A': 'Merger & Acquisition',
    'RTS': 'Rights Issue',
    'SPO': 'Spin-off',
    'BYB': 'Buyback',
    'CAP': 'Capital Change',
    'CVR': 'Conversion',
    'RED': 'Redemption',
    'MAT': 'Maturity',
    'CAL': 'Call',
    'PUT': 'Put',
    'TND': 'Tender Offer',
    'EXC': 'Exchange',
    'INT': 'Interest Payment',
    'DEF': 'Defeasance',
    'BKR': 'Bankruptcy',
    'LIQ': 'Liquidation',
}


def get_ca_type_description(mnemonic):
    """Get human-readable description for CA type mnemonic"""
    return CA_TYPE_DESCRIPTIONS.get(mnemonic, mnemonic)