#!/usr/bin/env python3
"""
Corporate Actions Routes
Flask routes for Bloomberg CA data
"""

from flask import Blueprint, jsonify, request, session
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Create blueprint
ca_bp = Blueprint('corporate_actions', __name__, url_prefix='/api/ca')


def login_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


@ca_bp.route('/actions', methods=['GET'])
@login_required
def get_corporate_actions():
    """
    Get corporate actions for specified date range
    
    Query parameters:
    - days_ahead: Number of days to look ahead (default: 7)
    - booking_only: If 'true', filter to only instruments in current bookings
    - search: Search term for ticker/company name
    """
    from app import ca_db  # Import from main app
    
    try:
        # Get query parameters
        days_ahead = int(request.args.get('days_ahead', 7))
        booking_only = request.args.get('booking_only', 'false').lower() == 'true'
        search_term = request.args.get('search', '').strip()
        
        # Validate days_ahead
        if days_ahead < 1 or days_ahead > 365:
            return jsonify({'error': 'days_ahead must be between 1 and 365'}), 400
        
        symbols = None
        booking_instruments = []
        
        # If filtering by booking instruments
        if booking_only:
            # Get instruments from current bookings
            booking_instruments = ca_db.get_current_booking_instruments()
            
            if not booking_instruments:
                return jsonify({
                    'actions': [],
                    'total': 0,
                    'booking_instruments': [],
                    'message': 'No instruments found in current bookings'
                })
            
            # Map instrument IDs to symbols
            instr_ids = [instr['instr_id'] for instr in booking_instruments]
            symbol_mapping = ca_db.map_instr_ids_to_symbols(instr_ids)
            
            # Add symbol codes to booking instruments
            for instr in booking_instruments:
                instr['symbol'] = symbol_mapping.get(instr['instr_id'], 'N/A')
            
            # Filter to only instruments with valid symbols
            symbols = [instr['symbol'] for instr in booking_instruments if instr['symbol'] != 'N/A']
            
            if not symbols:
                return jsonify({
                    'actions': [],
                    'total': 0,
                    'booking_instruments': booking_instruments,
                    'message': 'No valid symbols found for booking instruments'
                })
        
        # Get corporate actions
        actions = ca_db.get_corporate_actions(
            days_ahead=days_ahead,
            symbols=symbols,
            search_term=search_term if search_term else None
        )
        
        # Get CA type summary
        ca_summary = ca_db.get_ca_types_summary(
            days_ahead=days_ahead,
            symbols=symbols
        )
        
        logger.info(f"User {session['user']['username']} queried {len(actions)} corporate actions")
        
        return jsonify({
            'actions': actions,
            'total': len(actions),
            'booking_instruments': booking_instruments if booking_only else [],
            'ca_type_summary': ca_summary,
            'filters': {
                'days_ahead': days_ahead,
                'booking_only': booking_only,
                'search': search_term
            }
        })
        
    except Exception as e:
        logger.error(f"Error in get_corporate_actions: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@ca_bp.route('/actions/<action_id>', methods=['GET'])
@login_required
def get_action_details(action_id):
    """
    Get detailed information for a specific corporate action
    
    Query parameters:
    - ticker: Ticker/exchange code (required)
    """
    from app import ca_db
    
    try:
        ticker = request.args.get('ticker')
        
        if not ticker:
            return jsonify({'error': 'ticker parameter required'}), 400
        
        details = ca_db.get_ca_details(action_id, ticker)
        
        if not details:
            return jsonify({'error': 'Corporate action not found'}), 404
        
        return jsonify(details)
        
    except Exception as e:
        logger.error(f"Error in get_action_details: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@ca_bp.route('/booking-instruments', methods=['GET'])
@login_required
def get_booking_instruments():
    """Get list of instruments in current bookings with symbol mapping"""
    from app import ca_db
    
    try:
        # Get instruments from bookings
        instruments = ca_db.get_current_booking_instruments()
        
        if not instruments:
            return jsonify({
                'instruments': [],
                'total': 0,
                'message': 'No instruments found in current bookings'
            })
        
        # Map to symbols
        instr_ids = [instr['instr_id'] for instr in instruments]
        symbol_mapping = ca_db.map_instr_ids_to_symbols(instr_ids)
        
        # Add symbols to results
        for instr in instruments:
            instr['symbol'] = symbol_mapping.get(instr['instr_id'], 'N/A')
        
        return jsonify({
            'instruments': instruments,
            'total': len(instruments)
        })
        
    except Exception as e:
        logger.error(f"Error in get_booking_instruments: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@ca_bp.route('/ca-types', methods=['GET'])
@login_required
def get_ca_types():
    """Get list of CA types with descriptions"""
    from ca_database import CA_TYPE_DESCRIPTIONS, get_ca_type_description
    
    return jsonify({
        'ca_types': CA_TYPE_DESCRIPTIONS
    })
