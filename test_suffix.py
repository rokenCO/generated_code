#!/usr/bin/env python3
"""
Test script for Bloomberg suffix stripping
"""

# Bloomberg security type suffixes
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
    """Strip Bloomberg security type suffix from symbol"""
    if not symbol_code:
        return symbol_code
    
    for suffix in BLOOMBERG_SUFFIXES:
        if symbol_code.endswith(suffix):
            return symbol_code[:-len(suffix)].strip()
    
    return symbol_code


# Test cases
test_cases = [
    ('OSWED S1 Equity', 'OSWED S1'),
    ('GC1 Comdty', 'GC1'),
    ('EURUSD Curncy', 'EURUSD'),
    ('SPX Index', 'SPX'),
    ('AAPL US Equity', 'AAPL US'),
    ('US10YT=RR Corp', 'US10YT=RR'),
    ('NoSuffix', 'NoSuffix'),
    ('', ''),
    (None, None),
]

print("Testing Bloomberg Suffix Stripping")
print("=" * 60)

all_passed = True
for input_val, expected in test_cases:
    result = strip_bloomberg_suffix(input_val)
    passed = result == expected
    status = "✓ PASS" if passed else "✗ FAIL"
    
    print(f"{status}: '{input_val}' -> '{result}' (expected: '{expected}')")
    
    if not passed:
        all_passed = False

print("=" * 60)
if all_passed:
    print("✓ All tests passed!")
else:
    print("✗ Some tests failed")