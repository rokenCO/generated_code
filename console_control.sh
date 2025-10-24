#!/bin/bash
# console_control.sh - Wrapper to interact with interactive console_control binary

COMMAND=$1
CSV_FILE=$2

# Validate arguments
if [ -z "$COMMAND" ] || [ -z "$CSV_FILE" ]; then
    echo "Error: Missing arguments"
    echo "Usage: $0 <command> <csv_file>"
    exit 1
fi

# Check if CSV file exists
if [ ! -f "$CSV_FILE" ]; then
    echo "Error: CSV file not found: $CSV_FILE"
    exit 1
fi

# Path to the interactive console_control binary
CONSOLE_BINARY="/path/to/CONSOLE_CONTROL"

# Check if expect is available
if ! command -v expect &> /dev/null; then
    echo "Error: 'expect' is not installed. Please install it:"
    echo "  Ubuntu/Debian: sudo apt-get install expect"
    echo "  RHEL/CentOS: sudo yum install expect"
    exit 1
fi

# Check if binary exists
if [ ! -f "$CONSOLE_BINARY" ]; then
    echo "Error: Console control binary not found: $CONSOLE_BINARY"
    exit 1
fi

# Log the execution
echo "=== Console Control Execution ==="
echo "Command: $COMMAND"
echo "CSV File: $CSV_FILE"
echo "Timestamp: $(date)"
echo "================================="
echo ""

# Create a temporary file for output
TEMP_OUTPUT=$(mktemp)

# Use expect to interact with the interactive console
# This executes BOTH booking_load AND booking_book all
expect << EOF > "$TEMP_OUTPUT" 2>&1
set timeout 300

# Disable terminal features that cause escape codes
log_user 1

# Start the interactive console
spawn $CONSOLE_BINARY

# Wait for the prompt (adjust "> " to match your actual prompt)
expect "> "

# Send the first command: booking_load
send "$COMMAND $CSV_FILE\r"

# Wait for command to complete and prompt to return
expect {
    "error" {
        puts "\nError detected during booking_load"
        exit 1
    }
    "> " {
        puts "\nbooking_load completed, executing booking_book all..."
    }
    timeout {
        puts "\nCommand timed out during booking_load"
        exit 1
    }
}

# Send the second command: booking_book all
send "booking_book all\r"

# Wait for second command to complete
expect {
    "error" {
        puts "\nError detected during booking_book"
        exit 1
    }
    "> " {
        puts "\nbooking_book all completed"
    }
    timeout {
        puts "\nCommand timed out during booking_book"
        exit 1
    }
}

# Send exit command to close the console
send "exit\r"
expect eof
EOF

EXIT_CODE=$?

# Strip ANSI escape codes from output
# This removes color codes, cursor movements, and bracketed paste mode codes
if command -v sed &> /dev/null; then
    sed -r "s/\x1B\[[0-9;]*[JKmsu]//g; s/\x1B\[?[0-9]*[hl]//g" "$TEMP_OUTPUT"
else
    cat "$TEMP_OUTPUT"
fi

# Clean up
rm -f "$TEMP_OUTPUT"

# Check exit status
if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "Console commands completed successfully!"
    echo "✓ booking_load $CSV_FILE"
    echo "✓ booking_book all"
    exit 0
else
    echo ""
    echo "Console commands failed!"
    exit 1
fi