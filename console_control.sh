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

# Use expect to interact with the interactive console
expect << EOF
set timeout 300

# Start the interactive console
spawn $CONSOLE_BINARY

# Wait for the prompt (adjust "> " to match your actual prompt)
expect "> "

# Send the command with CSV file
send "$COMMAND $CSV_FILE\r"

# Wait for completion - you may need to adjust this based on your console's output
expect {
    "completed" { 
        # Success message detected
    }
    "error" {
        # Error message detected
        exit 1
    }
    "> " {
        # Prompt returned, command finished
    }
    timeout {
        puts "Command timed out after 300 seconds"
        exit 1
    }
}

# Send exit command to close the console
send "exit\r"
expect eof
EOF

# Check exit status
if [ $? -eq 0 ]; then
    echo ""
    echo "Console command completed successfully!"
    exit 0
else
    echo ""
    echo "Console command failed!"
    exit 1
fi