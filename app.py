# app.py
from flask import Flask, render_template, request, jsonify
import subprocess
import shlex
import os

app = Flask(__name__)

# Configuration
TASK_ADMIN_PATH = '/path/to/task_admin'
CONFIG_PATH = '/path/to/config.xml'
ALLOWED_COMMANDS = [
    'dobackpopulation',
    'status',
    'list',
    # Add your allowed commands here
]

@app.route('/')
def index():
    return render_template('index.html', commands=ALLOWED_COMMANDS)

@app.route('/execute', methods=['POST'])
def execute():
    data = request.json
    command = data.get('command')
    args = data.get('args', [])
    
    # Validate command
    if command not in ALLOWED_COMMANDS:
        return jsonify({'error': f'Command {command} not allowed'}), 400
    
    # Build the full command
    cmd = [TASK_ADMIN_PATH, '-c', CONFIG_PATH, command] + args
    
    try:
        # Execute with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)