#!/bin/bash
# NetGuardIDS Setup Script for Linux/Mac
echo "Setting up NetGuardIDS..."

# Ensure pip is installed
if ! command -v pip3 &> /dev/null
then
    echo "pip3 could not be found. Please install Python 3 and pip."
    exit 1
fi

# Install requirements
pip3 install -r requirements.txt

echo "Setup complete. You may need to run the scripts with sudo (root privileges) to capture network traffic."
