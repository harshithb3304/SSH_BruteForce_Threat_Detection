#!/bin/bash

# SSH Bruteforce Detection System Setup Script

echo "🔒 SSH Bruteforce Detection System Setup"
echo "========================================="

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1)
if [[ $python_version == *"Python 3"* ]]; then
    echo "✅ Python 3 found: $python_version"
else
    echo "❌ Python 3 is required but not found"
    exit 1
fi

# Create virtual environment
echo "🐍 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📥 Installing requirements..."
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data models reports logs

# Make scripts executable
chmod +x setup.sh
chmod +x main.py

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "🚀 To run the system:"
echo "   1. Activate virtual environment: source venv/bin/activate"
echo "   2. Run demo: python main.py --mode demo"
echo "   3. Or train models: python main.py --mode train"
echo "   4. Or start monitoring: python main.py --mode monitor --enable-monitoring"
echo ""
echo "📖 See README.md for detailed usage instructions"
