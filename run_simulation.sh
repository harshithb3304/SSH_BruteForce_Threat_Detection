#!/bin/bash

# SSH Bruteforce Detection - Real-time Simulation Script
# This script demonstrates real-time SSH attack detection using the trained models

set -e  # Exit on any error

# Configuration
PROJECT_DIR="/home/harshith/Projects/CNS_Lab/SSH_BruteForce_Threat_Detection"
PYTHON_ENV="/home/harshith/Projects/CNS_Lab/.venv/bin/python"
LOG_FILE="$PROJECT_DIR/logs/simulation_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_attack() {
    echo -e "${RED}[ATTACK DETECTED]${NC} $1"
}

# Function to display banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          SSH BRUTEFORCE DETECTION SYSTEM                ║"
    echo "║                Real-Time Simulation                     ║"
    echo "║                                                          ║"
    echo "║  Model: Ensemble (Logistic Regression + Isolation Forest) ║"
    echo "║  Accuracy: 94.56% | Precision: 99.95% | Recall: 94.05%   ║"
    echo "║  Processing Speed: Real-time capable (sub-second)         ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if project directory exists
    if [ ! -d "$PROJECT_DIR" ]; then
        print_error "Project directory not found: $PROJECT_DIR"
        exit 1
    fi
    
    # Check if Python environment exists
    if [ ! -f "$PYTHON_ENV" ]; then
        print_error "Python environment not found: $PYTHON_ENV"
        exit 1
    fi
    
    # Check if ensemble model exists
    if [ ! -f "$PROJECT_DIR/models/ensemble.pkl" ]; then
        print_error "Ensemble model not found. Please run: python scripts/proper_training.py"
        exit 1
    fi
    
    # Check if test dataset exists
    if [ ! -f "$PROJECT_DIR/datasets/labelled_testing_data.csv" ]; then
        print_error "Test dataset not found"
        exit 1
    fi
    
    print_status "All prerequisites met ✓"
}

# Function to check simulation script
check_simulation_script() {
    if [ ! -f "$PROJECT_DIR/scripts/simulate_realtime.py" ]; then
        print_error "Simulation script not found: $PROJECT_DIR/scripts/simulate_realtime.py"
        print_error "Please ensure the script exists before running simulation"
        exit 1
    fi
    print_status "Simulation script found ✓"
}

# Function to run the simulation
run_simulation() {
    local duration=$1
    print_status "Starting real-time SSH bruteforce detection simulation..."
    echo ""
    
    cd "$PROJECT_DIR"
    
    # Run the simulation with duration parameter
    $PYTHON_ENV scripts/simulate_realtime.py --duration "$duration" --sample-rate 5 2>&1 | tee "$LOG_FILE"
    
    echo ""
    print_status "Simulation completed. Log saved to: $LOG_FILE"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -q, --quick    Run quick 15-second simulation"
    echo "  -l, --long     Run extended 60-second simulation"
    echo "  -t, --test     Test prerequisites only"
    echo ""
    echo "Default: 30-second simulation with 5 samples/second"
}

# Main execution
main() {
    # Parse command line arguments
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -t|--test)
            show_banner
            check_prerequisites
            print_status "Prerequisites check completed successfully!"
            exit 0
            ;;
        -q|--quick)
            DURATION=15
            ;;
        -l|--long)
            DURATION=60
            ;;
        *)
            DURATION=30
            ;;
    esac
    
    # Main execution flow
    show_banner
    check_prerequisites
    check_simulation_script
    
    print_status "🚀 Starting SSH Bruteforce Detection Simulation..."
    print_status "Duration: ${DURATION} seconds"
    print_status "Press Ctrl+C to stop early"
    echo ""
    
    run_simulation "$DURATION"
    
    echo ""
    print_status "🎉 Simulation demonstration completed successfully!"
    print_warning "💡 This was a demonstration. For production use, integrate with real SSH logs."
}

# Execute main function
main "$@"