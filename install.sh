#!/bin/bash
# MSTT Installation Script for Ubuntu Linux
# Mahalanobis Security Testing Toolkit

set -e

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                      ║"
echo "║   MSTT - Mahalanobis Security Testing Toolkit                       ║"
echo "║   Installation Script for Ubuntu Linux                              ║"
echo "║                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on Ubuntu
if [ ! -f /etc/lsb-release ]; then
    echo "⚠️  Warning: This script is designed for Ubuntu Linux"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "📦 Step 1/5: Updating package lists..."
sudo apt-get update -qq

echo "📦 Step 2/5: Installing Python3 and pip..."
sudo apt-get install -y python3 python3-pip python3-venv

echo "📦 Step 3/5: Creating virtual environment..."
python3 -m venv mstt-env
source mstt-env/bin/activate

echo "📦 Step 4/5: Installing Python dependencies..."
pip install --upgrade pip
pip install numpy scipy --break-system-packages 2>/dev/null || pip install numpy scipy

echo "📦 Step 5/5: Setting up MSTT..."

# Create directory structure
mkdir -p mstt_toolkit
cd mstt_toolkit

# Copy toolkit files (assumes they're in the same directory)
if [ -f "../mstt.py" ]; then
    cp ../mstt.py .
    cp ../examples.py .
fi

# Create launcher script
cat > run_mstt.sh << 'EOF'
#!/bin/bash
# MSTT Launcher

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate virtual environment if exists
if [ -d "../mstt-env" ]; then
    source ../mstt-env/bin/activate
fi

echo "🔒 MSTT - Mahalanobis Security Testing Toolkit"
echo ""
echo "Available commands:"
echo "  1. python3 examples.py       - Run interactive examples"
echo "  2. python3 -i mstt.py        - Interactive Python shell with MSTT loaded"
echo "  3. python3 your_script.py    - Run your custom script"
echo ""

if [ "$1" == "examples" ]; then
    python3 examples.py
elif [ "$1" == "shell" ]; then
    python3 -i mstt.py
elif [ "$1" == "test" ]; then
    python3 -c "from mstt import *; print('✅ MSTT loaded successfully!')"
else
    echo "Usage: ./run_mstt.sh [examples|shell|test]"
    echo ""
    echo "Examples:"
    echo "  ./run_mstt.sh examples   # Run example demonstrations"
    echo "  ./run_mstt.sh shell      # Start Python interactive shell"
    echo "  ./run_mstt.sh test       # Test installation"
fi
EOF

chmod +x run_mstt.sh

# Create README
cat > README.md << 'EOF'
# MSTT - Mahalanobis Security Testing Toolkit

## 🔒 Overview

Complete security testing toolkit using Mahalanobis distance for anomaly detection.
Supports Whitebox, Blackbox, and Greybox testing methodologies.

## 📋 Features

- **Blackbox Testing**: External observation-based anomaly detection
- **Whitebox Testing**: Code-level vulnerability analysis with gradient-based root cause identification
- **Greybox Testing**: Hybrid approach combining both methods
- **Automated Reporting**: HTML, JSON, and console reports
- **Real-time Detection**: Statistical anomaly detection with configurable confidence levels

## 🚀 Quick Start

### Run Examples
```bash
./run_mstt.sh examples
```

### Interactive Shell
```bash
./run_mstt.sh shell
```

### Test Installation
```bash
./run_mstt.sh test
```

## 📖 Usage Examples

### Blackbox Testing (API Security)
```python
from mstt import BlackboxTester, ReportGenerator

# Define normal traffic patterns
normal_traffic = [
    {'request_rate': 10, 'payload_size': 1024, 'response_time': 0.2},
    {'request_rate': 12, 'payload_size': 1200, 'response_time': 0.25},
    # ... more samples
]

# Initialize and train
tester = BlackboxTester(confidence=0.95)
tester.collect_baseline(normal_traffic)

# Test for anomalies
test_data = [
    {'request_rate': 500, 'payload_size': 1200, 'response_time': 5.0},  # DDoS?
]

result = tester.test(test_data, target_name="API Gateway")
ReportGenerator.generate_html_report(result, "report.html")
```

### Whitebox Testing (Code Analysis)
```python
from mstt import WhiteboxTester

# Define code metrics
code_metrics = {
    'cyclomatic_complexity': [5, 6, 4, 7, 5],
    'input_validation_score': [9, 8, 9, 7, 8],
    'memory_safety_score': [8, 9, 8, 8, 9],
}

tester = WhiteboxTester(confidence=0.95)
tester.analyze_code_structure(code_metrics)

# Test for vulnerabilities
test_vectors = [
    {'cyclomatic_complexity': 25, 'input_validation_score': 2, 'memory_safety_score': 3},
]

result = tester.test_vulnerability(test_vectors, target_name="Auth Module")

# Get patch recommendations
for event in result.details:
    if event.is_anomaly:
        recommendations = tester.generate_patch_recommendations(event)
        print(recommendations)
```

### Greybox Testing (Web Application)
```python
from mstt import GreyboxTester

# Combine blackbox observations with whitebox code metrics
normal_traffic = [...]  # Observable traffic
code_metrics = {...}    # Code-level metrics (optional)

tester = GreyboxTester(confidence=0.95)
tester.setup(baseline_observations=normal_traffic, code_metrics=code_metrics)

# Multi-stage testing
result = tester.test(test_data, target_name="Web App")
```

## 📊 Understanding Results

### Severity Levels
- **Critical**: Distance ratio > 3x threshold
- **High**: Distance ratio > 2x threshold  
- **Medium**: Distance ratio > 1.5x threshold
- **Low**: Distance ratio > 1x threshold

### Distance Interpretation
- **Mahalanobis Distance**: Statistical distance considering correlations
- **Threshold**: Based on chi-squared distribution at specified confidence level
- **Gradient**: Points to problematic features (whitebox only)

## 🔧 Advanced Usage

### Custom Feature Engineering
```python
# Extract your own features from logs, traffic, code, etc.
features = extract_features(raw_data)
tester.collect_baseline(features)
```

### Model Persistence
```python
# Save trained model
tester.engine.save("model.json")

# Load model later
tester.engine.load("model.json")
```

### Real-time Monitoring
```python
while True:
    current_observation = get_current_metrics()
    distance = tester.engine.distance(current_observation)
    if distance > threshold:
        alert_security_team()
```

## 📈 Performance Tuning

### Confidence Levels
- 0.95 (95%): Standard detection, ~5% false positives
- 0.99 (99%): Stricter detection, ~1% false positives
- 0.90 (90%): More sensitive, ~10% false positives

### Feature Selection
- Choose features with high variance
- Remove highly correlated redundant features
- Normalize features if scales differ significantly

## 🛡️ Security Use Cases

1. **API Security**: Rate limiting, payload analysis, response time monitoring
2. **Network IDS**: Packet analysis, connection patterns, port scanning detection
3. **UEBA**: User behavior profiling, insider threat detection
4. **Code Analysis**: Vulnerability detection, complexity analysis
5. **WAF**: Web attack detection, bot detection

## 📝 Reports

All testers generate three types of reports:

1. **Console**: Real-time terminal output
2. **JSON**: Machine-readable for integration
3. **HTML**: Human-readable with visualizations

## 🤝 Contributing

This is a research toolkit. Extend it for your specific security needs.

## ⚠️ Disclaimer

This toolkit is for authorized security testing only. Always obtain proper 
authorization before testing any system you don't own.

## 📄 License

MIT License - See LICENSE file for details
EOF

cd ..

echo ""
echo "✅ Installation complete!"
echo ""
echo "📂 Toolkit installed in: ./mstt_toolkit/"
echo ""
echo "🚀 Quick start:"
echo "   cd mstt_toolkit"
echo "   ./run_mstt.sh examples    # Run examples"
echo "   ./run_mstt.sh shell       # Interactive shell"
echo "   ./run_mstt.sh test        # Test installation"
echo ""
echo "📖 Documentation: ./mstt_toolkit/README.md"
echo ""
