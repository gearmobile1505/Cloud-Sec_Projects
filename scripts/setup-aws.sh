#!/bin/bash
# setup-aws.sh
set -e

echo "Setting up AWS Security Group Auto-Remediation..."

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

# Check SAM CLI
if ! command -v sam &> /dev/null; then
    echo "SAM CLI not found. Please install SAM CLI first."
    exit 1
fi

# Create deployment package
cd aws/
pip install -r requirements.txt -t .

# Build and deploy with SAM
echo "Building SAM application..."
sam build

echo "Deploying to AWS..."
sam deploy --guided

echo "AWS setup complete!"