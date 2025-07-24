#!/bin/bash
# setup-gcp.sh
set -e

echo "Setting up GCP Firewall Auto-Remediation..."

# Check gcloud CLI
if ! command -v gcloud &> /dev/null; then
    echo "gcloud CLI not found. Please install Google Cloud SDK first."
    exit 1
fi

# Set project if provided
if [ ! -z "$GCP_PROJECT_ID" ]; then
    gcloud config set project $GCP_PROJECT_ID
fi

PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Please set GCP_PROJECT_ID environment variable or configure gcloud project"
    exit 1
fi

echo "Using project: $PROJECT_ID"

# Enable required APIs
echo "Enabling required APIs..."
gcloud services enable compute.googleapis.com
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable pubsub.googleapis.com
gcloud services enable logging.googleapis.com

# Create Pub/Sub topic
echo "Creating Pub/Sub topic..."
gcloud pubsub topics create security-alerts || echo "Topic may already exist"

# Deploy Cloud Function
echo "Deploying Cloud Function..."
cd gcp/
gcloud functions deploy firewall-remediation \
    --runtime python39 \
    --trigger-topic security-alerts \
    --entry-point main \
    --timeout 300 \
    --memory 256MB \
    --set-env-vars GCP_PROJECT_ID=$PROJECT_ID

echo "GCP setup complete!"