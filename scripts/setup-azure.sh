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

---
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

---
#!/bin/bash
# setup-azure.sh
set -e

echo "Setting up Azure NSG Auto-Remediation..."

# Check Azure CLI
if ! command -v az &> /dev/null; then
    echo "Azure CLI not found. Please install Azure CLI first."
    exit 1
fi

# Check Azure Functions Core Tools
if ! command -v func &> /dev/null; then
    echo "Azure Functions Core Tools not found. Please install it first."
    exit 1
fi

# Login check
az account show > /dev/null || {
    echo "Please login to Azure first: az login"
    exit 1
}

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "Using subscription: $SUBSCRIPTION_ID"

# Set variables
RESOURCE_GROUP=${AZURE_RESOURCE_GROUP:-"security-remediation-rg"}
LOCATION=${AZURE_LOCATION:-"East US"}
FUNCTION_APP_NAME=${AZURE_FUNCTION_APP_NAME:-"nsg-remediation-app-$(date +%s)"}
STORAGE_ACCOUNT_NAME="remediation$(date +%s | tail -c 8)"
SERVICE_BUS_NAMESPACE="remediation-sb-$(date +%s)"

echo "Creating resource group..."
az group create --name $RESOURCE_GROUP --location "$LOCATION"

echo "Creating storage account..."
az storage account create \
    --name $STORAGE_ACCOUNT_NAME \
    --resource-group $RESOURCE_GROUP \
    --location "$LOCATION" \
    --sku Standard_LRS

echo "Creating Service Bus namespace..."
az servicebus namespace create \
    --name $SERVICE_BUS_NAMESPACE \
    --resource-group $RESOURCE_GROUP \
    --location "$LOCATION" \
    --sku Standard

echo "Creating Service Bus queue..."
az servicebus queue create \
    --name security-alerts \
    --namespace-name $SERVICE_BUS_NAMESPACE \
    --resource-group $RESOURCE_GROUP

# Get connection string
SERVICE_BUS_CONNECTION_STRING=$(az servicebus namespace authorization-rule keys list \
    --resource-group $RESOURCE_GROUP \
    --namespace-name $SERVICE_BUS_NAMESPACE \
    --name RootManageSharedAccessKey \
    --query primaryConnectionString -o tsv)

echo "Creating Function App..."
az functionapp create \
    --resource-group $RESOURCE_GROUP \
    --consumption-plan-location "$LOCATION" \
    --runtime python \
    --runtime-version 3.9 \
    --functions-version 4 \
    --name $FUNCTION_