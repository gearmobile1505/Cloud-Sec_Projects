# Cloud Security Group Auto-Remediation

This repository contains auto-remediation scripts for security groups/firewall rules across AWS, GCP, and Azure. The scripts automatically detect and remediate security groups with overly permissive rules (0.0.0.0/0 source ranges) when triggered by security alerts.

## Overview

The solution handles alerts from various security tools:
- **AWS**: GuardDuty, Config, CNAPP tools via SNS
- **GCP**: Security Command Center, CNAPP tools via Pub/Sub  
- **Azure**: Sentinel, Defender, CNAPP tools via Service Bus

## Repository Structure

```
cloud-security-remediation/
├── aws/
│   ├── aws_sg_remediation.py
│   ├── requirements.txt -> requirements-aws.txt
│   └── template.yaml
├── gcp/
│   ├── gcp_firewall_remediation.py
│   ├── requirements.txt -> requirements-gcp.txt
│   └── main.py
├── azure/
│   ├── azure_nsg_remediation.py
│   ├── requirements.txt -> requirements-azure.txt
│   ├── function.json
│   └── __init__.py
├── deployment/
│   ├── aws-lambda-template.yaml
│   ├── gcp-function.yaml
│   └── azure-function-app.json
├── docs/
│   ├── aws-setup.md
│   ├── gcp-setup.md
│   └── azure-setup.md
├── requirements-aws.txt
├── requirements-gcp.txt
├── requirements-azure.txt
└── README.md
```

## Features

### Common Functionality
- **Auto-detection** of 0.0.0.0/0 rules in security groups
- **Smart remediation** - deletes high-risk rules, modifies others to use private ranges
- **Multi-format alert parsing** - supports native cloud tools and CNAPP platforms
- **Comprehensive logging** and audit trails
- **Error handling** and retry logic

### AWS Features
- Lambda function triggered by SNS messages
- Supports GuardDuty, Config, and CNAPP tool alerts
- Remediates EC2 Security Groups
- CloudWatch logging and SNS notifications

### GCP Features  
- Cloud Function triggered by Pub/Sub messages
- Supports Security Command Center and CNAPP alerts
- Remediates VPC firewall rules
- Cloud Logging integration

### Azure Features
- Azure Function triggered by Service Bus messages
- Supports Sentinel, Defender, and CNAPP alerts  
- Remediates Network Security Groups (NSGs)
- Azure Monitor integration

## Quick Start

### AWS Deployment
```bash
cd aws/
sam build
sam deploy --guided
```

### GCP Deployment
```bash
cd gcp/
gcloud functions deploy firewall-remediation \
  --runtime python39 \
  --trigger-topic security-alerts \
  --entry-point main
```

### Azure Deployment
```bash
cd azure/
func azure functionapp publish nsg-remediation-app
```

## Configuration

### Environment Variables

**AWS:**
- `AWS_DEFAULT_REGION` - Default region for operations
- `NOTIFICATION_SNS_TOPIC` - SNS topic for notifications

**GCP:**
- `GCP_PROJECT_ID` - Google Cloud project ID
- `NOTIFICATION_PUBSUB_TOPIC` - Pub/Sub topic for notifications

**Azure:**
- `AZURE_SUBSCRIPTION_ID` - Azure subscription ID
- `AZURE_SERVICE_BUS_CONNECTION_STRING` - Service Bus connection string
- `NOTIFICATION_QUEUE_NAME` - Service Bus queue for notifications

### Alert Format Examples

#### AWS GuardDuty Alert
```json
{
  "detail": {
    "service": {
      "resourceRole": "TARGET"
    },
    "region": "us-east-1"
  },
  "security_group_id": "sg-12345678"
}
```

#### GCP Security Command Center Alert
```json
{
  "finding": {
    "resourceName": "projects/my-project/global/firewalls/allow-all-ssh"
  }
}
```

#### Azure Sentinel Alert
```json
{
  "entities": [{
    "Type": "azure-resource",
    "ResourceId": "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.Network/networkSecurityGroups/nsg-name"
  }]
}
```

## Security Considerations

### Permissions Required

**AWS:**
- `ec2:DescribeSecurityGroups`
- `ec2:RevokeSecurityGroupIngress` 
- `ec2:RevokeSecurityGroupEgress`
- `sns:Publish` (for notifications)

**GCP:**
- `compute.firewalls.get`
- `compute.firewalls.update`
- `compute.firewalls.delete`
- `pubsub.topics.publish` (for notifications)

**Azure:**
- `Microsoft.Network/networkSecurityGroups/read`
- `Microsoft.Network/networkSecurityGroups/securityRules/write`
- `Microsoft.Network/networkSecurityGroups/securityRules/delete`
- `Microsoft.ServiceBus/namespaces/queues/messages/send` (for notifications)

### Remediation Logic

1. **High-risk rules** (SSH, RDP, database ports) with 0.0.0.0/0 are **deleted**
2. **Other rules** with 0.0.0.0/0 are **modified** to use private network ranges:
   - 10.0.0.0/8 (Private Class A)
   - 172.16.0.0/12 (Private Class B)  
   - 192.168.0.0/16 (Private Class C)

### Testing

Each script includes standalone execution for testing:

```bash
# AWS
python aws_sg_remediation.py

# GCP  
python gcp_firewall_remediation.py

# Azure
python azure_nsg_remediation.py
```

## Monitoring and Alerting

All scripts provide comprehensive logging and can send notifications via:
- **AWS**: SNS topics
- **GCP**: Pub/Sub topics
- **Azure**: Service Bus queues

Log entries include:
- Timestamp
- Action taken (delete/modify)
- Resource details
- Original security issue

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the documentation in the `docs/` directory
2. Review cloud provider setup guides
3. Open an issue on GitHub

## Roadmap

- [ ] Support for additional cloud providers
- [ ] Integration with more CNAPP tools
- [ ] Advanced rule modification strategies
- [ ] Terraform/Pulumi deployment options
- [ ] Metrics and dashboards
- [ ] Policy-based remediation rules