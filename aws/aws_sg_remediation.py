#!/usr/bin/env python3
"""
AWS Security Group Auto-Remediation Script
Handles alerts from AWS GuardDuty, Config, and CNAPP tools via SNS
"""

import json
import boto3
import logging
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, BotoCoreError
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AWSSecurityGroupRemediator:
    def __init__(self, region: str = None):
        """Initialize AWS clients"""
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        try:
            self.ec2_client = boto3.client('ec2', region_name=self.region)
            self.sns_client = boto3.client('sns', region_name=self.region)
            self.config_client = boto3.client('config', region_name=self.region)
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            raise

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        AWS Lambda handler for processing SNS messages
        """
        try:
            logger.info(f"Processing event: {json.dumps(event, default=str)}")
            
            # Handle SNS message
            if 'Records' in event:
                for record in event['Records']:
                    if record.get('EventSource') == 'aws:sns':
                        message = json.loads(record['Sns']['Message'])
                        self.process_alert(message)
            else:
                # Direct invocation
                self.process_alert(event)
                
            return {
                'statusCode': 200,
                'body': json.dumps('Remediation completed successfully')
            }
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps(f'Error: {str(e)}')
            }

    def process_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Process security alert and determine remediation action
        """
        try:
            # Parse different alert formats
            resource_info = self.parse_alert(alert_data)
            if not resource_info:
                logger.warning("Unable to parse alert data")
                return

            security_group_id = resource_info.get('security_group_id')
            region = resource_info.get('region', self.region)
            
            if security_group_id:
                self.remediate_security_group(security_group_id, region)
            else:
                logger.warning("No security group ID found in alert")
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")

    def parse_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Parse different types of security alerts
        """
        resource_info = {}
        
        try:
            # AWS GuardDuty format
            if 'detail' in alert_data and 'service' in alert_data['detail']:
                service_info = alert_data['detail']['service']
                if 'resourceRole' in service_info:
                    # Extract from GuardDuty finding
                    resource_info['security_group_id'] = self.extract_sg_from_guardduty(alert_data)
                    resource_info['region'] = alert_data.get('detail', {}).get('region')
            
            # AWS Config format
            elif 'configurationItem' in alert_data:
                config_item = alert_data['configurationItem']
                if config_item.get('resourceType') == 'AWS::EC2::SecurityGroup':
                    resource_info['security_group_id'] = config_item.get('resourceId')
                    resource_info['region'] = config_item.get('awsRegion')
            
            # CNAPP tool format (generic)
            elif 'resource' in alert_data:
                resource = alert_data['resource']
                resource_info['security_group_id'] = resource.get('id') or resource.get('resourceId')
                resource_info['region'] = resource.get('region')
            
            # Direct format
            elif 'security_group_id' in alert_data:
                resource_info = alert_data
                
            return resource_info if resource_info.get('security_group_id') else None
            
        except Exception as e:
            logger.error(f"Error parsing alert: {e}")
            return None

    def extract_sg_from_guardduty(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract security group ID from GuardDuty finding"""
        try:
            # Look in different possible locations
            detail = finding.get('detail', {})
            service = detail.get('service', {})
            
            # Check remoteIpDetails or localIpDetails
            for ip_details_key in ['remoteIpDetails', 'localIpDetails']:
                if ip_details_key in service:
                    # This is a simplified extraction - adjust based on actual GuardDuty format
                    pass
            
            # Alternative: extract from description or other fields
            description = detail.get('description', '')
            if 'sg-' in description:
                # Extract security group ID from description
                import re
                sg_match = re.search(r'sg-[a-z0-9]+', description)
                if sg_match:
                    return sg_match.group()
                    
            return None
        except Exception as e:
            logger.error(f"Error extracting SG from GuardDuty: {e}")
            return None

    def remediate_security_group(self, security_group_id: str, region: str = None) -> None:
        """
        Remediate security group by removing/modifying 0.0.0.0/0 rules
        """
        if region and region != self.region:
            ec2_client = boto3.client('ec2', region_name=region)
        else:
            ec2_client = self.ec2_client
            
        try:
            # Get security group details
            response = ec2_client.describe_security_groups(
                GroupIds=[security_group_id]
            )
            
            if not response['SecurityGroups']:
                logger.warning(f"Security group {security_group_id} not found")
                return
                
            sg = response['SecurityGroups'][0]
            logger.info(f"Processing security group: {sg['GroupName']} ({security_group_id})")
            
            # Check and remediate inbound rules
            self.remediate_inbound_rules(ec2_client, sg)
            
            # Check and remediate outbound rules
            self.remediate_outbound_rules(ec2_client, sg)
            
            # Log remediation action
            self.log_remediation_action(security_group_id, sg['GroupName'], region)
            
        except ClientError as e:
            logger.error(f"AWS API error remediating {security_group_id}: {e}")
        except Exception as e:
            logger.error(f"Error remediating {security_group_id}: {e}")

    def remediate_inbound_rules(self, ec2_client, sg: Dict[str, Any]) -> None:
        """Remove or modify inbound rules with 0.0.0.0/0"""
        rules_to_revoke = []
        
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    rules_to_revoke.append({
                        'IpProtocol': rule['IpProtocol'],
                        'FromPort': rule.get('FromPort'),
                        'ToPort': rule.get('ToPort'),
                        'IpRanges': [ip_range]
                    })
                    
        if rules_to_revoke:
            try:
                ec2_client.revoke_security_group_ingress(
                    GroupId=sg['GroupId'],
                    IpPermissions=rules_to_revoke
                )
                logger.info(f"Revoked {len(rules_to_revoke)} inbound rules from {sg['GroupId']}")
            except ClientError as e:
                logger.error(f"Failed to revoke inbound rules: {e}")

    def remediate_outbound_rules(self, ec2_client, sg: Dict[str, Any]) -> None:
        """Remove or modify outbound rules with 0.0.0.0/0 (if needed)"""
        # Generally, outbound 0.0.0.0/0 is less of a security concern
        # but can be configured based on security policy
        
        rules_to_revoke = []
        
        for rule in sg.get('IpPermissionsEgress', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Only revoke specific high-risk ports
                    port = rule.get('FromPort')
                    if port and port in [22, 3389, 1433, 3306]:  # SSH, RDP, SQL Server, MySQL
                        rules_to_revoke.append({
                            'IpProtocol': rule['IpProtocol'],
                            'FromPort': rule.get('FromPort'),
                            'ToPort': rule.get('ToPort'),
                            'IpRanges': [ip_range]
                        })
                        
        if rules_to_revoke:
            try:
                ec2_client.revoke_security_group_egress(
                    GroupId=sg['GroupId'],
                    IpPermissions=rules_to_revoke
                )
                logger.info(f"Revoked {len(rules_to_revoke)} outbound rules from {sg['GroupId']}")
            except ClientError as e:
                logger.error(f"Failed to revoke outbound rules: {e}")

    def log_remediation_action(self, sg_id: str, sg_name: str, region: str) -> None:
        """Log remediation action for audit purposes"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'security_group_remediation',
            'security_group_id': sg_id,
            'security_group_name': sg_name,
            'region': region,
            'remediation_type': 'remove_0.0.0.0/0_rules'
        }
        
        logger.info(f"Remediation completed: {json.dumps(log_entry)}")
        
        # Optionally send to CloudWatch Logs or other logging service
        try:
            # Example: Send to SNS for notifications
            if os.environ.get('NOTIFICATION_SNS_TOPIC'):
                self.sns_client.publish(
                    TopicArn=os.environ['NOTIFICATION_SNS_TOPIC'],
                    Message=json.dumps(log_entry),
                    Subject=f'Security Group Remediation: {sg_name}'
                )
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

# Standalone execution for testing
def main():
    """Main function for standalone execution"""
    remediation = AWSSecurityGroupRemediator()
    
    # Example test event
    test_event = {
        'security_group_id': 'sg-12345678',
        'region': 'us-east-1'
    }
    
    remediation.process_alert(test_event)

if __name__ == '__main__':
    main()