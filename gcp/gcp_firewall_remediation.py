#!/usr/bin/env python3
"""
GCP Firewall Rules Auto-Remediation Script
Handles alerts from GCP Security Command Center and CNAPP tools via Pub/Sub
"""

import json
import logging
from typing import Dict, List, Any, Optional
import os
from datetime import datetime
import base64

from google.cloud import compute_v1
from google.cloud import pubsub_v1
from google.cloud import logging as cloud_logging
from google.oauth2 import service_account
import functions_framework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class GCPFirewallRemediator:
    def __init__(self, project_id: str = None, credentials_path: str = None):
        """Initialize GCP clients"""
        self.project_id = project_id or os.environ.get('GCP_PROJECT_ID')
        if not self.project_id:
            raise ValueError("GCP_PROJECT_ID must be provided")
            
        # Initialize credentials
        self.credentials = None
        if credentials_path:
            self.credentials = service_account.Credentials.from_service_account_file(
                credentials_path
            )
        
        try:
            # Initialize clients
            self.compute_client = compute_v1.FirewallsClient(credentials=self.credentials)
            self.instances_client = compute_v1.InstancesClient(credentials=self.credentials)
            self.publisher = pubsub_v1.PublisherClient(credentials=self.credentials)
            
            # Initialize Cloud Logging
            self.logging_client = cloud_logging.Client(
                project=self.project_id, 
                credentials=self.credentials
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize GCP clients: {e}")
            raise

    @functions_framework.cloud_event
    def pubsub_handler(self, cloud_event):
        """
        Cloud Function handler for Pub/Sub messages
        """
        try:
            # Decode Pub/Sub message
            if 'data' in cloud_event.data:
                message_data = base64.b64decode(cloud_event.data['data']).decode('utf-8')
                alert_data = json.loads(message_data)
            elif 'message' in cloud_event.data:
                message_data = base64.b64decode(cloud_event.data['message']['data']).decode('utf-8')
                alert_data = json.loads(message_data)
            else:
                alert_data = cloud_event.data
                
            logger.info(f"Processing Pub/Sub message: {json.dumps(alert_data, default=str)}")
            
            self.process_alert(alert_data)
            
            return {'status': 'success'}
            
        except Exception as e:
            logger.error(f"Error processing Pub/Sub message: {e}")
            raise

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

            firewall_rule_name = resource_info.get('firewall_rule_name')
            
            if firewall_rule_name:
                self.remediate_firewall_rule(firewall_rule_name)
            else:
                logger.warning("No firewall rule name found in alert")
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")

    def parse_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Parse different types of security alerts
        """
        resource_info = {}
        
        try:
            # GCP Security Command Center format
            if 'finding' in alert_data:
                finding = alert_data['finding']
                resource_name = finding.get('resourceName', '')
                
                # Extract firewall rule name from resource name
                if 'firewalls/' in resource_name:
                    firewall_name = resource_name.split('firewalls/')[-1]
                    resource_info['firewall_rule_name'] = firewall_name
                    
            # GCP Asset Inventory format
            elif 'asset' in alert_data:
                asset = alert_data['asset']
                if asset.get('assetType') == 'compute.googleapis.com/Firewall':
                    resource_info['firewall_rule_name'] = asset['name'].split('/')[-1]
                    
            # CNAPP tool format (generic)
            elif 'resource' in alert_data:
                resource = alert_data['resource']
                resource_info['firewall_rule_name'] = resource.get('name') or resource.get('id')
                
            # Direct format
            elif 'firewall_rule_name' in alert_data:
                resource_info = alert_data
                
            # Cloud Security Scanner format
            elif 'scanConfig' in alert_data:
                # Extract from scan results
                scan_result = alert_data.get('scanResult', {})
                resource_info['firewall_rule_name'] = self.extract_fw_from_scan(scan_result)
                
            return resource_info if resource_info.get('firewall_rule_name') else None
            
        except Exception as e:
            logger.error(f"Error parsing alert: {e}")
            return None

    def extract_fw_from_scan(self, scan_result: Dict[str, Any]) -> Optional[str]:
        """Extract firewall rule name from security scan results"""
        try:
            # This would depend on the specific scanner output format
            # Placeholder implementation
            finding_details = scan_result.get('findingDetails', {})
            if 'firewallRule' in finding_details:
                return finding_details['firewallRule']
            return None
        except Exception as e:
            logger.error(f"Error extracting firewall rule from scan: {e}")
            return None

    def remediate_firewall_rule(self, firewall_rule_name: str) -> None:
        """
        Remediate firewall rule by removing/modifying 0.0.0.0/0 rules
        """
        try:
            # Get firewall rule details
            request = compute_v1.GetFirewallRequest(
                project=self.project_id,
                firewall=firewall_rule_name
            )
            
            firewall_rule = self.compute_client.get(request=request)
            logger.info(f"Processing firewall rule: {firewall_rule.name}")
            
            # Check if rule has 0.0.0.0/0 in source ranges
            needs_remediation = False
            
            for source_range in firewall_rule.source_ranges:
                if source_range == '0.0.0.0/0':
                    needs_remediation = True
                    break
                    
            if not needs_remediation:
                logger.info(f"Firewall rule {firewall_rule_name} doesn't need remediation")
                return
                
            # Determine remediation strategy
            if self.should_delete_rule(firewall_rule):
                self.delete_firewall_rule(firewall_rule_name)
            else:
                self.modify_firewall_rule(firewall_rule)
                
            # Log remediation action
            self.log_remediation_action(firewall_rule_name, 'modified')
            
        except Exception as e:
            logger.error(f"Error remediating firewall rule {firewall_rule_name}: {e}")

    def should_delete_rule(self, firewall_rule) -> bool:
        """
        Determine if the rule should be deleted entirely or just modified
        """
        # Delete if it's a high-risk rule with only 0.0.0.0/0 as source
        high_risk_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
        
        if len(firewall_rule.source_ranges) == 1 and firewall_rule.source_ranges[0] == '0.0.0.0/0':
            for allowed in firewall_rule.allowed:
                for port in allowed.ports:
                    if '-' in port:
                        start, end = map(int, port.split('-'))
                        if any(p in range(start, end + 1) for p in high_risk_ports):
                            return True
                    elif int(port) in high_risk_ports:
                        return True
                        
        return False

    def delete_firewall_rule(self, firewall_rule_name: str) -> None:
        """Delete the firewall rule entirely"""
        try:
            request = compute_v1.DeleteFirewallRequest(
                project=self.project_id,
                firewall=firewall_rule_name
            )
            
            operation = self.compute_client.delete(request=request)
            self.wait_for_operation(operation)
            
            logger.info(f"Deleted firewall rule: {firewall_rule_name}")
            
        except Exception as e:
            logger.error(f"Failed to delete firewall rule {firewall_rule_name}: {e}")

    def modify_firewall_rule(self, firewall_rule) -> None:
        """Modify the firewall rule to remove 0.0.0.0/0"""
        try:
            # Create modified rule - remove 0.0.0.0/0 and add more restrictive ranges
            modified_rule = compute_v1.Firewall()
            modified_rule.name = firewall_rule.name
            modified_rule.description = firewall_rule.description + " [Auto-remediated]"
            modified_rule.direction = firewall_rule.direction
            modified_rule.priority = firewall_rule.priority
            modified_rule.target_tags = firewall_rule.target_tags
            modified_rule.target_service_accounts = firewall_rule.target_service_accounts
            modified_rule.allowed = firewall_rule.allowed
            modified_rule.denied = firewall_rule.denied
            
            # Replace 0.0.0.0/0 with more restrictive ranges
            new_source_ranges = []
            for source_range in firewall_rule.source_ranges:
                if source_range == '0.0.0.0/0':
                    # Replace with common private network ranges
                    new_source_ranges.extend([
                        '10.0.0.0/8',      # Private Class A
                        '172.16.0.0/12',   # Private Class B
                        '192.168.0.0/16'   # Private Class C
                    ])
                else:
                    new_source_ranges.append(source_range)
                    
            modified_rule.source_ranges = new_source_ranges
            
            # Update the firewall rule
            request = compute_v1.UpdateFirewallRequest(
                project=self.project_id,
                firewall=firewall_rule.name,
                firewall_resource=modified_rule
            )
            
            operation = self.compute_client.update(request=request)
            self.wait_for_operation(operation)
            
            logger.info(f"Modified firewall rule: {firewall_rule.name}")
            
        except Exception as e:
            logger.error(f"Failed to modify firewall rule {firewall_rule.name}: {e}")

    def wait_for_operation(self, operation, timeout: int = 300) -> None:
        """Wait for GCP operation to complete"""
        import time
        
        start_time = time.time()
        while not operation.done() and (time.time() - start_time) < timeout:
            time.sleep(2)
            # Note: In real implementation, you'd use operation.wait() or similar
            break  # Simplified for this example

    def log_remediation_action(self, rule_name: str, action_type: str) -> None:
        """Log remediation action for audit purposes"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'firewall_rule_remediation',
            'firewall_rule_name': rule_name,
            'project_id': self.project_id,
            'remediation_type': action_type,
            'original_issue': 'source_range_0.0.0.0/0'
        }
        
        logger.info(f"Remediation completed: {json.dumps(log_entry)}")
        
        # Send structured log to Cloud Logging
        try:
            cloud_logger = self.logging_client.logger('security-remediation')
            cloud_logger.log_struct(log_entry, severity='INFO')
        except Exception as e:
            logger.error(f"Failed to send log to Cloud Logging: {e}")
            
        # Optionally publish to Pub/Sub for notifications
        try:
            if os.environ.get('NOTIFICATION_PUBSUB_TOPIC'):
                topic_path = self.publisher.topic_path(
                    self.project_id, 
                    os.environ['NOTIFICATION_PUBSUB_TOPIC']
                )
                
                message_data = json.dumps(log_entry).encode('utf-8')
                self.publisher.publish(topic_path, message_data)
                
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

# For Cloud Functions deployment
def main(request):
    """HTTP Cloud Function entry point"""
    try:
        request_json = request.get_json(silent=True)
        if not request_json:
            return {'error': 'No JSON data provided'}, 400
            
        remediator = GCPFirewallRemediator()
        remediator.process_alert(request_json)
        
        return {'status': 'success'}, 200
        
    except Exception as e:
        logger.error(f"Error in Cloud Function: {e}")
        return {'error': str(e)}, 500

# Standalone execution for testing
if __name__ == '__main__':
    remediator = GCPFirewallRemediator()
    
    # Example test event
    test_event = {
        'firewall_rule_name': 'allow-all-ssh',
        'project_id': 'your-project-id'
    }
    
    remediator.process_alert(test_event)