#!/usr/bin/env python3
"""
Azure Network Security Group Auto-Remediation Script
Handles alerts from Azure Sentinel, Defender, and CNAPP tools via Service Bus/Event Grid
"""

import json
import logging
from typing import Dict, List, Any, Optional
import os
from datetime import datetime
import asyncio

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from azure.monitor.query import LogsQueryClient
from azure.core.exceptions import AzureError
import azure.functions as func

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AzureNSGRemediator:
    def __init__(self, subscription_id: str = None, tenant_id: str = None, 
                 client_id: str = None, client_secret: str = None):
        """Initialize Azure clients"""
        self.subscription_id = subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID')
        if not self.subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID must be provided")
            
        # Initialize credentials
        if client_id and client_secret and tenant_id:
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            self.credential = DefaultAzureCredential()
        
        try:
            # Initialize Azure clients
            self.network_client = NetworkManagementClient(
                self.credential, 
                self.subscription_id
            )
            self.resource_client = ResourceManagementClient(
                self.credential, 
                self.subscription_id
            )
            
            # Initialize Service Bus client for notifications
            if os.environ.get('AZURE_SERVICE_BUS_CONNECTION_STRING'):
                self.service_bus_client = ServiceBusClient.from_connection_string(
                    os.environ['AZURE_SERVICE_BUS_CONNECTION_STRING']
                )
            else:
                self.service_bus_client = None
                
        except Exception as e:
            logger.error(f"Failed to initialize Azure clients: {e}")
            raise

    def main(self, msg: func.ServiceBusMessage) -> None:
        """
        Azure Function entry point for Service Bus messages
        """
        try:
            # Parse Service Bus message
            message_body = msg.get_body().decode('utf-8')
            alert_data = json.loads(message_body)
            
            logger.info(f"Processing Service Bus message: {json.dumps(alert_data, default=str)}")
            
            self.process_alert(alert_data)
            
        except Exception as e:
            logger.error(f"Error processing Service Bus message: {e}")
            raise

    def http_trigger(self, req: func.HttpRequest) -> func.HttpResponse:
        """
        Azure Function HTTP trigger for direct invocation
        """
        try:
            req_body = req.get_json()
            if not req_body:
                return func.HttpResponse(
                    "No JSON data provided",
                    status_code=400
                )
                
            self.process_alert(req_body)
            
            return func.HttpResponse(
                json.dumps({"status": "success"}),
                status_code=200,
                mimetype="application/json"
            )
            
        except Exception as e:
            logger.error(f"Error in HTTP trigger: {e}")
            return func.HttpResponse(
                json.dumps({"error": str(e)}),
                status_code=500,
                mimetype="application/json"
            )

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

            nsg_name = resource_info.get('nsg_name')
            resource_group = resource_info.get('resource_group')
            rule_name = resource_info.get('rule_name')
            
            if nsg_name and resource_group:
                self.remediate_nsg_rule(nsg_name, resource_group, rule_name)
            else:
                logger.warning("Insufficient information for remediation")
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")

    def parse_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Parse different types of security alerts
        """
        resource_info = {}
        
        try:
            # Azure Sentinel format
            if 'entities' in alert_data:
                for entity in alert_data['entities']:
                    if entity.get('Type') == 'azure-resource':
                        resource_id = entity.get('ResourceId', '')
                        if '/networkSecurityGroups/' in resource_id:
                            parts = resource_id.split('/')
                            resource_info['resource_group'] = parts[4]
                            resource_info['nsg_name'] = parts[-1]
                            
            # Azure Defender/Security Center format
            elif 'properties' in alert_data:
                properties = alert_data['properties']
                entities = properties.get('entities', [])
                
                for entity in entities:
                    if entity.get('type') == 'azure-resource':
                        resource_id = entity.get('resourceId', '')
                        if 'networkSecurityGroups' in resource_id:
                            resource_info.update(self.parse_resource_id(resource_id))
                            
            # Azure Activity Log format
            elif 'resourceId' in alert_data:
                resource_id = alert_data['resourceId']
                if 'networkSecurityGroups' in resource_id:
                    resource_info.update(self.parse_resource_id(resource_id))
                    
            # CNAPP tool format (generic)
            elif 'resource' in alert_data:
                resource = alert_data['resource']
                resource_info['nsg_name'] = resource.get('name')
                resource_info['resource_group'] = resource.get('resourceGroup')
                resource_info['rule_name'] = resource.get('ruleName')
                
            # Direct format
            elif 'nsg_name' in alert_data:
                resource_info = alert_data
                
            # Azure Policy compliance format
            elif 'complianceState' in alert_data:
                resource_id = alert_data.get('resourceId', '')
                if 'networkSecurityGroups' in resource_id:
                    resource_info.update(self.parse_resource_id(resource_id))
                    
            return resource_info if resource_info.get('nsg_name') and resource_info.get('resource_group') else None
            
        except Exception as e:
            logger.error(f"Error parsing alert: {e}")
            return None

    def parse_resource_id(self, resource_id: str) -> Dict[str, str]:
        """Parse Azure resource ID to extract resource group and NSG name"""
        parts = resource_id.split('/')
        result = {}
        
        try:
            if 'resourceGroups' in parts:
                rg_index = parts.index('resourceGroups') + 1
                result['resource_group'] = parts[rg_index]
                
            if 'networkSecurityGroups' in parts:
                nsg_index = parts.index('networkSecurityGroups') + 1
                result['nsg_name'] = parts[nsg_index]
                
            if 'securityRules' in parts:
                rule_index = parts.index('securityRules') + 1
                if rule_index < len(parts):
                    result['rule_name'] = parts[rule_index]
                    
        except (ValueError, IndexError) as e:
            logger.error(f"Error parsing resource ID {resource_id}: {e}")
            
        return result

    def remediate_nsg_rule(self, nsg_name: str, resource_group: str, rule_name: str = None) -> None:
        """
        Remediate NSG by removing/modifying rules with 0.0.0.0/0
        """
        try:
            # Get NSG details
            nsg = self.network_client.network_security_groups.get(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name
            )
            
            logger.info(f"Processing NSG: {nsg_name} in resource group: {resource_group}")
            
            rules_remediated = 0
            
            # Check security rules for 0.0.0.0/0
            if nsg.security_rules:
                for rule in nsg.security_rules:
                    if self.rule_needs_remediation(rule):
                        if rule_name and rule.name != rule_name:
                            continue  # Skip if specific rule name provided and doesn't match
                            
                        if self.should_delete_rule(rule):
                            self.delete_nsg_rule(nsg_name, resource_group, rule.name)
                        else:
                            self.modify_nsg_rule(nsg_name, resource_group, rule)
                            
                        rules_remediated += 1
            
            # Check default security rules (read-only, but log them)
            if nsg.default_security_rules:
                for rule in nsg.default_security_rules:
                    if self.rule_needs_remediation(rule):
                        logger.warning(f"Default rule {rule.name} has 0.0.0.0/0 but cannot be modified")
            
            if rules_remediated > 0:
                self.log_remediation_action(nsg_name, resource_group, rules_remediated)
            else:
                logger.info(f"No remediation needed for NSG {nsg_name}")
                
        except AzureError as e:
            logger.error(f"Azure API error remediating NSG {nsg_name}: {e}")
        except Exception as e:
            logger.error(f"Error remediating NSG {nsg_name}: {e}")

    def rule_needs_remediation(self, rule) -> bool:
        """Check if a security rule needs remediation"""
        if not rule.source_address_prefixes and not rule.source_address_prefix:
            return False
            
        # Check source address prefix
        if rule.source_address_prefix == '0.0.0.0/0' or rule.source_address_prefix == '*':
            return True
            
        # Check source address prefixes (list)
        if rule.source_address_prefixes:
            for prefix in rule.source_address_prefixes:
                if prefix == '0.0.0.0/0' or prefix == '*':
                    return True
                    
        return False

    def should_delete_rule(self, rule) -> bool:
        """Determine if the rule should be deleted entirely"""
        # Delete high-risk inbound rules with 0.0.0.0/0
        if rule.direction.lower() == 'inbound' and rule.access.lower() == 'allow':
            high_risk_ports = ['22', '3389', '1433', '3306', '5432', '6379', '27017']
            
            # Check destination port ranges
            ports_to_check = []
            if rule.destination_port_range:
                ports_to_check.append(rule.destination_port_range)
            if rule.destination_port_ranges:
                ports_to_check.extend(rule.destination_port_ranges)
                
            for port_range in ports_to_check:
                if port_range == '*':
                    return True
                elif '-' in str(port_range):
                    start, end = map(int, str(port_range).split('-'))
                    if any(int(p) in range(start, end + 1) for p in high_risk_ports):
                        return True
                elif str(port_range) in high_risk_ports:
                    return True
                    
        return False

    def delete_nsg_rule(self, nsg_name: str, resource_group: str, rule_name: str) -> None:
        """Delete an NSG security rule"""
        try:
            operation = self.network_client.security_rules.begin_delete(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule_name
            )
            
            # Wait for operation to complete
            operation.wait()
            
            logger.info(f"Deleted security rule: {rule_name} from NSG: {nsg_name}")
            
        except AzureError as e:
            logger.error(f"Failed to delete rule {rule_name}: {e}")

    def modify_nsg_rule(self, nsg_name: str, resource_group: str, rule) -> None:
        """Modify an NSG security rule to remove 0.0.0.0/0"""
        try:
            # Create modified rule parameters
            modified_rule_params = {
                'protocol': rule.protocol,
                'access': rule.access,
                'direction': rule.direction,
                'priority': rule.priority,
                'description': f"{rule.description or ''} [Auto-remediated]".strip(),
                'source_port_range': rule.source_port_range,
                'source_port_ranges': rule.source_port_ranges,
                'destination_port_range': rule.destination_port_range,
                'destination_port_ranges': rule.destination_port_ranges,
                'destination_address_prefix': rule.destination_address_prefix,
                'destination_address_prefixes': rule.destination_address_prefixes
            }
            
            # Replace 0.0.0.0/0 with more restrictive ranges
            new_source_prefixes = []
            
            # Handle single source address prefix
            if rule.source_address_prefix:
                if rule.source_address_prefix in ['0.0.0.0/0', '*']:
                    # Replace with private network ranges
                    new_source_prefixes = [
                        '10.0.0.0/8',      # Private Class A
                        '172.16.0.0/12',   # Private Class B
                        '192.168.0.0/16'   # Private Class C
                    ]
                    modified_rule_params['source_address_prefix'] = None
                    modified_rule_params['source_address_prefixes'] = new_source_prefixes
                else:
                    modified_rule_params['source_address_prefix'] = rule.source_address_prefix
            
            # Handle multiple source address prefixes
            elif rule.source_address_prefixes:
                for prefix in rule.source_address_prefixes:
                    if prefix not in ['0.0.0.0/0', '*']:
                        new_source_prefixes.append(prefix)
                    else:
                        # Add private ranges
                        new_source_prefixes.extend([
                            '10.0.0.0/8',
                            '172.16.0.0/12',
                            '192.168.0.0/16'
                        ])
                
                modified_rule_params['source_address_prefix'] = None
                modified_rule_params['source_address_prefixes'] = list(set(new_source_prefixes))
            
            # Update the security rule
            operation = self.network_client.security_rules.begin_create_or_update(
                resource_group_name=resource_group,
                network_security_group_name=nsg_name,
                security_rule_name=rule.name,
                security_rule_parameters=modified_rule_params
            )
            
            # Wait for operation to complete
            operation.wait()
            
            logger.info(f"Modified security rule: {rule.name} in NSG: {nsg_name}")
            
        except AzureError as e:
            logger.error(f"Failed to modify rule {rule.name}: {e}")

    def log_remediation_action(self, nsg_name: str, resource_group: str, rules_count: int) -> None:
        """Log remediation action for audit purposes"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'nsg_rule_remediation',
            'nsg_name': nsg_name,
            'resource_group': resource_group,
            'subscription_id': self.subscription_id,
            'rules_remediated': rules_count,
            'remediation_type': 'remove_0.0.0.0/0_rules'
        }
        
        logger.info(f"Remediation completed: {json.dumps(log_entry)}")
        
        # Send to Service Bus for notifications
        try:
            if self.service_bus_client and os.environ.get('NOTIFICATION_QUEUE_NAME'):
                with self.service_bus_client:
                    sender = self.service_bus_client.get_queue_sender(
                        queue_name=os.environ['NOTIFICATION_QUEUE_NAME']
                    )
                    with sender:
                        message = ServiceBusMessage(json.dumps(log_entry))
                        sender.send_messages(message)
                        
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

# Azure Function entry points
def main(msg: func.ServiceBusMessage) -> None:
    """Service Bus trigger entry point"""
    remediator = AzureNSGRemediator()
    remediator.main(msg)

def http_main(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger entry point"""
    remediator = AzureNSGRemediator()
    return remediator.http_trigger(req)

# Standalone execution for testing
if __name__ == '__main__':
    remediator = AzureNSGRemediator()
    
    # Example test event
    test_event = {
        'nsg_name': 'test-nsg',
        'resource_group': 'test-rg',
        'rule_name': 'allow-all-inbound'
    }
    
    remediator.process_alert(test_event)