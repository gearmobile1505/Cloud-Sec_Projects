from gcp_firewall_remediation import GCPFirewallRemediator
import functions_framework

@functions_framework.cloud_event
def main(cloud_event):
    """Cloud Function entry point"""
    remediator = GCPFirewallRemediator()
    return remediator.pubsub_handler(cloud_event)