import azure.functions as func
from .azure_nsg_remediation import AzureNSGRemediator

def main(msg: func.ServiceBusMessage) -> None:
    """Azure Function entry point"""
    remediator = AzureNSGRemediator()
    remediator.main(msg)

def http_main(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger entry point"""
    remediator = AzureNSGRemediator()
    return remediator.http_trigger(req)