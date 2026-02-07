#!/usr/bin/env python3
"""
Azure Infrastructure Export Tool
Exports Azure subscription resources to JSON for diagram generation

Usage:
    python azure_export.py --subscriptions <subscription_id> -o infrastructure.json
    python azure_export.py --subscriptions <subscription_id> -o infrastructure.json --count
"""

import json
import os
import platform
from argparse import ArgumentParser
from typing import List, Dict, Any

from azure.identity import AzureCliCredential
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.databricks import AzureDatabricksManagementClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.eventgrid import EventGridManagementClient
from azure.mgmt.eventhub import EventHubManagementClient
from azure.mgmt.frontdoor import FrontDoorManagementClient
from azure.mgmt.hdinsight import HDInsightManagementClient
from azure.mgmt.iothub import IotHubClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.mgmt.rdbms.mysql import MySQLManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.servicebus import ServiceBusManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.web import WebSiteManagementClient


# Terminal colors for better visibility
class Colors:
    ERROR = "\033[91m"
    WARNING = "\033[93m"
    SUCCESS = "\033[92m"
    INFO = "\033[94m"
    END = "\033[0m"


def print_message(msg: str, color: str = Colors.INFO):
    """Print colored message to console"""
    print(f"{color}{msg}{Colors.END}")


def safe_api_call(api_func, *args, **kwargs) -> List[Dict[str, Any]]:
    """
    Safely call Azure API and return results as list of dictionaries
    Handles pagination and errors gracefully
    """
    try:
        response = api_func(*args, **kwargs)
        result = []
        for item in response:
            result.append(item.as_dict())
        return result
    except Exception as e:
        print_message(f"\t\t\t{str(e)}", Colors.WARNING)
        return []


class AzureInfrastructureExporter:
    """Main class for exporting Azure infrastructure to JSON"""
    
    def __init__(self, subscription_ids: List[str] = None, output_file: str = "azure-infrastructure.json", count_resources: bool = False):
        self.subscription_ids = subscription_ids or []
        self.output_file = output_file if output_file.endswith('.json') else f"{output_file}.json"
        self.count_resources = count_resources
        
        # Initialize credential
        self.credential = AzureCliCredential()
        self.subscription_client = SubscriptionClient(self.credential)
        
        # Clients (initialized per subscription)
        self.clients = {}
    
    def initialize_clients(self, subscription_id: str):
        """Initialize all Azure management clients for a subscription"""
        self.clients = {
            'resource': ResourceManagementClient(self.credential, subscription_id),
            'network': NetworkManagementClient(self.credential, subscription_id),
            'compute': ComputeManagementClient(self.credential, subscription_id),
            'storage': StorageManagementClient(self.credential, subscription_id),
            'sql': SqlManagementClient(self.credential, subscription_id),
            'cosmosdb': CosmosDBManagementClient(self.credential, subscription_id),
            'web': WebSiteManagementClient(self.credential, subscription_id),
            'postgresql': PostgreSQLManagementClient(self.credential, subscription_id),
            'mysql': MySQLManagementClient(self.credential, subscription_id),
            'redis': RedisManagementClient(self.credential, subscription_id),
            'keyvault': KeyVaultManagementClient(self.credential, subscription_id),
            'dns': DnsManagementClient(self.credential, subscription_id),
            'privatedns': PrivateDnsManagementClient(self.credential, subscription_id),
            'trafficmanager': TrafficManagerManagementClient(self.credential, subscription_id),
            'cdn': CdnManagementClient(self.credential, subscription_id),
            'frontdoor': FrontDoorManagementClient(self.credential, subscription_id),
            'apimanagement': ApiManagementClient(self.credential, subscription_id),
            'servicebus': ServiceBusManagementClient(self.credential, subscription_id),
            'eventhub': EventHubManagementClient(self.credential, subscription_id),
            'iothub': IotHubClient(self.credential, subscription_id),
            'loganalytics': LogAnalyticsManagementClient(self.credential, subscription_id),
            'hdinsight': HDInsightManagementClient(self.credential, subscription_id),
            'databricks': AzureDatabricksManagementClient(self.credential, subscription_id),
            'datafactory': DataFactoryManagementClient(self.credential, subscription_id),
            'containerservice': ContainerServiceClient(self.credential, subscription_id),
            'msi': ManagedServiceIdentityClient(self.credential, subscription_id),
            'logic': LogicManagementClient(self.credential, subscription_id),
            'eventgrid': EventGridManagementClient(self.credential, subscription_id),
        }
    
    def get_network_resources(self, resource_group_name: str) -> Dict[str, List]:
        """Retrieve all network resources from a resource group"""
        print("\t\tRetrieving network resources...")
        
        network = self.clients['network']
        
        # Get VNets with FULL details (list only returns shallow data without subnets/peerings)
        vnets_shallow = safe_api_call(network.virtual_networks.list, resource_group_name)
        vnets_full = []
        for vnet in vnets_shallow:
            vnet_name = vnet.get('name', '')
            try:
                vnet_detail = network.virtual_networks.get(resource_group_name, vnet_name)
                vnets_full.append(vnet_detail.as_dict())
                subnet_count = len(vnet_detail.as_dict().get('subnets', []))
                peering_count = len(vnet_detail.as_dict().get('virtual_network_peerings', []))
                print(f"\t\t\tVNet '{vnet_name}': {subnet_count} subnets, {peering_count} peerings")
            except Exception as e:
                print_message(f"\t\t\tFailed to get VNet details for {vnet_name}: {e}", Colors.WARNING)
                vnets_full.append(vnet)  # Fallback to shallow data
        
        return {
            'applicationGateways': safe_api_call(network.application_gateways.list, resource_group_name),
            'loadBalancers': safe_api_call(network.load_balancers.list, resource_group_name),
            'virtualNetworks': vnets_full,
            'virtualNetworkGateways': safe_api_call(network.virtual_network_gateways.list, resource_group_name),
            'virtualNetworkGatewayConnections': safe_api_call(network.virtual_network_gateway_connections.list, resource_group_name),
            'localNetworkGateways': safe_api_call(network.local_network_gateways.list, resource_group_name),
            'subnets': [],  # Collected from VNets
            'publicIpAddresses': safe_api_call(network.public_ip_addresses.list, resource_group_name),
            'applicationSecurityGroups': safe_api_call(network.application_security_groups.list, resource_group_name),
            'networkSecurityGroups': safe_api_call(network.network_security_groups.list, resource_group_name),
            'networkInterfaces': safe_api_call(network.network_interfaces.list, resource_group_name),
            'firewalls': safe_api_call(network.azure_firewalls.list, resource_group_name),
            'routeTables': safe_api_call(network.route_tables.list, resource_group_name),
            'privateEndpoints': safe_api_call(network.private_endpoints.list, resource_group_name),
            'virtualWans': safe_api_call(network.virtual_wans.list_by_resource_group, resource_group_name),
            'expressRouteCircuits': safe_api_call(network.express_route_circuits.list, resource_group_name),
            'networkWatchers': safe_api_call(network.network_watchers.list_all),
            'ddosProtectionPlans': safe_api_call(network.ddos_protection_plans.list),
            'routeFilters': safe_api_call(network.route_filters.list_by_resource_group, resource_group_name),
            'serviceEndpointPolicies': safe_api_call(network.service_endpoint_policies.list_by_resource_group, resource_group_name),
            'frontDoorClassics': [],
        }
    
    def get_compute_resources(self, resource_group_name: str) -> Dict[str, List]:
        """Retrieve all compute resources from a resource group"""
        print("\t\tRetrieving compute resources...")
        
        compute = self.clients['compute']
        
        return {
            'disks': safe_api_call(compute.disks.list_by_resource_group, resource_group_name),
            'virtualMachines': safe_api_call(compute.virtual_machines.list, resource_group_name),
            'virtualMachineScaleSets': safe_api_call(compute.virtual_machine_scale_sets.list, resource_group_name),
        }
    
    def get_database_resources(self, resource_group_name: str) -> Dict[str, Dict[str, List]]:
        """Retrieve all database resources from a resource group"""
        print("\t\tRetrieving database resources...")
        
        # SQL
        sql_servers = safe_api_call(self.clients['sql'].servers.list_by_resource_group, resource_group_name)
        sql_databases = []
        for server in sql_servers:
            server_name = server['name']
            databases = safe_api_call(
                self.clients['sql'].databases.list_by_server,
                resource_group_name,
                server_name
            )
            sql_databases.extend(databases)
        
        # MySQL
        mysql_servers = safe_api_call(self.clients['mysql'].servers.list_by_resource_group, resource_group_name)
        mysql_databases = []
        
        # PostgreSQL
        postgresql_servers = safe_api_call(self.clients['postgresql'].servers.list_by_resource_group, resource_group_name)
        postgresql_databases = []
        
        return {
            'sql': {
                'servers': sql_servers,
                'databases': sql_databases,
                'managedInstances': [],
            },
            'mysql': {
                'servers': mysql_servers,
                'databases': mysql_databases,
            },
            'postgresql': {
                'servers': postgresql_servers,
                'databases': postgresql_databases,
            },
        }
    
    def get_storage_resources(self, resource_group_name: str) -> Dict[str, List]:
        """Retrieve all storage resources from a resource group"""
        print("\t\tRetrieving storage resources...")
        
        storage_accounts = safe_api_call(
            self.clients['storage'].storage_accounts.list_by_resource_group,
            resource_group_name
        )
        
        return {
            'storageAccounts': storage_accounts,
            'fileShares': [],
            'storageQueues': [],
        }
    
    def get_web_resources(self, resource_group_name: str) -> Dict[str, List]:
        """Retrieve all App Service resources from a resource group"""
        print("\t\tRetrieving App Service resources...")
        
        return {
            'appServicePlans': safe_api_call(self.clients['web'].app_service_plans.list_by_resource_group, resource_group_name),
            'webApps': safe_api_call(self.clients['web'].web_apps.list_by_resource_group, resource_group_name),
        }
    
    def get_resource_group_data(self, subscription_id: str, resource_group) -> Dict[str, Any]:
        """Collect all resources from a single resource group"""
        rg_name = resource_group['name']
        rg_id = resource_group['id']
        tags = resource_group.get('tags', {}) or {}
        
        print(f"\tProcessing Resource Group: {rg_name}")
        
        # Get all resource types
        network_resources = self.get_network_resources(rg_name)
        compute_resources = self.get_compute_resources(rg_name)
        db_resources = self.get_database_resources(rg_name)
        storage_resources = self.get_storage_resources(rg_name)
        web_resources = self.get_web_resources(rg_name)
        
        # Additional resources
        cosmosdb_accounts = safe_api_call(self.clients['cosmosdb'].database_accounts.list_by_resource_group, rg_name)
        databricks_workspaces = safe_api_call(self.clients['databricks'].workspaces.list_by_resource_group, rg_name)
        keyvaults = safe_api_call(self.clients['keyvault'].vaults.list_by_resource_group, rg_name)
        log_workspaces = safe_api_call(self.clients['loganalytics'].workspaces.list_by_resource_group, rg_name)
        
        return {
            'resourceGroupId': rg_id,
            'resourceGroupName': rg_name,
            'tags': tags,
            'resources': {
                'network': network_resources,
                'frontdoorandcdn': {
                    'frontDoorsAndCdnProfiles': [],
                },
                'compute': compute_resources,
                'cosmosdb': {
                    'databaseAccounts': cosmosdb_accounts,
                },
                'databricks': {
                    'workspaces': databricks_workspaces,
                },
                'storage': storage_resources,
                'sql': db_resources['sql'],
                'mysql': db_resources['mysql'],
                'postgresql': db_resources['postgresql'],
                'trafficmanager': {
                    'profiles': safe_api_call(self.clients['trafficmanager'].profiles.list_by_resource_group, rg_name),
                },
                'keyvault': {
                    'vaults': keyvaults,
                },
                'appservice': web_resources,
                'dns': {
                    'zones': safe_api_call(self.clients['dns'].zones.list_by_resource_group, rg_name),
                    'privateZones': safe_api_call(self.clients['privatedns'].private_zones.list_by_resource_group, rg_name),
                },
                'apimanagement': {
                    'apiManagementServices': safe_api_call(self.clients['apimanagement'].api_management_service.list_by_resource_group, rg_name),
                },
                'servicebus': {
                    'serviceBusNamespaces': safe_api_call(self.clients['servicebus'].namespaces.list_by_resource_group, rg_name),
                },
                'managedidentity': {
                    'userAssignedIdentities': safe_api_call(self.clients['msi'].user_assigned_identities.list_by_resource_group, rg_name),
                },
                'iothub': {
                    'iotHubs': safe_api_call(self.clients['iothub'].iot_hub_resource.list_by_resource_group, rg_name),
                },
                'cacheforredis': {
                    'cachesForRedis': safe_api_call(self.clients['redis'].redis.list_by_resource_group, rg_name),
                },
                'hdinsight': {
                    'clusters': safe_api_call(self.clients['hdinsight'].clusters.list_by_resource_group, rg_name),
                },
                'datafactory': {
                    'dataFactories': safe_api_call(self.clients['datafactory'].factories.list_by_resource_group, rg_name),
                },
                'loganalytics': {
                    'workspaces': log_workspaces,
                },
                'eventhubs': {
                    'eventHubs': [],
                    'eventHubsNamespaces': safe_api_call(self.clients['eventhub'].namespaces.list_by_resource_group, rg_name),
                },
                'logicapps': {
                    'workflows': safe_api_call(self.clients['logic'].workflows.list_by_resource_group, rg_name),
                },
                'eventgrid': {
                    'domains': safe_api_call(self.clients['eventgrid'].domains.list_by_resource_group, rg_name),
                    'topics': safe_api_call(self.clients['eventgrid'].topics.list_by_resource_group, rg_name),
                },
                'containerservice': {
                    'managedClusters': safe_api_call(self.clients['containerservice'].managed_clusters.list_by_resource_group, rg_name),
                },
            }
        }
    
    def count_resources(self, resource_group_data: Dict) -> int:
        """Count total resources in a resource group"""
        count = 0
        for category, resources in resource_group_data['resources'].items():
            if isinstance(resources, dict):
                for resource_type, resource_list in resources.items():
                    if isinstance(resource_list, list):
                        count += len(resource_list)
            elif isinstance(resources, list):
                count += len(resources)
        return count
    
    def export(self):
        """Main export function"""
        print_message(f"\n{'='*70}", Colors.INFO)
        print_message("Azure Infrastructure Export Tool", Colors.INFO)
        print_message(f"{'='*70}\n", Colors.INFO)
        
        # Get subscriptions
        if self.subscription_ids:
            subscriptions = [{'subscription_id': sub_id} for sub_id in self.subscription_ids]
        else:
            subscriptions_raw = safe_api_call(self.subscription_client.subscriptions.list)
            subscriptions = [{'subscription_id': sub['subscription_id']} for sub in subscriptions_raw]
        
        all_subscriptions_data = []
        total_resource_count = 0
        resource_counts = {}
        
        for subscription in subscriptions:
            sub_id = subscription['subscription_id']
            
            # Get subscription details
            try:
                sub_info = self.subscription_client.subscriptions.get(sub_id).as_dict()
                sub_name = sub_info.get('display_name', sub_id)
            except:
                sub_name = sub_id
            
            print_message(f"\n📊 Exporting Subscription: {sub_name} ({sub_id})", Colors.SUCCESS)
            
            # Initialize clients for this subscription
            self.initialize_clients(sub_id)
            
            # Get resource groups
            resource_groups = safe_api_call(self.clients['resource'].resource_groups.list)
            
            subscription_data = {
                'subscriptionId': sub_id,
                'displayName': sub_name,
                'resourceGroups': []
            }
            
            # Process each resource group
            for rg in resource_groups:
                rg_data = self.get_resource_group_data(sub_id, rg)
                subscription_data['resourceGroups'].append(rg_data)
                
                if self.count_resources:
                    count = self.count_resources(rg_data)
                    total_resource_count += count
            
            all_subscriptions_data.append(subscription_data)
        
        # Write output file
        output_data = {'subscriptions': all_subscriptions_data}
        
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print_message(f"\n{'='*70}", Colors.SUCCESS)
        print_message(f"✅ Export completed successfully!", Colors.SUCCESS)
        print_message(f"📁 Output file: {self.output_file}", Colors.SUCCESS)
        
        if self.count_resources:
            count_file = 'resource_counts.json'
            count_data = {
                'totalResourceCount': total_resource_count,
                'subscriptions': len(all_subscriptions_data),
            }
            with open(count_file, 'w') as f:
                json.dump(count_data, f, indent=2)
            print_message(f"📊 Resource counts: {count_file}", Colors.SUCCESS)
        
        print_message(f"{'='*70}\n", Colors.SUCCESS)


def main():
    """CLI entry point"""
    parser = ArgumentParser(
        description='Export Azure infrastructure to JSON for diagram generation',
        epilog='Example: python azure_export.py --subscriptions xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -o infrastructure.json'
    )
    
    parser.add_argument(
        '-s', '--subscriptions',
        type=str,
        nargs='+',
        help='Subscription IDs to export (space-separated). If omitted, exports all accessible subscriptions.'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='azure-infrastructure.json',
        help='Output file name (default: azure-infrastructure.json)'
    )
    
    parser.add_argument(
        '-c', '--count',
        action='store_true',
        help='Generate resource count summary'
    )
    
    args = parser.parse_args()
    
    # Enable colored output on Windows
    if platform.system() == "Windows":
        os.system("color")
    
    # Run export
    exporter = AzureInfrastructureExporter(
        subscription_ids=args.subscriptions,
        output_file=args.output,
        count_resources=args.count
    )
    
    exporter.export()


if __name__ == "__main__":
    main()
