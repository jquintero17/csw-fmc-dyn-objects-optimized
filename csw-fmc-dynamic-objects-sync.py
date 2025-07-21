#!/usr/bin/env python3
"""
Simplified CSW to FMC Dynamic Objects Synchronization Script

This script combines the functionality of both csw-all-inventory-processing.py 
and fmc-dynobjects-all-objects.py into a single, streamlined solution.

It performs the following operations:
1. Connects to CSW (Cisco Secure Workload) to retrieve inventory data
2. Processes the inventory data into dynamic object mappings
3. Connects to FMC (Firepower Management Center) to synchronize dynamic objects
4. Continuously monitors and updates the dynamic objects every 30 seconds
"""

import argparse
import json
import requests
import time
import pandas as pd
import threading
import logging
from datetime import datetime
from tetpyclient import RestClient
from json import loads, dumps
from tqdm import tqdm
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
DEBUG_ENABLED = False
PREFIX_FILTER = "csw-fmc-"
LOG_FILE = "csw-fmc-sync.log"

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
current_fmc_header = {}
previous_csw_data = []

def log_message(message):
    """Prints and logs a message with timestamp if debug is enabled."""
    if DEBUG_ENABLED:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"{timestamp} - {message}"
        print(log_msg)
        logging.info(log_msg)

def sanitize_name(name):
    """Sanitize name to conform to API requirements."""
    sanitized = name.replace(" ", "-")
    return ''.join(c if c.isalnum() or c in ['-', '_'] else '' for c in sanitized)

def normalize_ip(ip):
    """Normalize IP address by adding /32 if no CIDR is present."""
    return f"{ip}/32" if '/' not in ip else ip

class CSWProcessor:
    """Handles CSW API interactions and data processing."""
    
    def __init__(self, cluster, scope_name, credentials_file="api-csw.json"):
        self.cluster = cluster
        self.scope_name = scope_name
        self.api_endpoint = f"https://{cluster}"
        
        try:
            self.rc = RestClient(self.api_endpoint, credentials_file=credentials_file, verify=False)
        except Exception as e:
            log_message(f"Error initializing CSW REST client: {e}")
            raise

    def pagination(self, api_uri_path, method, **kwargs):
        """Handle API pagination for CSW requests."""
        all_results = []
        try:
            response = method(api_uri_path, **kwargs)
            if response.status_code != 200:
                log_message(f"Error accessing {api_uri_path}: {response.status_code}")
                return []

            results = response.json()
            
            if isinstance(results, list):
                return results
            elif isinstance(results, dict):
                if results.get('results'):
                    all_results += results['results']
                    while results.get("offset") and "post" in str(method.__func__):
                        next_page = results["offset"]
                        req_payload = loads(kwargs["json_body"])
                        req_payload["offset"] = next_page
                        kwargs["json_body"] = dumps(req_payload)
                        response = method(api_uri_path, **kwargs)
                        results = response.json()
                        if results.get('results'):
                            all_results += results['results']
                return all_results
            return []
        except Exception as e:
            log_message(f"Error in pagination: {e}")
            return []

    def hit_api(self, uri_path, method, **kwargs):
        """Make API calls to CSW with pagination support."""
        try:
            response = self.pagination(uri_path, method, **kwargs)
            if isinstance(response, list):
                return response
            elif isinstance(response, dict):
                return response.get("results", response)
            return response
        except Exception as e:
            log_message(f"Error hitting CSW API: {e}")
            return []

    def process_inventory_data(self):
        """Retrieve and process CSW inventory data."""
        log_message("Starting CSW inventory processing...")
        
        # Get inventory filters
        filters = self.hit_api("/filters/inventories", self.rc.get)
        num_filters = len(filters)
        log_message(f"Retrieved {num_filters} inventory filters from CSW")
        
        # Process each filter
        all_results = []
        for filter_item in filters:
            log_message(f"Processing filter: {filter_item['name']}")
            
            req_payload = {
                "filter": filter_item["query"],
                "scopeName": self.scope_name
            }
            
            result = self.hit_api("/inventory/search", self.rc.post, 
                                json_body=dumps(req_payload), pagination=True)
            
            if isinstance(result, list):
                for entry in result:
                    if isinstance(entry, dict) and entry.get('ip'):
                        entry['filter_name'] = filter_item["name"]
                        all_results.append(entry)
        
        log_message(f"Total inventory items processed: {len(all_results)}")
        return self.convert_to_dynamic_objects(all_results)

    def convert_to_dynamic_objects(self, inventory_data):
        """Convert inventory data to FMC dynamic object format."""
        if not inventory_data:
            return []
        
        # Create DataFrame for processing
        df = pd.DataFrame(inventory_data)
        
        # Netmask to CIDR mapping
        netmask_to_cidr = {
            '255.255.255.255': '/32', '255.255.255.254': '/31', '255.255.255.252': '/30',
            '255.255.255.248': '/29', '255.255.255.240': '/28', '255.255.255.224': '/27',
            '255.255.255.192': '/26', '255.255.255.128': '/25', '255.255.255.0': '/24',
            '255.255.254.0': '/23', '255.255.252.0': '/22', '255.255.248.0': '/21',
            '255.255.240.0': '/20', '255.255.224.0': '/19', '255.255.192.0': '/18',
            '255.255.128.0': '/17', '255.255.0.0': '/16', '255.254.0.0': '/15',
            '255.252.0.0': '/14', '255.248.0.0': '/13', '255.240.0.0': '/12',
            '255.224.0.0': '/11', '255.192.0.0': '/10', '255.128.0.0': '/9',
            '255.0.0.0': '/8', '254.0.0.0': '/7', '252.0.0.0': '/6',
            '248.0.0.0': '/5', '240.0.0.0': '/4', '224.0.0.0': '/3',
            '192.0.0.0': '/2', '128.0.0.0': '/1', '0.0.0.0': '/0'
        }
        
        # Process mappings
        def process_mapping(row):
            ip = row.get('ip', '')
            if not ip or pd.isna(ip):
                return None
            
            netmask = row.get('netmask', '')
            if '/' in ip:
                ip, cidr = ip.split('/')
                cidr = f'/{cidr}'
            else:
                cidr = None
            
            if pd.isna(netmask) or netmask == '':
                netmask_cidr = cidr if cidr else '/32'
            else:
                netmask_cidr = netmask_to_cidr.get(netmask, '/32')
            
            return f"{ip}{netmask_cidr}"
        
        df['mappings'] = df.apply(process_mapping, axis=1)
        df = df[df['mappings'].notna()]  # Remove invalid entries
        
        # Group by filter_name and create dynamic objects
        grouped = df.groupby('filter_name')['mappings'].apply(list).reset_index()
        
        dynamic_objects = []
        for _, row in grouped.iterrows():
            dynamic_obj = {
                "name": sanitize_name(f"{PREFIX_FILTER}{row['filter_name']}"),
                "type": "DynamicObject",
                "objectType": "IP",
                "items": [{"mapping": mapping} for mapping in row['mappings'] if mapping]
            }
            dynamic_objects.append(dynamic_obj)
        
        log_message(f"Created {len(dynamic_objects)} dynamic objects")
        return dynamic_objects

class FMCManager:
    """Handles FMC API interactions and dynamic object synchronization."""
    
    def __init__(self, fmc_ip, username, password):
        self.fmc_ip = fmc_ip
        self.username = username
        self.password = password
        self.auth_path = "/api/fmc_platform/v1/auth/generatetoken"
        self.current_header = {}
        
        # Get initial token
        self.refresh_token()
        
        # Start token refresh thread
        self.token_thread = threading.Thread(target=self.token_refresh_worker, daemon=True)
        self.token_thread.start()

    def get_token(self):
        """Get authentication token from FMC."""
        try:
            url = f"https://{self.fmc_ip}{self.auth_path}"
            response = requests.post(url, auth=(self.username, self.password), verify=False)
            response.raise_for_status()
            
            return {
                'X-auth-access-token': response.headers.get('X-auth-access-token'),
                'X-auth-refresh-token': response.headers.get('X-auth-refresh-token'),
                'DOMAIN_UUID': response.headers.get('DOMAIN_UUID'),
                'Content-Type': 'application/json'
            }
        except Exception as e:
            log_message(f"Error getting FMC token: {e}")
            raise

    def refresh_token(self):
        """Refresh the authentication token."""
        global current_fmc_header
        try:
            self.current_header = self.get_token()
            current_fmc_header = self.current_header
            log_message("FMC token refreshed successfully")
        except Exception as e:
            log_message(f"Error refreshing FMC token: {e}")

    def token_refresh_worker(self):
        """Background worker to refresh tokens every 20 minutes."""
        while True:
            time.sleep(1200)  # 20 minutes
            self.refresh_token()

    def hit_api(self, uri_path, method, **kwargs):
        """Make API calls to FMC."""
        try:
            response = method(uri_path, **kwargs)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            log_message(f"Error hitting FMC API {uri_path}: {e}")
            raise

    def get_existing_dynamic_objects(self):
        """Get existing dynamic objects from FMC that match our prefix."""
        try:
            path = f"/api/fmc_config/v1/domain/{self.current_header['DOMAIN_UUID']}/object/dynamicobjects"
            url = f"https://{self.fmc_ip}{path}"
            
            response = self.hit_api(url, requests.get, headers=self.current_header, verify=False)
            
            if isinstance(response, dict) and 'items' in response:
                dynamic_objects = response['items']
                # Filter objects with our prefix
                filtered = [obj for obj in dynamic_objects if obj.get('name', '').startswith(PREFIX_FILTER)]
                log_message(f"Found {len(filtered)} existing dynamic objects with prefix '{PREFIX_FILTER}'")
                return filtered
            return []
        except Exception as e:
            log_message(f"Error getting existing dynamic objects: {e}")
            return []

    def get_object_mappings(self, object_id):
        """Get all mappings for a specific dynamic object."""
        all_mappings = []
        offset = 0
        limit = 25
        
        try:
            while True:
                path = f"/api/fmc_config/v1/domain/{self.current_header['DOMAIN_UUID']}/object/dynamicobjects/{object_id}/mappings?offset={offset}&limit={limit}"
                url = f"https://{self.fmc_ip}{path}"
                
                response = self.hit_api(url, requests.get, headers=self.current_header, verify=False)
                
                if isinstance(response, dict) and 'items' in response:
                    items = response['items']
                    all_mappings.extend(items)
                    paging = response.get('paging', {})
                    if len(items) < limit or offset + limit >= paging.get('count', 0):
                        break
                    offset += limit
                else:
                    break
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                log_message(f"Object {object_id} not found")
                return []
            raise
        
        return all_mappings

    def synchronize_objects(self, csw_objects):
        """Synchronize CSW objects with FMC dynamic objects."""
        log_message("Starting FMC synchronization...")
        
        # Get existing objects from FMC
        existing_objects = self.get_existing_dynamic_objects()
        
        csw_names = {obj['name'] for obj in csw_objects}
        existing_names = {obj['name'] for obj in existing_objects}
        
        # Objects to add and remove
        to_add = csw_names - existing_names
        to_remove = existing_names - csw_names
        
        log_message(f"Objects to add: {len(to_add)}, to remove: {len(to_remove)}")
        
        # Remove objects that no longer exist in CSW
        if to_remove:
            self.remove_objects(existing_objects, to_remove)
        
        # Add new objects
        if to_add:
            self.add_objects(csw_objects, to_add)
        
        # Update mappings for existing objects
        existing_to_update = csw_names & existing_names
        if existing_to_update:
            self.update_object_mappings(csw_objects, existing_objects, existing_to_update)

    def remove_objects(self, existing_objects, names_to_remove):
        """Remove dynamic objects from FMC."""
        ids_to_remove = [obj['id'] for obj in existing_objects if obj['name'] in names_to_remove]
        
        if ids_to_remove:
            try:
                ids_filter = ','.join(ids_to_remove)
                path = f"/api/fmc_config/v1/domain/{self.current_header['DOMAIN_UUID']}/object/dynamicobjects?filter=ids%3A{ids_filter}&bulk=true"
                url = f"https://{self.fmc_ip}{path}"
                
                response = requests.delete(url, headers=self.current_header, verify=False)
                response.raise_for_status()
                log_message(f"Removed {len(ids_to_remove)} dynamic objects")
            except Exception as e:
                log_message(f"Error removing objects: {e}")

    def add_objects(self, csw_objects, names_to_add):
        """Add new dynamic objects to FMC."""
        add_payload = []
        
        for name in names_to_add:
            csw_obj = next((obj for obj in csw_objects if obj['name'] == name), None)
            if csw_obj:
                add_payload.append({
                    "name": csw_obj['name'],
                    "type": "DynamicObject",
                    "objectType": "IP"
                })
        
        if add_payload:
            try:
                path = f"/api/fmc_config/v1/domain/{self.current_header['DOMAIN_UUID']}/object/dynamicobjects?bulk=true"
                url = f"https://{self.fmc_ip}{path}"
                
                response = requests.post(url, headers=self.current_header, json=add_payload, verify=False)
                response.raise_for_status()
                log_message(f"Added {len(add_payload)} new dynamic objects")
            except Exception as e:
                log_message(f"Error adding objects: {e}")

    def update_object_mappings(self, csw_objects, existing_objects, names_to_update):
        """Update mappings for existing dynamic objects."""
        mapping_payload = {"add": [], "remove": []}
        
        for name in names_to_update:
            csw_obj = next((obj for obj in csw_objects if obj['name'] == name), None)
            existing_obj = next((obj for obj in existing_objects if obj['name'] == name), None)
            
            if csw_obj and existing_obj:
                # Get current mappings from FMC
                current_mappings = self.get_object_mappings(existing_obj['id'])
                api_mappings = {normalize_ip(item['mapping']) for item in current_mappings}
                
                # Get desired mappings from CSW
                file_mappings = {normalize_ip(item['mapping']) for item in csw_obj.get('items', [])}
                
                # Calculate differences
                to_add_mappings = file_mappings - api_mappings
                to_remove_mappings = api_mappings - file_mappings
                
                if to_add_mappings:
                    mapping_payload["add"].append({
                        "mappings": list(to_add_mappings),
                        "dynamicObject": {"name": name, "type": "DynamicObject"}
                    })
                
                if to_remove_mappings:
                    mapping_payload["remove"].append({
                        "mappings": list(to_remove_mappings),
                        "dynamicObject": {"name": name, "type": "DynamicObject"}
                    })
        
        # Apply mapping changes
        if mapping_payload["add"] or mapping_payload["remove"]:
            try:
                path = f"/api/fmc_config/v1/domain/{self.current_header['DOMAIN_UUID']}/object/dynamicobjectmappings"
                url = f"https://{self.fmc_ip}{path}"
                
                response = requests.post(url, headers=self.current_header, json=mapping_payload, verify=False)
                response.raise_for_status()
                log_message(f"Updated mappings: {len(mapping_payload['add'])} additions, {len(mapping_payload['remove'])} removals")
            except Exception as e:
                log_message(f"Error updating mappings: {e}")

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Simplified CSW to FMC Dynamic Objects Synchronization",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # CSW arguments
    parser.add_argument("csw_cluster", help="CSW cluster hostname/IP")
    parser.add_argument("csw_scope", help="CSW scope name")
    
    # FMC arguments  
    parser.add_argument("fmc_ip", help="FMC IP address")
    parser.add_argument("fmc_username", help="FMC username")
    parser.add_argument("fmc_password", help="FMC password")
    
    # Optional arguments
    parser.add_argument("--credentials", default="api-csw.json", 
                       help="CSW API credentials file (default: api-csw.json)")
    parser.add_argument("--interval", type=int, default=30,
                       help="Sync interval in seconds (default: 30)")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set debug mode
    global DEBUG_ENABLED
    DEBUG_ENABLED = args.debug
    
    # Initialize components
    try:
        log_message("Initializing CSW to FMC synchronization...")
        
        csw_processor = CSWProcessor(args.csw_cluster, args.csw_scope, args.credentials)
        fmc_manager = FMCManager(args.fmc_ip, args.fmc_username, args.fmc_password)
        
        log_message("Initialization complete. Starting synchronization loop...")
        
        # Main synchronization loop
        while True:
            try:
                start_time = time.time()
                log_message("Starting new synchronization cycle...")
                
                # Get data from CSW
                csw_objects = csw_processor.process_inventory_data()
                
                # Synchronize with FMC
                fmc_manager.synchronize_objects(csw_objects)
                
                elapsed_time = time.time() - start_time
                log_message(f"Synchronization cycle completed in {elapsed_time:.2f} seconds")
                
                # Wait for next cycle
                log_message(f"Waiting {args.interval} seconds before next sync...")
                time.sleep(args.interval)
                
            except KeyboardInterrupt:
                log_message("Synchronization stopped by user")
                break
            except Exception as e:
                log_message(f"Error in synchronization cycle: {e}")
                log_message(f"Retrying in {args.interval} seconds...")
                time.sleep(args.interval)
                
    except Exception as e:
        log_message(f"Fatal error during initialization: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
