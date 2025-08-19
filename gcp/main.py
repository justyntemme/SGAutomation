
#!/usr/bin/env python

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import requests
from google.cloud import container_v1
from google.api_core import exceptions

# --- Configuration ---
# Service to check the external IP address.
IP_CHECK_SERVICE = 'http://checkip.amazonaws.com'

def get_public_ip():
    """
    Fetches the current public IP address from an external service.
    """
    try:
        response = requests.get(IP_CHECK_SERVICE, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes
        ip = response.text.strip()
        print(f"INFO: Successfully fetched current public IP: {ip}")
        return ip
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch public IP address. Error: {e}", file=sys.stderr)
        sys.exit(1)

def manage_gke_authorized_networks():
    """
    Manages authorized networks for a specified GKE cluster.

    - Fetches the current public IP.
    - Checks if an authorized network for this IP already exists.
    - If not, it removes any old /32 rules and adds a new one for the current IP.
    """
    # --- Get Cluster Information from Environment Variables ---
    cluster_name = os.getenv('GKE_CLUSTER_NAME')
    location = os.getenv('GKE_CLUSTER_LOCATION') # e.g., 'us-central1', 'us-central1-c'
    project_id = os.getenv('GCP_PROJECT_ID')

    if not all([cluster_name, location, project_id]):
        print("ERROR: One or more environment variables are not set.", file=sys.stderr)
        print("INFO: Please set the following variables before running:", file=sys.stderr)
        print("  export GKE_CLUSTER_NAME='your-cluster-name'", file=sys.stderr)
        print("  export GKE_CLUSTER_LOCATION='your-cluster-zone-or-region'", file=sys.stderr)
        print("  export GCP_PROJECT_ID='your-gcp-project-id'", file=sys.stderr)
        sys.exit(1)

    current_ip = get_public_ip()
    current_cidr = f"{current_ip}/32"
    display_name = "Automated access from my workstation"

    # Initialize the GKE Cluster Manager client
    # This uses Application Default Credentials.
    # Ensure you have authenticated via `gcloud auth application-default login`
    client = container_v1.ClusterManagerClient()
    
    # The full resource name of the cluster
    cluster_path = f"projects/{project_id}/locations/{location}/clusters/{cluster_name}"

    try:
        print(f"INFO: Fetching details for GKE cluster '{cluster_name}' in '{location}'...")
        cluster = client.get_cluster(name=cluster_path)

        master_authorized_networks = cluster.master_authorized_networks_config
        
        rule_exists = False
        # Keep networks that are not single IPs (/32)
        updated_cidr_blocks = [
            block for block in master_authorized_networks.cidr_blocks
            if not block.cidr_block.endswith('/32')
        ]

        # Check existing /32 rules
        for block in master_authorized_networks.cidr_blocks:
            if block.cidr_block.endswith('/32'):
                if block.cidr_block == current_cidr:
                    print(f"SUCCESS: Authorized network for your current IP ({current_cidr}) already exists.")
                    rule_exists = True
                    # If the rule exists, we still want to add it to the updated list
                    updated_cidr_blocks.append(block)
                else:
                    print(f"INFO: Found an old rule for IP: {block.cidr_block}. It will be removed.")

        # If the rule for the current IP doesn't exist, add it.
        if not rule_exists:
            print(f"INFO: Rule for {current_cidr} does not exist. It will be added.")
            new_block = container_v1.types.MasterAuthorizedNetworksConfig.CidrBlock(
                display_name=display_name,
                cidr_block=current_cidr
            )
            updated_cidr_blocks.append(new_block)

        # --- Update the Cluster ---
        # Only call the update API if a change is necessary
        original_cidrs = set(b.cidr_block for b in master_authorized_networks.cidr_blocks)
        updated_cidrs = set(b.cidr_block for b in updated_cidr_blocks)

        if original_cidrs == updated_cidrs:
            print("INFO: No changes detected. Authorized networks are already up to date.")
            return

        print("INFO: Updating cluster with new authorized networks...")
        
        # Create the updated configuration object
        new_auth_networks_config = container_v1.types.MasterAuthorizedNetworksConfig(
            enabled=True,
            cidr_blocks=updated_cidr_blocks
        )

        # Create the cluster update object
        update = container_v1.types.ClusterUpdate(
            desired_master_authorized_networks_config=new_auth_networks_config
        )

        # Perform the update operation
        operation = client.update_cluster(
            name=cluster_path,
            update=update
        )

        print(f"INFO: Update operation initiated. Waiting for completion... (Operation ID: {operation.name})")
        # You can add logic here to wait for the operation to complete if needed,
        # but for this script, initiating is often sufficient.
        print(f"SUCCESS: Cluster update for authorized networks is in progress.")


    except exceptions.NotFound:
        print(f"ERROR: GKE cluster '{cluster_name}' not found in location '{location}'.", file=sys.stderr)
        sys.exit(1)
    except exceptions.GoogleAPICallError as e:
        print(f"ERROR: A Google Cloud API error occurred. Check your permissions and configuration. Details: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    manage_gke_authorized_networks()
