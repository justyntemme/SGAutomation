import boto3
import requests
from botocore.exceptions import ClientError
import sys
import os

# --- Configuration ---
# The Security Group ID is now read from the 'security-group' environment variable.
# Example of setting it in your shell before running:
# export security-group='sg-0123456789abcdef0'
PORT = 22
PROTOCOL = 'tcp'
IP_CHECK_SERVICE = 'http://checkip.amazonaws.com'

def get_public_ip():
    """
    Fetches the current public IP address from an external service.
    """
    try:
        response = requests.get(IP_CHECK_SERVICE, timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes
        ip = response.text.strip()
        print(f"INFO: Successfully fetched current public IP: {ip}")
        return ip
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not fetch public IP address. Error: {e}", file=sys.stderr)
        sys.exit(1)

def manage_security_group_rule():
    """
    Manages the SSH ingress rule for a specified security group.
    
    - Fetches the current public IP.
    - Checks if a rule for this IP already exists.
    - If not, it removes any old SSH rules and adds a new one for the current IP.
    """
    # Get Security Group ID from environment variable
    security_group_id = os.getenv('security-group')
    if not security_group_id:
        print("ERROR: The 'security-group' environment variable is not set.", file=sys.stderr)
        print("INFO: Please set it before running the script. Example: export security-group='sg-xxxxxxxx'", file=sys.stderr)
        sys.exit(1)

    current_ip = get_public_ip()
    current_cidr = f"{current_ip}/32"
    
    # Initialize the EC2 client
    # It will use your default AWS profile credentials.
    # Ensure you have run 'aws configure' or have credentials set in your environment.
    ec2 = boto3.client('ec2')

    try:
        print(f"INFO: Checking security group '{security_group_id}'...")
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        
        if not response['SecurityGroups']:
            print(f"ERROR: Security group '{security_group_id}' not found.", file=sys.stderr)
            sys.exit(1)
            
        group = response['SecurityGroups'][0]
        
        rule_exists = False
        old_rules_to_remove = []

        # Iterate through all inbound rules to find relevant SSH rules
        for permission in group.get('IpPermissions', []):
            # Check if the rule is for the correct port and protocol
            if permission.get('FromPort') == PORT and \
               permission.get('ToPort') == PORT and \
               permission.get('IpProtocol') == PROTOCOL:
                
                # Check all CIDR ranges within this rule
                for ip_range in permission.get('IpRanges', []):
                    cidr_ip = ip_range.get('CidrIp')
                    
                    if cidr_ip == current_cidr:
                        print(f"SUCCESS: Inbound rule for your current IP ({current_cidr}) on port {PORT} already exists.")
                        rule_exists = True
                    # Identify other /32 rules on the same port as candidates for removal
                    elif cidr_ip and cidr_ip.endswith('/32'):
                        print(f"INFO: Found an old rule for IP: {cidr_ip}. It will be removed.")
                        old_rules_to_remove.append(ip_range)

        # --- Revoke Old Rules ---
        if old_rules_to_remove:
            try:
                print(f"INFO: Revoking {len(old_rules_to_remove)} old ingress rule(s)...")
                revoke_params = {
                    'GroupId': security_group_id,
                    'IpPermissions': [{
                        'IpProtocol': PROTOCOL,
                        'FromPort': PORT,
                        'ToPort': PORT,
                        'IpRanges': old_rules_to_remove
                    }]
                }
                ec2.revoke_security_group_ingress(**revoke_params)
                print("INFO: Successfully revoked old rule(s).")
            except ClientError as e:
                print(f"ERROR: Failed to revoke security group rule. {e}", file=sys.stderr)
                # Continue execution to try and add the new rule anyway

        # --- Authorize New Rule ---
        if not rule_exists:
            try:
                print(f"INFO: Authorizing new ingress rule for {current_cidr} on port {PORT}...")
                auth_params = {
                    'GroupId': security_group_id,
                    'IpPermissions': [{
                        'IpProtocol': PROTOCOL,
                        'FromPort': PORT,
                        'ToPort': PORT,
                        'IpRanges': [{'CidrIp': current_cidr, 'Description': 'Automated access from my workstation'}]
                    }]
                }
                ec2.authorize_security_group_ingress(**auth_params)
                print(f"SUCCESS: Successfully added inbound rule for {current_cidr}.")
            except ClientError as e:
                # Handle the case where the rule might have been added by another process
                if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                    print(f"INFO: Rule for {current_cidr} already exists (likely added concurrently). No action needed.")
                else:
                    print(f"ERROR: Failed to authorize security group rule. {e}", file=sys.stderr)
                    sys.exit(1)

    except ClientError as e:
        print(f"ERROR: An AWS API error occurred. Check your credentials and permissions. Details: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    manage_security_group_rule()
