# AWS Dynamic Security Group Updater 🛡️

A simple Python script to automatically update an AWS EC2 Security Group to allow SSH access from your current, dynamic public IP address.

This tool is perfect for developers who need to SSH into their EC2 instances from locations with a non-static IP address (like a home or office network). It cleans up old, stale IP rules and ensures only your current IP is authorized.

---

## ✨ Features

- **Automatic IP Detection**: Fetches your current public IP address automatically.
- **Rule Cleanup**: Intelligently finds and removes old `/32` SSH rules from the specified security group.
- **Idempotent**: If the rule for your current IP already exists, the script does nothing.
- **Secure**: Only manages rules for a specific port (default is SSH port 22) and `/32` CIDR blocks, leaving other rules untouched.
- **Easy to Configure**: The target Security Group is set via a single environment variable.

---

## 📋 Prerequisites

Before you begin, ensure you have the following:

1.  **Python 3.x** installed.
2.  An **AWS Account** with an IAM user or role that has permissions for the following actions:
    - `ec2:DescribeSecurityGroups`
    - `ec2:AuthorizeSecurityGroupIngress`
    - `ec2:RevokeSecurityGroupIngress`
3.  **AWS Credentials Configured**: You must have your AWS credentials configured where `boto3` can find them. The most common way is to install the AWS CLI and run `aws configure`.

---

## 🚀 Installation

1.  **Clone the repository:**

    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Install the required Python packages:**
    It's recommended to use a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```
    ***

## ▶️ Usage

Running the script is a two-step process:

1.  **Set the Environment Variable**:
    You must set the `security-group` environment variable to the ID of the security group you want to manage.

    - **Linux/macOS:**

      ```bash
      export security-group='sg-0123456789abcdef0'
      ```

    - **Windows (Command Prompt):**

      ```cmd
      set security-group=sg-0123456789abcdef0
      ```

    - **Windows (PowerShell):**
      ```powershell
      $env:security-group="sg-0123456789abcdef0"
      ```

2.  **Run the Python script:**
    Assuming the code is saved as `update_security_group.py`:
    ```bash
    python update_security_group.py
    ```

The script will print its progress to the console. If a change is made, you'll see a success message.

### Example Output (New IP)

```
INFO: Successfully fetched current public IP: 99.203.15.10
INFO: Checking security group 'sg-0123456789abcdef0'...
INFO: Found an old rule for IP: 54.12.34.56/32. It will be removed.
INFO: Revoking 1 old ingress rule(s)...
INFO: Successfully revoked old rule(s).
INFO: Authorizing new ingress rule for 99.203.15.10/32 on port 22...
SUCCESS: Successfully added inbound rule for 99.203.15.10/32.
```

### Example Output (IP Unchanged)

```
INFO: Successfully fetched current public IP: 99.203.15.10
INFO: Checking security group 'sg-0123456789abcdef0'...
SUCCESS: Inbound rule for your current IP (99.203.15.10/32) on port 22 already exists.
```

Of course. Here is the complete `Readme.md` content from the first response, formatted inside a single code block for easy copying.

````markdown
# AWS Dynamic Security Group Updater 🛡️

A simple Python script to automatically update an AWS EC2 Security Group to allow SSH access from your current, dynamic public IP address.

This tool is perfect for developers who need to SSH into their EC2 instances from locations with a non-static IP address (like a home or office network). It cleans up old, stale IP rules and ensures only your current IP is authorized.

---

## ✨ Features

- **Automatic IP Detection**: Fetches your current public IP address automatically.
- **Rule Cleanup**: Intelligently finds and removes old `/32` SSH rules from the specified security group.
- **Idempotent**: If the rule for your current IP already exists, the script does nothing.
- **Secure**: Only manages rules for a specific port (default is SSH port 22) and `/32` CIDR blocks, leaving other rules untouched.
- **Easy to Configure**: The target Security Group is set via a single environment variable.

---

## 📋 Prerequisites

Before you begin, ensure you have the following:

1.  **Python 3.x** installed.
2.  An **AWS Account** with an IAM user or role that has permissions for the following actions:
    - `ec2:DescribeSecurityGroups`
    - `ec2:AuthorizeSecurityGroupIngress`
    - `ec2:RevokeSecurityGroupIngress`
3.  **AWS Credentials Configured**: You must have your AWS credentials configured where `boto3` can find them. The most common way is to install the AWS CLI and run `aws configure`.

---

## 🚀 Installation

1.  **Clone the repository:**

    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Install the required Python packages:**
    It's recommended to use a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```
    If you don't have a `requirements.txt` file, create one with the following content:
    ```
    boto3
    requests
    ```

---

## ▶️ Usage

Running the script is a two-step process:

1.  **Set the Environment Variable**:
    You must set the `security-group` environment variable to the ID of the security group you want to manage.

    - **Linux/macOS:**

      ```bash
      export security-group='sg-0123456789abcdef0'
      ```

    - **Windows (Command Prompt):**

      ```cmd
      set security-group=sg-0123456789abcdef0
      ```

    - **Windows (PowerShell):**
      ```powershell
      $env:security-group="sg-0123456789abcdef0"
      ```

2.  **Run the Python script:**
    Assuming the code is saved as `update_security_group.py`:
    ```bash
    python update_security_group.py
    ```

The script will print its progress to the console. If a change is made, you'll see a success message.

### Example Output (New IP)
````

INFO: Successfully fetched current public IP: 99.203.15.10
INFO: Checking security group 'sg-0123456789abcdef0'...
INFO: Found an old rule for IP: 54.12.34.56/32. It will be removed.
INFO: Revoking 1 old ingress rule(s)...
INFO: Successfully revoked old rule(s).
INFO: Authorizing new ingress rule for 99.203.15.10/32 on port 22...
SUCCESS: Successfully added inbound rule for 99.203.15.10/32.

```

### Example Output (IP Unchanged)
```

INFO: Successfully fetched current public IP: 99.203.15.10
INFO: Checking security group 'sg-0123456789abcdef0'...
SUCCESS: Inbound rule for your current IP (99.203.15.10/32) on port 22 already exists.

---

## ⚙️ How It Works

The script logic is straightforward:

1.  **Get Public IP**: It sends a request to `http://checkip.amazonaws.com` to get your machine's current public IP address.
2.  **Describe Security Group**: It uses `boto3` to connect to AWS and fetch all the existing ingress rules for the security group specified by the `security-group` environment variable.
3.  **Analyze Rules**: It iterates through the inbound rules, looking specifically for those that match the configured `PORT` (22) and `PROTOCOL` ('tcp').
    - It identifies any `/32` rules that **do not** match your current IP. These are considered "old" rules to be removed.
    - It checks if a rule for your current IP already exists.
4.  **Revoke Old Rules**: If any old rules were found, it issues a `revoke_security_group_ingress` command to remove them in a single API call.
5.  **Authorize New Rule**: If a rule for the current IP does not already exist, it issues an `authorize_security_group_ingress` command to add one, including a helpful description.

---

## 🔧 Customization

While the primary configuration is through the environment variable, you can modify the constants at the top of the script file (`update_security_group.py`) to change its behavior:

- `PORT`: Change the port to manage access for other services (e.g., `3389` for RDP).
- `PROTOCOL`: Change the protocol (e.g., `udp`).
- `IP_CHECK_SERVICE`: Change the service used to detect the public IP if needed.
