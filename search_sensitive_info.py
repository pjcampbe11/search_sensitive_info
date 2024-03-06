import argparse
import os
import re

# Further extended list of specific search patterns for local scanning
SEARCH_PATTERNS = [
    r'API_KEY|api_key=|GITHUB_TOKEN|AWS_ACCESS_KEY_ID',
    r'SECRET_TOKEN|secret_key_base|JWT_SECRET|encryption_key',
    r'DATABASE_URL|MYSQL_ROOT_PASSWORD|db_password',
    r'\.env secret|config/database\.yml secret|settings\.py secret',
    r'BEGIN PRIVATE KEY secret|BEGIN CERTIFICATE secret',
    r'aws_secret_access_key|\.aws/credentials|\.s3cfg',
    r'login=|password=|authToken',
    r'deploy\.sh secret|Dockerfile secret|docker-compose\.yml secret',
    r'admin_password|config/master\.key|id_rsa private',
    r'oauth_token|auth_token|client_secret',
    r'stripe_api_key|paypal_client_id|paypal_secret',
    r'sendgrid_api_key|twilio_api_key|mailgun_api_key',
    r'ssh_passphrase|jenkins_credentials',
    r'firebase_url|firebase_secret|firebase_config',
    r'google_api_key|google_oauth|azure_storage_account_key',
    r'heroku_api_key|heroku_oauth_token|slack_webhook',
    r'slack_token|slack_api_token|telegram_bot_token',
    r'github_oauth_token|gitlab_token|bitbucket_client_id|bitbucket_secret',
    # Additional patterns adapted for local file content matching
    r'private_key\.pem|access_token|refresh_token',
    r's3cfg_pass|pgpass|\.htpasswd|shadow|passwd',
    r'api_key:|ftp://|sftp://|smtp_pass|secret_access_key',
    r'client_email|private_key_id|webhook_secret|webhook_url',
    r'deployment_key|encrypt_key|SECRET_KEY_BASE|secret_key_base:',
    r'CF_API_KEY|mail_password|GH_TOKEN|travis_encrypt',
    r'exposed_aws_key|exposed_aws_secret|exposed_azure_key',
    r'exposed_google_cloud_key|exposed_digital_ocean_token',
]

# Initialize argument parser
parser = argparse.ArgumentParser(description="Search for sensitive information in a downloaded GitHub repository.")
parser.add_argument('directory', type=str, help="Path to the local repository directory")
args = parser.parse_args()

def search_files(directory, patterns):
    """Recursively search through files in a directory for given regex patterns."""
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                            findings.append((file_path, pattern))
                            break  # Found a pattern, no need to check others
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
    return findings

def main():
    findings = search_files(args.directory, SEARCH_PATTERNS)

    # Output findings
    for file_path, pattern in findings:
        print(f"Match found for pattern '{pattern}' in: {file_path}")

if __name__ == '__main__':
    main()