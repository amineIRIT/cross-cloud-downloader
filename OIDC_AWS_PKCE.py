import os
import re
import html
import json
import boto3
import base64
import hashlib
import requests
import urllib.parse
import botocore.exceptions
from colorama import Fore, Style


# Keycloak OIDC Configuration
keycloak_url = 'https://lemur-0.cloud-iam.com/auth/realms/sieramulticloudoidc'     # URL of your Keycloak server
client_id = 'xxx'  # Client ID for Keycloak # OMMITED FOR CONFIDENTIALITY
redirect_uri = 'https://bucketucv1.s3.eu-west-3.amazonaws.com'  # Redirect URI for PKCE flow
client_secret = 'xxx'  # Client secret for Keycloak # OMMITED FOR CONFIDENTIALITY
username = 'xxx'  # Username for Keycloak # OMMITED FOR CONFIDENTIALITY
password = 'xxx'  # Password for Keycloak # OMMITED FOR CONFIDENTIALITY
state = 'multicloud'  # State for PKCE flow

# AWS Configuration
aws_region = 'eu-west-3'   # AWS Region
cognito_identity_pool_id = 'xxx' # Cognito Identity Pool ID # OMMITED FOR CONFIDENTIALITY
s3_bucket_name = 'xxx'  # S3 Bucket Name # OMMITED FOR CONFIDENTIALITY

# File name in the S3 bucket
file_name = 'sujet.pdf'
file_destination = '[' + os.path.splitext(os.path.basename(__file__))[0] + ']' +file_name

def _b64_decode(data):
    data += '=' * (4 - len(data) % 4)
    return base64.b64decode(data).decode('utf-8')

def jwt_payload_decode(jwt):
    _, payload, _ = jwt.split('.')
    return json.loads(_b64_decode(payload))

# Function to get an OIDC token using PKCE flow
def get_oidc_token():
    try: 
        # Generate code verifier and code challenge for PKCE
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        print(f"{Fore.YELLOW}CODE VERIFIER :{Style.RESET_ALL}")
        print(code_verifier)
        
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')
        print(f"{Fore.YELLOW}CODE CHALLENGE :{Style.RESET_ALL}")
        print(code_challenge)

        # Authentication parameters for PKCE flow
        auth_params = {
            'state': state,
            'scope': 'openid', #In order to get access_token and id_token
            'client_id': client_id,
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'code_challenge_method': 'S256',
            'code_challenge': code_challenge,
        }

        # Request authorization code from Keycloak
        auth_response = requests.get(f'{keycloak_url}/protocol/openid-connect/auth', params=auth_params, allow_redirects=False)
        if auth_response.status_code != 200:
            print(f"{Fore.RED}STATUS CODE :{Style.RESET_ALL}" + str(auth_response.status_code))
            auth_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}STATUS CODE :{Style.RESET_ALL}" + str(auth_response.status_code))
        
        # Parse authorization code from response URL
        cookie = auth_response.headers['Set-Cookie']
        cookie = '; '.join(c.split(';')[0] for c in cookie.split(', '))
        print(f"{Fore.YELLOW}COOKIE :{Style.RESET_ALL}")
        print(cookie)
        
        page = auth_response.text
        form_action = html.unescape(re.search('<form\s+.*?\s+action="(.*?)"', page, re.DOTALL).group(1))
        print(f"{Fore.YELLOW}FORM ACTION :{Style.RESET_ALL}" + form_action)
        #exit()
        
        # Request authorization code from Keycloak
        login_data = {
            "username": username,
            "password": password,
        }
        
        login_response = requests.post(form_action, data=login_data, headers={"Cookie": cookie}, allow_redirects=False)
        if login_response.status_code != 302:
            print(f"{Fore.RED}STATUS CODE :{Style.RESET_ALL}" + str(login_response.status_code))
            auth_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}STATUS CODE :{Style.RESET_ALL}" + str(login_response.status_code))
        print(f"{Fore.GREEN}LOGIN resp headers :{Style.RESET_ALL}")
        print(login_response.headers)
        
        redirect = login_response.headers['Location']
        print(f"{Fore.YELLOW}Redirect :{Style.RESET_ALL}" + redirect)
        
        assert redirect.startswith(redirect_uri)
        query = urllib.parse.urlparse(redirect).query
        redirect_params = urllib.parse.parse_qs(query)
        
        auth_code = redirect_params['code'][0]
        print(f"{Fore.YELLOW}Auth code :{Style.RESET_ALL}")
        print(auth_code)
        
        data_access={
            "state": state,
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_secret": client_secret,
            "grant_type": "authorization_code"
        }
        
        token_response = requests.post(f'{keycloak_url}/protocol/openid-connect/token', data=data_access, allow_redirects=False)
        if token_response.status_code != 200:
            print(f"{Fore.RED}Token resp STATUS CODE :{Style.RESET_ALL} " + str(token_response.status_code))
            token_response.raise_for_status()  # Raises an exception if the response status is 4xx, 5xx
            exit()
        print(f"{Fore.GREEN}Token resp STATUS CODE :{Style.RESET_ALL} " + str(token_response.status_code))
        #exit()
        
        result = token_response.json()
        print(f"{Fore.GREEN}Token response :{Style.RESET_ALL}")
        print(result)
        
        return result['id_token']  # Write the token to a file
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Finished attempting to get OIDC token.")


# Function to get AWS credentials from Cognito Identity Pools
def get_aws_credentials():
    cognito = boto3.client('cognito-identity', region_name=aws_region)
    JWToken=get_oidc_token()
    # Getting Cognito Identity ID
    identity_id = cognito.get_credentials_for_identity(IdentityId=cognito_identity_pool_id, 
                                                       Logins={'lemur-0.cloud-iam.com/auth/realms/sieramulticloudoidc' : JWToken})
    return identity_id.get('Credentials')

# Function to download a file from S3
def download_file(credentials):
    try:
        # Creating an S3 client with the obtained credentials
        s3 = boto3.client('s3', aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretKey'],
                        aws_session_token=credentials['SessionToken'], region_name=aws_region)

        # Downloading the file
        s3.download_file(s3_bucket_name, file_name, file_destination)
        print(f"File '{file_destination}' successfully downloaded from AWS S3.")
    except botocore.exceptions.BotoCoreError as e:
        print(f"Failed to download file '{file_name}' from AWS S3: {e}")
    except botocore.exceptions.ClientError as e:
        print(f"Client error while downloading file '{file_name}' from AWS S3: {e}")


# Main function
def main():
    # Getting AWS credentials from the Idp then Cognito Identity Pools
    aws_credentials = get_aws_credentials()
    print("TOKEN OK")

    # Downloading the file from S3
    download_file(aws_credentials)

if __name__ == '__main__':
    main()  # Run the main function
