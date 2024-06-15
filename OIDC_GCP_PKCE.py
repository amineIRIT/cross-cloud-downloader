import os
import re
import html
import json
import base64
import hashlib
import requests
import urllib.parse
from colorama import Fore, Style
from google.cloud import storage


# Keycloak OIDC Configuration
keycloak_url = 'https://lemur-0.cloud-iam.com/auth/realms/sieramulticloudoidc'     # URL of your Keycloak server
client_id = 'xxx'  # Client ID for Keycloak # OMMITED FOR CONFIDENTIALITY
redirect_uri = 'https://bucketucv1.s3.eu-west-3.amazonaws.com'  # Redirect URI for PKCE flow
client_secret = 'xxx'  # Client secret for Keycloak # OMMITED FOR CONFIDENTIALITY
username = 'xxx'  # Username for Keycloak # OMMITED FOR CONFIDENTIALITY
password = 'xxx'  # Password for Keycloak # OMMITED FOR CONFIDENTIALITY
state = 'multicloud'  # State for PKCE flow

# Google Cloud Storage Configuration
bucket_name = 'xxx'  # Name of the bucket in Google Cloud Storage # OMMITED FOR CONFIDENTIALITY
file_name = 'sujet.pdf'  # Name of the file in Google Cloud Storage
file_destination = f"[{os.path.splitext(os.path.basename(__file__))[0]}]{file_name}"  # Destination of the file to be downloaded

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
        
        with open('tokenGCP.txt', 'w') as f:
            f.write(result['id_token'])  # Write the token to a file
        print("token saved in token.txt")
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Finished attempting to get OIDC token.")


# Function to download a file from Google Cloud Storage
def download_file(bucket_name, source_blob_name, destination_file_name):
    try:
        # Retrieve the token  and exchange it for Google short lived credentials.
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = '/Users/.../clientLibraryConfig-sieramulticloudoidc.json' # OMMITED FOR CONFIDENTIALITY
        storage_client = storage.Client(project='xxx')  # Create a storage client # OMMITED FOR CONFIDENTIALITY
        
        bucket = storage_client.get_bucket(bucket_name)  # Get the bucket
        blob = bucket.blob(source_blob_name)  # Get the blob
        blob.download_to_filename(destination_file_name)  # Download the blob to a file
        print(f"{Fore.GREEN}File {file_destination} successfully downloaded from GOOGLE CLOUD.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error downloading file from Google Cloud Storage{Style.RESET_ALL}")  # Print error message if there's an error
        print(f"{e}")

# Main function
def main():
    oidc_token = get_oidc_token()  # Get the OIDC token
    download_file(bucket_name, file_name, file_destination)  # Download the file

if __name__ == '__main__':
    main()  # Run the main function
