import os
import boto3
from urllib.parse import unquote
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

def download_s3_chunks(bucket_name, output_directory, file_prefix):
    boto3.setup_default_session(profile_name="rolesanywhere")
    s3 = boto3.client('s3')

    #Initialise the chunks array
    chunks = []
    
    # List objects in the S3 bucket
    response = s3.list_objects(Bucket=bucket_name)
    for obj in response.get('Contents', []):
        key = obj['Key']
        if key.startswith(file_prefix):
            chunks.append(key)

    # Download and assemble AWS S3 chunks
    chunks.sort()
    for chunk_key in chunks:
        try:
            chunk_path = os.path.join(output_directory, chunk_key)
            s3.download_file(bucket_name, chunk_key, chunk_path)
        except Exception as e:
            print(f"Skipping chunk due to error")

def download_azure_chunks(account_name, account_key, container_name, output_directory, file_prefix):
    blob_service_client = BlobServiceClient(account_url=f"https://{account_name}.blob.core.windows.net", credential=account_key)
    
    #Initialise the chunks array
    chunks = []
    
    # List blobs in the Azure Blob Storage container
    container_client = blob_service_client.get_container_client(container_name)
    blobs = container_client.list_blobs()
    for blob in blobs:
        if blob.name.startswith(file_prefix):
            chunks.append(blob.name)

    # Download and assemble Azure Blob Storage chunks
    chunks.sort()
    for chunk_key in chunks:
        try:
            blob_client = container_client.get_blob_client(chunk_key)
            chunk_path = os.path.join(output_directory, chunk_key)
            with open(chunk_path, 'wb') as chunk_file:
                blob_data = blob_client.download_blob()
                chunk_file.write(blob_data.readall())
        except Exception as e:
            print(f"Skipping chunk due to error")


def download_google_chunks(bucket_name, output_directory, file_prefix):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = '/media/ucv/smiling-matrix-411512-e04ec58d7fc7.json'
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)

    #Initialise the chunks array
    chunks = []
    
    # List blobs in the GCS bucket
    blobs = bucket.list_blobs()
    for blob in blobs:
        if blob.name.startswith(file_prefix):
            chunks.append(blob.name)

    # Download and assemble Google Cloud Storage chunks
    chunks.sort()
    for chunk_key in chunks:
        try:
            blob = bucket.blob(chunk_key)
            chunk_path = os.path.join(output_directory, chunk_key)
            blob.download_to_filename(chunk_path)
        except Exception as e:
            print(f"Skipping chunk due to error")

def assemble_file(input_directory, output_file):
    files = [f for f in os.listdir(input_directory) if os.path.isfile(os.path.join(input_directory, f))]
    files.sort()

    with open(output_file, 'wb') as out:
        for file in files:
            file_path = os.path.join(input_directory, file)
            with open(file_path, 'rb') as f:
                out.write(f.read())
    
def keep_before_period(input_string):
    # Split the string at the first period
    parts = input_string.split('.', 1)
    
    # If a period is found, return everything before it, otherwise, return the original string
    return parts[0] if len(parts) > 0 else input_string



if __name__ == "__main__":
    #Get the file name
    fileName = input("Enter file name : ")
    file_prefix = keep_before_period(fileName)+'_'
    
    #AWS
    s3_bucket_name = 'xxx' # OMMITED FOR CONFIDENTIALITY
    
    #GCP
    gcp_bucket_name = 'xxx' # OMMITED FOR CONFIDENTIALITY
    
    #Azure
    azure_container_name = 'xxx' # OMMITED FOR CONFIDENTIALITY
    azure_account_name = 'xxx' # OMMITED FOR CONFIDENTIALITY
    azure_account_key = 'xxx' # OMMITED FOR CONFIDENTIALITY
    
    #Assign an output directory
    output_directory = '/media/ucv/downloaded_chunks'
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    download_s3_chunks(s3_bucket_name, output_directory, file_prefix)
    download_azure_chunks(azure_account_name, azure_account_key, azure_container_name, output_directory, file_prefix)
    download_google_chunks(gcp_bucket_name, output_directory, file_prefix)
    print("Download complete 100%")
    assemble_file(output_directory, '[UCV4]'+fileName)
    print("Assembly complete 100%")