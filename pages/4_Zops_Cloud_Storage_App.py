# Zyquier Streamlit web app
# ZopsCloudSecuritySolutions

import streamlit as st
from streamlit_lottie import st_lottie
import re
from werkzeug.security import generate_password_hash, check_password_hash
from azure.storage.blob import BlobServiceClient
import psycopg2
from PIL import Image
from io import BytesIO
import pandas as pd
import json
from io import StringIO
import numpy as np
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import PyPDF2
from azure.core.exceptions import ResourceExistsError
from st_paywall import add_auth


# Constants for user registration 
MAX_USERNAME_LENGTH = 150
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")





@st.cache_resource(show_spinner=False,ttl=3600)
def fetch_sorted_secrets_from_dbkey_vault():
    key_vault_name = 'zopsdatabase'
    KVUri = f"https://{key_vault_name}.vault.azure.net"

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)

    dbname = client.get_secret('dbname').value
    user = client.get_secret('user').value
    password = client.get_secret('password').value
    sslmode = "require"  # Assuming this is constant and not a secret.
    host = client.get_secret('host').value

    connection_string = "host={0} user={1} dbname={2} password={3} sslmode={4}".format(host, user, dbname, password, sslmode)

    return connection_string

# Now you can call the function
conn_string = fetch_sorted_secrets_from_dbkey_vault()


#zopaKV
@st.cache_resource(show_spinner=False,ttl=3600)
def fetch_sorted_secrets_from_key_vault():
    key_vault_name = 'zopssecretvault'
    KVUri = f"https://{key_vault_name}.vault.azure.net"

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)

    secrets_dict = {}
    for secret_properties in client.list_properties_of_secrets():
        secret_value = client.get_secret(secret_properties.name).value
        secrets_dict[secret_properties.name] = secret_value

    return dict(sorted(secrets_dict.items(), key=lambda item: int(item[0][4:])))

STORAGE_ACCOUNT_CONNECTION_STRINGS = list(fetch_sorted_secrets_from_key_vault().values())

# Database Manager Class
@st.cache_resource(ttl=3600)
class DatabaseManager:
    """Manages database operations for users."""
   
    def __init__(self, conn_string):
        self.conn_string = conn_string

    def _get_connection(self):
        try:
            return psycopg2.connect(self.conn_string)
        except psycopg2.Error as e:
            st.error(f"Connection error: {e}")
            return False
  
    def _execute_query(self, query, params=None, fetch_results=False):
        conn = self._get_connection()
        if not conn:
            return False
        
        with conn.cursor() as cursor:
            try:
                cursor.execute(query, params)
                conn.commit()
                if fetch_results:
                    return cursor.fetchall()
                return True  # Return True for successfu.col execution of non-fetching queries
            except psycopg2.Error as e:
                st.error(f"Database error: {e}")
                conn.rollback()
                return False
            
     #inserting users into database
    def register_user(self, username, email, hashed_password):
        azure_uid = self.get_next_azure_uid()  # Function to get the next Azure UID
        
        if azure_uid is None:
            # Handle the case when no Azure UIDs are available
            st.error("No more Zops Cloud Storage Accounts available. User cannot be registered at this time.")
            return False

        query = "INSERT INTO zopsusers (UserName, EmailAddress, HashedPassword, AzureUID, IsActive) VALUES (%s, %s, %s, %s, %s)"
        return self._execute_query(query, (username, email, hashed_password, azure_uid, True))
     #the next availabie storage account
    def get_next_azure_uid(self):
        available_uids = fetch_sorted_secrets_from_key_vault()
        query = "SELECT AzureUID FROM zopsusers"
        assigned_uids = self._execute_query(query, fetch_results=True)
        assigned_uids_set = {uid[0] for uid in assigned_uids} if assigned_uids else set()

        for uid in available_uids:
            if uid not in assigned_uids_set:
                return uid
        return None
     #getting the storage account for paticularr user 
    def get_azure_uid(self, username):
        query = "SELECT AzureUID FROM zopsusers WHERE UserName = %s"
        result = self._execute_query(query, (username,), fetch_results=True)
        return result[0][0] if result else None
     
    def get_user(self, username):
        query = "SELECT UserName, HashedPassword FROM zopsusers WHERE UserName = %s"
        result = self._execute_query(query, (username,), fetch_results=True)
        return result[0] if result else None
    
    def get_total_registered_users(self):
        query = "SELECT COUNT(*) FROM zopsusers"
        results = self._execute_query(query, fetch_results=True)
        return results[0][0] if results else 0
    
# Validation Functions for registration
def is_valid_username(username):
    return bool(USERNAME_PATTERN.match(username)) and 0 < len(username) <= MAX_USERNAME_LENGTH

def is_valid_email(email):
    return bool(EMAIL_PATTERN.match(email)) and len(email) <= MAX_EMAIL_LENGTH

def is_secure_password(password):
    if not (8 <= len(password) <= MAX_PASSWORD_LENGTH):
        return False

    conditions = [
        any(char.isdigit() for char in password),
        any(char.isupper() for char in password),
        any(char.islower() for char in password),
        any(char in '!@#$%^&*()' for char in password)
    ]
    return all(conditions)

# Zops Operations for user when they are logged in
@st.cache_resource(show_spinner=False,ttl=3600)
def get_connection_string_from_key_vault(secret_name):
    key_vault_name = 'zopssecretvault'
    KVUri = f"https://{key_vault_name}.vault.azure.net"

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)

    try:
        secret_value = client.get_secret(secret_name).value
        return secret_value
    except Exception as e:
        st.error(f"Error fetching secret from Azure Key Vault: {e}")
        return None
# Functions for Zops Operations
def list_containers(blob_service_client):
    return [container['name'] for container in blob_service_client.list_containers()]


def create_storage(blob_service_client):
    container_name = st.text_input("Enter a new Storage Unit name in ZopsDataCenter:")
    if st.button("Create Storage"):
        # Check for naming violations before creating the container
        naming_violations = []
        if any(c.isupper() for c in container_name):
            naming_violations.append("Container names must be lowercase. Please avoid using uppercase letters.")
        if "_" in container_name:
            naming_violations.append("Container names cannot contain underscores (_). Please use hyphens (-) instead.")
        # It's a good practice to check if the name is empty as well.
        if not container_name:
            naming_violations.append("Container name cannot be empty.")
        # Display all naming violations
        for violation in naming_violations:
            st.warning(violation)
        # If there are any naming violations, do not proceed with the creation
        if naming_violations:
            return
        try:
            blob_service_client.create_container(container_name)
            st.success(f"Storage unit '{container_name}' created successfully.")
            # If using session state to store container names, ensure it's initialized
            if 'container_names' not in st.session_state:
                st.session_state.container_names = []
            st.session_state.container_names.append(container_name)
        except ResourceExistsError as e:
            st.error(f"The storage unit '{container_name}' already exists. Please try a different name.")
        except Exception as e:
            st.error(f"An error occurred: {e}")


def upload_blob(blob_service_client, container_name, uploaded_file):
    try:
        # Create a blob client for the container and the file to be uploaded
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=uploaded_file.name)
        
        # Upload the file, here we assume the file needs to be unique and should not overwrite existing files
        blob_client.upload_blob(uploaded_file.getvalue(), overwrite=False)
        st.success("File uploaded successfully!")
        
    except ResourceExistsError:
        st.error(f"The file '{uploaded_file.name}' already exists in the storage unit '{container_name}'. Please try uploading a file with a different name, or delete the existing file if you wish to overwrite it.")
    except Exception as e:
        st.error(f"Error uploading the file: {e}")
        

def list_blobs(blob_service_client, container_name):
    container_client = blob_service_client.get_container_client(container_name)
    return [blob.name for blob in container_client.list_blobs()]

def preview_blob(blob_service_client, container_name, blob_name):
    # Fetch the blob client
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    # Download blob data
    data = blob_client.download_blob().readall()
    
    # Utility function to extract text from pdf bytes
    @st.cache_data(ttl=3600)
    def extract_text_from_pdf(pdf_bytes):
        with BytesIO(pdf_bytes) as pdf_file:
            reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text += page.extract_text()
            return text

    # Mapping file extensions to their respective preview functions
    preview_functions = {
        ('.jpeg', '.jpg', '.png'): lambda data: st.image(Image.open(BytesIO(data)), caption=blob_name, use_column_width=True),
        ('.txt',): lambda data: st.text(data.decode('utf-8')),
        ('.csv',): lambda data: st.write(pd.read_csv(StringIO(data.decode('utf-8')))),
        ('.json',): lambda data: st.json(json.loads(data.decode('utf-8'))),
        ('.py',): lambda data: st.code(data.decode('utf-8'), language='python'),
        ('.mp3', '.wav'): lambda data: st.audio(data),  # Adding audio preview
        ('.mp4',): lambda data: st.video(data),          # Adding video preview
        ('.xlsx',): lambda data: st.dataframe(pd.read_excel(BytesIO(data))),  # Adding xlsx preview 
        ('.pdf',): lambda data: st.text(extract_text_from_pdf(data))  # Adding pdf preview
    }

    file_extension = f".{blob_name.split('.')[-1].lower()}"

    for extensions, func in preview_functions.items():
        if file_extension in extensions:
            func(data)
            return
    st.warning(f"Cannot preview files with {file_extension} extension")

@st.cache_resource(ttl=3600)
def initialize_storage_account_strings():
    if 'STORAGE_ACCOUNT_CONNECTION_STRINGS' not in st.session_state:
        st.session_state['STORAGE_ACCOUNT_CONNECTION_STRINGS'] = list(fetch_sorted_secrets_from_key_vault().values())
        
@st.cache_resource(ttl=3600)
def get_db_manager():
    if 'db_manager' not in st.session_state:
        st.session_state['db_manager'] = DatabaseManager(conn_string)
    return st.session_state['db_manager']

@st.cache_resource(show_spinner=False,ttl=3600)
def initialize_app():
    # Only run expensive initialization if it hasn't been done yet
    if 'initialized' not in st.session_state:
        # Database Initialization
        db_manager = DatabaseManager(conn_string)
        # Fetch and sort secrets from key vault
        st.session_state.STORAGE_ACCOUNT_CONNECTION_STRINGS = list(fetch_sorted_secrets_from_key_vault().values())
        # Set the flag to indicate that the app is initialized
        st.session_state['initialized'] = True
        
# Main Function
def main():   
    # Initialize once per session
    initialize_storage_account_strings()
    db_manager = get_db_manager()
   
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.current_user = None
      # Registration Page  
    if not st.session_state.logged_in:
        st.title("ZOPS Secure ☁️ Storage Solution ")
        menu = ["Login", "Register"]
        choice = st.sidebar.selectbox("Menu", menu)
        # Session state initialization
        initialize_app()

        if choice == "Register":
            st.subheader("Registration Form")
            add_auth(required=True)
            new_username = st.text_input("Username")
            new_email = st.text_input("Email Address")
            new_password = st.text_input("Password", type='password')
            new_password_confirm = st.text_input("Confirm Password", type='password')

            if st.button("Register"):
                if not is_valid_username(new_username):
                    st.error("Invalid username.")
                elif not is_valid_email(new_email):
                    st.error("Invalid email.")
                elif not new_password == new_password_confirm:
                    st.error("Passwords do not match.")
                elif not is_secure_password(new_password):
                    st.error("Password must be at least 8 characters long and include an uppercase, a lowercase, a digit and a special character (!@#$%^&*()).")
                else:
                    hashed_password = generate_password_hash(new_password, method='sha256')
                    registration_success = db_manager.register_user(new_username, new_email, hashed_password)
                   
                    
                if registration_success is True:
                     print(registration_success) 
                     st.success(f"User {new_username} has been registered successfully!")
                else:
                    st.error("Please check later for more Zops Storage accounts availability.")
                
        else:
            st.subheader("Login Form")

            username = st.text_input("Username")
            password = st.text_input("Password", type='password')

            if st.button("Login"):
                user_data = db_manager.get_user(username)    
                if user_data and check_password_hash(user_data[1], password):
                    st.session_state.logged_in = True
                    st.session_state.current_user = username
                else:
                    st.warning("Incorrect Username/Password.")
    
    # User Portal and initilizinag the app and required connections 
    else:
     initialize_app()
     if st.session_state.get("current_user"):  # Check if a user is logged in
        azure_uid = db_manager.get_azure_uid(st.session_state.current_user)
        connection_string = get_connection_string_from_key_vault(azure_uid)
        
        if connection_string:
        
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            
        else:
            st.error("Unable to connect to storage account.")

        st.title(f"Welcome {st.session_state.current_user}! 👋")
        menu = ["Upload Data📂", "View Files📁"]
        choice = st.sidebar.selectbox("Menu", menu)

        # Always show the logout checkbox irrespective of menu choice
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.current_user = None
            st.info("Logged out successfully.")


        #user ability to upload files and create azure storage accounts
        elif choice == "Upload Data📂":
            containers = list_containers(blob_service_client)
             # Initialize selected_container to None
            selected_container = None
            
            
            selected_container = st.selectbox("Available Data Storages in ZopsDataCenter:", containers)
            uploaded_file = st.file_uploader(f"Upload files to {selected_container}: 📂", accept_multiple_files=True)
            create_storage(blob_service_client)
            if uploaded_file: # Check if any file has been uploaded
                  for file in uploaded_file: # Loop through the list of uploaded files
                      try:
                          upload_blob(blob_service_client, selected_container, file) 
                          st.success(f"File {file.name} uploaded to {selected_container} successfully!")
                          
                          
                      except ValueError as e:
                          
                          if "Please specify a container name and blob name" in str(e):
                              st.warning("Please create a container before attempting to upload a file.")
                          else:
                              st.error(f"An unexpected error occurred: {e}")
                              st.warning("Please create a Storage Unit before attempting to upload files.")
                              
            if st.button(f"Delete {selected_container}"):
                try:
                    blob_service_client.delete_container(selected_container)
                    st.success(f"Data Storage '{selected_container}' deleted successfully.")
                except Exception as e:
                    st.error(f"An error occurred: {e}")
            
            
                
        #user ability to view files 
        elif choice == "View Files📁":
    
            containers = list_containers(blob_service_client)
            if containers:
               container_choice = st.selectbox("Choose a Data Storage", containers)
               blobs = list_blobs(blob_service_client, container_choice)
               
               if blobs:
                    blob_choice = st.selectbox("Choose a file", blobs)
                    
                    if st.button("Preview"):
                        preview_blob(blob_service_client, container_choice, blob_choice)
                        
                    if container_choice and blob_choice and st.button("Delete File"):
                       try:
                          blob_service_client.get_blob_client(container_choice, blob_choice).delete_blob()
                          st.success(f"File {blob_choice} deleted successfully!")
                  
                       except ValueError as e:
                           st.error(f"An error occurred: {e}")
                           st.warning("No files available to delete in the selected storage unit.")
                           
            else:
                      st.warning("⚠️ You must create a Storage Unit and Upload Files before you can view a file.")

    
     else:  # No user is logged in
            st.title("Please log in.")
  
        

if __name__ == '__main__':
    # Database Initialization
    #for subscription base business
    #add_auth(required=True)
    db_manager = DatabaseManager(conn_string)
    main()
