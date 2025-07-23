import os.path
import streamlit as st
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

# This scope will grant read/write access to files created by this app.
# It will not have access to other files in the user's Drive.
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def authenticate():
    """Handles the OAuth 2.0 flow for Google Drive API."""
    creds = None
    # The file token.json stores the user's access and refresh tokens.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "client_secrets.json",
                SCOPES,
                redirect_uri='urn:ietf:wg:oauth:2.0:oob'
            )
            
            auth_url, _ = flow.authorization_url(prompt='consent')
            
            # Display the auth URL and ask for the code in the Streamlit app
            st.session_state.auth_url = auth_url
            return None
        
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        service = build("drive", "v3", credentials=creds)
        return service
    except HttpError as error:
        st.error(f"An error occurred building the Drive service: {error}")
        return None

def upload_file(service, file_path, file_name):
    """Uploads a file to Google Drive."""
    try:
        # Check if a folder named "CredentialManagerBackups" exists, create if not
        folder_id = None
        folders = service.files().list(q="mimeType='application/vnd.google-apps.folder' and name='CredentialManagerBackups'",
                                     spaces='drive', fields='files(id, name)').execute()
        if not folders.get('files'):
            folder_metadata = {
                'name': 'CredentialManagerBackups',
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = service.files().create(body=folder_metadata, fields='id').execute()
            folder_id = folder.get('id')
        else:
            folder_id = folders.get('files')[0].get('id')

        # File metadata
        file_metadata = {'name': file_name, 'parents': [folder_id]}
        media = MediaFileUpload(file_path, mimetype='application/octet-stream')
        
        # Upload the file
        uploaded_file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
        st.success(f"Backup successful! File '{file_name}' uploaded to 'CredentialManagerBackups' folder in your Google Drive.")
        return uploaded_file.get("id")
    except HttpError as error:
        st.error(f"An error occurred during file upload: {error}")
        return None