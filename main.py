import streamlit as st
import os
import shutil
import datetime
from database import init_database, set_app_meta, get_app_meta
from encryption import derive_key_from_password, secure_store, retrieve_secure
from credential_manager import render_credential_manager
from gdrive_handler import authenticate, upload_file, SCOPES
from google_auth_oauthlib.flow import InstalledAppFlow

# --- Page and App Initialization ---

st.set_page_config(
    page_title="Secure Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def init_app():
    """Initialize the database if it doesn't exist."""
    init_database()

# --- Login / Authentication Flow ---

def render_login_form():
    """Renders the master password form and handles authentication."""
    st.header("🛡️ Master Password Required")

    _, col, _ = st.columns([1, 1.5, 1])
    with col:
        salt = get_app_meta('master_salt')
        if not salt:
            st.info("Welcome! Please create a master password to secure your vault.")
            with st.form("create_master_password"):
                password = st.text_input("Create Master Password", type="password")
                confirm_password = st.text_input("Confirm Master Password", type="password")
                if st.form_submit_button("Create Vault", use_container_width=True):
                    if not password or password != confirm_password:
                        st.error("Passwords do not match or are empty.")
                    else:
                        new_salt = os.urandom(16)
                        set_app_meta('master_salt', new_salt)
                        key = derive_key_from_password(password, new_salt)
                        check_phrase = "password_check_ok"
                        encrypted_check = secure_store(check_phrase, key)
                        set_app_meta('check_hash', encrypted_check.encode('utf-8'))
                        st.session_state.encryption_key = key
                        st.rerun()
        else:
            with st.form("login"):
                password = st.text_input("Enter Master Password", type="password")
                if st.form_submit_button("Unlock Vault", use_container_width=True):
                    key = derive_key_from_password(password, salt)
                    stored_check_hash_bytes = get_app_meta('check_hash')
                    if not stored_check_hash_bytes:
                        st.error("Vault is not properly configured. Cannot verify password.")
                        return
                    decrypted_check = retrieve_secure(stored_check_hash_bytes.decode('utf-8'), key)
                    if decrypted_check == "password_check_ok":
                        st.session_state.encryption_key = key
                        st.rerun()
                    else:
                        st.error("Incorrect master password.")

# --- Backup Logic ---
def run_backup_flow():
    """Handles the entire backup process."""
    with st.spinner("Starting backup process..."):
        # 1. Create a local backup file with a timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_filename = f"credentials_backup_{timestamp}.db"
        if not os.path.exists("backups"):
            os.makedirs("backups")
        backup_filepath = os.path.join("backups", backup_filename)
        shutil.copyfile("credentials.db", backup_filepath)
        
        # 2. Authenticate with Google Drive
        st.info("Authenticating with Google Drive...")
        service = authenticate()
        
        # 3. If authentication is complete, upload the file
        if service:
            st.info(f"Uploading backup file '{backup_filename}'...")
            upload_file(service, backup_filepath, backup_filename)
            # Clean up session state
            if 'auth_url' in st.session_state:
                del st.session_state.auth_url


# --- Sidebar and Main App Logic ---

def render_sidebar():
    """Render the sidebar navigation."""
    st.sidebar.title("🛡️ Secure Manager")
    st.sidebar.markdown("All data is encrypted using your master password.")
    
    if st.sidebar.button("Lock Vault", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.subheader("Backup")
    if st.sidebar.button("Backup to Google Drive", use_container_width=True):
        st.session_state.run_backup = True
        
    st.sidebar.markdown("---")
    st.sidebar.subheader("About")
    st.sidebar.markdown(
        """
        Developed by **Mohammadreza Mohammadi**.
        
        [GitHub Profile](https://github.com/mohammadreza-mohammadi94)
        """
    )

def main():
    """Main application function."""
    init_app()
    
    if 'encryption_key' not in st.session_state:
        render_login_form()
    else:
        render_sidebar()
        
        if st.session_state.get('run_backup', False):
            run_backup_flow()
            st.session_state.run_backup = False

        if st.session_state.get('auth_url'):
            st.info("Please log in to Google to authorize this application.")
            st.markdown(f"Visit this URL: [Google Auth Link]({st.session_state.auth_url})", unsafe_allow_html=True)
            auth_code = st.text_input("Enter the authorization code you received from Google here:")
            if auth_code:
                try:
                    # --- FIX: Added the explicit redirect_uri to match gdrive_handler.py ---
                    flow = InstalledAppFlow.from_client_secrets_file(
                        "client_secrets.json",
                        SCOPES,
                        redirect_uri='urn:ietf:wg:oauth:2.0:oob'
                    )
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    with open("token.json", "w") as token:
                        token.write(creds.to_json())
                    
                    del st.session_state.auth_url
                    st.session_state.run_backup = True
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to fetch token: {e}")
        else:
            render_credential_manager()


if __name__ == "__main__":
    main()