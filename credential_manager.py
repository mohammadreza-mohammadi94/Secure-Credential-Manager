import streamlit as st
import pandas as pd
import secrets
import string
from database import (
    get_all_credentials, insert_credential, update_credential, delete_credential
)
from encryption import retrieve_secure, secure_store

# --- Password Generation ---
def generate_password(length: int = 16, include_symbols: bool = True):
    """Generate a cryptographically secure password."""
    chars = string.ascii_letters + string.digits
    if include_symbols:
        chars += string.punctuation
    password = ''.join(secrets.choice(chars) for i in range(length))
    return password

# --- UI for Forms (used in dialogs) ---
def credential_form(credential=None):
    """Renders the form for adding or editing a credential. Can be pre-filled."""
    is_edit = credential is not None
    key = st.session_state.encryption_key

    if st.button("Generate Secure Password", key="generate_pass_dialog"):
        st.session_state.generated_password = generate_password()
    
    with st.form(key=f"credential_form_{credential['id'] if is_edit else 'add'}"):
        credential_types = ["Email", "API", "Service Password"]
        
        default_index = 0
        if is_edit:
            default_type = credential.get('credential_type', 'Email')
            if default_type in credential_types:
                default_index = credential_types.index(default_type)
        
        selected_type = st.selectbox("Credential Type", options=credential_types, index=default_index, key="credential_type")
        
        account_name, service_name, email_address, password_field, api_key_field = "", "", "", "", ""

        if selected_type == "Email":
            account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_email")
            service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_email")
            email_address = st.text_input("Email Address", value=credential.get('email', '') if is_edit else "", key="email_address_email_type")
            password_field = st.text_input(
                "Password", type="password",
                value=st.session_state.get("generated_password", retrieve_secure(credential['password'], key) if is_edit and credential.get('password') else ""),
                key="password_field_email_type"
            )
        elif selected_type == "API":
            service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_api", placeholder="e.g., OpenAI")
            account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_api", placeholder="e.g., Main Account")
            api_key_field = st.text_area("API Key", value=retrieve_secure(credential.get('api_key', ''), key) if is_edit and credential.get('api_key') else "", key="api_key_field_api_type")
            email_address = ""
            password_field = ""
        elif selected_type == "Service Password":
            service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_service", placeholder="e.g., Netflix")
            account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_service", placeholder="e.g., Main Acc")
            email_address = st.text_input("Registered Email", value=credential.get('email', '') if is_edit else "", key="email_address_service_type")
            password_field = st.text_input(
                "Password", type="password",
                value=st.session_state.get("generated_password", retrieve_secure(credential['password'], key) if is_edit and credential.get('password') else ""),
                key="password_field_service_type"
            )
            api_key_field = ""

        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes")

        if st.form_submit_button("Save Credential"):
            if "generated_password" in st.session_state:
                del st.session_state.generated_password

            if selected_type == "Email":
                if not all([account_name, service_name, email_address, password_field]):
                    st.error("All fields are required for Email.")
                    return
            elif selected_type == "API":
                if not all([service_name, account_name, api_key_field]):
                    st.error("Service Name, Account Name, and API Key are required for API.")
                    return
            elif selected_type == "Service Password":
                if not all([account_name, service_name, email_address, password_field]):
                    st.error("All fields are required for Service Password.")
                    return

            enc_pass = secure_store(password_field, key) if password_field else (credential.get('password', '') if is_edit else "")
            enc_api = secure_store(api_key_field, key) if api_key_field else (credential.get('api_key', '') if is_edit else "")
            final_email = email_address if email_address else (credential.get('email', '') if is_edit else "")

            if is_edit:
                update_credential(credential['id'], account_name, final_email, service_name, selected_type, enc_pass, enc_api, notes)
                st.success("Credential updated!")
            else:
                insert_credential(account_name, final_email, service_name, selected_type, enc_pass, enc_api, notes)
                st.success("Credential added!")
            st.rerun()

# --- Main Application UI ---
def render_credential_manager():
    """Render the main credential management interface."""
    st.title("🔐 Credential Manager")
    key = st.session_state.encryption_key

    # --- Dialogs ---
    @st.dialog("Add New Credential")
    def add_dialog():
        credential_form()

    @st.dialog("View Full Details")
    def view_dialog(credential):
        st.write(f"**Credential Type:** {credential.get('credential_type', 'N/A')}")
        st.write(f"**Account Name:** {credential['account_name']}")
        st.write(f"**Service Name:** {credential['service_name']}")
        if credential.get('credential_type') == 'Email':
            st.write(f"**Email Address:** {credential['email']}")
            if credential.get('password'):
                st.text_input("Password", retrieve_secure(credential['password'], key), type="password", disabled=True)
        elif credential.get('credential_type') == 'API':
            if credential.get('api_key'):
                st.text_area("API Key", retrieve_secure(credential['api_key'], key), disabled=True)
        elif credential.get('credential_type') == 'Service Password':
            st.write(f"**Registered Email:** {credential['email']}")
            if credential.get('password'):
                st.text_input("Password", retrieve_secure(credential['password'], key), type="password", disabled=True)
        if credential.get('notes'):
            st.write(f"**Notes:** {credential['notes']}")
        if st.button("Close"):
            st.rerun()

    @st.dialog("Edit Credential")
    def edit_dialog(credential_to_edit):
        credential_form(credential=credential_to_edit)

    @st.dialog("Confirm Deletion")
    def delete_dialog(credential_id):
        st.error("Are you sure you want to permanently delete this credential?")
        if st.button("Yes, Delete"):
            delete_credential(credential_id)
            st.rerun()

    @st.dialog("View Secret")
    def show_secret_dialog(name, value):
        st.write(f"**{name}**")
        st.text_input("Value", value=value, type="password", disabled=True)
        if st.button("Close", key=f"close_secret_{name}"):
            st.rerun()

    if st.button("✚ Add New Credential"):
        add_dialog()

    # --- Filtering and Sorting ---
    all_credentials = get_all_credentials()
    col1, col2 = st.columns([1, 2])
    with col1:
        unique_types = sorted(list(set(c.get('credential_type') for c in all_credentials if c.get('credential_type'))))
        types_to_display = st.multiselect("Filter by Type", options=unique_types, default=[])  # No default filter
    with col2:
        search_query = st.text_input("Search Credentials", placeholder="Search by Account, Service, or Email...")

    col3, col4 = st.columns(2)
    with col3:
        sort_by = st.selectbox("Sort by", options=["Type", "Account", "Service"], index=1)
    with col4:
        sort_order = st.radio("Order", options=["Ascending", "Descending"], horizontal=True)

    filtered_creds = [
        cred for cred in all_credentials if
        (not types_to_display or cred.get('credential_type') in types_to_display) and
        (not search_query or
         search_query.lower() in cred.get('account_name', '').lower() or
         search_query.lower() in cred.get('service_name', '').lower() or
         search_query.lower() in cred.get('email', '').lower())
    ]
    
    reverse_order = (sort_order == "Descending")
    sort_key_map = {"Type": "credential_type", "Account": "account_name", "Service": "service_name"}
    sort_key = sort_key_map[sort_by]
    filtered_creds.sort(key=lambda x: str(x.get(sort_key, "")).lower(), reverse=reverse_order)

    if not all_credentials:
        st.info("No credentials found. Click the button above to add one.")
        return

    def render_actions(credential):
        col1, col2, col3 = st.columns([1, 1, 1])
        if col1.button("👁️", key=f"view_{credential['id']}", help="View"):
            view_dialog(credential)
        if col2.button("✏️", key=f"edit_{credential['id']}", help="Edit"):
            edit_dialog(credential)
        if col3.button("🗑️", key=f"delete_{credential['id']}", help="Delete"):
            delete_dialog(credential['id'])

    tab_email, tab_api, tab_services = st.tabs(["📧 Email", "🔑 API", "⚙️ Services"])

    with tab_email:
        email_creds = [c for c in filtered_creds if c.get('credential_type') == 'Email']
        if not email_creds:
            st.info("No Email credentials match your filters.")
        else:
            col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
            col1.write("**Account Name**")
            col2.write("**Service Name**")
            col3.write("**Email Address**")
            col4.write("**Password**")
            col5.write("**Actions**")
            for cred in email_creds:
                col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
                col1.write(cred.get('account_name', ''))
                col2.write(cred.get('service_name', ''))
                col3.write(cred.get('email', ''))
                if col4.button("View", key=f"pwd_email_{cred['id']}"):
                    show_secret_dialog("Password", retrieve_secure(cred['password'], key))
                with col5:
                    render_actions(cred)

    with tab_api:
        api_creds = [c for c in filtered_creds if c.get('credential_type') == 'API']
        if not api_creds:
            st.info("No API credentials match your filters.")
        else:
            col1, col2, col3, col4 = st.columns([2.5, 2.5, 2, 1.5])
            col1.write("**Service Name**")
            col2.write("**Account Name**")
            col3.write("**API Key**")
            col4.write("**Actions**")
            for cred in api_creds:
                col1, col2, col3, col4 = st.columns([2.5, 2.5, 2, 1.5])
                col1.write(cred.get('service_name', ''))
                col2.write(cred.get('account_name', ''))
                if col3.button("View", key=f"key_api_{cred['id']}"):
                    show_secret_dialog("API Key", retrieve_secure(cred['api_key'], key))
                with col4:
                    render_actions(cred)

    with tab_services:
        service_creds = [c for c in filtered_creds if c.get('credential_type') == 'Service Password']
        if not service_creds:
            st.info("No Service credentials match your filters.")
        else:
            col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
            col1.write("**Service Name**")
            col2.write("**Account Name**")
            col3.write("**Registered Email**")
            col4.write("**Password**")
            col5.write("**Actions**")
            for cred in service_creds:
                col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
                col1.write(cred.get('service_name', ''))
                col2.write(cred.get('account_name', ''))
                col3.write(cred.get('email', ''))
                if col4.button("View", key=f"pwd_service_{cred['id']}"):
                    show_secret_dialog("Password", retrieve_secure(cred['password'], key))
                with col5:
                    render_actions(cred)