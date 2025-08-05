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
def email_form(credential=None):
    """Renders the form for adding or editing an email credential."""
    is_edit = credential is not None
    key = st.session_state.encryption_key

    if st.button("Generate Secure Password", key="generate_pass_dialog"):
        st.session_state.generated_password = generate_password()
    
    with st.form(key=f"email_form_{credential['id'] if is_edit else 'add'}"):
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_email")
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_email")
        email_address = st.text_input("Email Address", value=credential.get('email', '') if is_edit else "", key="email_address_email_type")
        password_field = st.text_input(
            "Password", type="password",
            value=st.session_state.get("generated_password", retrieve_secure(credential['password'], key) if is_edit and credential.get('password') else ""),
            key="password_field_email_type"
        )
        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes")

        if st.form_submit_button("Save Email"):
            if "generated_password" in st.session_state:
                del st.session_state.generated_password
            if not all([account_name, service_name, email_address, password_field]):
                st.error("All fields are required for Email.")
                return
            enc_pass = secure_store(password_field, key)
            final_email = email_address
            if is_edit:
                update_credential(credential['id'], account_name, final_email, service_name, "Email", enc_pass, "", notes)
                st.success("Email updated!")
            else:
                insert_credential(account_name, final_email, service_name, "Email", enc_pass, "", notes)
                st.success("Email added!")
            st.rerun()

def api_form(credential=None):
    """Renders the form for adding or editing an API credential."""
    is_edit = credential is not None
    key = st.session_state.encryption_key

    with st.form(key=f"api_form_{credential['id'] if is_edit else 'add'}"):
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_api")
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_api")
        api_key_field = st.text_input("API Key", type="password", value=retrieve_secure(credential['api_key'], key) if is_edit and credential.get('api_key') else "", key="api_key_field")
        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes_api")

        if st.form_submit_button("Save API Key"):
            if not all([account_name, service_name, api_key_field]):
                st.error("Service Name, Account Name and API Key are required.")
                return

            enc_api_key = secure_store(api_key_field, key)

            if is_edit:
                update_credential(credential['id'], account_name, "", service_name, "API", "", enc_api_key, notes)
                st.success("API Key updated!")
            else:
                insert_credential(account_name, "", service_name, "API", "", enc_api_key, notes)
                st.success("API Key added!")
            st.rerun()

def service_form(email_id, credential=None):
    """Renders the form for adding or editing a service credential in a dialog."""
    is_edit = credential is not None
    key = st.session_state.encryption_key

    if st.button("Generate Secure Password", key=f"generate_pass_service_{email_id}"):
        st.session_state[f"generated_password_{email_id}"] = generate_password()
    
    with st.form(key=f"service_form_{email_id}_{credential['id'] if is_edit else 'add'}"):
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key=f"service_name_service_{email_id}", placeholder="e.g., Netflix")
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key=f"account_name_service_{email_id}", placeholder="e.g., Main Acc")
        email_address = st.text_input("Email Address", value=next((c['email'] for c in get_all_credentials() if c['id'] == email_id), ""), disabled=True, key=f"email_address_service_{email_id}")
        password_field = st.text_input(
            "Password", type="password",
            value=st.session_state.get(f"generated_password_{email_id}", retrieve_secure(credential['password'], key) if is_edit and credential.get('password') else ""),
            key=f"password_field_service_{email_id}"
        )
        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key=f"notes_service_{email_id}")

        if st.form_submit_button("Save Service"):
            if f"generated_password_{email_id}" in st.session_state:
                del st.session_state[f"generated_password_{email_id}"]
            if not all([service_name, account_name, password_field]):
                st.error("Service Name, Account Name, and Password are required.")
                return
            enc_pass = secure_store(password_field, key)
            print(f"Debug: Attempting to insert service - email: {email_address}, service_name: {service_name}, account_name: {account_name}, password: {enc_pass[:10]}...")
            if is_edit:
                success = update_credential(credential['id'], account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
                if success:
                    st.success("Service updated!")
                else:
                    st.error("Failed to update service. Check logs.")
            else:
                success = insert_credential(account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
                if success:
                    st.success("Service added!")
                else:
                    st.error("Failed to add service. Check logs.")
            # Clear the dialog state and rerun
            st.session_state.dialog_type = "view_email" # Go back to the email view
            st.session_state.show_service_dialog = False
            st.session_state.editing_service_credential = None
            st.rerun()

# --- Main Application UI ---
def render_credential_manager():
    """Render the main credential management interface."""
    st.title("🔐 Credential Manager")
    if "dialog_type" not in st.session_state:
        st.session_state.dialog_type = None
    if "current_email_id" not in st.session_state:
        st.session_state.current_email_id = None
    if "current_credential" not in st.session_state:
        st.session_state.current_credential = None
    if 'show_service_dialog' not in st.session_state:
        st.session_state.show_service_dialog = False
    if 'editing_service_credential' not in st.session_state:
        st.session_state.editing_service_credential = None

    key = st.session_state.encryption_key

    @st.dialog("Manage Service")
    def service_dialog():
        """Dialog for adding or editing a service."""
        email_id = st.session_state.current_email_id
        credential = st.session_state.editing_service_credential
        title = "Edit Service" if credential else "Add New Service"
        st.subheader(title)
        service_form(email_id, credential)
        if st.button("Cancel"):
            st.session_state.show_service_dialog = False
            st.session_state.editing_service_credential = None
            st.rerun()

    # --- Dialogs ---
    @st.dialog("Credential Management")
    def credential_dialog():
        st.write(f"Debug: Dialog type is {st.session_state.dialog_type}")
        if st.session_state.dialog_type == "view_email" and st.session_state.current_credential:
            st.write(f"Debug: Viewing email {st.session_state.current_credential['id']}")
            st.write(f"**Credential Type:** {st.session_state.current_credential.get('credential_type', 'N/A')}")
            st.write(f"**Account Name:** {st.session_state.current_credential['account_name']}")
            st.write(f"**Service Name:** {st.session_state.current_credential['service_name']}")
            st.write(f"**Email Address:** {st.session_state.current_credential['email']}")
            if st.session_state.current_credential.get('password'):
                st.text_input("Password", retrieve_secure(st.session_state.current_credential['password'], key), type="password", disabled=True)
            if st.session_state.current_credential.get('notes'):
                st.write(f"**Notes:** {st.session_state.current_credential['notes']}")
            # نمایش و مدیریت سرویس‌ها مستقیماً در همین دیالوگ
            email_address = st.session_state.current_credential['email']
            services = [c for c in get_all_credentials() if c.get('credential_type') == 'Service Password' and c.get('email') == email_address]
            st.write(f"**Associated Services:**")
            st.write(f"Debug: Found {len(services)} services")
            if not services:
                st.write("No services associated with this email. Add one below.")
            if st.button("Add New Service"):
                st.session_state.show_service_dialog = True
                st.session_state.editing_service_credential = None # Ensure it's a new service
                st.rerun() # Rerun to open the new dialog
            for service in services:
                col1, col2, col3, col4 = st.columns([1, 1, 0.5, 0.5])
                col1.write(service.get('service_name', ''))
                col2.write(service.get('account_name', ''))
                if col3.button("✏️", key=f"edit_service_{service['id']}"):
                    st.session_state.show_service_dialog = True
                    st.session_state.editing_service_credential = service # Pass service to edit
                    st.rerun()
                if col4.button("🗑️", key=f"delete_service_{service['id']}"):
                    delete_credential(service['id'])
                    st.rerun()

            if st.button("Close"):
                st.session_state.dialog_type = None
                st.session_state.current_credential = None
                st.rerun()
        elif st.session_state.dialog_type == "add_email":
            st.write("Debug: Adding new email")
            email_form()
        elif st.session_state.dialog_type == "edit_email" and st.session_state.current_credential:
            st.write("Debug: Editing email")
            email_form(st.session_state.current_credential)
        elif st.session_state.dialog_type == "add_api":
            st.write("Debug: Adding new API")
            api_form()
        elif st.session_state.dialog_type == "edit_api" and st.session_state.current_credential:
            st.write("Debug: Editing API")
            api_form(st.session_state.current_credential)

    if st.session_state.show_service_dialog:
        service_dialog()

    @st.dialog("Confirm Deletion")
    def delete_dialog(credential_id):
        st.error("Are you sure you want to permanently delete this credential?")
        if st.button("Yes, Delete"):
            delete_credential(credential_id)
            st.session_state.dialog_type = None
            st.session_state.current_credential = None
            st.rerun()

    @st.dialog("View Secret")
    def show_secret_dialog(name, value):
        st.write(f"**{name}**")
        st.text_input("Value", value=value, type="password", disabled=True)
        if st.button("Close", key=f"close_secret_{name}"):
            st.rerun()

    c1, c2 = st.columns(2)
    if c1.button("✚ Add New Email", use_container_width=True):
        st.session_state.dialog_type = "add_email"
        credential_dialog()
    if c2.button("✚ Add New API Key", use_container_width=True):
        st.session_state.dialog_type = "add_api"
        credential_dialog()

    # --- Filtering and Sorting ---
    all_credentials = get_all_credentials()
    print(f"Debug: All credentials: {all_credentials}")  # Check database output
    col1, col2 = st.columns([1, 2])
    with col1:
        unique_types = ["Email", "API"]  # Only Email and API types now
        types_to_display = st.multiselect("Filter by Type", options=unique_types, default=[])
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
        # View button is specific to emails for now
        if credential.get('credential_type') == 'Email':
            if col1.button("👁️", key=f"view_{credential['id']}", help="View Details & Services"):
                st.session_state.dialog_type = "view_email"
                st.session_state.current_credential = credential
                st.session_state.current_email_id = credential['id']
                credential_dialog()
        else:
            col1.write("") # Placeholder to keep alignment

        if col2.button("✏️", key=f"edit_{credential['id']}", help="Edit"):
            # Set dialog type based on credential type
            if credential.get('credential_type') == 'API':
                st.session_state.dialog_type = "edit_api"
            else: # Default to email
                st.session_state.dialog_type = "edit_email"
            st.session_state.current_credential = credential
            credential_dialog()

        if col3.button("🗑️", key=f"delete_{credential['id']}", help="Delete"):
            delete_dialog(credential['id'])

    tab_email, tab_api = st.tabs(["📧 Email", "🔑 API"])

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
            # Actions column is wider to accommodate buttons
            col1, col2, col3, col4 = st.columns([2.5, 2.5, 1.5, 2])
            col1.write("**Service Name**")
            col2.write("**Account Name**")
            col3.write("**API Key**")
            col4.write("**Actions**")
            st.divider()
            for cred in api_creds:
                col1, col2, col3, col4 = st.columns([2.5, 2.5, 1.5, 2])
                col1.write(cred.get('service_name', ''))
                col2.write(cred.get('account_name', ''))
                if col3.button("View", key=f"key_api_{cred['id']}"):
                    show_secret_dialog("API Key", retrieve_secure(cred['api_key'], key))
                with col4:
                    render_actions(cred)