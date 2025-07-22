# credential_manager.py

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
    
    if st.button("Generate Secure Password", key="generate_pass"):
        st.session_state.generated_password = generate_password()
    
    with st.form(key=f"credential_form_{credential['id'] if is_edit else 'add'}"):
        credential_types = ["Email", "API", "Service Password"]
        
        if is_edit:
            default_type = credential.get('credential_type', 'Email')
            default_index = credential_types.index(default_type) if default_type in credential_types else 0
        else:
            default_index = 0
        
        st.selectbox(
            "Credential Type",
            options=credential_types,
            index=default_index,
            key="credential_type"
        )
        
        st.text_input("Account Name", value=credential['account_name'] if is_edit else "", key="account_name", placeholder="e.g., Personal Gmail")
        st.text_input("Service Name", value=credential['service_name'] if is_edit else "", key="service_name", placeholder="e.g., Google")
        st.text_input("Email Address", value=credential['email'] if is_edit else "", key="email")
        
        st.text_input(
            "Password Field",
            type="password",
            value=st.session_state.get("generated_password", ""),
            key="password_field"
        )
        
        st.text_area("API Key (Optional)", value=retrieve_secure(credential.get('api_key', ''), st.session_state.encryption_key) if is_edit else "", key="api_key")
        st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes", placeholder="e.g., Recovery codes")

        if st.form_submit_button("Save Credential", use_container_width=True):
            form_data = st.session_state
            
            if "generated_password" in st.session_state:
                del st.session_state.generated_password

            if not all([form_data.account_name, form_data.service_name, form_data.email]):
                st.error("Account Name, Service Name, and Email are required.")
                return

            if not is_edit and not form_data.password_field:
                st.error("Password is required for new credentials.")
                return
            
            key = st.session_state.encryption_key
            enc_pass = secure_store(form_data.password_field, key) if form_data.password_field else (credential['password'] if is_edit else "")
            enc_api = secure_store(form_data.api_key, key)

            if is_edit:
                update_credential(credential['id'], form_data.account_name, form_data.email, form_data.service_name, form_data.credential_type, enc_pass, enc_api, form_data.notes)
                st.success("Credential updated!")
            else:
                insert_credential(form_data.account_name, form_data.email, form_data.service_name, form_data.credential_type, enc_pass, enc_api, form_data.notes)
                st.success("Credential added!")
            
            st.rerun()

# --- Main Application UI ---
def render_credential_manager():
    """Render the main credential management interface."""

    # --- UI CHANGE: Inject CSS to create a compact, Excel-like table ---
    st.markdown("""
        <style>
            /* Reduce vertical space between rows by targeting the container of each row */
            .st-emotion-cache-16txtl3 {
                padding-top: 0.2rem !important;
                padding-bottom: 0.2rem !important;
            }
            /* Ensure columns are vertically centered */
            [data-testid="column"] {
                display: flex;
                align-items: center;
            }
        </style>
        """, unsafe_allow_html=True)

    st.header("🔐 Credential Manager")

    @st.dialog("Add New Credential")
    def add_dialog():
        credential_form()

    @st.dialog("View Details")
    def view_dialog(credential):
        key = st.session_state.encryption_key
        password = retrieve_secure(credential['password'], key)
        api_key = retrieve_secure(credential.get('api_key', ''), key)
        
        st.text_input("Password", password, type="password", disabled=True)
        if api_key:
            st.text_area("API Key", api_key, disabled=True)
        if credential.get('notes'):
            st.info(f"**Notes:** {credential['notes']}")
        if st.button("Close"):
            st.rerun()

    @st.dialog("Edit Credential")
    def edit_dialog(credential_to_edit):
        credential_form(credential=credential_to_edit)

    @st.dialog("Confirm Deletion")
    def delete_dialog(credential_id):
        st.error("Are you sure you want to permanently delete this credential?")
        if st.button("Yes, Delete", type="primary"):
            delete_credential(credential_id)
            st.rerun()

    if st.button("✚ Add New Credential", type="primary"):
        add_dialog()

    st.markdown("---")

    credentials = get_all_credentials()
    
    col1, col2 = st.columns([1, 2])
    with col1:
        unique_types = sorted(list(set(c.get('credential_type') for c in credentials if c.get('credential_type'))))
        types_to_display = st.multiselect(
            "Filter by Type",
            options=unique_types,
            default=unique_types
        )
    with col2:
        search_query = st.text_input("Search Credentials", placeholder="Search by Account, Service, or Email...")

    filtered_creds = [
        cred for cred in credentials if
        (not types_to_display or cred.get('credential_type') in types_to_display) and
        (not search_query or
         search_query.lower() in cred.get('account_name', '').lower() or
         search_query.lower() in cred.get('service_name', '').lower() or
         search_query.lower() in cred.get('email', '').lower())
    ]

    if not filtered_creds:
        st.info("No credentials found or match your filters. Click the button above to add one.")
        return
        
    # --- UI CHANGE: Compact row-based layout ---
    header_cols = st.columns([1, 3, 3, 2])
    header_cols[0].markdown("**Type**")
    header_cols[1].markdown("**Account**")
    header_cols[2].markdown("**Email / User ID**")
    header_cols[3].markdown("**Actions**")
    st.divider() # Use st.divider for a thinner line
    
    for i, cred in enumerate(filtered_creds):
        # Alternate background color for rows
        container = st.container()
        if i % 2 == 0:
            container.markdown("<div style='background-color: #262730; padding: 10px; border-radius: 5px;'>", unsafe_allow_html=True)

        cols = container.columns([1, 3, 3, 2])
        cols[0].text(cred.get('credential_type', 'N/A'))
        cols[1].markdown(f"**{cred['account_name']}**<br><small>Service: {cred['service_name']}</small>", unsafe_allow_html=True)
        cols[2].text(cred['email'])
        
        action_cols = cols[3].columns(3)
        if action_cols[0].button("👁️", key=f"view_{cred['id']}", help="View Details", use_container_width=True):
            view_dialog(cred)
        if action_cols[1].button("✏️", key=f"edit_{cred['id']}", help="Edit", use_container_width=True):
            edit_dialog(cred)
        if action_cols[2].button("🗑️", key=f"delete_{cred['id']}", help="Delete", use_container_width=True):
            delete_dialog(cred['id'])
        
        if i % 2 == 0:
            container.markdown("</div>", unsafe_allow_html=True)