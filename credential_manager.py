# import streamlit as st
# import pandas as pd
# import secrets
# import string
# from database import (
#     get_all_credentials, insert_credential, update_credential, delete_credential
# )
# from encryption import retrieve_secure, secure_store
# from st_copy import st_copy
# from zxcvbn import zxcvbn

# # --- Password Generation and Strength ---
# def get_password_strength(password):
#     """Return a color and text description of the password strength."""
#     if not password:
#         return "black", "Enter a password"
#     strength = zxcvbn(password)
#     score = strength['score']
#     if score < 2:
#         return "red", "Weak"
#     elif score < 3:
#         return "orange", "Okay"
#     elif score < 4:
#         return "lightgreen", "Good"
#     else:
#         return "darkgreen", "Strong"

# def generate_password(length: int = 16, include_symbols: bool = True):
#     """Generate a cryptographically secure password."""
#     chars = string.ascii_letters + string.digits
#     if include_symbols:
#         chars += string.punctuation
#     password = ''.join(secrets.choice(chars) for i in range(length))
#     return password

# # --- UI for Forms (used in dialogs) ---
# def email_form(credential=None):
#     """Renders the form for adding or editing an email credential."""
#     is_edit = credential is not None
#     form_id = f"email_form_{credential['id'] if is_edit else 'add'}"

#     # Initialize session state for the password field
#     if f"password_{form_id}" not in st.session_state:
#         st.session_state[f"password_{form_id}"] = retrieve_secure(credential['password'], st.session_state.encryption_key) if is_edit and credential.get('password') else ""

#     def update_password():
#         st.session_state[f"password_{form_id}"] = st.session_state[f"password_input_{form_id}"]

#     if st.button("Generate Secure Password", key=f"generate_pass_{form_id}"):
#         st.session_state[f"password_{form_id}"] = generate_password()

#     with st.form(key=form_id):
#         account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "")
#         service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "")
#         email_address = st.text_input("Email Address", value=credential.get('email', '') if is_edit else "")

#         password_field = st.text_input(
#             "Password", type="password",
#             value=st.session_state[f"password_{form_id}"],
#             on_change=update_password,
#             key=f"password_input_{form_id}"
#         )

#         # Password strength meter
#         color, text = get_password_strength(st.session_state[f"password_{form_id}"])
#         st.markdown(f"**Strength:** <span style='color:{color};'>{text}</span>", unsafe_allow_html=True)

#         notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "")

#         if st.form_submit_button("Save Email"):
#             password_to_save = st.session_state[f"password_{form_id}"]
#             if not all([account_name, service_name, email_address, password_to_save]):
#                 st.error("All fields are required for Email.")
#                 return

#             enc_pass = secure_store(password_to_save, st.session_state.encryption_key)

#             if is_edit:
#                 update_credential(credential['id'], account_name, email_address, service_name, "Email", enc_pass, "", notes)
#                 st.success("Email updated!")
#             else:
#                 insert_credential(account_name, email_address, service_name, "Email", enc_pass, "", notes)
#                 st.success("Email added!")

#             # Clean up session state for this form
#             del st.session_state[f"password_{form_id}"]
#             st.rerun()

# def api_form(credential=None):
#     """Renders the form for adding or editing an API credential."""
#     is_edit = credential is not None
#     key = st.session_state.encryption_key

#     # Set default is_active to True for new credentials, or get from existing
#     default_is_active = credential.get('is_active', 1) == 1 if is_edit else True

#     with st.form(key=f"api_form_{credential['id'] if is_edit else 'add'}"):
#         service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_api")
#         account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_api")
#         api_key_field = st.text_input("API Key", type="password", value=retrieve_secure(credential['api_key'], key) if is_edit and credential.get('api_key') else "", key="api_key_field")
#         notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes_api")
#         is_active = st.checkbox("Active", value=default_is_active, key="is_active_api")

#         if st.form_submit_button("Save API Key"):
#             if not all([account_name, service_name, api_key_field]):
#                 st.error("Service Name, Account Name and API Key are required.")
#                 return

#             enc_api_key = secure_store(api_key_field, key)

#             if is_edit:
#                 update_credential(credential['id'], account_name, "", service_name, "API", "", enc_api_key, notes, is_active)
#                 st.success("API Key updated!")
#             else:
#                 insert_credential(account_name, "", service_name, "API", "", enc_api_key, notes, is_active)
#                 st.success("API Key added!")
#             st.rerun()

# def service_form(email_id, credential=None):
#     """Renders the form for adding or editing a service credential in a dialog."""
#     is_edit = credential is not None
#     form_id = f"service_form_{email_id}_{credential['id'] if is_edit else 'add'}"

#     # Initialize session state for the password field
#     if f"password_{form_id}" not in st.session_state:
#         st.session_state[f"password_{form_id}"] = retrieve_secure(credential['password'], st.session_state.encryption_key) if is_edit and credential.get('password') else ""

#     def update_password():
#         st.session_state[f"password_{form_id}"] = st.session_state[f"password_input_{form_id}"]

#     if st.button("Generate Secure Password", key=f"generate_pass_{form_id}"):
#         st.session_state[f"password_{form_id}"] = generate_password()

#     with st.form(key=form_id):
#         service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", placeholder="e.g., Netflix")
#         account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", placeholder="e.g., Main Acc")
#         email_address = st.text_input("Email Address", value=next((c['email'] for c in get_all_credentials() if c['id'] == email_id), ""), disabled=True)

#         password_field = st.text_input(
#             "Password", type="password",
#             value=st.session_state[f"password_{form_id}"],
#             on_change=update_password,
#             key=f"password_input_{form_id}"
#         )

#         # Password strength meter
#         color, text = get_password_strength(st.session_state[f"password_{form_id}"])
#         st.markdown(f"**Strength:** <span style='color:{color};'>{text}</span>", unsafe_allow_html=True)

#         notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "")

#         if st.form_submit_button("Save Service"):
#             password_to_save = st.session_state[f"password_{form_id}"]
#             if not all([service_name, account_name, password_to_save]):
#                 st.error("Service Name, Account Name, and Password are required.")
#                 return

#             enc_pass = secure_store(password_to_save, st.session_state.encryption_key)

#             if is_edit:
#                 success = update_credential(credential['id'], account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
#                 if success: st.success("Service updated!")
#                 else: st.error("Failed to update service.")
#             else:
#                 success = insert_credential(account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
#                 if success: st.success("Service added!")
#                 else: st.error("Failed to add service.")

#             # Clean up and close dialog
#             del st.session_state[f"password_{form_id}"]
#             st.session_state.show_service_dialog = False
#             st.session_state.editing_service_credential = None
#             st.rerun()

# # --- Main Application UI ---
# def render_credential_manager():
#     """Render the main credential management interface."""
#     st.title("🔐 Credential Manager")

#     # Initialize state
#     if "dialog_state" not in st.session_state:
#         st.session_state.dialog_state = {"name": None, "props": {}}

#     key = st.session_state.encryption_key

#     # --- Dialog Router ---
#     def dialog_router():
#         dialog_name = st.session_state.dialog_state.get("name")
#         props = st.session_state.dialog_state.get("props", {})

#         if dialog_name == "add_email":
#             add_email_dialog()
#         elif dialog_name == "edit_email":
#             edit_email_dialog(**props)
#         elif dialog_name == "view_email":
#             view_email_dialog(**props)
#         elif dialog_name == "add_api":
#             add_api_dialog()
#         elif dialog_name == "edit_api":
#             edit_api_dialog(**props)
#         elif dialog_name == "add_service":
#             service_dialog(**props)
#         elif dialog_name == "edit_service":
#             service_dialog(**props)
#         elif dialog_name == "delete_credential":
#             delete_dialog(**props)


#     @st.dialog("Manage Service")
#     def service_dialog():
#         """Dialog for adding or editing a service."""
#         email_id = st.session_state.current_email_id
#         credential = st.session_state.editing_service_credential
#         title = "Edit Service" if credential else "Add New Service"
#         st.subheader(title)
#         service_form(email_id, credential)
#         if st.button("Cancel"):
#             st.session_state.show_service_dialog = False
#             st.session_state.editing_service_credential = None
#             st.rerun()

#     # --- Dialog Definitions ---
#     @st.dialog("Add Email")
#     def add_email_dialog():
#         email_form()

#     @st.dialog("Edit Email")
#     def edit_email_dialog(credential):
#         email_form(credential)

#     @st.dialog("Add API Key")
#     def add_api_dialog():
#         api_form()

#     @st.dialog("Edit API Key")
#     def edit_api_dialog(credential):
#         api_form(credential)

#     @st.dialog("View Email Details")
#     def view_email_dialog(credential):
#         st.write(f"**Credential Type:** {credential.get('credential_type', 'N/A')}")
#         st.write(f"**Account Name:** {credential['account_name']}")
#         st.write(f"**Service Name:** {credential['service_name']}")
#         st.write(f"**Email Address:** {credential['email']}")
#         if credential.get('password'):
#             st.text_input("Password", retrieve_secure(credential['password'], key), type="password", disabled=True)
#         if credential.get('notes'):
#             st.write(f"**Notes:** {credential['notes']}")

#         st.divider()
#         st.subheader("Associated Services")

#         email_address = credential['email']
#         services = [c for c in get_all_credentials() if c.get('credential_type') == 'Service Password' and c.get('email') == email_address]

#         if not services:
#             st.write("No services associated with this email.")

#         if st.button("Add New Service"):
#             st.session_state.dialog_state = {"name": "add_service", "props": {"email_id": credential['id']}}
#             st.rerun()

#         for service in services:
#             col1, col2, col3, col4 = st.columns([1, 1, 0.5, 0.5])
#             col1.write(service.get('service_name', ''))
#             col2.write(service.get('account_name', ''))
#             if col3.button("✏️", key=f"edit_service_{service['id']}"):
#                 st.session_state.dialog_state = {"name": "edit_service", "props": {"email_id": credential['id'], "credential": service}}
#                 st.rerun()
#             if col4.button("🗑️", key=f"delete_service_{service['id']}"):
#                 delete_credential(service['id'])
#                 st.rerun()

#         if st.button("Close"):
#             st.session_state.dialog_state = {"name": None, "props": {}}
#             st.rerun()

#     @st.dialog("Confirm Deletion")
#     def delete_dialog(credential_id):
#         st.error("Are you sure you want to permanently delete this credential?")
#         if st.button("Yes, Delete"):
#             delete_credential(credential_id)
#             st.session_state.dialog_state = {"name": None, "props": {}}
#             st.rerun()
#         if st.button("Cancel"):
#             st.session_state.dialog_state = {"name": None, "props": {}}
#             st.rerun()

#     # --- UI & Event Handling ---
#     dialog_router()

#     c1, c2 = st.columns(2)
#     if c1.button("✚ Add New Email", use_container_width=True):
#         st.session_state.dialog_state = {"name": "add_email", "props": {}}
#         st.rerun()
#     if c2.button("✚ Add New API Key", use_container_width=True):
#         st.session_state.dialog_state = {"name": "add_api", "props": {}}
#         st.rerun()

#     # --- Filtering and Sorting ---
#     all_credentials = get_all_credentials()
#     print(f"Debug: All credentials: {all_credentials}")  # Check database output
#     col1, col2 = st.columns([1, 2])
#     with col1:
#         unique_types = ["Email", "API"]  # Only Email and API types now
#         types_to_display = st.multiselect("Filter by Type", options=unique_types, default=[])
#     with col2:
#         search_query = st.text_input("Search Credentials", placeholder="Search by Account, Service, or Email...")

#     col3, col4 = st.columns(2)
#     with col3:
#         sort_by = st.selectbox("Sort by", options=["Type", "Account", "Service"], index=1)
#     with col4:
#         sort_order = st.radio("Order", options=["Ascending", "Descending"], horizontal=True)

#     filtered_creds = [
#         cred for cred in all_credentials if
#         (not types_to_display or cred.get('credential_type') in types_to_display) and
#         (not search_query or
#          search_query.lower() in cred.get('account_name', '').lower() or
#          search_query.lower() in cred.get('service_name', '').lower() or
#          search_query.lower() in cred.get('email', '').lower())
#     ]
    
#     reverse_order = (sort_order == "Descending")
#     sort_key_map = {"Type": "credential_type", "Account": "account_name", "Service": "service_name"}
#     sort_key = sort_key_map[sort_by]
#     filtered_creds.sort(key=lambda x: str(x.get(sort_key, "")).lower(), reverse=reverse_order)

#     if not all_credentials:
#         st.info("No credentials found. Click the button above to add one.")
#         return

#     def render_actions(credential):
#         col1, col2, col3 = st.columns([1, 1, 1])
#         if credential.get('credential_type') == 'Email':
#             if col1.button("👁️", key=f"view_{credential['id']}", help="View Details & Services"):
#                 st.session_state.dialog_state = {"name": "view_email", "props": {"credential": credential}}
#                 st.rerun()
#         else:
#             col1.write("") # Placeholder for alignment

#         if col2.button("✏️", key=f"edit_{credential['id']}", help="Edit"):
#             dialog_name = "edit_api" if credential.get('credential_type') == 'API' else "edit_email"
#             st.session_state.dialog_state = {"name": dialog_name, "props": {"credential": credential}}
#             st.rerun()

#         if col3.button("🗑️", key=f"delete_{credential['id']}", help="Delete"):
#             st.session_state.dialog_state = {"name": "delete_credential", "props": {"credential_id": credential['id']}}
#             st.rerun()

#     tab_email, tab_api = st.tabs(["📧 Email", "🔑 API"])

#     with tab_email:
#         email_creds = [c for c in filtered_creds if c.get('credential_type') == 'Email']
#         if not email_creds:
#             st.info("No Email credentials match your filters.")
#         else:
#             col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
#             col1.write("**Account Name**")
#             col2.write("**Service Name**")
#             col3.write("**Email Address**")
#             col4.write("**Password**")
#             col5.write("**Actions**")
#             for cred in email_creds:
#                 col1, col2, col3, col4, col5 = st.columns([2, 2, 2.5, 1.5, 1.5])
#                 col1.write(cred.get('account_name', ''))
#                 col2.write(cred.get('service_name', ''))
#                 col3.write(cred.get('email', ''))
#                 decrypted_pass = retrieve_secure(cred['password'], key)
#                 st_copy(decrypted_pass, button_text="📋 Copy", key=f"pwd_email_{cred['id']}")
#                 with col5:
#                     render_actions(cred)

#     with tab_api:
#         api_creds = [c for c in filtered_creds if c.get('credential_type') == 'API']
#         if not api_creds:
#             st.info("No API credentials match your filters.")
#         else:
#             # Add a status column
#             col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1.5, 2])
#             col1.write("**Service Name**")
#             col2.write("**Account Name**")
#             col3.write("**Status**")
#             col4.write("**API Key**")
#             col5.write("**Actions**")
#             st.divider()
#             for cred in api_creds:
#                 is_active = cred.get('is_active', 1) == 1
#                 # Gray out inactive credentials
#                 row_style = "style='color: #888;'" if not is_active else ""

#                 col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1.5, 2])

#                 col1.markdown(f"<span {row_style}>{cred.get('service_name', '')}</span>", unsafe_allow_html=True)
#                 col2.markdown(f"<span {row_style}>{cred.get('account_name', '')}</span>", unsafe_allow_html=True)

#                 status_text = "Active" if is_active else "Inactive"
#                 status_color = "green" if is_active else "red"
#                 col3.markdown(f"<span {row_style}> <span style='color:{status_color};'>●</span> {status_text}</span>", unsafe_allow_html=True)

#                 decrypted_key = retrieve_secure(cred['api_key'], key)
#                 st_copy(decrypted_key, button_text="📋 Copy", key=f"key_api_{cred['id']}")
#                 with col5:
#                     render_actions(cred)
import streamlit as st
import pandas as pd
import secrets
import string
from database import (
    get_all_credentials, insert_credential, update_credential, delete_credential
)
from encryption import retrieve_secure, secure_store
from streamlit_clipboard import st_copy_to_clipboard
from zxcvbn import zxcvbn

# --- Password Generation and Strength ---
def get_password_strength(password):
    """Return a color and text description of the password strength."""
    if not password:
        return "black", "Enter a password"
    strength = zxcvbn(password)
    score = strength['score']
    if score < 2:
        return "red", "Weak"
    elif score < 3:
        return "orange", "Okay"
    elif score < 4:
        return "lightgreen", "Good"
    else:
        return "darkgreen", "Strong"

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
    form_id = f"email_form_{credential['id'] if is_edit else 'add'}"

    # Initialize session state for the password field
    if f"password_{form_id}" not in st.session_state:
        st.session_state[f"password_{form_id}"] = retrieve_secure(credential['password'], st.session_state.encryption_key) if is_edit and credential.get('password') else ""

    def update_password():
        st.session_state[f"password_{form_id}"] = st.session_state[f"password_input_{form_id}"]

    if st.button("Generate Secure Password", key=f"generate_pass_{form_id}"):
        st.session_state[f"password_{form_id}"] = generate_password()

    with st.form(key=form_id):
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "")
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "")
        email_address = st.text_input("Email Address", value=credential.get('email', '') if is_edit else "")

        password_field = st.text_input(
            "Password", type="password",
            value=st.session_state[f"password_{form_id}"],
            on_change=update_password,
            key=f"password_input_{form_id}"
        )

        # Password strength meter
        color, text = get_password_strength(st.session_state[f"password_{form_id}"])
        st.markdown(f"**Strength:** <span style='color:{color};'>{text}</span>", unsafe_allow_html=True)

        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "")

        if st.form_submit_button("Save Email"):
            password_to_save = st.session_state[f"password_{form_id}"]
            if not all([account_name, service_name, email_address, password_to_save]):
                st.error("All fields are required for Email.")
                return

            enc_pass = secure_store(password_to_save, st.session_state.encryption_key)

            if is_edit:
                update_credential(credential['id'], account_name, email_address, service_name, "Email", enc_pass, "", notes)
                st.success("Email updated!")
            else:
                insert_credential(account_name, email_address, service_name, "Email", enc_pass, "", notes)
                st.success("Email added!")

            # Clean up session state for this form
            del st.session_state[f"password_{form_id}"]
            st.rerun()

def api_form(credential=None):
    """Renders the form for adding or editing an API credential."""
    is_edit = credential is not None
    key = st.session_state.encryption_key

    # Set default is_active to True for new credentials, or get from existing
    default_is_active = credential.get('is_active', 1) == 1 if is_edit else True

    with st.form(key=f"api_form_{credential['id'] if is_edit else 'add'}"):
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", key="service_name_api")
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", key="account_name_api")
        api_key_field = st.text_input("API Key", type="password", value=retrieve_secure(credential['api_key'], key) if is_edit and credential.get('api_key') else "", key="api_key_field")
        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "", key="notes_api")
        is_active = st.checkbox("Active", value=default_is_active, key="is_active_api")

        if st.form_submit_button("Save API Key"):
            if not all([account_name, service_name, api_key_field]):
                st.error("Service Name, Account Name and API Key are required.")
                return

            enc_api_key = secure_store(api_key_field, key)

            if is_edit:
                update_credential(credential['id'], account_name, "", service_name, "API", "", enc_api_key, notes, is_active)
                st.success("API Key updated!")
            else:
                insert_credential(account_name, "", service_name, "API", "", enc_api_key, notes, is_active)
                st.success("API Key added!")
            st.rerun()

def service_form(email_id, credential=None):
    """Renders the form for adding or editing a service credential in a dialog."""
    is_edit = credential is not None
    form_id = f"service_form_{email_id}_{credential['id'] if is_edit else 'add'}"

    # Initialize session state for the password field
    if f"password_{form_id}" not in st.session_state:
        st.session_state[f"password_{form_id}"] = retrieve_secure(credential['password'], st.session_state.encryption_key) if is_edit and credential.get('password') else ""

    def update_password():
        st.session_state[f"password_{form_id}"] = st.session_state[f"password_input_{form_id}"]

    if st.button("Generate Secure Password", key=f"generate_pass_{form_id}"):
        st.session_state[f"password_{form_id}"] = generate_password()

    with st.form(key=form_id):
        service_name = st.text_input("Service Name", value=credential.get('service_name', '') if is_edit else "", placeholder="e.g., Netflix")
        account_name = st.text_input("Account Name", value=credential.get('account_name', '') if is_edit else "", placeholder="e.g., Main Acc")
        email_address = st.text_input("Email Address", value=next((c['email'] for c in get_all_credentials() if c['id'] == email_id), ""), disabled=True)

        password_field = st.text_input(
            "Password", type="password",
            value=st.session_state[f"password_{form_id}"],
            on_change=update_password,
            key=f"password_input_{form_id}"
        )

        # Password strength meter
        color, text = get_password_strength(st.session_state[f"password_{form_id}"])
        st.markdown(f"**Strength:** <span style='color:{color};'>{text}</span>", unsafe_allow_html=True)

        notes = st.text_area("Notes (Optional)", value=credential.get('notes', '') if is_edit else "")

        if st.form_submit_button("Save Service"):
            password_to_save = st.session_state[f"password_{form_id}"]
            if not all([service_name, account_name, password_to_save]):
                st.error("Service Name, Account Name, and Password are required.")
                return

            enc_pass = secure_store(password_to_save, st.session_state.encryption_key)

            if is_edit:
                success = update_credential(credential['id'], account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
                if success: st.success("Service updated!")
                else: st.error("Failed to update service.")
            else:
                success = insert_credential(account_name, email_address, service_name, "Service Password", enc_pass, "", notes)
                if success: st.success("Service added!")
                else: st.error("Failed to add service.")

            # Clean up and close dialog
            del st.session_state[f"password_{form_id}"]
            st.session_state.show_service_dialog = False
            st.session_state.editing_service_credential = None
            st.rerun()

# --- Main Application UI ---
def render_credential_manager():
    """Render the main credential management interface."""
    st.title("🔐 Credential Manager")

    # Initialize state
    if "dialog_state" not in st.session_state:
        st.session_state.dialog_state = {"name": None, "props": {}}

    key = st.session_state.encryption_key

    # --- Dialog Router ---
    def dialog_router():
        dialog_name = st.session_state.dialog_state.get("name")
        props = st.session_state.dialog_state.get("props", {})

        if dialog_name == "add_email":
            add_email_dialog()
        elif dialog_name == "edit_email":
            edit_email_dialog(**props)
        elif dialog_name == "view_email":
            view_email_dialog(**props)
        elif dialog_name == "add_api":
            add_api_dialog()
        elif dialog_name == "edit_api":
            edit_api_dialog(**props)
        elif dialog_name == "add_service":
            service_dialog(**props)
        elif dialog_name == "edit_service":
            service_dialog(**props)
        elif dialog_name == "delete_credential":
            delete_dialog(**props)


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

    # --- Dialog Definitions ---
    @st.dialog("Add Email")
    def add_email_dialog():
        email_form()

    @st.dialog("Edit Email")
    def edit_email_dialog(credential):
        email_form(credential)

    @st.dialog("Add API Key")
    def add_api_dialog():
        api_form()

    @st.dialog("Edit API Key")
    def edit_api_dialog(credential):
        api_form(credential)

    @st.dialog("View Email Details")
    def view_email_dialog(credential):
        st.write(f"**Credential Type:** {credential.get('credential_type', 'N/A')}")
        st.write(f"**Account Name:** {credential['account_name']}")
        st.write(f"**Service Name:** {credential['service_name']}")
        st.write(f"**Email Address:** {credential['email']}")
        if credential.get('password'):
            st.text_input("Password", retrieve_secure(credential['password'], key), type="password", disabled=True)
        if credential.get('notes'):
            st.write(f"**Notes:** {credential['notes']}")

        st.divider()
        st.subheader("Associated Services")

        email_address = credential['email']
        services = [c for c in get_all_credentials() if c.get('credential_type') == 'Service Password' and c.get('email') == email_address]

        if not services:
            st.write("No services associated with this email.")

        if st.button("Add New Service"):
            st.session_state.dialog_state = {"name": "add_service", "props": {"email_id": credential['id']}}
            st.rerun()

        for service in services:
            col1, col2, col3, col4 = st.columns([1, 1, 0.5, 0.5])
            col1.write(service.get('service_name', ''))
            col2.write(service.get('account_name', ''))
            if col3.button("✏️", key=f"edit_service_{service['id']}"):
                st.session_state.dialog_state = {"name": "edit_service", "props": {"email_id": credential['id'], "credential": service}}
                st.rerun()
            if col4.button("🗑️", key=f"delete_service_{service['id']}"):
                delete_credential(service['id'])
                st.rerun()

        if st.button("Close"):
            st.session_state.dialog_state = {"name": None, "props": {}}
            st.rerun()

    @st.dialog("Confirm Deletion")
    def delete_dialog(credential_id):
        st.error("Are you sure you want to permanently delete this credential?")
        if st.button("Yes, Delete"):
            delete_credential(credential_id)
            st.session_state.dialog_state = {"name": None, "props": {}}
            st.rerun()
        if st.button("Cancel"):
            st.session_state.dialog_state = {"name": None, "props": {}}
            st.rerun()

    # --- UI & Event Handling ---
    dialog_router()

    c1, c2 = st.columns(2)
    if c1.button("✚ Add New Email", use_container_width=True):
        st.session_state.dialog_state = {"name": "add_email", "props": {}}
        st.rerun()
    if c2.button("✚ Add New API Key", use_container_width=True):
        st.session_state.dialog_state = {"name": "add_api", "props": {}}
        st.rerun()

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
        if credential.get('credential_type') == 'Email':
            if col1.button("👁️", key=f"view_{credential['id']}", help="View Details & Services"):
                st.session_state.dialog_state = {"name": "view_email", "props": {"credential": credential}}
                st.rerun()
        else:
            col1.write("") # Placeholder for alignment

        if col2.button("✏️", key=f"edit_{credential['id']}", help="Edit"):
            dialog_name = "edit_api" if credential.get('credential_type') == 'API' else "edit_email"
            st.session_state.dialog_state = {"name": dialog_name, "props": {"credential": credential}}
            st.rerun()

        if col3.button("🗑️", key=f"delete_{credential['id']}", help="Delete"):
            st.session_state.dialog_state = {"name": "delete_credential", "props": {"credential_id": credential['id']}}
            st.rerun()

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
                decrypted_pass = retrieve_secure(cred['password'], key)
                st_copy_to_clipboard(decrypted_pass, button_text="📋 Copy", key=f"pwd_email_{cred['id']}")
                with col5:
                    render_actions(cred)

    with tab_api:
        api_creds = [c for c in filtered_creds if c.get('credential_type') == 'API']
        if not api_creds:
            st.info("No API credentials match your filters.")
        else:
            # Add a status column
            col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1.5, 2])
            col1.write("**Service Name**")
            col2.write("**Account Name**")
            col3.write("**Status**")
            col4.write("**API Key**")
            col5.write("**Actions**")
            st.divider()
            for cred in api_creds:
                is_active = cred.get('is_active', 1) == 1
                # Gray out inactive credentials
                row_style = "style='color: #888;'" if not is_active else ""

                col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1.5, 2])

                col1.markdown(f"<span {row_style}>{cred.get('service_name', '')}</span>", unsafe_allow_html=True)
                col2.markdown(f"<span {row_style}>{cred.get('account_name', '')}</span>", unsafe_allow_html=True)

                status_text = "Active" if is_active else "Inactive"
                status_color = "green" if is_active else "red"
                col3.markdown(f"<span {row_style}> <span style='color:{status_color};'>●</span> {status_text}</span>", unsafe_allow_html=True)

                decrypted_key = retrieve_secure(cred['api_key'], key)
                st_copy_to_clipboard(decrypted_key, button_text="📋 Copy", key=f"key_api_{cred['id']}")
                with col5:
                    render_actions(cred)