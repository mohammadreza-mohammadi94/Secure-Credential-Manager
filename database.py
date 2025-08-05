# database.py

import sqlite3
import streamlit as st
from typing import List, Dict, Optional

DATABASE_PATH = "credentials.db"

def get_db_connection():
    """Create and return a database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize the database and handle schema migration for new columns."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create the main credentials table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_name TEXT NOT NULL,
            email TEXT,
            service_name TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            password TEXT,
            api_key TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # --- Schema Migration: Add 'is_active' column if it doesn't exist ---
    try:
        cursor.execute("SELECT is_active FROM credentials LIMIT 1")
    except sqlite3.OperationalError:
        # The column doesn't exist, so add it
        st.warning("Updating database schema to add 'is_active' column...")
        cursor.execute("ALTER TABLE credentials ADD COLUMN is_active INTEGER DEFAULT 1")
        st.success("Database updated.")

    # --- Schema Migration: Add 'favicon_url' column if it doesn't exist ---
    try:
        cursor.execute("SELECT favicon_url FROM credentials LIMIT 1")
    except sqlite3.OperationalError:
        # The column doesn't exist, so add it
        st.warning("Updating database schema to add 'favicon_url' column...")
        cursor.execute("ALTER TABLE credentials ADD COLUMN favicon_url TEXT")
        st.success("Database updated.")

    # Create the app_meta table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    ''')

    # --- New Table: Password History ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
        )
    ''')

    # --- New Tables for Tagging ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credential_tags (
            credential_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (credential_id, tag_id),
            FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

@st.cache_data(ttl=300, show_spinner=False)
def get_all_tags() -> List[str]:
    """Get all unique tag names."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM tags ORDER BY name")
    rows = cursor.fetchall()
    conn.close()
    return [row['name'] for row in rows]

def get_tags_for_credential(credential_id: int) -> List[str]:
    """Get all tags for a given credential."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT t.name FROM tags t
        JOIN credential_tags ct ON t.id = ct.tag_id
        WHERE ct.credential_id = ?
    ''', (credential_id,))
    rows = cursor.fetchall()
    conn.close()
    return [row['name'] for row in rows]

@st.cache_data(ttl=300, show_spinner=False)
def get_all_credentials() -> List[Dict]:
    """Get all credential records, including their tags."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM credentials ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    credentials = [dict(row) for row in rows]

    for cred in credentials:
        cred['tags'] = get_tags_for_credential(cred['id'])

    conn.close()
    return credentials

def add_tags_to_credential(credential_id: int, tags: List[str]):
    """Associate a list of tags with a credential."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing tags for this credential
    cursor.execute("DELETE FROM credential_tags WHERE credential_id = ?", (credential_id,))

    for tag_name in tags:
        # Get or create the tag
        cursor.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
        tag = cursor.fetchone()
        if tag:
            tag_id = tag['id']
        else:
            cursor.execute("INSERT INTO tags (name) VALUES (?)", (tag_name,))
            tag_id = cursor.lastrowid

        # Associate tag with credential
        cursor.execute("INSERT INTO credential_tags (credential_id, tag_id) VALUES (?, ?)", (credential_id, tag_id))

    conn.commit()
    conn.close()

def insert_credential(account_name: str, email: str, service_name: str, credential_type: str, password: str, api_key: Optional[str], notes: Optional[str], is_active: bool = True, favicon_url: Optional[str] = None, tags: List[str] = []) -> bool:
    """Insert a new credential record."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (account_name, email, service_name, credential_type, password, api_key, notes, is_active, favicon_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (account_name, email, service_name, credential_type, password, api_key, notes, 1 if is_active else 0, favicon_url)
        )
        credential_id = cursor.lastrowid
        conn.commit()

        if tags:
            add_tags_to_credential(credential_id, tags)

        st.cache_data.clear()
        print(f"Debug: Successfully inserted credential - ID: {credential_id}, type: {credential_type}")
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def is_password_in_history(credential_id: int, new_password_hash: str) -> bool:
    """Check if a password hash exists in the history for a credential."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM password_history WHERE credential_id = ? AND password_hash = ?", (credential_id, new_password_hash))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def add_password_to_history(credential_id: int, old_password_hash: str):
    """Add an old password hash to the history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO password_history (credential_id, password_hash) VALUES (?, ?)", (credential_id, old_password_hash))
    conn.commit()
    conn.close()

def update_credential(record_id: int, account_name: str, email: str, service_name: str, credential_type: str, password: str, api_key: Optional[str], notes: Optional[str], is_active: bool = True, favicon_url: Optional[str] = None, tags: List[str] = []) -> bool:
    """Update a credential record, checking for password reuse."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # --- Password History Check ---
        if password: # Only check if a new password is provided
            # Get the current password hash to archive it
            cursor.execute("SELECT password FROM credentials WHERE id = ?", (record_id,))
            result = cursor.fetchone()
            old_password_hash = result['password'] if result else None

            # Check if the new password is the same as the old one or in history
            if password == old_password_hash or is_password_in_history(record_id, password):
                st.error("Password has been used before. Please choose a new one.")
                return False

            # If the password is truly new, add the old one to history (if it existed)
            if old_password_hash:
                add_password_to_history(record_id, old_password_hash)

        # Proceed with the update
        cursor.execute('''
            UPDATE credentials
            SET account_name = ?, email = ?, service_name = ?, credential_type = ?, password = ?, api_key = ?, notes = ?, is_active = ?, favicon_url = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (account_name, email, service_name, credential_type, password, api_key, notes, 1 if is_active else 0, favicon_url, record_id))

        if tags:
            add_tags_to_credential(record_id, tags)

        conn.commit()
        st.cache_data.clear()
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def delete_credential(record_id: int) -> bool:
    """Delete a credential record."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (record_id,))
        conn.commit()
        st.cache_data.clear()
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def set_app_meta(key: str, value: bytes):
    conn = get_db_connection()
    conn.execute("INSERT OR REPLACE INTO app_meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def get_app_meta(key: str) -> Optional[bytes]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM app_meta WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else None