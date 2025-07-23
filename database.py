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
    """Initialize the database with a single, unified credentials table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # --- ADDED: credential_type column ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_name TEXT NOT NULL,
            email TEXT NOT NULL,
            service_name TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            password TEXT NOT NULL,
            api_key TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

@st.cache_data(ttl=300, show_spinner=False)  # TTL کوتاه برای به‌روزرسانی سریع
def get_all_credentials() -> List[Dict]:
    """Get all credential records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM credentials ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def insert_credential(account_name: str, email: str, service_name: str, credential_type: str, password: str, api_key: Optional[str], notes: Optional[str]) -> bool:
    """Insert a new credential record."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO credentials (account_name, email, service_name, credential_type, password, api_key, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (account_name, email, service_name, credential_type, password, api_key, notes)
        )
        conn.commit()
        st.cache_data.clear()
        print(f"Debug: Successfully inserted credential - ID: {cursor.lastrowid}, type: {credential_type}")
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def update_credential(record_id: int, account_name: str, email: str, service_name: str, credential_type: str, password: str, api_key: Optional[str], notes: Optional[str]) -> bool:
    """Update a credential record."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE credentials
            SET account_name = ?, email = ?, service_name = ?, credential_type = ?, password = ?, api_key = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (account_name, email, service_name, credential_type, password, api_key, notes, record_id))
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