import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib

# Generate a Fernet key from a passkey
def generate_key(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key)

# In-memory data storage
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}

# Track failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Track login status
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = True

def encrypt_data(data, passkey):
    f = Fernet(generate_key(passkey))
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, passkey):
    try:
        f = Fernet(generate_key(passkey))
        return f.decrypt(encrypted_data.encode()).decode()
    except InvalidToken:
        return None

def login_page():
    st.title("Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("Login successful!")
        else:
            st.error("Incorrect credentials")


def home():
    st.title("🔐 Secure Data Encryption System")
    option = st.radio("Choose an option", ("Insert Data", "Retrieve Data"))
    if option == "Insert Data":
        insert_data()
    elif option == "Retrieve Data":
        retrieve_data()

def insert_data():
    st.header("Store Encrypted Data")
    data = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter a passkey", type="password")
    key_name = st.text_input("Enter a unique key name")

    if st.button("Encrypt and Store"):
        if key_name in st.session_state.data_store:
            st.warning("Key name already exists. Choose a different name.")
        elif data and passkey:
            encrypted = encrypt_data(data, passkey)
            st.session_state.data_store[key_name] = encrypted
            st.success(f"Data stored under key: {key_name}")
        else:
            st.warning("Please fill in all fields.")

def retrieve_data():
    st.header("Retrieve Decrypted Data")
    key_name = st.text_input("Enter the key name")
    passkey = st.text_input("Enter the passkey", type="password")

    if st.button("Retrieve"):
        if key_name in st.session_state.data_store:
            encrypted = st.session_state.data_store[key_name]
            decrypted = decrypt_data(encrypted, passkey)
            if decrypted is not None:
                st.success("Decryption successful!")
                st.text_area("Decrypted Data", decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey! Attempts: {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
        else:
            st.error("Key name not found.")

# App logic
if st.session_state.is_logged_in:
    home()
else:
    login_page()
