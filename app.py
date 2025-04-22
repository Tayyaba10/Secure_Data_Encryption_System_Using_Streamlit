import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time
import json
import os


DATA_FILE = "data_store.json"
LOCKOUT_DURATION = 60  # seconds

# Load store data from file if it exists
if os.path.exists(DATA_FILE):
     with open(DATA_FILE, "r") as f:
            store_data = json.load(f)
else:
     store_data = {}

# Save store data to file
def save_store_data():
     with open(DATA_FILE, "w") as f:
          json.dump(store_data,f)

st.title("🔒 Secure Data Encryption System App")

# Initialize session state variables
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.fernet = Fernet(st.session_state.fernet_key)
    st.session_state.store_data = {}
    st.session_state.attempts = 0
    st.session_state.authorized = True
    st.session_state.LOCKOUT_DURATION = 0

# hash passkey using sha256
def hash_passkey(passkey: str) -> str:
        return hashlib.sha256(passkey.encode()).hexdigest()

# login function    
def login(passkey:str):
        st.subheader("Reauthorization Required")
        passkey = st.text_input("Enter your password: ", type="password")

        if st.button("Login"):
            if passkey == "admin123":
                st.session_state.attempts = 0
                st.session_state.authorized = True
                st.success("Login successful!")
            else:
                st.error("❌ Invalid password. Please try again.")

# Store data function    
def store_data():
        st.subheader("📂 Store Data")
        username = st.text_input("Enter your username: ")
        text = st.text_area("Enter the data you want to store: ")
        passkey = st.text_input("Enter your password: ", type="password")

        if st.button("Encrypt and Save"):
            if username and text and passkey:
                hashed = hash_passkey(passkey)
                encrypted = st.session_state.fernet.encrypt(text.encode()).decode()
                st.session_state.store_data[username] = {
                    "encrypted_text": encrypted,
                    "hash_passkey": hashed
                }
                save_store_data()
                st.success("Data encrypted and stored successfully.")
            else:
                st.warning("Please fill in all fields.")

# Retrieve data function
def retrieve_data():
        st.subheader("🔍 Retrieve Data")
        username = st.text_input("Enter your username:")
        passkey = st.text_input("Enter your password:", type="password")

        if st.button("Decrypt"):
            if username in st.session_state.store_data:
                stored_data = st.session_state.store_data[username]

                if hash_passkey(passkey) == stored_data["hash_passkey"]:
                    decrypted = st.session_state.fernet.decrypt(stored_data["encrypted_text"].encode()).decode()
                    st.success(f"Decrypted data: {decrypted}")
                    st.session_state.attempts = 0
                else:
                    st.session_state.attempts += 1
                    remaining = 3 - st.session_state.attempts
                    st.error(f"❌ Invalid password. Please try again.Attempts remaining: {remaining}")

                    if st.session_state.attempts >= 3:
                        st.session_state.authorized = False
                        st.session_state.LOCKOUT_DURATION = time.time() 
                        st.warning("🚫 Too many failed attempts. Redirecting to login...")
                        
            else:
                st.error("❌ Username not found. Please try again.")

# lockout logic
if st.session_state.LOCKOUT_DURATION:
     elapsed_time = time.time() - st.session_state.LOCKOUT_DURATION
     if elapsed_time < LOCKOUT_DURATION:
          st.warning(f"⏳ Locked out! Please wait {int(LOCKOUT_DURATION - elapsed_time)} seconds")
          st.stop()
     else:
          st.session_state.LOCKOUT_DURATION = 0
          st.session_state.attempts = 0
    

# Main app logic
if not st.session_state.authorized:
    st.warning("You need to reauthorize to access this feature.")
    login()
else:
    page = st.sidebar.selectbox("Select an option", ["Home", "Store Data", "Retrieve Data", "Login"])
    if page == "Home":
        st.subheader("Welcome to the Secure Data Encryption System App")
        st.write("This app allows you to securely store and retrieve sensitive data using encryption.")
        st.write("Please select an option from the sidebar.")

    elif page == "Store Data":
        store_data()

    elif page == "Retrieve Data":
        retrieve_data()
    
    elif page == "Login":
         login(passkey="admin123")
    
    else:
        st.warning("Please login to access this feature.")

