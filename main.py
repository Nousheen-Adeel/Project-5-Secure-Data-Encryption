import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

key_file = "simple_secret.key"

def load_key():
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file,"wb") as f:
            f.write(key)
    else:
        with open(key_file,"rb") as f:
            key= f.read()
    return key

cipher = Fernet(load_key())

def init_db():
    con = sqlite3.connect("simple_data.db")
    c = con.cursor()
    c.execute ("""
            create table if not exists vault(
            label text primary key, 
               encrypted_text text,
               passkey text )
                """)
    con.commit()
    con.close

init_db()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text):
    return hash_passkey(text)

def decrypt_text(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

st.title("Secure Data Encryption")

menu=["Store Secret","Retrieve Secret"]
choice=st.sidebar.selectbox("Select an option",menu)

if choice == "Store Secret":
    st.subheader("Store a new Secret")

    label=st.text_input("Enter a label for the secret)uniqe id)")
    secret=st.text_area("Enter the secret")
    passkey=st.text_input("Enter the passkey for the secret (to protect)",type="password")

    if st.button("Encrypt and Store"):
        if label and secret and passkey:
            hashed_passkey=hash_passkey(passkey)
            encrypted_text=encrypt_text(secret)
            con=sqlite3.connect("simple_data.db")
            c = con.cursor()

            try:
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)", (label, encrypted_text, hashed_passkey))
                con.commit()
                st.success("Secret stored successfully")
            except sqlite3.IntegrityError:
                st.error("A secret with this label already exists")
                con.close()

elif choice == "Retrieve Secret":
    st.subheader("Retrieve a Secret")

    label=st.text_input("Enter the label of the secret to retrieve")
    passkey=st.text_input("Enter the passkey for the secret",type="password")

    if st.button("Decrypt and Retrieve"):
        con=sqlite3.connect("simple_data.db")
        c = con.cursor()
        c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label,))
        result=c.fetchone()
        con.close()

        if result:
            encrypted_text, stored_passkey=result
            if hash_passkey(passkey) == stored_passkey:
                decrypted_text=decrypt_text(encrypted_text)
                st.success("Secret retrieved successfully")
                st.code(decrypted_text,language="python")

            else:
                st.error("Incorrect passkey")
        else:
                st.warning("No such label found")




 
                
