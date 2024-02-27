import streamlit as st

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte
        ciphertext.append(cipher_byte)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypt ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key) # XOR decryption is the same as encryption

def main():
    st.title("XOR Cipher")
    
    plaintext = st.text_input("Enter plaintext:")
    key = st.text_input("Enter key:")
    
    if st.button("Encrypt"):
        plaintext_bytes = bytes(plaintext.encode())
        key_bytes = bytes(key.encode())
        
        if len(plaintext_bytes) >= len(key_bytes):
            if plaintext_bytes != key_bytes:
                cipher = xor_encrypt(plaintext_bytes, key_bytes)
                st.write("Ciphertext:", "".join([f"{chr(byte_val)}" for byte_val in cipher]))
                
                decrypt = xor_decrypt(cipher, key_bytes)
                st.write("Decrypted:", "".join([f"{chr(byte_val)}" for byte_val in decrypt]))
            else:
                st.write("Plaintext should not be equal to the key")
        else:
            st.write("Plaintext length should be equal or greater than the length of key")

if __name__ == "__main__":
    main()
