import streamlit as st
import requests

def get_cipher_security_info()->dict:
    try:
        req = requests.get('https://ciphersuite.info/api/cs')
        data = req.json().get('ciphersuites',[])
        cipherdict = {''.join(cipher.keys()): list(cipher.values()) for cipher in data}
        return cipherdict
    except Exception as e:
        st.error(f"Error fetching cipher security info: {e}")
        return {}

def is_weak_encalg_sweet32(cipher_name:str,cipherdict:dict)->bool:
    """Check if the cipher is vulnerable to Sweet32 based on the cipher name."""
    # Vulnerable ciphers are those that use 64-bit block ciphers like 3DES and RC4
    enc_algs = ['3DES', 'RC4']
    if cipher_name.startswith('TLS_AKE_'):
        return False
    # If the Encryption Algorithm contains "3DES" or "RC4", it's vulnerable to Sweet32
    for enc_alg in enc_algs:
        if enc_alg in cipherdict[cipher_name][0]['enc_algorithm']:
            return True
    return False

def is_weak_kex_RSA(cipher_name:str,cipherdict:dict)->bool:
    """Checks if a cipher is vulnerable to the ROBOT attack."""
    # ROBOT attack is related to ciphers using RSA key exchange
    if cipher_name.startswith('TLS_AKE_'):
            return False
    elif cipherdict[cipher_name][0]['kex_algorithm'] == 'RSA':
        return True
    return False

def is_weak_kex_ECDH(cipher_name:str,cipherdict:dict)->bool:
    """Checks if a cipher is non ephemeral ."""
    # ROBOT attack is related to ciphers using RSA key exchange
    if cipher_name.startswith('TLS_AKE_'):
            return False
    elif cipherdict[cipher_name][0]['kex_algorithm'] == 'ECDH' :
        return True
    return False

def is_weak_encalg_cbc(cipher_name:str,cipherdict:dict)->bool:
    """Detect if the given cipher uses Cipher Block Chaining (CBC) mode."""
    if cipher_name.startswith('TLS_AKE_'):
            return False
    elif 'CBC' in cipherdict[cipher_name][0]['enc_algorithm'].split():
        return True
    return False

def is_weak_hashalg_MD5SHA1(cipher_name:str,cipherdict:dict)->bool:
    """Check if the given cipher suite uses SHA-1 or MD5"""
    # Look for 'SHA' in the cipher name (indicating use of SHA-1)
    if cipher_name.startswith('TLS_AKE_'):
            return False
    elif cipherdict[cipher_name][0]['hash_algorithm'] == "SHA" or cipherdict[cipher_name][0]['hash_algorithm'] == "MD5" :
        return True
    return False

def is_weak_kex_DHE(cipher_name:str,cipherdict:dict)->bool:
    """Check if the given cipher suite uses SHA-1."""
    # Look for 'SHA' in the cipher name (indicating use of SHA-1)
    if cipher_name.startswith('TLS_AKE_'):
            return False
    elif cipherdict[cipher_name][0]['kex_algorithm'] == "DHE":
        return True
    return False

def is_weak_tls_version(tls_name:str)->str:
    if tls_name in ['TLSv1.2','TLSv1.3']:
        return ''
    else: 
        return tls_name
