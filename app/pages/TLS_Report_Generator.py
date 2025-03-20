import streamlit as st
import requests
import json
import xml.etree.ElementTree as ET
import pandas as pd
import sys
import os 
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from libs.lib import *
import uuid
# Set the layout to wide mode
st.set_page_config(layout="wide", page_icon="🤷‍♂️", initial_sidebar_state="auto", menu_items=None)
pd.set_option("display.max_rows", None)




st.title('TLS Report Generator')
cipherdict = get_cipher_security_info()
st.session_state['files_uploaded'] = False
st.session_state['tls_cipher_eval'] = False

uploaded_files = st.file_uploader("Upload Nmap Files (XML):", accept_multiple_files=True)

if uploaded_files:
    save_folder = os.path.join(os.path.expanduser("~"), "uploaded_files")
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)
    xml_files = [uploaded_file for uploaded_file in uploaded_files if uploaded_file.name.endswith('.xml')]
    if xml_files:
        # Check if the folder exists, if not create it
        if not os.path.exists(save_folder):
            os.makedirs(save_folder)
        unique_folder = os.path.join(save_folder, str(uuid.uuid4()))
        os.makedirs(unique_folder)
        for uploaded_file in xml_files:
            # Save file to the unique folder
            file_path = os.path.join(unique_folder, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
        st.write(f"Saved XML files to: {unique_folder}")
        st.write("Processing the uploaded XML files now")
        st.session_state['files_uploaded'] = True
        st.session_state['upload_folder'] = unique_folder

    else:
        st.write("No XML files found")

if st.session_state['files_uploaded']:
    all_ciphers = []
    st.write(os.listdir(st.session_state['upload_folder']))
    for uploaded_file in os.listdir(st.session_state['upload_folder']):
        try:
            # Parse XML file
            st.write(f"Looking at {uploaded_file}")
            tree = ET.parse(os.path.join(st.session_state['upload_folder'],uploaded_file))
            root = tree.getroot()

            # Iterate through all hosts in the XML
            for host in root.findall(".//host"):
                # Get IP Address and its type of the host   
                ip_address = host.find(".//address").attrib.get('addr')
                ip_address_type = host.find(".//address").attrib.get('addrtype')
                # Check if the host has any ports
                ports_element = host.find(".//ports")
                if ports_element is not None:
                    # Iterate through each port in the 'ports' element
                    for port in ports_element.findall(".//port"):
                        port_id = port.attrib['portid']
                        port_protocol = port.attrib['protocol']
                        # Check if the port has the 'ssl-enum-ciphers' script
                        script = port.find(".//script[@id='ssl-enum-ciphers']")
                        if script is not None:
                            # Find all tables in the script, we will dynamically process each table
                            for table in script.findall(".//table"):
                                tls_version = table.attrib.get('key')
                                # If the 'key' attribute is a TLS version, process the ciphers for that version
                                if tls_version:
                                    cipher_table = table.find(".//table[@key='ciphers']")
                                    # If cipher table exists, process the ciphers
                                    if cipher_table is not None:
                                        for cipher in cipher_table.findall("table"):
                                            # Extract the cipher details: name, kex_info, and strength
                                            cipher_name = cipher.find(".//elem[@key='name']").text
                                            kex_info = cipher.find(".//elem[@key='kex_info']").text
                                            strength = cipher.find(".//elem[@key='strength']").text
                                            # Retrieve the security level from the cipherdict (default to "Unknown" if not found)
                                            security = cipherdict.get(cipher_name, [{"security": "Unknown"}])[0]['security']
                                            all_ciphers.append([f"{ip_address}[{ip_address_type}]", f"{port_id}[{port_protocol}]", cipher_name, kex_info, tls_version, security])
                                            st.session_state['tls_cipher_eval'] = True
        except ET.ParseError as e:
            st.warning(f"Error parsing XML file {uploaded_file}: {e}")
            continue
        except AttributeError as e:
            st.warning(f"Looks like {uploaded_file} is empty and does not have any IPv4 IPs inside it. Continuing Scan.")
            continue
        except Exception as e:
            st.warning(f"Unknown Error : {uploaded_file}: {e.__traceback__}")
            continue
    if all_ciphers:
        cipher_df = pd.DataFrame(all_ciphers, columns=["IP Address", "Port", "Cipher Name","Kex_info", "TLS Version", "Security"])
        st.write("SSL Enum Cipher Evaluation Result")
        st.dataframe(cipher_df)
    else:
        st.warning("No cipher details found in the uploaded XML files.")

if st.session_state['tls_cipher_eval']:
    # DF where cipher is not Secure or Recommended . Look at the ~ (negate)
    insecure_df = cipher_df[~cipher_df['Security'].isin(['secure', 'recommended'])|~cipher_df['TLS Version'].isin(['TLSv1.2', 'TLSv1.3'])]
    
    #Check for various cipher vulns
    insecure_df['is_weak_kex_RSA'] = insecure_df.apply(lambda row: 'Y' if is_weak_kex_RSA(cipher_name=row['Cipher Name'],cipherdict=cipherdict) else 'N', axis=1)
    insecure_df['is_weak_kex_ECDH'] = insecure_df.apply(lambda row: 'Y' if is_weak_kex_ECDH(cipher_name=row['Cipher Name'],cipherdict=cipherdict) else 'N', axis=1)
    insecure_df['is_weak_hashalg_MD5SHA1'] = insecure_df.apply(lambda row: 'Y' if is_weak_hashalg_MD5SHA1(cipher_name=row['Cipher Name'],cipherdict=cipherdict) else 'N', axis=1)
    insecure_df['is_weak_encalg_cbc'] = insecure_df.apply(lambda row: 'Y' if is_weak_encalg_cbc(cipher_name=row['Cipher Name'],cipherdict=cipherdict) else 'N', axis=1)
    insecure_df['is_weak_kex_DHE'] = insecure_df.apply(lambda row: 'Y' if is_weak_kex_DHE(cipher_name=row['Cipher Name'],cipherdict=cipherdict) else 'N', axis=1)
    insecure_df['is_weak_tls_version'] = insecure_df.apply(lambda row: is_weak_tls_version(tls_name=row['TLS Version']), axis=1)

    st.dataframe(insecure_df)

    summary_df = insecure_df.groupby(['IP Address']).agg({
    'Port': lambda x: '\n'.join(x.astype(str).unique()),  # Ports in new line
    'is_weak_kex_RSA': lambda x: '✓' if 'Y' in x.values else '',
    'is_weak_kex_ECDH': lambda x: '✓' if 'Y' in x.values else '',
    'is_weak_hashalg_MD5SHA1': lambda x: '✓' if 'Y' in x.values else '',
    'is_weak_encalg_cbc': lambda x: '✓' if 'Y' in x.values else '',
    'is_weak_kex_DHE': lambda x: '✓' if 'Y' in x.values else '',
    'is_weak_tls_version': lambda x: '\n'.join(x.astype(str).unique()),
    }).reset_index()

    st.dataframe(summary_df)
