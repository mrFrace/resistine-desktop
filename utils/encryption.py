"""
This script is used to encrypt and decrypt data using the Fernet symmetric encryption algorithm.
It securely stores the encryption key using the keyring module ONLY if a secure backend is available.
The encrypted data is stored in a dictionary format and can be retrieved later.

Author: Petr, Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import json

import keyring
from cryptography.fernet import Fernet

from utils.i18n import get_text
from utils.logger import logger


class InsecureKeyringuException(Exception):
    """Raised when the keyring backend is not secure enough for credential storage."""

    pass


def is_keyring_secure():
    """
    Check if the current keyring backend is secure.

    Insecure backends include:
    - PlaintextKeyring (stores passwords in plaintext)
    - Null/Fail backends
    - EncryptedKeyring (uses a master password that may be stored insecurely)

    :return: True if secure, False otherwise
    :raises InsecureKeyringuException: If the backend is insecure with instructions
    """
    backend = keyring.get_keyring()
    backend_name = backend.__class__.__name__
    backend_module = backend.__class__.__module__

    # List of known insecure backends
    insecure_backends = [
        "PlaintextKeyring",
        "EncryptedKeyring",
        "Keyring",  # Base class fallback
    ]

    # Check if backend module indicates a fail/null backend or is an insecure backend
    if (
        "fail" in backend_module.lower()
        or "null" in backend_module.lower()
        or backend_name in insecure_backends
    ):
        raise InsecureKeyringuException(
            get_text(
                "encryption.insecure_backend",
                backend=f"{backend_module}.{backend_name}",
            )
        )

    return True


def get_or_create_key():
    """
    Retrieve or generate an encryption key and store it securely in the system keyring.

    :return: The encryption key as bytes.
    :raises InsecureKeyringuException: If no secure keyring backend is available
    """
    # Check if keyring backend is secure first
    is_keyring_secure()

    key = keyring.get_password("resistine", "encryption_key")
    if key is None:
        new_key = Fernet.generate_key()  # already bytes
        keyring.set_password("resistine", "encryption_key", new_key.decode())
        logger.info("Key securely stored in system keyring.")
        return new_key
    else:
        logger.info("Key retrieved from system keyring.")
        # keyring normally returns str, but some backends return bytes;
        # never .encode() bytes (AttributeError) or double-encode.
        return key if isinstance(key, bytes) else key.encode()


def retrieve_key():
    """
    Retrieve the stored encryption key from the system keyring.

    :return: The encryption key as bytes.
    :raises ValueError: If no key is found in keyring.
    :raises InsecureKeyringuException: If no secure keyring backend is available
    """
    # Check if keyring backend is secure first
    is_keyring_secure()

    key = keyring.get_password("resistine", "encryption_key")
    if key is None:
        raise ValueError(get_text("encryption.no_key_found"))
    return key if isinstance(key, bytes) else key.encode()


def encrypt_data(data_dict):
    """
    Encrypt the data in the provided dictionary and store it securely in the system keyring.

    :param data_dict: A dictionary containing the data to be encrypted.
    :return: A dictionary containing the encrypted data.
    :raises InsecureKeyringuException: If no secure keyring backend is available
    """
    # Check if keyring backend is secure first
    is_keyring_secure()

    key = retrieve_key()
    cipher = Fernet(key)
    encrypted_data_dict = {}

    for key_name, value in data_dict.items():
        encrypted_data_dict[key_name] = cipher.encrypt(value.encode()).decode()

    keyring.set_password("resistine", "encrypted_data", json.dumps(encrypted_data_dict))
    logger.info("Encrypted data securely stored in system keyring.")

    return encrypted_data_dict


def decrypt_data():
    """
    Decrypt the stored encrypted data from the system keyring.

    :return: A dictionary containing the decrypted data.
    :raises ValueError: If no encrypted data is found in keyring.
    :raises InsecureKeyringuException: If no secure keyring backend is available
    """
    # Check if keyring backend is secure first
    is_keyring_secure()

    key = retrieve_key()
    cipher = Fernet(key)

    encrypted_data = keyring.get_password("resistine", "encrypted_data")
    if encrypted_data is None:
        raise ValueError(get_text("encryption.no_data_found"))

    encrypted_data_dict = json.loads(encrypted_data)
    decrypted_data_dict = {}

    for key_name, value in encrypted_data_dict.items():
        decrypted_data_dict[key_name] = cipher.decrypt(value.encode()).decode()

    return decrypted_data_dict
