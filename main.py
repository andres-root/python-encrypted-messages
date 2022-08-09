import os
from contextlib import contextmanager
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


@contextmanager
def create_key_file(path):
    try:
        private_key_file = open(f'{path}/private_key.pem', 'wt')
        yield
    except OSError:
        print('Error creating private key file.')
    try:
        public_key_file = open(f'{path}/public_key.pem', 'wt')
    except OSError:
        print('Error creating public key file.')


def generate_key():
    key = RSA.generate(4096)
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')

    # Save private key to file
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    # Save public key to file
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)


def encrypt(data_file, public_key_file):
    """
    Use EAX mode to allow detection of unauthorized modifications
    """
    # Read data from file
    with open(data_file, 'rb') as f:
        data = f.read()

    # Convert data to butes
    data = bytes(data)

    # Red public key from file
    with open(public_key_file, 'rb') as f:
        public_key = f.read()

    # Create public key object
    key = RSA.import_key(public_key)
    session_key = os.urandom(16)

    # Encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(key)
    # import ipdb; ipdb.set_trace()
    encrypted_session_key = cipher.encrypt(session_key)

    # Encrypt the data with the session key
    cipher = AES.new(session_key, AES.MODE_EAX)
    encrypted_data, tag = cipher.encrypt_and_digest(data)

    # save the encrypted data to file
    [filename, file_extension] = data_file.split('.')

    encrupted_file = f'{filename}_encrypted.{file_extension}'

    with open(encrupted_file, 'wb') as f:
        [f.write(x) for x in (encrypted_session_key, cipher.nonce, tag, encrypted_data)]

    print('Encrypted file saved to disk.')


def decrypt(data_file, private_key_file):
    """
    Use EAX mode to allow detection of unauthorized modifications
    """

    # read private key from file
    with open(private_key_file, 'rb') as f:
        private_key = f.read()
        # create private key object
        key = RSA.import_key(private_key)

    # read data from file
    with open(data_file, 'rb') as f:
        # read the session key
        encrypted_session_key, nonce, tag, encrypted_data = [f.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    session_key = cipher.decrypt(encrypted_session_key)

    # decrypt the data with the session key
    cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(encrypted_data, tag)

    # save the decrypted data to file
    [filename, file_extension] = data_file.split('.')
    decrypted_file = f'{filename}_decrypted.{file_extension}'
    with open(decrypted_file, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to disk.')


if __name__ == '__main__':
    BASE_DIR = Path(__file__).resolve().parent
    data_file = os.path.join(BASE_DIR, 'test.txt')
    encrypted_data_file = os.path.join(BASE_DIR, 'test_encrypted.txt')
    private_key_file = os.path.join(BASE_DIR, 'private_key.pem')
    public_key_file = os.path.join(BASE_DIR, 'public_key.pem')
    generate_key()
    encrypt(data_file, public_key_file)
    decrypt(encrypted_data_file, private_key_file)
