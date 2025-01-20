import datetime
import os
import shutil
import time
from decimal import Decimal
from typing import Any, Callable

import requests
import base58
import yaml

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
CFG_DIR = os.path.abspath('{}//..//..//cfg_files'.format(CURRENT_DIR))
with open("{}//cfg.yml".format(CFG_DIR), "r") as config_file:
    CFG = yaml.safe_load(config_file)

TOKEN_ADDRESS = CFG['LIVE']['TOKEN']

UPDOWN_ADDRESS = CFG['LIVE']['UPDOWN_ADDRESS']
UPDOWN_DIRECTORY = os.path.abspath('{}//..//..//{}'.format(CURRENT_DIR, CFG['UPDOWN_SUBMISSION_FOLDER_NAME']))
UPDOWN_ENCRYPTED_DIRECTORY = os.path.abspath('{}//..//..//{}'.format(CURRENT_DIR, CFG['UPDOWN_ENCRYPTED_SUBMISSIONS']))

NEUTRAL_ADDRESS = CFG['LIVE']['NEUTRAL_ADDRESS']
NEUTRAL_DIRECTORY = os.path.abspath('{}//..//..//{}'.format(CURRENT_DIR, CFG['NEUTRAL_SUBMISSION_FOLDER_NAME']))
NEUTRAL_ENCRYPTED_DIRECTORY = os.path.abspath('{}//..//..//{}'.format(CURRENT_DIR, CFG['NEUTRAL_ENCRYPTED_SUBMISSIONS']))


class CompetitionParams:
    def __init__(self, address, submission_directory, encrypted_directory):
        self.address = address
        self.submission_directory = submission_directory
        self.encrypted_directory = encrypted_directory


UPDOWN_COMP = CompetitionParams(UPDOWN_ADDRESS, UPDOWN_DIRECTORY, UPDOWN_ENCRYPTED_DIRECTORY)
NEUTRAL_COMP = CompetitionParams(NEUTRAL_ADDRESS, NEUTRAL_DIRECTORY, NEUTRAL_ENCRYPTED_DIRECTORY)

class GasPriceMode:
    safe_low = 'safeLow'
    standard = 'standard'
    fast = 'fast'


def cid_to_hash(cid: str) -> str:
    res = base58.b58decode(cid).hex()
    return res[4:]


def decimal_to_uint(decimal_value: Decimal | float | int, decimal_places=6) -> int:
    return int(Decimal('{}e{}'.format(decimal_value, decimal_places)))


def decrypt_file(file_name: str, decrypt_key_file: str, decrypted_file_name=None, verbose=False) -> str:
    with open(decrypt_key_file, 'rb') as key_f:
        decrypted_key = key_f.read()
    with open(file_name, 'rb') as enc_f:
        key = enc_f.read()
    nonce = key[:16]
    ciphertext = key[16:-16]
    tag = key[-16:]
    cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    if decrypted_file_name == None: decrypted_file_name = file_name.split('.')[0] + '_decrypted.csv'
    with open(decrypted_file_name, 'wb') as dec_f:
        dec_f.write(decrypted_data)
    if verbose:
        print('Decrypted predictions file saved to {}.'.format(decrypted_file_name))
    return decrypted_file_name


def encrypt_csv(file_name: str, submitter_address: str,
                submission_directory: str, encrypted_directory: str,
                public_key: RSA.RsaKey) -> tuple[str, bytes]:
    symmetric_key = get_random_bytes(16)


    new_submission_dir = '{}//{}'.format(encrypted_directory,
                                         datetime.datetime.now().strftime('%Y-%m-%d_%Hh%Mm%Ss'))
    os.makedirs(new_submission_dir, exist_ok=False)

    if file_name.split('.')[-1] != 'csv':
        assert False, 'Please input a .csv file.'

    # Encrypt and save predictions file.
    cipher = AES.new(symmetric_key, AES.MODE_GCM)
    with open('{}//{}'.format(submission_directory, file_name), 'rb') as f:
        ciphertext, tag = cipher.encrypt_and_digest(f.read())
    encrypted_predictions_path = '{}//{}.bin'.format(new_submission_dir, 'encrypted_predictions')
    with open(encrypted_predictions_path, 'wb') as encrypted_predictions_file:
        for x in (cipher.nonce, ciphertext, tag):
            encrypted_predictions_file.write(x)

    # Encrypt and save originator file.
    cipher = AES.new(symmetric_key, AES.MODE_GCM)
    submitter_address = web3.Web3.toChecksumAddress(submitter_address)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(submitter_address, 'utf-8'))
    encrypted_originator_path = '{}//{}.bin'.format(new_submission_dir, 'originator')
    with open(encrypted_originator_path, 'wb') as encrypted_originator_file:
        for x in (cipher.nonce, ciphertext, tag):
            encrypted_originator_file.write(x)

    # Encrypt and save symmetric key using Competition public key for this challenge.
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_symmetric_key = cipher.encrypt(symmetric_key)
    encrypted_symmetric_key_path = '{}//{}.pem'.format(new_submission_dir, 'encrypted_symmetric_key')
    with open(encrypted_symmetric_key_path, 'wb') as encrypted_symmetric_key_file:
        encrypted_symmetric_key_file.write(encrypted_symmetric_key)
    return new_submission_dir, symmetric_key


def get_avg_gas_price_in_gwei(mode=GasPriceMode.fast, retry_seconds=3, num_retries=10) -> int | None:
    for tries in range(num_retries):
        try:
            result = requests.get(CFG['GAS_PRICE_URL'], timeout=CFG['REQUESTS_TIMEOUT']).json()
            avg_gas_price_in_gwei = result[mode]["maxFee"]
            base_gas_price_in_gwei = get_base_gas_price_in_gwei()
            if avg_gas_price_in_gwei < (base_gas_price_in_gwei * 1.13):
                continue
            return avg_gas_price_in_gwei
        except Exception as e:
            if tries == num_retries - 1:
                try:
                    assert False, 'Response\n{}\n\nSystem Error\n{}'.format(result, e)
                except Exception as e:
                    assert False, 'Unspecified error.\n{}'.format(e)
            time.sleep(retry_seconds)


def get_base_gas_price_in_gwei() -> int:
    base_gas_wei_hex = network_read(['pending', False], 'eth_getBlockByNumber')['baseFeePerGas']
    base_gas_wei = int(base_gas_wei_hex, 16)
    base_gas_gwei = decimal_to_uint(base_gas_wei, -9)
    return base_gas_gwei


def hash_to_cid(hash_obj: bytes | bytearray | str) -> str:
    if isinstance(hash_obj, (bytes, bytearray)): hash_obj = hash_obj.hex()
    hash_obj = '1220' + str(hash_obj)
    hash_obj = int(hash_obj, 16)
    return base58.b58encode_int(hash_obj).decode('utf-8')


def network_read(params: [Any], method="eth_call", retry_seconds=3, num_retries=10) -> str:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json"}
    for retries in range(num_retries):
        r = requests.post(CFG['RPC_GATEWAY'], headers=headers, json=payload, timeout=CFG['REQUESTS_TIMEOUT'])
        if r.ok:
            keys = r.json().keys()
            if "result" in keys:
                return r.json()["result"]
            elif "error" in keys:
                assert False, r.json()["error"]["message"]
            else:
                assert False, "Unspecified network error."
        else:
            time.sleep(retry_seconds)
    assert False, "network read exceeded max retries. Please try again later."


def pin_file_to_ipfs(filename: str, jwt: str, cid_version=0, verbose=False, retry_seconds=3, num_retries=10) -> str | None:
    url = '{}/{}'.format(CFG['IPFS_API_URL'], 'pinning/pinFileToIPFS')
    headers = {"Authorization": "Bearer " + jwt}
    for tries in range(num_retries):
        try:
            with open(filename, 'rb') as f:
                files = {"file": f}
                params = {"cidVersion": cid_version}
                response = requests.post(url, headers=headers, files=files, params=params)
                if verbose:
                    print('Pinned payload with size {} bytes to {} at {}.'.format(
                        response['PinSize'], response['IpfsHash'], response['Timestamp']))
                return response.json()['IpfsHash']
        except Exception as e:
            if tries == num_retries - 1:
                assert False, 'File could not be uploaded and pinned to IPFS. Please try again later or contact {} for support.'.format(
                    CFG['SUPPORT_EMAIL'])
            time.sleep(retry_seconds)


def retrieve_file(cid, destination=None, retry_seconds=3, num_retries=10):
    content = retrieve_content(cid, retry_seconds, num_retries)
    with open(destination, 'wb') as f:
        f.write(content)
    return destination


def retrieve_content(cid, retry_seconds=3, num_retries=10):
    for tries in range(num_retries):
        try:
            requests.get('{}/{}'.format(CFG['IPFS_GATEWAY'], CFG['IPFS_DEFAULT']), timeout=CFG['REQUESTS_TIMEOUT'])
            r = requests.get('{}/{}'.format(CFG['IPFS_GATEWAY'], cid), timeout=CFG['REQUESTS_TIMEOUT'])
            return r.content
        except Exception as e:
            print(e)
            if tries == num_retries - 1:
                assert False, 'File could not be retrieved. Please try again later or contact {} for support.'.format(
                    CFG['SUPPORT_EMAIL'])
            time.sleep(retry_seconds)


def send_transaction(w3: web3.Web3, controlling_account, method: Callable, args: list, gas_price_in_wei: int, verbose=True) -> web3.types.TxReceipt:
    assert controlling_account is not None, 'Private key required to send blockchain transactions.'
    tx_data = method(*args).buildTransaction({
        'from': controlling_account.address,
        'maxFeePerGas': hex(gas_price_in_wei),
        'nonce': w3.eth.getTransactionCount(controlling_account.address)
    })
    signed_tx = w3.eth.account.sign_transaction(tx_data, controlling_account.privateKey)
    tx_id = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    if verbose:
        print('Sending transaction {}'.format(tx_id.hex()))
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_id, CFG['W3_TIMEOUT'], CFG['W3_INTERVAL'])
    if verbose:
        print('Transaction sent. Tx ID: {}'.format(tx_id.hex()))
    return tx_receipt


def set_gas_price_in_gwei(gas_price_in_gwei=None, verbose=True) -> int:
    if gas_price_in_gwei is None:
        gas_price_in_gwei = get_avg_gas_price_in_gwei()
    elif type(gas_price_in_gwei) is str:
        gas_price_in_gwei = get_avg_gas_price_in_gwei(gas_price_in_gwei)
    if verbose:
        print('Setting gas price to {:.3f} gwei.'.format(gas_price_in_gwei))
    gas_price_in_wei = decimal_to_uint(gas_price_in_gwei, 9)
    return gas_price_in_wei


def uint_to_decimal(uint_value: int, decimal_places=6) -> Decimal:
    if uint_value == 0:
        return Decimal(0)
    return Decimal('{}e-{}'.format(uint_value, decimal_places))


def unzip_dir(zippedFile: str, extractDest: str, verbose=False) -> str:
    shutil.unpack_archive(zippedFile, extractDest)
    if verbose:
        print('Data unzipped to {}.'.format(extractDest))
    return extractDest


def zip_file(file_path: str, dest=None) -> str:
    if dest is None:
        dest = file_path
    return shutil.make_archive(dest, 'zip', file_path)
