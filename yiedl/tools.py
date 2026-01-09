"""Collection of various tools and helper functions"""

import datetime
import os
import logging
from dataclasses import dataclass
import shutil
import time
from decimal import Decimal
from typing import Callable

import requests
import base58
import web3

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from eth_account.account import LocalAccount
from web3.types import TxReceipt
from yiedl import settings

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))

@dataclass
class CompetitionParams:
    """competitions settings"""
    address: str
    encrypted_directory: str


UPDOWN_COMP = CompetitionParams(
    settings.UPDOWN_ADDRESS,
    os.path.join(ROOT_DIR, settings.UPDOWN_ENCRYPTED_SUBMISSIONS))
NEUTRAL_COMP = CompetitionParams(
    settings.NEUTRAL_ADDRESS,
    os.path.join(ROOT_DIR, settings.NEUTRAL_ENCRYPTED_SUBMISSIONS))


@dataclass
class GasPriceMode:
    """gas price settings"""
    safe_low = 'safeLow'
    standard = 'standard'
    fast = 'fast'


def cid_to_hash(cid: str) -> str:
    """create hash from CID"""
    res = base58.b58decode(cid).hex()
    return res[4:]


def decimal_to_uint(decimal_value: Decimal | float | int, decimal_places=6) -> int:
    """convert decimal to unsigned int"""
    return int(Decimal(f'{decimal_value}e{decimal_places}'))


def decrypt_file(file_name: str, decrypt_key_file: str, decrypted_file_name=None) -> str:
    """decrypt a file using the provided key file"""
    with open(decrypt_key_file, 'rb') as key_f:
        decrypted_key = key_f.read()
    with open(file_name, 'rb') as enc_f:
        key = enc_f.read()
    nonce = key[:16]
    ciphertext = key[16:-16]
    tag = key[-16:]
    cipher = AES.new(decrypted_key, AES.MODE_GCM, nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    if decrypted_file_name is None:
        decrypted_file_name = file_name.split('.')[0] + '_decrypted.csv'
    with open(decrypted_file_name, 'wb') as dec_f:
        dec_f.write(decrypted_data)
    logger.info('Decrypted predictions file saved to %s.', decrypted_file_name)
    return decrypted_file_name


def encrypt_csv(file_path: str,
                submitter_address: str,
                encrypted_directory: str,
                public_key: RSA.RsaKey) -> tuple[str, bytes]:
    """encrypt a csv file"""
    symmetric_key = get_random_bytes(16)

    new_submission_dir = os.path.join(
        encrypted_directory, datetime.datetime.now().strftime('%Y-%m-%d_%Hh%Mm%Ss'))
    os.makedirs(new_submission_dir, exist_ok=False)

    if file_path.split('.')[-1] != 'csv':
        assert False, 'Please input a .csv file.'

    # Encrypt and save predictions file.
    cipher = AES.new(symmetric_key, AES.MODE_GCM)
    with open(file_path, 'rb') as f:
        ciphertext, tag = cipher.encrypt_and_digest(f.read())
    with open(os.path.join(new_submission_dir, "encrypted_predictions.bin"), 'wb') as fh:
        for x in (cipher.nonce, ciphertext, tag):
            fh.write(x)

    # Encrypt and save originator file.
    cipher = AES.new(symmetric_key, AES.MODE_GCM)
    submitter_address = web3.Web3.to_checksum_address(submitter_address)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(submitter_address, 'utf-8'))
    with open(os.path.join(new_submission_dir, "originator.bin"), 'wb') as file_handler:
        for x in (cipher.nonce, ciphertext, tag):
            file_handler.write(x)

    # Encrypt and save symmetric key using Competition public key for this challenge.
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_symmetric_key = cipher.encrypt(symmetric_key)
    with open(os.path.join(new_submission_dir, 'encrypted_symmetric_key.pem'), 'wb') as fh:
        fh.write(encrypted_symmetric_key)
    return new_submission_dir, symmetric_key


def get_avg_gas_price_in_gwei(mode=GasPriceMode.fast, retry_seconds: int = 3,
                              num_retries: int = 10) -> int:
    """fetch average gas price"""
    for tries in range(num_retries):
        try:
            result = requests.get(settings.GAS_PRICE_URL, timeout=settings.REQUESTS_TIMEOUT).json()
            avg_gas_price_in_gwei = result[mode]["maxFee"]
            base_gas_price_in_gwei = get_base_gas_price_in_gwei()
            return max(avg_gas_price_in_gwei, base_gas_price_in_gwei * settings.BASE_GAS_MULTIPLIER)
        except Exception as e1:
            if tries == num_retries - 1:
                try:
                    error_msg = f'Gas station response: {result}\nError: {e1}'
                except Exception as e2:
                    error_msg = f'Unspecified error: {e2}'
                logger.warning(f'Unable to compute gas price normally.\n{error_msg}\nTrying chain base fee..')
            time.sleep(retry_seconds)

    # if all retries fail, we first base our estimate on the chain's base fee
    try:
        base_gas_price_in_gwei = get_base_gas_price_in_gwei()
        return base_gas_price_in_gwei * settings.BASE_GAS_MULTIPLIER
    except Exception as e_chain:
        error_msg = f'Could not fetch base gas price from chain: {e_chain}\n'
        error_msg += 'Trying polygon gas station..'
        logger.warning(error_msg)

    # next we try to base our estimate on polygon gas station's values
    # we include a multiplier to try to mitigate cases where the base gas is spiking
    # but polygon gas station is lagging behind
    try:
        result = requests.get(settings.GAS_PRICE_URL, timeout=settings.REQUESTS_TIMEOUT).json()
        avg_gas_price_in_gwei = result[mode]["maxFee"]
        return avg_gas_price_in_gwei * settings.BASE_GAS_MULTIPLIER
    except Exception as e_gas_station:
        error_msg = f'Could not fetch gas price from polygon gas station: {e_gas_station}\n'
        error_msg += f'Falling back to hardcoded value: {settings.FALLBACK_GAS_PRICE_IN_GWEI} gwei'
        logger.warning(error_msg)

    # as a last resort, we return a hardcoded fallback value
    return settings.FALLBACK_GAS_PRICE_IN_GWEI


def get_base_gas_price_in_gwei() -> int:
    """fetch gas price"""
    base_gas_wei_hex = network_read(['pending', False], 'eth_getBlockByNumber')['baseFeePerGas']
    base_gas_wei = int(base_gas_wei_hex, 16)
    base_gas_gwei = decimal_to_uint(base_gas_wei, -9)
    return base_gas_gwei


def hash_to_cid(hash_obj: bytes | bytearray | str) -> str:
    """convert hash back to CID"""
    if isinstance(hash_obj, (bytes, bytearray)):
        hash_obj = hash_obj.hex()
    hash_obj = '1220' + str(hash_obj)
    hash_obj = int(hash_obj, 16)
    return base58.b58encode_int(hash_obj).decode('utf-8')


def network_read(params: list, method="eth_call", retry_seconds=3, num_retries=10) -> dict:
    """fetch result from RPC gateway"""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json"}
    for _ in range(num_retries):
        r = requests.post(settings.RPC_GATEWAY, headers=headers,
                          json=payload, timeout=settings.REQUESTS_TIMEOUT)
        if r.ok:
            keys = r.json().keys()
            if "result" in keys:
                return r.json()["result"]
            if "error" in keys:
                assert False, r.json()["error"]["message"]
            else:
                assert False, "Unspecified network error."
        else:
            time.sleep(retry_seconds)
    assert False, "network read exceeded max retries. Please try again later."


def pin_file_to_ipfs(filename: str, jwt: str, cid_version=0,
                     retry_seconds=3, num_retries=10) -> str | None:
    """try pinning a file to IPFS"""
    url = f"{settings.IPFS_API_URL}/pinning/pinFileToIPFS"
    headers = {"Authorization": "Bearer " + jwt}
    for tries in range(num_retries):
        try:
            with open(filename, 'rb') as f:
                files = {"file": f}
                params = {"cidVersion": cid_version}
                response = requests.post(url,
                                         headers=headers,
                                         files=files,
                                         params=params,
                                         timeout=settings.REQUESTS_TIMEOUT
                                         )
                response_json = response.json()
                logger.info(
                    'Pinned payload with size %s bytes to %s at %s.',
                    response_json['PinSize'],
                    response_json['IpfsHash'],
                    response_json['Timestamp']
                )
                return response_json['IpfsHash']
        except Exception:
            if tries == num_retries - 1:
                msg = ("File could not be uploaded and pinned to IPFS. Please try again later "
                       f"or contact {settings.SUPPORT_EMAIL} for support.")
                assert False, msg
            time.sleep(retry_seconds)
    return None


def retrieve_file(cid, destination=None, retry_seconds=3, num_retries=10):
    """retrieve file from IPFS gateway"""
    content = retrieve_content(cid, retry_seconds, num_retries)
    with open(destination, 'wb') as f:
        f.write(content)
    return destination


def retrieve_content(cid, retry_seconds=3, num_retries=10):
    """retrive file from IPFS gateway"""
    for tries in range(num_retries):
        try:
            url = f"{settings.IPFS_GATEWAY}/{settings.IPFS_DEFAULT}"
            requests.get(url, timeout=settings.REQUESTS_TIMEOUT)
            r = requests.get(f"{settings.IPFS_GATEWAY}/{cid}", timeout=settings.REQUESTS_TIMEOUT)
            return r.content
        except Exception as e:
            logger.warning(e)
            if tries == num_retries - 1:
                msg = ('File could not be retrieved. Please try again later'
                       f'or contact {settings.SUPPORT_EMAIL} for support.')
                assert False, msg
            time.sleep(retry_seconds)
    return None


def send_transaction(w3: web3.Web3, controlling_account: LocalAccount, method: Callable,
                     args: list, gas_price_in_wei: int) -> TxReceipt:
    """build, sign and send a transaction"""
    assert controlling_account is not None, 'Private key required to send blockchain transactions.'
    tx_data = method(*args).build_transaction({
        'from': controlling_account.address,
        'maxFeePerGas': hex(gas_price_in_wei),
        'nonce': w3.eth.get_transaction_count(controlling_account.address)
    })
    signed_tx = w3.eth.account.sign_transaction(tx_data, controlling_account._private_key)
    tx_id = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    logger.info('Sending transaction %s', tx_id.hex())
    tx_receipt = w3.eth.wait_for_transaction_receipt(
        tx_id, settings.W3_TIMEOUT, settings.W3_INTERVAL)
    logger.info('Transaction sent. Tx ID: %s', tx_id.hex())
    return tx_receipt


def set_gas_price_in_gwei(gas_price_in_gwei=None) -> int:
    """compute gas price"""
    if gas_price_in_gwei is None:
        gas_price_in_gwei = get_avg_gas_price_in_gwei()
    elif isinstance(gas_price_in_gwei, str):
        gas_price_in_gwei = get_avg_gas_price_in_gwei(gas_price_in_gwei)
    logger.info('Setting gas price to %.3f gwei.', gas_price_in_gwei)
    gas_price_in_wei = decimal_to_uint(gas_price_in_gwei, 9)
    return gas_price_in_wei


def uint_to_decimal(uint_value: int, decimal_places=6) -> Decimal:
    """convert unsigned int to decimal"""
    if uint_value == 0:
        return Decimal(0)
    return Decimal(f'{uint_value}e-{decimal_places}')


def unzip_dir(zipped_file: str, extract_dest: str) -> str:
    """extract .zip archive to directory"""
    shutil.unpack_archive(zipped_file, extract_dest)
    logger.info('Data unzipped to %s.', extract_dest)
    return extract_dest


def zip_file(file_path: str, dest=None) -> str:
    """zip file to destination"""
    if dest is None:
        dest = file_path
    return shutil.make_archive(dest, 'zip', file_path)
