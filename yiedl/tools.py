"""Collection of various tools and helper functions"""

import datetime
import os
import logging
from dataclasses import dataclass
import shutil
import time
from decimal import Decimal
from typing import Callable
from tqdm import tqdm

import requests
import base58
import web3
import pandas as pd

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from eth_account.account import LocalAccount, Account
from web3.types import TxReceipt
from yiedl import settings

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))


@dataclass
class CompetitionIds:
    """competition IDs"""
    UPDOWN = "UPDOWN"
    NEUTRAL = "NEUTRAL"


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


def unzip_dir(zipped_file: str, extract_dest: str | None = None) -> str | None:
    """extract .zip archive to directory"""
    try:
        if extract_dest is None:
            extract_dest = os.path.splitext(zipped_file)[0]
        os.makedirs(extract_dest, exist_ok=True)
        shutil.unpack_archive(zipped_file, extract_dest)
        logger.info('Source file unzipped to %s.', extract_dest)
        return extract_dest
    except Exception as e:
        logger.warning('Failed to unzip file %s. Error: %s', zipped_file, e)
        return None


def zip_file(file_path: str, dest=None) -> str:
    """zip file to destination"""
    if dest is None:
        dest = file_path
    return shutil.make_archive(dest, 'zip', file_path)


def download_weekly_yiedl_dataset(
        local_filepath=None,
        show_progress=True) -> bool:
    """
    Downloads the latest dataset from the Yiedl API.
    :param local_filepath: (optional) Path to save the weekly dataset to.
    :param show_progress: (optional) If true, shows the percentage of the download progress.
    :return: True if download was successful, False otherwise.
    """
    if local_filepath is None:
        local_filepath = settings.WEEKLY_DATASET_FILENAME
    logger.info('Downloading weekly dataset from server..')
    url = f"{settings.BASE_URL}?type={settings.WEEKLY_DATASET_TYPE}"
    status = _download_and_unzip_from_server(url, local_filepath, show_progress)
    return status


def download_daily_yiedl_dataset(
        local_filepath=None,
        show_progress=True) -> bool:
    """
    Downloads the latest dataset from the Yiedl API.
    :param local_filepath: (optional) Path to save the daily dataset to.
    :param show_progress: (optional) If true, shows the percentage of the download progress.
    :return: True if download was successful, False otherwise.
    """
    if local_filepath is None:
        local_filepath = settings.DAILY_DATASET_FILENAME
    logger.info('Downloading daily dataset from server..')
    url = f"{settings.BASE_URL}?type={settings.DAILY_DATASET_TYPE}"
    status = _download_and_unzip_from_server(url, local_filepath, show_progress)
    return status


def download_latest_yiedl_dataset(
        local_filepath=None,
        show_progress=True) -> bool:
    """
    Downloads the latest dataset from the Yiedl API.
    :param local_filepath: (optional) Path to save the latest dataset to.
    :param show_progress: (optional) If true, shows the percentage of the download progress.
    :return: True if download was successful, False otherwise.
    """
    if local_filepath is None:
        local_filepath = settings.LATEST_DATASET_FILENAME
    logger.info('Downloading latest dataset from server..')
    url = f"{settings.BASE_URL}?type={settings.LATEST_DATASET_TYPE}"
    status = _download_and_unzip_from_server(url, local_filepath, show_progress)
    return status


def download_historical_yiedl_dataset(
        local_filepath=None,
        show_progress=True) -> bool:
    """
    Downloads the historical dataset from the Yiedl API.
    :param local_filepath: (optional) Path to save the historical dataset to.
    :param show_progress: (optional) If true, shows the percentage of the download progress.
    :return: True if download was successful, False otherwise.
    """
    if local_filepath is None:
        local_filepath = settings.HISTORICAL_DATASET_FILENAME
    logger.info('Downloading historical dataset from server..')
    url = f"{settings.BASE_URL}?type={settings.HISTORICAL_DATASET_TYPE}"
    status = _download_and_unzip_from_server(url, local_filepath, show_progress)
    return status


def _download_and_unzip_from_server(url: str, local_filepath: str, show_progress: bool) -> bool:
    sleep_delay = settings.SLEEP_DELAY_SECONDS
    retries = settings.RETRIES
    for attempt in range(retries):
        try:
            with requests.get(url, stream=True) as response:
                response.raise_for_status()
                total_size = int(response.headers.get("content-length", 0))  # 0 if unknown
                chunk_size = settings.CHUNK_SIZE

                with open(local_filepath, "wb") as file:
                    if show_progress:
                        # total=None lets tqdm handle unknown size nicely
                        with tqdm(
                                total=total_size or None,
                                unit="B",
                                unit_scale=True,
                                unit_divisor=1024,
                                desc="Download",
                                leave=True,
                        ) as pbar:
                            for chunk in response.iter_content(chunk_size=chunk_size):
                                if not chunk:
                                    continue
                                file.write(chunk)
                                pbar.update(len(chunk))
                    else:
                        for chunk in response.iter_content(chunk_size=chunk_size):
                            if not chunk:
                                continue
                            file.write(chunk)

            logger.info("Download completed. Unzipping the dataset...")
            dest_path = unzip_dir(local_filepath)
            logger.info(f"Dataset unzipped to {dest_path}.")
            return True
        except Exception:
            if attempt < retries - 1:
                logger.info(
                    f"Download from server failed (attempt {attempt + 1}/{retries}). "
                    f"Retrying in {sleep_delay} seconds...")
                time.sleep(sleep_delay)
            else:
                logger.warning("Download from server failed after multiple attempts.")
    return False


def is_latest_sunday(latest_date_str: str) -> bool:
    """
    Check if latest date is the latest sunday.
    :param latest_date_str: date string in format 'YYYY-MM-DD' eg. 2026-01-30
    :return: True if latest date is the latest sunday, False otherwise
    """
    latest_date = datetime.datetime.strptime(latest_date_str, '%Y-%m-%d').date()
    today = datetime.date.today()
    last_sunday = today - datetime.timedelta(days=today.weekday() + 1)
    return latest_date == last_sunday


def verify_weekly_dataset_is_latest(dataset_dir: str) -> bool:
    """
    Verify if the weekly dataset is the latest by checking that the last date in the validation CSV is
    the most recent Sunday.
    :param dataset_dir: Path to the dataset directory.
    :return: True if the dataset is the latest, False otherwise.
    """
    try:
        validation_csv_path = os.path.join(dataset_dir, settings.YIEDL_VALIDATION_FILE_PATH)
        last_line = _last_csv_record(validation_csv_path)
        if not last_line:
            logger.warning("Validation CSV is empty.")
            return False
        latest_date_str = last_line.split(",")[0]
        return is_latest_sunday(latest_date_str)
    except Exception as e:
        logger.warning(f"Failed to verify if dataset is latest: {e}")
        return False


def _last_csv_record(path: str, chunk_size: int = 8192) -> str:
    """Read the last non-empty line from a CSV file efficiently."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if end == 0:
            return ""

        # Skip trailing newlines at EOF
        pos = end
        while pos > 0:
            step = min(chunk_size, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step)
            i = len(buf) - 1
            while i >= 0 and buf[i] in (10, 13):
                end -= 1
                i -= 1
            if i >= 0:
                break
        if end <= 0:
            return ""

        # Find the previous '\n' before end
        start = 0
        pos = end
        while pos > 0:
            step = min(chunk_size, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step)
            j = buf.rfind(b"\n")
            if j != -1:
                start = pos + j + 1
                break

        f.seek(start)
        line_bytes = f.read(end - start).rstrip(b"\r")
        return line_bytes.decode("utf-8")


def stream_and_unzip_from_ipfs(
        cid: str,
        filepath: str,
        challenge: int,
        gateway=None,
        pinata_access_token=None,
        unlimited_search: bool = False,
        verbose: bool = False,
) -> str | None:
    """
    Stream a file from IPFS gateway and unzip it.
    :param cid: v0 CID of the file to download
    :param filepath: path to save the downloaded file
    :param challenge: challenge number
    :param gateway: IPFS gateway URL
    :param pinata_access_token: (optional) Pinata access token for private gateways
    :param unlimited_search: (optional) If true, will keep retrying until successful. Default is False.
    :param verbose:(optional) If true, will print verbose error messages. Default is False.
    :return: Path to the unzipped directory if successful, None otherwise.
    """
    # Resolve gateway base URL safely
    base = (gateway or settings.IPFS_GATEWAY).rstrip("/") + "/ipfs/"
    url = base + cid

    request_timeout = 300
    chunk_size = 1024 * 128  # larger chunks = fewer syscalls
    tries_per_gateway = 20
    max_retries = tries_per_gateway

    # Resume from existing partial file if present
    downloaded = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    mode = "ab" if downloaded > 0 else "wb"

    retries = 0

    logger.info(
        f"Retrieving weekly dataset for challenge {challenge}. "
        f"(Please do not unzip the file until the download is complete.)"
    )
    logger.info("Download times may take up to an hour, depending on network conditions.")

    while True:
        if not unlimited_search and retries >= max_retries:
            break

        try:
            headers = {}
            if downloaded > 0:
                headers["Range"] = f"bytes={downloaded}-"
            if pinata_access_token is not None:
                headers["x-pinata-gateway-token"] = pinata_access_token

            r = requests.get(url, timeout=request_timeout, stream=True, headers=headers)
            r.raise_for_status()

            if downloaded > 0 and r.status_code != 206:
                raise RuntimeError("Server did not honor Range request; "
                                   "refusing to append to avoid corruption.")

            actual_total_size = None
            cr = r.headers.get("Content-Range")
            if cr and "/" in cr:
                try:
                    actual_total_size = int(cr.split("/")[-1])
                except ValueError:
                    actual_total_size = None

            if actual_total_size is None:
                cl = r.headers.get("Content-Length")
                if cl is None:
                    raise RuntimeError("Missing Content-Length and Content-Range;"
                                       "cannot determine download size.")
                remaining = int(cl)
                actual_total_size = downloaded + remaining

            # If file already complete, skip download and unzip
            if downloaded >= actual_total_size:
                logger.info("File already fully downloaded. Unzipping...")
                unzipped_dir = unzip_dir(filepath)
                if unzipped_dir is None:
                    remove_file(filepath)
                    downloaded = 0
                    mode = "wb"
                    continue
                logger.info(f"Dataset saved and unzipped to {unzipped_dir}.")
                return unzipped_dir

            with open(filepath, mode) as f, tqdm(
                    total=actual_total_size,
                    initial=downloaded,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc="Download",
                    leave=True,
            ) as pbar:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    f.write(chunk)
                    n = len(chunk)
                    downloaded += n
                    pbar.update(n)

            # Verify completion
            if downloaded < actual_total_size:
                raise RuntimeError("Download halted before completion. Reconnecting..")
            logger.info("Download complete. Unzipping...")
            try:
                unzipped_dir = unzip_dir(filepath)
            except Exception as e:
                raise RuntimeError(f"Downloaded file, but unzip failed: {e}") from e

            logger.info(f"Dataset saved and unzipped to {unzipped_dir}.")
            return unzipped_dir

        except Exception as e:
            retries += 1
            print("\r", end="")
            if verbose:
                print(f"Error: {e}")
            else:
                print("Retrying download..", end="")

            if os.path.exists(filepath):
                downloaded = os.path.getsize(filepath)
                mode = "ab" if downloaded > 0 else "wb"
            else:
                downloaded = 0
                mode = "wb"

            continue

    logger.warning(f"Gateway {base} is unavailable. Please try again later.")
    return None


def remove_file(filepath: str) -> None:
    """Remove file if it exists. Raise if it exists but cannot be removed."""
    try:
        os.remove(filepath)
        logger.info(f"Removed file {filepath}.")
    except FileNotFoundError:
        return
    except Exception as e:
        raise RuntimeError(f"Failed to remove file {filepath}: {e}") from e


def get_account_address(private_key: str) -> str:
    """
    @param private_key: Private key of the account.
    @returns: Address of the account associated with the private key.
    """
    account = Account().from_key(private_key)
    return account.address


def save_df_to_csv(df: pd.DataFrame, filepath: str) -> str | None:
    """
    Save dataframe to CSV file. Create directories recursively if they do not exist.
    :param df: Pandas dataframe to save.
    :param filepath: Full filepath to save to.
    :return: Filepath if successful, None otherwise.
    """
    if not filepath.endswith('.csv'):
        filepath += '.csv'

    try:
        dirpath = os.path.dirname(filepath)
        os.makedirs(dirpath, exist_ok=True)
        df.to_csv(filepath, index=False)
        logger.info(f"Dataframe saved to {filepath}.")
        return filepath
    except Exception as e:
        logger.warning(f"Failed to save dataframe to {filepath}: {e}")
        return None
