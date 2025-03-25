"""client to submit predictions to the Yiedl competitions"""

import json
import os
import logging
import shutil
from decimal import Decimal

import pandas as pd
import web3
from Crypto.PublicKey import RSA

from yiedl import contracts
from yiedl import tools
from yiedl import settings

logger = logging.getLogger(__name__)


class Submitter:
    """yiedl submission client"""
    def __init__(self, jwt: str, address: str,
                 competition: str = "neutral",
                 private_key=None, *, url=settings.RPC_GATEWAY,
                 verbose: bool = True):
        """
        @param verbose: (optional) Defaults to True. Prints method details.
        """
        self._w3 = web3.Web3(
            web3.Web3.HTTPProvider(
                url,
                request_kwargs={'timeout': settings.W3_TIMEOUT}
            )
        )
        # disabling strict byte checking...
        self._w3.strict_bytes_type_checking = False

        self._jwt = jwt
        self._address = self._w3.to_checksum_address(address)

        match competition.upper():
            case "NEUTRAL":
                self._comp_params = tools.NEUTRAL_COMP
            case "UPDOWN":
                self._comp_params = tools.UPDOWN_COMP
            case _: raise ValueError("unknown competition", competition)

        if verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

        if private_key is not None:
            self._controlling_account = self._w3.eth.account.from_key(private_key)

            # Sanity check on conrolling address.
            msg = f'Private key does not match address {self._address}.'
            assert self._controlling_account.address == self._address, msg
        else:
            self._controlling_account = None

        # Load Token interface.
        path = os.path.join(tools.CURRENT_DIR, settings.JSON_DIRECTORY, 'Token.json')
        with open(path, "r") as f:
            token_json = json.load(f)
        self._token = contracts.Token(
            token_json, self._w3, settings.TOKEN, self._controlling_account)

        # Load Competition interface.
        path = os.path.join(tools.CURRENT_DIR, settings.JSON_DIRECTORY, 'Competition.json')
        with open(path) as f:
            competition_json = json.load(f)
        self._competition = contracts.Competition(
            competition_json, self._w3, self._comp_params.address, self._controlling_account)

    @property
    def address(self):
        """
        @returns: Submitter's wallet address.
        """
        return self._address

    @property
    def w3(self):
        """
        @returns: Instantiated Web3 object in use by Submitter.
        """
        return self._w3

    def get_yiedl_balance(self) -> Decimal:
        """
        @returns: Amount of YIEDL in Submitter's wallet.
        """
        return tools.uint_to_decimal(self._token.balanceOf(self._address))

    def get_matic_balance(self) -> Decimal:
        """
        @returns: Amount of MATIC in Submitter's wallet.
        """
        return tools.uint_to_decimal(self._w3.eth.get_balance(self._address), decimal_places=18)

    def get_stake(self) -> Decimal:
        """
        @returns: Amount of YIEDL staked by Submitter in the Competition.
        """
        return tools.uint_to_decimal(self._competition.getStake(self._address))

    def get_stake_threshold(self) -> Decimal:
        """
        @returns: Minimum YIEDL required for staking.
        """
        return tools.uint_to_decimal(self._competition.getStakeThreshold())

    def get_submission_cid(self, challenge_number) -> str | None:
        """
        @params: challenge_number: Challenge to return Submitter's submission cid of.
        @returns: IPFS Content Identifier (CID) of Submitter's existing submission.
                  Returns None if no submission has been made.
        """
        cid = tools.hash_to_cid(self._competition.getSubmission(challenge_number, self._address))
        if cid == settings.NULL_IPFS_CID:
            return None
        return cid

    def get_dataset(self, destination_directory: str, challenge_number: int = None) -> str:
        """
        @param destination_directory: Folder path in which to save the dataset zip file.
        @param challenge_number: (optional) Challenge of which corresponding dataset should
            be retrieved. Defaults to the current challenge.
        @return: Path of the retrieved dataset.
        """
        if challenge_number is None:
            challenge_number = self._competition.getLatestChallengeNumber()
        dataset_hash = self._competition.getDatasetHash(challenge_number).hex()
        dataset_cid = tools.hash_to_cid(dataset_hash)
        if dataset_cid == settings.NULL_IPFS_CID:
            assert False, 'Dataset for this challenge does not exist.'
        os.makedirs(destination_directory, exist_ok=True)
        destination_file = os.path.join(destination_directory, 'dataset.zip')
        logger.info('Downloading dataset..')
        dataset_path = tools.retrieve_file(dataset_cid, destination_file)
        logger.info('Dataset saved to %s', dataset_path)
        return dataset_path

    def stake_and_submit(self, amount: Decimal | float | int, file_name: str,
                         gas_price_in_gwei=None) -> bool:
        """
        Submits a new prediction or updates an existing prediction along with a stake amount.
        @param amount: Amount to set stake to.
        @param file_name: Name of csv file in the 'updown_file_to_submit' or
            'neutral_file_to_submit' folder. Please include the .csv extension.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price
            from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """

        # Check that the current challenge is accepting submissions.
        challenge_number = self._competition.getLatestChallengeNumber()
        phase = self._competition.getPhase(challenge_number)
        assert phase == 1, f'Submissions currently not accepted for challenge {challenge_number}.'

        # Encrypt, zip and upload.
        logger.info('Encrypting file.')
        public_key_hash = self._competition.getKeyHash(challenge_number)
        public_key_content = tools.retrieve_content(tools.hash_to_cid(public_key_hash))
        public_key = RSA.import_key(public_key_content)
        submission_dir, symmetric_key = tools.encrypt_csv(file_name, self._address,
                                                    self._comp_params.submission_directory,
                                                    self._comp_params.encrypted_directory,
                                                    public_key)
        logger.info('Zipping encrypted file.')
        zipped_submission = tools.zip_file(submission_dir)
        logger.info('Uploading and recording on blockchain.')
        cid = tools.pin_file_to_ipfs(zipped_submission, self._jwt)
        self._token.stakeAndSubmit(
            self._competition.address,
            tools.decimal_to_uint(amount),
            tools.cid_to_hash(cid),
            tools.set_gas_price_in_gwei(gas_price_in_gwei))

        # Save symmetric key locally for verification.
        path = os.path.join(self._comp_params.encrypted_directory, f"{cid}_symmetric_key.bin")
        with open(path, 'wb') as f:
            f.write(symmetric_key)
        return True

    def withdraw(self, gas_price_in_gwei=None):
        """
        Removes submission and sets stake to 0.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price
            from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        # Check that the current challenge is accepting submissions.
        challenge_number = self._competition.getLatestChallengeNumber()
        phase = self._competition.getPhase(challenge_number)
        msg = f'Challenge {challenge_number} is currently locked from submission updates.'
        assert phase == 1, msg

        logger.info('Withdrawing submission and stake.')
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        self._token.stakeAndSubmit(
            self._competition.address, 0, (0).to_bytes(32, "big"), gas_price_in_wei)

    def download_and_check(self, original_submission_file_name: str, keep_temp_files=False) -> bool:
        """
        Downloads the submitted file associated with the submitter's wallet address from
        the blockchain and IPFS, then decrypts it using the local key and compares it with the
        original submission file.
        @param original_submission_file_name: Name of csv file in the 'updown_file_to_submit' or
            'neutral_file_to_submit' folder. Please include the .csv extension.
        @param keep_temp_files: (optional):
            Whether or not to retain the retrieved and decrypted files.
        @return: True if the retrieved submission file is identical to
            the local original submission file.
        """
        challenge_number = self._competition.getLatestChallengeNumber()
        cid = self.get_submission_cid(challenge_number)
        assert cid is not None, 'No submission found.'
        temp_zip = f'temp_{cid}.zip'
        unzipped = f'temp_{cid}'
        logger.info('Retrieving file.')
        tools.retrieve_file(cid, temp_zip)
        logger.info('File retrieved.')
        tools.unzip_dir(temp_zip, unzipped)
        logger.info('File unzipped.')
        symmetric_key_path = os.path.join(
            self._comp_params.encrypted_directory, f"{cid}_symmetric_key.bin")
        file_to_decrypt = os.path.join(unzipped, "encrypted_predictions.bin")
        decrypted_file_name = os.path.join(unzipped, f'{cid}.csv')
        tools.decrypt_file(file_to_decrypt, symmetric_key_path, decrypted_file_name)
        logger.info('File decrypted. Comparing files.')
        original = pd.read_csv(
            os.path.join(self._comp_params.submission_directory,
                original_submission_file_name))
        retrieved = pd.read_csv(decrypted_file_name)
        if not keep_temp_files:
            logger.info('Removing temp files.')
            shutil.rmtree(unzipped)
            os.remove(temp_zip)
            logger.info('Temp files removed.')
        return original.equals(retrieved)
