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
            case _:
                raise ValueError("unknown competition", competition)

        if verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

        if private_key is not None:
            self._controlling_account = self._w3.eth.account.from_key(private_key)

            # Sanity check on controlling address.
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

    def get_yiedl_allowance_for_competition(self) -> Decimal:
        """
        @returns: Amount of YIEDL approved for the competition contract to
        spend on Submitter's behalf.
        """
        return tools.uint_to_decimal(
            self._token.allowance(self._address, self._comp_params.address)
        )

    def get_matic_balance(self) -> Decimal:
        """
        @returns: Amount of MATIC in Submitter's wallet.
        """
        return tools.uint_to_decimal(self._w3.eth.get_balance(self._address), decimal_places=18)

    def get_pol_balance(self) -> Decimal:
        """
        Synonym for get_matic_balance.
        MATIC has been renamed to POL.
        @returns: Amount of MATIC (POL) in Submitter's wallet.
        """
        return self.get_matic_balance()

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

    def get_delegate(self) -> str:
        """
        @returns: The address of the delegate for the submitter.
        """
        return self._competition.getDelegate(self._address)

    def get_invited(self) -> str:
        """
        @returns: The address that the submitter has invited to be their delegate.
        """
        return self._competition.getInvited(self._address)

    def _manage_allowance(self, amount: Decimal | float | int,
                          auto_approve=True, gas_price_in_gwei=None) -> Decimal:
        """
        Manages the allowance for the competition contract to spend YIEDL on submitter's behalf.
        @param amount: Amount to approve.
        @param auto_approve: (optional) Defaults to True.
        If True, automatically approves the competition contract to
        spend YIEDL on submitter's behalf where required.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: The difference between the current allowance and the desired amount.
        """
        current_stake_uint = tools.decimal_to_uint(self.get_stake())
        delta_uint = tools.decimal_to_uint(amount) - current_stake_uint
        delta = tools.uint_to_decimal(delta_uint)
        if delta > 0:
            current_allowance = self.get_yiedl_allowance_for_competition()
            if current_allowance < delta:
                if auto_approve:
                    self.approve_competition_with_amount(delta, gas_price_in_gwei)
                else:
                    assert False, 'Insufficient YIEDL allowance for competition contract.'
        return delta

    def _prepare_submission_file(self, file_path: str) -> str:
        """
        Prepares a submission file for encryption and submission.
        @param file_path: Path of the csv file to submit.
        Relative to the calling script/notebook or
        absolute path to the file.
        Please include the .csv extension.
        @return: CID of the prepared submission file.
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
        submission_dir, symmetric_key = tools.encrypt_csv(file_path, self._address,
                                                          self._comp_params.encrypted_directory,
                                                          public_key)
        logger.info('Zipping encrypted file.')
        zipped_submission = tools.zip_file(submission_dir)
        logger.info('Uploading file.')
        cid = tools.pin_file_to_ipfs(zipped_submission, self._jwt)
        logger.info('File uploaded.')

        # Save symmetric key locally for verification.
        path = os.path.join(self._comp_params.encrypted_directory, f"{cid}_symmetric_key.bin")
        with open(path, 'wb') as f:
            f.write(symmetric_key)
        return cid

    def submit(self, file_path: str, gas_price_in_gwei=None) -> bool:
        """
        Submits a new prediction or updates an existing prediction.
        Stake amount must already be set by calling `set_stake`.
        @param file_path: Path of the csv file to submit.
        Relative to the calling script/notebook or
        absolute path to the file.
        Please include the .csv extension.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price
        from polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        cid = self._prepare_submission_file(file_path)
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Submitting to blockchain.')
        self._competition.submit(tools.cid_to_hash(cid), gas_price_in_wei)
        return True

    def stake_and_submit(self, amount: Decimal | float | int, file_path: str,
                         auto_approve=True, gas_price_in_gwei=None) -> bool:
        """
        Submits a new prediction or updates an existing prediction along with a stake amount.
        @param amount: Amount to set stake to.
        @param file_path: Path of the csv file to submit.
        Relative to the calling script/notebook or
        absolute path to the file.
        Please include the .csv extension.
        @param auto_approve: (optional) Defaults to True.
        If True, automatically approves the competition contract to
        spend YIEDL on submitter's behalf where required.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price
            from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        cid = self._prepare_submission_file(file_path)
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Submitting to blockchain.')
        self._manage_allowance(amount, auto_approve, gas_price_in_gwei)
        self._competition.stakeAndSubmit(
            tools.decimal_to_uint(amount),
            tools.cid_to_hash(cid),
            gas_price_in_wei)
        return True

    def remove_submission(self, gas_price_in_gwei=None) -> bool:
        """
        Removes submission.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        # Check that the current challenge is accepting submissions.
        challenge_number = self._competition.getLatestChallengeNumber()
        phase = self._competition.getPhase(challenge_number)
        msg = f'Challenge {challenge_number} is currently locked from submission updates.'
        assert phase == 1, msg

        logger.info('Withdrawing submission.')
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        self._competition.submit((0).to_bytes(32, "big"), gas_price_in_wei)
        return True

    def set_stake(self, amount: Decimal | float | int,
                  auto_approve=True, gas_price_in_gwei=None) -> bool:
        """
        Sets the stake amount.
        @param amount: Amount to set stake to.
        @param auto_approve: (optional) Defaults to True.
        If True, automatically approves the competition contract to
        spend YIEDL on submitter's behalf where required.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        uint_amount = tools.decimal_to_uint(amount)
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Setting stake for %s to %.6f YIEDL.', self._address, amount)
        self._manage_allowance(amount, auto_approve, gas_price_in_gwei)
        self._competition.setStakeForSelf(uint_amount, gas_price_in_wei)
        return True

    def withdraw_all_stake(self, gas_price_in_gwei=None) -> bool:
        """
        Withdraws all stake. Synonym for `set_stake` with amount 0.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        return self.set_stake(0, False, gas_price_in_gwei)

    def withdraw(self, gas_price_in_gwei=None):
        """
        Removes submission and sets stake to 0.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price
            from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        self.remove_submission(gas_price_in_gwei)
        self.withdraw_all_stake(gas_price_in_gwei)
        return True

    def _delegate_staking(self, delegate_address: str, is_cancel: bool,
                          gas_price_in_gwei=None, bypass_check=False) -> bool:
        """
        Delegates staking to another address.
        @param delegate_address: Address to delegate staking to.
        @param is_cancel: Whether to cancel the delegation.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @param bypass_check: (optional) Defaults to False.
        If true, bypasses the assertion that stake
        must be 0 before delegating.
        @return: True if completed successfully.
        """
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        self._competition.delegateStaking(
            delegate_address, self._address, is_cancel,
            gas_price_in_wei, bypass_check=bypass_check)
        return True

    def invite_delegate(self, delegate_address: str,
                        gas_price_in_gwei=None, bypass_check=False) -> bool:
        """
        Invites another address to be the delegate.
        @param delegate_address: Address to invite as delegate.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @param bypass_check: (optional) Defaults to False.
        If true, bypasses the assertion that stake
        must be 0 before delegating.
        @return: True if completed successfully.
        """
        return self._delegate_staking(delegate_address, False, gas_price_in_gwei, bypass_check)

    def cancel_delegate_invitation(self, delegate_address: str, gas_price_in_gwei=None) -> bool:
        """
        Cancels an invitation to delegate.
        @param delegate_address: Address to cancel invitation to.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        return self._delegate_staking(delegate_address, True, gas_price_in_gwei, bypass_check=True)

    def approve_competition_with_amount(self, amount: Decimal | float | int,
                                        gas_price_in_gwei=None) -> bool:
        """
        Approves the competition contract to move a specified amount of YIEDL on submitter's behalf.
        @param amount: Amount to approve.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        uint_amount = tools.decimal_to_uint(amount)
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Approving competition to spend %s YIEDL.', amount)
        self._token.approve(self._comp_params.address, uint_amount, gas_price_in_wei)
        return True

    def approve_competition(self, gas_price_in_gwei=None) -> bool:
        """
        Approves the competition contract to move YIEDL on submitter's behalf.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        uint_amount = 2 ** 256 - 1
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Approving competition.')
        self._token.approve(self._comp_params.address, uint_amount, gas_price_in_wei)
        return True

    def withdraw_approval_for_competition(self, gas_price_in_gwei=None) -> bool:
        """
        Withdraws approval for the competition contract to move YIEDL on submitter's behalf.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        uint_amount = 0
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Withdrawing approval for competition.')
        self._token.approve(self._comp_params.address, uint_amount, gas_price_in_wei)
        return True

    def accept_invite_for_self(self, gas_price_in_gwei=None) -> bool:
        """
        Accepts an invite from a delegate to set the delegate back to the submitter.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        gas_price_in_wei = tools.set_gas_price_in_gwei(gas_price_in_gwei)
        logger.info('Accepting invite for self.')
        self._competition.acceptStakingDelegationFor(self._address, gas_price_in_wei)
        return True

    def download_and_check(self, original_submission_file_path: str, keep_temp_files=False) -> bool:
        """
        Downloads the submitted file associated with the submitter's wallet address from
        the blockchain and IPFS, then decrypts it using the local key and compares it with the
        original submission file.
        @param original_submission_file_path: Path of the original submission file.
            Relative to the calling script/notebook or
            absolute path to the file.
            Please include the .csv extension.
        @param keep_temp_files: (optional):
            Whether to retain the retrieved and decrypted files.
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
        original = pd.read_csv(original_submission_file_path)
        retrieved = pd.read_csv(decrypted_file_name)
        if not keep_temp_files:
            logger.info('Removing temp files.')
            shutil.rmtree(unzipped)
            os.remove(temp_zip)
            logger.info('Temp files removed.')
        return original.equals(retrieved)
