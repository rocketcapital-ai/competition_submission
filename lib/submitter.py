from .core_tools.contracts import *


class Submitter:
    def __init__(self, jwt: str, address: str, comp_params: CompetitionParams, private_key=None, url=CFG['RPC_GATEWAY']):
        self._w3 = web3.Web3(
            web3.Web3.HTTPProvider(
                url,
                request_kwargs={'timeout': CFG['W3_TIMEOUT']}
            )
        )
        self._jwt = jwt
        self._address = self._w3.toChecksumAddress(address)
        self._private_key = private_key
        self._comp_params = comp_params
        if private_key is not None:
            self._controlling_account = self._w3.eth.account.from_key(self._private_key)

            # Sanity check on controlling address.
            assert self._controlling_account.address == self._address, 'Private key does not match address {}.'.format(
                self._address)
        else:
            self._controlling_account = None

        # Load Token interface.
        with open('{}//{}//Token.json'.format(CURRENT_DIR, CFG['JSON_DIRECTORY'])) as f:
            token_json = json.load(f)
        self._token = Token(token_json, self._w3, TOKEN_ADDRESS, self._controlling_account)

        # Load Competition interface.
        with open('{}//{}//Competition.json'.format(CURRENT_DIR, CFG['JSON_DIRECTORY'])) as f:
            competition_json = json.load(f)
        self._competition = Competition(competition_json, self._w3, self._comp_params.address, self._controlling_account)

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
        return uint_to_decimal(self._token.balanceOf(self._address))

    def get_matic_balance(self) -> Decimal:
        """
        @returns: Amount of MATIC in Submitter's wallet.
        """
        return uint_to_decimal(self._w3.eth.get_balance(self._address))

    def get_stake(self) -> Decimal:
        """
        @returns: Amount of YIEDL staked by Submitter in the Competition.
        """
        return uint_to_decimal(self._competition.getStake(self._address))

    def get_stake_threshold(self) -> Decimal:
        """
        @returns: Minimum YIEDL required for staking.
        """
        return uint_to_decimal(self._competition.getStakeThreshold())

    def get_submission_cid(self, challenge_number) -> str or None:
        """
        @params: challenge_number: Challenge to return Submitter's submission cid of.
        @returns: IPFS Content Identifier (CID) of Submitter's existing submission. Returns None if no submission has been made.
        """
        cid = hash_to_cid(self._competition.getSubmission(challenge_number, self._address))
        if cid == CFG['NULL_IPFS_CID']:
            return None
        return cid

    def get_dataset(self, destination_directory: str = None, challenge_number: int = None, verbose=True) -> str:
        """
        @param destination_directory: (optional) Folder path in which to save the dataset zip file.
        @param challenge_number: (optional) Challenge of which corresponding dataset should be retrieved. Defaults to the current challenge.
        @param verbose: (optional) Defaults to True. Prints transaction details.
        @return: Path of the retrieved dataset.
        """
        if challenge_number is None:
            challenge_number = self._competition.getLatestChallengeNumber()
        dataset_hash = self._competition.getDatasetHash(challenge_number).hex()
        dataset_cid = hash_to_cid(dataset_hash)
        if dataset_cid == CFG['NULL_IPFS_CID']:
            assert False, 'Dataset for this challenge does not exist.'
        if destination_directory is None:
            destination_directory = '{}//..//{}//challenge_{}'.format(CURRENT_DIR, CFG['DATASET_DIRECTORY'], challenge_number)
        os.makedirs(destination_directory, exist_ok=True)
        destination_file = '{}//dataset.zip'.format(destination_directory)
        if verbose:
            print('Downloading dataset..')
        dataset_path = retrieve_file(dataset_cid, destination_file)
        if verbose:
            print('Dataset saved to {}'.format(dataset_path))
        return dataset_path

    def stake_and_submit(self, amount: Decimal or float or int, file_name: str, gas_price_in_gwei=None, verbose=True) -> bool:
        """
        Submits a new prediction or updates an existing prediction along with a stake amount.
        @param amount: Amount to set stake to.
        @param file_name: Name of csv file in the 'updown_file_to_submit' or 'neutral_file_to_submit' folder. Please include the .csv extension.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @param verbose: (optional) Defaults to True. Prints transaction details.
        @return: True if completed successfully.
        """

        # Check that the current challenge is accepting submissions.
        challenge_number = self._competition.getLatestChallengeNumber()
        phase = self._competition.getPhase(challenge_number)
        assert phase == 1, 'Submissions are not currently accepted for challenge {}.'.format(challenge_number)

        # Encrypt, zip and upload.
        if verbose:
            print('Encrypting file.')
        public_key_hash = self._competition.getKeyHash(challenge_number)
        public_key_content = retrieve_content(hash_to_cid(public_key_hash))
        public_key = RSA.import_key(public_key_content)
        submission_dir, symmetric_key = encrypt_csv(file_name, self._address,
                                                    self._comp_params.submission_directory,
                                                    self._comp_params.encrypted_directory,
                                                    public_key)
        if verbose:
            print('Zipping encrypted file.')
        zipped_submission = zip_file(submission_dir)
        if verbose:
            print('Uploading and recording on blockchain.')
        cid = pin_file_to_ipfs(zipped_submission, self._jwt)
        gas_price_in_wei = set_gas_price_in_gwei(gas_price_in_gwei)
        self._token.stakeAndSubmit(self._competition.address, decimal_to_uint(amount), cid_to_hash(cid), gas_price_in_wei)

        # Save symmetric key locally for verification.
        with open('{}//{}.bin'.format(self._comp_params.encrypted_directory, '{}_symmetric_key'.format(cid)), 'wb') as f:
            f.write(symmetric_key)
        return True

    def withdraw(self, gas_price_in_gwei=None, verbose=True):
        """
        Removes submission and sets stake to 0.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from polygonscan.com/gastracker.
        Otherwise an explicit gwei value can be stated here, or one of the three GasPriceMode modes.
        @param verbose: (optional) Defaults to True. Prints transaction details.
        @return: True if completed successfully.
        """
        # Check that the current challenge is accepting submissions.
        challenge_number = self._competition.getLatestChallengeNumber()
        phase = self._competition.getPhase(challenge_number)
        assert phase == 1, 'Challenge {} is currently locked from submission updates.'.format(challenge_number)

        if verbose:
            print('Withdrawing submission and stake.')
        gas_price_in_wei = set_gas_price_in_gwei(gas_price_in_gwei)
        self._token.stakeAndSubmit(self._competition.address, 0, (0).to_bytes(32, "big"), gas_price_in_wei)

    def download_and_check(self, original_submission_file_name: str, keep_temp_files=False, verbose=True) -> bool:
        """
        Downloads the submitted file associated with the submitter's wallet address from the blockchain and IPFS, then
        decrypts it using the local key and compares it with the original submission file.
        @param original_submission_file_name: Name of csv file in the 'updown_file_to_submit' or 'neutral_file_to_submit' folder. Please include the .csv extension.
        @param keep_temp_files: (optional): Whether or not to retain the retrieved and decrypted files.
        @param verbose: (optional) Defaults to True. Prints method details.
        @return: True if the retrieved submission file is identical to the local original submission file.
        """
        challenge_number = self._competition.getLatestChallengeNumber()
        cid = self.get_submission_cid(challenge_number)
        assert cid is not None, 'No submission found.'
        temp_zip = 'temp_{}.zip'.format(cid)
        unzipped = 'temp_{}'.format(cid)
        if verbose:
            print('Retrieving file.')
        retrieve_file(cid, temp_zip)
        if verbose:
            print('File retrieved.')
        unzip_dir(temp_zip, unzipped)
        if verbose:
            print('File unzipped.')
        symmetric_key_path = '{}//{}_symmetric_key.bin'.format(self._comp_params.encrypted_directory, cid)
        file_to_decrypt = '{}//encrypted_predictions.bin'.format(unzipped)
        decrypted_file_name = '{}//{}.csv'.format(unzipped, cid)
        decrypt_file(file_to_decrypt, symmetric_key_path, decrypted_file_name)
        if verbose:
            print('File decrypted. Comparing files.')
        original = pd.read_csv('{}//{}'.format(self._comp_params.submission_directory, original_submission_file_name))
        retrieved = pd.read_csv(decrypted_file_name)
        if not keep_temp_files:
            if verbose:
                print('Removing temp files.')
            shutil.rmtree(unzipped)
            os.remove(temp_zip)
            if verbose:
                print('Temp files removed.')
        return original.equals(retrieved)
