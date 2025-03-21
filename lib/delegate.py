"""client to manage delegate operations for the Yiedl competitions"""

import json
import os
import logging
from decimal import Decimal

import web3

from lib.core_tools import contracts
from lib.core_tools import tools

logger = logging.getLogger(__name__)


class Delegate:
    """
    Delegate client for interacting with the Yiedl competitions.
    """
    def __init__(self, jwt: str, address: str,
                 comp_params: tools.CompetitionParams,
                 private_key=None, *, url=tools.CFG['RPC_GATEWAY'],
                 verbose: bool = True):
        """
        @param verbose: (optional) Defaults to True. Prints method details.
        """
        self._w3 = web3.Web3(
            web3.Web3.HTTPProvider(
                url,
                request_kwargs={'timeout': tools.CFG['W3_TIMEOUT']}
            )
        )
        # disabling strict byte checking...
        self._w3.strict_bytes_type_checking = False

        self._jwt = jwt
        self._address = self._w3.to_checksum_address(address)
        self._comp_params = comp_params

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
        path = os.path.join(tools.CURRENT_DIR, tools.CFG['JSON_DIRECTORY'], 'Token.json')
        with open(path, "r") as f:
            token_json = json.load(f)
        self._token = contracts.Token(
            token_json, self._w3, tools.TOKEN_ADDRESS, self._controlling_account)

        # Load Competition interface.
        path = os.path.join(tools.CURRENT_DIR, tools.CFG['JSON_DIRECTORY'], 'Competition.json')
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
        @returns: Amount of MATIC (POL) in Submitter's wallet.
        """
        return tools.uint_to_decimal(self._w3.eth.get_balance(self._address), decimal_places=18)

    def get_pol_balance(self) -> Decimal:
        """
        Synonym for get_matic_balance.
        MATIC has been renamed to POL.
        @returns: Amount of MATIC (POL) in Submitter's wallet.
        """
        return self.get_matic_balance()

    def get_stake(self, submitter: str) -> Decimal:
        """
        @params: submitter: Address of submitter to return stake of.
        @returns: Amount of YIEDL staked by Submitter in the Competition.
        """
        return tools.uint_to_decimal(self._competition.getStake(submitter))

    def get_stake_threshold(self) -> Decimal:
        """
        @returns: Minimum YIEDL required for staking.
        """
        return tools.uint_to_decimal(self._competition.getStakeThreshold())

    def get_submission_cid(self, challenge_number: int, submitter: str) -> str or None:
        """
        @params: challenge_number: Challenge to return Submitter's submission cid of.
        @params: submitter: Address of submitter to return submission cid of.
        @returns: IPFS Content Identifier (CID) of Submitter's existing submission.
        Returns None if no submission has been made.
        """
        cid = tools.hash_to_cid(self._competition.getSubmission(challenge_number, submitter))
        if cid == tools.CFG['NULL_IPFS_CID']:
            return None
        return cid

    def get_delegate(self, submitter: str) -> str:
        """
        @params: submitter: Address of submitter to return delegate of.
        @returns: The address of the delegate for the submitter.
        """
        return self._competition.getDelegate(submitter)

    def get_invited(self, submitter: str) -> str:
        """
        @params: submitter: Address of submitter to return invited delegate of.
        @returns: The address that the submitter has invited to be their delegate.
        """
        return self._competition.getInvited(submitter)

    def _manage_allowance(self, amount: Decimal | float | int,
                          submitter: str, auto_approve=True,
                          gas_price_in_gwei=None) -> Decimal:
        """
        Manages the allowance for the competition contract to spend YIEDL on submitter's behalf.
        @param amount: Amount to approve.
        @param submitter: Address of submitter to manage allowance for.
        @param auto_approve: (optional) Defaults to True.
        If True, automatically approves the competition contract to
        spend YIEDL on submitter's behalf where required.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: The difference between the current allowance and the desired amount.
        """
        current_stake_uint = tools.decimal_to_uint(self.get_stake(submitter))
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

    def set_stake(self, amount: Decimal | float | int,
                  submitter: str, auto_approve=True,
                  gas_price_in_gwei=None) -> bool:
        """
        Sets the stake amount.
        @param amount: Amount to set stake to.
        @param submitter: Address of submitter to set stake for.
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
        logger.info('Setting stake for %s to %.6f YIEDL.', submitter, amount)

        self._manage_allowance(amount, submitter, auto_approve, gas_price_in_gwei)
        self._competition.setStakeForSubmitter(uint_amount, submitter, gas_price_in_wei)
        return True

    def withdraw_all_stake(self, submitter: str, gas_price_in_gwei=None) -> bool:
        """
        Withdraws all stake. Synonym for `set_stake` with amount 0.
        @param submitter: Address of submitter whose stake is to be withdrawn.
        @param gas_price_in_gwei: (optional) Defaults to the "fast" gas price from
        polygonscan.com/gastracker. Otherwise an explicit gwei value can be stated here,
        or one of the three GasPriceMode modes.
        @return: True if completed successfully.
        """
        return self.set_stake(0, submitter, gas_price_in_gwei)

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

    def accept_invite_from(self, submitter: str):
        """
        Accepts an invite from a submitter.
        @param submitter: Address of submitter to accept invite from.
        """
        gas_price_in_wei = tools.set_gas_price_in_gwei()
        self._competition.acceptStakingDelegationFor(submitter, gas_price_in_wei)
