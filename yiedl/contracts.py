# pylint:disable=invalid-name, missing-function-docstring
"""ABI connectors"""

import web3
from web3 import types
from eth_account.account import LocalAccount
from yiedl import tools


class Competition:
    """competition ABI connector"""
    def __init__(self, json_interface: dict, w3: web3.Web3,
                 address: types.ChecksumAddress, controlling_account: LocalAccount | None = None):
        abi = json_interface['abi']
        contract = w3.eth.contract(abi=abi)
        self._w3 = w3
        self._contract = contract(address=address)
        self._controlling_account = controlling_account
        self._address = self._contract.address

    @property
    def address(self) -> types.ChecksumAddress:
        return self._address

    def getDatasetHash(self, challenge_number: int) -> str | bytes:
        return self._contract.functions.getDatasetHash(challenge_number).call()

    def getDeadlines(self, challenge_number: int, index: int) -> int:
        return self._contract.functions.getDeadlines(challenge_number, index).call()

    def getKeyHash(self, challenge_number: int) -> str:
        return self._contract.functions.getKeyHash(challenge_number).call()

    def getLatestChallengeNumber(self) -> int:
        return self._contract.functions.getLatestChallengeNumber().call()

    def getPhase(self, challenge_number: int) -> int:
        return self._contract.functions.getPhase(challenge_number).call()

    def getStake(self, participant: str) -> int:
        return self._contract.functions.getStake(participant).call()

    def getStakeThreshold(self) -> int:
        return self._contract.functions.getStakeThreshold().call()

    def getSubmission(self, challenge_number: int, participant: str) -> str:
        return self._contract.functions.getSubmission(challenge_number, participant).call()

    def getDelegate(self, submitter: str) -> str:
        delegate = self._contract.functions.getDelegate(submitter).call()
        if int(delegate, 16) == 0:
            return submitter
        return delegate

    def getInvited(self, submitter: str) -> str:
        return self._contract.functions.getInvited(submitter).call()

    def stakeAndSubmit(self, amount_token: int, submission_hash: str | bytes,
                       gas_price_in_wei: int):
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.stakeAndSubmit,
                                      [amount_token, submission_hash],
                                      gas_price_in_wei
                                      )

    def _setStake(self, amount_token: int, submitter_address: str, gas_price_in_wei: int):
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.setStake,
                                      [amount_token, submitter_address],
                                      gas_price_in_wei
                                      )

    def setStakeForSelf(self, amount_token: int, gas_price_in_wei: int):
        return self._setStake(amount_token, self._controlling_account.address, gas_price_in_wei)

    def setStakeForSubmitter(self, amount_token: int, submitter_address: str,
                             gas_price_in_wei: int):
        return self._setStake(amount_token, submitter_address, gas_price_in_wei)

    def submit(self, submission_hash: str | bytes, gas_price_in_wei: int):
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.submit,
                                      [submission_hash],
                                      gas_price_in_wei
                                      )

    def delegateStaking(self, invited_staker: str, submitter: str, is_cancel: bool,
                        gas_price_in_wei: int, *, bypass_check: bool = False):
        """
        Will check that current stake is 0 by default, to prevent unintended
        stake ownership transfer.
        To bypass this check, set the input parameter `bypass_check` to True.
        """
        if not bypass_check:
            if self.getStake(submitter) != 0:
                msg = f"Current stake of {submitter} is not 0."
                msg += "Are you sure you want to transfer stake ownership?"
                msg += "If sure, set the input parameter `bypass_check` to True."
                raise ValueError(msg)
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.delegateStaking,
                                      [invited_staker, submitter, is_cancel],
                                      gas_price_in_wei
                                      )

    def acceptStakingDelegationFor(self, submitter: str, gas_price_in_wei: int):
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.acceptStakingDelegationFor,
                                      [submitter],
                                      gas_price_in_wei
                                      )


class Token:
    """Token ABI connector"""
    def __init__(self, json_interface: dict, w3: web3.Web3,
                 address: types.ChecksumAddress, controlling_account: LocalAccount | None = None):
        abi = json_interface['abi']
        contract = w3.eth.contract(abi=abi)
        self._w3 = w3
        self._contract = contract(address=address)
        self._controlling_account = controlling_account
        self._name = self._contract.functions.name().call()
        self._symbol = self._contract.functions.symbol().call()
        self._address = self._contract.address

    @property
    def name(self) -> str:
        return self._name

    @property
    def symbol(self) -> str:
        return self._symbol

    @property
    def address(self) -> types.ChecksumAddress:
        return self._address

    def balanceOf(self, account: str) -> int:  # pylint:disable=invalid-name
        return self._contract.functions.balanceOf(account).call()

    def allowance(self, owner: str, spender: str) -> int:
        return self._contract.functions.allowance(owner, spender).call()

    def approve(self, spender: str, amount: int, gas_price_in_wei: int):
        return tools.send_transaction(self._w3,
                                      self._controlling_account,
                                      self._contract.functions.approve,
                                      [spender, amount],
                                      gas_price_in_wei
                                      )
