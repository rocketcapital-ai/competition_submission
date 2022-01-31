from .tools import *


class Competition:
    def __init__(self, json_interface: json, w3: web3.Web3, address: types.ChecksumAddress, controlling_account=None, verbose=True):
        abi = json_interface['abi']
        contract = w3.eth.contract(abi=abi)
        self._w3 = w3
        self._contract = contract(address=address)
        self._controlling_account = controlling_account
        self._verbose = verbose
        self._address = self._contract.address

    @property
    def address(self):
        return self._address

    def getDatasetHash(self, challenge_number):
        return self._contract.functions.getDatasetHash(challenge_number).call()

    def getDeadlines(self, challenge_number, index):
        return self._contract.functions.getDeadlines(challenge_number, index).call()

    def getKeyHash(self, challenge_number):
        return self._contract.functions.getKeyHash(challenge_number).call()

    def getLatestChallengeNumber(self):
        return self._contract.functions.getLatestChallengeNumber().call()

    def getPhase(self, challenge_number):
        return self._contract.functions.getPhase(challenge_number).call()

    def getStake(self, participant):
        return self._contract.functions.getStake(participant).call()

    def getStakeThreshold(self):
        return self._contract.functions.getStakeThreshold().call()
    
    def getSubmission(self, challenge_number, participant):
        return self._contract.functions.getSubmission(challenge_number, participant).call()

    def submitNewPredictions(self, submission_hash: str or bytes, gas_price_in_wei: int):
        return send_transaction(self._w3,
                                self._controlling_account,
                                self._contract.functions.submitNewPredictions,
                                [submission_hash],
                                gas_price_in_wei
                                )
    
    def updateSubmission(self, old_submission_hash: str or bytes, new_submission_hash: str or bytes, gas_price_in_wei: int):
        return send_transaction(self._w3,
                                self._controlling_account,
                                self._contract.functions.updateSubmission,
                                [old_submission_hash, new_submission_hash],
                                gas_price_in_wei
                                )


class Token:
    def __init__(self, json_interface: json, w3: web3.Web3, address: types.ChecksumAddress, controlling_account=None, verbose=True):
        abi = json_interface['abi']
        contract = w3.eth.contract(abi=abi)
        self._w3 = w3
        self._contract = contract(address=address)
        self._controlling_account = controlling_account
        self._verbose = verbose
        self._name = self._contract.functions.name().call()
        self._symbol = self._contract.functions.symbol().call()
        self._address = self._contract.address

    @property
    def name(self):
        return self._name

    @property
    def symbol(self):
        return self._symbol

    @property
    def address(self):
        return self._address

    def balanceOf(self, account):
        return self._contract.functions.balanceOf(account).call()

    def setStake(self, target: str, amount_token: int, gas_price_in_wei: int):
        return send_transaction(self._w3,
                                self._controlling_account,
                                self._contract.functions.setStake,
                                [target, amount_token],
                                gas_price_in_wei
                                )
