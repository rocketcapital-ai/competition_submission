
# Submission Script

### Please refer to `quickstart.ipynb` as the main guide on submitting predictions programmatically.

## Getting Set Up

Python Version Requirement: >= 3.11

Install Yiedl submission client.

    pip install -I git+https://github.com/rocketcapital-ai/competition_submission.git


In the first code cell of `quickstart.ipynb`, you will need to fill in 3 fields.
1. `jwt`. This is your personal [pinata](https://pinata.cloud) access key.
   1. Head over to [https://pinata.cloud](https://pinata.cloud) and sign up for an account.
   2. Log in to your [account](https://app.pinata.cloud/pinmanager).
   3. Click on your account avatar on the top right and select [API Keys](https://app.pinata.cloud/keys).
   4. Click on `+ New Key`.
   5. Under `API Endpoint Access`, select `Pinning`, turn on `pinFileToIPFS`.
   6. Give a name to your api key under `Key Name`. This can be any string of characters.
   7. Leave all other fields as default.
   8. **Copy the entire string in the `JWT` field and paste it somewhere safe.**
      1. (The string should look something like "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey.......")
2. `address`. This is your wallet address. It should be a hex string beginning with "0x" followed by 40 characters.
3. `pk`. This is the private key to your wallet address.
   1. You can find this under *Metamask* > *3-dot menu on the top right* > *Account details* > *Export Private Key*.

## Files stored on Pinata.
**Please do not unpin or delete your files that are stored on Pinata until at least the opening of the next challenge.**

## ! Please keep your Private Key safe !
Stolen private keys lead to loss of funds from your blockchain wallet.

Please take necessary steps to make sure your private key string is never exposed.

This can include storing the key as a password-protected local environment variable, as well as keeping your computer safe from prying eyes or malware.
