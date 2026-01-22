""" global settings """

GAS_PRICE_URL = 'https://gasstation.polygon.technology/v2'
IPFS_API_URL = 'https://api.pinata.cloud'
IPFS_DEFAULT = 'bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m#x-ipfs-companion-no-redirect'
IPFS_GATEWAY = 'https://gateway.pinata.cloud/ipfs'
JSON_DIRECTORY = 'json_interfaces'
NULL_IPFS_CID = "QmNLei78zWmzUdbeRB3CiUfAizWUrbeeZh5K1rhAQKCh51"
RPC_GATEWAY = 'https://polygon.drpc.org'
REQUESTS_TIMEOUT = 120
UPDOWN_SUBMISSION_FOLDER_NAME = 'updown_file_to_submit'
UPDOWN_SUBMISSION_FILE_PATH = f'{UPDOWN_SUBMISSION_FOLDER_NAME}/updown_submission.csv'
UPDOWN_ENCRYPTED_SUBMISSIONS = 'updown_encrypted_submissions'
NEUTRAL_SUBMISSION_FOLDER_NAME = 'neutral_file_to_submit'
NEUTRAL_SUBMISSION_FILE_PATH = f'{NEUTRAL_SUBMISSION_FOLDER_NAME}/neutral_submission.csv'
NEUTRAL_ENCRYPTED_SUBMISSIONS = 'neutral_encrypted_submissions'
SUPPORT_EMAIL = 'info@rocketcapital.ai'
W3_TIMEOUT = 600
W3_INTERVAL = 15
BASE_GAS_MULTIPLIER = 1.13
FALLBACK_GAS_PRICE_IN_GWEI = 2_000

# live
UPDOWN_ADDRESS = '0xEcB9716867f9300F2706EdbB5b81c7a0AbDC5B29'
NEUTRAL_ADDRESS = '0xC8519524013348466e18fC1747d11F1feA9473fd'
TOKEN = '0x97392b5bf12b70Ab7Eff76a4B9130d69ED48f23D'
TOKEN_NAME = 'YIEDL'

# download settings
BASE_URL = "https://api.yiedl.ai/yiedl/v1/downloadDataset"
WEEKLY_DATASET_TYPE = "weekly"
DAILY_DATASET_TYPE = "daily"
LATEST_DATASET_TYPE = "latest"
HISTORICAL_DATASET_TYPE = "historical"
WEEKLY_DATASET_FILENAME = "weekly_dataset.zip"
DAILY_DATASET_FILENAME = "daily_dataset.zip"
LATEST_DATASET_FILENAME = "latest_dataset.parquet"
HISTORICAL_DATASET_FILENAME = "historical_dataset.zip"
DOWNLOADED_DATASET_DIRECTORY = "datasets"
YIEDL_TRAIN_FILE_PATH = "dataset/train_dataset.csv"
YIEDL_VALIDATION_FILE_PATH = "dataset/validation_dataset.csv"
CHUNK_SIZE = 8192
SLEEP_DELAY_SECONDS = 3
RETRIES = 10
