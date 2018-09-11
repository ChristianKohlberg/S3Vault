import base64
import boto3
import pyaes

from botocore.exceptions import ClientError
from urllib.parse import urlparse


class S3Vault:
    def __init__(self, aws_credentials):
        self.session = boto3.Session(
            aws_access_key_id=aws_credentials["access_key"],
            aws_secret_access_key=aws_credentials["secret_access_key"],
        )
        self.s3 = self.session.client('s3')

    @staticmethod
    def parse_s3_url(s3url):
        parsed_url = urlparse(s3url)
        if not parsed_url.netloc:
            raise Exception('"%s" is no valid S3 url.' % s3url)
        else:
            bucket_name = parsed_url.netloc
            key = parsed_url.path.strip('/')
            return bucket_name, key

    @staticmethod
    def encrypt_string(text, encryption_key):
        key = encryption_key.encode()
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertext = aes.encrypt(text)
        b64_string = str(base64.b64encode(ciphertext), 'utf-8')
        return b64_string

    @staticmethod
    def decrypt_string(text, encryption_key):
        key = encryption_key.encode()
        aes = pyaes.AESModeOfOperationCTR(key)
        bytes = base64.b64decode(text)
        plaintext = aes.decrypt(bytes)
        return plaintext

    def check_if_key_exists(self, s3_url):
        try:
            s3_bucket, s3_key = S3Vault.parse_s3_url(s3_url)
            self.s3.head_object(Bucket=s3_bucket, Key=s3_key)
            return True
        except ClientError as e:
            print(e.response["Error"]["Message"])
            return False

    def store_file(self, filename, s3_url, encryption_key, overwrite=False):
        return "Not implemented!"

    def get_file(self, s3_url, encryption_key, overwrite=False):
        return "Not implemented!"

    def store_secret(self, plaintext, encryption_key, s3_url, overwrite=False):
        key_exists = self.check_if_key_exists(s3_url)

        if overwrite or not key_exists:
            ciphertext = S3Vault.encrypt_string(plaintext, encryption_key)
            s3_bucket, s3_key = S3Vault.parse_s3_url(s3_url)
            # TODO: storing as string permitted? doc says bytes or file-like obj
            self.s3.put_object(Body=ciphertext, Bucket=s3_bucket, Key=s3_key)
        else:
            print("Key already exists. Overwriting forbidden.")

    def get_secret(self, s3_url, encryption_key):
        try:
            s3_bucket, s3_key = S3Vault.parse_s3_url(s3_url)
            s3_file = self.s3.get_object(Bucket=s3_bucket, Key=s3_key)['Body'].read()

            # TODO: read as string or byte?
            # s3_file = io.StringIO(s3_file)
            plaintext = S3Vault.decrypt_string(s3_file, encryption_key)
            return plaintext
        except ClientError as e:
            print(e.response["Error"]["Message"])


aws_credentials = {
    "access_key": "!",
    "secret_access_key": "!"
}

key = "This_key_for_demo_purposes_only!"
text = '{"user}'.encode()
