import boto3
import os
import argparse

#check for public key, secret, and region 
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
region = os.environ.get('AWS_DEFAULT_REGION')

parser = argparse.ArgumentParser()
parser.add_argument('-access_key', help='Enter AWS Access Key ID', required=True)
parser.add_argument('-secret_key', help='Enter AWS Secret Access Key ID', required=True)
parser.add_argument('-region', help='Enter AWS Default Region', required=True)
args = parser.parse_args()

print args
print('You have successfully connected to AWS region')
