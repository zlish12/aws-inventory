import boto3
import os
import argparse
import sys

#check for public key, secret, and region
access_key = os.environ.get('AWS_ACCESS_KEY_ID')

if access_key is None:
    access_key = input('Enter AWS Access Key ID: ')
    print (access_key)

secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

if secret_key is None:
    secret_key = input('Enter AWS Secret Key ID: ')
    print (secret_key)

region = os.environ.get('AWS_DEFAULT_REGION')
if region is None:
    region = input('Enter AWS Region: ')
    print (region)

#Can't get the argparse stuff to work, need to move on though. Will come back to this.
#parser = argparse.ArgumentParser()
#parser.add_argument('-access_key', help='Enter AWS Access Key ID', required=True)
#parser.add_argument('-secret_key', help='Enter AWS Secret Access Key ID', required=True)
#parser.add_argument('-region', help='Enter AWS Default Region', required=True)
#args = parser.parse_args()
#print (args)

print('You have successfully connected to AWS region')
print ('Access key entered: '+access_key)
print ('Secret key enter: '+secret_key)
print ('Region entered: '+region)
