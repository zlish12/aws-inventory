#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import argparse
import sys
import os
import logging
import boto3

from aws_exporter import __version__
from pprint import pprint
from prettytable import PrettyTable

__author__ = "Zlish"
__copyright__ = "Zlish"
__license__ = "mit"

_logger = logging.getLogger(__name__)


def run_ec2(args):
    session = boto3.Session(
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
    )

    ec2 = session.resource('ec2')

    # Get information for all running instances
    running_instances = ec2.instances.filter(Filters=[{
        'Name': 'instance-state-name',
        'Values': ['running']}])

    ec2info = {}
    attributes = ['Name', 'KeyName', 'Type', 'ID', 'State', 'Private IP', 'Public IP', 'ImageID', 'Platform']

    for instance in running_instances:
        # Add instance info to a dictionary
        ec2info[instance.id] = {
            'Name': get_instance_name(instance),
            'KeyName': instance.key_name,
            'Type': instance.instance_type,
            'ID': instance.instance_id,
            'State': instance.state['Name'],
            'Private IP': instance.private_ip_address,
            'Public IP': instance.public_ip_address,
            'ImageId': instance.image_id,
            'Platform': instance.platform,
        }

    # Print results to stdout
    print_stdout(ec2info, attributes)

    if args.xlsx:
        export_to_xlsx(ec2info, attributes)


def get_instance_name(instance):
    for tag in instance.tags:
        if 'Name' in tag['Key']:
            return tag['Value']


def print_stdout(ec2info, attributes):
    print ('You have successfully connected to AWS')
    t = PrettyTable(['Instance ID', 'Name', 'KeyName', 'Type', 'ID', 'State', 'Private IP', 'Public IP', 'Image ID', 'Platform'])
    for instance_id, instance in ec2info.items():
        t.add_row([instance_id, instance['Name'], instance['KeyName'], instance['Type'], instance['ID'], instance['State'], 
        instance['Private IP'], instance['Public IP'], instance['ImageId'], instance['Platform']])
    print (t)

#def print_stdout(ec2info, attributes):
    #for instance_id, instance in ec2info.items():
        #print("Instance Id: " + instance_id)
        #for key in attributes:
            #print("{0}: {1}".format(key, instance[key]))
        #print("-------------")


def export_to_xlsx(ec2info, attributes):
    print("\n\nExporting results to excel spreadsheet")
    print("--------------------------------------")
    print("Instance Id,", end="")
    print(",".join(attributes))
    print("")



def parse_args(args):
    """Parse command line parameters
    Args:
      args ([str]): command line parameters as list of strings
    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="AWS Exporter Tool")
    parser.add_argument(
        dest="aws_service_name",
        help="AWS Service Name i.e. ec2, s3, elb")
    parser.add_argument(
        '--version',
        action='version',
        version='aws-exporter {ver}'.format(ver=__version__))
    parser.add_argument(
        '-access_key',
        '--access_key',
        dest="access_key",
        help="AWS Access Key ID")
    parser.add_argument(
        '-secret_key',
        '--secret_key',
        dest="secret_key",
        help="AWS Secret Key ID")
    parser.add_argument(
        '-region',
        '--region',
        dest="region",
        help="AWS Region",
        default='us-west-1')
    parser.add_argument(
        '-xlsx',
        '--xlsx',
        help="Export to excel spreadsheet",
        action='store_true')
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging
    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def validate(args):
    access_key = args.access_key if args.access_key is not None else os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = args.secret_key if args.secret_key is not None else os.environ.get('AWS_SECRET_ACCESS_KEY')
    region = args.region if args.region is not None else os.environ.get('AWS_DEFAULT_REGION')

    if access_key is None or secret_key is None or region is None:
        print("""
Must set AWS Secret Key and Access Key:
--access_key <access_key>
--secret_key <secret_key>
or
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
        """)
        sys.exit(1)


def main(args):
    """Main entry point allowing external calls
    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.debug("Starting crazy calculations...")

    # print("The {}-th Fibonacci number is {}".format(args.n, fib(args.n)))
    validate(args)

    # Do Stuff here
    if args.aws_service_name == 'ec2':
        run_ec2(args)
    else:
        print("service name: " + args.aws_service_name + " is not currently supported")
        sys.exit(1)

    _logger.info("Script ends here")


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()