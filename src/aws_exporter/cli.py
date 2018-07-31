#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import argparse
import sys
import os
import logging
import boto3
import xlsxwriter

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
    attributes = ['Instance ID','Availability Zone', 'Name', 'Type', 'Platform', 'Security Group Name']


    for instance in running_instances:
        # Add instance info to a dictionary
        ec2info[instance.id] = {
            'Availability Zone': instance.placement['AvailabilityZone'],
            'Name': get_instance_name(instance),
            'Type': instance.instance_type,
            'Platform': instance.platform,
            'Security Group Name': get_security_groups(instance),
        }

    # Print results to stdout
    print_stdout(ec2info, attributes)

    if args.xlsx:
        export_to_xlsx(ec2info, attributes)

def get_security_groups(instance):
    for group in instance.security_groups:
        if 'Security Group Name' in group['GroupName']:
            return group['Value']
    for groupid in instance.security_groups:
        if 'Security Group Id' in groupid['GroupId']:
            return groupid['Value']

def get_instance_name(instance):
    for tag in instance.tags:
        if 'Name' in tag['Key']:
            return tag['Value']


def print_stdout(ec2info, attributes):
    t = PrettyTable(attributes)
    for instance_id, instance in ec2info.items():
        t.add_row([instance_id, instance['Availability Zone'], instance['Name'], instance['Type'], instance['Platform'], instance['Security Group Name']])
    print(t)

def export_to_xlsx(ec2info, attributes):
    print("\n\nExporting following results to excel spreadsheet")
    print("--------------------------------------")
    print(",".join(attributes))
    print("")

    # Create a workbook and add a worksheet.
    workbook = xlsxwriter.Workbook('AWS-EC2.xlsx')
    worksheet = workbook.add_worksheet('EC2')

    # Add a bold format to use to highlight cells.
    bold = workbook.add_format({'bold': 1})

    # Adjust the column width.
    worksheet.set_column(0, 1, 18)
    worksheet.set_column(9, 1, 15)
   
    # Write data headers. 
    worksheet.write('A1', 'Instance Id', bold)
    worksheet.write('B1', 'Availability Zone', bold)
    worksheet.write('C1', 'Name', bold)
    worksheet.write('D1', 'Type', bold)
    worksheet.write('E1', 'Platform', bold)
    worksheet.write('F1', 'Security Group Id', bold)

    # Start from the first cell. Rows and columns are zero indexed 
    row = 1
    col = 0 

    # Iterate over data and write it out row by row
    for instance_id, instance in ec2info.items():
        worksheet.write(row, col,     instance_id                         )
        worksheet.write(row, col + 1, instance['Availability Zone']       )
        worksheet.write(row, col + 2, instance['Name']                    )
        worksheet.write(row, col + 3, instance['Type']                    )
        worksheet.write(row, col + 4, instance['Platform']                )
        worksheet.write(row, col + 5, instance['Security Group Name']     )
        row += 1
        
    workbook.close()


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