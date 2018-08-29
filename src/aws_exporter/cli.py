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
        'Values': ['running', 'stopped']}])
    

    ec2info = {}
    attributes_ec2 = ['Region', 'Name', 'Instance ID', 'Type', 'Platform', 'Security Group Name', 'Security Group ID', 'State']

    for instance in running_instances:
        # Add instance info to a dictionary
        ec2info[instance.id] = {
            'Region': instance.placement['AvailabilityZone'],
            'Name': get_instance_name(instance),
            'Instance ID': instance.id,
            'Type': instance.instance_type,
            'Platform': get_platform(instance),
            'Security Group Name': get_security_groups(instance),
            'Security Group ID': get_security_groups_id(instance),
            'State': instance.state['Name'],
        }

    # Print results to stdout
    print_stdout(ec2info, attributes_ec2)
    
    if args.all_regions: 
        all_regions(args)

    if args.xlsx:
        export_to_xlsx(ec2info, attributes_ec2, args)
    
   
def get_platform(instance):
    platform = instance.platform 
    if platform is None:
        return ('Linux')


def get_security_groups(instance):
    for group in instance.security_groups:
        return group['GroupName']


def get_security_groups_id(instance):
    for groupid in instance.security_groups:
        return groupid['GroupId']


def get_instance_name(instance):
    for tag in instance.tags:
        if 'Name' in tag['Key']:
            return tag['Value']


def print_stdout(ec2info, attributes_ec2):
    t = PrettyTable(attributes_ec2)
    for instance_id, instance in ec2info.items():
        t.add_row([instance['Region'], instance['Name'], instance_id,
        instance['Type'], instance['Platform'], instance['Security Group Name'], instance['Security Group ID'], instance['State']])
    print(t)


def run_vpc(args):
    client = boto3.client('ec2')
    vpcs = client.describe_vpcs()['Vpcs']
    subnets = client.describe_subnets()['Subnets']

    vpcinfo = {}
    attributes_vpc = ['Vpc Id', 'CIDR', 'State', 'Subnets']

    for vpc in vpcs:
        vpc_id = vpc['VpcId']

        subnets = []
        for subnet in subnets:
            subnets.append(subnet['SubnetId'])
        vpcinfo[vpc_id] = {
            'Vpc Id': vpc_id,
            'CIDR': vpc['CidrBlock'],
            'State': vpc['State'],
            'Subnet Id': subnets,
        }

    t = PrettyTable(attributes_vpc)
    t.add_row([vpc_id, vpc['CidrBlock'], vpc['State'], subnets])
    print(t)

    if args.xlsx:
        export_vpc_xlsx(vpcinfo, attributes_vpc, args)


def export_vpc_xlsx (vpcinfo, attributes_vpc, args):
    print("\n\nExporting following results to excel spreadsheet")
    print("--------------------------------------")
    print(",".join(attributes_vpc))
    print("")

    # Allow user to input own file_name
    file_name = args.file_name 
    if args.file_name is None:
        print("""
        Must enter file name 
        --file_name <file_name>
        """)    

    # Creates worksheet with user input
    workbook = xlsxwriter.Workbook(file_name)
    worksheet = workbook.add_worksheet('VPC')

    # Add a bold format to use to highlight cells.
    bold = workbook.add_format({'bold': 1})

    # Adjust the column width.
    worksheet.set_column(0, 1, 18)
    worksheet.set_column(9, 1, 15)
   
    # Write data headers. 
    worksheet.write('A1', 'Vpc Id', bold)
    worksheet.write('B1', 'CIDR', bold)
    worksheet.write('C1', 'State', bold)
    worksheet.write('D1', 'Subnet Id', bold)
    # Start from the first cell. Rows and columns are zero indexed 
    row = 1
    col = 0 

    # Iterate over data and write it out row by row
    for vpc_id, vpc in vpcinfo.items():
        worksheet.write(row, col,     vpc_id                  )
        worksheet.write(row, col + 1, vpc['CIDR']             )
        worksheet.write(row, col + 2, vpc['State']            )
        worksheet.write_row(row, col + 3, vpc['Subnet Id']    )
        row += 1
    workbook.close()


def all_regions(args):
    client = boto3.client('ec2') 
    regions = client.describe_regions()['Regions'] 
    
    # Connect to EC2 
    for region in regions:  
        ec2 = boto3.resource('ec2',region_name=region['RegionName']) 
    # Get information for all running instances 
    running_instances = ec2.instances.filter(Filters=[{ 
        'Name': 'instance-state-name', 
        'Values': ['running', 'stopped']}]) 
    ec2info = {}
    for instance in running_instances: 
        for tag in instance.tags: 
            if 'Name'in tag['Key']: 
                name = tag['Value']

    # Add instance info to a dictionary 
    ec2info[instance.id] = { 
        'Region': region['RegionName'],
        'Name': name,
        'Instance ID': instance.id,
        'Type': instance.instance_type,
        'Platform': get_platform(instance), 
        'Security Group Name': get_security_groups(instance),
        'Security Group ID': get_security_groups_id(instance), 
        'State': instance.state['Name'],
        } 

    attributes = ['Region', 'Name', 'Instance ID', 'Type', 'Platform', 'Security Group Name', 'Security Group ID', 'State'] 
    t = PrettyTable(attributes)
    for instance_id, instance in ec2info.items():
        t.add_row([instance['Region'], instance['Name'], instance_id,
        instance['Type'], instance['Platform'], instance['Security Group Name'], instance['Security Group ID'], instance['State']])
    print(t)


def export_to_xlsx(ec2info, attributes_ec2, args):
    print("\n\nExporting following results to excel spreadsheet")
    print("--------------------------------------")
    print(",".join(attributes_ec2))
    print("")

    # Allow user to input own file_name
    file_name = args.file_name 
    if args.file_name is None:
        print("""
        Must enter file name 
        --file_name <file_name>
        """)    

    # Creates worksheet with user input
    workbook = xlsxwriter.Workbook(file_name)
    worksheet = workbook.add_worksheet('EC2')

    # Add a bold format to use to highlight cells.
    bold = workbook.add_format({'bold': 1})

    # Adjust the column width.
    worksheet.set_column(0, 1, 18)
    worksheet.set_column(9, 1, 15)
   
    # Write data headers. 
    worksheet.write('A1', 'Region', bold)
    worksheet.write('B1', 'Name', bold)
    worksheet.write('C1', 'Instance ID', bold)
    worksheet.write('D1', 'Type', bold)
    worksheet.write('E1', 'Platform', bold)
    worksheet.write('F1', 'Security Group Name', bold)
    worksheet.write('G1', 'Security Group ID', bold)
    worksheet.write('H1', 'State', bold)
    # Start from the first cell. Rows and columns are zero indexed 
    row = 1
    col = 0 

    # Iterate over data and write it out row by row
    for instance_id, instance in ec2info.items():
        worksheet.write(row, col,     instance['Region']             )
        worksheet.write(row, col + 1, instance['Name']               )
        worksheet.write(row, col + 2, instance_id                    )
        worksheet.write(row, col + 3, instance['Type']               )
        worksheet.write(row, col + 4, instance['Platform']           )
        worksheet.write(row, col + 5, instance['Security Group Name'])
        worksheet.write(row, col + 6, instance['Security Group ID']  )
        worksheet.write(row, col + 7, instance['State']              )
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
        '-all_regions',
        '--all_regions',
        help="Outputs all AWS Regions",
        action='store_true')
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
    parser.add_argument(
        '-file_name',
        '--file_name',
        dest="file_name",
        help="Exports output to file",)

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
    elif args.aws_service_name == 'vpc':
        run_vpc(args)
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