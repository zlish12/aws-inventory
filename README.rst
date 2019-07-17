============
aws-exporter
============



AWS EC2 export tool built with python. Useful to get summarized information on AWS EC2, IAM, S3, and VPC. 
The tool by default produces a report that can easily be read from a terminal, 
but it can also be used produce a tab separated output report that can be viewed 
in an excel spreadsheet. This can be used by running the command followed by --xlsx --file_name <filename>.xlsx 
and information will be stored in excel file.

Install
==========

install boto3:

    $ pip install boto3


Configure 
==========

AWS tool can be configured through using environment variables or through using command line arguments. 

How to set env variables:
    1. open terminal 
    2. vim .bash_profile 
    3. insert:  
        
        export AWS_ACCESS_KEY_ID=AABBCCDDEEFF
        
        export AWS_SECRET_ACCESS_KEY=aabbCCDDeeff112233 
        
    4. esc :wq to save environment variables 
    5. close and reopen terminal 

Using CMD argument
    $ python ./cli.py ec2 --access_key AABBCCDDEEFF --secret_key aabbCCDDeeff112233 
    $ python ./cli.py vpc --access_key AABBCCDDEEFF --secret_key aabbCCDDeeff112233 
    $ python ./cli.py iam --access_key AABBCCDDEEFF --secret_key aabbCCDDeeff112233
    $ python ./cli.py s3 --access_key AABBCCDDEEFF --secret_key aabbCCDDeeff112233



Setup Additional Dependencies 
===========

$ python setup.py develop


Usage 
===========

$ python src/aws_exporter/cli.py ec2           

#reports EC2, IAM, S3, or VPC information 




Output Example
===========
when running the output should look like this: 

$ python ./cli.py ec2 

+-------------+-------+----------+--------+---------+----------+
| Instance ID |  Name |   Type   |   ID   |  State  | Platform | 
+-------------+-------+----------+--------+---------+----------+
|   1122aabb  | Name1 | t2.small | i-1123 | running |  linux   |
+-------------+-------+----------+--------+---------+----------+

$ python ./cli.py vpc 
+-------------+------------+-----------+-----------+
|   Vpc Id    |     CIDR   |   State   |   Subnets |  
+-------------+------------+-----------+-----------+
| vpc-11aab22 | 111.22.0.0 | available |      []   |
+-------------+------------+-----------+-----------+

$ python ./cli.py iam 
+--------------+------------+--------+
|  User name   |   User ID  |   ARN  |
+--------------+------------+--------+
|  user_name1  | aabbcc1122 | arn:322|
+--------------+------------+--------+

$ python ./cli.py s3 
+---------------+
|  Bucket name  | 
+---------------+
| bucket_name01 | 
+---------------+
|  bucket_name1 |
+---------------+



If you want information from above to go into excel spread sheet:
=====
$ python ./cli.py ec2 --xlsx --file_name <filename>.xlsx
$ python ./cli.py vpc --xlsx --file_name <filename>.xlsx
$ python ./cli.py iam --xlsx --file_name <filename>.xlsx
$ python ./cli.py s3 --xlsx --file_name <filename>.xlsx

#*Filename is stored as <filename>.xlsx


Note
====

This project has been set up using PyScaffold 3.0.3. For details and usage
information on PyScaffold see http://pyscaffold.org/.
