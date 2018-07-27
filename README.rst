============
aws-exporter
============



AWS EC2 export tool built with python. Useful to get summarized information on AWS EC2. 
The tool by default produces a report that can easily be read from a terminal, 
but it can also be used produce a tab separated output report that can be viewed 
in an excel spreadsheet. This can be used by running the command followed by --xlsx.


Configure 
==========

AWS EC2 export can be configured through using environment variables or through using command line arguments. 

How to set env variables:
    1. open terminal 
    2. vim .bash_profile 
    3. insert:  export AWS_ACCESS_KEY_ID=AABBCCDDEEFF
                export AWS_SECRET_ACCESS_KEY=aabbCCDDeeff112233 
    4. esc :wq to save environment variables 

Using CMD argument
    $ python ./cli.py ec2 --access_key AABBCCDDEEFF --secret_key aabbCCDDeeff112233 



Usage 
===========

$ python ./cli.py ec2           #reports EC2 information 


Output Example
===========
when running the output should look like this: 

$ python ./cli.py ec2 
+-------------+-------+----------+--------+---------+----------+--------------+--------------+
| Instance ID |  Name |   Type   |   ID   |  State  | Platform |  Private IP  |  Public IP   |
+-------------+-------+----------+--------+---------+----------+--------------+--------------+
|   1122aabb  | Name1 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
|   1122aabb  | Name2 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
|   1122aabb  | Name3 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
|   1122aabb  | Name4 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
|   1122aabb  | Name5 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
|   1122aabb  | Name6 | t2.small | i-1123 | running |  linux   | 111.22.33.44 | 111.22.33.44 |
+-------------+-------+----------+--------+---------+----------+--------------+--------------+
$

If you want information from above to go into excel spread sheet:
$ python ./cli.py ec2 --xlsx

Exporting results to excel spreadsheet
--------------------------------------
Instance Id,Name,Type,ID,State,Platform,Private IP,Public IP

#Filename is stored as EC2Instance.xlsx


Note
====

This project has been set up using PyScaffold 3.0.3. For details and usage
information on PyScaffold see http://pyscaffold.org/.
