#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import boto3
import re
import sys


class ExclCategory:
    def __init__(self, cidrIp, toPort, description):
        self.cidrIp = cidrIp
        self.toPort = toPort
        self.description = description

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, type(self))
                and (self.cidrIp, self.toPort, self.description) ==
                (other.cidrIp, other.toPort, other.description))

    def __hash__(self) -> int:
        return hash((self.cidrIp, self.toPort, self.description))


class PermRef:
    def __init__(self, perm, sgId):
        self.perm = perm
        self.sgId = sgId


rds = boto3.client('rds')

dbs = rds.describe_db_instances()['DBInstances']
# Build dict  SG_ID -> listOf(DB_WITH_ACTIVE_SG.INSTANCE_ID)
sgRefs = {}
for db in dbs:
    dbId = db['DBInstanceIdentifier']
    for sg in db['VpcSecurityGroups']:
        if sg['Status'] == 'active':
            sgId = sg['VpcSecurityGroupId']
            sgRefs.setdefault(sgId, []).append(dbId)

ec2 = boto3.client('ec2')

# Build dict ExclCategory -> listOf(IP_PERMISSION)
exclusions = {}
sgs = {sg['GroupId']: sg for sg in ec2.describe_security_groups(GroupIds=list(sgRefs.keys()))['SecurityGroups']}
for sgId, dbIds in sgRefs.items():
    sg = sgs[sgId]
    for perm in sg['IpPermissions']:
        for ipRange in perm['IpRanges']:
            toPort = perm['ToPort']
            cidrIp = ipRange['CidrIp']
            description = ipRange.get('Description', '')
            if re.search(r'\bremov(e|ing)\b', description, re.IGNORECASE):
                cat = ExclCategory(cidrIp, toPort, description)
                permRef = PermRef(perm, sgId)
                exclusions.setdefault(cat, []).append(permRef)

for cat, permRefList in exclusions.items():
    print("\nCidrIp: %s, ToPort: %s, Description: '%s'" % (cat.cidrIp, cat.toPort, cat.description))
    print("    %s" % ", ".join([permRef.sgId for permRef in permRefList]))
    print("\nDelete (y/N)? ", end='')
    ch = sys.stdin.read(1)
    print()
    if ch == "y" or ch == "Y":
        for permRef in permRefList:
            print("Revoking for SG=%s" % permRef.sgId)
            ec2.revoke_security_group_ingress(GroupId=permRef.sgId, IpPermissions=[permRef.perm])
