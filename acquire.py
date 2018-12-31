import logging
import sys
import time
import uuid
import boto3

logging.basicConfig(level=logging.INFO, format='time="%(asctime)s" level=%(levelname)s %(message)s', stream=sys.stdout)

def assume_role(account, role):
    client = boto3.client('sts')
    role = client.assume_role(
        RoleArn='arn:aws:iam::{}:role/{}'.format(account, role),
        RoleSessionName=role,
        DurationSeconds=900)
    return boto3.Session(
        aws_access_key_id=role['Credentials']['AccessKeyId'],
        aws_secret_access_key=role['Credentials']['SecretAccessKey'],
        aws_session_token = role['Credentials']['SessionToken'])

def attach_profile(session, instance, role):
    iam = session.client('iam')
    ec2 = session.client('ec2')
    associations = ec2.describe_iam_instance_profile_associations(
        Filters=[
            {'Name': 'instance-id', 'Values': [instance]},
            {'Name': 'state', 'Values': ['associating', 'associated']}
        ])
    profiles = iam.list_instance_profiles_for_role(
        RoleName=role)
    for profile in profiles['InstanceProfiles']:
        for association in associations['IamInstanceProfileAssociations']:
            if association['IamInstanceProfile']['Arn'] == profile['Arn']:
                return association['AssociationId']
        associate = ec2.associate_iam_instance_profile(
            IamInstanceProfile={
                'Arn': profile['Arn'], 
                'Name': profile['InstanceProfileName']},
            InstanceId=instance)
        return associate['IamInstanceProfileAssociation']['AssociationId']
    raise Exception('Could not associate instance profile.')

def wait_association(session, association, wait):
    ec2 = session.client('ec2')
    for _ in range(wait):
        associations = ec2.describe_iam_instance_profile_associations(
            AssociationIds=[association],
            Filters=[
                {'Name': 'state', 'Values': ['associated']}
            ])
        if associations['IamInstanceProfileAssociations']:
            return
        time.sleep(1)
    raise Exception('Timed out waiting for association.')

def detach_profile(session, association):
    ec2 = session.client('ec2')
    ec2.disassociate_iam_instance_profile(
        AssociationId=association)

def ssm_command(session, instance, command, wait):
    ssm = session.client('ssm')
    send = ssm.send_command(
        InstanceIds=[instance],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': [command]})
    for _ in range(wait):
        try:
            get = ssm.get_command_invocation(
                CommandId=send['Command']['CommandId'],
                InstanceId=instance)
            if get['StatusDetails'] not in ['Pending', 'InProgress', 'Delayed']:
                return get['StatusDetails'], get['StandardOutputContent'], get['StandardErrorContent']
        except ssm.exceptions.InvocationDoesNotExist:
            pass
        time.sleep(1)
    raise Exception('Timed out waiting for command.')

def ebs_snapshot(session, region, instance):
    ec2 = session.client('ec2', region)
    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'attachment.instance-id', 'Values': [instance]}])
    for volume in volumes['Volumes']:
        snapshot = ec2.create_snapshot(
            VolumeId=volume['VolumeId'],
            Description='app=aws-acquire instance={} volume={}'.format(
                instance, volume['VolumeId']))
        yield snapshot['VolumeId'], snapshot['SnapshotId']

def acquire_instance(account, region, instance):
    try:
        session = assume_role(account, 'aws-acquire-service')
        session = boto3.Session()
        association = attach_profile(session, instance, 'aws-acquire-instance')
        wait_association(session, association, 10)
        logging.info('event=association account=%s instance=%s association=%s', account, instance, association)
        command = 'wget https://github.com/google/rekall/releases/download/v1.5.1/linpmem-2.1.post4' \
            ' && chmod 700 linpmem-2.1.post4' \
            ' && echo "4a5a922b0c0c2b38131fb4831cc4ece9  linpmem-2.1.post4" | md5sum -c' \
            ' && ./linpmem-2.1.post4 --output image.$(date +%s).aff4'
        status, output, error = ssm_command(session, instance, command, 60)
        logging.info('event=command account=%s instance=%s status=%s', account, instance, status)
        for volume, snapshot in ebs_snapshot(session, region, instance):
            logging.info('event=snapshot account=%s instance=%s volume=%s snapshot=%s', account, instance, volume, snapshot)
        detach_profile(session, association)
        logging.info('event=detach account=%s instance=%s association=%s', account, instance, association)
    except Exception:
        logging.exception('event=error account=%s instance=%s', account, instance)
