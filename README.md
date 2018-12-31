# AWS Acquire

Acquire memory and snapshot EC2 instances that have SSM installed.

## Roles

aws-acquire-service:
- AmazonSSMFullAccess

aws-acquire-instance:
- AmazonEC2RoleforSSM

## Usage

```
import acquire
acquire.acquire_instance('account-id', 'region-name', 'instance-id')
```
