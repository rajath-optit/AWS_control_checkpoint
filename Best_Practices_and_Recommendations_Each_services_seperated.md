# AWS Compliance Controls

This document outlines all the controls that need to be followed for different AWS services to ensure compliance.

## Account
- Security contact information should be provided for an AWS account.

## ACM (AWS Certificate Manager)
- Ensure that ACM certificates are not in a failed state.
- Ensure that ACM certificates are not in a pending validation state.
- ACM certificates should not use wildcard certificates.
- Ensure that all expired ACM certificates are removed.
- RSA certificates managed by ACM should use a key length of at least 2,048 bits.

## API Gateway
- API Gateway methods authorizer should be configured.
- API Gateway methods request parameter should be validated.
- API Gateway REST API public endpoints should be configured with an authorizer.
- API Gateway routes should specify an authorization type.
- API Gateway V2 authorizer should be configured.
- API Gateway REST API endpoint type should be configured to private.
- API Gateway REST API stages should have AWS X-Ray tracing enabled.
- Access logging should be configured for API Gateway V2 Stages.

## AppStream
- AppStream fleet default internet access should be disabled.
- AppStream fleet idle disconnect timeout should be set to ≤ 10 mins.
- AppStream fleet max user duration should be set to < 10 hours.
- AppStream fleet session disconnect timeout should be set to ≤ 5 mins.

## AppSync
- AppSync GraphQL API logging should be enabled.

## Athena
- Athena workgroups should be encrypted at rest.
- Athena workgroups should enforce configuration.

## Auto Scaling
- EC2 Auto Scaling group launch configurations user data should not contain sensitive data.
- Auto Scaling groups should not have any suspended processes.
- EC2 Auto Scaling groups should propagate tags to EC2 instances they launch.
- EC2 Auto Scaling groups should use EC2 launch templates.
- EC2 Auto Scaling group launch configurations should not have metadata response hop limit > 1.
- Auto Scaling groups should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2).
- EC2 Auto Scaling groups should use multiple instance types in multiple availability zones.

## Backup
- Backup plan minimum frequency and retention period should be checked.
- Backup plan should exist in a region.
- Backup report plan should exist where the backup plan is enabled.
- Backup vaults should exist in a region.

## CloudFormation
- CloudFormation stacks should not differ from the expected configuration.
- CloudFormation stacks should have notifications enabled.
- CloudFormation stacks should have rollback enabled.
- CloudFormation stacks termination protection should be enabled.

## CloudFront
- CloudFront distributions should have a default root object configured.
- CloudFront distributions should require encryption in transit.
- CloudFront distributions should have field-level encryption enabled.
- CloudFront distributions should have geo-restriction enabled.
- CloudFront distributions should use the latest TLS version.
- CloudFront distributions should not point to non-existent S3 origins.
- CloudFront distributions should encrypt traffic to non-S3 origins.
- CloudFront distributions should have origin access identity enabled.
- CloudFront distributions should use SNI to serve HTTPS requests.
- CloudFront distributions should use custom SSL/TLS certificates.
- CloudFront distributions should use secure SSL cipher.

## CloudTrail
- CloudTrail trails should be enabled in all regions.
- CloudTrail multi-region trails should be integrated with CloudWatch logs.
- S3 bucket access logging should be enabled on the CloudTrail S3 bucket.
- Object-level logging for read events should be enabled for S3 bucket.
- Object-level logging for write events should be enabled for S3 bucket.
- CloudTrail trail S3 buckets MFA delete should be enabled.
- At least one CloudTrail trail should be enabled in the AWS account.
- CloudTrail trails should have insight selectors and logging enabled.

## CloudWatch
- CloudWatch alarm action should be enabled.
- Log group encryption at rest should be enabled.
- Ensure a log metric filter and alarm exist for:
  - S3 bucket policy changes
  - CloudTrail configuration changes
  - AWS Config configuration changes
  - AWS Management Console authentication failures
  - AWS Management Console sign-in without MFA
  - Disabling or scheduled deletion of customer-managed keys
  - IAM policy changes
  - Network Access Control List (NACL) changes
  - Network gateway changes
  - AWS Organizations changes
  - Usage of the 'root' account
  - Route table changes
  - Security group changes
  - Unauthorized API calls
  - VPC changes

## CodeBuild
- CodeBuild project environments should not have privileged mode enabled.
- CodeBuild GitHub or Bitbucket source repository URLs should use OAuth.

## CodeDeploy
- CodeDeploy deployment groups lambda all-at-once traffic shift should be disabled.

## Config
- Config configuration recorder should not fail to deliver logs.

## DAX (DynamoDB Accelerator)
- DAX clusters should be encrypted at rest.

## Directory Service
- Directory Service certificates should not expire within 90 days.
- Directory Service directories manual snapshots limit should not be less than 2.
- Directory Service directories should have SNS notification enabled.

## DLM (Data Lifecycle Manager)
- DLM EBS snapshot lifecycle policy should be enabled.

## DMS (Database Migration Service)
- Expired DMS certificates should be removed.
- DMS endpoints should use SSL.
- DMS replication instances should have automatic minor version upgrade enabled.
- DMS replication tasks should have logging enabled for both source and target databases.

## DocumentDB
- DocumentDB clusters should have an adequate backup retention period.
- DocumentDB clusters should have deletion protection enabled.
- DocumentDB clusters and instances should be encrypted at rest.
- DocumentDB instance logging should be enabled.
- DocumentDB manual cluster snapshots should not be public.

## DRS (Disaster Recovery Service)
- DRS jobs should be enabled.

## DynamoDB
- DynamoDB table should have deletion protection enabled.
- DynamoDB table should be encrypted with AWS KMS.

## EBS (Elastic Block Store)
- Attached EBS volumes should have delete-on-termination enabled.
- Attached EBS volumes should have encryption enabled.
- EBS snapshots should be encrypted.
- EBS volumes should be in a backup plan and protected by it.
- EBS volume snapshots should exist.

## EC2 (Elastic Compute Cloud)
- Ensure EC2 AMIs are encrypted and are not older than 90 days.
- EC2 AMIs should restrict public access.
- EC2 Client VPN endpoints should have client connection logging enabled.
- Ensure EBS volumes attached to an EC2 instance are marked for deletion upon instance termination.
- EC2 instance should have EBS optimization enabled.
- EC2 instances should not use key pairs in running state.
- EC2 instances should not have high-level findings in inspector scans.
- EC2 instance IAM roles should avoid overly permissive access and write access to critical configurations and services.
- Ensure no EC2 instances are older than 180 days.
- EC2 instances should have termination protection enabled.
- Paravirtual EC2 instance types should not be used.
- EC2 launch templates should not assign public IPs to network interfaces.
- Ensure unused ENIs are removed.
- Instances stopped for over 90 days should be removed.
- EC2 transit gateways should have auto-accept shared attachments disabled.

## ECR (Elastic Container Registry)
- ECR private repositories should have tag immutability configured.

## ECS (Elastic Container Service)
- ECS cluster container instances should have a connected agent.
- ECS clusters should be encrypted at rest.
- ECS clusters should have active services.
- At least one instance should be registered with ECS clusters.
- ECS services should be attached to a load balancer.
- ECS services should not have public IP addresses assigned automatically.
- ECS containers should run as non-privileged.
- ECS task definitions should not share the host's process namespace or use the root user.

## EFS (Elastic File System)
- EFS access points should enforce root directory and user identity.
- EFS file systems should be encrypted with CMK and enforce SSL.
- EFS file systems should be included in and protected by a backup plan.
- EFS file systems should restrict public access.

## EKS (Elastic Kubernetes Service)
- EKS clusters endpoint public access should be restricted.
- EKS clusters should not be configured within a default VPC.
- EKS clusters should not use multiple security groups.
- EKS clusters should run on a supported Kubernetes version.

## ElastiCache
- Minor version upgrades should be automatically applied to ElastiCache for Redis clusters.
- ElastiCache clusters should not use default subnet group or public subnet.
- ElastiCache for Redis replication groups should have automatic failover enabled and be encrypted at rest and in transit.

## Elastic Beanstalk
- Elastic Beanstalk should stream logs to CloudWatch.
- Elastic Beanstalk environment should have managed updates enabled.

## ELB (Elastic Load Balancing)
- Classic load balancers should have connection draining enabled.
- ELB application load balancers should have deletion protection and defensive desync mitigation mode enabled.
- ELB secured listener certificates should not expire soon.
- ELB load balancers should have at least one outbound rule and use listeners.
- ELB classic load balancers should have at least one registered instance and inbound/outbound rules.
- ELB network load balancers should have TLS listener security policy configured.
- ELB listeners' SSL/TLS protocol version should be checked.

## EMR (Elastic MapReduce)
- EMR clusters should have encryption at rest and in transit, client-side encryption with CMK, server-side encryption with KMS, and local disk encryption.
- EMR clusters should have security configuration enabled.



## AWS Security Compliance Checklist

### All Controls
- Security contact information should be provided for an AWS account

### ACM (AWS Certificate Manager)
- Ensure ACM certificates are not in a failed state
- Ensure ACM certificates are not in pending validation state
- ACM certificates should not use wildcard certificates
- Ensure all expired ACM certificates are removed
- RSA certificates managed by ACM should use a key length of at least 2,048 bits

### API Gateway
- API Gateway methods authorizer should be configured
- API Gateway methods request parameter should be validated
- API Gateway REST API public endpoints should be configured with authorizer
- API Gateway routes should specify an authorization type
- API Gateway V2 authorizer should be configured
- API Gateway REST API endpoint type should be configured to private
- API Gateway REST API stages should have AWS X-Ray tracing enabled
- Access logging should be configured for API Gateway V2 Stages

### AppStream
- AppStream fleet default internet access should be disabled
- AppStream fleet idle disconnect timeout should be set to less than or equal to 10 mins
- AppStream fleet max user duration should be set to less than 10 hours
- AppStream fleet session disconnect timeout should be set to less than or equal to 5 mins

### AppSync
- AppSync GraphQL API logging should be enabled

### Athena
- Athena workgroups should be encrypted at rest
- Athena workgroups should enforce configuration

### Auto Scaling
- EC2 auto scaling group launch configurations user data should not have any sensitive data
- Auto Scaling groups should not have any suspended processes
- Ensure EC2 Auto Scaling Groups propagate tags to EC2 instances that it launches
- EC2 Auto Scaling groups should use EC2 launch templates
- EC2 auto scaling group launch configurations should not have metadata response hop limit greater than 1
- Auto Scaling group should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)
- EC2 auto scaling groups should use multiple instance types in multiple availability zones

### Backup
- Backup plan min frequency and min retention check
- Backup plan should exist in a region
- Backup report plan should exist in a region where backup plan is enabled
- Backup vaults should exist in a region

### CloudFormation
- CloudFormation stacks differ from the expected configuration
- CloudFormation stacks should have notifications enabled
- CloudFormation stacks should have rollback enabled
- CloudFormation stacks termination protection should be enabled

### CloudFront
- CloudFront distributions should have a default root object configured
- CloudFront distributions should require encryption in transit
- CloudFront distributions should have field level encryption enabled
- CloudFront distributions should have geo restriction enabled
- CloudFront distributions should have the latest TLS version
- CloudFront distributions should not point to non-existent S3 origins
- CloudFront distributions should encrypt traffic to non-S3 origins
- CloudFront distributions should have origin access identity enabled
- CloudFront distributions should use SNI to serve HTTPS requests
- CloudFront distributions should use custom SSL/TLS certificates
- CloudFront distributions should use secure SSL cipher

### CloudTrail
- CloudTrail trails should be enabled in all regions
- CloudTrail multi-region trails should be integrated with CloudWatch logs
- Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
- Ensure Object-level logging for read events is enabled for S3 bucket
- Ensure Object-level logging for write events is enabled for S3 bucket
- CloudTrail trail S3 buckets MFA delete should be enabled
- At least one CloudTrail trail should be enabled in the AWS account
- CloudTrail trails should have insight selectors and logging enabled

### CloudWatch
- CloudWatch alarm action should be enabled
- Log group encryption at rest should be enabled
- Ensure log metric filter and alarm exist for S3 bucket policy changes
- Ensure log metric filter and alarm exist for CloudTrail configuration changes
- Ensure log metric filter and alarm exist for AWS Config configuration changes
- Ensure log metric filter and alarm exist for AWS Management Console authentication failures
- Ensure log metric filter and alarm exist for AWS Management Console sign-in without MFA
- Ensure log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys
- Ensure log metric filter and alarm exist for IAM policy changes
- Ensure log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
- Ensure log metric filter and alarm exist for changes to network gateways
- Ensure AWS Organizations changes are monitored
- Ensure log metric filter and alarm exist for usage of 'root' account
- Ensure log metric filter and alarm exist for route table changes
- Ensure log metric filter and alarm exist for security group changes
- Ensure log metric filter and alarm exist for unauthorized API calls
- Ensure log metric filter and alarm exist for VPC changes

### CodeBuild
- CodeBuild project environments should not have privileged mode enabled
- CodeBuild GitHub or Bitbucket source repository URLs should use OAuth

### CodeDeploy
- CodeDeploy deployment groups lambda all-at-once traffic shift should be disabled

### Config
- Config configuration recorder should not fail to deliver logs

### DAX
- DynamoDB Accelerator (DAX) clusters should be encrypted at rest

### Directory Service
- Directory Service certificates should not expire within 90 days
- Directory Service directories manual snapshots limit should not be less than 2
- Directory Service directories should have SNS notification enabled

### DLM (Data Lifecycle Manager)
- DLM EBS snapshot lifecycle policy should be enabled

### DMS (Database Migration Service)
- Ensure all expired DMS certificates are removed
- DMS endpoints should use SSL
- DMS replication instances should have automatic minor version upgrade enabled
- DMS replication tasks for the source database should have logging enabled
- DMS replication tasks for the target database should have logging enabled

### DocumentDB
- AWS DocumentDB clusters should have an adequate backup retention period
- DocumentDB clusters should have deletion protection enabled
- AWS DocumentDB clusters should be encrypted at rest
- DocumentDB instance should be encrypted at rest
- DocumentDB instance logging should be enabled
- Amazon DocumentDB manual cluster snapshots should not be public

### DRS (Disaster Recovery Service)
- DRS jobs should be enabled

### DynamoDB
- DynamoDB table should have deletion protection enabled
- DynamoDB table should be encrypted with AWS KMS

### EBS (Elastic Block Store)
- Attached EBS volumes should have delete on termination enabled
- Attached EBS volumes should have encryption enabled
- EBS snapshots should be encrypted
- EBS volumes should be in a backup plan
- EBS volumes should be protected by a backup plan
- EBS volume snapshots should exist

### EC2 (Elastic Compute Cloud)
- Ensure Images (AMI's) are encrypted
- Ensure Images (AMI) are not older than 90 days
- EC2 AMIs should restrict public access
- EC2 Client VPN endpoints should have client connection logging enabled
- Ensure EBS volumes attached to an EC2 instance are marked for deletion upon instance termination
- EC2 instance should have EBS optimization enabled
- EC2 instances should not use key pairs in running state
- EC2 instances high-level findings should not be there in inspector scans
- EC2 instance IAM should not allow pass role and lambda invoke function access.
- EC2 instance IAM role should not be attached with credentials exposure access
- EC2 instance IAM role should not allow to alter critical S3 permissions configuration
- EC2 instance IAM role should not allow cloud log tampering access
- EC2 instance IAM role should not allow data destruction access
- EC2 instance IAM role should not allow database management write access
- EC2 instance IAM role should not allow defense evasion impact of AWS security services access
- EC2 instance IAM role should not allow destruction KMS access
- EC2 instance IAM role should not allow destruction RDS access
- EC2 instance IAM role should not allow elastic IP hijacking access.
- EC2 instance IAM role should not allow management level access
- EC2 instance IAM role should not allow new group creation with attached policy access
- EC2 instance IAM role should not allow new role creation with attached policy access
- EC2 instance IAM role should not allow new user creation with attached policy access
- EC2 instance IAM role should not allow organization write access
- EC2 instance IAM role should not allow privilege escalation risk access
- EC2 instance IAM role should not allow security group write access
- EC2 instance IAM role should not allow write access to resource-based policies
- EC2 instance IAM role should not allow write permission on critical S3 configuration
- EC2 instance IAM role should not allow write-level access
- Ensure no AWS EC2 Instances are older than 180 days
- AWS EC2 instances should have termination protection enabled
- Paravirtual EC2 instance types should not be used
- AWS EC2 launch templates should not assign public IPs to network interfaces
- Ensure unused ENIs are removed
- Ensure instances stopped for over 90 days are removed
- EC2 transit gateways should have auto-accept shared attachments disabled

### ECR (Elastic Container Registry)
- ECR private repositories should have tag immutability configured

### ECS (Elastic Container Service)
- ECS cluster container instances should have connected agent
- ECS clusters encryption at rest should be enabled
- ECS cluster should be configured with active services
- At least one instance should be registered with ECS cluster
- ECS services should be attached to a load balancer
- AWS ECS services should not have public IP addresses assigned to them automatically
- ECS containers should run as non-privileged
- ECS task definitions should not share the host's process namespace
- ECS task definitions should not use root user.

### EFS (Elastic File System)
- EFS file systems should have automatic backups enabled
- EFS file systems should have lifecycle management policies enabled
- EFS file systems should not have unrestricted access

### EKS (Elastic Kubernetes Service)
- Ensure that all the provisioned EKS clusters have 'kubernetes.io/cluster' tag with the value of 'shared' or 'shared'
- Ensure that all the provisioned EKS clusters have `eks.amazonaws.com/cluster-shared` tag with the value of 'shared' or 'shared'
- Ensure that all the provisioned EKS clusters have private networking disabled
- Ensure that all the provisioned EKS clusters have endpoint access logging enabled
- Ensure that all the provisioned EKS clusters have the update in progress
- Ensure that all the provisioned EKS clusters have update failed
- Ensure that all the provisioned EKS clusters have creation completed
- Ensure that all the provisioned EKS clusters have execution role active
- Ensure that all the provisioned EKS clusters have execution roles active
  ``
