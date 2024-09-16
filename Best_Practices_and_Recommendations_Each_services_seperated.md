# AWS Security Best Practices

## Elasticsearch
- Elasticsearch domains should have audit logging enabled.
- Elasticsearch domains should have Cognito authentication enabled.
- Elasticsearch domains should have at least three data nodes.
- Elasticsearch domains should be configured with at least three dedicated master nodes.
- Connections to Elasticsearch domains should be encrypted using TLS 1.2.
- Elasticsearch domain error logging to CloudWatch Logs should be enabled.
- Elasticsearch domains should have internal user database enabled.

## EventBridge
- EventBridge custom event buses should have a resource-based policy attached.

## FSx
- FSx for OpenZFS file systems should be configured to copy tags to backups and volumes.

## Glacier
- Glacier vault should restrict public access.

## Glue
- Glue connection SSL should be enabled.
- Glue data catalog metadata encryption should be enabled.
- Glue data catalog connection password encryption should be enabled.

## GuardDuty
- GuardDuty Detector should be centrally configured.
- GuardDuty findings should be archived.
- GuardDuty Detector should not have high severity findings.

## IAM
- Ensure that IAM Access Analyzer is enabled for all regions.
- IAM Access Analyzer should be enabled without findings.
- Ensure IAM password policy requires a minimum length of 14 or greater.
- Ensure IAM password policy requires at least one lowercase letter.
- Ensure IAM password policy requires at least one number.
- Ensure IAM password policy requires at least one symbol.
- Ensure IAM password policy requires at least one uppercase letter.
- Ensure IAM password policy prevents password reuse.
- Password policies for IAM users should have strong configurations with a minimum length of 8 or greater.
- Ensure IAM policy should not grant full access to service.
- IAM unattached custom policy should not have statements with admin access.
- IAM groups, users, and roles should not have any inline policies.
- IAM inline policy should not have administrative privileges.
- IAM AWS managed policies should be attached to IAM roles.
- Ensure IAM policies that allow full "*:*" administrative privileges are not attached.
- IAM policies should not allow full '*' administrative privileges.
- IAM roles should not have any assume role policies attached.
- IAM custom policy should not have overly permissive STS role assumption.
- Ensure inline policies attached to IAM users, roles, and groups should not allow blocked actions on KMS keys.
- IAM policy should not grant full access to CloudTrail service.
- IAM policy should not grant full access to KMS service.
- IAM policy should be in use.
- IAM roles should not have read-only access for external AWS accounts.
- Ensure IAM role is not attached with AdministratorAccess policy.
- IAM roles that have not been used in 60 days should be removed.
- Eliminate use of the 'root' user for administrative and daily tasks.
- IAM Security Audit role should be created to conduct security audits.
- Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed.
- Ensure IAM users with access keys unused for 45 days or greater are disabled.
- Ensure IAM users are assigned access keys and passwords at setup.
- Ensure IAM users with console access unused for 45 days or greater are disabled.
- Ensure access to AWSCloudShellFullAccess is restricted.
- IAM users should be in at least one group.
- IAM user should not have any inline or attached policies.
- Ensure IAM policies are attached only to groups or roles.
- Ensure there is only one active access key available for any single IAM user.
- Ensure credentials unused for 45 days or greater are disabled.

## Kinesis
- Kinesis Firehose delivery streams should have server-side encryption enabled.
- Kinesis streams should be encrypted with CMK.
- Kinesis streams should have server-side encryption enabled.

## KMS
- KMS key should be in use.
- KMS key decryption should be restricted in IAM customer-managed policy.
- KMS key decryption should be restricted in IAM inline policy.

## Lambda
- Ensure CloudWatch Lambda Insights is enabled.
- Lambda functions CORS configuration should not allow all origins.
- Lambda functions should be configured with a dead-letter queue.
- Ensure encryption in transit is enabled for Lambda environment variables.
- Lambda functions should restrict public URL.
- Lambda functions tracing should be enabled.
- Lambda functions should use the latest runtimes.
- Lambda functions variable should not have any sensitive data.

## Lightsail
- Disable IPv6 Networking if not in use within your organization.
- Ensure RDP is restricted to only IP addresses that should have this access.
- Disable SSH and RDP ports for Lightsail instances when not needed.
- Ensure SSH is restricted to only IP addresses that should have this access.

## MQ
- MQ brokers should restrict public access.

## MSK
- MSK clusters should be encrypted in transit among broker nodes.

## Neptune
- Neptune DB clusters should publish audit logs to CloudWatch Logs.
- Neptune DB clusters should have automated backups enabled.
- Neptune DB clusters should be configured to copy tags to snapshots.
- Neptune DB clusters should have deletion protection enabled.
- Neptune DB clusters should be encrypted at rest.
- Neptune DB clusters should have IAM database authentication enabled.
- Neptune DB clusters should not use public_subnet.
- Neptune DB cluster snapshots should be encrypted at rest.
- Neptune DB cluster snapshots should not be public.

## Network Firewall
- Network Firewall firewalls should have deletion protection enabled.
- Network Firewall firewall should be in a VPC.
- Network Firewall logging should be enabled.
- The default stateless action for Network Firewall policies should be drop or forward for fragmented packets.
- The default stateless action for Network Firewall policies should be drop or forward for full packets.
- Network Firewall policies should have at least one rule group associated.
- Stateless network firewall rule group should not be empty.

## OpenSearch
- OpenSearch domains Cognito authentication should be enabled for Kibana.
- OpenSearch domains should have at least three data nodes.
- OpenSearch domains should have fine-grained access control enabled.
- OpenSearch domains internal user database should be disabled.
- OpenSearch domains logs to AWS CloudWatch Logs.
- OpenSearch domains should be updated to the latest service software version.

## Organization
- Ensure Tag Policies are enabled.

## Private Certificate Authority
- AWS Private CA root certificate authority should be disabled.

## RDS
- Aurora MySQL DB clusters should publish audit logs to CloudWatch Logs.
- RDS Aurora PostgreSQL clusters should not be exposed to local file read vulnerability.
- RDS DB clusters should have automatic minor version upgrade enabled.
- RDS DB clusters should be configured to copy tags to snapshots.
- RDS clusters should have deletion protection enabled.
- RDS DB clusters should be encrypted with CMK.
- RDS DB clusters should be encrypted at rest.
- An RDS event notifications subscription should be configured for critical cluster events.
- IAM authentication should be configured for RDS clusters.
- RDS database clusters should use a custom administrator username.
- RDS DB instance and cluster enhanced monitoring should be enabled.
- RDS databases and clusters should not use a database engine default port.
- RDS DB instances backup retention period should be greater than or equal to 7 days.
- RDS DB instances CA certificates should not expire within the next 7 days.
- RDS DB instances connections should be encrypted.
- RDS DB instances should be configured to copy tags to snapshots.
- RDS DB instances should have deletion protection enabled.
- An RDS event notifications subscription should be configured for critical database instance events.
- RDS DB instances should have IAM authentication enabled.
- RDS DB instances should be in a backup plan.
- RDS instances should be deployed in a VPC.
- RDS database instances should use a custom administrator username.
- RDS DB instances should not use public subnet.
- RDS PostgreSQL DB instances should not be exposed to local file read vulnerability.
- RDS DB instance should be protected by a backup plan.
- An RDS event notifications subscription should be configured for critical database parameter group events.
- An RDS event notifications subscription should be configured for critical database security group events.

## Redshift
- AWS Redshift clusters should have automatic snapshots enabled.
- AWS Redshift should have automatic upgrades to major versions enabled.
- Redshift clusters should be encrypted with CMK.
- Redshift cluster audit logging and encryption should be enabled.
- AWS Redshift clusters should not use the default Admin username.
- Redshift clusters should not use the default database name.

## Route 53
- Route 53 domains auto-renew should be enabled.
- Route 53 domains should not expire within the next 30 days.
- Route 53 domains should not expire within the next 7 days.
- Route 53 domains should not be expired.

## S3
- **S3 access points** should have block public access settings enabled.
- **S3 bucket default encryption** should be enabled with KMS.
- **S3 buckets** should have event notifications enabled.
- **S3 buckets** should have lifecycle policies configured.
- Ensure **MFA Delete** is enabled on S3 buckets.
- **S3 bucket ACLs** should not be accessible to all authenticated users.
- **S3 bucket object lock** should be enabled.
- AWS **S3 permissions** granted to other AWS accounts in bucket policies should be restricted.
- Ensure all data in AWS S3 has been discovered, classified, and secured when required.
- **S3 buckets** should prohibit public read access.
- **S3 buckets** static website hosting should be disabled.
- **S3 buckets** with versioning enabled should have lifecycle policies configured.
- **S3 public access** should be blocked at bucket levels.
- **S3 public access** should be blocked at account and bucket levels.

## SageMaker
- SageMaker notebooks should have encryption enabled.
- SageMaker endpoints should be configured with encryption.
- SageMaker models should use private endpoints.

## Secrets Manager
- **Secrets Manager secrets** should be rotated within a specified number of days.
- **Secrets Manager secrets** should be encrypted using CMK.
- Remove unused **Secrets Manager secrets**.

## Security Hub
- **AWS Security Hub** should be enabled for an AWS Account.

## Step Functions
- **Step Functions state machines** should have logging turned on.

## SNS
- Logging of delivery status should be enabled for notification messages sent to a topic.
- **SNS topic policies** should prohibit cross-account access.
- **SNS topic policies** should prohibit publishing access.
- **SNS topic policies** should prohibit subscription public access.

## SQS
- **SQS queues** should be configured with a dead-letter queue.
- AWS **SQS queues** should be encrypted at rest.
- **SQS queues** should be encrypted with KMS CMK.

## SSM
- **SSM parameters encryption** should be enabled.

## VPC
- **VPC** should be configured to use VPC endpoints.
- **VPC endpoint services** should have acceptance required enabled.
- **VPC gateway endpoints** should restrict public access.
- **VPC internet gateways** should be attached to authorized VPC.
- **VPCs** should exist in multiple regions.
- **VPCs** should be in use.
- **VPC peering connections** should not be allowed in cross-account scenarios.
- **VPC peering connection route tables** should have least privilege.
- **VPC route table** should restrict public access to IGW.
- **VPC security groups** should restrict ingress from `0.0.0.0/0` or `::/0` to Cassandra ports `7199`, `9160`, or `8888`.
- **VPC security groups** should restrict ingress from `0.0.0.0/0` or `::/0` to Memcached port `11211`.
- **VPC security groups** should restrict ingress from `0.0.0.0/0` or `::/0` to MongoDB ports `27017` and `27018`.
- **VPC security groups** should restrict ingress from `0.0.0.0/0` or `::/0` to Oracle ports `1521` or `2483`.
- **VPC security groups** should be associated with at least one ENI.
- **VPC security groups** should restrict use of 'launch-wizard' security groups.
- Ensure no security groups allow ingress from `::/0` to remote server administration ports.
- Ensure no security groups allow ingress from `0.0.0.0/0` to remote server administration ports.
- **VPC security groups** should restrict ingress Kibana port access from `0.0.0.0/0`.
- Ensure no security groups allow ingress from `0.0.0.0/0` to port `3389`.
- **VPC security groups** should restrict ingress SSH access from `0.0.0.0/0`.
- Unused **EC2 security groups** should be removed.
- **VPC subnets** should exist in multiple availability zones.
- **VPCs** should have both public and private subnets configured.

------------------------------------------------------------------------------------------------------------

## WAF
- **WAF regional rule** should have at least one condition.
- **WAF regional rule group** should have at least one rule attached.
- **WAF regional web ACL** should have at least one rule or rule group attached.
- **WAF global rule** should have at least one condition.
- **WAF web ACL** should be associated with an Application Load Balancer, API Gateway stage, or CloudFront distributions.

## WAFv2
- **AWS WAF rules** should have CloudWatch metrics enabled.
- A **WAFv2 web ACL** should have at least one rule or rule group.

## WorkSpaces
- **WorkSpaces root and user volume encryption** should be enabled.

# AWS Well-Architected Framework

## Operational Excellence

### OPS04: How do you design your workload so that you can understand its state?
- **BP01:** Implement application telemetry.
- Auto Scaling groups with a load balancer should use health checks.
- **BP02:** Implement and configure workload telemetry.
- At least one enabled trail should be present in a region.
- **CloudWatch alarm** should have an action configured.

### OPS05: How do you reduce defects, ease remediation, and improve flow into production?
- **BP03:** Use configuration management systems.
- **AWS Config** should be enabled.
- **BP05:** Perform patch management.
- **SSM managed instance patching** should be compliant.

**Reliability**

- **REL01 How do you manage service quotas and constraints?**
  - BP03 Accommodate fixed service quotas and constraints through architecture
    - Lambda functions concurrent execution limit configured

- **REL02 How do you plan your network topology?**
  - BP01 Use highly available network connectivity for your workload public endpoints
    - CloudFront distributions should have origin failover configured
    - ELB application, network, and gateway load balancers should span multiple availability zones
    - ELB classic load balancers should have cross-zone load balancing enabled
    - ELB classic load balancers should span multiple availability zones
    - Lambda functions should operate in more than one availability zone
    - RDS DB clusters should be configured for multiple Availability Zones
    - RDS DB instance multiple az should be enabled
    - S3 bucket cross-region replication should be enabled
  - BP02 Provision redundant connectivity between private networks in the cloud and on-premises environments
    - ECS cluster instances should be in a VPC
    - Both VPN tunnels provided by AWS Site-to-Site VPN should be in UP status
  - REL06 How do you monitor workload resources?
    - BP01 Monitor all components for the workload
      - EC2 instance detailed monitoring should be enabled
      - CodeBuild projects should have logging enabled
      - ECS task definitions should have logging enabled
      - S3 bucket logging should be enabled
      - WAF web ACL logging should be enabled
    - BP02 Define and calculate metrics (Aggregation)
      - Elastic Beanstalk enhanced health reporting should be enabled
  - REL07 How do you design your workload to adapt to changes in demand?
    - BP01 Use automation when obtaining or scaling resources
      - EC2 auto scaling groups should cover multiple availability zones
      - DynamoDB table auto scaling should be enabled
  - REL08 How do you implement change?
    - BP05 Deploy changes with automation
  - REL09 How do you back up data?
    - BP02 Secure and encrypt backups
      - EBS volume encryption at rest should be enabled
    - BP03 Perform data backup automatically
      - Backup recovery points manual deletion should be disabled
      - Backup recovery points should not expire before retention period
      - DynamoDB tables should be in a backup plan
      - DynamoDB table point-in-time recovery should be enabled
      - DynamoDB table should be protected by backup plan
      - EC2 instances should be protected by backup plan
      - ElastiCache Redis cluster automatic backup should be enabled with retention period of 15 days or greater
      - FSx file system should be protected by backup plan
      - RDS Aurora clusters should have backtracking enabled
      - RDS Aurora clusters should be protected by backup plan
      - RDS DB instance backup should be enabled

**Security**

- **SEC01 How do you securely operate your workload?**
  - BP01 Separate workloads using accounts
  - BP02 Secure account root user and properties
    - IAM root user hardware MFA should be enabled
    - IAM root user MFA should be enabled
  - BP06 Automate testing and validation of security controls in pipelines
  - BP08 Evaluate and implement new security services and features regularly
    - CodeBuild project plaintext environment variables should not contain sensitive AWS values

- **SEC02 How do you manage identities for people and machines?**
  - BP01 Use strong sign-in mechanisms
    - IAM password policies for users should have strong configurations
    - IAM users should have hardware MFA enabled
    - IAM user MFA should be enabled
    - IAM users with console access should have MFA enabled
    - IAM root user should not have access keys
    - IAM administrator users should have MFA enabled
    - SageMaker notebook instances root access should be disabled
  - BP02 Use temporary credentials
    - Secrets Manager secrets should be rotated within specific number of days
    - Secrets Manager secrets should be rotated as per the rotation schedule
  - BP03 Store and use secrets securely
    - CloudFormation stacks outputs should not have any secrets
    - EC2 instances user data should not have secrets
    - ECS task definition containers should not have secrets passed as environment variables
  - BP05 Audit and rotate credentials periodically
    - IAM user access keys should be rotated at least every 90 days
    - KMS CMK rotation should be enabled
    - Secrets Manager secrets should have automatic rotation enabled

- **SEC03 How do you manage permissions for people and machines?**
  - BP01 Define access requirements
    - ECS task definition container definitions should be checked for host mode
    - CloudWatch should not allow cross-account sharing
  - BP02 Grant least privilege access
    - ECS containers should be limited to read-only access to root filesystems
    - EMR cluster Kerberos should be enabled
  - BP03 Establish emergency access process
    - IAM groups should have at least one user
    - Ensure managed IAM policies should not allow blocked actions on KMS keys
  - BP04 Reduce permissions continuously
    - IAM policy should not have statements with admin access
  - BP05 Define permission guardrails for your organization
  - BP06 Manage access based on lifecycle
    - IAM user credentials that have not been used in 90 days should be disabled
    - Log group retention period should be at least 365 days
    - CodeBuild projects should not be unused for 90 days or greater
    - VPC EIPs should be associated with an EC2 instance or ENI
    - ECR repositories should have lifecycle policies configured
    - Ensure IAM password policy expires passwords within 90 days or less
  - BP07 Analyze public and cross-account access
    - EC2 instances should not have a public IP address
    - EMR cluster master nodes should not have public IP addresses
    - EMR public access should be blocked at account level
    - Lambda functions should restrict public access
    - RDS DB instances should prohibit public access
    - RDS snapshots should prohibit public access
    - KMS CMK policies should prohibit public access
    - Redshift clusters should prohibit public access
    - S3 bucket policy should prohibit public access
    - S3 buckets should prohibit public write access
    - Ensure the S3 bucket CloudTrail logs to is not publicly accessible
    - ECR repositories should prohibit public access
    - ELB load balancers should prohibit public access
    - S3 public access should be blocked at account level
    - SNS topic policies should prohibit public access
    - SQS queue policies should prohibit public access
    - SSM documents should not be public
  - BP08 Share resources securely within your organization
    - Secrets Manager secrets that have not been used in 90 days should be removed
    - CodeBuild projects should not use a user-controlled buildspec

- **SEC04 How do you detect and investigate security events?**
  - BP01 Configure service and application logging
    - API Gateway stage logging should be enabled
    - OpenSearch domains should have audit logging enabled.
    - CloudTrail trails should be integrated with CloudWatch logs
    - All S3 buckets should log S3 data events in CloudTrail
    - ACM certificates should have transparency logging enabled
    - Lambda functions CloudTrail logging should be enabled
    - CloudFront distributions access logs should be enabled
    - Ensure that Object-level logging for write events is enabled for S3 bucket
    - Ensure that Object-level logging for read events is enabled for S3 bucket
    - EKS clusters should have control plane audit logging enabled
    - RDS DB instances should be integrated with CloudWatch logs
    - Route 53 zones should have query logging enabled
    - S3 buckets object logging should be enabled
  - BP02 Analyze logs, findings, and metrics centrally
    - AWS Config should be enabled
  - BP03 Automate response to events
    - Elasticsearch domain should send logs to CloudWatch
    - ELB application and classic load balancer logging should be enabled
    - At least one multi-region AWS CloudTrail should be present in an account
    - Database logging should be enabled
    - Logging should be enabled on AWS WAFv2 regional and global web access control list (ACLs)

- **SEC05 How do you protect your network resources?**
  - BP01 Create network layers
    - ES domains should be in a VPC
    - OpenSearch domains should be in a VPC
    - EC2 instances should be in a VPC
    - AWS Redshift enhanced VPC routing should be enabled
    - ELB application load balancers should have Web Application Firewall (WAF) enabled
    - API Gateway stage should be associated with WAF
    - CloudFront distributions should have AWS WAF enabled
    - EKS clusters endpoint should restrict public access
    - SageMaker models should have network isolation enabled
    - SageMaker models should be in a VPC
    - SageMaker notebook instances should be in a VPC
    - SageMaker training jobs should have network isolation enabled
    - SageMaker training jobs should be in VPC
  - BP02 Control traffic at all layers
    - EBS snapshots should not be publicly restorable
    - SageMaker notebook instances should not have direct internet access
    - VPC subnet auto assign public IP should be disabled
    - S3 buckets access control lists (ACLs) should not be used to manage user access to buckets
    - Ensure MFA Delete is enabled on S3 buckets
  - BP03 Automate network protection
    - DMS replication instances should not be publicly accessible
    - Auto Scaling launch config public IP should be disabled
    - Network ACLs should not allow ingress from 0.0.0.0/

0 for all ports
    - Ensure security groups used by EC2 instances do not have unrestricted access
    - ECR repositories should have lifecycle policies configured
  - BP04 Use network monitoring and response tools
    - EC2 instances should have Security Hub enabled
    - VPC flow logs should be enabled
    - Ensure that VPC security groups and NACLs have the minimum necessary access
    - VPC flow logs should be enabled on private VPCs
    - VPC flow logs should be enabled on public VPCs

**Performance Efficiency**

- **PER01 How do you select the appropriate compute resources?**
  - BP01 Use compute resources designed for the workload
    - EC2 instance types should match workload requirements
  - BP02 Choose cost-effective resources
    - Use cost-effective EC2 instances based on usage
    - Use Lambda functions for specific workload tasks
  - BP03 Optimize computing resources for your workload
    - Use EC2 Reserved Instances where appropriate
    - Use EC2 Spot Instances where appropriate
    - Use AWS Fargate for containerized workloads
    - Use ECS cluster capacity providers for spot instances
    - Enable ECS Service Auto Scaling

- **PER02 How do you manage and optimize storage resources?**
  - BP01 Choose the appropriate storage type for your workload
    - EBS volumes should be sized based on the workload requirements
    - S3 storage classes should be used based on the data access patterns
    - Use DynamoDB for high performance NoSQL databases
  - BP02 Optimize storage performance
    - EBS volume IOPS should match the workload performance needs
    - Use S3 storage class analysis to optimize storage cost

- **PER03 How do you manage and optimize database resources?**
  - BP01 Choose the right database engine and instance types for your workload
    - Use RDS for managed relational databases
    - Use DynamoDB for NoSQL workloads
    - Use Aurora for high-performance and high-availability needs
  - BP02 Optimize database performance
    - Use RDS Performance Insights to monitor database performance
    - Use DynamoDB Accelerator (DAX) for faster in-memory caching
    - Enable RDS and DynamoDB auto scaling

**Cost Optimization**

- **COS01 How do you understand and monitor costs and usage?**
  - BP01 Monitor costs and usage regularly
    - Enable AWS Cost Explorer
    - Enable AWS Budgets
    - Use AWS Cost and Usage Reports
  - BP02 Implement cost controls
    - Set up alerts for cost and usage thresholds
    - Enable AWS Cost Anomaly Detection

- **COS02 How do you manage and optimize your resources?**
  - BP01 Use cost-effective resource types and pricing models
    - Use EC2 Reserved Instances and Savings Plans where appropriate
    - Use AWS Fargate and Lambda for serverless computing
  - BP02 Optimize cost of resources
    - Review and optimize storage and compute usage regularly
    - Use Trusted Advisor for cost optimization recommendations
