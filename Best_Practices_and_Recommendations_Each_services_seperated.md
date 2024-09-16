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

