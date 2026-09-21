// Barrel file — lists all AWS scanner keys
export const AWS_SERVICE_KEYS = ['s3','iam','ec2','vpc','rds','lambda','eks','cloudtrail','kms','secretsmanager','acm','dynamodb','sqs','sns','cloudfront','guardduty','securityhub','config','redshift','opensearch'] as const;
export type AWSServiceKey = typeof AWS_SERVICE_KEYS[number];