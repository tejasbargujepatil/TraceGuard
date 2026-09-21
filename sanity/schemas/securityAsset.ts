// Sanity schema: SecurityAsset
// Represents a cloud infrastructure asset (S3 bucket, IAM role, EC2 instance, etc.)

import { defineType, defineField } from 'sanity';

export const securityAsset = defineType({
  name: 'securityAsset',
  title: 'Security Asset',
  type: 'document',
  icon: () => '🖥️',
  fields: [
    defineField({
      name: 'name',
      title: 'Name',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'assetId',
      title: 'Asset ID',
      type: 'string',
      description: 'e.g. arn:aws:s3:::prod-customer-backups',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'provider',
      title: 'Cloud Provider',
      type: 'string',
      options: {
        list: [
          { title: 'AWS', value: 'aws' },
          { title: 'GCP', value: 'gcp' },
          { title: 'Azure', value: 'azure' },
          { title: 'On-Premise', value: 'on-prem' },
        ],
      },
      initialValue: 'aws',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'service',
      title: 'Service',
      type: 'string',
      description: 'e.g. S3, IAM, EC2, RDS, CloudTrail, Lambda, SecurityGroup',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'environment',
      title: 'Environment',
      type: 'string',
      options: {
        list: [
          { title: 'Production', value: 'production' },
          { title: 'Staging', value: 'staging' },
          { title: 'Development', value: 'development' },
          { title: 'Unknown', value: 'unknown' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'description',
      title: 'Description',
      type: 'text',
      rows: 3,
    }),
    defineField({
      name: 'sensitivity',
      title: 'Data Sensitivity',
      type: 'string',
      options: {
        list: [
          { title: 'Restricted (PII / Sensitive)', value: 'restricted' },
          { title: 'Confidential', value: 'confidential' },
          { title: 'Internal', value: 'internal' },
          { title: 'Public', value: 'public' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'owner',
      title: 'Owner / Team',
      type: 'string',
    }),
    defineField({
      name: 'tags',
      title: 'Tags',
      type: 'array',
      of: [{ type: 'string' }],
    }),
    defineField({
      name: 'region',
      title: 'Region',
      type: 'string',
      description: 'e.g. us-east-1',
    }),
    defineField({
      name: 'accountId',
      title: 'Account ID',
      type: 'string',
    }),
    defineField({
      name: 'relatedAssets',
      title: 'Related Assets',
      type: 'array',
      of: [{ type: 'reference', to: [{ type: 'securityAsset' }] }],
      description: 'Other assets this asset has a relationship with.',
    }),
    defineField({
      name: 'source',
      title: 'Source',
      type: 'reference',
      to: [{ type: 'source' }],
    }),
    defineField({
      name: 'notes',
      title: 'Notes',
      type: 'text',
      rows: 2,
    }),
  ],
  preview: {
    select: {
      title: 'name',
      service: 'service',
      environment: 'environment',
      sensitivity: 'sensitivity',
    },
    prepare({ title, service, environment, sensitivity }) {
      const envIcon = environment === 'production' ? '🔴' : environment === 'staging' ? '🟡' : '🟢';
      return {
        title: `${envIcon} ${title}`,
        subtitle: `${service} · ${environment} · ${sensitivity}`,
      };
    },
  },
});
