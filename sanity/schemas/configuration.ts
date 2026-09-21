// Sanity schema: Configuration
// Observed configuration snapshot for a security asset.
// Captures both the observed and expected values, enabling drift detection.

import { defineType, defineField } from 'sanity';

export const configuration = defineType({
  name: 'configuration',
  title: 'Configuration',
  type: 'document',
  icon: () => '⚙️',
  fields: [
    defineField({
      name: 'asset',
      title: 'Asset',
      type: 'reference',
      to: [{ type: 'securityAsset' }],
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'setting',
      title: 'Setting Name',
      type: 'string',
      description: 'e.g. "PublicAccessBlock", "MFAEnabled", "LoggingEnabled"',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'observedValue',
      title: 'Observed Value',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'expectedValue',
      title: 'Expected Value',
      type: 'string',
      description: 'What the value should be per policy.',
    }),
    defineField({
      name: 'status',
      title: 'Compliance Status',
      type: 'string',
      options: {
        list: [
          { title: '✅ Compliant', value: 'compliant' },
          { title: '❌ Non-Compliant', value: 'non_compliant' },
          { title: '❓ Unknown', value: 'unknown' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'observedAt',
      title: 'Observed At',
      type: 'datetime',
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
        ],
      },
    }),
    defineField({
      name: 'source',
      title: 'Source Reference',
      type: 'reference',
      to: [{ type: 'source' }],
      description: 'The guidance or standard this expected value comes from.',
    }),
    defineField({
      name: 'notes',
      title: 'Notes',
      type: 'text',
      rows: 2,
    }),
    defineField({
      name: 'configPath',
      title: 'Config Path / Key',
      type: 'string',
      description: 'e.g. "S3.BucketAcl.PublicReadGrantee"',
    }),
  ],
  preview: {
    select: {
      assetName: 'asset.name',
      setting: 'setting',
      status: 'status',
      observedValue: 'observedValue',
    },
    prepare({ assetName, setting, status, observedValue }) {
      const icon = status === 'compliant' ? '✅' : status === 'non_compliant' ? '❌' : '❓';
      return {
        title: `${icon} ${assetName}: ${setting}`,
        subtitle: `Observed: ${observedValue}`,
      };
    },
  },
});
