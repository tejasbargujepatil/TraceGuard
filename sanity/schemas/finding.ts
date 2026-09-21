// Sanity schema: Finding
// A detected security misconfiguration or risk observation.
// This is the entry point for all investigations.

import { defineType, defineField } from 'sanity';

export const finding = defineType({
  name: 'finding',
  title: 'Finding',
  type: 'document',
  icon: () => '🚨',
  fields: [
    defineField({
      name: 'title',
      title: 'Title',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'findingId',
      title: 'Finding ID',
      type: 'string',
      description: 'e.g. F001, F002',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'severity',
      title: 'Severity',
      type: 'string',
      options: {
        list: [
          { title: '🔴 Critical', value: 'critical' },
          { title: '🟠 High', value: 'high' },
          { title: '🟡 Medium', value: 'medium' },
          { title: '🟢 Low', value: 'low' },
          { title: '⚪ Informational', value: 'info' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'category',
      title: 'Category',
      type: 'string',
      options: {
        list: [
          { title: 'Data Exposure', value: 'data_exposure' },
          { title: 'Identity & Access', value: 'iam' },
          { title: 'Network Security', value: 'network' },
          { title: 'Logging & Monitoring', value: 'logging' },
          { title: 'Encryption', value: 'encryption' },
          { title: 'Configuration Drift', value: 'drift' },
          { title: 'Compliance', value: 'compliance' },
        ],
      },
    }),
    defineField({
      name: 'affectedAsset',
      title: 'Affected Asset',
      type: 'reference',
      to: [{ type: 'securityAsset' }],
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'observedCondition',
      title: 'Observed Condition',
      type: 'text',
      rows: 3,
      description: 'The specific configuration or state observed.',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'evidence',
      title: 'Evidence',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'Factual observations supporting this finding.',
    }),
    defineField({
      name: 'relatedConfigurations',
      title: 'Related Configurations',
      type: 'array',
      of: [{ type: 'reference', to: [{ type: 'configuration' }] }],
    }),
    defineField({
      name: 'relatedFindings',
      title: 'Related Findings',
      type: 'array',
      of: [{ type: 'reference', to: [{ type: 'finding' }] }],
      description: 'Other findings that compound this risk.',
    }),
    defineField({
      name: 'potentialImpact',
      title: 'Potential Impact',
      type: 'text',
      rows: 3,
    }),
    defineField({
      name: 'status',
      title: 'Status',
      type: 'string',
      options: {
        list: [
          { title: 'Open', value: 'open' },
          { title: 'Investigating', value: 'investigating' },
          { title: 'Remediated', value: 'remediated' },
          { title: 'Accepted Risk', value: 'accepted' },
          { title: 'False Positive', value: 'false_positive' },
        ],
      },
      initialValue: 'open',
    }),
    defineField({
      name: 'discoveredAt',
      title: 'Discovered At',
      type: 'datetime',
    }),
  ],
  preview: {
    select: {
      title: 'title',
      findingId: 'findingId',
      severity: 'severity',
      status: 'status',
    },
    prepare({ title, findingId, severity, status }) {
      const severityIcon =
        severity === 'critical' ? '🔴' :
        severity === 'high' ? '🟠' :
        severity === 'medium' ? '🟡' :
        severity === 'low' ? '🟢' : '⚪';
      return {
        title: `${severityIcon} [${findingId}] ${title}`,
        subtitle: `Status: ${status}`,
      };
    },
  },
});
