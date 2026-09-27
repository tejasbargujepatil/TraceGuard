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
      description: 'e.g. F001, s3-public-access::my-bucket',
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
          { title: 'SecurityHub', value: 'securityhub' },
        ],
      },
    }),
    // Optional reference — manual findings link to a securityAsset; auto-detected scan findings do not
    defineField({
      name: 'affectedAsset',
      title: 'Affected Asset',
      type: 'reference',
      to: [{ type: 'securityAsset' }],
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
    defineField({ name: 'discoveredAt', title: 'Discovered At', type: 'datetime' }),

    // ── Cloud scan metadata (populated by the scanner engine) ──────────────
    defineField({ name: 'cloudProvider', title: 'Cloud Provider', type: 'string', options: { list: ['aws', 'gcp'] } }),
    defineField({ name: 'cloudAccountId', title: 'Cloud Account Sanity ID', type: 'string' }),
    defineField({ name: 'resourceId', title: 'Resource ID', type: 'string' }),
    defineField({ name: 'resourceArn', title: 'Resource ARN / Full ID', type: 'string' }),
    defineField({ name: 'resourceName', title: 'Resource Name', type: 'string' }),
    defineField({ name: 'region', title: 'Region', type: 'string' }),
    defineField({ name: 'service', title: 'Service', type: 'string' }),
    defineField({ name: 'compliance', title: 'Compliance Frameworks', type: 'array', of: [{ type: 'string' }] }),
    defineField({ name: 'mitre', title: 'MITRE ATT&CK Techniques', type: 'array', of: [{ type: 'string' }] }),
    defineField({ name: 'remediationSummary', title: 'Remediation Summary', type: 'text', rows: 2 }),
    defineField({ name: 'remediationSteps', title: 'Remediation Steps', type: 'array', of: [{ type: 'string' }] }),
    defineField({ name: 'remediationAwsCli', title: 'AWS CLI Command', type: 'text', rows: 2 }),
    defineField({ name: 'remediationGcpCli', title: 'GCP CLI Command', type: 'text', rows: 2 }),
    defineField({ name: 'remediationTerraform', title: 'Terraform Snippet', type: 'text', rows: 3 }),
    defineField({ name: 'remediationConsoleUrl', title: 'Console URL', type: 'url' }),
    defineField({ name: 'remediationEffort', title: 'Estimated Effort', type: 'string', options: { list: ['minutes', 'hours', 'days'] } }),
    defineField({ name: 'operationalImpact', title: 'Operational Impact', type: 'string', options: { list: ['none', 'low', 'medium', 'high'] } }),
    defineField({ name: 'autoDetected', title: 'Auto Detected by Scanner', type: 'boolean', initialValue: false }),
    defineField({ name: 'scanTimestamp', title: 'Scan Timestamp', type: 'datetime' }),
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

