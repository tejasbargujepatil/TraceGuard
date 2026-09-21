// Sanity schema: ThreatTechnique
// MITRE ATT&CK and other threat intelligence techniques relevant to cloud security.

import { defineType, defineField } from 'sanity';

export const threatTechnique = defineType({
  name: 'threatTechnique',
  title: 'Threat Technique',
  type: 'document',
  icon: () => '☠️',
  fields: [
    defineField({
      name: 'techniqueId',
      title: 'Technique ID',
      type: 'string',
      description: 'e.g. T1530, T1078.004',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'name',
      title: 'Name',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'description',
      title: 'Description',
      type: 'text',
      rows: 4,
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'tactics',
      title: 'Tactics',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'e.g. Collection, Discovery, Initial Access',
    }),
    defineField({
      name: 'affectedServices',
      title: 'Affected AWS Services',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'e.g. S3, IAM, EC2',
    }),
    defineField({
      name: 'relevantConditions',
      title: 'Relevant Conditions',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'Configuration states that enable this technique.',
    }),
    defineField({
      name: 'cloudContext',
      title: 'Cloud Context',
      type: 'text',
      rows: 3,
      description: 'How this technique applies specifically in cloud environments.',
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
        ],
      },
    }),
    defineField({
      name: 'mitigations',
      title: 'Mitigations',
      type: 'array',
      of: [{ type: 'string' }],
    }),
    defineField({
      name: 'source',
      title: 'Source',
      type: 'reference',
      to: [{ type: 'source' }],
    }),
    defineField({
      name: 'externalUrl',
      title: 'External URL',
      type: 'url',
      description: 'Link to MITRE ATT&CK entry.',
    }),
  ],
  preview: {
    select: {
      techniqueId: 'techniqueId',
      name: 'name',
      severity: 'severity',
    },
    prepare({ techniqueId, name, severity }) {
      const icon = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '☠️';
      return {
        title: `${icon} ${techniqueId} — ${name}`,
      };
    },
  },
});
