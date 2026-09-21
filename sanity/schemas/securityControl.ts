// Sanity schema: SecurityControl
// A specific security requirement from a framework (CIS, NIST, etc.)
// that applies to cloud assets.

import { defineType, defineField } from 'sanity';

export const securityControl = defineType({
  name: 'securityControl',
  title: 'Security Control',
  type: 'document',
  icon: () => '🛡️',
  fields: [
    defineField({
      name: 'controlId',
      title: 'Control ID',
      type: 'string',
      description: 'e.g. CIS-2.1.2, NIST-PR.AC-3',
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
      name: 'framework',
      title: 'Framework',
      type: 'string',
      options: {
        list: [
          { title: 'CIS AWS Foundations', value: 'CIS' },
          { title: 'NIST CSF', value: 'NIST' },
          { title: 'SOC 2', value: 'SOC2' },
          { title: 'PCI-DSS', value: 'PCI-DSS' },
          { title: 'ISO 27001', value: 'ISO27001' },
          { title: 'Internal', value: 'internal' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'requirements',
      title: 'Requirements',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'Specific technical requirements of this control.',
    }),
    defineField({
      name: 'applicableServices',
      title: 'Applicable AWS Services',
      type: 'array',
      of: [{ type: 'string' }],
    }),
    defineField({
      name: 'remediationGuidance',
      title: 'Remediation Guidance',
      type: 'text',
      rows: 4,
    }),
    defineField({
      name: 'relevantThreatTechniques',
      title: 'Relevant Threat Techniques',
      type: 'array',
      of: [{ type: 'reference', to: [{ type: 'threatTechnique' }] }],
    }),
    defineField({
      name: 'source',
      title: 'Source',
      type: 'reference',
      to: [{ type: 'source' }],
    }),
    defineField({
      name: 'version',
      title: 'Version',
      type: 'string',
      description: 'Framework version this control comes from.',
    }),
    defineField({
      name: 'severity',
      title: 'Severity if Violated',
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
  ],
  preview: {
    select: {
      controlId: 'controlId',
      name: 'name',
      framework: 'framework',
    },
    prepare({ controlId, name, framework }) {
      return {
        title: `🛡️ [${controlId}] ${name}`,
        subtitle: `Framework: ${framework}`,
      };
    },
  },
});
