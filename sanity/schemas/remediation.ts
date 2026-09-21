// Sanity schema: Remediation
// A structured remediation proposal for a Finding.
// Human approval is required before any remediation is acted upon.

import { defineType, defineField } from 'sanity';

export const remediation = defineType({
  name: 'remediation',
  title: 'Remediation',
  type: 'document',
  icon: () => '🔧',
  fields: [
    defineField({
      name: 'title',
      title: 'Title',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'finding',
      title: 'Finding',
      type: 'reference',
      to: [{ type: 'finding' }],
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'proposedChange',
      title: 'Proposed Change',
      type: 'text',
      rows: 4,
      description: 'What specifically should be changed.',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'rationale',
      title: 'Rationale',
      type: 'text',
      rows: 3,
      description: 'Why this change is recommended.',
    }),
    defineField({
      name: 'prerequisites',
      title: 'Prerequisites',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'What must be done or verified before applying.',
    }),
    defineField({
      name: 'operationalImpact',
      title: 'Operational Impact',
      type: 'text',
      rows: 3,
      description: 'Potential side effects or operational disruptions.',
    }),
    defineField({
      name: 'risk',
      title: 'Remediation Risk',
      type: 'string',
      options: {
        list: [
          { title: '🟢 Low', value: 'low' },
          { title: '🟡 Medium', value: 'medium' },
          { title: '🔴 High', value: 'high' },
        ],
      },
    }),
    defineField({
      name: 'verificationSteps',
      title: 'Verification Steps',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'How to verify the remediation was effective.',
    }),
    defineField({
      name: 'requiredApproval',
      title: 'Required Approver',
      type: 'string',
      description: 'Who must approve this remediation. e.g. "Cloud Security Owner"',
    }),
    defineField({
      name: 'automationAvailable',
      title: 'Automation Available?',
      type: 'boolean',
      initialValue: false,
      description: 'Whether this can be automated (for future implementation).',
    }),
    defineField({
      name: 'affectedControls',
      title: 'Affected Controls',
      type: 'array',
      of: [{ type: 'reference', to: [{ type: 'securityControl' }] }],
    }),
  ],
  preview: {
    select: {
      title: 'title',
      risk: 'risk',
      findingTitle: 'finding.title',
    },
    prepare({ title, risk, findingTitle }) {
      const icon = risk === 'high' ? '🔴' : risk === 'medium' ? '🟡' : '🟢';
      return {
        title: `🔧 ${title}`,
        subtitle: `Risk: ${icon} ${risk} · For: ${findingTitle}`,
      };
    },
  },
});
