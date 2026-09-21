// Sanity schema: Investigation
// The result document created when TraceGuard investigates a Finding.
// Tracks the full evidence chain, conflicts, reasoning, and workflow state.

import { defineType, defineField } from 'sanity';

export const investigation = defineType({
  name: 'investigation',
  title: 'Investigation',
  type: 'document',
  icon: () => '🔍',
  fields: [
    defineField({
      name: 'investigationId',
      title: 'Investigation ID',
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
      name: 'status',
      title: 'Status',
      type: 'string',
      options: {
        list: [
          { title: '🔄 Investigating', value: 'investigating' },
          { title: '✅ Analysis Complete', value: 'analysis_complete' },
          { title: '📝 Remediation Proposed', value: 'remediation_proposed' },
          { title: '⏳ Pending Review', value: 'pending_review' },
          { title: '✅ Approved', value: 'approved' },
          { title: '❌ Rejected', value: 'rejected' },
          { title: '🔍 Verified', value: 'verified' },
          { title: '🔒 Closed', value: 'closed' },
        ],
      },
      initialValue: 'investigating',
    }),
    defineField({
      name: 'reasoningSummary',
      title: 'Reasoning Summary',
      type: 'text',
      rows: 6,
      description: 'Natural-language explanation of what was found and why it matters.',
    }),
    defineField({
      name: 'evidence',
      title: 'Evidence',
      type: 'array',
      of: [
        {
          type: 'object',
          fields: [
            defineField({ name: 'type', type: 'string', title: 'Type' }),
            defineField({ name: 'label', type: 'string', title: 'Label' }),
            defineField({ name: 'value', type: 'string', title: 'Value' }),
            defineField({ name: 'sourceId', type: 'string', title: 'Source ID' }),
            defineField({ name: 'sourceTitle', type: 'string', title: 'Source Title' }),
            defineField({ name: 'sourceUrl', type: 'url', title: 'Source URL' }),
            defineField({ name: 'sourceVersion', type: 'string', title: 'Source Version' }),
            defineField({ name: 'confidence', type: 'string', title: 'Confidence' }),
          ],
        },
      ],
    }),
    defineField({
      name: 'claims',
      title: 'Claims',
      type: 'array',
      of: [
        {
          type: 'object',
          fields: [
            defineField({ name: 'statement', type: 'string', title: 'Statement' }),
            defineField({
              name: 'supportedBy',
              type: 'array',
              of: [{ type: 'string' }],
              title: 'Supported By',
            }),
            defineField({ name: 'confidence', type: 'string', title: 'Confidence' }),
          ],
        },
      ],
    }),
    defineField({
      name: 'conflicts',
      title: 'Conflicts Detected',
      type: 'array',
      of: [
        {
          type: 'object',
          fields: [
            defineField({ name: 'type', type: 'string', title: 'Conflict Type' }),
            defineField({ name: 'description', type: 'string', title: 'Description' }),
            defineField({ name: 'sourceA', type: 'string', title: 'Source A' }),
            defineField({ name: 'sourceB', type: 'string', title: 'Source B' }),
            defineField({ name: 'recommendation', type: 'string', title: 'Recommendation' }),
            defineField({ name: 'severity', type: 'string', title: 'Severity' }),
          ],
        },
      ],
    }),
    defineField({
      name: 'nextChecks',
      title: 'Next Investigation Checks',
      type: 'array',
      of: [{ type: 'string' }],
    }),
    defineField({
      name: 'remediation',
      title: 'Proposed Remediation',
      type: 'reference',
      to: [{ type: 'remediation' }],
    }),
    defineField({
      name: 'approvalStatus',
      title: 'Approval Status',
      type: 'string',
      options: {
        list: [
          { title: '⏳ Pending', value: 'pending' },
          { title: '✅ Approved', value: 'approved' },
          { title: '❌ Rejected', value: 'rejected' },
        ],
      },
    }),
    defineField({
      name: 'approvedBy',
      title: 'Approved By',
      type: 'string',
    }),
    defineField({
      name: 'approvedAt',
      title: 'Approved At',
      type: 'datetime',
    }),
    defineField({
      name: 'rejectionReason',
      title: 'Rejection Reason',
      type: 'text',
      rows: 2,
    }),
    defineField({
      name: 'createdAt',
      title: 'Created At',
      type: 'datetime',
    }),
    defineField({
      name: 'updatedAt',
      title: 'Updated At',
      type: 'datetime',
    }),
  ],
  preview: {
    select: {
      investigationId: 'investigationId',
      findingTitle: 'finding.title',
      status: 'status',
    },
    prepare({ investigationId, findingTitle, status }) {
      const statusIcon =
        status === 'closed' ? '🔒' :
        status === 'verified' ? '✅' :
        status === 'pending_review' ? '⏳' :
        status === 'approved' ? '✅' :
        status === 'rejected' ? '❌' : '🔍';
      return {
        title: `${statusIcon} [${investigationId}]`,
        subtitle: findingTitle,
      };
    },
  },
});
