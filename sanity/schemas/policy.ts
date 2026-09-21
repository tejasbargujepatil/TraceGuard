// Sanity schema: Policy
// Organizational security policies with full versioning.
// The Policy schema with version history enables security drift detection
// and conflict identification between current and legacy policies.

import { defineType, defineField } from 'sanity';

export const policy = defineType({
  name: 'policy',
  title: 'Policy',
  type: 'document',
  icon: () => '📋',
  fields: [
    defineField({
      name: 'name',
      title: 'Policy Name',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'policyId',
      title: 'Policy ID',
      type: 'string',
      description: 'e.g. POL-001',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'version',
      title: 'Version',
      type: 'string',
      description: 'e.g. "1.0", "2.0"',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'isCurrentVersion',
      title: 'Is Current Version?',
      type: 'boolean',
      description: 'Only one version of each policy should be marked current.',
      initialValue: false,
    }),
    defineField({
      name: 'requirement',
      title: 'Requirement',
      type: 'text',
      rows: 4,
      description: 'What this policy requires.',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'appliesTo',
      title: 'Applies To',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'e.g. "production", "customer_data", "s3", "all_environments"',
    }),
    defineField({
      name: 'effectiveFrom',
      title: 'Effective From',
      type: 'date',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'effectiveTo',
      title: 'Effective To',
      type: 'date',
      description: 'Leave blank if this policy is currently active.',
    }),
    defineField({
      name: 'exceptions',
      title: 'Exceptions',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'Any documented exceptions to this policy.',
    }),
    defineField({
      name: 'supersededBy',
      title: 'Superseded By',
      type: 'reference',
      to: [{ type: 'policy' }],
      description: 'If this policy was replaced, reference the newer version.',
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
      description: 'Additional context about this policy, including legacy rationale.',
    }),
    defineField({
      name: 'approvedBy',
      title: 'Approved By',
      type: 'string',
    }),
  ],
  preview: {
    select: {
      name: 'name',
      policyId: 'policyId',
      version: 'version',
      isCurrentVersion: 'isCurrentVersion',
    },
    prepare({ name, policyId, version, isCurrentVersion }) {
      const icon = isCurrentVersion ? '✅' : '🗄️';
      return {
        title: `${icon} [${policyId}] ${name} v${version}`,
        subtitle: isCurrentVersion ? 'Current Policy' : 'Historical / Superseded',
      };
    },
  },
});
