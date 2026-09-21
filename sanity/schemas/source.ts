// Sanity schema: Source
// The authoritative record for any external or internal reference.
// Every security claim traces back to a Source document.

import { defineType, defineField } from 'sanity';

export const source = defineType({
  name: 'source',
  title: 'Source',
  type: 'document',
  icon: () => '📚',
  fields: [
    defineField({
      name: 'title',
      title: 'Title',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'organization',
      title: 'Organization',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'url',
      title: 'URL',
      type: 'url',
    }),
    defineField({
      name: 'authority',
      title: 'Authority',
      type: 'string',
      options: {
        list: [
          { title: 'AWS', value: 'aws' },
          { title: 'MITRE ATT&CK', value: 'mitre' },
          { title: 'CIS', value: 'cis' },
          { title: 'NIST', value: 'nist' },
          { title: 'Internal', value: 'internal' },
          { title: 'Vendor', value: 'vendor' },
          { title: 'Other', value: 'other' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'publicationDate',
      title: 'Publication Date',
      type: 'date',
    }),
    defineField({
      name: 'version',
      title: 'Version',
      type: 'string',
      description: 'e.g. "2.0", "v1.3", "2024"',
    }),
    defineField({
      name: 'sourceType',
      title: 'Source Type',
      type: 'string',
      options: {
        list: [
          { title: 'Documentation', value: 'documentation' },
          { title: 'Security Standard', value: 'standard' },
          { title: 'Threat Intelligence', value: 'threat_intel' },
          { title: 'Internal Policy', value: 'policy' },
          { title: 'Architecture Document', value: 'architecture_doc' },
        ],
      },
    }),
    defineField({
      name: 'retrievedAt',
      title: 'Retrieved At',
      type: 'datetime',
    }),
    defineField({
      name: 'status',
      title: 'Status',
      type: 'string',
      options: {
        list: [
          { title: 'Current', value: 'current' },
          { title: 'Historical', value: 'historical' },
          { title: 'Deprecated', value: 'deprecated' },
          { title: 'Unknown', value: 'unknown' },
        ],
      },
      initialValue: 'current',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'summary',
      title: 'Summary',
      type: 'text',
      rows: 3,
      description: 'A concise summary of what this source covers.',
    }),
  ],
  preview: {
    select: {
      title: 'title',
      subtitle: 'organization',
      status: 'status',
    },
    prepare({ title, subtitle, status }) {
      const statusIcon = status === 'current' ? '✅' : status === 'deprecated' ? '⚠️' : '📋';
      return { title: `${statusIcon} ${title}`, subtitle };
    },
  },
});
