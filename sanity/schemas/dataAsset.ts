// Sanity schema: DataAsset
// Represents data stored within or accessible through a SecurityAsset.

import { defineType, defineField } from 'sanity';

export const dataAsset = defineType({
  name: 'dataAsset',
  title: 'Data Asset',
  type: 'document',
  icon: () => '🗃️',
  fields: [
    defineField({
      name: 'name',
      title: 'Name',
      type: 'string',
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'classification',
      title: 'Data Classification',
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
      name: 'sensitivity',
      title: 'Sensitivity Level',
      type: 'string',
      options: {
        list: [
          { title: 'Restricted', value: 'restricted' },
          { title: 'Confidential', value: 'confidential' },
          { title: 'Internal', value: 'internal' },
          { title: 'Public', value: 'public' },
        ],
      },
      validation: (Rule) => Rule.required(),
    }),
    defineField({
      name: 'contains',
      title: 'Contains',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'Types of data contained — e.g. "customer_pii", "financial_records", "credentials"',
    }),
    defineField({
      name: 'storedIn',
      title: 'Stored In',
      type: 'reference',
      to: [{ type: 'securityAsset' }],
      description: 'The SecurityAsset where this data is stored.',
    }),
    defineField({
      name: 'owner',
      title: 'Data Owner',
      type: 'string',
    }),
    defineField({
      name: 'description',
      title: 'Description',
      type: 'text',
      rows: 3,
    }),
    defineField({
      name: 'regulatoryScope',
      title: 'Regulatory Scope',
      type: 'array',
      of: [{ type: 'string' }],
      description: 'e.g. GDPR, CCPA, HIPAA, PCI-DSS',
    }),
    defineField({
      name: 'estimatedRecordCount',
      title: 'Estimated Record Count',
      type: 'string',
      description: 'e.g. "100k+", "unknown", ">1M"',
    }),
  ],
  preview: {
    select: {
      title: 'name',
      classification: 'classification',
      assetName: 'storedIn.name',
    },
    prepare({ title, classification, assetName }) {
      const classIcon = classification === 'restricted' ? '🔒' : classification === 'confidential' ? '🔐' : '📂';
      return {
        title: `${classIcon} ${title}`,
        subtitle: assetName ? `Stored in: ${assetName}` : 'Location unknown',
      };
    },
  },
});
