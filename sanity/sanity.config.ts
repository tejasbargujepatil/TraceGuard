// Sanity Studio configuration
import { defineConfig } from 'sanity';
import { structureTool } from 'sanity/structure';
import { visionTool } from '@sanity/vision';
import { schemaTypes } from './schemas';

const projectId = process.env.NEXT_PUBLIC_SANITY_PROJECT_ID || 'placeholder';
const dataset = process.env.NEXT_PUBLIC_SANITY_DATASET || 'production';

export default defineConfig({
  name: 'traceguard',
  title: 'TraceGuard — Security Knowledge Studio',
  projectId,
  dataset,
  plugins: [
    structureTool({
      structure: (S) =>
        S.list()
          .title('TraceGuard Security Knowledge')
          .items([
            S.listItem()
              .title('🚨 Findings')
              .child(S.documentTypeList('finding').title('Findings')),
            S.listItem()
              .title('🔍 Investigations')
              .child(S.documentTypeList('investigation').title('Investigations')),
            S.divider(),
            S.listItem()
              .title('🖥️ Security Assets')
              .child(S.documentTypeList('securityAsset').title('Security Assets')),
            S.listItem()
              .title('🗃️ Data Assets')
              .child(S.documentTypeList('dataAsset').title('Data Assets')),
            S.listItem()
              .title('⚙️ Configurations')
              .child(S.documentTypeList('configuration').title('Configurations')),
            S.divider(),
            S.listItem()
              .title('☠️ Threat Techniques')
              .child(S.documentTypeList('threatTechnique').title('Threat Techniques')),
            S.listItem()
              .title('🛡️ Security Controls')
              .child(S.documentTypeList('securityControl').title('Security Controls')),
            S.listItem()
              .title('📋 Policies')
              .child(S.documentTypeList('policy').title('Policies')),
            S.listItem()
              .title('🔧 Remediations')
              .child(S.documentTypeList('remediation').title('Remediations')),
            S.divider(),
            S.listItem()
              .title('📚 Sources')
              .child(S.documentTypeList('source').title('Sources')),
          ]),
    }),
    visionTool(),
  ],
  schema: {
    types: schemaTypes,
  },
});
