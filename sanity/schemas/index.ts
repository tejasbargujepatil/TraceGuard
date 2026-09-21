// Sanity schema index — exports all schemas for Sanity Studio

import { source } from './source';
import { securityAsset } from './securityAsset';
import { dataAsset } from './dataAsset';
import { configuration } from './configuration';
import { finding } from './finding';
import { threatTechnique } from './threatTechnique';
import { securityControl } from './securityControl';
import { policy } from './policy';
import { remediation } from './remediation';
import { investigation } from './investigation';
import { cloudAccount } from './cloudAccount';

export const schemaTypes = [
  // Foundation
  source,
  // Infrastructure
  securityAsset,
  dataAsset,
  configuration,
  cloudAccount,
  // Security knowledge
  threatTechnique,
  securityControl,
  policy,
  // Findings and workflow
  finding,
  remediation,
  investigation,
];
