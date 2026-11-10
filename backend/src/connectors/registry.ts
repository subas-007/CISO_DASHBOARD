import type { ConnectorAdapter } from './types.js';
import { elastic, qradar, splunk } from './adapters/siem.js';
import { nessus, qualys, tenable } from './adapters/vulnerability.js';
import { ansible, satellite, wsus } from './adapters/patch.js';
import { jira, servicenow } from './adapters/change.js';
import { cisaKev, genericRest, misp, taxii } from './adapters/threatIntel.js';
import { genericChange, genericPatch, genericSiem, genericVulnerability } from './adapters/generic.js';

const adapters: ConnectorAdapter[] = [
  splunk,
  elastic,
  qradar,
  tenable,
  nessus,
  qualys,
  wsus,
  ansible,
  satellite,
  servicenow,
  jira,
  misp,
  taxii,
  cisaKev,
  genericRest,
  genericSiem,
  genericVulnerability,
  genericPatch,
  genericChange,
];

const byVendor = new Map(adapters.map((a) => [a.vendor, a]));

export function getAdapter(vendor: string): ConnectorAdapter | undefined {
  return byVendor.get(vendor);
}

export function listAdapters(): ConnectorAdapter[] {
  return adapters;
}

export const VENDORS = adapters.map((a) => a.vendor) as [string, ...string[]];
