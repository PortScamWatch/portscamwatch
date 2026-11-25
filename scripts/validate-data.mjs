import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  isAllowedVendorUrl,
  isProtectedDomain,
  normalizeIndicator,
} from './lib/constants.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../public/data');

function readAndParseJson(fileName, errors) {
  const fullPath = path.join(DATA_DIR, fileName);
  try {
    const raw = fs.readFileSync(fullPath, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    errors.push(`${fileName}: invalid JSON or unreadable file (${err.message})`);
    return null;
  }
}

function assertNonEmptyString(val, label, errors) {
  if (typeof val !== 'string' || val.trim().length === 0) {
    errors.push(`${label} must be a non-empty string`);
  }
}

function assertStringArray(val, label, errors, { allowEmpty = false } = {}) {
  if (!Array.isArray(val)) {
    errors.push(`${label} must be an array`);
    return;
  }
  if (!allowEmpty && val.length === 0) {
    errors.push(`${label} must not be empty`);
    return;
  }
  for (let i = 0; i < val.length; i += 1) {
    if (typeof val[i] !== 'string' || val[i].trim().length === 0) {
      errors.push(`${label}[${i}] must be a non-empty string`);
    }
  }
}

function validateThreats(data, errors) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    errors.push('threats.json: root must be an object');
    return;
  }

  if (!data.meta || typeof data.meta !== 'object') {
    errors.push('threats.json: missing meta object');
  } else {
    assertNonEmptyString(data.meta.siteDomain, 'threats.json meta.siteDomain', errors);
    assertNonEmptyString(data.meta.lastVerifiedUtc, 'threats.json meta.lastVerifiedUtc', errors);
    assertNonEmptyString(
      data.meta.officialPcReleaseStatus,
      'threats.json meta.officialPcReleaseStatus',
      errors,
    );
    assertStringArray(data.meta.officialPlatforms, 'threats.json meta.officialPlatforms', errors);
  }

  if (!Array.isArray(data.threats) || data.threats.length === 0) {
    errors.push('threats.json: threats must be a non-empty array');
    return;
  }

  const seenIds = new Set();
  const seenIndicators = new Map();

  const requiredStringFields = [
    'id',
    'title',
    'severity',
    'malwareFamily',
    'lureType',
    'summary',
    'vendorName',
    'advisoryDate',
    'advisoryUrl',
  ];

  const requiredArrayFields = [
    'displayIndicators',
    'indicators',
    'targetedData',
    'hostArtifacts',
  ];

  for (let i = 0; i < data.threats.length; i += 1) {
    const entry = data.threats[i];
    const prefix = `threats.json threats[${i}]`;

    if (!entry || typeof entry !== 'object') {
      errors.push(`${prefix} must be an object`);
      continue;
    }

    for (const field of requiredStringFields) {
      assertNonEmptyString(entry[field], `${prefix}.${field}`, errors);
    }

    for (const field of requiredArrayFields) {
      assertStringArray(entry[field], `${prefix}.${field}`, errors);
    }

    if (typeof entry.id === 'string' && entry.id.trim()) {
      if (seenIds.has(entry.id)) {
        errors.push(`${prefix}.id duplicate threat ID "${entry.id}"`);
      }
      seenIds.add(entry.id);
    }

    if (typeof entry.advisoryUrl === 'string' && entry.advisoryUrl.trim()) {
      if (!isAllowedVendorUrl(entry.advisoryUrl)) {
        errors.push(
          `${prefix}.advisoryUrl "${entry.advisoryUrl}" is not on the strict vendor allowlist`,
        );
      }
    }

    if (Array.isArray(entry.indicators)) {
      for (let j = 0; j < entry.indicators.length; j += 1) {
        const rawIndicator = entry.indicators[j];
        if (typeof rawIndicator !== 'string') continue;

        const norm = normalizeIndicator(rawIndicator);
        if (norm.length < 3) {
          errors.push(`${prefix}.indicators[${j}] "${rawIndicator}" is too short`);
          continue;
        }

        if (isProtectedDomain(norm)) {
          errors.push(
            `${prefix}.indicators[${j}] "${rawIndicator}" matches protected domain blocklist`,
          );
        }

        if (seenIndicators.has(norm)) {
          errors.push(
            `${prefix}.indicators[${j}] duplicate normalized indicator "${norm}" (already in "${seenIndicators.get(norm)}")`,
          );
        } else {
          seenIndicators.set(norm, entry.id || `index ${i}`);
        }
      }
    }
  }
}

function validateTriageTree(data, errors) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    errors.push('triage-tree.json: root must be an object');
    return;
  }

  if (!Array.isArray(data.questions) || data.questions.length === 0) {
    errors.push('triage-tree.json: questions must be a non-empty array');
  } else {
    data.questions.forEach((q, idx) => {
      const prefix = `triage-tree.json questions[${idx}]`;
      assertNonEmptyString(q?.id, `${prefix}.id`, errors);
      assertNonEmptyString(q?.prompt, `${prefix}.prompt`, errors);
      assertNonEmptyString(q?.helperText, `${prefix}.helperText`, errors);
      assertNonEmptyString(q?.yesTriggersSeverity, `${prefix}.yesTriggersSeverity`, errors);
      if (typeof q?.riskWeight !== 'number' || Number.isNaN(q.riskWeight)) {
        errors.push(`${prefix}.riskWeight must be a number`);
      }
    });
  }

  if (!data.outcomes || typeof data.outcomes !== 'object' || Array.isArray(data.outcomes)) {
    errors.push('triage-tree.json: outcomes must be an object');
    return;
  }

  const requiredOutcomes = ['CRITICAL_INFECTED', 'HIGH_EXPOSURE', 'UNVERIFIED_CAUTION'];
  for (const key of requiredOutcomes) {
    if (!data.outcomes[key]) {
      errors.push(`triage-tree.json: missing required outcome "${key}"`);
    }
  }

  for (const [key, outcome] of Object.entries(data.outcomes)) {
    if (/^(SAFE|CLEAN)$/i.test(key.trim())) {
      errors.push(`triage-tree.json: forbidden outcome key "${key}"`);
    }
    const prefix = `triage-tree.json outcomes.${key}`;
    assertNonEmptyString(outcome?.badge, `${prefix}.badge`, errors);
    assertNonEmptyString(outcome?.headline, `${prefix}.headline`, errors);
    assertNonEmptyString(outcome?.summary, `${prefix}.summary`, errors);

    if (typeof outcome?.badge === 'string' && /\b(SAFE|CLEAN)\b/i.test(outcome.badge)) {
      errors.push(`${prefix}.badge "${outcome.badge}" violates safety invariant (contains SAFE/CLEAN)`);
    }

    if (!Array.isArray(outcome?.steps) || outcome.steps.length === 0) {
      errors.push(`${prefix}.steps must be a non-empty array`);
    } else {
      outcome.steps.forEach((step, idx) => {
        const stepPrefix = `${prefix}.steps[${idx}]`;
        if (typeof step?.order !== 'number') {
          errors.push(`${stepPrefix}.order must be a number`);
        }
        assertNonEmptyString(step?.title, `${stepPrefix}.title`, errors);
        assertNonEmptyString(step?.detail, `${stepPrefix}.detail`, errors);
      });
    }
  }
}

function validateDisclaimers(data, errors) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    errors.push('disclaimers.json: root must be an object');
    return;
  }
  assertNonEmptyString(data.siteName, 'disclaimers.json siteName', errors);
  assertNonEmptyString(data.affiliateDisclosure, 'disclaimers.json affiliateDisclosure', errors);
  assertNonEmptyString(data.asIsDisclaimer, 'disclaimers.json asIsDisclaimer', errors);
  assertNonEmptyString(data.nonAffiliationNotice, 'disclaimers.json nonAffiliationNotice', errors);
}

export function runValidation() {
  const errors = [];
  const threats = readAndParseJson('threats.json', errors);
  const triageTree = readAndParseJson('triage-tree.json', errors);
  const disclaimers = readAndParseJson('disclaimers.json', errors);

  if (threats) validateThreats(threats, errors);
  if (triageTree) validateTriageTree(triageTree, errors);
  if (disclaimers) validateDisclaimers(disclaimers, errors);

  if (errors.length > 0) {
    console.error('❌ Data validation failed:');
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    return false;
  }

  console.log(
    `✅ Data validation passed (${threats.threats.length} threat advisories, ${triageTree.questions.length} triage questions).`,
  );
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const ok = runValidation();
  if (!ok) process.exit(1);
}
