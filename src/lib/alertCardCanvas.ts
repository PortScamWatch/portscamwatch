import { formatDomainAge, formatUtcTimestamp } from './formatters';
import type { LookupResult, ThreatsMeta } from '../types/data';

const SANS_FONT =
  'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
const MONO_FONT =
  'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace';

function wrapText(
  ctx: CanvasRenderingContext2D,
  text: string,
  maxWidth: number,
  maxLines: number,
): string[] {
  const words = text.trim().split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (ctx.measureText(candidate).width <= maxWidth) {
      current = candidate;
    } else {
      if (current) lines.push(current);
      current = word;
      if (lines.length === maxLines) {
        break;
      }
    }
  }

  if (current && lines.length < maxLines) {
    lines.push(current);
  }

  if (lines.length === maxLines && words.length > 0) {
    const last = lines[maxLines - 1];
    if (ctx.measureText(last).width > maxWidth) {
      lines[maxLines - 1] = `${last.slice(0, Math.max(0, last.length - 4))}...`;
    }
  }

  return lines;
}

function drawRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

export interface AlertCardInput {
  siteDomain: string;
  meta: ThreatsMeta;
  totalAdvisories: number;
  totalIocs: number;
  lookupResult: LookupResult | null;
}

/**
 * Draws a 1200x630 clinical dark-mode summary card using purely local
 * Canvas 2D primitives and system fonts (zero external image/font CDN assets).
 */
export function renderAlertCardCanvas(
  canvas: HTMLCanvasElement,
  input: AlertCardInput,
): void {
  const width = 1200;
  const height = 630;
  canvas.width = width;
  canvas.height = height;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const tier = input.lookupResult?.tier ?? null;
  const isThreat = tier === 'CONFIRMED_THREAT';
  const isEstablished = tier === 'ESTABLISHED_DOMAIN';
  const isNewlyRegistered = Boolean(input.lookupResult?.isNewlyRegisteredDomain);

  let accentColor = '#64748b';
  let accentSoft = 'rgba(100, 116, 139, 0.14)';
  let accentBorder = '#1e293b';

  if (isThreat) {
    accentColor = '#ef4444';
    accentSoft = 'rgba(239, 68, 68, 0.14)';
    accentBorder = 'rgba(239, 68, 68, 0.55)';
  } else if (isEstablished) {
    accentColor = '#38bdf8';
    accentSoft = 'rgba(56, 189, 248, 0.12)';
    accentBorder = 'rgba(56, 189, 248, 0.45)';
  } else if (isNewlyRegistered) {
    accentColor = '#f59e0b';
    accentSoft = 'rgba(245, 158, 11, 0.12)';
    accentBorder = 'rgba(245, 158, 11, 0.45)';
  } else if (tier === 'NOT_LISTED') {
    accentColor = '#cbd5e1';
    accentSoft = 'rgba(148, 163, 184, 0.12)';
    accentBorder = '#334155';
  }

  // Base clinical surface
  ctx.fillStyle = '#0b0f17';
  ctx.fillRect(0, 0, width, height);

  // Subtle card surface
  drawRoundedRect(ctx, 44, 40, width - 88, height - 80, 14);
  ctx.fillStyle = '#111827';
  ctx.fill();
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = accentBorder;
  ctx.stroke();

  // Top hairline bar
  drawRoundedRect(ctx, 44, 40, width - 88, 6, 3);
  ctx.fillStyle = accentColor;
  ctx.fill();

  // Header metadata + verdict badge
  ctx.font = `600 17px ${MONO_FONT}`;
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('PORTSCAMWATCH // THREAT & DOMAIN ADVISORY REPORT', 84, 96);

  const badgeText =
    input.lookupResult?.verdictLabel ??
    `TRACKING ${input.totalAdvisories} ADVISORIES · ${input.totalIocs} IOCs`;
  ctx.font = `700 15px ${MONO_FONT}`;
  const badgeMetrics = ctx.measureText(badgeText);
  const badgeW = badgeMetrics.width + 32;
  drawRoundedRect(ctx, width - 84 - badgeW, 70, badgeW, 38, 6);
  ctx.fillStyle = accentSoft;
  ctx.fill();
  ctx.lineWidth = 1;
  ctx.strokeStyle = accentColor;
  ctx.stroke();
  ctx.fillStyle = accentColor;
  ctx.fillText(badgeText, width - 84 - badgeW + 16, 94);

  // Headline
  let primaryHeadline = `${input.totalAdvisories} Vendor Advisories · ${input.totalIocs} Tracked IOCs`;
  if (isThreat && input.lookupResult) {
    primaryHeadline = `Confirmed Match: ${input.lookupResult.matches[0]?.malwareFamily ?? 'Infostealer'}`;
  } else if (isEstablished && input.lookupResult) {
    primaryHeadline = 'Established Domain — Not Listed in Threat Advisories';
  } else if (tier === 'NOT_LISTED') {
    primaryHeadline = 'Indicator Not Found in Published Vendor Advisories';
  }

  ctx.font = `700 38px ${SANS_FONT}`;
  ctx.fillStyle = '#f8fafc';
  const headlineLines = wrapText(ctx, primaryHeadline, width - 168, 2);
  let y = 166;
  for (const line of headlineLines) {
    ctx.fillText(line, 84, y);
    y += 48;
  }

  // Details panel
  const panelY = Math.max(240, y + 14);
  drawRoundedRect(ctx, 84, panelY, width - 168, 200, 10);
  ctx.fillStyle = '#0b0f17';
  ctx.fill();
  ctx.lineWidth = 1;
  ctx.strokeStyle = '#1e293b';
  ctx.stroke();

  if (input.lookupResult) {
    const defangedQuery = input.lookupResult.normalizedQuery.replace(/\./g, '[.]');
    ctx.font = `600 15px ${MONO_FONT}`;
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('CHECKED INDICATOR', 112, panelY + 38);

    ctx.font = `600 24px ${MONO_FONT}`;
    ctx.fillStyle = accentColor;
    const indicatorLines = wrapText(ctx, defangedQuery || input.lookupResult.query, width - 224, 1);
    ctx.fillText(indicatorLines[0] ?? '', 112, panelY + 74);

    let detailMsg = '';
    if (isThreat) {
      const m = input.lookupResult.matches[0];
      detailMsg = `Source: ${m?.vendorName ?? 'Vendor Advisory'} (${m?.advisoryDate ?? 'Verified'}) — ${m?.lureType ?? 'Infostealer campaign'}.`;
    } else if (isEstablished) {
      const rdapAge =
        input.lookupResult.rdap?.status === 'ok' && input.lookupResult.rdap.ageDays !== null
          ? `RDAP registered ${input.lookupResult.rdap.registeredYear} (${formatDomainAge(input.lookupResult.rdap.ageDays)}). `
          : '';
      detailMsg = `${rdapAge}Not present in tracked malware advisories. Official GTA 6 releases are listed only on rockstargames.com (currently PS5 & Xbox Series X|S only).`;
    } else {
      const rdapAge = input.lookupResult.rdap?.ageDays ?? null;
      const rdapNotice =
        isNewlyRegistered && rdapAge !== null
          ? `Newly Registered Domain (${rdapAge} days old via RDAP). `
          : '';
      detailMsg = `${rdapNotice}Not found in tracked vendor feeds (Bitdefender, Malwarebytes, Netcraft, Darktrace, NordVPN, ESET, Cynet). No official PC/mobile GTA 6 build exists.`;
    }

    ctx.font = `400 20px ${SANS_FONT}`;
    ctx.fillStyle = '#cbd5e1';
    const detailLines = wrapText(ctx, detailMsg, width - 224, 3);
    detailLines.forEach((line, idx) => {
      ctx.fillText(line, 112, panelY + 116 + idx * 28);
    });
  } else {
    ctx.font = `600 15px ${MONO_FONT}`;
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('LIVE VENDOR THREAT TRACKER', 112, panelY + 38);

    ctx.font = `600 23px ${MONO_FONT}`;
    ctx.fillStyle = '#e2e8f0';
    ctx.fillText(
      `${input.totalAdvisories} Vendor Advisories · ${input.totalIocs} Tracked IOCs`,
      112,
      panelY + 74,
    );

    ctx.font = `400 20px ${SANS_FONT}`;
    ctx.fillStyle = '#cbd5e1';
    const summaryText = `Tracking published advisories covering fake PC ports, ClickFix clipboard lures, keygens, and infostealers. Live client-side RDAP domain verification.`;
    const summaryLines = wrapText(ctx, summaryText, width - 224, 3);
    summaryLines.forEach((line, idx) => {
      ctx.fillText(line, 112, panelY + 116 + idx * 28);
    });
  }

  // Footer
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(84, 520);
  ctx.lineTo(width - 84, 520);
  ctx.stroke();

  ctx.font = `600 20px ${MONO_FONT}`;
  ctx.fillStyle = '#e2e8f0';
  ctx.fillText(input.siteDomain, 84, 560);

  ctx.font = `500 16px ${MONO_FONT}`;
  ctx.fillStyle = '#94a3b8';
  const verifiedText = `Last verified: ${formatUtcTimestamp(input.meta.lastVerifiedUtc)}`;
  const vtWidth = ctx.measureText(verifiedText).width;
  ctx.fillText(verifiedText, width - 84 - vtWidth, 560);
}

export function buildShareText(siteDomain: string, lookupResult: LookupResult | null): string {
  if (lookupResult?.tier === 'CONFIRMED_THREAT') {
    const defanged = lookupResult.normalizedQuery.replace(/\./g, '[.]');
    const match = lookupResult.matches[0];
    return `Advisory notice: "${defanged}" matched ${match?.vendorName ?? 'vendor'} reporting for ${match?.malwareFamily ?? 'infostealer malware'}. Official GTA 6 releases are PS5 & Xbox Series X|S only (no PC build). Verify indicators at https://${siteDomain}`;
  }

  if (lookupResult?.tier === 'ESTABLISHED_DOMAIN') {
    const defanged = lookupResult.normalizedQuery.replace(/\./g, '[.]');
    return `"${defanged}" is an established domain and does not appear in tracked GTA 6 fake-port threat advisories. Official GTA 6 releases are listed only on rockstargames.com (PS5 & Xbox Series X|S only). Lookup tool: https://${siteDomain}`;
  }

  return `Check suspicious GTA 6 PC port links, installers, or hashes against published vendor advisories and live RDAP records at https://${siteDomain}. Official GTA 6 releases are currently PS5 & Xbox Series X|S only.`;
}
