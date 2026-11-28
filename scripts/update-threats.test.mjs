import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  VENDOR_FEEDS,
  finalizeThreatsUpdate,
  matchesGta6Topic,
  parseFeedItems,
} from './update-threats.mjs';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..');

describe('automated threat scout safeguards', () => {
  it('monitors Bitdefender Hot for Security and BleepingComputer without dead McAfee feed', () => {
    const feedUrls = VENDOR_FEEDS.map((f) => f.url);
    expect(feedUrls).toContain('https://www.bitdefender.com/nuxt/api/en-us/rss/labs/');
    expect(feedUrls).toContain('https://www.bitdefender.com/blog/api/rss/hotforsecurity/');
    expect(feedUrls).toContain('https://www.malwarebytes.com/blog/feed/index.xml');
    expect(feedUrls).toContain('https://www.darktrace.com/blog/rss.xml');
    expect(feedUrls).toContain('https://www.welivesecurity.com/en/rss/feed/');
    expect(feedUrls).toContain('https://www.bleepingcomputer.com/feed/');
    expect(feedUrls.some((url) => url.includes('mcafee.com'))).toBe(false);
  });

  it('matches GTA 6, GTA VI, and Grand Theft Auto VI/6 consumer advisory variants case-insensitively', () => {
    expect(matchesGta6Topic('Fake GTA 6 installer drops Vidar stealer', '')).toBe(true);
    expect(matchesGta6Topic('gta-vi PC port hype abused in ClickFix lure', '')).toBe(true);
    expect(matchesGta6Topic('Warning: Grand Theft Auto VI leaked demo scam', '')).toBe(true);
    expect(matchesGta6Topic('Grand Theft Auto 6 keygen malware wave', '')).toBe(true);
    expect(matchesGta6Topic('Security Brief', 'Attackers target GTA&nbsp;VI fans with ClickFix.')).toBe(true);

    // Even when <content:encoded> exceeds 14k chars, topic matching scans the full description
    const longPrefix = '<p>Unrelated intro context.</p>'.repeat(600);
    expect(
      matchesGta6Topic('Weekly Threat Wrap', `${longPrefix}<p>Fake GTA VI download site spotted.</p>`),
    ).toBe(true);

    expect(matchesGta6Topic('Grand Theft Auto V mod roundup', 'Patch notes only.')).toBe(false);
    expect(matchesGta6Topic('ClickFix targets enterprise Zoom updates', '')).toBe(false);
  });

  it('prevents no-op commits when appendedCount is 0 and updates lastVerifiedUtc only when new advisories are added', () => {
    const sampleData = JSON.parse(
      fs.readFileSync(path.join(ROOT, 'public/data/threats.json'), 'utf-8'),
    );
    const originalTimestamp = sampleData.meta.lastVerifiedUtc;

    const noOpResult = finalizeThreatsUpdate(sampleData, 0, '2026-11-28T12:00:00Z');
    expect(noOpResult.shouldWrite).toBe(false);
    expect(noOpResult.data.meta.lastVerifiedUtc).toBe(originalTimestamp);

    const updatedResult = finalizeThreatsUpdate(sampleData, 1, '2026-11-28T12:34:56.789Z');
    expect(updatedResult.shouldWrite).toBe(true);
    expect(updatedResult.data.meta.lastVerifiedUtc).toBe('2026-11-28T12:34:56Z');
    expect(sampleData.meta.lastVerifiedUtc).toBe(originalTimestamp);
  });

  it('parses RSS <item> and Atom <entry> blocks cleanly', () => {
    const rssXml = `<?xml version="1.0"?><rss><channel><item><title><![CDATA[GTA 6 Scam]]></title><link>https://www.bleepingcomputer.com/news/security/test/</link><pubDate>Fri, 27 Nov 2026 12:00:00 GMT</pubDate><description>Fake GTA VI lure</description></item></channel></rss>`;
    const parsedRss = parseFeedItems(rssXml, 'BleepingComputer');
    expect(parsedRss).toHaveLength(1);
    expect(parsedRss[0]).toMatchObject({
      vendorName: 'BleepingComputer',
      title: 'GTA 6 Scam',
      link: 'https://www.bleepingcomputer.com/news/security/test/',
    });

    const atomXml = `<feed><entry><title>Atom Advisory</title><link rel="alternate" href="https://www.darktrace.com/blog/test" /><updated>2026-11-27T10:00:00Z</updated><summary>Summary text</summary></entry></feed>`;
    const parsedAtom = parseFeedItems(atomXml, 'Darktrace');
    expect(parsedAtom).toHaveLength(1);
    expect(parsedAtom[0].link).toBe('https://www.darktrace.com/blog/test');
  });
});
