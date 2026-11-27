import { useEffect, useState } from 'react';
import { ArrowRight, BookOpen, ChevronDown, ExternalLink, Search } from 'lucide-react';
import { DefenseToolsPanel } from './DefenseToolsPanel';

interface RemovalGuideItem {
  anchorId: string;
  title: string;
  vendorLabel: string;
  advisoryUrl: string;
  secondaryAdvisoryLabel?: string;
  secondaryAdvisoryUrl?: string;
  lookupIndicator: string;
  summary: string;
  removalNotes: string;
}

const REMOVAL_GUIDES: RemovalGuideItem[] = [
  {
    anchorId: 'guide-gta6cloud-lstrace',
    title: 'GTA6Cloud.exe & %LOCALAPPDATA%\\Temp\\ls_trace.txt',
    vendorLabel: 'Bitdefender Labs · Nov 20, 2026',
    advisoryUrl:
      'https://www.bitdefender.com/en-us/blog/labs/fake-gta-vi-pc-client-malware-clickfix',
    lookupIndicator: 'GTA6Cloud.exe',
    summary:
      'ClickFix Rust infostealer campaign using GTA6Cloud.exe, side-loaded loadperf.dll (via unlodctr.exe), PhotoCache.exe, and staging directory IconCacheToDelete\\0a3f2c91.',
    removalNotes:
      'Disconnect network, rotate browser/Steam/Discord/API credentials from a clean device, inspect HKCU Run persistence, and run a full offline malware scan.',
  },
  {
    anchorId: 'guide-velmontriq-nimbuskeep',
    title: 'velmontriq[.]net & nimbuskeep[.]com',
    vendorLabel: 'Bitdefender Labs · Nov 20, 2026',
    advisoryUrl:
      'https://www.bitdefender.com/en-us/blog/labs/fake-gta-vi-pc-client-malware-clickfix',
    lookupIndicator: 'velmontriq.net',
    summary:
      'ClickFix payload delivery (velmontriq[.]net) and C2 exfiltration (nimbuskeep[.]com) domains used by fake GTA VI cloud-streaming portals.',
    removalNotes:
      'If you copied and executed a Win+R PowerShell verification command from either domain, revoke active OAuth/browser sessions and rotate all saved passwords.',
  },
  {
    anchorId: 'guide-vidar-gta6demo',
    title: 'gta6_installer.exe & gta6demo[.]asia',
    vendorLabel: 'Malwarebytes Aug 24 / Darktrace Nov 17, 2026',
    advisoryUrl:
      'https://www.malwarebytes.com/blog/threat-intel/2026/08/fake-gta-6-extended-look-and-demo-sites-deliver-an-infostealer',
    secondaryAdvisoryLabel: 'Darktrace Nov 17, 2026',
    secondaryAdvisoryUrl:
      'https://www.darktrace.com/blog/gta-vi-cyber-threats-fake-downloads-ransomware-and-account-hijacking',
    lookupIndicator: 'gta6_installer.exe',
    summary:
      '1.1 MB Vidar infostealer targeting 19 web browsers, FTP/email profiles, and session tokens before exfiltrating to ses.1001gacor[.]org.',
    removalNotes:
      'Because Vidar spawns headless browser sessions to extract decrypted cookies, signing out of all active sessions on Google, Steam, and email is critical.',
  },
  {
    anchorId: 'guide-gta6-keygen-xmrig',
    title: 'GTA6 Keygen.exe & XMRig',
    vendorLabel: 'NordVPN Threat Intelligence via TechRadar · Nov 18, 2026',
    advisoryUrl:
      'https://www.techradar.com/vpn/vpn-privacy-security/fake-gta-6-pc-downloads-are-spreading-malware-through-dark-web-scam-bundle-nordvpn-warns',
    lookupIndicator: 'GTA6 Keygen.exe',
    summary:
      '$200 dark-web scam bundle pairing a session-cookie stealer with an XMRig cryptocurrency miner and ETH/BSC/Solana/Polygon wallet drainer.',
    removalNotes:
      'Check Task Manager for hidden XMRig processes, revoke suspicious token approvals from an unaffected device, and transfer assets to a fresh seed phrase.',
  },
  {
    anchorId: 'guide-com-gta6-apkrate',
    title: 'com.gta6.apkrate',
    vendorLabel: 'Malwarebytes · Nov 18, 2026',
    advisoryUrl:
      'https://www.malwarebytes.com/blog/scams/2026/11/gta-6-scams-could-cost-you-your-account-money-or-crypto',
    lookupIndicator: 'com.gta6.apkrate',
    summary:
      '36.8 MB fake GTA 6 Android APK adware package uploaded 1,700+ times across mobile download lures, enumerating installed apps and SIM metadata.',
    removalNotes:
      'Uninstall the package in Android Settings > Apps, revoke "Install unknown apps" permissions, and run an Android anti-malware scan.',
  },
  {
    anchorId: 'guide-warden-uroker',
    title: 'Gta_6_Exe_File_Download.zip & uroker[.]casa',
    vendorLabel: 'Cynet · Nov 13, 2026',
    advisoryUrl:
      'https://www.cynet.com/blog/download-gta6-for-free-inside-the-malware-trap/',
    lookupIndicator: 'uroker.casa',
    summary:
      'Google Colab lure archive dropping WARDEN Stealer to exfiltrate browser passwords, session cookies, Steam/Roblox logins, and crypto wallets to uroker[.]casa.',
    removalNotes:
      'Delete the archive without extracting, or if executed, rotate gaming and browser credentials from an unaffected device and scan the host.',
  },
];

interface RemovalGuidesSectionProps {
  onInspectIndicator: (indicator: string) => void;
  onOpenTriage: () => void;
}

export function RemovalGuidesSection({
  onInspectIndicator,
  onOpenTriage,
}: RemovalGuidesSectionProps) {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const syncAnchor = () => {
      const h = window.location.hash;
      if (h === '#removal-guides' || h.startsWith('#guide-')) {
        setIsOpen(true);
      }
    };
    syncAnchor();
    window.addEventListener('hashchange', syncAnchor);
    return () => window.removeEventListener('hashchange', syncAnchor);
  }, []);

  return (
    <section
      id="removal-guides"
      aria-label="Known GTA 6 Malware and Removal Guides"
      className="mx-auto w-full max-w-5xl px-4 pb-6 sm:px-6"
    >
      <details
        open={isOpen}
        onToggle={(e) => setIsOpen(e.currentTarget.open)}
        className="rounded-xl border border-slate-800 bg-[#111827]"
      >
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 text-left select-none hover:bg-slate-800/30">
          <div className="flex items-center gap-2.5">
            <BookOpen className="h-4 w-4 shrink-0 text-slate-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100 sm:text-base">
                Known GTA 6 Malware &amp; Removal Guides (Vendor Advisories)
              </h2>
              <p className="text-xs text-slate-400">
                6 documented infostealer, ClickFix, keygen, and APK campaigns with direct advisory
                links
              </p>
            </div>
          </div>
          <ChevronDown
            className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${
              isOpen ? 'rotate-180' : ''
            }`}
          />
        </summary>

        <div className="border-t border-slate-800 p-5 grid gap-4 md:grid-cols-2">
          {REMOVAL_GUIDES.map((guide) => (
            <article
              key={guide.anchorId}
              id={guide.anchorId}
              className="flex min-w-0 flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-4"
            >
              <div className="min-w-0">
                <p className="font-mono text-[11px] text-slate-400">{guide.vendorLabel}</p>
                <h3 className="mt-1 font-mono text-sm font-semibold text-slate-100 break-all">
                  {guide.title}
                </h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-300">{guide.summary}</p>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">
                  <strong className="text-slate-300">Containment:</strong> {guide.removalNotes}
                </p>

                <DefenseToolsPanel
                  variant="compact"
                  placement="guide"
                  heading="Recovery & Prevention Tools"
                  className="mt-3"
                />
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-slate-800/80 pt-3">
                <button
                  type="button"
                  onClick={() => onInspectIndicator(guide.lookupIndicator)}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#111827] px-2.5 py-1.5 font-mono text-[11px] text-slate-200 transition hover:border-sky-500/60 hover:text-sky-200 cursor-pointer"
                >
                  <Search className="h-3 w-3" />
                  Inspect IOC
                </button>
                <button
                  type="button"
                  onClick={onOpenTriage}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 bg-[#111827] px-2.5 py-1.5 font-mono text-[11px] text-slate-200 transition hover:border-slate-500 cursor-pointer"
                >
                  Triage Checklist
                  <ArrowRight className="h-3 w-3" />
                </button>
                <a
                  href={guide.advisoryUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-auto inline-flex items-center gap-1 font-mono text-[11px] text-sky-400 hover:text-sky-300"
                >
                  Advisory <ExternalLink className="h-3 w-3" />
                </a>
                {guide.secondaryAdvisoryUrl && (
                  <a
                    href={guide.secondaryAdvisoryUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-400 hover:text-slate-200"
                  >
                    {guide.secondaryAdvisoryLabel} <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            </article>
          ))}
        </div>
      </details>
    </section>
  );
}
