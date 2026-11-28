import { useEffect, useState } from 'react';
import { ChevronDown, ShieldCheck } from 'lucide-react';

export function MethodologySection() {
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    const syncAnchor = () => {
      if (window.location.hash === '#methodology') {
        setIsOpen(true);
      }
    };
    syncAnchor();
    window.addEventListener('hashchange', syncAnchor);
    return () => window.removeEventListener('hashchange', syncAnchor);
  }, []);

  return (
    <section
      id="methodology"
      aria-label="Methodology, Threat Model and Funding"
      className="mx-auto w-full max-w-5xl px-4 pb-6 sm:px-6"
    >
      <details
        open={isOpen}
        onToggle={(e) => setIsOpen(e.currentTarget.open)}
        className="rounded-xl border border-slate-800 bg-[#111827]"
      >
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-5 py-4 text-left select-none hover:bg-slate-800/30">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="h-4 w-4 shrink-0 text-sky-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100 sm:text-base">
                Methodology, Threat Model &amp; Funding
              </h2>
              <p className="text-xs text-slate-400">
                Client-side hashing, RDAP privacy boundaries, automated scout guardrails &amp;
                independent funding
              </p>
            </div>
          </div>
          <ChevronDown
            className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${
              isOpen ? 'rotate-180' : ''
            }`}
          />
        </summary>

        <div className="grid gap-4 border-t border-slate-800 p-5 md:grid-cols-2">
          <div className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-sky-400">
              1. Static &amp; Zero-Logging Lookup
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-300">
              Indicators and local file SHA-256 hashes (computed via the browser Web Crypto API)
              are evaluated strictly in your browser against the static{' '}
              <code className="text-slate-100">threats.json</code> file. No search terms, URLs, or
              file bytes are uploaded or logged by PortScamWatch servers.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-sky-400">
              2. RDAP Privacy Caveat
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-300">
              When you submit a domain or URL, your browser issues a direct client-side query to the
              public RDAP registry (<code className="text-slate-100">rdap.org</code>) to determine
              registration age. That lookup reveals the queried registrable domain to the public
              RDAP provider, never to a PortScamWatch backend.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-sky-400">
              3. Automated Scout Verification Guardrails
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-300">
              Our scheduled 6-hour GitHub Actions scout polls allowlisted security feeds
              (Bitdefender Labs &amp; Hot for Security, Malwarebytes, Darktrace, ESET
              WeLiveSecurity, and BleepingComputer) and extracts vendor-published IOCs append-only,
              updating <code className="text-slate-100">threats.json</code> only when a new
              verified advisory is added. Deterministic validation rejects non-allowlisted URLs,
              duplicates, invalid SHA-256 strings, and protected platforms before committing to{' '}
              <code className="text-slate-100">main</code>.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4">
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-sky-400">
              4. Independent Funding Disclosure
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-300">
              PortScamWatch is a free, static, zero-ad tool supported solely by clearly labeled
              affiliate links (Bitdefender, NordVPN, NordPass, and Coveron). Affiliate links never
              influence threat verdicts, vendor citations, or database entries, and are hidden on
              benign or established domain checks.
            </p>
          </div>
        </div>
      </details>
    </section>
  );
}
