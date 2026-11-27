import { useEffect, useMemo, useState } from 'react';
import { Database, FileImage, ListFilter, Search, Shield, ShieldAlert } from 'lucide-react';
import { MethodologySection } from './components/MethodologySection';
import { OpenIntelExports } from './components/OpenIntelExports';
import { RemovalGuidesSection } from './components/RemovalGuidesSection';
import { ShareAlertCard } from './components/ShareAlertCard';
import { StatusAndVerifier, type AppPage } from './components/StatusAndVerifier';
import { ThreatFeedTable } from './components/ThreatFeedTable';
import { TriageWizard } from './components/TriageWizard';
import { getSiteDomain } from './lib/env';
import { countTrackedIocs, lookupThreat } from './lib/threatLookup';
import type {
  DisclaimersData,
  LookupResult,
  RdapDomainInfo,
  ThreatsData,
  TriageTreeData,
} from './types/data';

interface LoadedAppData {
  threatsData: ThreatsData;
  triageTree: TriageTreeData;
  disclaimers: DisclaimersData;
}

const VALID_PAGES: AppPage[] = ['lookup', 'triage', 'advisories', 'exports', 'export'];

function readHashPage(): AppPage {
  if (typeof window === 'undefined') return 'lookup';
  const raw = window.location.hash.replace(/^#\/?/, '').toLowerCase() as AppPage;
  return VALID_PAGES.includes(raw) ? raw : 'lookup';
}

function readInitialSearchQuery(): string | null {
  if (typeof window === 'undefined') return null;
  const q = new URLSearchParams(window.location.search).get('q');
  const trimmed = q?.trim() ?? '';
  return trimmed.length > 0 ? trimmed.slice(0, 512) : null;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) {
    throw new Error(`Failed to load ${url} (${res.status})`);
  }
  return (await res.json()) as T;
}

export function App() {
  const [data, setData] = useState<LoadedAppData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [activePage, setActivePage] = useState<AppPage>(() => {
    return readInitialSearchQuery() ? 'lookup' : readHashPage();
  });
  const [pendingQuery, setPendingQuery] = useState<string | null>(() => readInitialSearchQuery());

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      fetchJson<ThreatsData>('/data/threats.json'),
      fetchJson<TriageTreeData>('/data/triage-tree.json'),
      fetchJson<DisclaimersData>('/data/disclaimers.json'),
    ])
      .then(([threatsData, triageTree, disclaimers]) => {
        if (!cancelled) {
          setData({ threatsData, triageTree, disclaimers });
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load threat data.');
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onHashChange = () => {
      setActivePage(readHashPage());
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const navigate = (page: AppPage) => {
    setActivePage(page);
    const url = new URL(window.location.href);
    url.hash = `#${page}`;
    window.history.pushState(null, '', `${url.pathname}${url.search}${url.hash}`);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const openMethodology = () => {
    window.location.hash = '#methodology';
    const el = document.getElementById('methodology');
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const siteDomain = getSiteDomain(data?.threatsData.meta.siteDomain);

  const totalIocs = useMemo(
    () => (data ? countTrackedIocs(data.threatsData.threats) : 0),
    [data],
  );

  const handleCompleteLookup = (rawQuery: string, rdap: RdapDomainInfo | null) => {
    if (!data) return;
    const result = lookupThreat(rawQuery, data.threatsData.threats, rdap);
    setLookupResult(result);
  };

  const handleInspectFromFeed = (indicator: string) => {
    setPendingQuery(indicator);
    navigate('lookup');
  };

  const navItems: { id: AppPage; label: string; badge?: string; icon: typeof Search }[] = [
    { id: 'lookup', label: 'Lookup', icon: Search },
    { id: 'triage', label: 'Exposure Triage', icon: ShieldAlert },
    {
      id: 'advisories',
      label: 'Advisories',
      badge: data ? String(data.threatsData.threats.length) : undefined,
      icon: ListFilter,
    },
    { id: 'exports', label: 'Open Intel', icon: Database },
    { id: 'export', label: 'Export Card', icon: FileImage },
  ];

  return (
    <div className="flex min-h-screen flex-col bg-[#0b0f17] text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-[#0b0f17]/95 backdrop-blur">
        <div className="mx-auto flex max-w-5xl flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <button
            type="button"
            onClick={() => navigate('lookup')}
            className="flex items-center gap-2.5 text-left cursor-pointer"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700 bg-[#111827] text-slate-200">
              <Shield className="h-4 w-4" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-semibold tracking-tight text-slate-100">
                PortScamWatch
              </span>
              <span className="rounded border border-slate-800 bg-[#111827] px-1.5 py-0.5 font-mono text-[11px] text-slate-400">
                {siteDomain}
              </span>
            </div>
          </button>

          <nav aria-label="Primary navigation" className="flex flex-wrap items-center gap-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-mono text-xs font-medium transition cursor-pointer ${
                    isActive
                      ? 'border-sky-500/50 bg-sky-500/15 text-sky-200'
                      : 'border-slate-800 bg-[#111827] text-slate-300 hover:border-slate-600 hover:text-white'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
            <button
              type="button"
              onClick={openMethodology}
              className="rounded-lg border border-transparent px-2 py-1.5 font-mono text-xs text-slate-400 transition hover:text-slate-200 cursor-pointer"
            >
              Methodology
            </button>
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
        {error && (
          <div
            role="alert"
            className="rounded-xl border border-red-500/50 bg-red-950/20 p-4 font-mono text-sm text-red-200"
          >
            Failed to load threat feed: {error}
          </div>
        )}

        {!data && !error && (
          <div className="rounded-xl border border-slate-800 bg-[#111827] p-8 text-center font-mono text-sm text-slate-400">
            Loading threat advisories &amp; triage definitions...
          </div>
        )}

        {data && activePage === 'lookup' && (
          <StatusAndVerifier
            meta={data.threatsData.meta}
            threats={data.threatsData.threats}
            totalAdvisories={data.threatsData.threats.length}
            totalIocs={totalIocs}
            lookupResult={lookupResult}
            pendingQuery={pendingQuery}
            onConsumePendingQuery={() => setPendingQuery(null)}
            onCompleteLookup={handleCompleteLookup}
            onClear={() => setLookupResult(null)}
            onNavigate={navigate}
          />
        )}

        {data && activePage === 'triage' && (
          <TriageWizard
            triageTree={data.triageTree}
            disclaimers={data.disclaimers}
          />
        )}

        {data && activePage === 'advisories' && (
          <ThreatFeedTable
            threats={data.threatsData.threats}
            onInspectIndicator={handleInspectFromFeed}
            onOpenExports={() => navigate('exports')}
          />
        )}

        {data && activePage === 'exports' && (
          <OpenIntelExports threatsData={data.threatsData} />
        )}

        {data && activePage === 'export' && (
          <ShareAlertCard
            siteDomain={siteDomain}
            meta={data.threatsData.meta}
            totalAdvisories={data.threatsData.threats.length}
            totalIocs={totalIocs}
            lookupResult={lookupResult}
          />
        )}
      </main>

      {data && (
        <RemovalGuidesSection
          onInspectIndicator={handleInspectFromFeed}
          onOpenTriage={() => navigate('triage')}
        />
      )}

      {data && <MethodologySection />}

      {data && (
        <footer className="border-t border-slate-800 bg-[#0b0f17] py-6">
          <div className="mx-auto max-w-5xl space-y-2.5 px-4 text-xs leading-relaxed text-slate-400 sm:px-6">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-mono text-slate-300">
                {data.disclaimers.siteName.toLowerCase() === siteDomain.toLowerCase()
                  ? siteDomain
                  : `${data.disclaimers.siteName} (${siteDomain})`}
              </p>
              <div className="flex flex-wrap items-center gap-3 font-mono text-[11px]">
                <button
                  type="button"
                  onClick={() => navigate('exports')}
                  className="text-slate-300 underline hover:text-white cursor-pointer"
                >
                  Open IOC Exports
                </button>
                <button
                  type="button"
                  onClick={openMethodology}
                  className="text-slate-300 underline hover:text-white cursor-pointer"
                >
                  Methodology &amp; Threat Model
                </button>
                <a
                  href="/data/threats.json"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-300 underline hover:text-white"
                >
                  threats.json
                </a>
              </div>
            </div>
            <p>{data.disclaimers.asIsDisclaimer}</p>
            <p>{data.disclaimers.nonAffiliationNotice}</p>
          </div>
        </footer>
      )}
    </div>
  );
}
