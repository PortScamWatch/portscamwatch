import { Fragment, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Filter,
  Search,
} from 'lucide-react';
import { truncateIndicator } from '../lib/formatters';
import type { ThreatEntry } from '../types/data';

interface ThreatFeedTableProps {
  threats: ThreatEntry[];
  onInspectIndicator?: (indicator: string) => void;
}

const PREVIEW_IOC_LIMIT = 3;

export function ThreatFeedTable({ threats, onInspectIndicator }: ThreatFeedTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [vendorFilter, setVendorFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const vendors = useMemo(() => {
    const unique = Array.from(new Set(threats.map((t) => t.vendorName)));
    return ['ALL', ...unique];
  }, [threats]);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return threats.filter((entry) => {
      if (vendorFilter !== 'ALL' && entry.vendorName !== vendorFilter) {
        return false;
      }
      if (!q) return true;
      const haystack = [
        entry.title,
        entry.malwareFamily,
        entry.lureType,
        entry.vendorName,
        ...entry.displayIndicators,
        ...entry.indicators,
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [threats, searchTerm, vendorFilter]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <section
      aria-label="Published Vendor Advisories"
      className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-6"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">
            Vendor Threat Intelligence
          </p>
          <h1 className="mt-1 text-xl font-bold text-slate-50 sm:text-2xl">
            Tracked Vendor Advisories &amp; IOC Feed
          </h1>
          <p className="mt-1 text-xs text-slate-400 sm:text-sm">
            Showing {filtered.length} of {threats.length} published advisories. Expand any row for
            full SHA-256 hashes, host artifacts, and vendor writeups.
          </p>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter IOCs, families..."
              aria-label="Filter vendor threat feed"
              className="w-full rounded-lg border border-slate-700 bg-[#0b0f17] py-2 pl-8 pr-3 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none sm:w-52"
            />
          </div>

          <div className="relative flex items-center">
            <Filter className="pointer-events-none absolute left-3 h-3.5 w-3.5 text-slate-400" />
            <select
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
              aria-label="Filter by vendor"
              className="w-full appearance-none rounded-lg border border-slate-700 bg-[#0b0f17] py-2 pl-8 pr-7 font-mono text-xs text-slate-100 focus:border-sky-400 focus:outline-none cursor-pointer"
            >
              {vendors.map((vendor) => (
                <option key={vendor} value={vendor}>
                  {vendor === 'ALL' ? 'All Vendors' : vendor}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Mobile Cards (< md) */}
      <div className="mt-4 space-y-3 md:hidden">
        {filtered.length === 0 ? (
          <div className="rounded-lg border border-slate-800 bg-[#0b0f17] p-6 text-center font-mono text-xs text-slate-400">
            No matching advisories for your current filter.
          </div>
        ) : (
          filtered.map((entry) => {
            const isExpanded = expandedId === entry.id;
            const previewIocs = entry.displayIndicators.slice(0, PREVIEW_IOC_LIMIT);
            const remainingCount = entry.displayIndicators.length - previewIocs.length;

            return (
              <div
                key={entry.id}
                className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4 space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-red-400">
                    {entry.severity}
                  </span>
                  <a
                    href={entry.advisoryUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-300 hover:text-white"
                  >
                    {entry.vendorName} · {entry.advisoryDate}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>

                <div>
                  <h2 className="text-sm font-semibold text-slate-100">{entry.title}</h2>
                  <p className="mt-0.5 font-mono text-xs text-slate-400">{entry.malwareFamily}</p>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {previewIocs.map((ind) => (
                    <code
                      key={ind}
                      title={ind}
                      className="rounded border border-slate-800 bg-[#111827] px-2 py-0.5 font-mono text-[11px] text-slate-200"
                    >
                      {truncateIndicator(ind)}
                    </code>
                  ))}
                  {remainingCount > 0 && (
                    <button
                      type="button"
                      onClick={() => toggleExpand(entry.id)}
                      className="rounded border border-slate-700 bg-[#111827] px-2 py-0.5 font-mono text-[11px] text-sky-300 cursor-pointer"
                    >
                      +{remainingCount} more
                    </button>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => toggleExpand(entry.id)}
                  className="inline-flex items-center gap-1 font-mono text-xs text-slate-300 hover:text-white cursor-pointer"
                >
                  {isExpanded ? (
                    <>
                      Hide details <ChevronUp className="h-3.5 w-3.5" />
                    </>
                  ) : (
                    <>
                      View full IOCs &amp; summary <ChevronDown className="h-3.5 w-3.5" />
                    </>
                  )}
                </button>

                {isExpanded && (
                  <ExpandedAdvisoryPanel
                    entry={entry}
                    onInspectIndicator={onInspectIndicator}
                  />
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Desktop Table (md+) */}
      <div className="mt-4 hidden overflow-x-auto rounded-lg border border-slate-800 bg-[#0b0f17] md:block">
        <table className="w-full border-collapse text-left text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-[#111827] font-mono text-[11px] uppercase tracking-wider text-slate-400">
              <th className="w-[34%] px-4 py-3">Campaign / Lure</th>
              <th className="w-[20%] px-4 py-3">Malware Family</th>
              <th className="w-[28%] px-4 py-3">Key Indicators</th>
              <th className="w-[18%] px-4 py-3 text-right">Vendor Source</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center font-mono text-xs text-slate-400">
                  No matching advisories for your current filter.
                </td>
              </tr>
            ) : (
              filtered.map((entry) => {
                const isExpanded = expandedId === entry.id;
                const previewIocs = entry.displayIndicators.slice(0, PREVIEW_IOC_LIMIT);
                const remainingCount = entry.displayIndicators.length - previewIocs.length;

                return (
                  <Fragment key={entry.id}>
                    <tr className="align-top transition hover:bg-[#111827]/40">
                      <td className="px-4 py-3.5">
                        <div className="flex items-start gap-2.5">
                          <span className="mt-0.5 shrink-0 rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-red-400">
                            {entry.severity}
                          </span>
                          <div>
                            <p className="font-semibold leading-snug text-slate-100">
                              {entry.title}
                            </p>
                            <p className="mt-1 text-xs text-slate-400">{entry.lureType}</p>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3.5 font-mono text-xs leading-relaxed text-slate-200">
                        {entry.malwareFamily}
                      </td>

                      <td className="px-4 py-3.5">
                        <div className="flex flex-wrap gap-1.5">
                          {previewIocs.map((ind) => (
                            <code
                              key={ind}
                              title={ind}
                              className="rounded border border-slate-800 bg-[#111827] px-2 py-0.5 font-mono text-[11px] text-slate-200"
                            >
                              {truncateIndicator(ind)}
                            </code>
                          ))}
                        </div>
                        <button
                          type="button"
                          onClick={() => toggleExpand(entry.id)}
                          className="mt-2 inline-flex items-center gap-1 font-mono text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                        >
                          {isExpanded ? (
                            <>
                              Hide details <ChevronUp className="h-3 w-3" />
                            </>
                          ) : remainingCount > 0 ? (
                            <>
                              +{remainingCount} more IOCs &amp; details{' '}
                              <ChevronDown className="h-3 w-3" />
                            </>
                          ) : (
                            <>
                              View artifacts &amp; summary <ChevronDown className="h-3 w-3" />
                            </>
                          )}
                        </button>
                      </td>

                      <td className="px-4 py-3.5 text-right">
                        <a
                          href={entry.advisoryUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-slate-700 bg-[#111827] px-2.5 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500 hover:text-white"
                        >
                          <span>{entry.vendorName}</span>
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                        <p className="mt-1 font-mono text-[11px] text-slate-500">
                          {entry.advisoryDate}
                        </p>
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-[#0b0f17]">
                        <td colSpan={4} className="px-4 pb-4 pt-1">
                          <ExpandedAdvisoryPanel
                            entry={entry}
                            onInspectIndicator={onInspectIndicator}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ExpandedAdvisoryPanel({
  entry,
  onInspectIndicator,
}: {
  entry: ThreatEntry;
  onInspectIndicator?: (indicator: string) => void;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#111827]/70 p-4 space-y-3">
      <p className="text-xs leading-relaxed text-slate-300 sm:text-sm">{entry.summary}</p>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded border border-slate-800 bg-[#0b0f17] p-3">
          <p className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
            Targeted Data
          </p>
          <ul className="mt-1.5 space-y-1 text-xs text-slate-300">
            {entry.targetedData.map((item) => (
              <li key={item}>• {item}</li>
            ))}
          </ul>
        </div>

        <div className="rounded border border-slate-800 bg-[#0b0f17] p-3">
          <p className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
            Host Artifacts
          </p>
          <ul className="mt-1.5 space-y-1 font-mono text-xs text-slate-300">
            {entry.hostArtifacts.map((art) => (
              <li key={art} className="break-all">
                {art}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div>
        <p className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
          All Defanged Indicators ({entry.displayIndicators.length})
        </p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {entry.displayIndicators.map((ind) => (
            <button
              key={ind}
              type="button"
              onClick={() => onInspectIndicator?.(ind)}
              title="Run lookup on this indicator"
              className="rounded border border-slate-700/80 bg-[#0b0f17] px-2 py-1 font-mono text-[11px] text-slate-200 transition hover:border-sky-500/60 hover:text-sky-200 break-all text-left cursor-pointer"
            >
              {ind}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
