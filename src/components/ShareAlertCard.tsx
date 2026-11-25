import { useEffect, useRef, useState } from 'react';
import { Check, Copy, Download, Share2 } from 'lucide-react';
import { buildShareText, renderAlertCardCanvas } from '../lib/alertCardCanvas';
import type { LookupResult, ThreatsMeta } from '../types/data';

interface ShareAlertCardProps {
  siteDomain: string;
  meta: ThreatsMeta;
  totalAdvisories: number;
  totalIocs: number;
  lookupResult: LookupResult | null;
}

export function ShareAlertCard({
  siteDomain,
  meta,
  totalAdvisories,
  totalIocs,
  lookupResult,
}: ShareAlertCardProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [copiedPlatform, setCopiedPlatform] = useState<string | null>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    renderAlertCardCanvas(canvasRef.current, {
      siteDomain,
      meta,
      totalAdvisories,
      totalIocs,
      lookupResult,
    });
  }, [siteDomain, meta, totalAdvisories, totalIocs, lookupResult]);

  const shareText = buildShareText(siteDomain, lookupResult);

  const handleDownloadPng = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dataUrl = canvas.toDataURL('image/png');
    const link = document.createElement('a');
    link.download = 'portscamwatch-alert-card.png';
    link.href = dataUrl;
    link.click();
  };

  const handleCopyShareText = async (label: string) => {
    try {
      await navigator.clipboard.writeText(shareText);
      setCopiedPlatform(label);
      setTimeout(() => setCopiedPlatform((prev) => (prev === label ? null : prev)), 2200);
    } catch {
      // Ignore clipboard failure gracefully
    }
  };

  const xIntentUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}`;
  const redditSubmitUrl = `https://www.reddit.com/submit?title=${encodeURIComponent(
    'GTA 6 Fake-Port & ClickFix Advisory Summary',
  )}&text=${encodeURIComponent(shareText)}`;

  return (
    <section
      aria-label="Shareable Advisory PNG Card"
      className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-7"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">
            Client-Side PNG Export (1200x630)
          </p>
          <h2 className="mt-1 text-xl font-bold text-slate-50 sm:text-2xl">
            Shareable Advisory Card
          </h2>
        </div>

        <button
          type="button"
          onClick={handleDownloadPng}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-[#0b0f17] px-4 py-2 text-xs font-semibold text-slate-100 transition hover:border-slate-500 hover:text-white cursor-pointer"
        >
          <Download className="h-4 w-4" />
          Download PNG Card
        </button>
      </div>

      {/* Live Canvas Preview */}
      <div className="mt-4 overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f17]">
        <canvas
          ref={canvasRef}
          width={1200}
          height={630}
          className="block h-auto w-full"
        />
      </div>

      {/* Plain-text Share Controls */}
      <div className="mt-4 rounded-lg border border-slate-800 bg-[#0b0f17] p-3.5">
        <p className="font-mono text-xs text-slate-400">Plain-text summary:</p>
        <p className="mt-1.5 text-xs leading-relaxed text-slate-300 sm:text-sm">{shareText}</p>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => handleCopyShareText('general')}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500 cursor-pointer"
          >
            {copiedPlatform === 'general' ? (
              <>
                <Check className="h-3.5 w-3.5 text-sky-300" /> Copied
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" /> Copy Share Text
              </>
            )}
          </button>

          <a
            href={xIntentUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500"
          >
            <Share2 className="h-3.5 w-3.5" /> Post on X
          </a>

          <button
            type="button"
            onClick={() => handleCopyShareText('discord')}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500 cursor-pointer"
          >
            {copiedPlatform === 'discord' ? (
              <>
                <Check className="h-3.5 w-3.5 text-sky-300" /> Copied for Discord
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" /> Copy for Discord
              </>
            )}
          </button>

          <a
            href={redditSubmitUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500"
          >
            <Share2 className="h-3.5 w-3.5" /> Share on Reddit
          </a>
        </div>
      </div>
    </section>
  );
}
