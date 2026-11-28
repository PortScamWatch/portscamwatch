import { ExternalLink, Shield } from 'lucide-react';
import { getConfiguredTools, type AffiliatePlacement } from '../config/env';

const INLINE_FTC_DISCLOSURE =
  'Disclosure: Independent affiliate links. We may earn a commission at no extra cost; affiliate links never influence threat verdicts.';

export interface DefenseToolsPanelProps {
  variant: 'compact' | 'full';
  placement: AffiliatePlacement;
  heading?: string;
  subheading?: string;
  className?: string;
}

export function DefenseToolsPanel({
  variant,
  placement,
  heading,
  subheading,
  className = '',
}: DefenseToolsPanelProps) {
  const tools = getConfiguredTools(placement);
  if (tools.length === 0) {
    return null;
  }

  if (variant === 'compact') {
    const compactColsClass =
      tools.length === 1
        ? 'sm:grid-cols-1'
        : tools.length === 3 && placement === 'verdict'
          ? 'md:grid-cols-3'
          : 'sm:grid-cols-2';
    const spanOddLast = tools.length === 3 && placement !== 'verdict';

    return (
      <div
        data-testid={`defense-tools-compact-${placement}`}
        className={`rounded-lg border border-slate-800 bg-[#0b0f17] p-3.5 ${className}`.trim()}
      >
        {heading && (
          <div className="mb-2.5 flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-slate-300">
            <Shield className="h-3.5 w-3.5 text-sky-400" />
            <span>{heading}</span>
          </div>
        )}

        <div className={`grid gap-2 ${compactColsClass}`}>
          {tools.map((tool, idx) => (
            <a
              key={tool.key}
              href={tool.url}
              target="_blank"
              rel="noopener noreferrer sponsored"
              data-tool-key={tool.key}
              className={`group flex min-w-0 items-center justify-between gap-2.5 rounded-md border border-slate-700/90 bg-[#111827] px-3 py-2.5 text-left transition hover:border-sky-500/60 hover:bg-slate-800/80 ${
                spanOddLast && idx === tools.length - 1 ? 'sm:col-span-2' : ''
              }`.trim()}
            >
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-semibold text-slate-100 group-hover:text-white">
                  {tool.name}
                  {tool.badgeTag && (
                    <span className="ml-1.5 font-mono text-[10px] font-normal text-slate-400">
                      {tool.badgeTag}
                    </span>
                  )}
                </p>
                <p className="truncate font-mono text-[10px] text-slate-400">
                  {tool.shortLabel}
                </p>
              </div>
              <ExternalLink className="h-3.5 w-3.5 shrink-0 text-sky-400 transition group-hover:text-sky-300" />
            </a>
          ))}
        </div>

        <p className="mt-2.5 text-[11px] leading-relaxed text-slate-400">
          {INLINE_FTC_DISCLOSURE}
        </p>
      </div>
    );
  }

  const gridColsClass =
    tools.length === 1
      ? 'sm:grid-cols-1'
      : tools.length === 2
        ? 'sm:grid-cols-2'
        : tools.length === 3
          ? 'md:grid-cols-3'
          : 'sm:grid-cols-2 lg:grid-cols-4';

  return (
    <section
      data-testid={`defense-tools-full-${placement}`}
      aria-label={heading ?? 'Recommended Protection Stack'}
      className={`rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-6 ${className}`.trim()}
    >
      <div className="flex items-start gap-2.5">
        <Shield className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
        <div>
          <h2 className="text-base font-bold text-slate-50 sm:text-lg">
            {heading ?? 'Recommended Protection Stack'}
          </h2>
          {subheading && (
            <p className="mt-1 text-xs leading-relaxed text-slate-400 sm:text-sm">
              {subheading}
            </p>
          )}
        </div>
      </div>

      <div className={`mt-4 grid gap-3 ${gridColsClass}`}>
        {tools.map((tool) => (
          <div
            key={tool.key}
            className="flex min-w-0 flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-4"
          >
            <div className="min-w-0">
              <span className="font-mono text-[10px] uppercase tracking-wider text-sky-400">
                {tool.category}
              </span>
              <h3 className="mt-1 text-sm font-bold text-slate-100">
                {tool.name}
                {tool.badgeTag && (
                  <span className="ml-1.5 font-mono text-xs font-normal text-slate-400">
                    {tool.badgeTag}
                  </span>
                )}
              </h3>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
                {tool.description}
              </p>
            </div>

            <a
              href={tool.url}
              target="_blank"
              rel="noopener noreferrer sponsored"
              data-tool-key={tool.key}
              className="mt-4 flex min-w-0 items-center justify-between gap-2 rounded-md border border-slate-700 bg-[#111827] px-3 py-2 font-mono text-xs font-semibold leading-snug text-slate-100 transition hover:border-sky-500/60 hover:bg-slate-800 hover:text-white"
            >
              <span className="min-w-0 break-words">{tool.actionLabel}</span>
              <ExternalLink className="h-3.5 w-3.5 shrink-0 text-sky-400" />
            </a>
          </div>
        ))}
      </div>

      <p className="mt-3.5 border-t border-slate-800/80 pt-3 text-[11px] leading-relaxed text-slate-400">
        {INLINE_FTC_DISCLOSURE}
      </p>
    </section>
  );
}
