import { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Check,
  Copy,
  ExternalLink,
  FolderSearch,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { getAllTools, getToolInfo } from '../lib/env';
import { formatOutcomeBadge } from '../lib/formatters';
import { computeTriageOutcomeKey } from '../lib/threatLookup';
import type { DisclaimersData, TriageTreeData } from '../types/data';

interface TriageWizardProps {
  triageTree: TriageTreeData;
  disclaimers: DisclaimersData;
}

const SAFE_INSPECT_PATHS = [
  {
    label: 'Temp Folder',
    path: '%LOCALAPPDATA%\\Temp',
  },
  {
    label: 'Downloads Folder',
    path: '%USERPROFILE%\\Downloads',
  },
];

export function TriageWizard({ triageTree, disclaimers }: TriageWizardProps) {
  const [answers, setAnswers] = useState<Record<string, boolean | null>>({});
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  const outcomeKey = computeTriageOutcomeKey(triageTree.questions, answers);
  const outcome = triageTree.outcomes[outcomeKey];
  const answeredCount = Object.values(answers).filter((v) => v !== null && v !== undefined).length;
  const allTools = getAllTools();

  const handleCopyPath = async (path: string) => {
    try {
      await navigator.clipboard.writeText(path);
      setCopiedPath(path);
      setTimeout(() => setCopiedPath((prev) => (prev === path ? null : prev)), 2200);
    } catch {
      // Clipboard may be unavailable in restricted contexts; fail gracefully.
    }
  };

  const setAnswer = (questionId: string, value: boolean) => {
    setAnswers((prev) => ({ ...prev, [questionId]: value }));
  };

  const isCritical = outcomeKey === 'CRITICAL_INFECTED';
  const isHigh = outcomeKey === 'HIGH_EXPOSURE';

  const outcomeBorder = isCritical
    ? 'border-red-500/60 bg-red-950/20'
    : isHigh
      ? 'border-amber-500/50 bg-amber-950/15'
      : 'border-slate-700 bg-[#0b0f17]';

  const outcomeBadgeStyle = isCritical
    ? 'bg-red-600 text-white'
    : isHigh
      ? 'bg-amber-500 text-slate-950'
      : 'border border-slate-600 bg-slate-800 text-slate-200';

  return (
    <section
      id="triage-wizard"
      aria-label="60-Second Exposure Triage"
      className="rounded-xl border border-slate-800 bg-[#111827] p-5 sm:p-7"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">
            Host Exposure Triage
          </p>
          <h2 className="mt-1 text-xl font-bold text-slate-50 sm:text-2xl">
            60-Second &ldquo;Did I Run a Fake Port?&rdquo; Check
          </h2>
          <p className="mt-1 text-sm text-slate-300">
            Answer {triageTree.questions.length} diagnostic checks ({answeredCount}/
            {triageTree.questions.length} completed) to generate an ordered containment checklist.
          </p>
        </div>

        {answeredCount > 0 && (
          <button
            type="button"
            onClick={() => setAnswers({})}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-[#0b0f17] px-3 py-1.5 font-mono text-xs text-slate-300 transition hover:border-slate-500 hover:text-white cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Reset
          </button>
        )}
      </div>

      {/* Safe Read-Only Explorer Path Helper */}
      <div className="mt-4 rounded-lg border border-slate-800 bg-[#0b0f17] p-3.5">
        <div className="flex items-center gap-2 text-xs font-medium text-slate-300">
          <FolderSearch className="h-4 w-4 text-slate-400" />
          <span>
            Read-only File Explorer paths (paste into Explorer&apos;s address bar only — never
            into Win+R)
          </span>
        </div>
        <div className="mt-2.5 flex flex-wrap gap-2">
          {SAFE_INSPECT_PATHS.map((item) => {
            const isCopied = copiedPath === item.path;
            return (
              <button
                key={item.path}
                type="button"
                onClick={() => handleCopyPath(item.path)}
                className="inline-flex items-center gap-2 rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs text-slate-200 transition hover:border-slate-500 cursor-pointer"
              >
                <span>{item.path}</span>
                {isCopied ? (
                  <span className="inline-flex items-center gap-1 text-sky-300">
                    <Check className="h-3.5 w-3.5" /> Copied
                  </span>
                ) : (
                  <Copy className="h-3.5 w-3.5 text-slate-400" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* 5 Triage Questions */}
      <div className="mt-5 space-y-2.5">
        {triageTree.questions.map((question, idx) => {
          const val = answers[question.id] ?? null;
          return (
            <div
              key={question.id}
              className="rounded-lg border border-slate-800 bg-[#0b0f17] p-4"
            >
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="space-y-1 sm:pr-4">
                  <p className="text-sm font-medium text-slate-100">
                    <span className="mr-2 font-mono text-xs text-slate-400">0{idx + 1}.</span>
                    {question.prompt}
                  </p>
                  <p className="text-xs text-slate-400">
                    {question.helperText.replace(/UNVERIFIED_HIGH_RISK/g, 'Unverified / High Risk')}
                  </p>
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    aria-pressed={val === true}
                    onClick={() => setAnswer(question.id, true)}
                    className={`min-w-[68px] rounded-md border px-3.5 py-2 font-mono text-xs font-semibold transition cursor-pointer ${
                      val === true
                        ? 'border-red-500 bg-red-600 text-white'
                        : 'border-slate-700 bg-[#111827] text-slate-300 hover:border-slate-500'
                    }`}
                  >
                    YES
                  </button>
                  <button
                    type="button"
                    aria-pressed={val === false}
                    onClick={() => setAnswer(question.id, false)}
                    className={`min-w-[68px] rounded-md border px-3.5 py-2 font-mono text-xs font-semibold transition cursor-pointer ${
                      val === false
                        ? 'border-slate-500 bg-slate-700 text-white'
                        : 'border-slate-700 bg-[#111827] text-slate-300 hover:border-slate-500'
                    }`}
                  >
                    NO
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Containment Checklist Outcome */}
      <div className={`mt-6 rounded-xl border p-5 ${outcomeBorder}`}>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-mono text-xs font-semibold tracking-wide ${outcomeBadgeStyle}`}
          >
            {isCritical || isHigh ? (
              <AlertOctagon className="h-3.5 w-3.5" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5" />
            )}
            {formatOutcomeBadge(outcome.badge)}
          </span>
        </div>

        <h3 className="mt-3 text-base font-bold text-slate-50 sm:text-lg">{outcome.headline}</h3>
        <p className="mt-1.5 text-sm leading-relaxed text-slate-300">{outcome.summary}</p>

        <ol className="mt-4 space-y-2.5">
          {outcome.steps.map((step) => {
            const stepTool = step.recommendedToolKey ? getToolInfo(step.recommendedToolKey) : null;
            return (
              <li
                key={step.order}
                className="rounded-lg border border-slate-800 bg-[#0b0f17]/90 p-3.5"
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">
                      <span className="mr-2 font-mono text-slate-400">#{step.order}</span>
                      {step.title}
                    </p>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">{step.detail}</p>
                  </div>
                  {stepTool && (
                    <a
                      href={stepTool.url}
                      target="_blank"
                      rel="noopener noreferrer sponsored"
                      className="inline-flex shrink-0 items-center gap-1.5 self-start rounded-md border border-slate-700 bg-[#111827] px-3 py-1.5 font-mono text-xs font-medium text-slate-200 transition hover:border-slate-500 hover:text-white"
                    >
                      {stepTool.actionLabel}
                      <ExternalLink className="h-3.5 w-3.5" />
                    </a>
                  )}
                </div>
              </li>
            );
          })}
        </ol>

        {/* Affiliate Disclosure + Recommended Security Tool Buttons */}
        <div className="mt-5 border-t border-slate-800 pt-4">
          <div className="flex items-start gap-2 rounded-lg border border-slate-800 bg-[#0b0f17] p-3 text-xs text-slate-400">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
            <p>{disclaimers.affiliateDisclosure}</p>
          </div>

          <div className="mt-3 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {allTools.map((tool) => (
              <a
                key={tool.key}
                href={tool.url}
                target="_blank"
                rel="noopener noreferrer sponsored"
                className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#0b0f17] p-3 transition hover:border-slate-600"
              >
                <div>
                  <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                    {tool.category}
                  </span>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{tool.name}</p>
                </div>
                <span className="mt-2 inline-flex items-center gap-1 font-mono text-xs text-sky-300">
                  Official Site <ExternalLink className="h-3 w-3" />
                </span>
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
