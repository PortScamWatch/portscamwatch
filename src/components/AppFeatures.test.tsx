// @vitest-environment jsdom
import fs from 'node:fs';
import path from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { DefenseToolsPanel } from './DefenseToolsPanel';
import { TriageWizard } from './TriageWizard';
import type { DisclaimersData, ThreatsData, TriageTreeData } from '../types/data';

const ROOT = path.resolve(__dirname, '../..');
const threatsData = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'public/data/threats.json'), 'utf-8'),
) as ThreatsData;
const triageTree = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'public/data/triage-tree.json'), 'utf-8'),
) as TriageTreeData;
const disclaimers = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'public/data/disclaimers.json'), 'utf-8'),
) as DisclaimersData;

describe('React UI & Component Tests', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/');
    window.scrollTo = vi.fn();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('DefenseToolsPanel hides completely when env vars are unset and renders 2-col Nord grid when configured', () => {
    vi.stubEnv('VITE_NORDVPN_URL', '');
    vi.stubEnv('VITE_NORDPASS_URL', '');
    vi.stubEnv('VITE_MALWAREBYTES_URL', '');
    vi.stubEnv('VITE_BITDEFENDER_URL', '');

    const { container, unmount } = render(
      <DefenseToolsPanel variant="full" placement="homepage" />,
    );
    expect(container.innerHTML).toBe('');
    unmount();

    vi.stubEnv(
      'VITE_NORDPASS_URL',
      'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356',
    );
    vi.stubEnv(
      'VITE_NORDVPN_URL',
      'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902',
    );

    render(<DefenseToolsPanel variant="compact" placement="verdict" heading="Immediate Containment" />);
    const links = screen.getAllByRole('link');
    expect(links).toHaveLength(2);
    for (const link of links) {
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('rel')).toBe('noopener noreferrer sponsored');
      expect(link.getAttribute('href')).toContain('aff_id=162042');
      expect(link.getAttribute('href')).toContain('aff_sub=psw_verdict');
    }
    expect(screen.getByText(/Disclosure: Independent affiliate links/i)).toBeTruthy();
  });

  it('App hydrates ?q=GTA6Cloud.exe permalink, handles benign lookup without affiliate links, and supports / and Escape shortcuts', async () => {
    vi.stubEnv(
      'VITE_NORDPASS_URL',
      'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356',
    );
    vi.stubEnv(
      'VITE_NORDVPN_URL',
      'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902',
    );

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith('/data/threats.json')) {
        return new Response(JSON.stringify(threatsData), { status: 200 });
      }
      if (url.endsWith('/data/triage-tree.json')) {
        return new Response(JSON.stringify(triageTree), { status: 200 });
      }
      if (url.endsWith('/data/disclaimers.json')) {
        return new Response(JSON.stringify(disclaimers), { status: 200 });
      }
      return new Response('{}', { status: 404 });
    });

    window.history.replaceState(null, '', '/?q=GTA6Cloud.exe');
    render(<App />);

    await waitFor(
      () => {
        expect(screen.getByText('MATCHED IN VENDOR ADVISORIES')).toBeTruthy();
      },
      { timeout: 4000 },
    );
    expect(screen.getByTestId('defense-tools-compact-verdict')).toBeTruthy();

    // "/" focuses input and "Escape" resets & blurs
    const searchInput = screen.getByLabelText(
      /Suspicious URL, domain, filename, Windows path, or SHA-256 hash/i,
    ) as HTMLInputElement;
    expect(searchInput.value).toBe('GTA6Cloud.exe');

    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => {
      expect(searchInput.value).toBe('');
      expect(screen.queryByText('MATCHED IN VENDOR ADVISORIES')).toBeNull();
    });

    fireEvent.keyDown(window, { key: '/' });
    expect(document.activeElement).toBe(searchInput);

    // Benign lookup: rockstargames.com -> ESTABLISHED DOMAIN and 0 affiliate links inside verdict
    fireEvent.change(searchInput, { target: { value: 'rockstargames.com' } });
    fireEvent.submit(searchInput.closest('form')!);
    await waitFor(
      () => {
        expect(screen.getByText('ESTABLISHED DOMAIN — NOT IN THREAT LISTS')).toBeTruthy();
      },
      { timeout: 4000 },
    );
    expect(screen.queryByTestId('defense-tools-compact-verdict')).toBeNull();
  });

  it('TriageWizard transitions cleanly across all severity outcomes and attaches psw_triage', () => {
    vi.stubEnv(
      'VITE_NORDPASS_URL',
      'https://go.nordpass.io/aff_c?offer_id=488&aff_id=162042&url_id=9356',
    );
    vi.stubEnv(
      'VITE_NORDVPN_URL',
      'https://go.nordvpn.net/aff_c?offer_id=15&aff_id=162042&url_id=902',
    );

    render(<TriageWizard triageTree={triageTree} disclaimers={disclaimers} />);
    expect(screen.getByText('UNVERIFIED · HIGH RISK')).toBeTruthy();

    const yesButtons = screen.getAllByRole('button', { name: 'YES' });
    fireEvent.click(yesButtons[3]); // q4 -> HIGH_EXPOSURE
    expect(screen.getByText('HIGH ACCOUNT OR DEVICE EXPOSURE')).toBeTruthy();

    fireEvent.click(yesButtons[0]); // q1 -> CRITICAL_INFECTED
    expect(screen.getByText('HIGH LIKELIHOOD OF COMPROMISE')).toBeTruthy();

    const panel = screen.getByTestId('defense-tools-full-triage');
    const links = Array.from(panel.querySelectorAll('a'));
    expect(links.length).toBe(2);
    expect(links[0].getAttribute('href')).toContain('aff_sub=psw_triage');
  });
});
