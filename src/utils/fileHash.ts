export const MAX_BROWSER_HASH_BYTES = 256 * 1024 * 1024; // 256 MB safety guard

export type FileHashResult =
  | {
      ok: true;
      sha256: string;
      fileName: string;
      fileSize: number;
    }
  | {
      ok: false;
      reason: 'OVERSIZED' | 'UNSUPPORTED' | 'READ_ERROR';
      fileName: string;
      fileSize: number;
      maxBytes: number;
      message: string;
    };

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export async function computeBufferSha256(input: ArrayBuffer | Uint8Array): Promise<string> {
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle?.digest) {
    throw new Error('Web Crypto SHA-256 is unavailable in this browser context.');
  }

  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data as BufferSource);
  const hashBytes = new Uint8Array(digest);
  return Array.from(hashBytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeFileSha256(file: File): Promise<FileHashResult> {
  if (file.size > MAX_BROWSER_HASH_BYTES) {
    return {
      ok: false,
      reason: 'OVERSIZED',
      fileName: file.name,
      fileSize: file.size,
      maxBytes: MAX_BROWSER_HASH_BYTES,
      message: `Skipped reading ${file.name} (${formatBytes(file.size)}) into browser RAM. Attackers pad fake GTA 6 installers to multi-GB sizes to evade tools—compute SHA-256 locally using the native OS commands below and paste the hash into the Lookup bar.`,
    };
  }

  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle?.digest) {
    return {
      ok: false,
      reason: 'UNSUPPORTED',
      fileName: file.name,
      fileSize: file.size,
      maxBytes: MAX_BROWSER_HASH_BYTES,
      message:
        'Web Crypto API (SHA-256) requires a secure HTTPS/localhost context. Use the local OS commands below instead.',
    };
  }

  try {
    const buffer = await file.arrayBuffer();
    const sha256 = await computeBufferSha256(buffer);
    return {
      ok: true,
      sha256,
      fileName: file.name,
      fileSize: file.size,
    };
  } catch (err) {
    return {
      ok: false,
      reason: 'READ_ERROR',
      fileName: file.name,
      fileSize: file.size,
      maxBytes: MAX_BROWSER_HASH_BYTES,
      message: err instanceof Error ? err.message : 'Unable to read local file.',
    };
  }
}

export function sanitizeShellFilename(rawName: string): string {
  return rawName.replace(/["`$\\;\r\n|&<>]/g, '').trim() || 'installer.exe';
}

export function buildNativeHashCommands(fileName: string): {
  powershell: string;
  unix: string;
} {
  const safeName = sanitizeShellFilename(fileName);
  return {
    powershell: `Get-FileHash -Algorithm SHA256 "${safeName}"`,
    unix: `shasum -a 256 "${safeName}"`,
  };
}
