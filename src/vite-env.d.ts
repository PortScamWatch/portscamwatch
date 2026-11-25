/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SITE_DOMAIN?: string;
  readonly VITE_MALWAREBYTES_URL?: string;
  readonly VITE_BITDEFENDER_URL?: string;
  readonly VITE_NORDVPN_URL?: string;
  readonly VITE_NORDPASS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
