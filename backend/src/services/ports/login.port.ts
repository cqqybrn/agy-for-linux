import type { AccountLoginSession } from '@agy-studio/contracts';

export interface StartLoginOptions {
  accountName: string;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
}

export interface LoginHandle {
  readonly loginId: string;
  readonly session: AccountLoginSession;
  waitForAuthUrl(): Promise<string>;
  waitForCompletion(): Promise<AccountLoginSession>;
  /** Relays the authorization code into the login terminal; only terminals owned by the backend offer it. */
  submitCode?(code: string): Promise<void>;
  cancel(): Promise<void>;
}

export interface LoginPort {
  /**
   * Spawns login flow in a pseudo-terminal.
   */
  startLogin(options: StartLoginOptions): Promise<LoginHandle>;
}
