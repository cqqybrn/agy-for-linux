import type { PtyProcess } from '../../src/integrations/agy/pty-spawn.js';

/** A scripted pseudo-terminal: tests push output with `emit` / `exit` and inspect what was typed. */
export class FakePty implements PtyProcess {
  pid = 4242;
  written: string[] = [];
  killed = 0;
  private dataListeners: Array<(d: string) => void> = [];
  private exitListeners: Array<(c: number | null) => void> = [];
  onData(l: (d: string) => void) {
    this.dataListeners.push(l);
  }
  onExit(l: (c: number | null) => void) {
    this.exitListeners.push(l);
  }
  write(d: string) {
    this.written.push(d);
  }
  kill() {
    this.killed += 1;
  }
  emit(chunk: string) {
    this.dataListeners.forEach((l) => l(chunk));
  }
  exit(code: number | null) {
    this.exitListeners.forEach((l) => l(code));
  }
}
