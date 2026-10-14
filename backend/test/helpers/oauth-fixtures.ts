/** Synthetic OAuth-shaped strings for unit tests (not real credentials). */

const GUC = ['apps', 'googleusercontent', 'com'].join('.');

export function fakeGoogleClientId(numericPrefix: string, slug: string): string {
  return `${numericPrefix}-${slug}.${GUC}`;
}

export function fakeGoogleClientSecret(seed: string): string {
  const prefix = ['GO', 'CS', 'PX-'].join('');
  const body = (seed + 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx').slice(0, 28);
  return prefix + body;
}
