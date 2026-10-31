// Logic of the background library of the branding screen (BackgroundPresets.svelte), kept out of
// the component so that it is unit tested in Node.

/** Identifier of the default background (the one used when a tenant picks nothing). */
export const DEFAULT_PRESET = 'default';

/** Language used when a preset has no label in the interface language. */
export const FALLBACK_LANGUAGE = 'en';

const API_BASE = '/api/v1';

/** One background of the library, as listed by listBackgroundPresets. */
export interface PresetItem {
  id: string;
  labels: Readonly<Record<string, string>>;
}

/**
 * Label of a preset in the interface language (base tag, e.g. "fr-FR" gives "fr"), else in
 * English, else its identifier.
 */
export function presetLabel(item: PresetItem, language: string): string {
  const base = language.toLowerCase().split('-')[0] ?? '';
  const own = item.labels[base];
  if (own !== undefined && own !== '') {
    return own;
  }
  const fallback = item.labels[FALLBACK_LANGUAGE];
  return fallback !== undefined && fallback !== '' ? fallback : item.id;
}

/** Choice shown for the value of the API: an absent or null preset is the default one. */
export function normalizeChoice(preset: string | null | undefined): string {
  return preset === undefined || preset === null || preset === '' ? DEFAULT_PRESET : preset;
}

/** Whether the choice differs from the saved preset (both normalized). */
export function choiceChanged(choice: string, saved: string | null | undefined): boolean {
  return choice !== normalizeChoice(saved);
}

/** Body value of setBackgroundPreset: the default preset is sent as null (reset). */
export function presetToSend(choice: string): string | null {
  return choice === DEFAULT_PRESET ? null : choice;
}

/** URL of the preview image of a preset (same origin, admin session cookie). */
export function previewUrl(id: string): string {
  return `${API_BASE}/admin/background-presets/${encodeURIComponent(id)}`;
}
