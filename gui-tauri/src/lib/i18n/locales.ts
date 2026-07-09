// Supported locales (one per vendored .po), display names, RTL set. `code` MUST equal the .po
// basename in src/lib/i18n/po/ so the generated JSON filename matches.
export interface LocaleInfo { code: string; name: string; nativeName: string; rtl: boolean; }

export const SUPPORTED: LocaleInfo[] = [
  { code: "en", name: "English", nativeName: "English", rtl: false },
  { code: "ar", name: "Arabic", nativeName: "العربية", rtl: true },
  { code: "bn", name: "Bengali", nativeName: "বাংলা", rtl: false },
  { code: "es", name: "Spanish", nativeName: "Español", rtl: false },
  { code: "es-cu", name: "Spanish (Cuba)", nativeName: "Español (Cuba)", rtl: false },
  { code: "fa", name: "Persian", nativeName: "فارسی", rtl: true },
  { code: "fr", name: "French", nativeName: "Français", rtl: false },
  { code: "fr-ca", name: "French (Canada)", nativeName: "Français (Canada)", rtl: false },
  { code: "hi", name: "Hindi", nativeName: "हिन्दी", rtl: false },
  { code: "ms", name: "Malay", nativeName: "Bahasa Melayu", rtl: false },
  { code: "my", name: "Burmese", nativeName: "မြန်မာ", rtl: false },
  { code: "ps", name: "Pashto", nativeName: "پښتو", rtl: true },
  { code: "ru", name: "Russian", nativeName: "Русский", rtl: false },
  { code: "th", name: "Thai", nativeName: "ไทย", rtl: false },
  { code: "tk", name: "Turkmen", nativeName: "Türkmençe", rtl: false },
  { code: "tr", name: "Turkish", nativeName: "Türkçe", rtl: false },
  { code: "ur", name: "Urdu", nativeName: "اردو", rtl: true },
  { code: "vi", name: "Vietnamese", nativeName: "Tiếng Việt", rtl: false },
  { code: "zh-Hans", name: "Chinese (Simplified)", nativeName: "简体中文", rtl: false },
  { code: "zh-Hant", name: "Chinese (Traditional)", nativeName: "繁體中文", rtl: false },
];

export const RTL_LOCALES = new Set(SUPPORTED.filter((l) => l.rtl).map((l) => l.code));
const CODES = new Set(SUPPORTED.map((l) => l.code));

export function matchLocale(requested: string | undefined | null): string | null {
  if (!requested) return null;
  if (CODES.has(requested)) return requested;
  const lower = requested.toLowerCase();
  const base = lower.split("-")[0];
  if (base === "zh") return /hant|tw|hk|mo/.test(lower) ? "zh-Hant" : "zh-Hans";
  const exactBase = SUPPORTED.find((l) => l.code === base);
  if (exactBase) return exactBase.code;
  const anyBase = SUPPORTED.find((l) => l.code.toLowerCase().split("-")[0] === base);
  return anyBase ? anyBase.code : null;
}
