/**
 * i18n (Internationalization) Setup
 *
 * Provides language management and translation hooks for the application
 */

import { useState, useCallback } from 'react';
import { tr } from './locales/tr';
import { en } from './locales/en';

export const translations = { tr, en };

export type Language = keyof typeof translations;
export type TranslationKeys = typeof tr;

/**
 * useTranslation Hook
 *
 * Provides language state management and translation access
 *
 * @returns { lang, t, changeLanguage }
 */
export function useTranslation() {
  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem('securiscan_lang');
    return (saved === 'tr' || saved === 'en') ? saved : 'tr';
  });

  const changeLanguage = useCallback((newLang: Language) => {
    setLang(newLang);
    localStorage.setItem('securiscan_lang', newLang);
  }, []);

  return {
    lang,
    t: translations[lang],
    changeLanguage
  };
}

// Export translations for compatibility
export { tr, en };
