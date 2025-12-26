import React, { useState } from 'react';
import { translations } from '../../../i18n';
import { Lock, CreditCard, CheckCircle, ShieldCheck, Loader2 } from 'lucide-react';

interface Props {
  onUnlock: () => void;
  onReset: () => void;
  lang: 'tr' | 'en';
}

const PaywallOverlay: React.FC<Props> = ({ onUnlock, onReset, lang }) => {
  const [processing, setProcessing] = useState(false);
  const t = translations[lang];

  const handlePayment = () => {
    setProcessing(true);
    setTimeout(() => {
      setProcessing(false);
      onUnlock();
    }, 2000);
  };

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center p-4 animate-fade-in">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onReset}></div>
      <div className="relative bg-cyber-dark border border-cyber-green/30 rounded-2xl p-8 max-w-md w-full shadow-[0_0_50px_rgba(0,255,65,0.1)] text-center">
        <div className="mb-6 flex justify-center">
          <div className="w-20 h-20 bg-cyber-green/10 rounded-full flex items-center justify-center border border-cyber-green/20">
            <Lock className="w-10 h-10 text-cyber-green" />
          </div>
        </div>

        <h2 className="text-2xl font-bold text-white mb-2 font-mono">{t.paywallTitle}</h2>
        <p className="text-gray-400 text-sm mb-8">{t.paywallDesc}</p>

        <div className="bg-black/30 rounded-xl p-6 border border-gray-800 mb-8 text-left space-y-3">
          <div className="flex justify-between items-center border-b border-gray-800 pb-4 mb-2">
            <span className="text-gray-300 font-mono">{lang === 'tr' ? 'Analiz Paketi' : 'Full Report'}</span>
            <span className="text-2xl font-bold text-white">{t.paywallPrice}<span className="text-sm text-gray-500 font-normal">.00</span></span>
          </div>
        </div>

        <button onClick={handlePayment} disabled={processing} className="w-full bg-cyber-green hover:bg-green-400 text-black font-bold py-4 rounded-lg flex items-center justify-center gap-2">
          {processing ? <Loader2 className="w-5 h-5 animate-spin" /> : <><CreditCard className="w-5 h-5" /> {t.paywallUnlock}</>}
        </button>
      </div>
    </div>
  );
};

export default PaywallOverlay;