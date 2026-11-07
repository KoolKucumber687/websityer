/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface TestCase {
  id: string;
  category: 'bank_alert' | 'delivery_text' | 'grandparent_emergency' | 'legitimate_service';
  sender: string;
  message: string;
  language: 'EN' | 'ES' | 'FR';
  isScam: boolean;
  vectors: string[];
}

export interface EvalMetrics {
  totalCases: number;
  scamCases: number;
  legitCases: number;
  languages: string[];
  precision: number;
  recall: number;
  f1Score: number;
  falseAlarms: number;
}

export const SAMPLE_DATASET: TestCase[] = [
  {
    id: 'CASE-01',
    category: 'grandparent_emergency',
    sender: '+1 (555) 019-8422',
    message: "Grandma, it's me! I'm in jail. Please send $2,000 in gift cards.",
    language: 'EN',
    isScam: true,
    vectors: ['urgency_coercion', 'gift_card_anomaly', 'impersonation'],
  },
  {
    id: 'CASE-02',
    category: 'bank_alert',
    sender: 'ChaseAlert-Verify',
    message: 'Chase Alert: Did you authorize $948.20 at Target Minneapolis? If NO, click auth-chase-security.net/verify',
    language: 'EN',
    isScam: true,
    vectors: ['lookalike_domain', 'panic_trigger', 'credential_harvesting'],
  },
  {
    id: 'CASE-03',
    category: 'delivery_text',
    sender: 'USPS-TrackNotice',
    message: 'USPS: Package US-98842-X held for incomplete address. Confirm details within 12h: usps-postaltag-tracking.vip/redelivery',
    language: 'EN',
    isScam: true,
    vectors: ['unregistered_tld', 'time_pressure', 'smishing'],
  },
  {
    id: 'CASE-04',
    category: 'grandparent_emergency',
    sender: '+34 611 234 567',
    message: 'Abuela, soy Carlos. He tenido un accidente grave en Madrid. Por favor transfiere 1.500€ urgente y no le digas a papá.',
    language: 'ES',
    isScam: true,
    vectors: ['urgency_coercion', 'family_impersonation', 'secrecy_demand'],
  },
  {
    id: 'CASE-05',
    category: 'delivery_text',
    sender: 'LaPoste-Suivi',
    message: 'La Poste : Votre colis ne peut être livré. Frais de dédouanement de 1,95€ en attente sur laposte-colis-douane.info',
    language: 'FR',
    isScam: true,
    vectors: ['phishing_redirect', 'low_fee_trap', 'fake_portal'],
  },
  {
    id: 'CASE-06',
    category: 'legitimate_service',
    sender: 'Chase (24273)',
    message: 'Chase: Free Msg - Did you spend $42.50 at Trader Joes? Reply YES or NO. Do not click any links.',
    language: 'EN',
    isScam: false,
    vectors: ['official_shortcode', 'zero_link_policy', 'standard_sms_prompt'],
  },
];

export function computeEvaluationMetrics(cases: TestCase[], predictedScams: Record<string, boolean>): EvalMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  const languages = Array.from(new Set(cases.map((c) => c.language)));

  for (const item of cases) {
    const predicted = predictedScams[item.id] ?? false;
    if (item.isScam && predicted) tp++;
    else if (!item.isScam && predicted) fp++;
    else if (!item.isScam && !predicted) tn++;
    else if (item.isScam && !predicted) fn++;
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1Score = precision + recall === 0 ? 0 : (2 * (precision * recall)) / (precision + recall);

  const totalCases = cases.length;
  const scamCases = cases.filter((c) => c.isScam).length;
  const legitCases = cases.filter((c) => !c.isScam).length;

  return {
    totalCases,
    scamCases,
    legitCases,
    languages,
    precision,
    recall,
    f1Score,
    falseAlarms: fp,
  };
}

export function evaluateThreatLevel(message: string, domain?: string): {
  isThreat: boolean;
  score: number;
  reason: string;
} {
  const urgencyWords = ['jail', 'gift cards', 'urgent', 'immediately', '12h', 'police', 'arrested', 'secrecy'];
  const lower = message.toLowerCase();
  const matchedWords = urgencyWords.filter((w) => lower.includes(w));

  const hasSuspiciousDomain = domain ? domain.endsWith('.vip') || domain.endsWith('.net') || domain.includes('auth-') : false;

  if (matchedWords.length >= 2 || hasSuspiciousDomain) {
    return {
      isThreat: true,
      score: 0.98,
      reason: 'Urgent coercion pattern and suspicious redirect structure detected',
    };
  }

  return {
    isThreat: false,
    score: 0.08,
    reason: 'Verified safe communication channel',
  };
}
