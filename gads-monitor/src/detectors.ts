// detectors.ts
// Rules that decide whether one Google Ads change_event deserves a Slack alert.
// See brief "Criteres d'alerte (a pousser sur Slack)".

export interface ChangeEvent {
  resourceName?: string;
  changeDateTime?: string;
  userEmail?: string;
  clientType?: string;
  changeResourceType?: string;
  changedFields?: string;
  resourceChangeOperation?: string;
  campaign?: string;
  adGroup?: string;
  oldResource?: any;
  newResource?: any;
}

export interface DetectionResult {
  matched: boolean;
  rule: string; // short rule id, used for dedup context
  headline: string;
  details: string[];
  why: string;
  actions: string[];
  critical?: boolean; // true => force 🚨 regardless of who did it (e.g. very large budget)
}

// Daily-budget thresholds in micros (1 $ = 1_000_000 micros), passed in from env.
// The signature of this incident is scripts that auto-create campaigns with huge
// daily budgets (~4500 $/day), so a high "critical" tier is the real smoking gun.
export interface EvalOptions {
  warnMicros: number; // at/above this on a new campaign -> alert ⚠️
  critMicros: number; // at/above this -> force 🚨 (auto-created big-budget campaign)
}

function micros(resource: any): number | null {
  // campaign_budget.amount_micros lives under different shapes depending on the
  // resource snapshot; try the common paths.
  const v =
    resource?.campaignBudget?.amountMicros ??
    resource?.amountMicros ??
    resource?.campaign_budget?.amount_micros;
  if (v == null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Returns a DetectionResult if the event matches any sensitive rule, else matched:false.
export function evaluate(ev: ChangeEvent, opts: EvalOptions): DetectionResult {
  const type = (ev.changeResourceType ?? "").toUpperCase();
  const op = (ev.resourceChangeOperation ?? "").toUpperCase();
  const client = (ev.clientType ?? "").toUpperCase();
  const fields = ev.changedFields ?? "";

  const no: DetectionResult = { matched: false, rule: "", headline: "", details: [], why: "", actions: [] };

  // 1. Manager link created or modified.
  if (type === "CUSTOMER_MANAGER_LINK" && (op === "CREATE" || op === "UPDATE")) {
    return {
      matched: true,
      rule: "manager_link",
      headline: `Manager link ${op} via ${ev.clientType ?? "?"}`,
      details: [
        `Type d'operation : CUSTOMER_MANAGER_LINK ${op}`,
        `Client : ${ev.clientType ?? "?"}`,
      ],
      why:
        "Un Manager link permet d'etendre le controle a de nouveaux comptes clients. " +
        "C'est exactement la mecanique qu'un attaquant utilise pour s'accrocher a la structure MCC.",
      actions: [
        "Confirmer avec la personne qu'elle a bien fait cette operation",
        "Si non : revoquer le Manager link et reset le mot de passe du compte concerne",
        "Verifier que le compte lie est un client legitime",
      ],
    };
  }

  // 2. User added to an account.
  if (type === "CUSTOMER_USER_ACCESS" && op === "CREATE") {
    return {
      matched: true,
      rule: "user_access",
      headline: "Nouvel utilisateur ajoute a un compte Google Ads",
      details: [`Type d'operation : CUSTOMER_USER_ACCESS ${op}`],
      why:
        "Ajouter un utilisateur a un compte est une facon directe pour l'attaquant de garder un acces " +
        "meme apres un reset de mot de passe.",
      actions: [
        "Verifier l'identite de l'utilisateur ajoute",
        "Si inconnu : retirer l'acces immediatement",
      ],
    };
  }

  // 3. Billing / payments changes.
  if (["BILLING_SETUP", "ACCOUNT_BUDGET", "PAYMENTS_ACCOUNT"].includes(type)) {
    return {
      matched: true,
      rule: "billing",
      headline: `Changement billing/payments (${type} ${op})`,
      details: [`Type d'operation : ${type} ${op}`],
      why:
        "Les changements de facturation peuvent rediriger les depenses ou ouvrir des budgets " +
        "que l'attaquant exploitera pour des campagnes frauduleuses.",
      actions: [
        "Confirmer le changement de facturation avec la direction",
        "Verifier le moyen de paiement et le budget de compte",
      ],
    };
  }

  // 4. New campaign budget with a notable daily amount. This is THE incident signature:
  //    a script creates a campaign whose budget is huge (~4500 $/day). The dollar amount
  //    lives on the CAMPAIGN_BUDGET resource (a CAMPAIGN only references its budget), so
  //    we key the budget check here, not on CAMPAIGN CREATE.
  if (type === "CAMPAIGN_BUDGET" && op === "CREATE") {
    const m = micros(ev.newResource);
    if (m != null && m >= opts.warnMicros) {
      const daily = (m / 1_000_000).toFixed(0);
      // A big absolute budget alone is only "worth a look" (⚠️): some clients legitimately
      // spend a lot. The 🚨 escalation is decided by the caller from the real signals
      // (non-human client / compromised account), not from the dollar amount by itself.
      return {
        matched: true,
        critical: false,
        rule: "campaign_big_budget",
        headline: `Nouveau budget de campagne : ${daily} $/jour`,
        details: [
          `Type d'operation : CAMPAIGN_BUDGET CREATE`,
          `Budget quotidien : ${daily} $/jour (au-dessus du seuil de revue ${(opts.warnMicros / 1_000_000).toFixed(0)} $/jour)`,
        ],
        why:
          "Le hack en cours cree des campagnes en automatique avec de gros budgets quotidiens. " +
          "Un nouveau budget eleve merite un coup d'oeil; il devient critique s'il a ete cree par " +
          "un script/API ou par un compte compromis (voir ci-dessus).",
        actions: [
          "Verifier que cette campagne/budget est reconnu",
          "Si genere par script/API ou non reconnu : mettre en PAUSE, revoquer l'acces et reset le mot de passe",
        ],
      };
    }
  }

  // 5. Budget increase of more than 50%.
  if (type === "CAMPAIGN_BUDGET" && op === "UPDATE") {
    const oldM = micros(ev.oldResource);
    const newM = micros(ev.newResource);
    if (oldM != null && newM != null && oldM > 0 && newM > oldM * 1.5) {
      const pct = (((newM - oldM) / oldM) * 100).toFixed(0);
      // Drastic = more than tripled (relative), OR above the absolute critical backstop.
      // Relative is the priority signal: a small budget suddenly exploding is suspicious
      // even if the absolute number is modest.
      const isCrit = newM > oldM * 3 || newM >= opts.critMicros;
      return {
        matched: true,
        critical: isCrit,
        rule: "budget_increase",
        headline: `Augmentation de budget de +${pct}% (vers ${(newM / 1_000_000).toFixed(0)} $/jour)`,
        details: [
          `Ancien budget : ${(oldM / 1_000_000).toFixed(2)} $/jour`,
          `Nouveau budget : ${(newM / 1_000_000).toFixed(2)} $/jour`,
        ],
        why:
          "Une hausse brutale de budget est une facon discrete d'augmenter la depense frauduleuse " +
          "sans creer de nouvelle campagne visible.",
        actions: [
          "Verifier que la hausse est legitime",
          "Si non : remettre l'ancien budget et investiguer le compte",
        ],
      };
    }
  }

  // 6. Paused campaign re-enabled.
  if (type === "CAMPAIGN" && op === "UPDATE" && fields.includes("status")) {
    const oldStatus = (ev.oldResource?.campaign?.status ?? ev.oldResource?.status ?? "").toUpperCase();
    const newStatus = (ev.newResource?.campaign?.status ?? ev.newResource?.status ?? "").toUpperCase();
    if (oldStatus === "PAUSED" && newStatus === "ENABLED") {
      return {
        matched: true,
        rule: "campaign_reactivated",
        headline: "Campagne en pause reactivee",
        details: ["Statut : PAUSED -> ENABLED"],
        why:
          "Reactiver une vieille campagne en pause est un moyen de relancer une depense sans " +
          "creer de campagne nouvelle qui attirerait l'oeil.",
        actions: ["Confirmer la reactivation", "Si non reconnue : remettre en pause et investiguer"],
      };
    }
  }

  // 7. Conversion action created.
  if (type === "CONVERSION_ACTION" && op === "CREATE") {
    return {
      matched: true,
      rule: "conversion_action",
      headline: "Nouvelle conversion action creee",
      details: [`Type d'operation : CONVERSION_ACTION ${op}`],
      why:
        "Les conversions fraudees servent a tromper le Smart Bidding pour qu'il pousse la depense " +
        "vers les pages de l'attaquant.",
      actions: ["Verifier la conversion action et sa source"],
    };
  }

  // 8. client_type GOOGLE_ADS_API or OTHER (rare chez Rablab, toujours a verifier).
  if (client === "GOOGLE_ADS_API" || client === "OTHER") {
    return {
      matched: true,
      rule: "api_client",
      headline: `Operation via client externe : ${ev.clientType}`,
      details: [
        `Type d'operation : ${type} ${op}`,
        `Client : ${ev.clientType}`,
      ],
      why:
        "Les operations par API ou outil externe sont rares chez Rablab. Un attaquant qui pilote " +
        "le compte par script utilisera ce canal.",
      actions: ["Identifier l'outil/script a l'origine de cette operation"],
    };
  }

  // 9. Bulk / CSV upload (pattern Tristan du 1er juin).
  if (client.includes("BULK") || fields.includes("Generated sheet") || client.includes("LOCAL_FILE")) {
    return {
      matched: true,
      rule: "bulk_upload",
      headline: "Operation bulk / upload CSV",
      details: [
        `Type d'operation : ${type} ${op}`,
        `Client : ${ev.clientType}`,
      ],
      why:
        "Un upload CSV / bulk peut creer ou modifier en masse des liens, budgets ou campagnes " +
        "d'un coup. C'est le pattern observe le 1er juin.",
      actions: ["Recuperer le fichier uploade et verifier chaque ligne"],
    };
  }

  return no;
}
