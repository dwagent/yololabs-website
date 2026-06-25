---
title: "Building a Security-First Azure Landing Zone in 2026"
date: "2026-05-22"
readTime: "12 min read"
tags: ["azure", "iac", "bicep", "governance"]
---

The Microsoft Azure Landing Zone accelerator is genuinely good. It enforces management group hierarchy, handles policy inheritance correctly, and gives you a solid foundation for enterprise Azure. But its security defaults are far too permissive for production.

This is what we add on top.

## What the default ALZ leaves open

Before criticizing the defaults, it's worth understanding why they're permissive: the ALZ accelerator is trying to deploy without breaking your existing workloads. Aggressive deny policies on day one would block migrations. Microsoft errs on the side of not breaking things.

The gaps that matter most in practice:

**No default retention on Log Analytics.** The workspace is created, but retention is set to 30 days. For most compliance frameworks (PCI, HIPAA, FedRAMP), you need 90 days minimum hot retention with a year of cold storage. Set it at the workspace level or you'll be paying for remediation later.

**Defender for Cloud plans aren't all enabled.** The default deployment enables some plans but not all. Defender for Servers, Databases, and Storage all need explicit opt-in. At scale, managing this per-subscription doesn't work — you need a policy that auto-provisions the plans.

**No NSG flow logs.** Network Security Group flow logs give you the telemetry you need for network-level detection and forensics. They're not on by default. Enable them with a policy, send them to a storage account, and funnel them to your Log Analytics workspace.

**Storage accounts are too permissive.** The default ALZ doesn't prevent public blob access or enforce minimum TLS versions on new storage accounts. A policy deny on `allowBlobPublicAccess: true` would catch this, but it's not there out of the box.

**Guest user invitations are unrestricted.** Entra ID defaults allow any member user to invite guest users. In most enterprise tenants, you want this restricted to specific roles or disabled entirely.

## The security overlay approach

Rather than forking the ALZ and maintaining a parallel version (a maintenance nightmare), we extend it with a security overlay: a separate Bicep module that deploys on top of the ALZ and adds the missing controls.

The overlay is structured as a custom Azure Policy initiative per framework: one for CIS Azure Foundations Benchmark L1, one for our internal baseline. This makes compliance reporting straightforward — you can see exactly which controls are from which framework.

```bicep
// security-baseline-initiative.bicep
resource securityInitiative 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = {
  name: 'yololabs-security-baseline'
  properties: {
    displayName: 'YoloLabs Security Baseline'
    policyType: 'Custom'
    policyDefinitions: [
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/...'
        // Require secure transfer to storage accounts
      }
      // ... additional policies
    ]
  }
}
```

The initiative is assigned at the root management group scope, so it applies to every subscription automatically. New subscriptions inherit it on creation.

## The audit → deny progression

One lesson learned the hard way: don't deploy deny effects on day one.

We run every new policy in audit mode for 30 days first. This generates compliance data without blocking anything. You review the non-compliant resources, triage them (legitimate exception, or something that needs fixing), and document your decision.

After 30 days, you switch to deny for new resources while leaving existing non-compliant resources flagged for remediation. This prevents the sprawl from getting worse while giving existing workloads time to remediate.

After 90 days, if the remediation rate is high enough, you add a remediation task to auto-fix existing resources. For most policy types, there's a built-in remediation action.

The progression: `Audit` → `Deny (new only)` → `DeployIfNotExists` with remediation.

## Defender for Cloud configuration that actually works

The default Defender for Cloud configuration sends every alert to the Azure portal and stops there. You need to get those alerts into your SIEM.

The alert pipeline we use:
1. Defender for Cloud → Event Hub (continuous export)
2. Event Hub → Microsoft Sentinel (data connector)
3. Sentinel analytics rules fire on Defender alerts

The continuous export is underused. It's free, it's built-in, and it means every Defender alert is queryable in Sentinel within minutes.

One Sentinel rule worth enabling immediately: alert on any Defender for Cloud high-severity finding that has been open for more than 72 hours without a status change. This catches alerts that fell through the cracks — not because nobody triaged them, but because the triage workflow failed silently.

## The one metric that matters

We measure landing zone security posture with a single metric: **Secure Score delta from baseline over 90 days**.

Secure Score goes down when new resources are deployed non-compliantly and up when remediations happen. Tracking the delta (not the absolute score) tells you whether your controls are working or whether new deployments are outpacing your remediation capacity.

If the delta is negative for two consecutive months, you have a process problem, not a technical one. Either your policy is too aggressive and people are finding workarounds, or your remediation workflow is broken.

Fix the process, not the score.

## The Bicep module

The full overlay is published on our GitHub. It's structured to be applied after the ALZ accelerator deploys and doesn't conflict with any ALZ-managed resources. PRs welcome — especially for additional compliance frameworks.
