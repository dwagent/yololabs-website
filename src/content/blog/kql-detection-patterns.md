---
title: "KQL Detection Patterns That Actually Reduce Alert Fatigue"
date: "2026-04-15"
readTime: "10 min read"
tags: ["kql", "sentinel", "detection", "soc"]
---

The difference between a SOC analyst who dreads coming to work and one who finds the job manageable often comes down to alert quality. High false positive rates aren't just annoying — they cause real harm. Analysts build up tolerance to alerts, start dismissing things without full investigation, and eventually miss the real incidents hidden in the noise.

Most Sentinel deployments we've worked in have false positive rates between 30–60% on their analytic rules. The organizations we've helped get this below 10% aren't using magic — they're applying a small set of structural patterns consistently.

## Why generic rules fail

The fundamental problem with out-of-the-box detection rules is that they're written against a hypothetical environment. "Alert if more than 10 failed logins in 5 minutes" sounds reasonable. In an organization with a large call center where agents routinely hit keyboard shortcuts that trigger failed auth, you're going to generate thousands of alerts per day.

The fix isn't to raise the threshold to 50, or 100. The fix is to detect *deviation from that user's baseline*, not violation of a global threshold. An account that normally has 0 failed logins per day and suddenly has 15 is interesting. An account that averages 8 per day and hits 15 is noise.

## Pattern 1: Baseline deviation instead of fixed thresholds

The structure: calculate the user's or entity's behavior over the last 14 days, then compare today's behavior to that baseline and alert when deviation exceeds a multiple of standard deviation.

```kql
let lookback = 14d;
let today = 1d;
let baseline = SigninLogs
    | where TimeGenerated > ago(lookback) and TimeGenerated < ago(today)
    | where ResultType != "0"
    | summarize AvgFailed = avg(count()), StdDevFailed = stdev(count())
        by UserPrincipalName, bin(TimeGenerated, 1d)
    | summarize BaselineAvg = avg(AvgFailed), BaselineStdDev = avg(StdDevFailed)
        by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(today)
| where ResultType != "0"
| summarize TodayFailed = count() by UserPrincipalName
| join kind=inner baseline on UserPrincipalName
| where TodayFailed > BaselineAvg + (3 * BaselineStdDev)
| where BaselineAvg > 0  // exclude accounts with no baseline
```

Three standard deviations from baseline catches real anomalies while tolerating natural variation. Adjust the multiplier based on your environment — two sigma for higher sensitivity, four for lower noise.

The catch: this requires 14 days of data before it's useful. For new environments, run in Report-Only for two weeks before enabling.

## Pattern 2: Correlated multi-event detection

Single-event rules are the loudest and least accurate. One failed login means nothing. Ten failed logins from different countries for the same account, followed by a successful login, followed by a password change — that means something.

The pattern: require a sequence of events within a time window, correlated by a shared entity (user, IP, device).

```kql
let failed_logins = SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType != "0"
    | summarize FailedCount = count(), Countries = make_set(Location)
        by UserPrincipalName
    | where FailedCount >= 5;
let successful_login = SigninLogs
    | where TimeGenerated > ago(30m)
    | where ResultType == "0"
    | project UserPrincipalName, SuccessTime = TimeGenerated;
let password_change = AuditLogs
    | where TimeGenerated > ago(30m)
    | where OperationName == "Change user password"
    | project UserPrincipalName = tostring(TargetResources[0].userPrincipalName),
              ChangeTime = TimeGenerated;
failed_logins
| join kind=inner successful_login on UserPrincipalName
| join kind=inner password_change on UserPrincipalName
| where ChangeTime > SuccessTime
| project UserPrincipalName, FailedCount, Countries, SuccessTime, ChangeTime
```

This generates far fewer alerts than any of the three individual rules — but almost every alert it generates is worth investigating.

## Pattern 3: Time-window aggregation with entity enrichment

Raw event counts are hard to contextualize. Enriching alerts with entity data (user's department, device ownership, recent activity) at query time means analysts have the context they need without pivoting to five other dashboards.

```kql
SecurityAlert
| where TimeGenerated > ago(1d)
| where AlertSeverity in ("High", "Medium")
| extend UserUpn = tostring(Entities[0].UserPrincipalName)
| join kind=leftouter (
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUPN
) on $left.UserUpn == $right.AccountUPN
| project TimeGenerated, AlertName, AlertSeverity, UserUpn,
          Department, JobTitle, AccountCreatedTime,
          RiskLevel = iff(JobTitle has_any("admin","executive"), "High", "Standard")
| order by RiskLevel desc, AlertSeverity desc
```

This doesn't reduce alert volume, but it dramatically reduces time-to-triage. An alert on an executive account goes straight to the top of the queue. An alert on a contractor account from a department with no sensitive data gets triaged differently.

## Pattern 4: Entity scoring

For high-volume environments, scoring is more scalable than individual alerts. Rather than firing an alert for every suspicious event, accumulate a risk score for each entity over a rolling window. Alert when the score exceeds a threshold.

```kql
let score_events = union
    (
        SigninLogs
        | where TimeGenerated > ago(24h) and ResultType != "0"
        | project UserPrincipalName, Score = 2, Reason = "failed_login"
    ),
    (
        SigninLogs
        | where TimeGenerated > ago(24h)
        | where IPAddress !in (trusted_ips)
        | project UserPrincipalName, Score = 5, Reason = "untrusted_ip"
    ),
    (
        AuditLogs
        | where TimeGenerated > ago(24h)
        | where OperationName has "privileged"
        | project UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName),
                  Score = 10, Reason = "privileged_operation"
    );
score_events
| summarize TotalScore = sum(Score), Reasons = make_set(Reason)
    by UserPrincipalName
| where TotalScore >= 15
| order by TotalScore desc
```

Scoring approaches work best as a daily scheduled rule rather than a near-real-time alert. You're looking for entities with sustained suspicious behavior, not single events.

## The rule that has prevented the most real incidents

Across all the detection work we've done, the single KQL rule that has triggered the most legitimate incident responses isn't complex. It's this: alert when an account that has never successfully authenticated from outside the country completes a successful authentication from outside the country, followed within 10 minutes by any bulk file download or export operation.

Not a sophisticated pattern. But it matches the actual attack chain for business email compromise and data exfiltration, and it almost never fires on legitimate activity.

The best detections aren't the most technically sophisticated ones. They're the ones that match real attacker behavior closely enough that false positives are structurally impossible, or nearly so.
