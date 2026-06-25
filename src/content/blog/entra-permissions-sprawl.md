---
title: "Tackling Entra ID Permissions Sprawl at Scale"
date: "2026-03-28"
readTime: "7 min read"
tags: ["identity", "entra id", "graph api", "powershell"]
---

Every Entra ID tenant accumulates technical debt. It's not a failure of process — it's entropy. Apps get registered for a project that ended. Service principals get Global Admin "temporarily" for a migration that finished two years ago. Conditional Access exclusions get added during an incident and never get removed. Guest users from vendors whose contracts expired stay in the tenant indefinitely.

We've audited dozens of tenants. The patterns are identical across organizations of every size. Here's how we address each category systematically.

## The four categories of sprawl

### 1. Over-privileged service principals

Service principals (the identity used by apps and automation) are the most dangerous category of over-privilege. Unlike human identities, they don't get reviewed in access reviews by default, they don't show up in sign-in dashboards the same way, and they often have no owner who cares about them.

The worst offenders are always migration tools and legacy integrations. Someone needed Global Admin for an AD Sync migration in 2021. The migration finished, but nobody revoked the permission.

**How to find them:**

```powershell
$sp = Get-MgServicePrincipal -All
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All

$sp | ForEach-Object {
    $id = $_.Id
    $assignments = $roleAssignments | Where-Object { $_.PrincipalId -eq $id }
    if ($assignments) {
        [PSCustomObject]@{
            DisplayName = $_.DisplayName
            AppId       = $_.AppId
            Roles       = ($assignments.RoleDefinitionId -join ', ')
            LastSignIn  = $_.SignInAudience
        }
    }
} | Sort-Object DisplayName
```

Any service principal with Directory roles that aren't explicitly justified with a current, documented reason gets flagged for review. We've never seen a case where a service principal legitimately needed Global Admin that couldn't be replaced with a more scoped role.

### 2. Orphaned app registrations

App registrations accumulate when developers register apps for testing, POCs, or projects that ended. The danger isn't the registration itself — it's the client secrets and certificates attached to them.

An expired client secret on an orphaned app is low risk. An active client secret on an app registration that nobody monitors is a credential that an attacker can use to authenticate as that app with whatever permissions it has.

**Find registrations with active secrets and no recent sign-in activity:**

```powershell
$cutoff = (Get-Date).AddDays(-90)

Get-MgApplication -All | ForEach-Object {
    $app = $_
    $activeCreds = $app.PasswordCredentials | Where-Object { $_.EndDateTime -gt (Get-Date) }
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    $lastSignIn = $sp?.SignInActivity?.LastSignInDateTime

    if ($activeCreds -and ($lastSignIn -lt $cutoff -or -not $lastSignIn)) {
        [PSCustomObject]@{
            DisplayName  = $app.DisplayName
            AppId        = $app.AppId
            ActiveCreds  = $activeCreds.Count
            LastSignIn   = $lastSignIn ?? 'Never'
            Owners       = ($app.Owners | Select-Object -ExpandProperty Id) -join ', '
        }
    }
}
```

The remediation playbook: contact the listed owners. No response in 14 days → revoke the secrets. App registration still needed → owner re-registers with current ownership. App registration not needed → delete it.

### 3. Conditional Access exclusions

CA exclusions are the most politically sensitive category. They exist because something was broken and someone needed a fix now. "We'll clean it up later" is said in good faith. Later never comes.

The specific pattern that causes the most risk: exclusion groups with no expiration, no documentation, and membership that has grown over time. We once found a CA exclusion group called "MFA-Bypass-Temp" with 847 members, added over 4 years, with no documentation for any of them.

**Audit your CA policies for exclusions:**

```powershell
Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {
    $policy = $_
    $exclusions = $policy.Conditions.Users.ExcludeGroups

    if ($exclusions) {
        $exclusions | ForEach-Object {
            $group = Get-MgGroup -GroupId $_ -ErrorAction SilentlyContinue
            $memberCount = (Get-MgGroupMember -GroupId $_ -All).Count

            [PSCustomObject]@{
                Policy      = $policy.DisplayName
                GroupName   = $group.DisplayName
                GroupId     = $_
                MemberCount = $memberCount
                GroupAge    = $group.CreatedDateTime
            }
        }
    }
} | Sort-Object MemberCount -Descending
```

For each exclusion group: document why each member is in it, set an expiration on the group membership, and schedule a quarterly review. Groups with no documented justification for any member get emptied.

### 4. Stale guest users

Guest users from partner organizations, vendors, and former contractors accumulate silently. They retain access to whatever SharePoint sites, Teams channels, and apps they were given until someone explicitly removes them.

The Graph API makes bulk remediation straightforward:

```powershell
$cutoff = (Get-Date).AddDays(-180)

Get-MgUser -Filter "userType eq 'Guest'" -All | ForEach-Object {
    $lastSignIn = $_.SignInActivity?.LastSignInDateTime

    if (-not $lastSignIn -or $lastSignIn -lt $cutoff) {
        [PSCustomObject]@{
            DisplayName  = $_.DisplayName
            Mail         = $_.Mail
            LastSignIn   = $lastSignIn ?? 'Never'
            CreatedDate  = $_.CreatedDateTime
            InvitedBy    = $_.ExternalUserState
        }
    }
} | Sort-Object LastSignIn
```

We run this monthly and route the output to the guest's internal sponsor (if they have one) for an access decision. No sponsor, no response in 7 days → guest account disabled. Disabled for 30 days with no reactivation request → deleted.

## Making this sustainable

The mistake is treating this as a one-time cleanup project. Permission sprawl is entropy — it accumulates continuously. The cleanup has to become a recurring process.

What we run monthly via Azure Automation:
- SP over-privilege report → team lead review queue
- Orphaned app registration report → developer team Slack channel
- CA exclusion membership delta (new members added this month) → security team review
- Stale guest report → sponsor notification workflow

The monthly cadence catches drift before it compounds. The quarterly access review process (if you're doing one properly) catches the rest.

The tooling for all of this is in the entra-auditor repo. It outputs a prioritized HTML report that's easier to route to stakeholders than a raw PowerShell dump.
