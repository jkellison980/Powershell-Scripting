<#
.SYNOPSIS
    Microsoft 365 cloud offboarding helpers (interactive menu).

.DESCRIPTION
    Prompts for common actions taken during user offboarding in Microsoft 365
    (Graph + Exchange Online). Shows before/after state in the terminal for review.
    Complementary to on-prem AD termination tooling (AD.html) - do not merge AD
    into this file.

.RESTRICTIONS
    Works fully for cloud-only (O365-managed) accounts. Hybrid / AD-synced
    accounts (onPremisesSyncEnabled) will fail many cloud mutations; the script
    detects and warns, and advises running AD term first then syncing.

.NOTES
    Author:       Jeremy (hardened by Zeus for Michael Menor / Tactical IT)
    Version:      1.1.0
    Date:         2026-10-01
    History:
    1.1.0 - 2026-10-01 - Zeus harden for Michael: fix loops/selection bugs,
                          implement Set-MailSettings + Remove-UserLicenses,
                          Select All groups, disconnect try/finally, hybrid
                          guards, confirmations, before/after output.
    1.0.1 - 2026-08-24 - Implement Remove-Groups function
    1.0.0 - 2026-08-17 - Initial script creation.

.PENDINGFUNCTIONS
    Set-Mailbox permissions / Full Access / Send As (not in scope for 1.1.0)

.EXAMPLE
    # Install modules if missing, then run interactively (do not auto-run against prod):
    # Install-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, ExchangeOnlineManagement -Scope CurrentUser
    .\O365-Offboard.ps1
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, ExchangeOnlineManagement

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
$script:SelectedUser = $null

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------
function Test-MgGraphConnected {
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        return ($null -ne $ctx -and $null -ne $ctx.Account)
    }
    catch {
        return $false
    }
}

function Test-ExchangeOnlineConnected {
    try {
        $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' -and $_.Name -like 'ExchangeOnline*' }
        return ($null -ne $conn)
    }
    catch {
        return $false
    }
}

function Ensure-CloudConnections {
    $graphScopes = @(
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'GroupMember.ReadWrite.All',
        'Directory.Read.All',
        'LicenseAssignment.ReadWrite.All',
        'MailboxSettings.ReadWrite'
    )

    if (-not (Test-MgGraphConnected)) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -ContextScope Process -Scopes $graphScopes -NoWelcome | Out-Null
    }
    else {
        Write-Host "Microsoft Graph: already connected." -ForegroundColor DarkGreen
    }

    if (-not (Test-ExchangeOnlineConnected)) {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowBanner:$false
    }
    else {
        Write-Host "Exchange Online: already connected." -ForegroundColor DarkGreen
    }
}

function Disconnect-CloudSessions {
    Write-Host "Disconnecting Exchange Online and Microsoft Graph..." -ForegroundColor Yellow
    try {
        if (Test-ExchangeOnlineConnected) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host "EXO disconnect warning: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    try {
        if (Test-MgGraphConnected) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {
        Write-Host "Graph disconnect warning: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# User selection / hybrid helpers
# ---------------------------------------------------------------------------
function Test-UserSelected {
    if ($null -eq $script:SelectedUser) {
        Write-Host "No user selected. Choose option 6 (Select User) first." -ForegroundColor Red
        $prompt = Read-Host "Select a user now? (Y/N)"
        if ($prompt -match '^[Yy]') {
            Select-User
        }
        return ($null -ne $script:SelectedUser)
    }
    return $true
}

function Get-SelectedUserDetails {
    <#
    Refresh selected user with properties needed for offboard guards.
    #>
    if ($null -eq $script:SelectedUser) { return $null }
    try {
        $u = Get-MgUser -UserId $script:SelectedUser.Id -Property @(
            'Id', 'DisplayName', 'UserPrincipalName', 'Mail',
            'AccountEnabled', 'OnPremisesSyncEnabled', 'AssignedLicenses'
        ) -ErrorAction Stop
        $script:SelectedUser = $u
        return $u
    }
    catch {
        Write-Host "Unable to refresh user: $($_.Exception.Message)" -ForegroundColor Red
        return $script:SelectedUser
    }
}

function Test-CloudOnlyUser {
    param(
        [string]$ActionName,
        [switch]$WarnOnly
    )
    $u = Get-SelectedUserDetails
    if ($null -eq $u) { return $false }

    $synced = $false
    if ($null -ne $u.OnPremisesSyncEnabled -and $u.OnPremisesSyncEnabled -eq $true) {
        $synced = $true
    }

    if ($synced) {
        Write-Host ""
        Write-Host "WARNING: $($u.UserPrincipalName) is directory-synced (onPremisesSyncEnabled)." -ForegroundColor Yellow
        Write-Host "Cloud-only mutation '$ActionName' will likely fail for hybrid accounts." -ForegroundColor Yellow
        Write-Host "Guidance: complete AD termination first, allow sync, then re-run cloud steps." -ForegroundColor Cyan
        Write-Host "Complementary tool: on-prem AD.html (do not merge AD into this script)." -ForegroundColor Cyan
        if ($WarnOnly) {
            return $true
        }
        $cont = Read-Host "Attempt anyway? (Y/N)"
        if ($cont -notmatch '^[Yy]') {
            Write-Host "Skipped." -ForegroundColor Yellow
            return $false
        }
    }
    return $true
}

function Select-User {
    $searchTerm = Read-Host "Enter user's name or email"
    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "Empty search cancelled." -ForegroundColor Yellow
        return
    }

    try {
        $user = $null

        if ($searchTerm -match '@') {
            $user = Get-MgUser `
                -UserId $searchTerm `
                -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, OnPremisesSyncEnabled `
                -ErrorAction Stop
        }
        else {
            # Escape single quotes in OData filter
            $escaped = $searchTerm.Replace("'", "''")
            $users = @(Get-MgUser `
                -Filter "startswith(displayName,'$escaped') or startswith(userPrincipalName,'$escaped')" `
                -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, OnPremisesSyncEnabled `
                -ErrorAction Stop)

            if ($users.Count -eq 0) {
                Write-Host "No user found." -ForegroundColor Red
                return
            }

            if ($users.Count -gt 1) {
                Write-Host "`nMultiple users found:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $users.Count; $i++) {
                    Write-Host "$($i + 1). $($users[$i].DisplayName) - $($users[$i].UserPrincipalName)"
                }

                $validSelection = $false
                $selection = 0
                do {
                    $raw = Read-Host "Select user number"
                    if ($raw -notmatch '^\d+$') {
                        Write-Host "Invalid selection. Please enter a number." -ForegroundColor Red
                        continue
                    }
                    $selection = [int]$raw
                    if ($selection -lt 1 -or $selection -gt $users.Count) {
                        Write-Host "Invalid selection. Please choose a number between 1 and $($users.Count)." -ForegroundColor Red
                        continue
                    }
                    $validSelection = $true
                } while (-not $validSelection)

                $user = $users[$selection - 1]
            }
            else {
                $user = $users[0]
            }
        }

        $script:SelectedUser = $user

        Write-Host ""
        Write-Host "Selected user:" -ForegroundColor Green
        Write-Host "  Name:  $($SelectedUser.DisplayName)"
        Write-Host "  UPN:   $($SelectedUser.UserPrincipalName)"
        Write-Host "  Id:    $($SelectedUser.Id)"
        $enabled = if ($null -ne $SelectedUser.AccountEnabled) { $SelectedUser.AccountEnabled } else { '(unknown)' }
        Write-Host "  Sign-in enabled: $enabled"
        $sync = if ($null -ne $SelectedUser.OnPremisesSyncEnabled -and $SelectedUser.OnPremisesSyncEnabled) { 'Yes (hybrid)' } else { 'No (cloud-only or unknown)' }
        Write-Host "  Directory-synced: $sync"
        Write-Host ""
        Write-Host "Safety: this script never deletes the user object or purges the mailbox." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "Unable to find user: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------
function Get-Groups {
    if (-not (Test-UserSelected)) { return $null }

    try {
        $groups = Get-MgUserMemberOfAsGroup -UserId $SelectedUser.Id -All -ErrorAction Stop
        return @($groups)
    }
    catch {
        Write-Host "Failed to list groups: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Test-SkippableGroup {
    param($Group)
    # Cloud has no Domain Users; skip well-known / system groups that removal often fails on
    $skipNames = @(
        'All Users',
        'All Company'
    )
    if ($Group.DisplayName -and $skipNames -contains $Group.DisplayName) {
        return $true
    }
    # Dynamic membership / role-assignable often cannot be removed via member API
    try {
        $detail = Get-MgGroup -GroupId $Group.Id -Property 'Id,DisplayName,GroupTypes,MembershipRule,IsAssignableToRole' -ErrorAction SilentlyContinue
        if ($detail) {
            if ($detail.GroupTypes -contains 'DynamicMembership') { return $true }
            if ($detail.IsAssignableToRole -eq $true) { return $true }
            if (-not [string]::IsNullOrEmpty($detail.MembershipRule)) { return $true }
        }
    }
    catch {
        # If detail lookup fails, allow attempt; Remove-Groups catch will warn
    }
    return $false
}

function Remove-Groups {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Remove from groups' -WarnOnly)) { return }

    $groups = Get-Groups
    if ($null -eq $groups -or $groups.Count -eq 0) {
        Write-Host "User is not a member of any groups." -ForegroundColor Yellow
        return
    }

    Write-Host "`nGroups for $($SelectedUser.UserPrincipalName):" -ForegroundColor Cyan
    $groups | Select-Object DisplayName, Id, Mail, MailEnabled, SecurityEnabled |
        Format-Table -AutoSize | Out-Host

    for ($i = 0; $i -lt $groups.Count; $i++) {
        $flag = ''
        if (Test-SkippableGroup -Group $groups[$i]) {
            $flag = ' [dynamic/role/well-known - may skip]'
        }
        Write-Host "[$($i + 1)] $($groups[$i].DisplayName)$flag"
    }

    $selectedGroups = @()

    do {
        $choice = Read-Host "`nEnter group number, C: Clear, A: Select All, F: Finalize"

        if ($choice -eq 'F') {
            break
        }

        if ($choice -eq 'A') {
            $selectedGroups = @($groups)
            Write-Host "Selected ALL $($groups.Count) group(s)." -ForegroundColor Green
            continue
        }

        if ($choice -eq 'C') {
            $selectedGroups = @()
            Write-Host "Selection cleared." -ForegroundColor Yellow
            continue
        }

        if ($choice -match '^\d+$') {
            $index = [int]$choice - 1
            if ($index -ge 0 -and $index -lt $groups.Count) {
                $group = $groups[$index]
                if ($selectedGroups.Id -notcontains $group.Id) {
                    $selectedGroups += $group
                    Write-Host "Selected: $($group.DisplayName)" -ForegroundColor Green
                }
                else {
                    Write-Host "Group already selected." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "Invalid group number." -ForegroundColor Red
            }
        }
        else {
            Write-Host "Enter group number, C: Clear, A: Select All, F: Finalize" -ForegroundColor Red
        }
    } while ($true)

    if ($selectedGroups.Count -eq 0) {
        Write-Host "No groups selected for removal." -ForegroundColor Yellow
        return
    }

    Write-Host "`nGroups selected for removal:" -ForegroundColor Cyan
    foreach ($g in $selectedGroups) {
        Write-Host "  - $($g.DisplayName)"
    }
    $confirm = Read-Host "Confirm remove user from these groups? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($group in $selectedGroups) {
        if (Test-SkippableGroup -Group $group) {
            Write-Host "SKIP/WARN: $($group.DisplayName) looks dynamic, role-assignable, or well-known. Attempting anyway..." -ForegroundColor Yellow
        }

        Write-Host "Removing $($SelectedUser.UserPrincipalName) from $($group.DisplayName)..."
        try {
            Remove-MgGroupMemberDirectoryObjectByRef `
                -GroupId $group.Id `
                -DirectoryObjectId $SelectedUser.Id `
                -ErrorAction Stop
            Write-Host "  Successfully removed." -ForegroundColor Green
        }
        catch {
            Write-Host "  FAILED: $($group.DisplayName)" -ForegroundColor Red
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  (Dynamic / role-assignable / synced / well-known groups often cannot be removed in cloud.)" -ForegroundColor DarkYellow
        }
    }

    Write-Host "`nAfter (remaining memberships):" -ForegroundColor Cyan
    $after = Get-Groups
    if ($null -eq $after -or $after.Count -eq 0) {
        Write-Host "  (none)" -ForegroundColor Green
    }
    else {
        $after | Select-Object DisplayName, Id | Format-Table -AutoSize | Out-Host
    }
}

# ---------------------------------------------------------------------------
# Sign-in disable
# ---------------------------------------------------------------------------
function Disable-UserSignIn {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Disable sign-in')) { return }

    $u = Get-SelectedUserDetails
    $before = $u.AccountEnabled
    Write-Host "BEFORE AccountEnabled: $before" -ForegroundColor Cyan

    if ($before -eq $false) {
        Write-Host "Sign-in is already disabled." -ForegroundColor Yellow
        return
    }

    $confirm = Read-Host "Disable sign-in for $($u.DisplayName) ($($u.UserPrincipalName))? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Update-MgUser -UserId $u.Id -AccountEnabled:$false -ErrorAction Stop
        $afterUser = Get-MgUser -UserId $u.Id -Property AccountEnabled, DisplayName, UserPrincipalName
        Write-Host "AFTER AccountEnabled: $($afterUser.AccountEnabled)" -ForegroundColor Green
        Write-Host "$($afterUser.DisplayName) sign-in disabled." -ForegroundColor Green
        $script:SelectedUser = Get-SelectedUserDetails
    }
    catch {
        Write-Host "FAILED to disable sign-in." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "If this is a hybrid/AD-synced account, disable in Active Directory first, then sync." -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# Shared mailbox
# ---------------------------------------------------------------------------
function Convert-ToSharedMailbox {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Convert to shared mailbox' -WarnOnly)) { return }

    $upn = $SelectedUser.UserPrincipalName
    try {
        $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
    }
    catch {
        Write-Host "Unable to get mailbox: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hybrid mailboxes may need on-prem changes first." -ForegroundColor Cyan
        return
    }

    Write-Host "BEFORE RecipientTypeDetails: $($mbx.RecipientTypeDetails)" -ForegroundColor Cyan
    if ($mbx.RecipientTypeDetails -eq 'SharedMailbox') {
        Write-Host "Mailbox is already shared." -ForegroundColor Yellow
        return
    }

    Write-Host "Note: hybrid / remote mailboxes often cannot be converted via EXO alone." -ForegroundColor DarkYellow
    $confirm = Read-Host "Convert $($SelectedUser.DisplayName) mailbox to Shared? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Set-Mailbox -Identity $upn -Type Shared -ErrorAction Stop
        $after = Get-Mailbox -Identity $upn -ErrorAction Stop
        Write-Host "AFTER RecipientTypeDetails: $($after.RecipientTypeDetails)" -ForegroundColor Green
        Write-Host "Mailbox converted successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED to convert mailbox." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Hybrid may fail: convert/manage via on-prem Exchange or AD attributes, then sync." -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# Mail settings (menu option 4)
# ---------------------------------------------------------------------------
function Set-MailSettings {
    if (-not (Test-UserSelected)) { return }

    $upn = $SelectedUser.UserPrincipalName

    try {
        $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
    }
    catch {
        Write-Host "Unable to get mailbox: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hybrid errors are common; fix on-prem / sync first if needed." -ForegroundColor Cyan
        return
    }

    Write-Host "`n=== Current mailbox settings ===" -ForegroundColor Cyan
    Write-Host "  RecipientTypeDetails:           $($mbx.RecipientTypeDetails)"
    Write-Host "  ForwardingAddress:              $($mbx.ForwardingAddress)"
    Write-Host "  ForwardingSmtpAddress:          $($mbx.ForwardingSmtpAddress)"
    Write-Host "  DeliverToMailboxAndForward:     $($mbx.DeliverToMailboxAndForward)"
    Write-Host "  HiddenFromAddressListsEnabled:  $($mbx.HiddenFromAddressListsEnabled)"
    Write-Host "  LitigationHoldEnabled:          $($mbx.LitigationHoldEnabled)  (left alone unless you confirm elsewhere)"
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "Safety: Litigation Hold is NOT changed by this menu. User object is never deleted; mailbox is never purged." -ForegroundColor DarkGray

    do {
        Write-Host ""
        Write-Host "Mail settings actions:" -ForegroundColor Cyan
        Write-Host "  1. Hide from GAL (HiddenFromAddressListsEnabled = `$true)"
        Write-Host "  2. Clear forwarding (ForwardingAddress / ForwardingSmtpAddress)"
        Write-Host "  3. Set AutoReply (optional OOF)"
        Write-Host "  4. Refresh / show current settings"
        Write-Host "  5. Back to main menu"
        $sub = Read-Host "Select mail action"

        switch ($sub) {
            '1' {
                if (-not (Test-CloudOnlyUser -ActionName 'Hide from GAL' -WarnOnly)) { break }
                Write-Host "BEFORE HiddenFromAddressListsEnabled: $($mbx.HiddenFromAddressListsEnabled)" -ForegroundColor Cyan
                $c = Read-Host "Hide mailbox from GAL? (Y/N)"
                if ($c -notmatch '^[Yy]') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    break
                }
                try {
                    Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true -ErrorAction Stop
                    $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
                    Write-Host "AFTER HiddenFromAddressListsEnabled: $($mbx.HiddenFromAddressListsEnabled)" -ForegroundColor Green
                }
                catch {
                    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "Hybrid may require on-prem msExchHideFromAddressLists / sync." -ForegroundColor Cyan
                }
            }
            '2' {
                Write-Host "BEFORE ForwardingAddress: $($mbx.ForwardingAddress)" -ForegroundColor Cyan
                Write-Host "BEFORE ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)" -ForegroundColor Cyan
                $c = Read-Host "Clear all forwarding on this mailbox? (Y/N)"
                if ($c -notmatch '^[Yy]') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    break
                }
                try {
                    Set-Mailbox -Identity $upn -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
                    $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
                    Write-Host "AFTER ForwardingAddress: $($mbx.ForwardingAddress)" -ForegroundColor Green
                    Write-Host "AFTER ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)" -ForegroundColor Green
                }
                catch {
                    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '3' {
                $c = Read-Host "Configure AutoReply (Out of Office)? (Y/N)"
                if ($c -notmatch '^[Yy]') {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    break
                }
                $internal = Read-Host "Internal AutoReply message (or blank to skip setting)"
                $external = Read-Host "External AutoReply message (blank = same as internal / or leave)"
                if ([string]::IsNullOrWhiteSpace($external) -and -not [string]::IsNullOrWhiteSpace($internal)) {
                    $external = $internal
                }
                $audience = Read-Host "External audience: None / Known / All [All]"
                if ([string]::IsNullOrWhiteSpace($audience)) { $audience = 'All' }
                try {
                    # Prefer EXO cmdlet when available
                    if (Get-Command Set-MailboxAutoReplyConfiguration -ErrorAction SilentlyContinue) {
                        $params = @{
                            Identity          = $upn
                            AutoReplyState    = 'Enabled'
                            ExternalAudience  = $audience
                            ErrorAction       = 'Stop'
                        }
                        if (-not [string]::IsNullOrWhiteSpace($internal)) {
                            $params['InternalMessage'] = $internal
                        }
                        if (-not [string]::IsNullOrWhiteSpace($external)) {
                            $params['ExternalMessage'] = $external
                        }
                        Set-MailboxAutoReplyConfiguration @params
                        $ar = Get-MailboxAutoReplyConfiguration -Identity $upn
                        Write-Host "AFTER AutoReplyState: $($ar.AutoReplyState)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Set-MailboxAutoReplyConfiguration not available in this session." -ForegroundColor Red
                    }
                }
                catch {
                    Write-Host "FAILED AutoReply: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '4' {
                try {
                    $mbx = Get-Mailbox -Identity $upn -ErrorAction Stop
                    Write-Host "RecipientTypeDetails: $($mbx.RecipientTypeDetails)" -ForegroundColor Cyan
                    Write-Host "ForwardingAddress: $($mbx.ForwardingAddress)"
                    Write-Host "ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)"
                    Write-Host "HiddenFromAddressListsEnabled: $($mbx.HiddenFromAddressListsEnabled)"
                    Write-Host "LitigationHoldEnabled: $($mbx.LitigationHoldEnabled)"
                }
                catch {
                    Write-Host "Refresh failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '5' { return }
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
            }
        }
    } while ($true)
}

# ---------------------------------------------------------------------------
# Licenses (menu option 5)
# ---------------------------------------------------------------------------
function Remove-UserLicenses {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Remove licenses' -WarnOnly)) { return }

    try {
        $u = Get-MgUser -UserId $SelectedUser.Id -Property Id, UserPrincipalName, AssignedLicenses -ErrorAction Stop
        $skuList = @(Get-MgSubscribedSku -All -ErrorAction Stop)
        $skuMap = @{}
        foreach ($s in $skuList) {
            $skuMap[$s.SkuId] = $s.SkuPartNumber
        }
    }
    catch {
        Write-Host "Unable to list licenses: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($null -eq $u.AssignedLicenses -or $u.AssignedLicenses.Count -eq 0) {
        Write-Host "User has no assigned licenses." -ForegroundColor Yellow
        return
    }

    $assigned = @()
    Write-Host "`nAssigned licenses for $($u.UserPrincipalName):" -ForegroundColor Cyan
    $idx = 0
    foreach ($lic in $u.AssignedLicenses) {
        $idx++
        $name = if ($skuMap.ContainsKey($lic.SkuId)) { $skuMap[$lic.SkuId] } else { $lic.SkuId.ToString() }
        Write-Host "[$idx] $name  ($($lic.SkuId))"
        $assigned += [pscustomobject]@{ Index = $idx; SkuId = $lic.SkuId; Name = $name }
    }

    $selectedSkus = @()
    do {
        $choice = Read-Host "`nEnter license number, C: Clear, A: Select All, F: Finalize"
        if ($choice -eq 'F') { break }
        if ($choice -eq 'A') {
            $selectedSkus = @($assigned)
            Write-Host "Selected ALL $($assigned.Count) license(s)." -ForegroundColor Green
            continue
        }
        if ($choice -eq 'C') {
            $selectedSkus = @()
            Write-Host "Selection cleared." -ForegroundColor Yellow
            continue
        }
        if ($choice -match '^\d+$') {
            $n = [int]$choice
            $item = $assigned | Where-Object { $_.Index -eq $n } | Select-Object -First 1
            if ($null -eq $item) {
                Write-Host "Invalid license number." -ForegroundColor Red
            }
            elseif ($selectedSkus.SkuId -contains $item.SkuId) {
                Write-Host "Already selected." -ForegroundColor Yellow
            }
            else {
                $selectedSkus += $item
                Write-Host "Selected: $($item.Name)" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Enter license number, C: Clear, A: Select All, F: Finalize" -ForegroundColor Red
        }
    } while ($true)

    if ($selectedSkus.Count -eq 0) {
        Write-Host "No licenses selected." -ForegroundColor Yellow
        return
    }

    Write-Host "`nLicenses to remove:" -ForegroundColor Cyan
    foreach ($s in $selectedSkus) { Write-Host "  - $($s.Name)" }
    $confirm = Read-Host "Confirm license removal? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    Write-Host "BEFORE:" -ForegroundColor Cyan
    foreach ($lic in $u.AssignedLicenses) {
        $name = if ($skuMap.ContainsKey($lic.SkuId)) { $skuMap[$lic.SkuId] } else { $lic.SkuId }
        Write-Host "  $name"
    }

    $removeIds = @($selectedSkus | ForEach-Object { $_.SkuId })
    try {
        Set-MgUserLicense -UserId $u.Id -AddLicenses @() -RemoveLicenses $removeIds -ErrorAction Stop | Out-Null
        Write-Host "Licenses removed." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED license removal: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Group-based licensing or hybrid sync may block direct removal." -ForegroundColor Cyan
        return
    }

    try {
        $after = Get-MgUser -UserId $u.Id -Property AssignedLicenses -ErrorAction Stop
        Write-Host "AFTER:" -ForegroundColor Cyan
        if ($null -eq $after.AssignedLicenses -or $after.AssignedLicenses.Count -eq 0) {
            Write-Host "  (none)" -ForegroundColor Green
        }
        else {
            foreach ($lic in $after.AssignedLicenses) {
                $name = if ($skuMap.ContainsKey($lic.SkuId)) { $skuMap[$lic.SkuId] } else { $lic.SkuId }
                Write-Host "  $name"
            }
        }
    }
    catch {
        Write-Host "Could not refresh licenses: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
function Show-MainMenu {
    Clear-Host
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  Microsoft 365 Offboard 1.1.0" -ForegroundColor Cyan
    Write-Host "  (Jeremy / Zeus harden)" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    if ($null -ne $script:SelectedUser) {
        Write-Host "Selected: $($SelectedUser.DisplayName) <$($SelectedUser.UserPrincipalName)>" -ForegroundColor Green
    }
    else {
        Write-Host "Selected: (none - use option 6 first)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "1. Disable user sign-in"
    Write-Host "2. Remove user from groups"
    Write-Host "   2a. Get user groups"
    Write-Host "3. Convert mailbox to shared"
    Write-Host "4. Change mailbox settings"
    Write-Host "5. Remove licenses"
    Write-Host "6. Select User"
    Write-Host "7. Exit (disconnect Graph + EXO)"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Entry: connect, menu loop with try/finally disconnect
# ---------------------------------------------------------------------------
try {
    Ensure-CloudConnections

    $choice = $null
    do {
        Show-MainMenu
        $choice = Read-Host "Select an option"

        switch ($choice) {
            '1' {
                Write-Host "Running: Disable Sign-in..." -ForegroundColor Yellow
                Disable-UserSignIn
            }
            '2' {
                Write-Host "Running: Remove User From Groups..." -ForegroundColor Yellow
                Remove-Groups
            }
            '2a' {
                Write-Host "Running: Getting user groups..." -ForegroundColor Yellow
                $groups = Get-Groups
                if ($null -eq $groups -or $groups.Count -eq 0) {
                    Write-Host "User is not a member of any groups." -ForegroundColor Yellow
                }
                else {
                    Write-Host "`nGroups for $($SelectedUser.UserPrincipalName):" -ForegroundColor Cyan
                    Write-Host ""
                    $groups |
                        Select-Object DisplayName, Id, Mail, MailEnabled, SecurityEnabled |
                        Format-Table -AutoSize | Out-Host
                }
            }
            '3' {
                Write-Host "Running: Convert Mailbox..." -ForegroundColor Yellow
                Convert-ToSharedMailbox
            }
            '4' {
                Write-Host "Running: Mailbox Settings..." -ForegroundColor Yellow
                Set-MailSettings
            }
            '5' {
                Write-Host "Running: License Removal..." -ForegroundColor Yellow
                Remove-UserLicenses
            }
            '6' {
                Write-Host "Running: Select User..." -ForegroundColor Yellow
                Select-User
            }
            '7' {
                Write-Host "Exiting..." -ForegroundColor Green
            }
            default {
                Write-Host "Invalid selection. Please choose 1-7 (or 2a)." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }

        if ($choice -ne '7') {
            Write-Host ""
            Read-Host "Press Enter to return to the menu" | Out-Null
        }
    } while ($choice -ne '7')
}
finally {
    # Always disconnect on exit or Ctrl+C / terminating error
    Disconnect-CloudSessions
    Write-Host "Disconnected. Goodbye." -ForegroundColor Green
}
