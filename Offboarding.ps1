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
    Version:      1.1.1
    Date:         2026-10-05
    History:
    1.1.1 - 2026-10-05 - Reformat Code, add Show-Groups function, improve 
                          group handling.
    1.1.0 - 2026-10-01 - Zeus harden for Michael: fix loops/selection bugs,
                          implement MailboxMenu + Invoke-RemoveLicenses
                        ,
                          Select All groups, disconnect try/finally, hybrid
                          guards, confirmations, before/after output.
    1.0.1 - 2026-08-24 - Implement Invoke-RemoveGroups
 function
    1.0.0 - 2026-08-17 - Initial script creation.

.PENDINGFUNCTIONS
    Set-Mailbox permissions / Full Access / Send As (not in scope for 1.1.1)
    Get-Mailbox Permissions | Get-RecipientPermission
    Export Offboarding Report

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

function Export-OffboardingReport {

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

function Test-CloudOnlyUser {
    param(
        [string]$ActionName,
        [switch]$WarnOnly
    )
    $selectedUser = Get-SelectedUserDetails
    if ($null -eq $selectedUser) { return $false }

    $synced = $false
    if ($null -ne $selectedUser.OnPremisesSyncEnabled -and $selectedUser.OnPremisesSyncEnabled -eq $true) {
        $synced = $true
    }

    if ($synced) {
        Write-Host ""
        Write-Host "WARNING: $($selectedUser.UserPrincipalName) is directory-synced (onPremisesSyncEnabled)." -ForegroundColor Yellow
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
        # If detail lookup fails, allow attempt; Invoke-RemoveGroups
     catch will warn
    }
    return $false
}

function Get-Groups-Data {
    if (-not (Test-UserSelected)) { return $null }

    try {
        $groups = Get-MgUserMemberOfAsGroup -UserId $script:SelectedUser.Id -All -ErrorAction Stop
        return @($groups)
    }
    catch {
        Write-Host "Failed to list groups: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-SelectedUserDetails {
    <#
    Refresh selected user with properties needed for offboard guards.
    #>
    if ($null -eq $script:SelectedUser) { return $null }
    try {
        $selectedUser = Get-MgUser -UserId $script:SelectedUser.Id -Property @(
            'Id', 'DisplayName', 'UserPrincipalName', 'Mail',
            'AccountEnabled', 'OnPremisesSyncEnabled', 'AssignedLicenses'
        ) -ErrorAction Stop
        $script:SelectedUser = $selectedUser
        return $selectedUser
    }
    catch {
        Write-Host "Unable to refresh user: $($_.Exception.Message)" -ForegroundColor Red
        return $script:SelectedUser
    }
}

function Get-LicenseData
 {

    if (-not (Test-UserSelected)) { return }

    try {
        $selectedUser = Get-MgUser `
            -UserId $script:SelectedUser.Id `
            -Property Id, DisplayName, UserPrincipalName, AssignedLicenses `
            -ErrorAction Stop

        $skuList = @(Get-MgSubscribedSku -All -ErrorAction Stop)

        $skuMap = @{}
        foreach ($sku in $skuList) {
            $skuMap[$sku.SkuId] = $sku.SkuPartNumber
        }

        $licenses = foreach ($license in $selectedUser.AssignedLicenses) {
            [PSCustomObject]@{
                LicenseName = if ($skuMap.ContainsKey($license.SkuId)) {
                    $skuMap[$license.SkuId]
                }
                else {
                    $license.SkuId
                }
            }
        }
        return [PSCustomObject]@{
            User        = $selectedUser
            Licenses    = $licenses
        }
        
    }
    catch {
        Write-Host "Unable to retrieve license information: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

function Get-MailboxData {
    if (-not (Test-UserSelected)) {return $null}

    try{
        return Get-Mailbox `
        -Identity $script:SelectedUser.UserPrincipalName -ErrorAction Stop
    }
    catch {
        Write-Host "Unable to get mailbox: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hybrid errors are common; fix on-prem / sync first if needed." -ForegroundColor Cyan
        return $null
    }
}

function Show-AccountLockStatus {
    if (-not (Test-UserSelected)) { return }

    $selectedUser = Get-SelectedUserDetails
    if ($null -eq $selectedUser) {return}

    $mailbox = Get-MailboxData
    $groups = Get-Groups-Data
    $licenses = Get-LicenseData

    Write-Host ""
    Write-Host "Account Lock Status" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan

    Write-Host "Display Name : $($selectedUser.DisplayName)"
    Write-Host "UPN : $($selectedUser.UserPrincipalName)"
    Write-Host ""

    Write-Host "Account Status" -ForegroundColor Cyan
    Write-Host "----------------" -ForegroundColor Cyan

    if ($selectedUser.AccountEnabled) {
        Write-Host "Sign-In Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "Sign-In Disabled" -ForegroundColor Yellow
    }

    if ($selectedUser.OnPremisesSyncEnabled) {
        Write-Host "[INFO] Hybrid / AD Synced Account" -ForegroundColor Cyan
    }
    else {
        Write-Host "[INFO] Cloud Only Account" -ForegroundColor Cyan
    }
    
    Write-Host ""
    
    if ($mailbox) {
        Write-Host "Mailbox Status" -ForegroundColor Cyan
        Write-Host "--------------" -ForegroundColor Cyan
        
        Write-Host "Recipient Type : $($mailbox.RecipientTypeDetails)"
        
        if ($mailbox.HiddenFromAddressListsEnabled) {
            Write-Host "Hidden From GAL" -ForegroundColor Yellow
        }
        else {
            Write-Host "Visible In GAL" -ForegroundColor Green
        }
        
        if ([string]:: -and [string]:: {
            Write-Host "[PASS] No Mail Forwarding Configured" -ForegroundColor Green
        }
        else {
            Write-Host "[WARN] Mail Forwarding Present" -ForegroundColor Yellow
        }
        
        Write-Host "Litigation Hold : $($mailbox.LitigationHoldEnabled)"
        Write-Host ""
    }
    
    Write-Host "License Status" -ForegroundColor Cyan
    Write-Host "--------------" -ForegroundColor Cyan
    
    if ($licenseData -and $licenseData.Licenses.Count -gt 0) {
        Write-Host "[INFO] Licenses Assigned: $($licenseData.Licenses.Count)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[PASS] No Assigned Licenses" -ForegroundColor Green
    }
    
    Write-Host ""
    
    Write-Host "Group Membership" -ForegroundColor Cyan
    Write-Host "----------------" -ForegroundColor Cyan
    
    if ($groups.Count -gt 0) {
        Write-Host "[INFO] Group Memberships Remaining: $($groups.Count)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[PASS] No Group Memberships Remaining" -ForegroundColor Green
    }
    
    Write-Host ""

}

function Show-Groups {
    $groups = Get-Groups-Data

    if ($null -eq $groups -or $groups.Count -eq 0) {
        Write-Host ""
        Write-Host "Group Membership Information" -ForegroundColor Cyan
        Write-Host "========================" -ForegroundColor Cyan
        Write-Host "User is not a member of any groups." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Group Membership Information" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan

    Write-Host "Display Name : $($script:SelectedUser.DisplayName)"
    Write-Host "UPN : $($script:SelectedUser.UserPrincipalName)"
    Write-Host ""

    $groups | 
        Sort-Object DisplayName |
        Select-Object `
            DisplayName,
            Mail,
            MailEnabled,
            SecurityEnabled |
        Format-Table -Autosize |
        Out-Host

    Write-Host ""
    Write-Host "Total Groups: $($groups.Count)" -ForegroundColor Green
}

function Show-Licenses {
    $licenseData = Get-LicenseData


    if ($null -eq $licenseData) {return}

    Write-Host ""
    Write-Host "User License Information" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan

    Write-Host "Display Name : $($licenseData.User.DisplayName)"
    Write-Host "UPN : $($licenseData.User.UserPrincipalName)"
    Write-Host ""

    if ($licenseData.Licenses.Count -eq 0) {
        Write-Host "No licenses assigned." -ForegroundColor Yellow
        return
    }

    $licenseData.Licenses |
        Sort-Object LicenseName |
        Format-Table LicenseName, SkuId -AutoSize |
        Out-Host

    Write-Host ""
    Write-Host "Total Licenses Assigned: $($licenseData.Licenses.Count)" -ForegroundColor Green
}

function Show-MailboxMenu {
    Clear-Host

    Write-Host "======================" -ForegroundColor Cyan
    Write-Host " Mailbox Menu"
    Write-Host "======================" -ForegroundColor Cyan

    if ($null -ne $script:SelectedUser) {
        Write-Host ""
        Write-Host "Selected User:" -ForegroundColor Green
        Write-Host "$($script:SelectedUser.DisplayName)"
        Write-Host "$($script:SelectedUser.UserPrincipalName)"
    }

    Write-Host ""
    Write-Host "1. Hide From GAL"
    Write-Host "2. Clear Forwarding"
    Write-Host "3. Configure AutoReply"
    Write-Host "4. Show Mailbox Settings"
    Write-Host "B. Back"
    Write-Host ""
}

function Show-MailboxSettings {
    $mbx = Get-MailboxData

    if ($null -eq $mbx) { return }

    Write-Host ""
    Write-Host "Mailbox Settings" -ForegroundColor Cyan
    Write-Host "================" -ForegroundColor Cyan

    Write-Host "Display Name : $($mbx.DisplayName)"
    Write-Host "UPN : $($mbx.UserPrincipalName)"
    Write-Host ""

    Write-Host "RecipientTypeDetails: $($mbx.RecipientTypeDetails)"
    Write-Host "ForwardingAddress: $($mbx.ForwardingAddress)"
    Write-Host "ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)"
    Write-Host "DeliverToMailboxAndForward: $($mbx.DeliverToMailboxAndForward)"
    Write-Host "HiddenFromAddressListsEnabled: $($mbx.HiddenFromAddressListsEnabled)"
    Write-Host "LitigationHoldEnabled: $($mbx.LitigationHoldEnabled)"
}

# ---------------------------------------------------------------------------
# Main Menu Options
# ---------------------------------------------------------------------------
function Select-User {
    $searchTerm = Read-Host "Enter user's name or email"
    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        Write-Host "Empty search cancelled." -ForegroundColor Yellow
        return
    }

    try {
        $selectedUser = $null

        if ($searchTerm -match '@') {
            $selectedUser = Get-MgUser `
                -UserId $searchTerm `
                -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, OnPremisesSyncEnabled `
                -ErrorAction Stop
        }
        else {
            # Escape single quotes in OData filter
            $escaped = $searchTerm.Replace("'", "''")
            $selectedUsers = @(Get-MgUser `
                -Filter "startswith(displayName,'$escaped') or startswith(userPrincipalName,'$escaped')" `
                -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, OnPremisesSyncEnabled `
                -ErrorAction Stop)

            if ($selectedUsers.Count -eq 0) {
                Write-Host "No user found." -ForegroundColor Red
                return
            }

            if ($selectedUsers.Count -gt 1) {
                Write-Host "`nMultiple users found:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $selectedUsers.Count; $i++) {
                    Write-Host "$($i + 1). $($selectedUsers[$i].DisplayName) - $($selectedUsers[$i].UserPrincipalName)"
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
                    if ($selection -lt 1 -or $selection -gt $selectedUsers.Count) {
                        Write-Host "Invalid selection. Please choose a number between 1 and $($selectedUsers.Count)." -ForegroundColor Red
                        continue
                    }
                    $validSelection = $true
                } while (-not $validSelection)

                $selectedUser = $selectedUsers[$selection - 1]
            }
            else {
                $selectedUser = $selectedUsers[0]
            }
        }

        $script:SelectedUser = $selectedUser

        Write-Host ""
        Write-Host "Selected user:" -ForegroundColor Green
        Write-Host "  Name:  $($script:SelectedUser.DisplayName)"
        Write-Host "  UPN:   $($script:SelectedUser.UserPrincipalName)"
        Write-Host "  Id:    $($script:SelectedUser.Id)"
        $enabled = if ($null -ne $script:SelectedUser.AccountEnabled) { $script:SelectedUser.AccountEnabled } else { '(unknown)' }
        Write-Host "  Sign-in enabled: $enabled"
        $sync = if ($null -ne $script:SelectedUser.OnPremisesSyncEnabled -and $script:SelectedUser.OnPremisesSyncEnabled) { 'Yes (hybrid)' } else { 'No (cloud-only or unknown)' }
        Write-Host "  Directory-synced: $sync"
        Write-Host ""
        Write-Host "Safety: this script never deletes the user object or purges the mailbox." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "Unable to find user: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Offboarding Menu Options
# ---------------------------------------------------------------------------
function Invoke-BlockUserSignIn {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Disable sign-in')) { return }

    $selectedUser = Get-SelectedUserDetails
    $before = $selectedUser.AccountEnabled
    Write-Host "BEFORE AccountEnabled: $before" -ForegroundColor Cyan

    if ($before -eq $false) {
        Write-Host "Sign-in is already disabled." -ForegroundColor Yellow
        return
    }

    $confirm = Read-Host "Disable sign-in for $($selectedUser.DisplayName) ($($selectedUser.UserPrincipalName))? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Update-MgUser -UserId $selectedUser.Id -AccountEnabled:$false -ErrorAction Stop
        $afterUser = Get-MgUser -UserId $selectedUser.Id -Property AccountEnabled, DisplayName, UserPrincipalName
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

function Invoke-ClearMailForwarding {
    $mbx = Get-MailboxData

    if ($null -eq $mbx) {return}

    Write-Host "BEFORE ForwardingAddress: $($mbx.ForwardingAddress)" -ForegroundColor Cyan
    Write-Host "BEFORE ForwardingSmtpAddress: $($mbx.ForwardingSmtpAddress)" -ForegroundColor Cyan

    $confirm = Read-Host "Clear mail forwarding for $($mbx.DisplayName) ($($mbx.UserPrincipalName))? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Set-Mailbox `
            -Identity $script:SelectedUser.UserPrincipalName `
            -ForwardingAddress $null `
            -ForwardingSmtpAddress $null `
            -DeliverToMailboxAndForward $false `
            -ErrorAction Stop
        
        $after = Get-MailboxData
        Write-Host "AFTER ForwardingAddress: $($after.ForwardingAddress)" -ForegroundColor Green
        Write-Host "AFTER ForwardingSmtpAddress: $($after.ForwardingSmtpAddress)" -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED to clear mail forwarding." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

function Invoke-ConvertToSharedMailbox {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Convert to shared mailbox' -WarnOnly)) { return }

    $upn = $script:SelectedUser.UserPrincipalName
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
    $confirm = Read-Host "Convert $($script:SelectedUser.DisplayName) mailbox to Shared? (Y/N)"
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

function Invoke-DisabledMailboxOOF {

}

function Invoke-FullAccountLock {
    if (-not (Test-UserSelected)) { return }

    $selectedUser = Get-SelectedUserDetails
}

function Invoke-HideFromGAL {
    if (-not (Test-CloudOnlyUser -ActionName 'Hide from GAL' -WarnOnly)) {return}
    
    $mbx = Get-MailboxData
    
    if ($null -eq $mbx) { return }
    
    Write-Host "BEFORE HiddenFromAddressListsEnabled: $($mbx.HiddenFromAddressListsEnabled)" -ForegroundColor Cyan
    $confirm = Read-Host "Hide mailbox from GAL? (Y/N)"
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    
    try {
        Set-Mailbox `
            -Identity $script:SelectedUser.UserPrincipalName `
            -HiddenFromAddressListsEnabled $true `
            -ErrorAction Stop
    
        $after = Get-MailboxData

        Write-Host "AFTER HiddenFromAddressListsEnabled: $($after.HiddenFromAddressListsEnabled)" -ForegroundColor Green  
    }
    catch {
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hybrid may require on-prem changes and sync." -ForegroundColor Cyan
    }
}

function Invoke-MobileDeviceWipe {
    Get-MobileDevice
    Clear-MobileDevice
}

function Invoke-PasswordReset {

}

function Invoke-RemoveGroups {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Remove from groups' -WarnOnly)) { return }

    $groups = Get-Groups-Data
    if ($null -eq $groups -or $groups.Count -eq 0) {
        Write-Host "User is not a member of any groups." -ForegroundColor Yellow
        return
    }

    Write-Host "`nGroups for $($script:SelectedUser.UserPrincipalName):" -ForegroundColor Cyan
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

        Write-Host "Removing $($script:SelectedUser.UserPrincipalName) from $($group.DisplayName)..."
        try {
            Remove-MgGroupMemberDirectoryObjectByRef `
                -GroupId $group.Id `
                -DirectoryObjectId $script:SelectedUser.Id `
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
    $after = Get-Groups-Data
    if ($null -eq $after -or $after.Count -eq 0) {
        Write-Host "  (none)" -ForegroundColor Green
    }
    else {
        $after | Select-Object DisplayName, Id | Format-Table -AutoSize | Out-Host
    }
}

function Invoke-RemoveLicenses {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Remove licenses' -WarnOnly)) { return }

    try {
        $selectedUser = Get-MgUser -UserId $script:SelectedUser.Id -Property Id, UserPrincipalName, AssignedLicenses -ErrorAction Stop
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

    if ($null -eq $selectedUser.AssignedLicenses -or $selectedUser.AssignedLicenses.Count -eq 0) {
        Write-Host "User has no assigned licenses." -ForegroundColor Yellow
        return
    }

    $assigned = @()
    Write-Host "`nAssigned licenses for $($selectedUser.UserPrincipalName):" -ForegroundColor Cyan
    $idx = 0
    foreach ($lic in $selectedUser.AssignedLicenses) {
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
    foreach ($lic in $selectedUser.AssignedLicenses) {
        $name = if ($skuMap.ContainsKey($lic.SkuId)) { $skuMap[$lic.SkuId] } else { $lic.SkuId }
        Write-Host "  $name"
    }

    $removeIds = @($selectedSkus | ForEach-Object { $_.SkuId })
    try {
        Set-MgUserLicense -UserId $selectedUser.Id -AddLicenses @() -RemoveLicenses $removeIds -ErrorAction Stop | Out-Null
        Write-Host "Licenses removed." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED license removal: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Group-based licensing or hybrid sync may block direct removal." -ForegroundColor Cyan
        return
    }

    try {
        $after = Get-MgUser -UserId $selectedUser.Id -Property AssignedLicenses -ErrorAction Stop
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

function Invoke-RevokeActiveSessions {
    if (-not (Test-UserSelected)) { return }
    if (-not (Test-CloudOnlyUser -ActionName 'Revoke active sessions')) { return }

    $selectedUser = Get-SelectedUserDetails
    $confirm = Read-Host "Revoke active sessions for $($selectedUser.DisplayName) ($($selectedUser.UserPrincipalName))? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Revoke-MgUserSignInSession -UserId $selectedUser.Id -ErrorAction Stop
        Write-Host "Active sessions revoked for $($selectedUser.DisplayName)." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED to revoke active sessions." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

function Invoke-SetMailboxOOF {
    if (-not (Test-UserSelected)) { return }

    $mailbox = Get-MailboxData
    if ($null -eq $mailbox) { return }

    Write-Host ""
    Write-Host "Configure Out of Office" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan

    try {
        $current = Get-MailboxAutoReplyConfiguration `
        -Identity $script:SelectedUser.UserPrincipalName `
        -ErrorAction Stop

        Write-Host "Current Settings" -ForegroundColor Cyan
        Write-Host "----------------" -ForegroundColor Cyan
        Write-Host "AutoReply State : $($current.AutoReplyState)"
        Write-Host "External Audience : $($current.ExternalAudience)"
        Write-Host ""
    }
    catch {
        Write-Host "Unable to retrieve current AutoReply settings." -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor DarkYellow
    }

    $confirm = Read-Host "Configure Out of Office for $($script:SelectedUser.DisplayName)? (Y/N)"

    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }

    $internalMessage = Read-Host "Internal AutoReply message"
    $externalMessage = Read-Host "External AutoReply message (blank = same as internal)"
    if ([string]:: IsNullOrWhiteSpace( $externalMessage ) ) {
        $externalMessage = $internalMessage
    }

    $audience = Read-Host "External audience: None / Known / All [All]"

    if ([string]::IsNullOrWhiteSpace($audience)) {
        $audience = 'All'
    }

    try {
        $params = @{
        Identity = $script:SelectedUser.UserPrincipalName
        AutoReplyState = 'Enabled'
        ExternalAudience = $audience
        ErrorAction = 'Stop'
        }
        if (-not [string]:: IsNullOrWhiteSpace( $internalMessage ) ) {
            $params['InternalMessage'] = $internalMessage
        }

        if (-not [string]:: IsNullOrWhiteSpace( $externalMessage ) ) {
            $params['ExternalMessage'] = $externalMessage
        }

        Set-MailboxAutoReplyConfiguration @params

        $after = Get-MailboxAutoReplyConfiguration `
        -Identity $script:SelectedUser.UserPrincipalName `
        -ErrorAction Stop

        Write-Host ""
        Write-Host "AutoReply configured successfully." -ForegroundColor Green
        Write-Host ""
        Write-Host "Updated Settings" -ForegroundColor Cyan
        Write-Host "----------------" -ForegroundColor Cyan
        Write-Host "AutoReply State : $($after.AutoReplyState)"
        Write-Host "External Audience : $($after.ExternalAudience)"
    }
    catch {
        Write-Host "FAILED to configure AutoReply." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}



# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------
function OffboardingMenu {
    if (-not (Test-UserSelected)) { return }
    
    do {
    
        Write-Host ""
        Write-Host "Account Lock Actions:" -ForegroundColor Cyan
        Write-Host " 1. Disable User Sign-In"
        Write-Host " 2. Revoke Active Sessions"
        Write-Host " 3. Reset Password"
        Write-Host " 4. Remote Wipe Mobile Devices"
        Write-Host " 5. Execute Full Lock Checklist"
        Write-Host " 6. Refresh Status"
        Write-Host " 7. Back to Main Menu"
        
        $sub = Read-Host "Select account lock action"
        
        switch ($sub) {
        
            '1' { Invoke-BlockUserSignIn }
            
            '2' { Invoke-RevokeActiveSessions }
            
            '3' { Invoke-PasswordReset }
            
            '4' { Invoke-MobileDeviceWipe }
            
            '5' { Invoke-FullAccountLock }
            
            '6' { Show-AccountLockStatus }
            
            '7' { return }
            
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
            }
        }
    
    } while ($true)
}

function MailboxMenu {
    if (-not (Test-UserSelected)) { return }
    
    do {
        Show-MailboxMenu
        $choice = Read-Host "Select an option"
        
        switch ($choice) {
            '1' { Invoke-HideFromGAL }
            '2' { Invoke-ClearMailForwarding }
            '3' { Invoke-SetMailboxOOF }
            '4' { Show-MailboxSettings }
            'B' { return }
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
            }
        }
        
        if ($choice -ne 'B') {
            Write-Host ""
            Read-Host "Press Enter to continue" | Out-Null
        }
    
    } while ($true)
}

function MainMenu {
    Clear-Host
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  Microsoft 365 Offboard 1.1.1" -ForegroundColor Cyan
    Write-Host "  (Jeremy / Zeus harden)" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    if ($null -ne $script:SelectedUser) {
        Write-Host "Selected: $($script:SelectedUser.DisplayName) <$($script:SelectedUser.UserPrincipalName)>" -ForegroundColor Green
    }
    else {
        Write-Host "Selected: (none - use option 1 first)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "1. Select User"
    Write-Host "2. Offboarding Menu"
    Write-Host "2a. Disable user sign-in"
    Write-Host "2b. Revoke Active Sessions"
    Write-Host "3. Show Groups"
    Write-Host "4. Show Licenses"
    Write-Host "5. Convert Mailbox to Shared"
    Write-Host "6. Change Mailbox Settings"
    Write-Host "E. Exit (disconnect Graph + EXO)"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Entry: connect, menu loop with try/finally disconnect
# ---------------------------------------------------------------------------
try {
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptPath

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    $script:TranscriptFile = Join-Path `
        $scriptDir `
        "O365-Offboard-$timestamp.log"

    Start-Transcript -Path $script:TranscriptFile -Force

    Ensure-CloudConnections

    $choice = $null
    do {
        MainMenu
    
        $choice = Read-Host "Select an option"

        switch ($choice) {
            '1' {
                Write-Host "Running: Select User..." -ForegroundColor Yellow
                Select-User
            }
            '2' {
                OffboardingMenu
            }
            '2a' {
                Write-Host "Running: Disable Sign-in..." -ForegroundColor Yellow
                #Invoke-BlockUserSignIn
            }
            '2b' {
                Write-Host "Running: Revoke Active Sessions..." -ForegroundColor Yellow
                #Invoke-RevokeActiveSessions
            }
            '3' {
                Write-Host "Running: Getting user groups..." -ForegroundColor Yellow
                Show-Groups
            }
            '4' {
                Write-Host "Running: Getting Licenses..." -ForegroundColor Yellow
                Show-Licenses
            }
            '5' {
                Write-Host "Running: Convert Mailbox..." -ForegroundColor Yellow
                #Invoke-ConvertToSharedMailbox
                
            }
            '6' {
                Write-Host "Running: Mailbox Settings..." -ForegroundColor Yellow
                #MailboxMenu
            }
            'E' {
                Write-Host "Exiting..." -ForegroundColor Green
            }
            default {
                Write-Host "Invalid selection. Please choose 1-6, or 'E' to exit." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }

        if ($choice -ne 'E') {
            Write-Host ""
            Read-Host "Press Enter to return to the menu" | Out-Null
        }
    } while ($choice -ne 'E')
}
finally {
    # Always disconnect on exit or Ctrl+C / terminating error
    Disconnect-CloudSessions

    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # Ignore if transcript wasn't started
    }
    
    Write-Host "Transcript saved to:"
    Write-Host $script:TranscriptFile -ForegroundColor Green

    Write-Host "Disconnected. Goodbye." -ForegroundColor Green
}
