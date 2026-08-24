<#
.SYNOPSIS
    Remove permissions from O365 management of users

.DESCRIPTION
    Script that prompts for common actions taken during user offboarding. It will log in to the 
	user portal on each session and then list available actions to take. Output of before and 
	after states will be given to terminal for review.

.RESTRICTIONS
	This only works fully for O365 managed user accounts. Accounts that are Hybrid/AD-Sync Managed
	will encounter errors when attempting to use some functions.

.ISSUES
Microsoft Graph needs permissions granted to be able to access anything and I do not feel comfortable
giving permissions.

.NOTES
    Author:       Jeremy
    Version:      1.0.0
    Date:         2026-08-24
    History:
	1.0.1 - 2026-08-24 - Impliment Remove-Groups function
    1.0.0 - 2026-08-17 - Initial script creation.
	
.PENDINGFUNCTIONS
	Remove-Groups
	SET-Mailbox-permissions
	Remove-License

#>

#Global Variables
$SelectedUser = $null

# Connect Microsoft Graph
Connect-MgGraph `
    -ContextScope Process `
    -Scopes "User.ReadWrite.All","Group.ReadWrite.All","GroupMember.ReadWrite.All","Directory.Read.All","LicenseAssignment.ReadWrite.All"

#Connect Exchange Online
Connect-ExchangeOnline

function Get-Groups {
	if ($null -eq $SelectedUser) {
        Write-Host "No user selected." -ForegroundColor Red
        return
    }
	
	$groups = Get-MgUserMemberOfAsGroup `
		-UserID $SelectedUser.Id `
		-All 
	
	return $groups
}

function Remove-Groups { #currently shows what is considered a group
	if ($null -eq $SelectedUser) {
        Write-Host "No user selected." -ForegroundColor Red
        return
    }
	
	#Get Groups
	$groups = Get-Groups
	
	if ($null -eq $groups -or $groups.Count -eq 0) {
		Write-Host "User is not a member of any groups." -ForegroundColor Yellow
		return
	}
	
	$groups | Select-Object DisplayName, Id, Mail, MailEnabled, SecurityEnabled | 
		Format-Table -AutoSize
		
	#Display Groups
	Write-Host "`nGroups for $($SelectedUser.UserPrincipalName):" -ForegroundColor Cyan
	
	for ($i = 0; $i -lt $groups.Count; i++) {
		Write-Host "[$($i + 1)] $($groups[$i].DisplayName)"
	}
	
	# Selection Loop
	$selectedGroups = @()
	
	do {
        $choice = Read-Host "`nEnter group number, C: Clear, A: Select All and F: Finalize"

        if ($choice -eq 'F') {
            break
        }
		
		if ($choice -eq 'A') {
            Write-Host "Function Not Yet Implemented"
        }
		
		if ($choice -eq 'C') {
            $selectedGroups = @()
        }
		
        if ($choice -match '^\d+$') {

        $index = [int]$choice - 1

        if ($index -ge 0 -and $index -lt $groups.Count) {

            $group = $groups[$index]

            if ($selectedGroups.Id -notcontains $group.Id) {

                $selectedGroups += $group

                Write-Host "Selected: $($group.DisplayName)" `
                    -ForegroundColor Green
            }
            else {
                Write-Host "Group already selected." `
                    -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Invalid group number." `
                -ForegroundColor Red
        }
    }
    else {
        Write-Host "Enter group number, C: Clear, A: Select All and F: Finalize" `
            -ForegroundColor Red
    }

    } while ($true)

    # Show final selection
    Write-Host "`nGroups selected for removal:" -ForegroundColor Cyan

    foreach ($group in $selectedGroups) {
        Write-Host "Removing $($SelectedUser.UserPrincipalName) from $($group.DisplayName)..."
		
		try {
			Remove-MgGroupMemberDirectoryObjectByRef `
				-GroupId $group.Id `
				-DirectoryObjectId $SelectedUser.Id `
				-ErrorAction Stop

			Write-Host "Successfully removed." -ForegroundColor Green
		}
		catch {
			Write-Host "FAILED: $($group.DisplayName)" -ForegroundColor Red
			Write-Host $_.Exception.Message -ForegroundColor Yellow
		}
    }
}

function Disable-UserSignIn {
	
    if ($null -eq $SelectedUser) {
        Write-Host "No user selected." -ForegroundColor Red
        return
    }

    Update-MgUser `
        -UserId $SelectedUser.Id `
        -AccountEnabled:$false

    Write-Host "$($SelectedUser.DisplayName) sign-in disabled." -ForegroundColor Green
}

function Select-User {
    $searchTerm = Read-Host "Enter user's name or email"

    try {
        # Looks like an email
        if ($searchTerm -match "@") {
            $user = Get-MgUser `
                -UserId $searchTerm `
                -Property Id, DisplayName, UserPrincipalName, Mail
        }
        else {
            # Search by display name
            $users = @(Get-MgUser `
                -Filter "displayName eq '$searchTerm'" `
                -Property Id, DisplayName, UserPrincipalName, Mail)
        }

        if ($searchTerm -notmatch "@") {
            if ($users.Count -eq 0) {
                Write-Host "No user found." -ForegroundColor Red
                return
            }

            if ($users.Count -gt 1) {
                Write-Host "`nMultiple users found:" -ForegroundColor Yellow

                for ($i = 0; $i -lt $users.Count; $i++) {
                    Write-Host "$($i + 1). $($users[$i].DisplayName) - $($users[$i].UserPrincipalName)"
                }

                do {
					$selection = Read-Host "Select user number"

					if ($selection -notmatch '^\d+$') {
						Write-Host "Invalid selection. Please enter a number." -ForegroundColor Red
						continue
					}

					$selection = [int]$selection

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
        Write-Host "Name: $($SelectedUser.DisplayName)"
        Write-Host "Email: $($SelectedUser.UserPrincipalName)"
        Write-Host ""
    }
    catch {
        Write-Host "Unable to find user: $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Convert-ToSharedMailbox {

    if ($null -eq $SelectedUser) {
        Write-Host "No user selected." -ForegroundColor Red
        return
    }

    Write-Host "Converting $($SelectedUser.DisplayName) to shared mailbox..."

    Set-Mailbox -Identity $SelectedUser.UserPrincipalName -Type Shared

    Write-Host "Mailbox converted successfully." -ForegroundColor Green
}


#switch option, needs to be at bottom of script
do {
    Clear-Host

    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "     Microsoft 365 Admin" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Disable user sign-in"
    Write-Host "2. Remove user from groups"
	Write-Host "	2a. Get user grups"
    Write-Host "3. Convert mailbox to shared"
    Write-Host "4. Change mailbox settings"
    Write-Host "5. Remove licenses"
    Write-Host "6. Select User"
    Write-Host "7. Exit"
    Write-Host ""

    $choice = Read-Host "Select an option"

    switch ($choice) {

        "1" {
            Write-Host "Running: Disable Sign-in..." -ForegroundColor Yellow

            # Your disable user sign-in function here
            Disable-UserSignIn
        }

        "2" {
            Write-Host "Running: Remove User From Groups..." -ForegroundColor Yellow

            # Your group removal function here
            Remove-Groups
        }
		
		"2a" {
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
                    Format-Table -AutoSize
            }
        }

        "3" {
            Write-Host "Running: Convert Mailbox..." -ForegroundColor Yellow

            # Your mailbox conversion function here
            Convert-ToSharedMailbox
        }

        "4" {
            Write-Host "Running: Mailbox Settings..." -ForegroundColor Yellow

            # Your mail settings function here
            Set-MailSettings
        }

        "5" {
            Write-Host "Running: License Removal..." -ForegroundColor Yellow

            # Your license function here
            Remove-UserLicenses
        }

        "6" {
            Write-Host "Running: Select User..." -ForegroundColor Yellow

            # Your Select User function here
            Select-User
        }

        "7" {
            Write-Host "Exiting..." -ForegroundColor Green
			
			Disconnect-ExchangeOnline -Confirm:$false
			Disconnect-MgGraph
			Pause
        }

        default {
            Write-Host "Invalid selection. Please choose 1-7." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }

    if ($choice -ne "7") {
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
    }

} while ($choice -ne "7")