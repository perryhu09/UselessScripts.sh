# Fixed/updated version of win_harden.ps1
# - Replaced nonexistent Pause calls with Read-Host pauses
# - Made secure_registry_settings set registry value types based on the value type (DWord vs String)
# - Minor robustness fixes (type casts) to avoid common runtime errors

function manageLocalGroups {
    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session."
        return
    }

    # Helper: get applicable local users (exclude built-ins)
    function Get-ManagedLocalUsers {
        Get-LocalUser -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Enabled -and
                -not ($_.Name -in @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount'))
            } | Select-Object -ExpandProperty Name
    }

    while ($true) {
        Clear-Host
        Write-Host "Local Groups:"
        Get-LocalGroup | Select-Object -Property Name, Description | Format-Table -AutoSize
        Write-Host ""
        Write-Host "Options:"
        Write-Host " 1) Add ALL managed local users to Administrators"
        Write-Host " 2) Remove ALL managed local users from Administrators"
        Write-Host " 3) Add ALL managed local users to Users group"
        Write-Host " 4) Remove ALL managed local users from Users group"
        Write-Host " 5) Create new local user(s)"
        Write-Host " 6) Create a group and add ALL managed users into it"
        Write-Host " 7) Remove a local group (will remove its members first)"
        Write-Host " 8) Manage a single group (interactive add/remove individual users)"
        Write-Host " 9) Exit"
        $choice = Read-Host "Select an option [1-9]"

        switch ($choice) {
            '1' {
                $users = Get-ManagedLocalUsers
                if (-not $users) { Write-Host "No eligible users found."; Read-Host "Press Enter to continue" | Out-Null; continue }
                if ((Read-Host "Add these users to Administrators? `n$($users -join ', ')`nConfirm (Y/N)") -notmatch '^[Yy]') { continue }
                try {
                    Add-LocalGroupMember -Group 'Administrators' -Member $users -ErrorAction Stop
                    Write-Host "Added users to Administrators."
                } catch {
                    Write-Host "Error adding users: $_"
                }
            }
            '2' {
                $members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                           Where-Object { $_.ObjectClass -eq 'User' -and -not ($_.Name -eq 'Administrator') } |
                           Select-Object -ExpandProperty Name
                if (-not $members) { Write-Host "No removable user members found in Administrators."; Read-Host "Press Enter to continue" | Out-Null; continue }
                if ((Read-Host "Remove these users from Administrators? `n$($members -join ', ')`nConfirm (Y/N)") -notmatch '^[Yy]') { continue }
                try {
                    Remove-LocalGroupMember -Group 'Administrators' -Member $members -ErrorAction Stop
                    Write-Host "Removed users from Administrators."
                } catch {
                    Write-Host "Error removing users: $_"
                }
            }
            '3' {
                $users = Get-ManagedLocalUsers
                if (-not $users) { Write-Host "No eligible users found."; Read-Host "Press Enter to continue" | Out-Null; continue }
                if ((Read-Host "Add these users to Users group? `n$($users -join ', ')`nConfirm (Y/N)") -notmatch '^[Yy]') { continue }
                try {
                    Add-LocalGroupMember -Group 'Users' -Member $users -ErrorAction Stop
                    Write-Host "Added users to Users group."
                } catch {
                    Write-Host "Error adding users: $_"
                }
            }
            '4' {
                $members = Get-LocalGroupMember -Group 'Users' -ErrorAction SilentlyContinue |
                           Where-Object { $_.ObjectClass -eq 'User' } |
                           Select-Object -ExpandProperty Name
                if (-not $members) { Write-Host "No user members found in Users group."; Read-Host "Press Enter to continue" | Out-Null; continue }
                if ((Read-Host "Remove these users from Users group? `n$($members -join ', ')`nConfirm (Y/N)") -notmatch '^[Yy]') { continue }
                try {
                    Remove-LocalGroupMember -Group 'Users' -Member $members -ErrorAction Stop
                    Write-Host "Removed users from Users group."
                } catch {
                    Write-Host "Error removing users: $_"
                }
            }
            '5' {
                $input = Read-Host "Enter new user names (comma-separated)"
                if (-not $input) { Write-Host "No users specified."; continue }
                $names = $input -split '\s*,\s*' | Where-Object { $_ -ne '' }
                $pwdPlain = Read-Host "Enter a password to assign to all new users (will be used as plain text)" -AsSecureString
                $pwd = $pwdPlain
                foreach ($n in $names) {
                    try {
                        if (Get-LocalUser -Name $n -ErrorAction SilentlyContinue) {
                            Write-Host "User $n already exists. Skipping."
                            continue
                        }
                        New-LocalUser -Name $n -Password $pwd -FullName $n -Description "Created by script" -ErrorAction Stop
                        Add-LocalGroupMember -Group 'Users' -Member $n -ErrorAction SilentlyContinue
                        Write-Host "Created user $n and added to Users."
                    } catch {
                        Write-Host "Failed to create ${n}: $($_)"
                    }
                }
            }
            '6' {
                $groupName = Read-Host "Enter new group name"
                if (-not $groupName) { Write-Host "No group name provided."; continue }
                if (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue) {
                    Write-Host "Group $groupName already exists."
                    continue
                }
                try {
                    New-LocalGroup -Name $groupName -Description "Created and populated by script" -ErrorAction Stop
                    $users = Get-ManagedLocalUsers
                    if ($users) {
                        Add-LocalGroupMember -Group $groupName -Member $users -ErrorAction SilentlyContinue
                        Write-Host "Created group $groupName and added users: $($users -join ', ')"
                    } else {
                        Write-Host "Created group $groupName (no users found to add)."
                    }
                } catch {
                    Write-Host "Failed to create/populate group: $_"
                }
            }
            '7' {
                $groupName = Read-Host "Enter group name to remove"
                if (-not $groupName) { Write-Host "No group name provided."; continue }
                if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
                    Write-Host "Group $groupName does not exist."
                    continue
                }
                $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                Write-Host "Group $groupName members: $($members -join ', ')"
                if ((Read-Host "Remove all members and delete group $groupName? (Y/N)") -notmatch '^[Yy]') { continue }
                try {
                    if ($members) { Remove-LocalGroupMember -Group $groupName -Member $members -ErrorAction SilentlyContinue }
                    Remove-LocalGroup -Name $groupName -ErrorAction Stop
                    Write-Host "Removed group $groupName."
                } catch {
                    Write-Host "Failed to remove group: $_"
                }
            }
            '8' {
                $group = Read-Host "Enter group to manage (existing)"
                if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
                    Write-Host "Group $group not found."; continue
                }
                while ($true) {
                    Write-Host "Members of ${group}:"
                    Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Format-Table -AutoSize
                    $action = Read-Host "Action: add / remove / back"
                    switch ($action.ToLower()) {
                        'add' {
                            $userAdd = Read-Host "Enter user name(s) to add (comma-separated)"
                            $list = $userAdd -split '\s*,\s*' | Where-Object { $_ -ne '' }
                            try { Add-LocalGroupMember -Group $group -Member $list -ErrorAction Stop; Write-Host "Added: $($list -join ', ')" } catch { Write-Host "Error: $_" }
                        }
                        'remove' {
                            $userRem = Read-Host "Enter user name(s) to remove (comma-separated)"
                            $list = $userRem -split '\s*,\s*' | Where-Object { $_ -ne '' }
                            try { Remove-LocalGroupMember -Group $group -Member $list -ErrorAction Stop; Write-Host "Removed: $($list -join ', ')" } catch { Write-Host "Error: $_" }
                        }
                        'back' {
                            break
                        }
                        default { Write-Host "Unknown action." }
                    }
                }
            }
            '9' {
                break
            }
            default {
                Write-Host "Invalid selection."
            }
        }
        Write-Host ""
        if ($choice -ne '9') { Read-Host "Press Enter to continue" | Out-Null }
        if ($choice -eq '9') { break }
    }
}


function check_audit_policy {
    param(
        [switch]$Fix
    )

    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session."
        return
    }

    Write-Host "Querying local audit policy (auditpol)..."

    $raw = & auditpol.exe /get /subcategory:* /r 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $raw) {
        Write-Host "Failed to query audit policy."
        return
    }

    $lines = $raw -split "`n" | ForEach-Object { $_.TrimEnd() } |
             Where-Object { $_ -and ($_ -notmatch '^Category') -and ($_ -notmatch '^-{2,}') }

    $nonCompliant = @()
    foreach ($line in $lines) {
        if ($line -match '^(?<subcat>.+?)\s{2,}(?<setting>.+)$') {
            $subcat = $matches['subcat'].Trim()
            $setting = $matches['setting'].Trim()

            $hasSuccess = $setting -match 'Success'
            $hasFailure = $setting -match 'Failure'

            if (-not ($hasSuccess -and $hasFailure)) {
                $nonCompliant += [PSCustomObject]@{
                    Subcategory = $subcat
                    Setting     = $setting
                }
            }
        }
    }

    if ($nonCompliant.Count -eq 0) {
        Write-Host "All audit subcategories report both Success and Failure."
        return
    }

    Write-Host "The following audit subcategories are missing Success and/or Failure:"
    $nonCompliant | ForEach-Object { Write-Host " - $($_.Subcategory) => $($_.Setting)" }

    if ($Fix) {
        foreach ($item in $nonCompliant) {
            try {
                Write-Host "Enabling Success and Failure for: $($item.Subcategory)"
                & auditpol.exe /set /subcategory:"$($item.Subcategory)" /success:enable /failure:enable 2>&1 | Out-Null
                Write-Host "  -> applied"
            } catch {
                Write-Host "  -> failed to apply: $($_)"
            }
        }

        Write-Host "Re-checking audit policy..."
        return (check_audit_policy)  # recursive call without -Fix to report final state
    }
}

#User Accounts
function check_user_accounts {
    Write-Host "Checking user accounts and permissions..."
    
    $users = Get-LocalUser
    
    # Check administrator accounts
    $adminUsers = Get-LocalGroupMember -Group "Administrators"
    Write-Host "Administrator accounts:"
    $adminUsers | ForEach-Object { Write-Host " - $($_.Name)" }

    # Check guest account status
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Enabled) {
            Write-Host "WARNING: Guest account is enabled."
            $confirm = Read-Host "Do you want to disable the Guest account? (Y/N)"
            if ($confirm -eq "Y") {
                Disable-LocalUser -Name "Guest"
                Write-Host "Guest account has been disabled."
            } else {
                Write-Host "Guest account remains enabled."
            }
        } else {
            Write-Host "Guest account is properly disabled."
        }
    }

    # Check guest group permissions
    $guestGroup = Get-LocalGroup -Name "Guests" -ErrorAction SilentlyContinue
    if ($guestGroup) {
        $guestMembers = Get-LocalGroupMember -Group "Guests" -ErrorAction SilentlyContinue
        if ($guestMembers) {
            Write-Host "WARNING: Users found in Guests group:"
            $guestMembers | ForEach-Object { Write-Host " - $($_.Name)" }
        } else {
            Write-Host "No users found in Guests group - Good."
        }
    }
}

function Set-AllLocalPasswords {
    param(
        [switch]$Force
    )

    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session."
        return
    }

    $confirmMsg = "This will set the password for ALL enabled local accounts to 'CyberPatri0t!'. Continue? (Y/N)"
    if (-not $Force) {
        if ((Read-Host $confirmMsg) -notmatch '^[Yy]') {
            Write-Host "Aborted by user."
            return
        }
    }

    $securePwd = ConvertTo-SecureString "CyberPatri0t!" -AsPlainText -Force
    $changed = @()
    $failed  = @()

    # Collect enabled local users, skip known system accounts that should not be modified
    $skip = @('WDAGUtilityAccount','DefaultAccount')
    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue |
                  Where-Object { $_.Enabled -and -not ($_.Name -in $skip) } |
                  Select-Object -ExpandProperty Name

    foreach ($u in $localUsers) {
        try {
            Set-LocalUser -Name $u -Password $securePwd -ErrorAction Stop

            # Enforce expiration and require change at next logon (best-effort; some parameters may be unavailable depending on OS)
            try { Set-LocalUser -Name $u -PasswordNeverExpires $false -ErrorAction SilentlyContinue } catch {}
            try { Set-LocalUser -Name $u -PasswordExpires $true -ErrorAction SilentlyContinue } catch {}
            try { Set-LocalUser -Name $u -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue } catch {}

            $changed += $u
        } catch {
            $failed += [PSCustomObject]@{User = $u; Error = $_.Exception.Message}
        }
    }

    Write-Host "Password change complete."
    if ($changed.Count -gt 0) {
        Write-Host "Changed passwords for:"
        $changed | ForEach-Object { Write-Host " - $_" }
    } else {
        Write-Host "No local users had passwords changed."
    }

    if ($failed.Count -gt 0) {
        Write-Host "Failures:"
        $failed | ForEach-Object { Write-Host " - $($_.User) : $($_.Error)" }
    }
}

function update_firefox {
    Write-Host "Updating Firefox..."
    try {
        # Check if Firefox is installed
        $firefoxPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
        if (Test-Path $firefoxPath) {
            # Launch Firefox with update parameter (best-effort)
            Start-Process $firefoxPath -ArgumentList "-update" -Wait
            Write-Host "Firefox update check completed."
        } else {
            Write-Host "Firefox is not installed in the default location."
        }
    } catch {
        Write-Host "Error updating Firefox: $_"
    }
}
function firewall_status {
    # Ensure firewall profiles are enabled and default inbound action is Block
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
        if (-not $p.Enabled) {
            Write-Host "Firewall profile '$($p.Name)' is disabled. Enabling now..."
            try { Set-NetFirewallProfile -Name $p.Name -Enabled True -ErrorAction Stop } catch { Write-Host "Failed to enable $($p.Name): $($_.Exception.Message)" }
        } else {
            Write-Host "Firewall profile '$($p.Name)' is already enabled."
        }

        if ($p.DefaultInboundAction -ne 'Block') {
            Write-Host "Setting DefaultInboundAction to 'Block' for profile '$($p.Name)'..."
            try { Set-NetFirewallProfile -Name $p.Name -DefaultInboundAction Block -ErrorAction Stop } catch { Write-Host "Failed to set DefaultInboundAction for $($p.Name): $($_.Exception.Message)" }
        }
    }

    # Mitigation: block common unicast name-resolution response ports to reduce LLMNR/NetBIOS unicast replies
    # Ports: LLMNR = 5355, NetBIOS Name/Datagram = 137/138
    $ports = @(5355,137,138)
    foreach ($dir in @('Inbound','Outbound')) {
        foreach ($port in $ports) {
            $ruleName = "Block-Unicast-UDP-$port-$dir"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                try {
                    New-NetFirewallRule -DisplayName $ruleName `
                                        -Direction $dir `
                                        -Action Block `
                                        -Protocol UDP `
                                        -LocalPort $port `
                                        -Profile Any `
                                        -Description "Block UDP port $port to reduce unicast name-resolution responses (LLMNR/NetBIOS)" `
                                        -ErrorAction Stop
                    Write-Host "Created firewall rule: $ruleName"
                } catch {
                    Write-Host "Failed to create rule $($ruleName): $($_.Exception.Message)"
                }
            } else {
                Write-Host "Firewall rule already exists: $ruleName"
            }
        }
    }

    Write-Host "Firewall profile checks and unicast-response mitigation completed."
}

function reset_passwords {
    Write-Host "Checking for users with non-expiring passwords..."
    $users = Get-LocalUser | Where-Object { $_.PasswordNeverExpires }
    
    $newPassword = ConvertTo-SecureString "CyberPatri0t!" -AsPlainText -Force
    
    foreach ($user in $users) {
        try {
            # Reset password
            Set-LocalUser -Name $user.Name -Password $newPassword
            Write-Host "Reset password for user: $($user.Name)"
            
            # Disable password never expires
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            Write-Host "Disabled 'Password never expires' for user: $($user.Name)"
            
            Set-LocalUser -Name $user.Name -PasswordExpires $true
            Write-Host "Set password expiration for user: $($user.Name)"
            
            if ($user.Enabled) {
                Set-LocalUser -Name $user.Name -ChangePasswordAtLogon $true
                Write-Host "Set 'Change password at next logon' for user: $($user.Name)"
            }
        }
        catch {
            Write-Host "Error modifying password settings for $($user.Name): $_"
        }
    }
}

function windows_update {
    Write-Host "Checking for Windows updates..."
    try {
        $moduleImported = $false

        # Try a normal import first
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            $moduleImported = $true
        } catch {
            # Search all PSModulePath locations for a PSWindowsUpdate folder and try to import from there
            $paths = $env:PSModulePath -split ';' | Where-Object { $_ -and (Test-Path $_) }
            foreach ($p in $paths) {
                $candidate = Join-Path $p 'PSWindowsUpdate'
                if (Test-Path $candidate) {
                    try {
                        Import-Module $candidate -ErrorAction Stop
                        $moduleImported = $true
                        break
                    } catch {}
                }
            }
        }

        # If still not imported, attempt to install to CurrentUser (does not require admin)
        if (-not $moduleImported) {
            Write-Host "PSWindowsUpdate module not found in PSModulePath; attempting to install to CurrentUser..."
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Import-Module PSWindowsUpdate -ErrorAction Stop
            $moduleImported = $true
        }

        # Verify the cmdlet exists before invoking
        if ($moduleImported -and (Get-Command -Name Install-WindowsUpdate -ErrorAction SilentlyContinue)) {
            Install-WindowsUpdate -AcceptAll -AutoReboot
            Write-Host "Windows updates installed successfully."
        } else {
            Write-Host "Install-WindowsUpdate cmdlet not available after importing PSWindowsUpdate."
        }
    } catch {
        Write-Host "Error installing Windows updates: $_"
    }
}
function antivirus_check {
    Write-Host "Checking for antivirus software..."
    try {
        $antivirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        if ($antivirus) {
            # Could be multiple products; join names
            $names = ($antivirus | Select-Object -ExpandProperty displayName) -join ', '
            Write-Host "Antivirus software is installed: $names"
        } else {
            Write-Host "No antivirus software found. Please install an antivirus solution."
        }
    } catch {
        Write-Host "Unable to query antivirus status. The SecurityCenter2 namespace may not be available on this system."
    }
}



function disable_remote_services {
    Write-Host "Disabling Remote services (Telnet, SSH, WinRM, Remote Registry, Remote Access, Remote Assistance)..."

    # Services to disable: key = service short name, value = friendly name
    $servicesToDisable = @{
        'TlntSvr'        = 'Telnet Server'
        'sshd'           = 'OpenSSH Server'
        'WinRM'          = 'Windows Remote Management (WinRM)'
        'RemoteRegistry' = 'Remote Registry'
        'RemoteAccess'   = 'Routing and Remote Access'
        'RasMan'         = 'Remote Access Connection Manager'
    }

    foreach ($svcName in $servicesToDisable.Keys) {
        $friendly = $servicesToDisable[$svcName]
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    Write-Host "Stopping $friendly ($svcName)..."
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                }
                Write-Host "Setting $friendly ($svcName) startup type to Disabled..."
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-Host "$friendly ($svcName) is now disabled."
            } catch {
                Write-Host "Warning: could not modify service $svcName : $($_.Exception.Message)"
            }
        } else {
            Write-Host "$friendly ($svcName) not present on this system."
        }
    }

    # Ask user whether to disable Remote Desktop entirely
    $resp = Read-Host "Disable Remote Desktop entirely? (Y/N)"
    $disableRDP = $resp -match '^[Yy]'

    # Registry path for enabling/disabling RDP
    $rdpRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    if ($disableRDP) {
        Write-Host "Disabling Remote Desktop (RDP) as requested..."

        # Stop and disable TermService
        try {
            $term = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
            if ($term) {
                if ($term.Status -ne 'Stopped') {
                    Stop-Service -Name 'TermService' -Force -ErrorAction Stop
                    Write-Host "Stopped Remote Desktop Services (TermService)."
                }
                Set-Service -Name 'TermService' -StartupType Disabled -ErrorAction Stop
                Write-Host "Set TermService startup type to Disabled."
            } else {
                Write-Host "Remote Desktop Service (TermService) not present on this system."
            }
        } catch {
            Write-Host "Warning: could not stop/disable TermService: $($_.Exception.Message)"
        }

        # Set registry to deny connections
        try {
            if (Test-Path $rdpRegPath) {
                Set-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -Value 1 -Type DWord -ErrorAction Stop
                Write-Host "Remote Desktop connections disabled via registry (fDenyTSConnections=1)."
            } else {
                New-Item -Path $rdpRegPath -Force | Out-Null
                Set-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -Value 1 -Type DWord -ErrorAction Stop
                Write-Host "Created registry path and disabled Remote Desktop (fDenyTSConnections=1)."
            }
        } catch {
            Write-Host "Warning: Unable to set registry to disable Remote Desktop: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Keeping/Enabling Remote Desktop (RDP)..."

        # Ensure TermService is enabled and started
        try {
            $term = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
            if ($term) {
                Set-Service -Name 'TermService' -StartupType Automatic -ErrorAction Stop
                if ($term.Status -ne 'Running') {
                    Start-Service -Name 'TermService' -ErrorAction Stop
                }
                Write-Host "Remote Desktop Services (TermService) set to Automatic and started."
            } else {
                Write-Host "Remote Desktop Service (TermService) not present on this system."
            }
        } catch {
            Write-Host "Warning: could not enable/start TermService: $($_.Exception.Message)"
        }

        # Set registry to allow connections
        try {
            if (Test-Path $rdpRegPath) {
                Set-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -Value 0 -Type DWord -ErrorAction Stop
                Write-Host "Remote Desktop connections enabled via registry (fDenyTSConnections=0)."
            } else {
                New-Item -Path $rdpRegPath -Force | Out-Null
                Set-ItemProperty -Path $rdpRegPath -Name 'fDenyTSConnections' -Value 0 -Type DWord -ErrorAction Stop
                Write-Host "Created registry path and enabled Remote Desktop (fDenyTSConnections=0)."
            }
        } catch {
            Write-Host "Warning: Unable to set registry to enable Remote Desktop: $($_.Exception.Message)"
        }
    }

    # Always disable Remote Assistance connections (policy + standard path)
    $raPaths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    )

    foreach ($path in $raPaths) {
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            # fAllowToGetHelp = 0 disables Remote Assistance; other flags set defensively
            Set-ItemProperty -Path $path -Name 'fAllowToGetHelp' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name 'fAllowUnsolicited' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name 'fAllowFullControl' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Write-Host "Disabled Remote Assistance settings in $path (where present)."
        } catch {
            Write-Host "Warning: could not modify Remote Assistance settings at $path : $($_.Exception.Message)"
        }
    }

    Write-Host "Remote services adjustment complete."
}

function disable_additional_services {
    Write-Host "Disabling additional vulnerable services..."

    $servicesToDisable = @(
        'TapiSrv',
        'TlntSvr',
        'ftpsvc',
        'SNMP',
        'SessionEnv',
        'UmRdpService',    # Note: UmRdpService removed from target list below in favor of preserving RDP functionality
        'SharedAccess',
        'RemoteRegistry',
        'SSDPSRV',
        'W3SVC',
        'SNMPTRAP',
        'RemoteAccess',
        'HomeGroupProvider',
        'HomeGroupListener'
    )

    # Remove TermService and UmRdpService from disable list to avoid disabling RDP functionality
    $servicesToDisable = $servicesToDisable | Where-Object { $_ -notin @('TermService','UmRdpService') }

    foreach ($service in $servicesToDisable) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                if ($svc.Status -ne 'Stopped') {
                    Stop-Service -Name $service -Force -ErrorAction Stop
                    Write-Host "Stopped service: $service"
                }
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Host "Disabled service: $service"
            } catch {
                Write-Host "Warning: Could not modify service $service : $($_.Exception.Message)"
            }
        } else {
            Write-Host "Service $service not found on this system."
        }
    }
}
function checkUAC {
    Write-Host "Checking UAC settings for maximum security..."
    $uacRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $maxUAC = @{
        'EnableLUA' = 1
        'ConsentPromptBehaviorAdmin' = 2
        'PromptOnSecureDesktop' = 1
    }
    $allGood = $true
    foreach ($key in $maxUAC.Keys) {
        $value = Get-ItemProperty -Path $uacRegPath -Name $key -ErrorAction SilentlyContinue
        if ($null -eq $value -or $value.$key -ne $maxUAC[$key]) {
            Write-Host "UAC setting '$key' is not at maximum. Setting to $($maxUAC[$key])..."
            Set-ItemProperty -Path $uacRegPath -Name $key -Value $maxUAC[$key] -ErrorAction SilentlyContinue
            $allGood = $false
        }
    }
    if ($allGood) {
        Write-Host "All UAC settings are at maximum security."
    } else {
        Write-Host "UAC settings have been updated to maximum security."
    }
}

function set_lockout_policy {
    Write-Host "Setting account lockout policy..."
    try {
        net accounts /lockoutduration:30
        net accounts /lockoutthreshold:10
        net accounts /lockoutwindow:30
        Write-Host "Account lockout policy set successfully."
    } catch {
        Write-Host "Error setting lockout policy: $_"
    }
}


function secure_password_policy {
    Write-Host "Configuring secure password policies..."
    try {
        # Set minimum password length / ages / history using net accounts (legacy but effective)
        net accounts /minpwlen:13
        net accounts /maxpwage:90
        net accounts /minpwage:15
        net accounts /uniquepw:7

        # Build a secedit INF to enforce PasswordComplexity and disable reversible encryption (ClearTextPassword = 0)
        $secEditPath = Join-Path $env:TEMP "securitypolicy.inf"
        $inf = @"
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
ClearTextPassword = 0

[Version]
signature="$CHICAGO$"
Revision=1
"@ 

        # Write INF as ASCII (secedit expects ANSI/ASCII)
        $inf | Out-File -FilePath $secEditPath -Encoding ASCII -Force

        # Apply the policy section containing System Access settings
        secedit.exe /configure /db "$env:windir\security\database\local.sdb" /cfg $secEditPath /areas SECURITYPOLICY | Out-Null

        Remove-Item -Path $secEditPath -ErrorAction SilentlyContinue

        Write-Host "Password policies have been configured successfully. Reversible encryption for stored passwords disabled (ClearTextPassword=0)."
    }
    catch {
        Write-Host "Error configuring password policies: $_"
    }
}

function enable_critical_services {
    Write-Host "Enabling and configuring critical Windows services..."

    $servicesToEnable = @{
        # Security Services
        'WinDefend' = 'Automatic'
        'wscsvc' = 'Automatic'
        'mpssvc' = 'Automatic'
        'EventLog' = 'Automatic'
        'RpcSs' = 'Automatic'
        'DcomLaunch' = 'Automatic'

        # System Integrity Services
        'TrustedInstaller' = 'Manual'
        'Winmgmt' = 'Automatic'
        'PlugPlay' = 'Automatic'
        'Power' = 'Automatic'
        'LSM' = 'Automatic'

        # Network and Update Services
        'wuauserv' = 'Automatic'
        'BITS' = 'Automatic'
        'Dhcp' = 'Automatic'
        'Dnscache' = 'Automatic'
        'LanmanWorkstation' = 'Automatic'
        'Netlogon' = 'Automatic'
        'W32Time' = 'Automatic'

        # Optional Services
        'AppIDSvc' = 'Manual'
        'Appinfo' = 'Manual'
        'SysMain' = 'Automatic'
        'NlaSvc' = 'Automatic'
    }

    foreach ($service in $servicesToEnable.Keys) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Set-Service -Name $service -StartupType $servicesToEnable[$service]
                Start-Service -Name $service -ErrorAction SilentlyContinue
                Write-Host "Enabled and started $service"
            } else {
                Write-Host "Service $service not found"
            }
        } catch {
            Write-Host "Error configuring service $service : $_"
        }
    }
}

function secure_registry_settings {
    Write-Host "Configuring secure registry settings..."

    # Restrict CD ROM drive
    try { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1 -Type DWord -ErrorAction Stop } catch { Write-Host "Warning: $($_)" }

    # Disable Automatic Admin logon
    try { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type DWord -ErrorAction Stop } catch { Write-Host "Warning: $($_)" }

    # Set logon message
    $body = Read-Host "Please enter logon text"
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}

    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "LegalNoticeText" -Value $body -ErrorAction SilentlyContinue
    } catch {}

    $subject = Read-Host "Please enter the title of the message"
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "LegalNoticeCaption" -Value $subject -ErrorAction SilentlyContinue } catch {}

    # Configure security settings
    $registrySettings = @{
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{
            "ClearPageFileAtShutdown" = 1
        }
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
            "AllocateFloppies" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" = @{
            "AddPrinterDrivers" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
            "LimitBlankPasswordUse" = 1
            "auditbaseobjects" = 1
            "fullprivilegeauditing" = 1
            "disabledomaincreds" = 1
            "everyoneincludesanonymous" = 0
            "restrictanonymous" = 1
            "restrictanonymoussam" = 1
            "UseMachineId" = 0
        }
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            "dontdisplaylastusername" = 1
            "EnableInstallerDetection" = 1
            "undockwithoutlogon" = 0
            "DisableCAD" = 0
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" = @{
            "MaximumPasswordAge" = 15
            "DisablePasswordChange" = 1
            "RequireStrongKey" = 1
            "RequireSignOrSeal" = 1
            "SignSecureChannel" = 1
            "SealSecureChannel" = 1
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" = @{
            "autodisconnect" = 45
            "enablesecuritysignature" = 0
            "requiresecuritysignature" = 0
            "NullSessionPipes" = ""
            "NullSessionShares" = ""
        }
        "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" = @{
            "EnablePlainTextPassword" = 0
        }
    }

    foreach ($path in $registrySettings.Keys) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        foreach ($name in $registrySettings[$path].Keys) {
            try {
                $val = $registrySettings[$path][$name]
                if ($val -is [bool]) {
                    # bool -> DWord (0/1)
                    $dw = [int]$val
                    Set-ItemProperty -Path $path -Name $name -Value $dw -Type DWord -ErrorAction Stop
                } elseif ($val -is [int] -or $val -is [long] -or $val -is [uint32]) {
                    Set-ItemProperty -Path $path -Name $name -Value $val -Type DWord -ErrorAction Stop
                } else {
                    # default to string type for empty strings or text
                    Set-ItemProperty -Path $path -Name $name -Value $val -Type String -ErrorAction Stop
                }
                Write-Host "Successfully set $name in $path"
            }
            catch {
                Write-Host "Error setting $name in $path : $_"
            }
        }
    }
}

function remove_backdoors {
    param(
        [switch]$Force
    )

    Write-Host "Scanning for common backdoors, suspicious persistence and artifacts..."

    # Helper - matches paths that are commonly abused for persistence
    $suspiciousPathPatterns = @(
        '\\Temp\\',
        '\\Windows\\Temp\\',
        '\\AppData\\Roaming\\',
        '\\AppData\\Local\\Temp\\',
        '\\ProgramData\\',
        '\\Users\\.*\\LocalSettings\\Temp\\'
    ) -join '|'

    # 1) Find suspicious processes by executable path or common names
    $suspiciousNamePatterns = '(nc|netcat|ncat|meterpreter|psexec|c2|backdoor|reverse|shell|rbot)'
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
             Where-Object {
                 ($_.ExecutablePath -and ($_.ExecutablePath -match $suspiciousPathPatterns)) -or
                 ($_.Name -and ($_.Name -match $suspiciousNamePatterns))
             } |
             Select-Object ProcessId, Name, ExecutablePath

    if ($procs) {
        Write-Host "Suspicious processes found:"
        $procs | ForEach-Object { Write-Host " - $($_.Name) (PID $($_.ProcessId)) Path:$($_.ExecutablePath)" }

        if ($Force -or (Read-Host "Kill these processes? (Y/N)" ) -match '^[Yy]') {
            foreach ($p in $procs) {
                try {
                    Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                    Write-Host "Stopped process PID $($p.ProcessId)"
                } catch {
                    Write-Host "Failed to stop PID $($p.ProcessId): $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No suspicious processes detected by path/name patterns."
    }

    # 2) Find services whose binaries live in suspicious locations or have suspicious names
    $services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue |
                Where-Object {
                    ($_.PathName -and ($_.PathName -match $suspiciousPathPatterns)) -or
                    ($_.Name -match $suspiciousNamePatterns) -or
                    ($_.DisplayName -match $suspiciousNamePatterns)
                } |
                Select-Object Name, DisplayName, PathName, State

    if ($services) {
        Write-Host "Suspicious services found:"
        $services | ForEach-Object { Write-Host " - $($_.Name) [$($_.DisplayName)] State:$($_.State) Path:$($_.PathName)" }

        if ($Force -or (Read-Host "Stop and delete these services? (Y/N)" ) -match '^[Yy]') {
            foreach ($s in $services) {
                try {
                    if ($s.State -ne 'Stopped') {
                        Write-Host "Stopping service $($s.Name)..."
                        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
                try {
                    Write-Host "Deleting service $($s.Name)..."
                    sc.exe delete $s.Name | Out-Null
                } catch {
                    Write-Host "Failed to delete service $($s.Name): $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No suspicious services detected by path/name patterns."
    }

    # 3) Scheduled tasks that execute binaries in suspicious locations
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                 Where-Object {
                     $actionText = ($_.Actions | ForEach-Object {
                         ($_ | ForEach-Object { ($_.Execute -as [string]) + ' ' + ($_.Arguments -as [string]) })
                     }) -join ' '
                     ($actionText -match $suspiciousPathPatterns) -or ($_.TaskName -match $suspiciousNamePatterns)
                 }
    } catch {
        $tasks = @()
    }

    if ($tasks -and $tasks.Count -gt 0) {
        Write-Host "Suspicious scheduled tasks found:"
        $tasks | ForEach-Object { Write-Host " - $($_.TaskName) Path:$($_.Actions | ForEach-Object { $_.Execute })" }

        if ($Force -or (Read-Host "Disable and delete these scheduled tasks? (Y/N)" ) -match '^[Yy]') {
            foreach ($t in $tasks) {
                try {
                    Disable-ScheduledTask -TaskName $t.TaskName -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Host "Deleted scheduled task $($t.TaskName)"
                } catch {
                    Write-Host "Failed to delete task $($t.TaskName): $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No suspicious scheduled tasks found."
    }

    # 4) Autorun registry entries that point to suspicious locations
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )

    $runEntriesToRemove = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object {
                $name = $_.Name
                $value = (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue).$name
                if ($value -and ($value -match $suspiciousPathPatterns -or $name -match $suspiciousNamePatterns)) {
                    $runEntriesToRemove += [PSCustomObject]@{Key=$key;Name=$name;Value=$value}
                }
            }
        }
    }

    if ($runEntriesToRemove.Count -gt 0) {
        Write-Host "Suspicious autorun entries:"
        $runEntriesToRemove | ForEach-Object { Write-Host " - $($_.Key)\$($_.Name) => $($_.Value)" }

        if ($Force -or (Read-Host "Remove these autorun registry entries? (Y/N)" ) -match '^[Yy]') {
            foreach ($r in $runEntriesToRemove) {
                try {
                    Remove-ItemProperty -Path $r.Key -Name $r.Name -ErrorAction Stop
                    Write-Host "Removed $($r.Key)\$($r.Name)"
                } catch {
                    Write-Host "Failed to remove $($r.Key)\$($r.Name): $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No suspicious autorun registry entries found."
    }

    # 5) Find and optionally delete suspicious files (executables, scripts) in temp/appdata areas
    $searchPaths = @(
        "$env:TEMP",
        "$env:windir\Temp"
    )
    Get-ChildItem -Path C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $searchPaths += Join-Path $_.FullName 'AppData\Roaming'
        $searchPaths += Join-Path $_.FullName 'AppData\Local\Temp'
    }

    $filesToRemove = @()
    foreach ($p in $searchPaths | Select-Object -Unique) {
        if (Test-Path $p) {
            try {
                $files = Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue |
                         Where-Object { -not $_.PSIsContainer -and $_.Extension -match '^\.(exe|dll|ps1|bat|cmd|vbs)$' -and $_.Length -gt 1024 } |
                         Where-Object { $_.FullName -match $suspiciousPathPatterns -or $_.Name -match $suspiciousNamePatterns }
                $filesToRemove += $files
            } catch {}
        }
    }

    $filesToRemove = $filesToRemove | Sort-Object -Property FullName -Unique
    if ($filesToRemove.Count -gt 0) {
        Write-Host "Suspicious files detected:"
        $filesToRemove | ForEach-Object { Write-Host " - $($_.FullName) ($([math]::Round($_.Length/1KB)) KB)" }

        if ($Force -or (Read-Host "Delete these files? (Y/N)" ) -match '^[Yy]') {
            foreach ($f in $filesToRemove) {
                try {
                    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                    Write-Host "Deleted $($f.FullName)"
                } catch {
                    Write-Host "Failed to delete $($f.FullName): $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No suspicious files found in scanned locations."
    }

    # 6) Specific common backdoor types: utilman/sethc replacements and netcat binaries
    $sensitiveNames = @('utilman.exe','sethc.exe','cmd.exe','nc.exe','netcat.exe','ncat.exe','netcat5.exe')
    $candidateRoots = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:ProgramData",
        "$env:USERPROFILE",
        "$env:TEMP",
        "$env:windir"
    ) + (Get-ChildItem -Path C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $candidateRoots = $candidateRoots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

    $foundSensitive = @()
    foreach ($root in $candidateRoots) {
        foreach ($name in $sensitiveNames) {
            try {
                $matches = Get-ChildItem -Path $root -Filter $name -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($m in $matches) {
                    # Exclude legitimate system32 originals unless they look modified (handled below)
                    $foundSensitive += $m.FullName
                }
            } catch {}
        }
    }
    $foundSensitive = $foundSensitive | Sort-Object -Unique

    if ($foundSensitive.Count -gt 0) {
        Write-Host "Potential backdoor files discovered (utilman/sethc/netcat/etc):"
        $foundSensitive | ForEach-Object { Write-Host " - $_" }

        if ($Force -or (Read-Host "Remove these backdoor files? (Y/N)" ) -match '^[Yy]') {
            foreach ($path in $foundSensitive) {
                try {
                    # Do not remove the system's original utilman/sethc in system32 blindly here;
                    # flag them for restoration instead if they appear suspicious (see next block)
                    $normalizedSys32 = $env:windir.TrimEnd('\') + '\System32\'
                    if ($path.ToLower().StartsWith($normalizedSys32.ToLower())) {
                        Write-Host "Skipping direct deletion of system32 file (will evaluate for replacement/restoration): $path"
                        continue
                    }
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                    Write-Host "Removed backdoor file: $path"
                } catch {
                    Write-Host "Failed to remove $path : $($_.Exception.Message)"
                }
            }
        }
    } else {
        Write-Host "No extraneous utilman/sethc/netcat binaries found outside system locations."
    }

    # 7) Inspect system32 utilman/sethc/cmd for signs of replacement (unsigned or newer than expected)
    $sysUtilman = Join-Path $env:windir 'System32\utilman.exe'
    $sysSethc   = Join-Path $env:windir 'System32\sethc.exe'
    $sysCmd     = Join-Path $env:windir 'System32\cmd.exe'

    $toRestore = @()

    foreach ($sysFile in @($sysUtilman, $sysSethc, $sysCmd)) {
        if (Test-Path $sysFile) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $sysFile -ErrorAction SilentlyContinue
                $isSignedValid = $false
                if ($sig -and $sig.Status -eq 'Valid') { $isSignedValid = $true }

                # Compare LastWriteTime: if utilman/sethc newer than cmd, suspicious
                $sysCmdTime = (Get-Item -Path $sysCmd -ErrorAction SilentlyContinue).LastWriteTime
                $fileTime = (Get-Item -Path $sysFile -ErrorAction SilentlyContinue).LastWriteTime

                $suspicious = -not $isSignedValid -or ($sysCmdTime -and $fileTime -and ($fileTime -gt $sysCmdTime.AddMinutes(5)))

                if ($suspicious) {
                    Write-Host "System file appears suspicious: $sysFile (SignedValid: $isSignedValid) LastWrite: $fileTime"
                    $toRestore += $sysFile
                }
            } catch {
                Write-Host "Error inspecting $sysFile : $($_.Exception.Message)"
                $toRestore += $sysFile
            }
        }
    }

    if ($toRestore.Count -gt 0) {
        Write-Host "Detected system files that may have been replaced: "
        $toRestore | ForEach-Object { Write-Host " - $_" }

        # Attempt to find original copies in WinSxS and restore, fallback to recommending SFC
        $restored = @()
        foreach ($target in $toRestore) {
            $nameOnly = [IO.Path]::GetFileName($target)
            $found = Get-ChildItem -Path "$env:windir\winsxs" -Filter $nameOnly -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                try {
                    Copy-Item -Path $found.FullName -Destination $target -Force -ErrorAction Stop
                    Write-Host "Restored $nameOnly from WinSxS: $($found.FullName) -> $target"
                    $restored += $target
                } catch {
                    Write-Host "Failed to restore $target from WinSxS: $($_.Exception.Message)"
                }
            } else {
                Write-Host "No copy found in WinSxS for $nameOnly"
            }
        }

        if ($restored.Count -eq 0) {
            Write-Host "Automatic restoration from WinSxS not possible for any items. You should run 'sfc /scannow' or 'DISM /Online /Cleanup-Image /RestoreHealth' to repair system files."
            if ($Force -or (Read-Host "Run 'sfc /scannow' now? (Y/N)" ) -match '^[Yy]') {
                try {
                    Write-Host "Launching: sfc /scannow (this may take considerable time)..."
                    Start-Process -FilePath "sfc.exe" -ArgumentList '/scannow' -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    Write-Host "sfc /scannow completed (check output)."
                } catch {
                    Write-Host "Failed to run sfc /scannow: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "Restoration attempts completed. Run 'sfc /scannow' to validate integrity if desired."
        }
    } else {
        Write-Host "No suspicious modifications detected for utilman/sethc/cmd in System32 (by heuristic)."
    }

    # 7.5) Detect and remove 'Sticky Keys' / Ease-of-Access backdoor via IFEO 'Debugger' or other Image File Execution Options tricks
    try {
        $ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $accessibilityTargets = @('sethc.exe','utilman.exe','osk.exe','magnify.exe')
        $ifeoFindings = @()

        foreach ($t in $accessibilityTargets) {
            $keyPath = Join-Path $ifeoPath $t
            if (Test-Path $keyPath) {
                $dbg = (Get-ItemProperty -Path $keyPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
                if ($dbg) {
                    $ifeoFindings += [PSCustomObject]@{Key=$keyPath;Target=$t;Debugger=$dbg}
                } else {
                    # also check for other suspicious properties (e.g. ShellExecHooks or other remapping)
                    $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
                    foreach ($p in $props) {
                        if ($p -match 'Debugger|shell|hook|redirect' ) {
                            $val = (Get-ItemProperty -Path $keyPath -Name $p -ErrorAction SilentlyContinue).$p
                            if ($val) { $ifeoFindings += [PSCustomObject]@{Key=$keyPath;Target=$t;Property=$p;Value=$val} }
                        }
                    }
                }
            }
        }

        if ($ifeoFindings.Count -gt 0) {
            Write-Host "Image File Execution Options backdoor entries detected for accessibility executables:"
            $ifeoFindings | ForEach-Object {
                if ($_.Debugger) {
                    Write-Host (" - {0} -> Debugger: {1}" -f $_.Target, $_.Debugger)
                } else {
                    Write-Host (" - {0} -> {1} = {2}" -f $_.Target, $_.Property, $_.Value)
                }
            }

            if ($Force -or (Read-Host "Remove Debugger/IFEO entries for accessibility backdoors? (Y/N)" ) -match '^[Yy]') {
                foreach ($e in $ifeoFindings) {
                    try {
                        # Remove the Debugger value if present, otherwise remove the suspicious property
                        if ((Get-ItemProperty -Path $e.Key -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger) {
                            Remove-ItemProperty -Path $e.Key -Name 'Debugger' -ErrorAction Stop
                            Write-Host "Removed Debugger for $($e.Target)"
                        } else {
                            if ($e.Property) {
                                Remove-ItemProperty -Path $e.Key -Name $e.Property -ErrorAction Stop
                                Write-Host "Removed $($e.Property) for $($e.Target)"
                            }
                        }

                        # If the IFEO key is now empty, remove the key itself
                        $remaining = Get-ItemProperty -Path $e.Key -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
                        if (-not $remaining -or $remaining.Count -eq 0) {
                            Remove-Item -Path $e.Key -Force -ErrorAction SilentlyContinue
                            Write-Host "Removed empty IFEO key: $($e.Key)"
                        }
                    } catch {
                        Write-Host "Failed to remove IFEO entry $($e.Key): $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Host "IFEO backdoor entries left in place per user request."
            }
        } else {
            Write-Host "No IFEO 'Debugger' backdoor entries found for accessibility executables."
        }
    } catch {
        Write-Host "Error while inspecting Image File Execution Options: $($_.Exception.Message)"
    }

    # 8) Stop/remove netcat-like binaries and processes explicitly (extra pass)
    try {
        $ncProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(nc|netcat|ncat)$' }
        if ($ncProcs) {
            Write-Host "Netcat-like processes detected:"
            $ncProcs | ForEach-Object { Write-Host " - $($_.Name) (PID $($_.Id))" }
            if ($Force -or (Read-Host "Kill netcat-like processes? (Y/N)" ) -match '^[Yy]') {
                $ncProcs | ForEach-Object {
                    try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; Write-Host "Stopped PID $($_.Id)" } catch { Write-Host "Failed to stop PID $($_.Id): $($_.Exception.Message)" }
                }
            }
        }

        # Remove netcat binaries found earlier (filesToRemove + foundSensitive already covered many locations)
        $extraNcFiles = @()
        foreach ($root in $candidateRoots) {
            foreach ($pattern in @('nc.exe','netcat.exe','ncat.exe')) {
                try {
                    $extraNcFiles += Get-ChildItem -Path $root -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
                } catch {}
            }
        }
        $extraNcFiles = $extraNcFiles | Sort-Object -Unique
        if ($extraNcFiles.Count -gt 0) {
            Write-Host "Additional netcat binaries found:"
            $extraNcFiles | ForEach-Object { Write-Host " - $_" }
            if ($Force -or (Read-Host "Remove these netcat binaries? (Y/N)" ) -match '^[Yy]') {
                foreach ($f in $extraNcFiles) {
                    try {
                        Remove-Item -LiteralPath $f -Force -ErrorAction Stop
                        Write-Host "Removed $f"
                    } catch {
                        Write-Host "Failed to remove ${f}: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Host "Error during extra netcat pass: $($_.Exception.Message)"
    }

    Write-Host "Backdoor removal scan complete. Review logs and consider running a full antivirus/EDR scan and SFC/DISM to validate system integrity."
}


function remove_unapproved_third_party_apps {
    param(
        [switch]$Force,
        [switch]$AllowMetasploit,
        [switch]$AllowTeamViewer,
        [switch]$AllowCCleaner,
        [switch]$AllowSteam
    )

    Write-Host "Scanning for media files and unapproved third‑party apps..."

    # File extensions to remove
    $mediaExts = @('*.mp3','*.mp4','*.avi','*.mov')

    # Applications/patterns to remove (keys = canonical name, value = pattern)
    $apps = @{
        'Hashcat'     = 'hashcat'
        'Nmap'        = 'nmap'
        'Wireshark'   = 'wireshark'
        'Ophcrack'    = 'ophcrack'
        'Metasploit'  = 'metasploit'
        'Steam'       = 'steam'
        'TeamViewer'  = 'teamviewer'
        'PuTTY'       = 'putty'
        'iTunes'      = 'itunes'
        'CCleaner'    = 'ccleaner'
    }

    # Respect allow switches
    if ($AllowMetasploit) { $apps.Remove('Metasploit') | Out-Null }
    if ($AllowTeamViewer) { $apps.Remove('TeamViewer') | Out-Null }
    if ($AllowCCleaner) { $apps.Remove('CCleaner') | Out-Null }
    if ($AllowSteam) { $apps.Remove('Steam') | Out-Null }

    # Search roots - restrict to common user/profile and program locations to avoid system files
    $roots = @(
        $env:USERPROFILE,
        "C:\Users",
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:ProgramData",
        $env:TEMP
    ) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

    # 1) Find media files
    $mediaFiles = @()
    foreach ($r in $roots) {
        foreach ($ext in $mediaExts) {
            try {
                $mediaFiles += Get-ChildItem -Path $r -Include $ext -File -Recurse -ErrorAction SilentlyContinue
            } catch {}
        }
    }
    $mediaFiles = $mediaFiles | Sort-Object -Property FullName -Unique

    # 2) Find installed programs from registry uninstall keys
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $matchedPrograms = @()
    foreach ($key in $uninstallKeys) {
        try {
            Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                $display = $_.DisplayName
                $un = $_.UninstallString
                if ($display) {
                    foreach ($app in $apps.GetEnumerator()) {
                        if (($display -match $app.Value) -or ($display.ToLower() -match $app.Value.ToLower())) {
                            $matchedPrograms += [PSCustomObject]@{
                                Name = $display
                                UninstallString = $un
                                RegistryPath = $_.PSPath
                                Pattern = $app.Key
                            }
                            break
                        }
                    }
                }
            }
        } catch {}
    }

    # 3) Find folders/executables by pattern under Program Files and user AppData
    $fileTargets = @()
    $candidateRoots = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:ProgramData"
    )
    # include each user's AppData locations
    Get-ChildItem -Path C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $candidateRoots += Join-Path $_.FullName 'AppData\Local'
        $candidateRoots += Join-Path $_.FullName 'AppData\Roaming'
        $candidateRoots += Join-Path $_.FullName 'Downloads'
    }
    $candidateRoots = $candidateRoots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

    foreach ($root in $candidateRoots) {
        foreach ($app in $apps.GetEnumerator()) {
            try {
                $found = Get-ChildItem -Path $root -Filter "*$($app.Value)*" -Recurse -Force -ErrorAction SilentlyContinue |
                         Where-Object { $_.PSIsContainer -or ($_.Extension -match '^\.(exe|bat|cmd|ps1|dll)$') }
                if ($found) {
                    $found | ForEach-Object {
                        $fileTargets += [PSCustomObject]@{
                            Path = $_.FullName
                            Pattern = $app.Key
                        }
                    }
                }
            } catch {}
        }
    }
    $fileTargets = $fileTargets | Sort-Object -Property Path -Unique

    # 3.5) Find .ps1 files (PowerShell scripts) in candidate roots (user is asked if they are needed)
    $ps1Files = @()
    foreach ($root in $candidateRoots) {
        try {
            $ps1Files += Get-ChildItem -Path $root -Filter '*.ps1' -Recurse -File -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    $ps1Files = $ps1Files | Sort-Object -Property FullName -Unique

    # Summary
    Write-Host ""
    Write-Host "Summary of findings:"
    Write-Host (" - Media files to remove: {0}" -f $mediaFiles.Count)
    Write-Host (" - Installed program entries matching patterns: {0}" -f $matchedPrograms.Count)
    Write-Host (" - Files/folders matching patterns: {0}" -f $fileTargets.Count)
    Write-Host (" - PowerShell scripts (.ps1) found: {0}" -f $ps1Files.Count)
    Write-Host ""

    if (-not $Force) {
        $confirm = Read-Host "Proceed to remove the above items? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Aborting removal per user request."
            return
        }
    }

    # 4) Attempt to uninstall programs using UninstallString where available
    foreach ($p in $matchedPrograms) {
        try {
            if ($p.UninstallString) {
                Write-Host "Uninstalling $($p.Name) ..."
                # Clean up uninstall string and run
                $cmd = $p.UninstallString.Trim()
                # If it is an msiexec /I or /X with a GUID, try silent uninstall
                if ($cmd -match 'msiexec' -or $cmd -match '\{[0-9A-Fa-f\-]{36}\}') {
                    $msiCmd = $cmd -replace '/I','/x'
                    if ($msiCmd -notmatch '/qn') { $msiCmd += ' /qn' }
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c",$msiCmd -Wait -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue
                } else {
                    # Try to execute uninstall string (may require interactive UI)
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c",$cmd -Wait -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue
                }
                Write-Host "Requested uninstall for: $($p.Name)"
            } else {
                Write-Host "No uninstall command for $($p.Name). Will attempt to delete files instead."
            }
        } catch {
            Write-Host "Warning: failed to run uninstall for $($p.Name) : $($_.Exception.Message)"
        }
    }

    # 5) Stop processes matching patterns before file removal
    foreach ($app in $apps.GetEnumerator()) {
        try {
            $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $app.Value }
            foreach ($proc in $procs) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "Stopped process: $($proc.Name) (PID $($proc.Id))"
                } catch {}
            }
        } catch {}
    }

    # 6) Delete matched files/folders
    foreach ($t in $fileTargets) {
        try {
            if (Test-Path $t.Path) {
                Remove-Item -LiteralPath $t.Path -Recurse -Force -ErrorAction Stop
                Write-Host "Removed: $($t.Path)"
            }
        } catch {
            Write-Host "Failed to remove $($t.Path) : $($_.Exception.Message)"
        }
    }

    # 7) Delete media files
    foreach ($f in $mediaFiles) {
        try {
            if (Test-Path $f.FullName) {
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                Write-Host "Deleted media file: $($f.FullName)"
            }
        } catch {
            Write-Host "Failed to delete $($f.FullName) : $($_.Exception.Message)"
        }
    }

    # 8) Prompt about .ps1 files (ask if they are needed). If Force provided, delete without prompt.
    if ($ps1Files.Count -gt 0) {
        Write-Host ""
        Write-Host "PowerShell scripts discovered (.ps1):"
        # show up to first 20 for review
        $ps1Files | Select-Object -First 20 | ForEach-Object { Write-Host " - $($_.FullName)" }
        if ($ps1Files.Count -gt 20) { Write-Host " - ... and $($ps1Files.Count - 20) more" }

        $deletePs1 = $false
        if ($Force) {
            $deletePs1 = $true
        } else {
            # Ask user whether these scripts are needed. If user answers N, we remove them.
            $resp = Read-Host "Are these .ps1 scripts needed? Answer Y to keep them, N to delete (Y/N)"
            if ($resp -match '^[Nn]') { $deletePs1 = $true } else { $deletePs1 = $false }
        }

        if ($deletePs1) {
            foreach ($s in $ps1Files) {
                try {
                    if (Test-Path $s.FullName) {
                        Remove-Item -LiteralPath $s.FullName -Force -ErrorAction Stop
                        Write-Host "Deleted .ps1: $($s.FullName)"
                    }
                } catch {
                    Write-Host "Failed to delete $($s.FullName) : $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "Leaving .ps1 scripts in place per user selection."
        }
    }

    Write-Host "Removal pass complete. Manual verification recommended for remaining artifacts."
}


function stop-DefaultSharedFolders {
    param(
        [switch]$Force
    )

    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session." 
        return
    }

    Write-Host "Enumerating shares..."

    # Preferred enumeration via SMB cmdlets; fallback to WMI
    if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) {
        $allShares = Get-SmbShare -ErrorAction SilentlyContinue
    } else {
        $allShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Name; Path = $_.Path; Type = $_.Type }
        }
    }

    if (-not $allShares) {
        Write-Host "No shares found or unable to enumerate shares."
        return
    }

    # Typical admin/default shares to stop: ADMIN$, IPC$, drive-letter$ (C$, D$, ...)
    $candidates = $allShares | Where-Object {
        $_.Name -match '^(ADMIN\$|IPC\$|[A-Z]\$)$'
    } | Sort-Object -Property Name -Unique

    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Host "No default/admin shares (ADMIN$, IPC$, X$) detected."
        return
    }

    Write-Host "Shares identified for removal:"
    $candidates | ForEach-Object { Write-Host " - $($_.Name)" }

    if (-not $Force) {
        $confirm = Read-Host "Stop sharing these? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Aborting per user request."
            return
        }
    }

    foreach ($s in $candidates) {
        $name = $s.Name
        try {
            if (Get-Command -Name Remove-SmbShare -ErrorAction SilentlyContinue) {
                Remove-SmbShare -Name $name -Force -ErrorAction Stop
                Write-Host "Removed SMB share: $name"
            } else {
                # Fallback to net share delete
                & net share $name /delete | Out-Null
                Write-Host "Requested removal via 'net share' for: $name"
            }
        } catch {
            Write-Host "Failed to remove $($name): $($_.Exception.Message)"
        }
    }

    # Prevent automatic recreation of administrative shares (requires reboot)
    try {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

        # AutoShareServer (Server OS) and AutoShareWks (Workstation OS)
        Set-ItemProperty -Path $regPath -Name 'AutoShareServer' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $regPath -Name 'AutoShareWks' -Value 0 -Type DWord -ErrorAction SilentlyContinue

        Write-Host "Set AutoShareServer/AutoShareWks to 0 to prevent automatic recreation. A reboot may be required."
    } catch {
        Write-Host "Unable to write registry to disable auto-shares: $($_.Exception.Message)"
    }

    Write-Host "Operation complete. Verify Shares in Computer Management -> Shared Folders if needed."
}

function enforce_domain_hardening {
    param(
        [switch]$Fix
    )

    Write-Host "Running domain & DC hardening checks..."

    # Helper: require elevation for registry/service changes
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Administrative privileges are required to inspect/apply many settings. Re-run elevated to apply fixes."
    }

    $results = [System.Collections.ArrayList]::new()

    #
    # 1) Authenticated users cannot add workstations to the domain
    #    (ms-DS-MachineAccountQuota = 0 on the domain)
    #
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }

        $domain = $null
        try { $domain = Get-ADDomain -ErrorAction Stop } catch {}
        if ($domain) {
            $currentQuota = $domain.'ms-DS-MachineAccountQuota'
            if ($null -eq $currentQuota) { $currentQuota = 10 } # default if absent
            $results.Add("MachineAccountQuota current: $currentQuota") | Out-Null

            if ($Fix) {
                try {
                    if ($currentQuota -ne 0) {
                        Set-ADDomain -Identity $domain.DNSRoot -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -ErrorAction Stop
                        $results.Add("Set ms-DS-MachineAccountQuota = 0") | Out-Null
                    } else {
                        $results.Add("ms-DS-MachineAccountQuota already 0") | Out-Null
                    }
                } catch {
                    $results.Add("Failed to set ms-DS-MachineAccountQuota: $($_.Exception.Message)") | Out-Null
                }
            } else {
                $results.Add("Run with -Fix to set ms-DS-MachineAccountQuota=0 (prevents authenticated users joining machines)") | Out-Null
            }
        } else {
            $results.Add("Not joined to an AD domain or ActiveDirectory module unavailable; cannot query/set ms-DS-MachineAccountQuota") | Out-Null
        }
    } catch {
        $results.Add("Error while handling machine account quota: $($_.Exception.Message)") | Out-Null
    }

    #
    # 2) Prevent delegation abuse: ensure common Netlogon / delegation protections are enabled
    #    We set Netlogon/secure channel and require strong keys/signing where possible.
    #
    try {
        $netlogonPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        $changes = @{}
        $desiredNetlogon = @{
            'RequireStrongKey'   = 1
            'RequireSignOrSeal'  = 1
            'SignSecureChannel'  = 1
            'SealSecureChannel'  = 1
        }

        foreach ($k in $desiredNetlogon.Keys) {
            $current = (Get-ItemProperty -Path $netlogonPath -Name $k -ErrorAction SilentlyContinue).$k
            if ($current -ne $desiredNetlogon[$k]) {
                if ($Fix) {
                    try {
                        Set-ItemProperty -Path $netlogonPath -Name $k -Value $desiredNetlogon[$k] -Type DWord -ErrorAction Stop
                        $changes[$k] = "updated -> $($desiredNetlogon[$k])"
                    } catch {
                        $changes[$k] = "failed to update: $($_.Exception.Message)"
                    }
                } else {
                    $changes[$k] = "current=$current (run with -Fix to set $($desiredNetlogon[$k]))"
                }
            } else {
                $changes[$k] = "ok"
            }
        }

        $results.Add("Netlogon secure-channel settings:") | Out-Null
        foreach ($c in $changes.GetEnumerator()) {
            $results.Add(" - $($c.Key): $($c.Value)") | Out-Null
        }
    } catch {
        $results.Add("Failed to inspect/update Netlogon parameters: $($_.Exception.Message)") | Out-Null
    }

    #
    # 3) LDAP server signing requirements [Require Signing] (Domain Controllers)
    #    Attempt to set NTDS LDAP signing requirement to 'require' (DWORD = 2)
    #
    try {
        $ldapRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $ldapName = 'LDAPServerIntegrity'
        $current = (Get-ItemProperty -Path $ldapRegPath -Name $ldapName -ErrorAction SilentlyContinue).$ldapName
        if ($current -ne 2) {
            if ($Fix) {
                try {
                    if (!(Test-Path $ldapRegPath)) { New-Item -Path $ldapRegPath -Force | Out-Null }
                    Set-ItemProperty -Path $ldapRegPath -Name $ldapName -Value 2 -Type DWord -ErrorAction Stop
                    $results.Add("Set LDAP server signing requirement to 'Require signing' (LDAPServerIntegrity=2)") | Out-Null
                } catch {
                    $results.Add("Failed to set LDAPServerIntegrity: $($_.Exception.Message)") | Out-Null
                }
            } else {
                $results.Add("LDAPServerIntegrity current: $current (run with -Fix to set to 2 = Require signing)") | Out-Null
            }
        } else {
            $results.Add("LDAP server signing already set to 'Require signing' (LDAPServerIntegrity=2)") | Out-Null
        }
    } catch {
        $results.Add("Error checking LDAP signing setting: $($_.Exception.Message)") | Out-Null
    }

    #c
    # 4) Domain logons are not cached to disk on members (CachedLogonsCount = 0)
    #
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $name = 'CachedLogonsCount'
        $current = (Get-ItemProperty -Path $winlogonPath -Name $name -ErrorAction SilentlyContinue).$name
        if ($current -ne '0') {
            if ($Fix) {
                try {
                    Set-ItemProperty -Path $winlogonPath -Name $name -Value '0' -Type String -ErrorAction Stop
                    $results.Add("Set CachedLogonsCount = 0 (domain logons will not be cached)") | Out-Null
                } catch {
                    $results.Add("Failed to set CachedLogonsCount: $($_.Exception.Message)") | Out-Null
                }
            } else {
                $results.Add("CachedLogonsCount current: $current (run with -Fix to set to 0)") | Out-Null
            }
        } else {
            $results.Add("CachedLogonsCount already 0") | Out-Null
        }
    } catch {
        $results.Add("Error checking CachedLogonsCount: $($_.Exception.Message)") | Out-Null
    }

    #
    # 5) Use FIPS compliant algorithms (enable FIPS policy)
    #
    try {
        $fipsPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'
        $fipsName = 'Enabled'
        $current = (Get-ItemProperty -Path $fipsPath -Name $fipsName -ErrorAction SilentlyContinue).$fipsName
        if ($current -ne 1) {
            if ($Fix) {
                try {
                    if (!(Test-Path $fipsPath)) { New-Item -Path $fipsPath -Force | Out-Null }
                    Set-ItemProperty -Path $fipsPath -Name $fipsName -Value 1 -Type DWord -ErrorAction Stop
                    $results.Add("Enabled FIPS algorithms (FipsAlgorithmPolicy\\Enabled = 1)") | Out-Null
                } catch {
                    $results.Add("Failed to enable FIPS policy: $($_.Exception.Message)") | Out-Null
                }
            } else {
                $results.Add("FIPS policy current: $current (run with -Fix to enable)") | Out-Null
            }
        } else {
            $results.Add("FIPS algorithm policy already enabled") | Out-Null
        }
    } catch {
        $results.Add("Error checking FIPS policy: $($_.Exception.Message)") | Out-Null
    }

    #
    # 6) Delegation hardening guidance (informational)
    #
    try {
        if ($Fix) {
            $results.Add("NOTE: Hardening to prevent domain users from enabling 'trusted for delegation' requires domain ACL changes.") | Out-Null
            $results.Add("Automated ACL changes are NOT performed by this script. Use AD ACL tooling (dsacls, Set-ACL via DirectoryServices) and restrict write perms to msDS-AllowedToDelegateTo/msDS-AllowedToActOnBehalfOfOtherIdentity to privileged groups only.") | Out-Null
        } else {
            $results.Add("Delegation prevention (requires AD ACL changes). Run with -Fix to enforce some local settings; manual AD ACL work recommended.") | Out-Null
        }
    } catch {}

    #
    # Final: report and recommendations
    #
    Write-Host ""
    Write-Host "Enforcement summary:"
    foreach ($line in $results) { Write-Host " - $line" }

    Write-Host ""
    Write-Host "Recommendations:"
    Write-Host " - Reboot domain controllers / affected members where registry keys were changed."
    Write-Host " - For ms-DS-MachineAccountQuota change, verify via: Get-ADDomain | Select-Object ms-DS-MachineAccountQuota"
    Write-Host " - To fully prevent delegation misuse and tighten Netlogon/LDAP protections, run this on domain controllers and/or perform AD ACL hardening as Domain Admin."
    Write-Host " - Test changes in a lab before wide deployment."
}

function harden_defender_and_exploit_protection {
    param(
        [switch]$Fix
    )

    # Require elevation for registry/service changes
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session."
        return
    }

    Write-Host "Hardening Microsoft Defender and Exploit Protection..."

    # 1) Ensure Defender is not in passive mode (remove ForceDefenderPassiveMode)
    try {
        $passiveReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
        if (Test-Path $passiveReg) {
            $prop = Get-ItemProperty -Path $passiveReg -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
            if ($null -ne $prop -and $prop.ForceDefenderPassiveMode -ne $null) {
                if ($Fix) {
                    Remove-ItemProperty -Path $passiveReg -Name 'ForceDefenderPassiveMode' -ErrorAction Stop
                    Write-Host "Removed ForceDefenderPassiveMode registry value."
                } else {
                    Write-Host "Detected ForceDefenderPassiveMode present; run with -Fix to remove it."
                }
            } else {
                Write-Host "ForceDefenderPassiveMode not present."
            }
        } else {
            Write-Host "ATP registry path not present (no ForceDefenderPassiveMode)."
        }
    } catch {
        Write-Host "Failed handling ForceDefenderPassiveMode: $($_.Exception.Message)"
    }

    # 2) Enable Defender network protection
    if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
        try {
            $current = Get-MpPreference
            if ($current.EnableNetworkProtection -ne 'Enabled') {
                if ($Fix) {
                    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
                    Write-Host "Enabled Defender Network Protection."
                } else {
                    Write-Host "Network Protection is not enabled; run with -Fix to enable it."
                }
            } else {
                Write-Host "Network Protection already enabled."
            }
        } catch {
            Write-Host "Failed to query/set Network Protection: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Defender cmdlets not available; cannot set Network Protection via Set-MpPreference."
    }

    # 3) Ensure Severe threat default action is not 'Ignore' (numeric value 6)
    try {
        if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
            $mp = Get-MpPreference
            if ($mp.PSObject.Properties.Name -contains 'SevereThreatDefaultAction') {
                $sev = $mp.SevereThreatDefaultAction
                if ($sev -eq 6) {
                    if ($Fix) {
                        Set-MpPreference -SevereThreatDefaultAction 1 -ErrorAction Stop
                        Write-Host "Severe threat default action was 'Ignore' (6). Changed to a non-ignore action."
                    } else {
                        Write-Host "Severe threat default action is 'Ignore' (6). Run with -Fix to change it."
                    }
                } else {
                    Write-Host "Severe threat default action is not 'Ignore' (current: $sev)."
                }
            } else {
                Write-Host "SevereThreatDefaultAction property not present in Get-MpPreference output."
            }
        } else {
            Write-Host "Get-MpPreference not available to check Severe threat action."
        }
    } catch {
        Write-Host "Failed handling Severe threat default action: $($_.Exception.Message)"
    }

    # 4) Enable ASR rule: Block executable files from running unless they meet prevalence/age/trusted list
    $asrGuid = '01443614-cd74-433a-b99e-2ecdc07bfc25'
    try {
        if (Get-Command -Name Add-MpPreference -ErrorAction SilentlyContinue) {
            $mp = Get-MpPreference
            $ids = @()
            if ($mp.AttackSurfaceReductionRules_Ids) { $ids = $mp.AttackSurfaceReductionRules_Ids }
            if ($ids -notcontains $asrGuid) {
                if ($Fix) {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids @($asrGuid) -AttackSurfaceReductionRules_Actions @('Enabled') -ErrorAction Stop
                    Write-Host "Added/enabled ASR rule $asrGuid."
                } else {
                    Write-Host "ASR rule $asrGuid not present/enabled. Run with -Fix to enable."
                }
            } else {
                Write-Host "ASR rule $asrGuid already present."
            }
        } else {
            Write-Host "Add-MpPreference not available; cannot add ASR rule via cmdlet."
        }
    } catch {
        Write-Host "Failed to add ASR rule: $($_.Exception.Message)"
    }

    # 5) Ensure cloud/block-at-first-seen features are enabled (make ASR effective)
    try {
        if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
            $mp = Get-MpPreference
            $needs = @()
            if ($mp.DisableBlockAtFirstSeen) { $needs += 'BlockAtFirstSeen' }
            if ($mp.DisableRealtimeMonitoring) { $needs += 'RealtimeMonitoring' }
            if ($mp.DisableBehaviorMonitoring) { $needs += 'BehaviorMonitoring' }
            if ($mp.DisableIOAVProtection) { $needs += 'IOAVProtection' }

            if ($needs.Count -gt 0) {
                if ($Fix) {
                    Set-MpPreference -DisableBlockAtFirstSeen $false -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -ErrorAction Stop
                    Write-Host "Enabled cloud/block-at-first-seen and core real-time protections: $($needs -join ', ')."
                } else {
                    Write-Host "One or more cloud/real-time protections appear disabled ($($needs -join ', ')). Run with -Fix to enable them."
                }
            } else {
                Write-Host "Cloud and core real-time protections appear enabled."
            }
        }
    } catch {
        Write-Host "Failed to enforce cloud/block-at-first-seen settings: $($_.Exception.Message)"
    }

    # 6) Remove Attack Surface Reduction exclusions
    try {
        if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
            $mp = Get-MpPreference
            if ($mp.AttackSurfaceReductionOnlyExclusions -and $mp.AttackSurfaceReductionOnlyExclusions.Count -gt 0) {
                if ($Fix) {
                    try {
                        Set-MpPreference -AttackSurfaceReductionOnlyExclusions @() -ErrorAction Stop
                        Write-Host "Cleared AttackSurfaceReductionOnlyExclusions via Set-MpPreference."
                    } catch {
                        # fallback to registry removal if cmdlet fails
                        $asrReg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
                        if (Test-Path $asrReg) {
                            Remove-ItemProperty -Path $asrReg -Name 'AttackSurfaceReductionOnlyExclusions' -ErrorAction SilentlyContinue
                            Write-Host "Removed AttackSurfaceReductionOnlyExclusions from registry (fallback)."
                        } else {
                            Write-Host "Could not clear ASR exclusions; registry path not present."
                        }
                    }
                } else {
                    Write-Host "ASR exclusions detected; run with -Fix to remove them."
                }
            } else {
                Write-Host "No AttackSurfaceReductionOnlyExclusions configured."
            }
        } else {
            Write-Host "Get-MpPreference not available; attempting registry removal of ASR exclusions (if present)."
            $asrReg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            if (Test-Path $asrReg) {
                if ($Fix) {
                    Remove-ItemProperty -Path $asrReg -Name 'AttackSurfaceReductionOnlyExclusions' -ErrorAction SilentlyContinue
                    Write-Host "Removed AttackSurfaceReductionOnlyExclusions from registry."
                } else {
                    Write-Host "ASR registry path exists; run with -Fix to remove AttackSurfaceReductionOnlyExclusions if present."
                }
            } else {
                Write-Host "ASR registry path not present."
            }
        }
    } catch {
        Write-Host "Failed to remove ASR exclusions: $($_.Exception.Message)"
    }

    # 7) Ensure Google Chrome cannot override DEP (Exploit Protection / DEP)
    try {
        if (Get-Command -Name Get-ProcessMitigation -ErrorAction SilentlyContinue) {
            $chromeMitigations = Get-ProcessMitigation -Name 'chrome.exe' -ErrorAction SilentlyContinue
            if ($chromeMitigations) {
                $depEnabled = $null
                if ($chromeMitigations.PSObject.Properties.Name -contains 'DataExecutionPrevention') {
                    $dep = $chromeMitigations.DataExecutionPrevention
                    if ($dep -is [System.Management.Automation.PSObject]) {
                        if ($dep.Properties.Name -contains 'Enable') { $depEnabled = [bool]$dep.Enable }
                    } elseif ($dep -is [bool]) {
                        $depEnabled = [bool]$dep
                    }
                }
                if ($depEnabled -eq $false -or $depEnabled -eq $null) {
                    if ($Fix) {
                        try {
                            Set-ProcessMitigation -Name 'chrome.exe' -EnableForceRelocateImages 1 -ErrorAction Stop
                            Write-Host "Attempted to update Chrome exploit mitigations (DEP/mitigations). Verify in Windows Security -> Exploit Protection -> Program settings."
                        } catch {
                            Write-Host "Unable to programmatically change Chrome DEP via Set-ProcessMitigation: $($_.Exception.Message)"
                            Write-Host "Manually verify DEP is enabled for chrome.exe in Windows Security -> App & browser control -> Exploit protection -> Program settings."
                        }
                    } else {
                        Write-Host "Chrome exploit mitigation (DEP) not clearly enabled. Run with -Fix to attempt to enforce (or enable manually in Exploit Protection)."
                    }
                } else {
                    Write-Host "Chrome DEP appears enabled."
                }
            } else {
                Write-Host "No per-app mitigation entry for chrome.exe."
                if ($Fix) { Write-Host "If necessary, add chrome.exe to Exploit Protection program settings and enable DEP via the UI or Set-ProcessMitigation." }
            }
        } else {
            Write-Host "Get-ProcessMitigation / Set-ProcessMitigation not available on this system. Configure Chrome DEP via Windows Security -> Exploit Protection settings."
        }
    } catch {
        Write-Host "Failed to inspect/apply Chrome DEP mitigations: $($_.Exception.Message)"
    }

    Write-Host "Defender & Exploit Protection hardening pass complete. Review output for any manual actions required."
}
########################################################################
# Execute Functions
########################################################################

# Main Function
function main {
    Write-Host "Starting Windows Hardening Script..."
    
    #Calling Functions
    manageLocalGroups
    firewall_status
    antivirus_check
    check_user_accounts
    disable_remote_services
    checkUAC
    disable_additional_services
    secure_registry_settings
    set_lockout_policy
    update_firefox

    windows_update
    reset_passwords
    secure_password_policy
    enable_critical_services
    remove_backdoors
    remove_unapproved_third_party_apps
    remove_unauthorized_services
    stop-DefaultSharedFolders
    check_audit_policy
    Set-AllLocalPasswords
    enforce_domain_hardening
    harden_defender_and_exploit_protection

   
    Write-Host "Windows Hardening Script completed."
}

main
