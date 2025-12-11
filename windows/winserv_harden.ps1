function Manage-UsersAndGroups {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    function Is-DomainJoined {
        try {
            return ($null -ne [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain())
        } catch {
            return $false
        }
    }

    $domainJoined = Is-DomainJoined

    do {
        Clear-Host
        Write-Host "1. View all users"
        Write-Host "2. Add a new user"
        Write-Host "3. Remove a user"
        Write-Host "4. View all groups"
        Write-Host "5. Add a new group"
        Write-Host "6. Remove a group"
        Write-Host "7. Add user to group"
        Write-Host "8. Remove user from group"
        Write-Host "9. Exit"
        Write-Host "10. Manage a single group (add/remove multiple users separated by commas)"
        Write-Host ""

        $choice = Read-Host "Enter your choice (1-10)"

        switch ($choice) {
            1 {
                if ($domainJoined) {
                    Write-Host "`n--- Domain Users ---"
                    # Show some useful columns and don't let the menu immediately clear the output
                    Get-ADUser -Filter * -Properties Enabled |
                        Select-Object SamAccountName, Enabled |
                        Format-Table -AutoSize
                } else {
                    Write-Host "`n--- Local Users ---"
                    Get-LocalUser | Select-Object Name, Enabled | Format-Table -AutoSize
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            2 {
                $userName = Read-Host "Enter new username"
                $password = Read-Host "Enter password" -AsSecureString

                if ($domainJoined) {
                    try {
                        New-ADUser -Name $userName -SamAccountName $userName -AccountPassword $password -Enabled $true -ErrorAction Stop
                        Write-Host "✅ Domain user '$userName' created."
                    } catch {
                        Write-Host "Error creating domain user: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        New-LocalUser -Name $userName -Password $password -FullName $userName -Description "Created by hardening script" -ErrorAction Stop
                        Write-Host "✅ Local user '$userName' created."
                    } catch {
                        Write-Host "Error creating local user: $($_.Exception.Message)"
                    }
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            3 {
                $userName = Read-Host "Enter username to remove"
                if ($domainJoined) {
                    try {
                        Remove-ADUser -Identity $userName -Confirm:$false -ErrorAction Stop
                        Write-Host "User '$userName' removed from domain."
                    } catch {
                        Write-Host "Error removing domain user: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        Remove-LocalUser -Name $userName -ErrorAction Stop
                        Write-Host "Local user '$userName' removed."
                    } catch {
                        Write-Host "Error removing local user: $($_.Exception.Message)"
                    }
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            4 {
                if ($domainJoined) {
                    Write-Host "`n--- Domain Groups ---"
                    Get-ADGroup -Filter * | Select-Object Name, GroupScope | Format-Table -AutoSize
                } else {
                    Write-Host "`n--- Local Groups ---"
                    Get-LocalGroup | Select-Object Name | Format-Table -AutoSize
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            5 {
                $groupName = Read-Host "Enter new group name"
                if ($domainJoined) {
                    $scopeChoice = Read-Host "Enter group scope (Global / Universal / DomainLocal, default = Global)"
                    if (-not $scopeChoice) { $scopeChoice = "Global" }
                    try {
                        New-ADGroup -Name $groupName -GroupScope $scopeChoice -GroupCategory Security -ErrorAction Stop
                        Write-Host "Domain group '$groupName' ($scopeChoice) created."
                    } catch {
                        Write-Host "Error creating domain group: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        New-LocalGroup -Name $groupName -Description "Created by hardening script" -ErrorAction Stop
                        Write-Host "Local group '$groupName' created."
                    } catch {
                        Write-Host "Error creating local group: $($_.Exception.Message)"
                    }
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            6 {
                $groupName = Read-Host "Enter group name to remove"
                if ($domainJoined) {
                    try {
                        Remove-ADGroup -Identity $groupName -Confirm:$false -ErrorAction Stop
                        Write-Host "Domain group '$groupName' removed."
                    } catch {
                        Write-Host "Error removing domain group: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        Remove-LocalGroup -Name $groupName -ErrorAction Stop
                        Write-Host "Local group '$groupName' removed."
                    } catch {
                        Write-Host "Error removing local group: $($_.Exception.Message)"
                    }
                }
                Read-Host "`nPress Enter to return to menu..."
            }

            7 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                try {
                    if ($domainJoined) {
                        Add-ADGroupMember -Identity $groupName -Members $userName -ErrorAction Stop
                    } else {
                        Add-LocalGroupMember -Group $groupName -Member $userName -ErrorAction Stop
                    }
                    Write-Host "Added '$userName' to '$groupName'."
                } catch {
                    Write-Host "Error adding user to group: $($_.Exception.Message)"
                }

                Read-Host "`nPress Enter to return to menu..."
            }

            8 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                try {
                    if ($domainJoined) {
                        Remove-ADGroupMember -Identity $groupName -Members $userName -Confirm:$false -ErrorAction Stop
                    } else {
                        Remove-LocalGroupMember -Group $groupName -Member $userName -ErrorAction Stop
                    }
                    Write-Host "Removed '$userName' from '$groupName'."
                } catch {
                    Write-Host "Error removing user from group: $($_.Exception.Message)"
                }

                Read-Host "`nPress Enter to return to menu..."
            }

            10 {
                # Manage a single group: add/remove multiple users separated by commas
                $groupName = Read-Host "Enter the target group name"

                # Show current members first
                Write-Host "`nCurrent members of '$groupName':"
                try {
                    if ($domainJoined) {
                        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName -ErrorAction SilentlyContinue
                        if ($members) {
                            $members | ForEach-Object { Write-Host " - $_" }
                        } else {
                            Write-Host " (no members or group not found)"
                        }
                    } else {
                        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
                        if ($members) {
                            $members | ForEach-Object { Write-Host " - $_" }
                        } else {
                            Write-Host " (no members or group not found)"
                        }
                    }
                } catch {
                    Write-Host "Unable to enumerate members: $($_.Exception.Message)"
                }

                $action = Read-Host "Enter action ('add' or 'remove')"
                if ($action -notin @('add','remove')) {
                    Write-Host "Invalid action. Use 'add' or 'remove'."
                    Read-Host "`nPress Enter to return to menu..."
                    break
                }

                $usersInput = Read-Host "Enter usernames separated by commas"
                $users = $usersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

                if ($users.Count -eq 0) {
                    Write-Host "No valid usernames provided."
                    Read-Host "`nPress Enter to return to menu..."
                    break
                }

                try {
                    if ($domainJoined) {
                        if ($action -eq 'add') {
                            Add-ADGroupMember -Identity $groupName -Members $users -ErrorAction Stop
                            Write-Host "Added users to domain group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-ADGroupMember -Identity $groupName -Members $users -Confirm:$false -ErrorAction Stop
                            Write-Host "Removed users from domain group '$groupName': $($users -join ', ')"
                        }
                    } else {
                        if ($action -eq 'add') {
                            Add-LocalGroupMember -Group $groupName -Member $users -ErrorAction Stop
                            Write-Host "Added users to local group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-LocalGroupMember -Group $groupName -Member $users -Confirm:$false -ErrorAction Stop
                            Write-Host "Removed users from local group '$groupName': $($users -join ', ')"
                        }
                    }
                } catch {
                    Write-Host "Error processing group membership changes:`n$($_.Exception.Message)"
                }

                Read-Host "`nPress Enter to return to menu..."
            }

            9 {
                Write-Host "Exiting user management..."
                break;
            }

            Default {
                Write-Host "Invalid selection. Try again."
                Read-Host "`nPress Enter to return to menu..."
            }
        }
    } until ($choice -eq "9")
}

function Enable-AllAuditPolicies {
    Write-Host "Enabling all audit policies for Success and Failure..."

    $output = auditpol /get /category:* 2>$null
    if (-not $output) {
        Write-Host "Failed to retrieve audit policy data."
        return
    }

    $subcategories = @()

    foreach ($line in $output) {
        # Match lines that look like subcategories (indented and not empty)
        if ($line -match "^\s+([A-Za-z].*?)\s{2,}") {
            $subcategories += $matches[1].Trim()
        }
    }

    if ($subcategories.Count -eq 0) {
        Write-Host "Could not retrieve audit categories."
        return
    }

    foreach ($s in $subcategories) {
        try {
            auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
            Write-Host "Set '$s' to Success and Failure"
        } catch {
            Write-Host "Failed to set '$s'"
        }
    }

    Write-Host "All audit policies updated."
}

function disable_guest_account {
    Write-Host "Checking user accounts and permissions..."
    # Check guest account status
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Host ($guestAccount.Enabled)
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
        Write-Host "MAKE SURE TO TURN ON NETWORK LEVEL AUTHENTICATION"

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

    Write-Host "Disabling SMBv1 protocol (server and client)..."

    try {
        if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
            Write-Host "SMBv1 server protocol disabled via Set-SmbServerConfiguration."
        } else {
            Write-Host "Set-SmbServerConfiguration not available on this system."
        }
    } catch {
        Write-Host "Warning: Could not disable SMBv1 server: $($_.Exception.Message)"
    }

    try {
        if (Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            $featureName = 'SMB1Protocol'
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
            if ($feat -and $feat.State -ne 'Disabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop
                Write-Host "SMBv1 client feature disabled (no restart)."
            } else {
                Write-Host "SMBv1 client feature already disabled or not present."
            }
        } else {
            Write-Host "Disable-WindowsOptionalFeature not available on this system."
        }
    } catch {
        Write-Host "Warning: Could not disable SMBv1 client feature: $($_.Exception.Message)"
    }

    Write-Host "Additional service hardening complete."
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

function Clear-UserProfilesSafe {
    # Prompt for the username to keep
    $KeepUser = Read-Host "Enter the username you want to KEEP (case-sensitive as shown in C:\Users)"

    $userRoot = "C:\Users"

    # Folders to always skip (system/important)
    $skip = @("Default", "Default User", "All Users", $KeepUser)

    # Allowed standard profile folders (whitelist)
    $allowedFolders = @(
        "Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music",
        "Favorites", "Links", "Saved Games", "Searches", "3D Objects", "Contacts"
    )

    # Process each profile folder
    $profiles = Get-ChildItem -Path $userRoot -Directory
    foreach ($p in $profiles) {
        if ($skip -contains $p.Name) {
            Write-Host "Skipping $($p.Name)"
            continue
        }

        Write-Host "Cleaning extra files in: $($p.Name)"

        # Remove files/folders in the user folder that are NOT in the allowedFolders whitelist
        $items = Get-ChildItem -Path $p.FullName -Force
        foreach ($item in $items) {
            if ($allowedFolders -notcontains $item.Name) {
                try {
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "Removed: $($item.FullName)"
                } catch { Write-Host "Failed to remove: $($item.FullName)" }
            }
        }
    }

    # Also clean Public folder, keeping structure
    $publicPath = Join-Path $userRoot "Public"
    Write-Host "Cleaning Public folder..."
    $publicAllowed = @("Desktop","Documents","Downloads","Pictures","Videos","Music","Public Desktop","Public Documents","Public Downloads")
    $publicItems = Get-ChildItem -Path $publicPath -Force
    foreach ($item in $publicItems) {
        if ($publicAllowed -notcontains $item.Name) {
            try { Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    Write-Host "Cleanup complete. Only standard folders remain."
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
        # Set minimum password length
        net accounts /minpwlen:13
        
        # Set maximum password age
        net accounts /maxpwage:90
        
        # Set minimum password age
        net accounts /minpwage:15
        
        # Set password history
        net accounts /uniquepw:7

        # Disable storing passwords using reversible encryption
        secedit /export /cfg C:\Windows\Temp\secpol.cfg
        (Get-Content C:\Windows\Temp\secpol.cfg) -replace 'PasswordStoreClearText\s*=\s*1', 'PasswordStoreClearText = 0' |
            Set-Content C:\Windows\Temp\secpol.cfg
        secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
        Remove-Item C:\Windows\Temp\secpol.cfg

        
        # Enable password complexity
        $secEditPath = "$env:TEMP\securitypolicy.cfg"
        "PasswordComplexity = 1" | Out-File $secEditPath
        secedit /configure /db c:\windows\security\local.sdb /cfg $secEditPath /areas SECURITYPOLICY
        Remove-Item $secEditPath -ErrorAction SilentlyContinue

        Write-Host "Password policies have been configured successfully."
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

        # DNS Server (ensure DNS service is enabled on DNS servers)
        'DNS' = 'Automatic'

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
                if ($svc.Status -ne 'Running') {
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                }
                Write-Host "Enabled and started $service (StartupType=$($servicesToEnable[$service]))"
            } else {
                Write-Host "Service $service not found"
            }
        } catch {
            Write-Host "Error configuring service $service : $_"
        }
    }
}

function Remove-ProhibitedApps {

    Write-Host "Enter allowed apps EXACTLY as they appear in Programs & Features."
    Write-Host "Separate each one with a comma."
    $input = Read-Host "Allowed apps"
    $AllowedApps = $input.Split(",").ForEach{ $_.Trim() }

    Write-Host "`nScanning installed software..."
    $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, 
                                   HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
                                   -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName } |
                 Sort-Object DisplayName

    foreach ($app in $installed) {
        $name = $app.DisplayName

        # Skip whitelisted apps
        if ($AllowedApps -contains $name) {
            Write-Host "KEEPING: $name" -ForegroundColor Green
            continue
        }

        # Skip Microsoft / Windows components
        if ($name -match "Microsoft|Windows|Visual C\+\+|Edge|OneDrive|Update") {
            Write-Host "SYSTEM APP (ignored): $name" -ForegroundColor Yellow
            continue
        }

        Write-Host "REMOVING: $name" -ForegroundColor Red

        try {
            # Use uninstall string if available
            if ($app.UninstallString) {
                $cmd = $app.UninstallString

                # Fix msiexec uninstall syntax
                if ($cmd -match "MsiExec.exe") {
                    Start-Process "msiexec.exe" -ArgumentList "/x $($app.PSChildName) /quiet /norestart" -NoNewWindow -Wait
                } else {
                    Start-Process $cmd -ArgumentList "/quiet /norestart" -NoNewWindow -Wait
                }
            }

        } catch {
            Write-Host "Failed to remove $name"
        }
    }

    Write-Host "`nThird-party cleanup complete."
}

function secure_registry_settings {
    Write-Host "Configuring secure registry settings..."

    # Restrict CD ROM drive
    try { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1 -Type DWord -ErrorAction Stop } catch { Write-Host "Warning: $($_)" }

    # Disable Automatic Admin logon
    try { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type DWord -ErrorAction Stop } catch { Write-Host "Warning: $($_)" }

    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}
    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}

    try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "Dummy" -Value $null -ErrorAction SilentlyContinue } catch {}

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

function Configure-UserRightsAssignments {
    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session." -ForegroundColor Red
        return
    }

    Write-Host "Configuring User Rights Assignments for secure settings..." -ForegroundColor Cyan

    # Create temporary security template file
    $secEditPath = "$env:TEMP\secedit_ura_$(Get-Random).inf"
    $secDbPath = "$env:TEMP\secedit_db_$(Get-Random).sdb"
    $logPath = "$env:TEMP\secedit_log_$(Get-Random).txt"

    # Define User Rights Assignments - Using proper account names instead of just SIDs
    $userRightsConfig = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeTrustedCredManAccessPrivilege = 
SeNetworkLogonRight = *S-1-5-32-544
SeTcbPrivilege = 
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeBackupPrivilege = *S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege = 
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege = 
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113
SeEnableDelegationPrivilege = 
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege = 
SeBatchLogonRight = *S-1-5-32-544
SeServiceLogonRight = 
SeSecurityPrivilege = *S-1-5-32-544
SeRelabelPrivilege = 
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeTakeOwnershipPrivilege = *S-1-5-32-544
"@

    try {
        # Write configuration to temp file
        Write-Host "Creating security template..." -ForegroundColor Yellow
        $userRightsConfig | Out-File -FilePath $secEditPath -Encoding unicode -Force

        # Verify file was created
        if (-not (Test-Path $secEditPath)) {
            throw "Failed to create security template file"
        }

        Write-Host "Applying User Rights Assignments via secedit..." -ForegroundColor Yellow
        Write-Host "Template: $secEditPath" -ForegroundColor Gray
        Write-Host "This may take 30-60 seconds..." -ForegroundColor Yellow
        Write-Host ""

        # Apply the security template with verbose output
        $seceditArgs = @(
            "/configure"
            "/db", $secDbPath
            "/cfg", $secEditPath
            "/areas", "USER_RIGHTS"
            "/log", $logPath
            "/overwrite"
        )
        
        $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -NoNewWindow
        
        Write-Host ""
        
        # Check the log file for details
        if (Test-Path $logPath) {
            $logContent = Get-Content $logPath -Raw
            Write-Host "Secedit Log Output:" -ForegroundColor Cyan
            Write-Host $logContent
            Write-Host ""
        }

        if ($process.ExitCode -eq 0) {
            Write-Host "✓ Successfully applied User Rights Assignments!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Applied settings include:" -ForegroundColor Cyan
            Write-Host " ✓ Restricted network access to Administrators"
            Write-Host " ✓ Cleared dangerous privileges (Act as OS, Create token)"
            Write-Host " ✓ Restricted debugging to Administrators"
            Write-Host " ✓ Restricted driver loading to Administrators"
            Write-Host " ✓ Configured deny rules for Guest"
            Write-Host " ✓ Removed delegation privileges"
            Write-Host " ✓ Secured backup/restore rights"
            Write-Host ""
            Write-Host "VERIFICATION:" -ForegroundColor Yellow
            Write-Host "  Run: secpol.msc"
            Write-Host "  Navigate to: Local Policies -> User Rights Assignment"
            Write-Host "  Check that settings match expectations"
        } else {
            Write-Host "⚠ secedit returned exit code: $($process.ExitCode)" -ForegroundColor Red
            Write-Host "Some settings may not have been applied correctly." -ForegroundColor Yellow
            Write-Host "Check the log above for details." -ForegroundColor Yellow
        }

        # Refresh group policy
        Write-Host ""
        Write-Host "Refreshing group policy..." -ForegroundColor Yellow
        $gpResult = & gpupdate.exe /force 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Group policy refreshed" -ForegroundColor Green
        } else {
            Write-Host "⚠ Group policy refresh had issues" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    } finally {
        # Clean up temporary files
        Write-Host ""
        Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
        @($secEditPath, $secDbPath, $logPath) | ForEach-Object {
            if (Test-Path $_) {
                Remove-Item $_ -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Write-Host ""
    Write-Host "Configuration complete." -ForegroundColor Cyan
    Write-Host "IMPORTANT: Verify settings in secpol.msc before continuing!" -ForegroundColor Yellow
}

function harden_server2022_accounts_and_audit {
    Write-Host "Applying Server 2022-specific account & audit hardening..."

    # Confirm Windows Server 2022
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os -or ($os.Caption -notmatch 'Windows Server 2022')) {
        Write-Host "Host is not Windows Server 2022. Skipping this hardening function."
        return
    }

    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Administrative privileges required. Re-run in an elevated session."
        return
    }

    # Helper to ensure registry path exists
    function Ensure-RegistryPath {
        param($Path)
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    }

    # 1) Administrator account: disable
    try {
        $admin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if ($admin) {
            if ($admin.Enabled) {
                Disable-LocalUser -Name 'Administrator' -ErrorAction Stop
                Write-Host "Disabled built-in Administrator account."
            } else {
                Write-Host "Built-in Administrator already disabled."
            }
        } else {
            Write-Host "Built-in Administrator account not found."
        }
    } catch {
        Write-Host "Failed to disable Administrator account: $($_.Exception.Message)"
    }

    # 2) Block Microsoft accounts: "Users can’t add or log on with Microsoft accounts"
    try {
        $sysPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Ensure-RegistryPath -Path $sysPolicyPath
        # Value semantics: set to 3 to block add and logon with MS accounts (common policy value)
        Set-ItemProperty -Path $sysPolicyPath -Name 'NoConnectedUser' -Value 3 -Type DWord -ErrorAction Stop
        Write-Host "Configured 'Block Microsoft accounts' (NoConnectedUser=3)."
    } catch {
        Write-Host "Failed to set 'Block Microsoft accounts' policy: $($_.Exception.Message)"
    }

    # 3) Guest account: disable
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest) {
            if ($guest.Enabled) {
                Disable-LocalUser -Name 'Guest' -ErrorAction Stop
                Write-Host "Disabled Guest account."
            } else {
                Write-Host "Guest account already disabled."
            }
        } else {
            Write-Host "Guest account not present."
        }
    } catch {
        Write-Host "Failed to disable Guest account: $($_.Exception.Message)"
    }

    # LSA / audit related registry path
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Ensure-RegistryPath -Path $lsaPath

    # 4) Limit local account use of blank passwords to console logon only: enabled (LimitBlankPasswordUse = 1)
    try {
        Set-ItemProperty -Path $lsaPath -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "Enabled 'Limit local account use of blank passwords to console logon only' (LimitBlankPasswordUse=1)."
    } catch {
        Write-Host "Failed to set LimitBlankPasswordUse: $($_.Exception.Message)"
    }

    # 5) Audit access of global system objects: disabled (AuditBaseObjects = 0)
    try {
        Set-ItemProperty -Path $lsaPath -Name 'auditbaseobjects' -Value 0 -Type DWord -ErrorAction Stop
        Write-Host "Disabled 'Audit access of global system objects' (auditbaseobjects=0)."
    } catch {
        Write-Host "Failed to set auditbaseobjects: $($_.Exception.Message)"
    }

    # 6) Audit the use of Backup and Restore privilege: disabled (fullprivilegeauditing = 0)
    try {
        Set-ItemProperty -Path $lsaPath -Name 'fullprivilegeauditing' -Value 0 -Type DWord -ErrorAction Stop
        Write-Host "Disabled 'Audit the use of Backup and Restore privilege' (fullprivilegeauditing=0)."
    } catch {
        Write-Host "Failed to set fullprivilegeauditing: $($_.Exception.Message)"
    }

    # 7) Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings: enabled
    #    Common registry name observed for this policy: SCENoApplyLegacyAuditPolicy = 1
    try {
        Set-ItemProperty -Path $lsaPath -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "Enabled 'Force audit policy subcategory settings (Vista or later)' (SCENoApplyLegacyAuditPolicy=1)."
    } catch {
        Write-Host "Failed to set SCENoApplyLegacyAuditPolicy: $($_.Exception.Message)"
    }

    # 8) Shutdown system immediately if unable to log security audits: enable (CrashOnAuditFail = 1)
    try {
        Set-ItemProperty -Path $lsaPath -Name 'CrashOnAuditFail' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "Enabled 'Shutdown system immediately if unable to log security audits' (CrashOnAuditFail=1)."
    } catch {
        Write-Host "Failed to set CrashOnAuditFail: $($_.Exception.Message)"
    }

    Write-Host "Server 2022 account & audit hardening complete. Some changes may require a reboot to take full effect."
}

function harden_server2022_dcom_and_device_policies {
    Write-Host "Applying Server 2022-only DCOM and Device policy hardening..."

    # Ensure Windows Server 2022 only
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os -or ($os.Caption -notmatch 'Windows Server 2022')) {
        Write-Host "Host is not Windows Server 2022. Skipping this function."
        return
    }

    # Require elevation for registry changes
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "Administrative privileges required. Re-run in an elevated session to apply these settings."
        return
    }

    try {
        # 1) DCOM - Machine access & launch restrictions
        $dcomSecPath = 'HKLM:\SOFTWARE\Microsoft\Ole\Security'
        if (-not (Test-Path $dcomSecPath)) {
            New-Item -Path $dcomSecPath -Force | Out-Null
        }

        # Restrictive SDDL: allow only Local System and Builtin\Administrators (prevents remote access for other accounts)
        # NOTE: SDDL strings are powerful. This sample sets a conservative allow-only SDDL for SYSTEM and Administrators.
        $restrictSDDL = 'D:P(A;;GA;;;SY)(A;;GA;;;BA)'

        Set-ItemProperty -Path $dcomSecPath -Name 'MachineAccessRestriction' -Value $restrictSDDL -Type String -ErrorAction Stop
        Set-ItemProperty -Path $dcomSecPath -Name 'MachineLaunchRestriction' -Value $restrictSDDL -Type String -ErrorAction Stop

        Write-Host "Set DCOM MachineAccessRestriction and MachineLaunchRestriction to restrict remote access/launch to SYSTEM and Administrators only."
    } catch {
        Write-Host "Failed to apply DCOM restrictions: $($_.Exception.Message)"
    }

    try {
        # 2) Devices: Allow undock without having to log on => Disabled
        $sysPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (-not (Test-Path $sysPolicyPath)) { New-Item -Path $sysPolicyPath -Force | Out-Null }
        Set-ItemProperty -Path $sysPolicyPath -Name 'UndockWithoutLogon' -Value 0 -Type DWord -ErrorAction Stop
        Write-Host "Disabled 'Allow undock without having to log on' (UndockWithoutLogon=0)."
    } catch {
        Write-Host "Failed to set UndockWithoutLogon: $($_.Exception.Message)"
    }

    try {
        # 3) Devices: Allowed to format and eject removable media
        # Implement as a registry marker that local administrators and interactive users are allowed.
        # Many environments enforce this via local policy mapping; this value is used here as a clear, auditable intent.
        $devicePolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if (-not (Test-Path $devicePolicyPath)) { New-Item -Path $devicePolicyPath -Force | Out-Null }

        # Create a descriptive value (REG_SZ or REG_MULTI_SZ). Using REG_SZ listing principals.
        $allowedPrincipals = 'Administrators,INTERACTIVE'
        Set-ItemProperty -Path $devicePolicyPath -Name 'AllowedToFormatAndEjectRemovableMedia' -Value $allowedPrincipals -Type String -ErrorAction Stop
        Write-Host "Configured 'Allowed to format and eject removable media' to Administrators and Interactive users (marker value set)."
    } catch {
        Write-Host "Failed to configure removable-media format/eject policy: $($_.Exception.Message)"
    }

    try {
        # 4) Devices: Prevent users from installing printer drivers => Enabled
        # Use policy registry area for printers/PointAndPrint where possible.
        $printerPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        if (-not (Test-Path $printerPolicyPath)) { New-Item -Path $printerPolicyPath -Force | Out-Null }

        # Restrict driver installation to administrators; value names reflect common policy mapping.
        Set-ItemProperty -Path $printerPolicyPath -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Type DWord -ErrorAction Stop
        # Also enforce requiring elevation for printer driver installs
        Set-ItemProperty -Path $printerPolicyPath -Name 'NoWarningNoElevationOnInstall' -Value 0 -Type DWord -ErrorAction SilentlyContinue

        Write-Host "Enabled 'Prevent users from installing printer drivers' (RestrictDriverInstallationToAdministrators=1)."
    } catch {
        Write-Host "Failed to set printer driver install prevention keys: $($_.Exception.Message)"
    }

    Write-Host "Server 2022 DCOM & Device hardening applied. Some settings (DCOM/PointAndPrint) may require a reboot and/or a policy refresh to take effect."
}

function main {
    Write-Host "Starting Windows 2022 Server Script..." 
    Manage-UsersAndGroups
    Enable-AllAuditPolicies
    disable_guest_account
    Set-AllLocalPasswords
    firewall_status
    disable_remote_services
    disable_additional_services

    checkUAC
    set_lockout_policy
    secure_password_policy
    enable_critical_services
    secure_registry_settings
    Clear-UserProfilesSafe
    stop-DefaultSharedFolders
    Remove-ProhibitedApps
    Configure-UserRightsAssignments
    harden_server2022_accounts_and_audit
    harden_server2022_dcom_and_device_policies
}
main
