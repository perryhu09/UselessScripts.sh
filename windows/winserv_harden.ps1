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

function Set-UserRightsAssignments {
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

function Set-SecPol {
    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session." -ForegroundColor Red
        return
    }

    Write-Host "=== CyberPatriot Security Policy Configuration ===" -ForegroundColor Cyan
    Write-Host "Configuring all local security policies..." -ForegroundColor Yellow
    Write-Host ""

    # Create temporary files
    $secEditPath = "$env:TEMP\secedit_config_$(Get-Random).inf"
    $secDbPath = "$env:TEMP\secedit_db_$(Get-Random).sdb"
    $logPath = "$env:TEMP\secedit_log_$(Get-Random).txt"

    # Complete security template with all CyberPatriot settings
    $securityTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 1
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
EnableAdminAccount = 0
EnableGuestAccount = 0
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"4"
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,14
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"1"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"CyberPatriot Warning"
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,Unauthorized access prohibited
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts=4,10
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,0
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,"O:BAG:BAD:(A;;RC;;;BA)"
MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1
MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,1
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7,
MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,0
MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1
MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1
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
        Write-Host "[1/5] Creating security template..." -ForegroundColor Yellow
        $securityTemplate | Out-File -FilePath $secEditPath -Encoding unicode -Force

        if (-not (Test-Path $secEditPath)) {
            throw "Failed to create security template file"
        }
        Write-Host "  ✓ Template created" -ForegroundColor Green

        Write-Host "[2/5] Applying security configuration (this may take 30-60 seconds)..." -ForegroundColor Yellow
        
        $seceditArgs = @(
            "/configure"
            "/db", $secDbPath
            "/cfg", $secEditPath
            "/log", $logPath
            "/overwrite"
            "/quiet"
        )
        
        $process = Start-Process -FilePath "secedit.exe" -ArgumentList $seceditArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Host "  ✓ Security policies applied successfully" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Secedit exit code: $($process.ExitCode)" -ForegroundColor Yellow
            if (Test-Path $logPath) {
                Write-Host "  Log details:" -ForegroundColor Gray
                Get-Content $logPath | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
            }
        }

        Write-Host "[3/5] Configuring additional registry-based policies..." -ForegroundColor Yellow
        
        # Additional policies that need direct registry configuration
        $regPolicies = @(
            # Block Microsoft Accounts
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="NoConnectedUser"; Value=3; Type="DWord"}
            
            # DCOM restrictions
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM"; Name="MachineAccessRestriction"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM"; Name="MachineLaunchRestriction"; Value=1; Type="DWord"}
            
            # UAC policies
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Value=0; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableSecureUIAPaths"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Value=1; Type="DWord"}
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="FilterAdministratorToken"; Value=1; Type="DWord"}
            
            # Network security - Restrict NTLM
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="RestrictReceivingNTLMTraffic"; Value=2; Type="DWord"}
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"; Name="RestrictSendingNTLMTraffic"; Value=2; Type="DWord"}
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Name="RestrictNTLMInDomain"; Value=7; Type="DWord"}
            
            # Kerberos encryption types
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Name="SupportedEncryptionTypes"; Value=2147483640; Type="DWord"}
        )

        $regCount = 0
        foreach ($policy in $regPolicies) {
            try {
                if (-not (Test-Path $policy.Path)) {
                    New-Item -Path $policy.Path -Force | Out-Null
                }
                New-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.Value -PropertyType $policy.Type -Force -ErrorAction Stop | Out-Null
                $regCount++
            } catch {
                Write-Host "    ⚠ Failed to set $($policy.Name): $_" -ForegroundColor Yellow
            }
        }
        Write-Host "  ✓ Applied $regCount additional registry policies" -ForegroundColor Green

        Write-Host "[4/5] Disabling Guest and Administrator accounts..." -ForegroundColor Yellow
        try {
            Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
            Write-Host "  ✓ Accounts disabled" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Could not disable accounts (may already be disabled)" -ForegroundColor Yellow
        }

        Write-Host "[5/5] Refreshing group policy..." -ForegroundColor Yellow
        $gpResult = & gpupdate.exe /force /wait:0 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Group policy refreshed" -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "============================================" -ForegroundColor Green
        Write-Host "✓ SECURITY CONFIGURATION COMPLETE" -ForegroundColor Green
        Write-Host "============================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Applied settings:" -ForegroundColor Cyan
        Write-Host "  ✓ User rights assignments (43 policies)" -ForegroundColor White
        Write-Host "  ✓ Security options (UAC, network security, etc.)" -ForegroundColor White
        Write-Host "  ✓ Guest and Administrator accounts disabled" -ForegroundColor White
        Write-Host "  ✓ Network security hardening (SMB signing, NTLM restrictions)" -ForegroundColor White
        Write-Host "  ✓ Interactive logon security (no last username, inactivity timeout)" -ForegroundColor White
        Write-Host ""
        Write-Host "VERIFICATION:" -ForegroundColor Yellow
        Write-Host "  1. Open: secpol.msc" -ForegroundColor White
        Write-Host "  2. Check: Local Policies -> Security Options" -ForegroundColor White
        Write-Host "  3. Check: Local Policies -> User Rights Assignment" -ForegroundColor White
        Write-Host "  4. Check: Account Policies -> Password Policy" -ForegroundColor White
        Write-Host ""

    } catch {
        Write-Host ""
        Write-Host "ERROR: $_" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    } finally {
        # Clean up temporary files
        Write-Host "Cleaning up temporary files..." -ForegroundColor Gray
        @($secEditPath, $secDbPath, $logPath) | ForEach-Object {
            if (Test-Path $_) {
                Remove-Item $_ -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Set-WindowsUpdate {
    Write-Host "Configuring Windows Update for automatic updates..." -ForegroundColor Cyan
    
    try {
        # Enable Windows Update service
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        
        # Configure automatic updates via registry
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        
        # AUOptions: 4 = Auto download and schedule install
        Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -Type DWord -Force
        Set-ItemProperty -Path $wuPath -Name "ScheduledInstallDay" -Value 0 -Type DWord -Force  # 0 = Every day
        Set-ItemProperty -Path $wuPath -Name "ScheduledInstallTime" -Value 3 -Type DWord -Force  # 3 AM
        
        Write-Host "  ✓ Windows Update configured for automatic updates" -ForegroundColor Green
        
        # Check for updates
        $updateCheck = Read-Host "Do you want to check for updates now? (Y/N)"
        if ($updateCheck -match '^[Yy]') {
            Write-Host "Checking for Windows updates (this may take a minute)..." -ForegroundColor Yellow
            Start-Process "ms-settings:windowsupdate" -ErrorAction SilentlyContinue
            Write-Host "  ✓ Windows Update opened - please install available updates" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring Windows Update: $_" -ForegroundColor Red
    }
}

function Disable-AutoRun {
    Write-Host "Disabling AutoRun/AutoPlay for all drives..." -ForegroundColor Cyan
    
    try {
        # Disable AutoRun for all drives
        $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $autorunPath)) {
            New-Item -Path $autorunPath -Force | Out-Null
        }
        
        # NoDriveTypeAutoRun: 0xFF disables autorun for all drive types
        Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
        Set-ItemProperty -Path $autorunPath -Name "NoAutorun" -Value 1 -Type DWord -Force
        
        # Also disable for current user
        $userAutorunPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $userAutorunPath)) {
            New-Item -Path $userAutorunPath -Force | Out-Null
        }
        Set-ItemProperty -Path $userAutorunPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
        
        Write-Host "  ✓ AutoRun/AutoPlay disabled for all drives" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error disabling AutoRun: $_" -ForegroundColor Red
    }
}

function Set-ScreenSaver {
    Write-Host "Configuring secure screensaver settings..." -ForegroundColor Cyan
    
    try {
        $screenSaverPath = "HKCU:\Control Panel\Desktop"
        
        # Enable screensaver (screen saver active)
        Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveActive" -Value "1" -Type String -Force
        
        # Set timeout to 10 minutes (600 seconds)
        Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveTimeOut" -Value "600" -Type String -Force
        
        # Require password on resume
        Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaverIsSecure" -Value "1" -Type String -Force
        
        # Apply to all users via registry (HKLM)
        $allUsersPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (-not (Test-Path $allUsersPath)) {
            New-Item -Path $allUsersPath -Force | Out-Null
        }
        Set-ItemProperty -Path $allUsersPath -Name "InactivityTimeoutSecs" -Value 600 -Type DWord -Force
        
        Write-Host "  ✓ Screensaver configured: 10 minute timeout with password" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring screensaver: $_" -ForegroundColor Red
    }
}

function Disable-IPv6 {
    Write-Host "Checking IPv6 configuration..." -ForegroundColor Cyan
    
    $disable = Read-Host "Do you want to disable IPv6? (Y/N)"
    
    if ($disable -match '^[Yy]') {
        try {
            # Disable IPv6 on all adapters
            Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop
            
            # Also disable via registry (more thorough)
            $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            if (-not (Test-Path $ipv6Path)) {
                New-Item -Path $ipv6Path -Force | Out-Null
            }
            Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 0xFF -Type DWord -Force
            
            Write-Host "  ✓ IPv6 disabled on all network adapters" -ForegroundColor Green
            Write-Host "  ⚠ A reboot may be required for changes to take full effect" -ForegroundColor Yellow
            
        } catch {
            Write-Host "  ⚠ Error disabling IPv6: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  ℹ IPv6 left enabled" -ForegroundColor Gray
    }
}

function Set-EventLogSize {
    Write-Host "Configuring Event Log retention and size..." -ForegroundColor Cyan
    
    try {
        $logs = @("Application", "Security", "System")
        $maxSize = 512MB  # 512 MB
        
        foreach ($log in $logs) {
            try {
                $logInstance = Get-WinEvent -ListLog $log -ErrorAction Stop
                $logInstance.MaximumSizeInBytes = $maxSize
                $logInstance.IsEnabled = $true
                $logInstance.SaveChanges()
                Write-Host "  ✓ Configured $log log: Max size 512MB, enabled" -ForegroundColor Green
            } catch {
                Write-Host "  ⚠ Could not configure $log log: $_" -ForegroundColor Yellow
            }
        }
        
        # Enable log retention
        $logPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
        foreach ($log in $logs) {
            $fullPath = "$logPath\$log"
            if (Test-Path $fullPath) {
                Set-ItemProperty -Path $fullPath -Name "Retention" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $fullPath -Name "AutoBackupLogFiles" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            }
        }
        
        Write-Host "  ✓ Event log retention configured" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring event logs: $_" -ForegroundColor Red
    }
}

function Find-SuspiciousScheduledTasks {
    Write-Host "Scanning for suspicious scheduled tasks..." -ForegroundColor Cyan
    
    try {
        $suspiciousTasks = @()
        $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
        
        foreach ($task in $allTasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            
            # Check for suspicious characteristics
            $suspicious = $false
            $reasons = @()
            
            # Check if task runs from suspicious locations
            if ($task.Actions.Execute -match '(\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp)') {
                $suspicious = $true
                $reasons += "Runs from temp location"
            }
            
            # Check if task runs script files
            if ($task.Actions.Execute -match '\.(bat|cmd|vbs|ps1|js)$') {
                $suspicious = $true
                $reasons += "Executes script file"
            }
            
            # Check if hidden task
            if ($task.Settings.Hidden) {
                $suspicious = $true
                $reasons += "Hidden task"
            }
            
            if ($suspicious) {
                $suspiciousTasks += [PSCustomObject]@{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    Action = $task.Actions.Execute
                    Arguments = $task.Actions.Arguments
                    Reasons = $reasons -join ", "
                    Author = $task.Author
                }
            }
        }
        
        if ($suspiciousTasks.Count -gt 0) {
            Write-Host "  ⚠ Found $($suspiciousTasks.Count) suspicious scheduled tasks:" -ForegroundColor Yellow
            $suspiciousTasks | Format-Table -AutoSize
            
            $remove = Read-Host "Review these tasks and disable suspicious ones manually? (Y/N)"
            if ($remove -match '^[Yy]') {
                Start-Process taskschd.msc
            }
        } else {
            Write-Host "  ✓ No obviously suspicious scheduled tasks found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error scanning scheduled tasks: $_" -ForegroundColor Red
    }
}

function Test-StartupPrograms {
    Write-Host "Checking startup programs..." -ForegroundColor Cyan
    
    try {
        $startupLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        $startupItems = @()
        
        foreach ($location in $startupLocations) {
            if (Test-Path $location) {
                $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                if ($items) {
                    $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $startupItems += [PSCustomObject]@{
                            Location = $location
                            Name = $_.Name
                            Command = $_.Value
                        }
                    }
                }
            }
        }
        
        if ($startupItems.Count -gt 0) {
            Write-Host "  Found $($startupItems.Count) startup items:" -ForegroundColor Yellow
            $startupItems | Format-Table -AutoSize -Wrap
            
            Write-Host "  ℹ Review these items and remove any unauthorized programs" -ForegroundColor Cyan
            $openMsconfig = Read-Host "Open Task Manager to manage startup? (Y/N)"
            if ($openMsconfig -match '^[Yy]') {
                Start-Process taskmgr.exe -ArgumentList "/0 /startup"
            }
        } else {
            Write-Host "  ✓ No startup programs found in registry" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking startup programs: $_" -ForegroundColor Red
    }
}

function Disable-UnnecessaryWindowsFeatures {
    Write-Host "Checking for unnecessary Windows features..." -ForegroundColor Cyan
    
    # Features that are typically unnecessary and should be removed
    $featuresToDisable = @(
        "TelnetClient",
        "TelnetServer", 
        "TFTP",
        "SMB1Protocol",
        "SMB1Protocol-Client",
        "SMB1Protocol-Server",
        "SimpleTCP",
        "Printing-XPSServices-Features",
        "SNMP",
        "WorkFolders-Client"
    )
    
    try {
        Write-Host "  Checking Windows optional features..." -ForegroundColor Yellow
        
        foreach ($feature in $featuresToDisable) {
            try {
                $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
                
                if ($featureState -and $featureState.State -eq "Enabled") {
                    Write-Host "    Disabling: $feature" -ForegroundColor Yellow
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                    Write-Host "    ✓ Disabled: $feature" -ForegroundColor Green
                }
            } catch {
                # Feature might not exist on this version, skip silently
            }
        }
        
        Write-Host "  ✓ Unnecessary Windows features disabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error disabling Windows features: $_" -ForegroundColor Red
    }
}

function Set-PowerOptions {
    Write-Host "Configuring power options for security..." -ForegroundColor Cyan
    
    try {
        # Set power plan to High Performance or Balanced
        $powerPlan = powercfg /list | Select-String "Balanced" | ForEach-Object { 
            if ($_ -match '([a-f0-9\-]{36})') { $matches[1] }
        }
        
        if ($powerPlan) {
            powercfg /setactive $powerPlan
            Write-Host "  ✓ Set power plan to Balanced" -ForegroundColor Green
        }
        
        # Disable hibernation (security risk - hiberfil.sys can contain sensitive data)
        powercfg /hibernate off
        Write-Host "  ✓ Hibernation disabled" -ForegroundColor Green
        
        # Set screen timeout
        powercfg /change monitor-timeout-ac 10  # 10 minutes on AC
        powercfg /change monitor-timeout-dc 5   # 5 minutes on battery
        
        # Set sleep timeout
        powercfg /change standby-timeout-ac 0   # Never sleep on AC (server)
        powercfg /change standby-timeout-dc 15  # 15 minutes on battery
        
        Write-Host "  ✓ Power timeouts configured" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring power options: $_" -ForegroundColor Red
    }
}

function Test-SuspiciousFiles {
    Write-Host "Checking for suspicious files in common locations..." -ForegroundColor Cyan
    
    try {
        $suspiciousExtensions = @('*.exe', '*.bat', '*.cmd', '*.vbs', '*.ps1', '*.com', '*.scr')
        $suspiciousLocations = @(
            "$env:TEMP",
            "$env:SystemRoot\Temp",
            "C:\Users\Public\Desktop",
            "C:\ProgramData"
        )
        
        $suspiciousFiles = @()
        
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                foreach ($ext in $suspiciousExtensions) {
                    $files = Get-ChildItem -Path $location -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                             Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }  # Modified in last 7 days
                    
                    if ($files) {
                        $suspiciousFiles += $files
                    }
                }
            }
        }
        
        if ($suspiciousFiles.Count -gt 0) {
            Write-Host "  ⚠ Found $($suspiciousFiles.Count) recently modified executable files in temp locations:" -ForegroundColor Yellow
            $suspiciousFiles | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
            
            $review = Read-Host "Open these locations in Explorer to review? (Y/N)"
            if ($review -match '^[Yy]') {
                $suspiciousLocations | ForEach-Object {
                    if (Test-Path $_) {
                        explorer.exe $_
                    }
                }
            }
        } else {
            Write-Host "  ✓ No suspicious files found in common temp locations" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error scanning for suspicious files: $_" -ForegroundColor Red
    }
}
function Test-HostsFile {
    Write-Host "Checking HOSTS file for suspicious entries..." -ForegroundColor Cyan
    
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        
        if (Test-Path $hostsPath) {
            $hostsContent = Get-Content $hostsPath
            $suspiciousEntries = $hostsContent | Where-Object { 
                $_ -notmatch '^\s*#' -and  # Not a comment
                $_ -notmatch '^\s*$' -and  # Not empty
                $_ -match '\S'              # Contains non-whitespace
            }
            
            if ($suspiciousEntries.Count -gt 0) {
                Write-Host "  ⚠ Found $($suspiciousEntries.Count) entries in HOSTS file:" -ForegroundColor Yellow
                $suspiciousEntries | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
                
                $edit = Read-Host "Open HOSTS file for review? (Y/N)"
                if ($edit -match '^[Yy]') {
                    notepad.exe $hostsPath
                }
            } else {
                Write-Host "  ✓ HOSTS file is clean (only comments/empty lines)" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  ⚠ Error checking HOSTS file: $_" -ForegroundColor Red
    }
}

function Disable-NetBIOSoverTCP {
    Write-Host "Disabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
    
    try {
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        foreach ($adapter in $adapters) {
            # Disable NetBIOS over TCP/IP (2 = Disable)
            $adapter.SetTcpipNetbios(2) | Out-Null
            Write-Host "  ✓ Disabled NetBIOS on: $($adapter.Description)" -ForegroundColor Green
        }
        
        Write-Host "  ✓ NetBIOS over TCP/IP disabled on all adapters" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error disabling NetBIOS: $_" -ForegroundColor Red
    }
}

function Set-DNSClientSecurity {
    Write-Host "Configuring DNS client security..." -ForegroundColor Cyan
    
    try {
        # Disable LLMNR (Link-Local Multicast Name Resolution)
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrPath)) {
            New-Item -Path $llmnrPath -Force | Out-Null
        }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
        Write-Host "  ✓ LLMNR disabled" -ForegroundColor Green
        
        # Disable NetBIOS name resolution fallback
        $netbiosPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        if (Test-Path $netbiosPath) {
            Set-ItemProperty -Path $netbiosPath -Name "NodeType" -Value 2 -Type DWord -Force  # 2 = P-node (WINS only)
        }
        
        Write-Host "  ✓ DNS client security configured" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring DNS security: $_" -ForegroundColor Red
    }
}

function harden_defender_and_exploit_protection {
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
                    Remove-ItemProperty -Path $passiveReg -Name 'ForceDefenderPassiveMode' -ErrorAction Stop
                    Write-Host "Removed ForceDefenderPassiveMode registry value."
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
                    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
                    Write-Host "Enabled Defender Network Protection."
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
                        Set-MpPreference -SevereThreatDefaultAction 1 -ErrorAction Stop
                        Write-Host "Severe threat default action was 'Ignore' (6). Changed to a non-ignore action."
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
                    Add-MpPreference -AttackSurfaceReductionRules_Ids @($asrGuid) -AttackSurfaceReductionRules_Actions @('Enabled') -ErrorAction Stop
                    Write-Host "Added/enabled ASR rule $asrGuid."
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
                    Set-MpPreference -DisableBlockAtFirstSeen $false -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -ErrorAction Stop
                    Write-Host "Enabled cloud/block-at-first-seen and core real-time protections: $($needs -join ', ')."
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
                Write-Host "No AttackSurfaceReductionOnlyExclusions configured."
            }
        } else {
            Write-Host "Get-MpPreference not available; attempting registry removal of ASR exclusions (if present)."
            $asrReg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            if (Test-Path $asrReg) {
                    Remove-ItemProperty -Path $asrReg -Name 'AttackSurfaceReductionOnlyExclusions' -ErrorAction SilentlyContinue
                    Write-Host "Removed AttackSurfaceReductionOnlyExclusions from registry."
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
                        try {
                            Set-ProcessMitigation -Name 'chrome.exe' -EnableForceRelocateImages 1 -ErrorAction Stop
                            Write-Host "Attempted to update Chrome exploit mitigations (DEP/mitigations). Verify in Windows Security -> Exploit Protection -> Program settings."
                        } catch {
                            Write-Host "Unable to programmatically change Chrome DEP via Set-ProcessMitigation: $($_.Exception.Message)"
                            Write-Host "Manually verify DEP is enabled for chrome.exe in Windows Security -> App & browser control -> Exploit protection -> Program settings."
                        }
                } else {
                    Write-Host "Chrome DEP appears enabled."
                }
            } else {
                Write-Host "No per-app mitigation entry for chrome.exe."
            }
        } else {
            Write-Host "Get-ProcessMitigation / Set-ProcessMitigation not available on this system. Configure Chrome DEP via Windows Security -> Exploit Protection settings."
        }
    } catch {
        Write-Host "Failed to inspect/apply Chrome DEP mitigations: $($_.Exception.Message)"
    }

    Write-Host "Defender & Exploit Protection hardening pass complete. Review output for any manual actions required."
}

function enforce_domain_hardening {

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
                    try {
                        Set-ItemProperty -Path $netlogonPath -Name $k -Value $desiredNetlogon[$k] -Type DWord -ErrorAction Stop
                        $changes[$k] = "updated -> $($desiredNetlogon[$k])"
                    } catch {
                        $changes[$k] = "failed to update: $($_.Exception.Message)"
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
                try {
                    if (!(Test-Path $ldapRegPath)) { New-Item -Path $ldapRegPath -Force | Out-Null }
                    Set-ItemProperty -Path $ldapRegPath -Name $ldapName -Value 2 -Type DWord -ErrorAction Stop
                    $results.Add("Set LDAP server signing requirement to 'Require signing' (LDAPServerIntegrity=2)") | Out-Null
                } catch {
                    $results.Add("Failed to set LDAPServerIntegrity: $($_.Exception.Message)") | Out-Null
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
                try {
                    Set-ItemProperty -Path $winlogonPath -Name $name -Value '0' -Type String -ErrorAction Stop
                    $results.Add("Set CachedLogonsCount = 0 (domain logons will not be cached)") | Out-Null
                } catch {
                    $results.Add("Failed to set CachedLogonsCount: $($_.Exception.Message)") | Out-Null
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
                try {
                    if (!(Test-Path $fipsPath)) { New-Item -Path $fipsPath -Force | Out-Null }
                    Set-ItemProperty -Path $fipsPath -Name $fipsName -Value 1 -Type DWord -ErrorAction Stop
                    $results.Add("Enabled FIPS algorithms (FipsAlgorithmPolicy\\Enabled = 1)") | Out-Null
                } catch {
                    $results.Add("Failed to enable FIPS policy: $($_.Exception.Message)") | Out-Null
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
            $results.Add("NOTE: Hardening to prevent domain users from enabling 'trusted for delegation' requires domain ACL changes.") | Out-Null
            $results.Add("Automated ACL changes are NOT performed by this script. Use AD ACL tooling (dsacls, Set-ACL via DirectoryServices) and restrict write perms to msDS-AllowedToDelegateTo/msDS-AllowedToActOnBehalfOfOtherIdentity to privileged groups only.") | Out-Null
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

function Set-WindowsDefender {
    Write-Host "Configuring Windows Defender for maximum security..." -ForegroundColor Cyan
    
    # Require elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Host "This operation requires administrative privileges. Re-run in an elevated session." -ForegroundColor Red
        return
    }

    try {
        # Ensure Defender is not disabled
        Write-Host "  Checking Defender status..." -ForegroundColor Yellow
        
        # Remove passive mode if present
        $passiveReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
        if (Test-Path $passiveReg) {
            $prop = Get-ItemProperty -Path $passiveReg -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
            if ($null -ne $prop.ForceDefenderPassiveMode) {
                Remove-ItemProperty -Path $passiveReg -Name 'ForceDefenderPassiveMode' -ErrorAction Stop
                Write-Host "  ✓ Removed ForceDefenderPassiveMode" -ForegroundColor Green
            }
        }

        # Ensure Defender is enabled
        $defenderReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        if (Test-Path $defenderReg) {
            $disableAS = Get-ItemProperty -Path $defenderReg -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
            if ($null -ne $disableAS.DisableAntiSpyware -and $disableAS.DisableAntiSpyware -eq 1) {
                Set-ItemProperty -Path $defenderReg -Name 'DisableAntiSpyware' -Value 0 -Type DWord -Force
                Write-Host "  ✓ Enabled Windows Defender (DisableAntiSpyware=0)" -ForegroundColor Green
            }
        }

        # Configure core protection features
        Write-Host "  Configuring core protection features..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            # Real-time protection
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            } catch {
                
            }
            # Behavior monitoring
            try {
                Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            } catch {

            }
            # IOAV (scan downloads and attachments)
            try {
                Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            } catch {

            }
            # On-access protection
            try {
                Set-MpPreference -DisableOnAccessProtection $false -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Unable to disable on access protection"; 
            }
            # Script scanning
            try {
                Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
            } catch {

            }
            # Block at first sight
            try {
                Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
            } catch {

            }
            Write-Host "  ✓ Core protection features enabled" -ForegroundColor Green
        }

        # Enable Cloud Protection
        Write-Host "  Enabling cloud-delivered protection..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            # Cloud protection
            Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
            
            # Submit samples automatically
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
            
            Write-Host "  ✓ Cloud protection enabled" -ForegroundColor Green
        }

        # Enable Network Protection
        Write-Host "  Enabling Network Protection..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
            Write-Host "  ✓ Network Protection enabled" -ForegroundColor Green
        }

        # Enable PUA (Potentially Unwanted Application) protection
        Write-Host "  Enabling PUA protection..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
            Write-Host "  ✓ PUA protection enabled" -ForegroundColor Green
        }

        # Configure Attack Surface Reduction (ASR) Rules
        Write-Host "  Configuring Attack Surface Reduction rules..." -ForegroundColor Yellow
        
        # ASR Rule GUIDs with descriptions
        $asrRules = @{
            # Block executable content from email client and webmail
            'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email client and webmail'
            
            # Block all Office applications from creating child processes
            'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block all Office applications from creating child processes'
            
            # Block Office applications from creating executable content
            '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office applications from creating executable content'
            
            # Block Office applications from injecting code into other processes
            '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office applications from injecting code into other processes'
            
            # Block JavaScript or VBScript from launching downloaded executable content
            'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript or VBScript from launching downloaded executable content'
            
            # Block execution of potentially obfuscated scripts
            '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block execution of potentially obfuscated scripts'
            
            # Block Win32 API calls from Office macros
            '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
            
            # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
            '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'Block executable files from running unless they meet prevalence/age/trusted list criteria'
            
            # Use advanced protection against ransomware
            'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced protection against ransomware'
            
            # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
            '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from lsass.exe'
            
            # Block process creations originating from PSExec and WMI commands
            'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creations originating from PSExec and WMI commands'
            
            # Block untrusted and unsigned processes that run from USB
            'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted and unsigned processes that run from USB'
            
            # Block Office communication application from creating child processes
            '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication application from creating child processes'
            
            # Block Adobe Reader from creating child processes
            '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
            
            # Block persistence through WMI event subscription
            'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
        }

        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            $asrCount = 0
            foreach ($ruleId in $asrRules.Keys) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                    $asrCount++
                } catch {
                    # Rule might already exist, try to enable it
                    try {
                        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
            Write-Host "  ✓ Configured $asrCount ASR rules" -ForegroundColor Green
        }

        # Remove ASR exclusions if any exist
        Write-Host "  Removing ASR exclusions..." -ForegroundColor Yellow
        
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            $mp = Get-MpPreference
            if ($mp.AttackSurfaceReductionOnlyExclusions -and $mp.AttackSurfaceReductionOnlyExclusions.Count -gt 0) {
                try {
                    Set-MpPreference -AttackSurfaceReductionOnlyExclusions @() -ErrorAction Stop
                    Write-Host "  ✓ Cleared ASR exclusions" -ForegroundColor Green
                } catch {
                    Write-Host "  ⚠ Could not clear ASR exclusions via cmdlet" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  ✓ No ASR exclusions present" -ForegroundColor Green
            }
        }

        # Enable Controlled Folder Access (Ransomware protection)
        Write-Host "  Enabling Controlled Folder Access..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
            Write-Host "  ✓ Controlled Folder Access enabled" -ForegroundColor Green
        }

        # Configure scan settings
        Write-Host "  Configuring scan settings..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            # Scan removable drives
            Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue
            
            # Scan network files
            Set-MpPreference -DisableScanningNetworkFiles $false -ErrorAction SilentlyContinue
            
            # Scan archives
            Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
            
            # Enable email scanning
            Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue
            
            Write-Host "  ✓ Scan settings configured" -ForegroundColor Green
        }

        # Configure threat actions
        Write-Host "  Configuring threat default actions..." -ForegroundColor Yellow
        
        if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
            # Severe threats: Remove
            Set-MpPreference -SevereThreatDefaultAction Remove -ErrorAction SilentlyContinue
            
            # High threats: Quarantine
            Set-MpPreference -HighThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
            
            # Moderate threats: Quarantine
            Set-MpPreference -ModerateThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
            
            # Low threats: Quarantine
            Set-MpPreference -LowThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
            
            Write-Host "  ✓ Threat actions configured" -ForegroundColor Green
        }

        # Enable Tamper Protection via registry
        Write-Host "  Enabling Tamper Protection..." -ForegroundColor Yellow
        
        $tamperPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        if (-not (Test-Path $tamperPath)) {
            New-Item -Path $tamperPath -Force | Out-Null
        }
        Set-ItemProperty -Path $tamperPath -Name 'TamperProtection' -Value 5 -Type DWord -Force
        Write-Host "  ✓ Tamper Protection enabled" -ForegroundColor Green

        # Enable DNS protection (examines DNS queries for exfiltration)
        Write-Host "  Enabling DNS Protection..." -ForegroundColor Yellow
        
        $dnsProtPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
        if (-not (Test-Path $dnsProtPath)) {
            New-Item -Path $dnsProtPath -Force | Out-Null
        }
        Set-ItemProperty -Path $dnsProtPath -Name 'EnableDnsProtection' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host "  ✓ DNS Protection enabled" -ForegroundColor Green

        # Enable Sandbox mode (Defender runs in sandboxed environment)
        Write-Host "  Enabling Defender Sandbox..." -ForegroundColor Yellow
        
        # Check current sandbox status
        $sandboxStatus = & "C:\Program Files\Windows Defender\MpCmdRun.exe" -GetFiles 2>&1 | Out-Null
        
        # Enable sandbox via setx (requires restart of Defender service)
        try {
            & setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null
            Write-Host "  ✓ Defender Sandbox enabled (service restart recommended)" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Could not enable sandbox mode" -ForegroundColor Yellow
        }

        # Configure additional protections via registry
        Write-Host "  Configuring additional protections..." -ForegroundColor Yellow
        
        $spynetPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        if (-not (Test-Path $spynetPath)) {
            New-Item -Path $spynetPath -Force | Out-Null
        }
        
        # Advanced MAPS reporting
        Set-ItemProperty -Path $spynetPath -Name 'SpynetReporting' -Value 2 -Type DWord -Force
        
        # Submit samples automatically
        Set-ItemProperty -Path $spynetPath -Name 'SubmitSamplesConsent' -Value 3 -Type DWord -Force
        
        $realtimePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        if (-not (Test-Path $realtimePath)) {
            New-Item -Path $realtimePath -Force | Out-Null
        }
        
        # Enable real-time protection
        Set-ItemProperty -Path $realtimePath -Name 'DisableRealtimeMonitoring' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $realtimePath -Name 'DisableBehaviorMonitoring' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $realtimePath -Name 'DisableOnAccessProtection' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $realtimePath -Name 'DisableScanOnRealtimeEnable' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $realtimePath -Name 'DisableIOAVProtection' -Value 0 -Type DWord -Force
        
        Write-Host "  ✓ Additional protections configured" -ForegroundColor Green

        # Start Defender service if not running
        Write-Host "  Checking Defender service..." -ForegroundColor Yellow
        
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($defenderService) {
            if ($defenderService.Status -ne 'Running') {
                Start-Service -Name WinDefend -ErrorAction Stop
                Write-Host "  ✓ Started Windows Defender service" -ForegroundColor Green
            } else {
                Write-Host "  ✓ Windows Defender service is running" -ForegroundColor Green
            }
        }

        # Run a quick scan
        Write-Host ""
        $scanChoice = Read-Host "Run a Windows Defender Quick Scan now? (Y/N)"
        if ($scanChoice -match '^[Yy]') {
            Write-Host "  Starting Quick Scan (this may take a few minutes)..." -ForegroundColor Yellow
            Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
            Write-Host "  ✓ Quick scan initiated" -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "============================================" -ForegroundColor Green
        Write-Host "✓ WINDOWS DEFENDER CONFIGURATION COMPLETE" -ForegroundColor Green
        Write-Host "============================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Configured protections:" -ForegroundColor Cyan
        Write-Host "  ✓ Real-time protection enabled" -ForegroundColor White
        Write-Host "  ✓ Cloud-delivered protection enabled" -ForegroundColor White
        Write-Host "  ✓ Network Protection enabled" -ForegroundColor White
        Write-Host "  ✓ PUA Protection enabled" -ForegroundColor White
        Write-Host "  ✓ Attack Surface Reduction rules configured" -ForegroundColor White
        Write-Host "  ✓ Controlled Folder Access enabled (Ransomware protection)" -ForegroundColor White
        Write-Host "  ✓ Tamper Protection enabled" -ForegroundColor White
        Write-Host "  ✓ DNS Protection enabled" -ForegroundColor White
        Write-Host "  ✓ Defender Sandbox enabled" -ForegroundColor White
        Write-Host "  ✓ PSExec/WMI command blocking enabled" -ForegroundColor White
        Write-Host ""
        Write-Host "VERIFICATION:" -ForegroundColor Yellow
        Write-Host "  1. Open: Windows Security (windowsdefender://)" -ForegroundColor White
        Write-Host "  2. Check: Virus & threat protection → Manage settings" -ForegroundColor White
        Write-Host "  3. Check: App & browser control → Exploit protection" -ForegroundColor White
        Write-Host ""

    } catch {
        Write-Host ""
        Write-Host "ERROR: $_" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    }
}

function Enable-WindowsSmartScreen {
    Write-Host "Enabling Windows SmartScreen..." -ForegroundColor Cyan
    
    try {
        $smartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $smartScreenPath)) {
            New-Item -Path $smartScreenPath -Force | Out-Null
        }
        
        $currentEnabled = (Get-ItemProperty -Path $smartScreenPath -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
        $currentLevel = (Get-ItemProperty -Path $smartScreenPath -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue).ShellSmartScreenLevel
        
        if ($currentEnabled -eq 1 -and $currentLevel -eq "Block") {
            Write-Host "  ✓ Windows SmartScreen already configured correctly" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $smartScreenPath -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $smartScreenPath -Name "ShellSmartScreenLevel" -Value "Block" -Type String -Force
        
        Write-Host "  ✓ Windows SmartScreen enabled" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Error enabling SmartScreen: $_" -ForegroundColor Red
    }
}

function Set-SMBSecurity {
    Write-Host "Configuring SMB security settings..." -ForegroundColor Cyan
    
    try {
        $lanmanServerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer"
        $lanmanWorkstationPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
        
        if (-not (Test-Path $lanmanServerPath)) {
            New-Item -Path $lanmanServerPath -Force | Out-Null
        }
        if (-not (Test-Path $lanmanWorkstationPath)) {
            New-Item -Path $lanmanWorkstationPath -Force | Out-Null
        }
        
        $changes = @()
        
        # Enable SMB over QUIC
        $smbQuicServer = (Get-ItemProperty -Path $lanmanServerPath -Name "EnableSMBQUIC" -ErrorAction SilentlyContinue).EnableSMBQUIC
        $smbQuicClient = (Get-ItemProperty -Path $lanmanWorkstationPath -Name "EnableSMBQUIC" -ErrorAction SilentlyContinue).EnableSMBQUIC
        
        if ($smbQuicServer -ne 1) {
            Set-ItemProperty -Path $lanmanServerPath -Name "EnableSMBQUIC" -Value 1 -Type DWord -Force
            $changes += "SMB over QUIC (Server)"
        }
        
        if ($smbQuicClient -ne 1) {
            Set-ItemProperty -Path $lanmanWorkstationPath -Name "EnableSMBQUIC" -Value 1 -Type DWord -Force
            $changes += "SMB over QUIC (Client)"
        }
        
        # Block NTLM
        $blockNtlm = (Get-ItemProperty -Path $lanmanWorkstationPath -Name "BlockNTLM" -ErrorAction SilentlyContinue).BlockNTLM
        if ($blockNtlm -ne 1) {
            Set-ItemProperty -Path $lanmanWorkstationPath -Name "BlockNTLM" -Value 1 -Type DWord -Force
            $changes += "Block NTLM"
        }
        
        # Set minimum SMB version to 3.0.0
        $minSmb = (Get-ItemProperty -Path $lanmanServerPath -Name "MinSmb2Dialect" -ErrorAction SilentlyContinue).MinSmb2Dialect
        if ($minSmb -ne 300) {
            Set-ItemProperty -Path $lanmanServerPath -Name "MinSmb2Dialect" -Value 300 -Type DWord -Force
            $changes += "Minimum SMB 3.0.0"
        }
        
        # Enable authentication rate limiter
        $rateLimiter = (Get-ItemProperty -Path $lanmanServerPath -Name "EnableAuthRateLimiter" -ErrorAction SilentlyContinue).EnableAuthRateLimiter
        if ($rateLimiter -ne 1) {
            Set-ItemProperty -Path $lanmanServerPath -Name "EnableAuthRateLimiter" -Value 1 -Type DWord -Force
            $changes += "Auth rate limiter"
        }
        
        # Set invalid authentication delay
        $authDelay = (Get-ItemProperty -Path $lanmanServerPath -Name "InvalidAuthenticationDelayTimeInMs" -ErrorAction SilentlyContinue).InvalidAuthenticationDelayTimeInMs
        if ($authDelay -ne 2000) {
            Set-ItemProperty -Path $lanmanServerPath -Name "InvalidAuthenticationDelayTimeInMs" -Value 2000 -Type DWord -Force
            $changes += "Auth delay (2000ms)"
        }
        
        if ($changes.Count -eq 0) {
            Write-Host "  ✓ SMB security already configured correctly" -ForegroundColor Green
        } else {
            Write-Host "  ✓ SMB security configured: $($changes -join ', ')" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring SMB security: $_" -ForegroundColor Red
    }
}

function Secure-CAPolicy {
    Write-Host "Securing Certificate Authority policy file..." -ForegroundColor Cyan
    
    try {
        $caPolicyPath = "$env:SystemRoot\System32\CAPolicy.inf"
        
        if (-not (Test-Path $caPolicyPath)) {
            Write-Host "  ℹ CAPolicy.inf not found (not a CA server)" -ForegroundColor Gray
            return
        }
        
        $acl = Get-Acl $caPolicyPath
        
        # Check if Everyone has full control
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $accessRules = $acl.Access | Where-Object { 
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $everyoneSid -and
            $_.FileSystemRights -eq "FullControl"
        }
        
        if (-not $accessRules) {
            Write-Host "  ✓ CAPolicy.inf permissions already secure" -ForegroundColor Green
            return
        }
        
        foreach ($rule in $accessRules) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }
        Set-Acl -Path $caPolicyPath -AclObject $acl
        Write-Host "  ✓ Removed insecure Everyone permissions from CAPolicy.inf" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error securing CAPolicy.inf: $_" -ForegroundColor Red
    }
}

function Enable-ADCSDisallowedCertAutoUpdate {
    Write-Host "Enabling AD CS disallowed cert auto update..." -ForegroundColor Cyan
    
    try {
        $certPath = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot"
        if (-not (Test-Path $certPath)) {
            New-Item -Path $certPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $certPath -Name "EnableDisallowedCertAutoUpdate" -ErrorAction SilentlyContinue).EnableDisallowedCertAutoUpdate
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ AD CS disallowed cert auto update already enabled" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $certPath -Name "EnableDisallowedCertAutoUpdate" -Value 1 -Type DWord -Force
        Write-Host "  ✓ AD CS disallowed cert auto update enabled" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Error enabling AD CS cert auto update: $_" -ForegroundColor Red
    }
}

function Enable-VBSMandatoryMode {
    Write-Host "Enabling Virtualization Based Security in Mandatory Mode..." -ForegroundColor Cyan
    
    try {
        $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        if (-not (Test-Path $deviceGuardPath)) {
            New-Item -Path $deviceGuardPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $deviceGuardPath -Name "Mandatory" -ErrorAction SilentlyContinue).Mandatory
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ VBS Mandatory Mode already enabled" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $deviceGuardPath -Name "Mandatory" -Value 1 -Type DWord -Force
        Write-Host "  ✓ VBS Mandatory Mode enabled (helps prevent downdate vulnerability CVE-2024-21302)" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Error enabling VBS Mandatory Mode: $_" -ForegroundColor Red
    }
}

function Set-MachineIdentityIsolation {
    Write-Host "Configuring Machine Identity Isolation..." -ForegroundColor Cyan
    
    try {
        $deviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        if (-not (Test-Path $deviceGuardPath)) {
            New-Item -Path $deviceGuardPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $deviceGuardPath -Name "MachineIdentityIsolation" -ErrorAction SilentlyContinue).MachineIdentityIsolation
        
        if ($currentValue -eq 2) {
            Write-Host "  ✓ Machine Identity Isolation already set to enforcement mode" -ForegroundColor Green
            return
        }
        
        # Set to 1 for audit mode, 2 for enforcement mode
        Set-ItemProperty -Path $deviceGuardPath -Name "MachineIdentityIsolation" -Value 2 -Type DWord -Force
        Write-Host "  ✓ Machine Identity Isolation set to enforcement mode" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Error configuring Machine Identity Isolation: $_" -ForegroundColor Red
    }
}

function Set-BrowserDoNotTrack {
    Write-Host "Configuring browser Do Not Track settings..." -ForegroundColor Cyan
    
    try {
        $changes = @()
        
        # Configure Chrome
        $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        $chromeInstalled = Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe"
        
        if ($chromeInstalled) {
            if (-not (Test-Path $chromePath)) {
                New-Item -Path $chromePath -Force | Out-Null
            }
            
            $chromeValue = (Get-ItemProperty -Path $chromePath -Name "EnableDoNotTrack" -ErrorAction SilentlyContinue).EnableDoNotTrack
            if ($chromeValue -ne 1) {
                Set-ItemProperty -Path $chromePath -Name "EnableDoNotTrack" -Value 1 -Type DWord -Force
                $changes += "Chrome"
            }
        }
        
        # Configure Firefox
        $firefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
        $firefoxInstalled = Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe"
        
        if ($firefoxInstalled) {
            if (-not (Test-Path $firefoxPath)) {
                New-Item -Path $firefoxPath -Force | Out-Null
            }
            
            $firefoxValue = (Get-ItemProperty -Path $firefoxPath -Name "EnableTrackingProtection" -ErrorAction SilentlyContinue).EnableTrackingProtection
            if ($firefoxValue -ne 1) {
                Set-ItemProperty -Path $firefoxPath -Name "EnableTrackingProtection" -Value 1 -Type DWord -Force
                $changes += "Firefox"
            }
        }
        
        # Configure Edge
        $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        $edgeInstalled = Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        
        if ($edgeInstalled) {
            if (-not (Test-Path $edgePath)) {
                New-Item -Path $edgePath -Force | Out-Null
            }
            
            $edgeValue = (Get-ItemProperty -Path $edgePath -Name "ConfigureDoNotTrack" -ErrorAction SilentlyContinue).ConfigureDoNotTrack
            if ($edgeValue -ne 1) {
                Set-ItemProperty -Path $edgePath -Name "ConfigureDoNotTrack" -Value 1 -Type DWord -Force
                $changes += "Edge"
            }
        }
        
        if ($changes.Count -eq 0) {
            if ($chromeInstalled -or $firefoxInstalled -or $edgeInstalled) {
                Write-Host "  ✓ Browser Do Not Track already configured" -ForegroundColor Green
            } else {
                Write-Host "  ℹ No supported browsers found installed" -ForegroundColor Gray
            }
        } else {
            Write-Host "  ✓ Do Not Track configured for: $($changes -join ', ')" -ForegroundColor Green
            Write-Host "  ℹ Users may also need to enable this in browser settings" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  ⚠ Error configuring browser Do Not Track: $_" -ForegroundColor Red
    }
}

function Disable-PowerShell2 {
    Write-Host "Checking PowerShell 2.0 status..." -ForegroundColor Cyan
    
    try {
        $ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction SilentlyContinue
        
        if (-not $ps2Feature) {
            Write-Host "  ✓ PowerShell 2.0 feature not present on this system" -ForegroundColor Green
            return
        }
        
        if ($ps2Feature.State -eq "Disabled") {
            Write-Host "  ✓ PowerShell 2.0 already disabled" -ForegroundColor Green
            return
        }
        
        Write-Host "  ⚠ PowerShell 2.0 is currently enabled" -ForegroundColor Yellow
        Write-Host "  ℹ PowerShell 2.0 should be disabled after this script completes" -ForegroundColor Gray
        Write-Host "  ℹ Run this command after the script finishes:" -ForegroundColor Gray
        Write-Host "    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -Remove" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking PowerShell 2.0: $_" -ForegroundColor Red
    }
}

function Enable-DefenderASRWebshellRule {
    Write-Host "Enabling Defender ASR rule to block webshell creation..." -ForegroundColor Cyan
    
    try {
        if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ Windows Defender cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $webshellRuleId = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"
        
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        if (-not $mp) {
            Write-Host "  ⚠ Unable to query Defender preferences" -ForegroundColor Yellow
            return
        }
        
        $existingRules = @()
        if ($mp.AttackSurfaceReductionRules_Ids) {
            $existingRules = $mp.AttackSurfaceReductionRules_Ids
        }
        
        if ($existingRules -contains $webshellRuleId) {
            Write-Host "  ✓ Defender ASR webshell rule already enabled" -ForegroundColor Green
            return
        }
        
        Add-MpPreference -AttackSurfaceReductionRules_Ids $webshellRuleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
        Write-Host "  ✓ Defender ASR webshell blocking rule enabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error enabling Defender ASR webshell rule: $_" -ForegroundColor Red
    }
}

function Find-TamperedVBSScripts {
    Write-Host "Checking for tampered VBS scripts..." -ForegroundColor Cyan
    
    try {
        $systemVbsPath = "$env:SystemRoot\System32"
        $systemWowVbsPath = "$env:SystemRoot\SysWOW64"
        
        $knownVbsFiles = @(
            "$systemVbsPath\slmgr.vbs",
            "$systemVbsPath\winrm.vbs",
            "$systemWowVbsPath\slmgr.vbs",
            "$systemWowVbsPath\winrm.vbs"
        )
        
        Write-Host "  ℹ System VBS file hashes (verify against clean baseline):" -ForegroundColor Gray
        
        $foundFiles = 0
        foreach ($vbsFile in $knownVbsFiles) {
            if (Test-Path $vbsFile) {
                $hash = (Get-FileHash -Path $vbsFile -Algorithm SHA256).Hash
                Write-Host "    $vbsFile" -ForegroundColor White
                Write-Host "      SHA256: $hash" -ForegroundColor Gray
                $foundFiles++
            }
        }
        
        if ($foundFiles -eq 0) {
            Write-Host "  ℹ No system VBS files found to check" -ForegroundColor Gray
        } else {
            Write-Host "  ℹ Compare these hashes with a baseline Windows Server 2022 system" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "  ⚠ Error checking VBS scripts: $_" -ForegroundColor Red
    }
}

function Test-ShareCreationEvents {
    Write-Host "Checking file shares..." -ForegroundColor Cyan
    
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$)$' }
        
        if (-not $shares -or $shares.Count -eq 0) {
            Write-Host "  ✓ No custom file shares found" -ForegroundColor Green
            return
        }
        
        Write-Host "  ℹ Current non-default shares found:" -ForegroundColor Yellow
        $shares | Select-Object Name, Path, Description | Format-Table -AutoSize
        
        Write-Host "  ℹ To check when shares were created:" -ForegroundColor Gray
        Write-Host "    Event Viewer -> Windows Logs -> Security -> Filter by Event ID 5142" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error checking shares: $_" -ForegroundColor Red
    }
}

function Set-AdvancedAuditPolicy {
    Write-Host "Configuring advanced audit policies..." -ForegroundColor Cyan
    
    try {
        $changes = @()
        
        # Check Computer Account Management
        $compAcctOutput = auditpol /get /subcategory:"Computer Account Management" 2>&1
        if ($compAcctOutput -notmatch "Success and Failure") {
            auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable | Out-Null
            $changes += "Computer Account Management"
        }
        
        # Check SAM auditing
        $samOutput = auditpol /get /subcategory:"SAM" 2>&1
        if ($samOutput -notmatch "Success and Failure") {
            auditpol /set /subcategory:"SAM" /success:enable /failure:enable | Out-Null
            $changes += "SAM"
        }
        
        # Check Certification Services auditing
        $certOutput = auditpol /get /subcategory:"Certification Services" 2>&1
        if ($certOutput -notmatch "Success and Failure") {
            auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable | Out-Null
            $changes += "Certification Services"
        }
        
        if ($changes.Count -eq 0) {
            Write-Host "  ✓ Advanced audit policies already configured" -ForegroundColor Green
        } else {
            Write-Host "  ✓ Configured audit policies: $($changes -join ', ')" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring advanced audit policies: $_" -ForegroundColor Red
    }
}

function Disable-AnonymousSAMEnumeration {
    Write-Host "Restricting anonymous access..." -ForegroundColor Cyan
    
    try {
        $changes = @()`
        
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        # Check anonymous SAM enumeration
        $currentSAM = (Get-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue).RestrictAnonymousSAM
        if ($currentSAM -ne 1) {
            Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
            $changes += "Anonymous SAM enumeration restricted"
        }
        
        # Check CD-ROM restriction
        $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $currentCDRom = (Get-ItemProperty -Path $winlogonPath -Name "AllocateCDRoms" -ErrorAction SilentlyContinue).AllocateCDRoms
        if ($currentCDRom -ne 1) {
            Set-ItemProperty -Path $winlogonPath -Name "AllocateCDRoms" -Value 1 -Type DWord -Force
            $changes += "CD-ROM access restricted to local users"
        }
        
        if ($changes.Count -eq 0) {
            Write-Host "  ✓ Anonymous access restrictions already configured" -ForegroundColor Green
        } else {
            Write-Host "  ✓ Configured: $($changes -join ', ')" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error restricting anonymous access: $_" -ForegroundColor Red
    }
}

function Enable-LSAProtection {
    Write-Host "Enabling Additional LSA Protection (RunAsPPL)..." -ForegroundColor Cyan
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        $currentValue = (Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ LSA Protection (RunAsPPL) already enabled" -ForegroundColor Green
            return
        }
        
        if (-not (Test-Path $lsaPath)) {
            New-Item -Path $lsaPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
        Write-Host "  ✓ LSA Protection enabled (prevents credential dumping attacks like Mimikatz)" -ForegroundColor Green
        Write-Host "  ⚠ A system restart is required for this change to take effect" -ForegroundColor Yellow
        
    } catch {
        Write-Host "  ⚠ Error enabling LSA Protection: $_" -ForegroundColor Red
    }
}

function Disable-AnonymousLDAPBind {
    Write-Host "Disabling Anonymous LDAP Bind..." -ForegroundColor Cyan
    
    try {
        # Check if this is a domain controller
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        
        if (-not $isDC) {
            Write-Host "  ℹ This is not a Domain Controller, skipping LDAP configuration" -ForegroundColor Gray
            return
        }
        
        # Check if Active Directory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "  ⚠ Active Directory module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        Write-Host "  ℹ To disable anonymous LDAP operations:" -ForegroundColor Yellow
        Write-Host "    1. Open ADSI Edit" -ForegroundColor White
        Write-Host "    2. Connect to Configuration naming context" -ForegroundColor White
        Write-Host "    3. Navigate to: CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=<domain>" -ForegroundColor White
        Write-Host "    4. In dsHeuristics property, change 7th character from '2' to '0'" -ForegroundColor White
        Write-Host "    5. Example: '0000002' should become '0000000'" -ForegroundColor White
        Write-Host "  ℹ This prevents anonymous LDAP enumeration attacks" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error checking LDAP configuration: $_" -ForegroundColor Red
    }
}

function Disable-KerberosPreAuthBypass {
    Write-Host "Checking Kerberos Pre-Authentication settings..." -ForegroundColor Cyan
    
    try {
        # Check if this is a domain environment
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in a domain environment, skipping Kerberos check" -ForegroundColor Gray
            return
        }
        
        # Check if Active Directory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "  ⚠ Active Directory module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        # Get all users with Kerberos pre-auth disabled
        $usersWithoutPreAuth = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
        
        if ($usersWithoutPreAuth) {
            Write-Host "  ⚠ Found $($usersWithoutPreAuth.Count) user(s) with Kerberos Pre-Authentication disabled:" -ForegroundColor Yellow
            foreach ($user in $usersWithoutPreAuth) {
                Write-Host "    - $($user.SamAccountName)" -ForegroundColor White
            }
            
            $fix = Read-Host "Enable Kerberos Pre-Authentication for these users? (Y/N)"
            if ($fix -match '^[Yy]') {
                foreach ($user in $usersWithoutPreAuth) {
                    try {
                        Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth $false -ErrorAction Stop
                        Write-Host "    ✓ Enabled Pre-Auth for $($user.SamAccountName)" -ForegroundColor Green
                    } catch {
                        Write-Host "    ⚠ Failed to update $($user.SamAccountName): $_" -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "  ✓ All domain users have Kerberos Pre-Authentication enabled" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking Kerberos settings: $_" -ForegroundColor Red
    }
}

function Test-PasswordExpiration {
    Write-Host "Checking password expiration settings..." -ForegroundColor Cyan
    
    try {
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if ($isDomain) {
            # Domain environment - check AD users
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                
                $usersNoExpiry = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires -ErrorAction SilentlyContinue | 
                    Where-Object { $_.SamAccountName -notmatch '^(Administrator|Guest|krbtgt)$' }
                
                if ($usersNoExpiry) {
                    Write-Host "  ⚠ Found $($usersNoExpiry.Count) enabled user(s) with non-expiring passwords:" -ForegroundColor Yellow
                    foreach ($user in $usersNoExpiry) {
                        Write-Host "    - $($user.SamAccountName)" -ForegroundColor White
                    }
                    
                    $fix = Read-Host "Enable password expiration for these users? (Y/N)"
                    if ($fix -match '^[Yy]') {
                        foreach ($user in $usersNoExpiry) {
                            try {
                                Set-ADUser -Identity $user -PasswordNeverExpires $false -ErrorAction Stop
                                Write-Host "    ✓ Enabled expiration for $($user.SamAccountName)" -ForegroundColor Green
                            } catch {
                                Write-Host "    ⚠ Failed to update $($user.SamAccountName): $_" -ForegroundColor Red
                            }
                        }
                    }
                } else {
                    Write-Host "  ✓ All enabled domain users have password expiration enabled" -ForegroundColor Green
                }
            }
        } else {
            # Local environment
            $localUsersNoExpiry = Get-LocalUser -ErrorAction SilentlyContinue | 
                Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true -and $_.Name -notmatch '^(Administrator|Guest|DefaultAccount)$' }
            
            if ($localUsersNoExpiry) {
                Write-Host "  ⚠ Found $($localUsersNoExpiry.Count) local user(s) with non-expiring passwords:" -ForegroundColor Yellow
                foreach ($user in $localUsersNoExpiry) {
                    Write-Host "    - $($user.Name)" -ForegroundColor White
                }
                
                $fix = Read-Host "Enable password expiration for these users? (Y/N)"
                if ($fix -match '^[Yy]') {
                    foreach ($user in $localUsersNoExpiry) {
                        try {
                            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -ErrorAction Stop
                            Write-Host "    ✓ Enabled expiration for $($user.Name)" -ForegroundColor Green
                        } catch {
                            Write-Host "    ⚠ Failed to update $($user.Name): $_" -ForegroundColor Red
                        }
                    }
                }
            } else {
                Write-Host "  ✓ All enabled local users have password expiration enabled" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  ⚠ Error checking password expiration: $_" -ForegroundColor Red
    }
}

function Disable-PowerShellRemoting {
    Write-Host "Checking PowerShell Remoting status..." -ForegroundColor Cyan
    
    try {
        $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        
        if (-not $winrmService) {
            Write-Host "  ✓ WinRM service not present" -ForegroundColor Green
            return
        }
        
        # Check if WinRM is configured for remoting
        $psRemotingEnabled = $false
        try {
            $null = Test-WSMan -ErrorAction Stop
            $psRemotingEnabled = $true
        } catch {
            # Test-WSMan failed, remoting likely disabled
        }
        
        if (-not $psRemotingEnabled -and $winrmService.Status -eq 'Stopped') {
            Write-Host "  ✓ PowerShell Remoting already disabled" -ForegroundColor Green
            return
        }
        
        Write-Host "  ⚠ PowerShell Remoting appears to be enabled" -ForegroundColor Yellow
        $disable = Read-Host "Disable PowerShell Remoting? (Y/N)"
        
        if ($disable -match '^[Yy]') {
            try {
                Disable-PSRemoting -Force -ErrorAction Stop
                Stop-Service -Name WinRM -Force -ErrorAction Stop
                Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
                Write-Host "  ✓ PowerShell Remoting disabled and WinRM service stopped" -ForegroundColor Green
            } catch {
                Write-Host "  ⚠ Error disabling PowerShell Remoting: $_" -ForegroundColor Red
            }
        }
        
    } catch {
        Write-Host "  ⚠ Error checking PowerShell Remoting: $_" -ForegroundColor Red
    }
}

function Test-DelegationRights {
    Write-Host "Checking delegation rights..." -ForegroundColor Cyan
    
    try {
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in a domain environment, skipping delegation check" -ForegroundColor Gray
            return
        }
        
        Write-Host "  ℹ Checking for overly permissive delegation settings..." -ForegroundColor Yellow
        Write-Host "  ℹ To check and fix delegation rights:" -ForegroundColor Gray
        Write-Host "    1. Open Group Policy Management" -ForegroundColor White
        Write-Host "    2. Edit Default Domain Policy" -ForegroundColor White
        Write-Host "    3. Navigate to: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment" -ForegroundColor White
        Write-Host "    4. Find: 'Enable computer and user accounts to be trusted for delegation'" -ForegroundColor White
        Write-Host "    5. Remove 'Everyone' group if present" -ForegroundColor White
        Write-Host "    6. Only Domain Admins should have this right" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking delegation rights: $_" -ForegroundColor Red
    }
}

function Disable-SMBCompression {
    Write-Host "Disabling SMB Compression..." -ForegroundColor Cyan
    
    try {
        $smbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        $currentValue = (Get-ItemProperty -Path $smbPath -Name "DisableCompression" -ErrorAction SilentlyContinue).DisableCompression
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ SMB Compression already disabled" -ForegroundColor Green
            return
        }
        
        if (-not (Test-Path $smbPath)) {
            New-Item -Path $smbPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $smbPath -Name "DisableCompression" -Value 1 -Type DWord -Force
        Write-Host "  ✓ SMB Compression disabled (mitigates CVE-2020-0796 SMBGhost)" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error disabling SMB Compression: $_" -ForegroundColor Red
    }
}

function Enable-SMBEncryption {
    Write-Host "Enabling SMB Server-wide Encryption..." -ForegroundColor Cyan
    
    try {
        if (-not (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ SMB cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        
        if ($smbConfig.EncryptData -eq $true) {
            Write-Host "  ✓ SMB Server-wide Encryption already enabled" -ForegroundColor Green
            return
        }
        
        Set-SmbServerConfiguration -EncryptData $true -Force -Confirm:$false -ErrorAction Stop
        Write-Host "  ✓ SMB Server-wide Encryption enabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error enabling SMB Encryption: $_" -ForegroundColor Red
    }
}

function Set-DNSSIGRedMitigation {
    Write-Host "Applying DNS SIGRed (CVE-2020-1350) mitigation..." -ForegroundColor Cyan
    
    try {
        # Check if DNS service exists
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        
        if (-not $dnsService) {
            Write-Host "  ℹ DNS Server service not present, skipping SIGRed mitigation" -ForegroundColor Gray
            return
        }
        
        $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
        
        $currentValue = (Get-ItemProperty -Path $dnsPath -Name "TcpReceivePacketSize" -ErrorAction SilentlyContinue).TcpReceivePacketSize
        
        if ($currentValue -eq 0xFF00) {
            Write-Host "  ✓ DNS SIGRed mitigation already applied" -ForegroundColor Green
            return
        }
        
        if (-not (Test-Path $dnsPath)) {
            New-Item -Path $dnsPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $dnsPath -Name "TcpReceivePacketSize" -Value 0xFF00 -Type DWord -Force
        Write-Host "  ✓ DNS SIGRed mitigation applied (TcpReceivePacketSize set to 0xFF00)" -ForegroundColor Green
        
        # Restart DNS service
        $restart = Read-Host "Restart DNS service to apply changes? (Y/N)"
        if ($restart -match '^[Yy]') {
            Restart-Service -Name DNS -Force -ErrorAction Stop
            Write-Host "  ✓ DNS service restarted" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ DNS service restart required for changes to take effect" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "  ⚠ Error applying DNS SIGRed mitigation: $_" -ForegroundColor Red
    }
}

function Test-SuspiciousServices {
    Write-Host "Checking for suspicious services..." -ForegroundColor Cyan
    
    try {
        $suspiciousServices = @()
        $allServices = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
        
        foreach ($service in $allServices) {
            $suspicious = $false
            $reasons = @()
            
            # Check for services running from temp locations
            if ($service.PathName -match '(\\Temp\\|\\AppData\\Local\\Temp|\\Downloads\\)') {
                $suspicious = $true
                $reasons += "Runs from temp location"
            }
            
            # Check for services with suspicious names (common backdoor patterns)
            if ($service.Name -match '(inetinfo|psexe|remcom|backdoor|shell|hack)' -and 
                $service.Name -notmatch '^(W3SVC|IISADMIN)$') {
                $suspicious = $true
                $reasons += "Suspicious service name"
            }
            
            # Check for services running as SYSTEM from non-standard locations
            if ($service.StartName -eq 'LocalSystem' -and 
                $service.PathName -notmatch '^[A-Z]:\\Windows\\' -and
                $service.PathName -notmatch '^[A-Z]:\\Program Files') {
                $suspicious = $true
                $reasons += "System service from unusual location"
            }
            
            if ($suspicious) {
                $suspiciousServices += [PSCustomObject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    PathName = $service.PathName
                    StartName = $service.StartName
                    State = $service.State
                    Reasons = $reasons -join ", "
                }
            }
        }
        
        if ($suspiciousServices.Count -gt 0) {
            Write-Host "  ⚠ Found $($suspiciousServices.Count) suspicious service(s):" -ForegroundColor Yellow
            $suspiciousServices | Format-Table -AutoSize -Wrap
            
            Write-Host "  ℹ Review these services carefully and remove any unauthorized backdoors" -ForegroundColor Yellow
            $openServices = Read-Host "Open Services console to investigate? (Y/N)"
            if ($openServices -match '^[Yy]') {
                services.msc
            }
        } else {
            Write-Host "  ✓ No obviously suspicious services found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking services: $_" -ForegroundColor Red
    }
}

function Test-ListeningPorts {
    Write-Host "Checking listening network ports..." -ForegroundColor Cyan
    
    try {
        Write-Host "  ℹ Gathering listening ports and associated processes..." -ForegroundColor Gray
        
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
            Select-Object LocalAddress, LocalPort, OwningProcess, State |
            Sort-Object LocalPort
        
        if ($listeners) {
            $portInfo = @()
            foreach ($listener in $listeners) {
                try {
                    $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
                    $portInfo += [PSCustomObject]@{
                        Port = $listener.LocalPort
                        Address = $listener.LocalAddress
                        Process = $process.ProcessName
                        PID = $listener.OwningProcess
                        Path = $process.Path
                    }
                } catch {
                    $portInfo += [PSCustomObject]@{
                        Port = $listener.LocalPort
                        Address = $listener.LocalAddress
                        Process = "Unknown"
                        PID = $listener.OwningProcess
                        Path = "N/A"
                    }
                }
            }
            
            Write-Host "  ℹ Listening ports:" -ForegroundColor Yellow
            $portInfo | Format-Table -AutoSize
            
            Write-Host "  ℹ Review for suspicious listeners on non-standard ports (especially high ports)" -ForegroundColor Gray
            Write-Host "  ℹ Common legitimate ports: 53 (DNS), 80/443 (HTTP/HTTPS), 88 (Kerberos), 135 (RPC), 389/636 (LDAP), 445 (SMB), 3389 (RDP)" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "  ⚠ Error checking listening ports: $_" -ForegroundColor Red
    }
}

function Test-ADReplicationRights {
    Write-Host "Checking Active Directory replication rights..." -ForegroundColor Cyan
    
    try {
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in a domain environment, skipping AD replication check" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "  ⚠ Active Directory module not available" -ForegroundColor Yellow
            return
        }
        
        Write-Host "  ℹ Checking for users with dangerous replication rights..." -ForegroundColor Yellow
        Write-Host "  ℹ To check and fix replication rights:" -ForegroundColor Gray
        Write-Host "    1. Open ADSI Edit" -ForegroundColor White
        Write-Host "    2. Connect to Default naming context" -ForegroundColor White
        Write-Host "    3. Right-click domain root > Properties > Security > Advanced" -ForegroundColor White
        Write-Host "    4. Look for users with 'Replicating Directory Changes All' permission" -ForegroundColor White
        Write-Host "    5. Remove this permission from non-admin users" -ForegroundColor White
        Write-Host "  ℹ This prevents DCSync attacks" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error checking AD replication rights: $_" -ForegroundColor Red
    }
}

function Enable-PowerShellTranscription {
    Write-Host "Enabling PowerShell Transcription logging..." -ForegroundColor Cyan
    
    try {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        if (-not (Test-Path $psPath)) {
            New-Item -Path $psPath -Force | Out-Null
        }
        
        $currentEnabled = (Get-ItemProperty -Path $psPath -Name "EnableTranscripting" -ErrorAction SilentlyContinue).EnableTranscripting
        $currentInvocation = (Get-ItemProperty -Path $psPath -Name "EnableInvocationHeader" -ErrorAction SilentlyContinue).EnableInvocationHeader
        
        if ($currentEnabled -eq 1 -and $currentInvocation -eq 1) {
            Write-Host "  ✓ PowerShell Transcription already enabled" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $psPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $psPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $psPath -Name "OutputDirectory" -Value "C:\PowerShell_Transcripts" -Type String -Force
        
        # Create the transcript directory
        if (-not (Test-Path "C:\PowerShell_Transcripts")) {
            New-Item -Path "C:\PowerShell_Transcripts" -ItemType Directory -Force | Out-Null
        }
        
        Write-Host "  ✓ PowerShell Transcription enabled" -ForegroundColor Green
        Write-Host "  ℹ Transcripts will be saved to: C:\PowerShell_Transcripts" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error enabling PowerShell Transcription: $_" -ForegroundColor Red
    }
}

function Set-BitLocker {
    Write-Host "Checking BitLocker encryption status..." -ForegroundColor Cyan
    
    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        if (-not $bitlockerVolumes) {
            Write-Host "  ℹ BitLocker cmdlets not available or no volumes found" -ForegroundColor Gray
            return
        }
        
        $unencryptedVolumes = $bitlockerVolumes | Where-Object { $_.ProtectionStatus -eq 'Off' -and $_.VolumeType -eq 'OperatingSystem' }
        
        if (-not $unencryptedVolumes) {
            Write-Host "  ✓ BitLocker already enabled on operating system volumes" -ForegroundColor Green
            return
        }
        
        Write-Host "  ⚠ Found unencrypted operating system volume(s)" -ForegroundColor Yellow
        Write-Host "  ℹ To enable BitLocker:" -ForegroundColor Gray
        Write-Host "    1. Open Control Panel > BitLocker Drive Encryption" -ForegroundColor White
        Write-Host "    2. Click 'Turn on BitLocker' for the system drive" -ForegroundColor White
        Write-Host "    3. Follow the wizard to complete encryption" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking BitLocker status: $_" -ForegroundColor Red
    }
}

function Set-DHCPAuditLogging {
    Write-Host "Checking DHCP audit logging..." -ForegroundColor Cyan
    
    try {
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        
        if (-not $dhcpService) {
            Write-Host "  ℹ DHCP Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DhcpServerAuditLog -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DHCP Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $auditLog = Get-DhcpServerAuditLog -ErrorAction SilentlyContinue
        
        if ($auditLog.Enable -eq $true) {
            Write-Host "  ✓ DHCP audit logging already enabled" -ForegroundColor Green
            return
        }
        
        Set-DhcpServerAuditLog -Enable $true -ErrorAction Stop
        Write-Host "  ✓ DHCP audit logging enabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring DHCP audit logging: $_" -ForegroundColor Red
    }
}

function Set-DHCPServerAuthorization {
    Write-Host "Checking DHCP server authorization..." -ForegroundColor Cyan
    
    try {
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        
        if (-not $dhcpService) {
            Write-Host "  ℹ DHCP Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in domain environment, DHCP authorization not applicable" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DhcpServerInDC -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DHCP Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $authorizedServers = Get-DhcpServerInDC -ErrorAction SilentlyContinue
        $computerName = $env:COMPUTERNAME
        
        if ($authorizedServers | Where-Object { $_.DnsName -match $computerName }) {
            Write-Host "  ✓ DHCP server already authorized in Active Directory" -ForegroundColor Green
            return
        }
        
        Write-Host "  ⚠ DHCP server not authorized in Active Directory" -ForegroundColor Yellow
        Write-Host "  ℹ To authorize, run as Domain Admin:" -ForegroundColor Gray
        Write-Host "    Add-DhcpServerInDC -DnsName $computerName" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking DHCP authorization: $_" -ForegroundColor Red
    }
}

function Remove-UnauthorizedDHCPServers {
    Write-Host "Checking for unauthorized DHCP servers..." -ForegroundColor Cyan
    
    try {
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in domain environment, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DhcpServerInDC -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DHCP Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $authorizedServers = Get-DhcpServerInDC -ErrorAction SilentlyContinue
        
        if ($authorizedServers) {
            Write-Host "  ℹ Authorized DHCP servers in domain:" -ForegroundColor Yellow
            $authorizedServers | Format-Table DnsName, IPAddress -AutoSize
            
            Write-Host "  ℹ Review this list and remove any unauthorized servers using:" -ForegroundColor Gray
            Write-Host "    Remove-DhcpServerInDC -DnsName <servername>" -ForegroundColor White
        } else {
            Write-Host "  ✓ No DHCP servers found in Active Directory" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking DHCP servers: $_" -ForegroundColor Red
    }
}

function Set-DHCPNameProtection {
    Write-Host "Checking DHCP name protection..." -ForegroundColor Cyan
    
    try {
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        
        if (-not $dhcpService) {
            Write-Host "  ℹ DHCP Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DHCP Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        
        if (-not $scopes) {
            Write-Host "  ℹ No DHCP scopes configured" -ForegroundColor Gray
            return
        }
        
        $changes = @()
        foreach ($scope in $scopes) {
            $dnsSetting = Get-DhcpServerv4DnsSetting -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
            
            if ($dnsSetting.NameProtection -ne $true) {
                Set-DhcpServerv4DnsSetting -ScopeId $scope.ScopeId -NameProtection $true -ErrorAction SilentlyContinue
                $changes += $scope.ScopeId.ToString()
            }
        }
        
        if ($changes.Count -eq 0) {
            Write-Host "  ✓ DHCP name protection already enabled on all scopes" -ForegroundColor Green
        } else {
            Write-Host "  ✓ Enabled name protection on scopes: $($changes -join ', ')" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring DHCP name protection: $_" -ForegroundColor Red
    }
}

function Set-DHCPLogPath {
    Write-Host "Checking DHCP log file path..." -ForegroundColor Cyan
    
    try {
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
        
        if (-not $dhcpService) {
            Write-Host "  ℹ DHCP Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DhcpServerAuditLog -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DHCP Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $auditLog = Get-DhcpServerAuditLog -ErrorAction SilentlyContinue
        
        if ($auditLog.Path) {
            Write-Host "  ✓ DHCP log path configured: $($auditLog.Path)" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ DHCP log path not configured" -ForegroundColor Yellow
            Write-Host "  ℹ Setting default path to C:\Windows\System32\dhcp" -ForegroundColor Gray
            Set-DhcpServerAuditLog -Path "C:\Windows\System32\dhcp" -ErrorAction Stop
            Write-Host "  ✓ DHCP log path configured" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking DHCP log path: $_" -ForegroundColor Red
    }
}

function Disable-DNSIPv6Tunneling {
    Write-Host "Checking DNS global query block list for IPv6 tunneling..." -ForegroundColor Cyan
    
    try {
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        
        if (-not $dnsService) {
            Write-Host "  ℹ DNS Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DnsServerGlobalQueryBlockList -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DNS Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $blockList = Get-DnsServerGlobalQueryBlockList -ErrorAction SilentlyContinue
        
        if ($blockList.Enable -eq $true) {
            Write-Host "  ✓ DNS global query block list already enabled" -ForegroundColor Green
        } else {
            Set-DnsServerGlobalQueryBlockList -Enable $true -ErrorAction Stop
            Write-Host "  ✓ DNS global query block list enabled (blocks IPv6 to IPv4 tunneling)" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring DNS query block list: $_" -ForegroundColor Red
    }
}

function Set-DNSRateLimiting {
    Write-Host "Checking DNS server rate limiting..." -ForegroundColor Cyan
    
    try {
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        
        if (-not $dnsService) {
            Write-Host "  ℹ DNS Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Command -Name Get-DnsServerResponseRateLimiting -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ DNS Server cmdlets not available" -ForegroundColor Yellow
            return
        }
        
        $rlConfig = Get-DnsServerResponseRateLimiting -ErrorAction SilentlyContinue
        
        if ($rlConfig.Mode -eq 'Enable') {
            Write-Host "  ✓ DNS response rate limiting already enabled" -ForegroundColor Green
            return
        }
        
        Set-DnsServerResponseRateLimiting -Mode Enable -ErrorAction Stop
        Write-Host "  ✓ DNS response rate limiting enabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring DNS rate limiting: $_" -ForegroundColor Red
    }
}

function Disable-DNSSlaveServer {
    Write-Host "Checking DNS server configuration..." -ForegroundColor Cyan
    
    try {
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        
        if (-not $dnsService) {
            Write-Host "  ℹ DNS Server service not installed, skipping" -ForegroundColor Gray
            return
        }
        
        # Check if this is a secondary (slave) DNS server
        $dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
        $slaveValue = (Get-ItemProperty -Path $dnsRegPath -Name "IsSlave" -ErrorAction SilentlyContinue).IsSlave
        
        if ($slaveValue -eq 1) {
            Write-Host "  ⚠ This DNS server is configured as a slave server" -ForegroundColor Yellow
            Write-Host "  ℹ If this server should be authoritative (not a slave), convert it to a primary zone" -ForegroundColor Gray
        } else {
            Write-Host "  ✓ DNS server is not configured as a slave server" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking DNS configuration: $_" -ForegroundColor Red
    }
}

function Test-KerberosDelegation {
    Write-Host "Checking for accounts allowed to delegate Kerberos..." -ForegroundColor Cyan
    
    try {
        $isDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        
        if (-not $isDomain) {
            Write-Host "  ℹ Not in a domain environment, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "  ⚠ Active Directory module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        # Check for computer accounts trusted for delegation
        $delegatedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -ErrorAction SilentlyContinue
        
        if ($delegatedComputers) {
            Write-Host "  ⚠ Found $($delegatedComputers.Count) computer account(s) trusted for delegation:" -ForegroundColor Yellow
            foreach ($comp in $delegatedComputers) {
                Write-Host "    - $($comp.Name)" -ForegroundColor White
            }
            Write-Host "  ℹ Review these carefully - only domain controllers and specific servers should be trusted for delegation" -ForegroundColor Gray
        } else {
            Write-Host "  ✓ No computer accounts trusted for delegation (beyond domain controllers)" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking Kerberos delegation: $_" -ForegroundColor Red
    }
}

function Test-ADDatabasePermissions {
    Write-Host "Checking Active Directory database permissions..." -ForegroundColor Cyan
    
    try {
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
        
        if (-not $isDC) {
            Write-Host "  ℹ Not a domain controller, skipping" -ForegroundColor Gray
            return
        }
        
        Write-Host "  ℹ Checking that MEI cannot read/perform actions on AD database..." -ForegroundColor Yellow
        Write-Host "  ℹ To verify permissions:" -ForegroundColor Gray
        Write-Host "    1. Open ADSI Edit" -ForegroundColor White
        Write-Host "    2. Connect to default naming context" -ForegroundColor White
        Write-Host "    3. Right-click domain root > Properties > Security" -ForegroundColor White
        Write-Host "    4. Verify that only authorized accounts have full control" -ForegroundColor White
        Write-Host "    5. Remove excessive permissions from regular users/groups" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking AD permissions: $_" -ForegroundColor Red
    }
}

function Remove-DangerousPowerShellModules {
    Write-Host "Checking for dangerous PowerShell modules..." -ForegroundColor Cyan
    
    try {
        $dangerousModules = @(
            "PowerSploit",
            "Nishang",
            "Empire",
            "PowerShellEmpire",
            "Invoke-Mimikatz",
            "PowerUp",
            "PowerView"
        )
        
        $foundModules = @()
        
        foreach ($module in $dangerousModules) {
            if (Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue) {
                $foundModules += $module
            }
        }
        
        if ($foundModules.Count -gt 0) {
            Write-Host "  ⚠ Found $($foundModules.Count) dangerous PowerShell module(s):" -ForegroundColor Yellow
            foreach ($mod in $foundModules) {
                Write-Host "    - $mod" -ForegroundColor White
            }
            
            $remove = Read-Host "Remove these modules? (Y/N)"
            if ($remove -match '^[Yy]') {
                foreach ($mod in $foundModules) {
                    try {
                        $modulePath = (Get-Module -ListAvailable -Name $mod).ModuleBase
                        Remove-Item -Path $modulePath -Recurse -Force -ErrorAction Stop
                        Write-Host "    ✓ Removed $mod" -ForegroundColor Green
                    } catch {
                        Write-Host "    ⚠ Failed to remove $mod : $_" -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "  ✓ No dangerous PowerShell modules found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking PowerShell modules: $_" -ForegroundColor Red
    }
}

function Enable-ObjectAccessAuditing {
    Write-Host "Checking object access auditing..." -ForegroundColor Cyan
    
    try {
        $output = auditpol /get /subcategory:"File System" 2>&1
        
        if ($output -match "Success and Failure") {
            Write-Host "  ✓ Object access auditing already enabled" -ForegroundColor Green
            return
        }
        
        auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
        Write-Host "  ✓ Object access auditing enabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring object access auditing: $_" -ForegroundColor Red
    }
}

function Set-NTLMv2Only {
    Write-Host "Configuring LAN Manager to send NTLMv2 responses only..." -ForegroundColor Cyan
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $currentValue = (Get-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
        
        # Value 5 = Send NTLMv2 response only, refuse LM & NTLM
        if ($currentValue -eq 5) {
            Write-Host "  ✓ LAN Manager already configured to send NTLMv2 responses only" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
        Write-Host "  ✓ LAN Manager configured to send NTLMv2 responses only" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring NTLM settings: $_" -ForegroundColor Red
    }
}

function Disable-IISDirectoryBrowsing {
    Write-Host "Checking IIS Directory Browsing..." -ForegroundColor Cyan
    
    try {
        # Check if IIS is installed
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        
        if (-not $iisFeature -or $iisFeature.InstallState -ne 'Installed') {
            Write-Host "  ℹ IIS not installed, skipping" -ForegroundColor Gray
            return
        }
        
        # Check if WebAdministration module is available
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            Write-Host "  ⚠ WebAdministration module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $currentValue = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath 'IIS:\' -ErrorAction SilentlyContinue
        
        if ($currentValue.Value -eq $false) {
            Write-Host "  ✓ IIS Directory Browsing already disabled" -ForegroundColor Green
            return
        }
        
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath 'IIS:\' -ErrorAction Stop
        Write-Host "  ✓ IIS Directory Browsing disabled" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error disabling IIS Directory Browsing: $_" -ForegroundColor Red
    }
}

function Enable-IISHTTPS {
    Write-Host "Checking IIS HTTPS configuration..." -ForegroundColor Cyan
    
    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        
        if (-not $iisFeature -or $iisFeature.InstallState -ne 'Installed') {
            Write-Host "  ℹ IIS not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            Write-Host "  ⚠ WebAdministration module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $httpsBinding = Get-WebBinding -Protocol https -ErrorAction SilentlyContinue
        
        if ($httpsBinding) {
            Write-Host "  ✓ IIS HTTPS binding already configured" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ No HTTPS binding found on IIS" -ForegroundColor Yellow
            Write-Host "  ℹ To configure HTTPS:" -ForegroundColor Gray
            Write-Host "    1. Open IIS Manager" -ForegroundColor White
            Write-Host "    2. Select your site > Bindings" -ForegroundColor White
            Write-Host "    3. Add HTTPS binding with SSL certificate" -ForegroundColor White
        }
        
    } catch {
        Write-Host "  ⚠ Error checking IIS HTTPS: $_" -ForegroundColor Red
    }
}

function Disable-IISDetailedErrors {
    Write-Host "Checking IIS detailed error messages..." -ForegroundColor Cyan
    
    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        
        if (-not $iisFeature -or $iisFeature.InstallState -ne 'Installed') {
            Write-Host "  ℹ IIS not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            Write-Host "  ⚠ WebAdministration module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $currentValue = Get-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath 'IIS:\' -ErrorAction SilentlyContinue
        
        if ($currentValue.Value -eq 'DetailedLocalOnly' -or $currentValue.Value -eq 'Custom') {
            Write-Host "  ✓ IIS detailed errors already configured to not appear remotely" -ForegroundColor Green
            return
        }
        
        Set-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -Value 'DetailedLocalOnly' -PSPath 'IIS:\' -ErrorAction Stop
        Write-Host "  ✓ IIS configured to not show detailed errors remotely" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring IIS error messages: $_" -ForegroundColor Red
    }
}

function Remove-IISXPoweredByHeader {
    Write-Host "Checking IIS X-Powered-By header..." -ForegroundColor Cyan
    
    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        
        if (-not $iisFeature -or $iisFeature.InstallState -ne 'Installed') {
            Write-Host "  ℹ IIS not installed, skipping" -ForegroundColor Gray
            return
        }
        
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            Write-Host "  ⚠ WebAdministration module not available" -ForegroundColor Yellow
            return
        }
        
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        
        $header = Get-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name . -PSPath 'IIS:\' -ErrorAction SilentlyContinue |
                  Where-Object { $_.name -eq 'X-Powered-By' }
        
        if (-not $header) {
            Write-Host "  ✓ X-Powered-By header already removed from IIS" -ForegroundColor Green
            return
        }
        
        Remove-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name . -AtElement @{name='X-Powered-By'} -PSPath 'IIS:\' -ErrorAction Stop
        Write-Host "  ✓ X-Powered-By header removed from IIS" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error removing X-Powered-By header: $_" -ForegroundColor Red
    }
}

function Set-ChromeTLSVersion {
    Write-Host "Checking Chrome TLS version requirement..." -ForegroundColor Cyan
    
    try {
        $chromeInstalled = Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe"
        
        if (-not $chromeInstalled) {
            $chromeInstalled = Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        }
        
        if (-not $chromeInstalled) {
            Write-Host "  ℹ Chrome not installed, skipping" -ForegroundColor Gray
            return
        }
        
        $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        if (-not (Test-Path $chromePath)) {
            New-Item -Path $chromePath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $chromePath -Name "SSLVersionMin" -ErrorAction SilentlyContinue).SSLVersionMin
        
        if ($currentValue -eq "tls1.2") {
            Write-Host "  ✓ Chrome already requires at least TLS v1.2" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $chromePath -Name "SSLVersionMin" -Value "tls1.2" -Type String -Force
        Write-Host "  ✓ Chrome configured to require at least TLS v1.2" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring Chrome TLS version: $_" -ForegroundColor Red
    }
}

function Set-BrowserTLSVersion {
    Write-Host "Checking browser TLS version requirements..." -ForegroundColor Cyan
    
    try {
        $changes = @()
        
        # Configure Chrome
        $chromeInstalled = (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") -or 
                          (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
        
        if ($chromeInstalled) {
            $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
            if (-not (Test-Path $chromePath)) {
                New-Item -Path $chromePath -Force | Out-Null
            }
            
            $currentValue = (Get-ItemProperty -Path $chromePath -Name "SSLVersionMin" -ErrorAction SilentlyContinue).SSLVersionMin
            
            if ($currentValue -ne "tls1.2") {
                Set-ItemProperty -Path $chromePath -Name "SSLVersionMin" -Value "tls1.2" -Type String -Force
                $changes += "Chrome"
            }
        }
        
        # Configure Firefox
        $firefoxInstalled = Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe"
        
        if ($firefoxInstalled) {
            $firefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
            if (-not (Test-Path $firefoxPath)) {
                New-Item -Path $firefoxPath -Force | Out-Null
            }
            
            $securityPath = "$firefoxPath\security"
            if (-not (Test-Path $securityPath)) {
                New-Item -Path $securityPath -Force | Out-Null
            }
            
            $currentValue = (Get-ItemProperty -Path $securityPath -Name "tls.version.min" -ErrorAction SilentlyContinue)."tls.version.min"
            
            if ($currentValue -ne 3) {
                Set-ItemProperty -Path $securityPath -Name "tls.version.min" -Value 3 -Type DWord -Force
                $changes += "Firefox"
            }
        }
        
        # Configure Edge
        $edgeInstalled = (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") -or
                        (Test-Path "C:\Program Files\Microsoft\Edge\Application\msedge.exe")
        
        if ($edgeInstalled) {
            $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
            if (-not (Test-Path $edgePath)) {
                New-Item -Path $edgePath -Force | Out-Null
            }
            
            $currentValue = (Get-ItemProperty -Path $edgePath -Name "SSLVersionMin" -ErrorAction SilentlyContinue).SSLVersionMin
            
            if ($currentValue -ne "tls1.2") {
                Set-ItemProperty -Path $edgePath -Name "SSLVersionMin" -Value "tls1.2" -Type String -Force
                $changes += "Edge"
            }
        }
        
        if ($changes.Count -eq 0) {
            if ($chromeInstalled -or $firefoxInstalled -or $edgeInstalled) {
                Write-Host "  ✓ All installed browsers already require TLS 1.2+" -ForegroundColor Green
            } else {
                Write-Host "  ℹ No supported browsers found installed" -ForegroundColor Gray
            }
        } else {
            Write-Host "  ✓ Configured TLS 1.2+ requirement for: $($changes -join ', ')" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error configuring browser TLS versions: $_" -ForegroundColor Red
    }
}

function Disable-MySQLRootRemoteLogin {
    Write-Host "Checking MySQL root remote login..." -ForegroundColor Cyan
    
    try {
        $mysqlService = Get-Service -Name MySQL* -ErrorAction SilentlyContinue
        
        if (-not $mysqlService) {
            Write-Host "  ℹ MySQL service not found, skipping" -ForegroundColor Gray
            return
        }
        
        Write-Host "  ⚠ MySQL service detected" -ForegroundColor Yellow
        Write-Host "  ℹ To disable root remote login:" -ForegroundColor Gray
        Write-Host "    1. Connect to MySQL: mysql -u root -p" -ForegroundColor White
        Write-Host "    2. Run: DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" -ForegroundColor White
        Write-Host "    3. Run: FLUSH PRIVILEGES;" -ForegroundColor White
        Write-Host "  ℹ Or use MySQL Workbench to manage user privileges" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error checking MySQL configuration: $_" -ForegroundColor Red
    }
}

function Disable-RDPAdminControl {
    Write-Host "Checking RDP administrative session control..." -ForegroundColor Cyan
    
    try {
        $tsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        
        if (-not (Test-Path $tsPath)) {
            New-Item -Path $tsPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $tsPath -Name "fDisableCdm" -ErrorAction SilentlyContinue).fDisableCdm
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ Administrators already cannot control RDP sessions" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $tsPath -Name "fDisableCdm" -Value 1 -Type DWord -Force
        Write-Host "  ✓ Administrators now cannot control active RDP sessions" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring RDP admin control: $_" -ForegroundColor Red
    }
}

function Test-7ZipVersion {
    Write-Host "Checking 7-Zip version..." -ForegroundColor Cyan
    
    try {
        $7zipPath = "C:\Program Files\7-Zip\7z.exe"
        $7zipPath32 = "C:\Program Files (x86)\7-Zip\7z.exe"
        
        $path = $null
        if (Test-Path $7zipPath) {
            $path = $7zipPath
        } elseif (Test-Path $7zipPath32) {
            $path = $7zipPath32
        }
        
        if (-not $path) {
            Write-Host "  ℹ 7-Zip not installed" -ForegroundColor Gray
            return
        }
        
        $version = (Get-Item $path).VersionInfo.FileVersion
        Write-Host "  ℹ 7-Zip version installed: $version" -ForegroundColor Yellow
        Write-Host "  ℹ Check if this is the latest version at: https://www.7-zip.org/" -ForegroundColor Gray
        Write-Host "  ℹ Update if newer version available" -ForegroundColor Gray
        
    } catch {
        Write-Host "  ⚠ Error checking 7-Zip version: $_" -ForegroundColor Red
    }
}

function Disable-PrinterDriverInstallation {
    Write-Host "Checking printer driver installation restriction..." -ForegroundColor Cyan
    
    try {
        $printerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        
        if (-not (Test-Path $printerPath)) {
            New-Item -Path $printerPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $printerPath -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue).RestrictDriverInstallationToAdministrators
        
        if ($currentValue -eq 1) {
            Write-Host "  ✓ Printer driver installation already restricted to administrators" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $printerPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -Force
        Write-Host "  ✓ Print drivers can no longer be installed over HTTP" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error restricting printer driver installation: $_" -ForegroundColor Red
    }
}

function Enable-SensitivePrivilegeAuditing {
    Write-Host "Checking audit usage of sensitive privileges..." -ForegroundColor Cyan
    
    try {
        $output = auditpol /get /subcategory:"Sensitive Privilege Use" 2>&1
        
        if ($output -match "Success") {
            Write-Host "  ✓ Sensitive privilege usage auditing already enabled" -ForegroundColor Green
            return
        }
        
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable | Out-Null
        Write-Host "  ✓ Audit usage of sensitive privileges enabled (Success)" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring sensitive privilege auditing: $_" -ForegroundColor Red
    }
}

function Disable-ElevatedInstallApplications {
    Write-Host "Checking elevated application installation setting..." -ForegroundColor Cyan
    
    try {
        $installerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        
        if (-not (Test-Path $installerPath)) {
            New-Item -Path $installerPath -Force | Out-Null
        }
        
        $currentValue = (Get-ItemProperty -Path $installerPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
        
        if ($currentValue -eq 0 -or $null -eq $currentValue) {
            Write-Host "  ✓ Applications no longer install with elevated permissions" -ForegroundColor Green
            return
        }
        
        Set-ItemProperty -Path $installerPath -Name "AlwaysInstallElevated" -Value 0 -Type DWord -Force
        
        # Also check user policy
        $userInstallerPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        if (Test-Path $userInstallerPath) {
            Set-ItemProperty -Path $userInstallerPath -Name "AlwaysInstallElevated" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "  ✓ Applications no longer install with elevated permissions" -ForegroundColor Green
        
    } catch {
        Write-Host "  ⚠ Error configuring application installation: $_" -ForegroundColor Red
    }
}

function Remove-ScheduledTaskScripts {
    Write-Host "Checking for suspicious scheduled task scripts..." -ForegroundColor Cyan
    
    try {
        $suspiciousTasks = @()
        $allTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
        
        foreach ($task in $allTasks) {
            # Check if task runs PowerShell scripts
            if ($task.Actions.Execute -match 'powershell' -and 
                $task.Actions.Arguments -match '\.ps1') {
                
                # Skip if it's this hardening script
                if ($task.Actions.Arguments -notmatch 'hardening|security|cyberpatriot') {
                    $suspiciousTasks += [PSCustomObject]@{
                        Name = $task.TaskName
                        Path = $task.TaskPath
                        Action = $task.Actions.Execute
                        Arguments = $task.Actions.Arguments
                    }
                }
            }
        }
        
        if ($suspiciousTasks.Count -gt 0) {
            Write-Host "  ⚠ Found $($suspiciousTasks.Count) scheduled task(s) running PowerShell scripts:" -ForegroundColor Yellow
            $suspiciousTasks | Format-Table -AutoSize -Wrap
            
            Write-Host "  ℹ Review these tasks - remove if they are unauthorized" -ForegroundColor Yellow
            $openTasks = Read-Host "Open Task Scheduler to review? (Y/N)"
            if ($openTasks -match '^[Yy]') {
                taskschd.msc
            }
        } else {
            Write-Host "  ✓ No suspicious PowerShell scheduled tasks found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking scheduled tasks: $_" -ForegroundColor Red
    }
}

function Remove-GroupPolicyStartupScripts {
    Write-Host "Checking Group Policy startup scripts..." -ForegroundColor Cyan
    
    try {
        Write-Host "  ℹ To check Group Policy startup/shutdown scripts:" -ForegroundColor Gray
        Write-Host "    1. Run: gpedit.msc" -ForegroundColor White
        Write-Host "    2. Navigate to: Computer Configuration > Windows Settings > Scripts" -ForegroundColor White
        Write-Host "    3. Check Startup and Shutdown scripts" -ForegroundColor White
        Write-Host "    4. Remove any unauthorized PowerShell scripts" -ForegroundColor White
        
    } catch {
        Write-Host "  ⚠ Error checking Group Policy scripts: $_" -ForegroundColor Red
    }
}

function Remove-PHPBackdoors {
    Write-Host "Checking for PHP backdoors..." -ForegroundColor Cyan
    
    try {
        $webRoots = @(
            "C:\inetpub\wwwroot",
            "C:\xampp\htdocs",
            "C:\wamp\www",
            "C:\wamp64\www"
        )
        
        $suspiciousFiles = @()
        
        foreach ($root in $webRoots) {
            if (Test-Path $root) {
                $phpFiles = Get-ChildItem -Path $root -Filter *.php -Recurse -ErrorAction SilentlyContinue
                
                foreach ($file in $phpFiles) {
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                    
                    # Check for common backdoor patterns
                    if ($content -match 'eval\(|base64_decode\(|system\(|exec\(|shell_exec\(|passthru\(|proc_open\(|popen\(') {
                        $suspiciousFiles += $file.FullName
                    }
                }
            }
        }
        
        if ($suspiciousFiles.Count -gt 0) {
            Write-Host "  ⚠ Found $($suspiciousFiles.Count) suspicious PHP file(s):" -ForegroundColor Yellow
            $suspiciousFiles | ForEach-Object { Write-Host "    - $_" -ForegroundColor White }
            
            Write-Host "  ℹ Review these files for backdoors and remove if malicious" -ForegroundColor Yellow
        } else {
            Write-Host "  ✓ No obvious PHP backdoors found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking for PHP backdoors: $_" -ForegroundColor Red
    }
}

function Test-StickyKeysBackdoor {
    Write-Host "Checking for Sticky Keys backdoor..." -ForegroundColor Cyan
    
    try {
        $stickyKeysPath = "C:\Windows\System32\sethc.exe"
        $stickyKeysBackup = "C:\Windows\System32\sethc.exe.bak"
        
        if (Test-Path $stickyKeysPath) {
            $hash = (Get-FileHash -Path $stickyKeysPath -Algorithm SHA256).Hash
            
            # Check if sethc.exe is actually cmd.exe (common backdoor)
            $cmdHash = (Get-FileHash -Path "C:\Windows\System32\cmd.exe" -Algorithm SHA256).Hash
            
            if ($hash -eq $cmdHash) {
                Write-Host "  ⚠ Sticky Keys backdoor detected! sethc.exe is cmd.exe" -ForegroundColor Red
                
                if (Test-Path $stickyKeysBackup) {
                    Copy-Item -Path $stickyKeysBackup -Destination $stickyKeysPath -Force
                    Write-Host "  ✓ Restored sethc.exe from backup" -ForegroundColor Green
                } else {
                    Write-Host "  ⚠ No backup found - manually restore sethc.exe from a clean Windows install" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  ✓ No Sticky Keys backdoor detected" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  ⚠ Error checking Sticky Keys backdoor: $_" -ForegroundColor Red
    }
}

function Test-AccessibilityBackdoors {
    Write-Host "Checking for accessibility backdoors..." -ForegroundColor Cyan
    
    try {
        $accessibilityFiles = @(
            "C:\Windows\System32\sethc.exe",
            "C:\Windows\System32\utilman.exe",
            "C:\Windows\System32\osk.exe",
            "C:\Windows\System32\narrator.exe",
            "C:\Windows\System32\magnify.exe"
        )
        
        $cmdHash = (Get-FileHash -Path "C:\Windows\System32\cmd.exe" -Algorithm SHA256).Hash
        $explorerHash = (Get-FileHash -Path "C:\Windows\explorer.exe" -Algorithm SHA256).Hash
        
        $backdoors = @()
        
        foreach ($file in $accessibilityFiles) {
            if (Test-Path $file) {
                $hash = (Get-FileHash -Path $file -Algorithm SHA256).Hash
                
                if ($hash -eq $cmdHash -or $hash -eq $explorerHash) {
                    $backdoors += $file
                }
            }
        }
        
        if ($backdoors.Count -gt 0) {
            Write-Host "  ⚠ Found $($backdoors.Count) accessibility backdoor(s):" -ForegroundColor Red
            $backdoors | ForEach-Object { Write-Host "    - $_" -ForegroundColor White }
            Write-Host "  ⚠ Restore these files from a clean Windows installation" -ForegroundColor Yellow
        } else {
            Write-Host "  ✓ No accessibility backdoors detected" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  ⚠ Error checking accessibility backdoors: $_" -ForegroundColor Red
    }
}

function main {
    Write-Host "Starting Windows 2022 Server Script..." 
    
    Manage-UsersAndGroups
    Is-DomainJoined
    Enable-AllAuditPolicies
    disable_guest_account
    Set-AllLocalPasswords
    firewall_status
    disable_remote_services
    disable_additional_services
    checkUAC
    Clear-UserProfilesSafe
    set_lockout_policy
    secure_password_policy
    enable_critical_services
    Remove-ProhibitedApps
    secure_registry_settings
    stop-DefaultSharedFolders
    Set-UserRightsAssignments
    Set-SecPol
    Set-WindowsUpdate
    Disable-AutoRun
    Set-ScreenSaver
    Disable-IPv6
    Set-EventLogSize
    Find-SuspiciousScheduledTasks
    Test-StartupPrograms
    Disable-UnnecessaryWindowsFeatures
    Set-PowerOptions
    Test-SuspiciousFiles
    Test-HostsFile
    Disable-NetBIOSoverTCP
    Set-DNSClientSecurity
    harden_defender_and_exploit_protection
    enforce_domain_hardening
    Set-WindowsDefender
    Enable-WindowsSmartScreen
    Set-SMBSecurity
    Secure-CAPolicy
    Enable-ADCSDisallowedCertAutoUpdate
    Enable-VBSMandatoryMode
    Set-MachineIdentityIsolation
    Set-BrowserDoNotTrack
    Disable-PowerShell2
    Enable-DefenderASRWebshellRule
    Find-TamperedVBSScripts
    Test-ShareCreationEvents
    Set-AdvancedAuditPolicy
    Disable-AnonymousSAMEnumeration
    Enable-LSAProtection
    Disable-AnonymousLDAPBind
    Disable-KerberosPreAuthBypass
    Test-PasswordExpiration
    Disable-PowerShellRemoting
    Test-DelegationRights
    Disable-SMBCompression
    Enable-SMBEncryption
    Set-DNSSIGRedMitigation
    Test-SuspiciousServices
    Test-ListeningPorts
    Test-ADReplicationRights
    Enable-PowerShellTranscription
    Set-BitLocker
    Set-DHCPAuditLogging
    Set-DHCPServerAuthorization
    Remove-UnauthorizedDHCPServers
    Set-DHCPNameProtection
    Set-DHCPLogPath
    Disable-DNSIPv6Tunneling
    Set-DNSRateLimiting
    Disable-DNSSlaveServer
    Test-KerberosDelegation
    Test-ADDatabasePermissions
    Remove-DangerousPowerShellModules
    Enable-ObjectAccessAuditing
    Set-NTLMv2Only
    Disable-IISDirectoryBrowsing
    Enable-IISHTTPS
    Disable-IISDetailedErrors
    Remove-IISXPoweredByHeader
    Set-ChromeTLSVersion
    Set-BrowserTLSVersion
    Disable-MySQLRootRemoteLogin
    Disable-RDPAdminControl
    Test-7ZipVersion
    Disable-PrinterDriverInstallation
    Enable-SensitivePrivilegeAuditing
    Disable-ElevatedInstallApplications
    Remove-ScheduledTaskScripts
    Remove-GroupPolicyStartupScripts
    Remove-PHPBackdoors
    Test-StickyKeysBackdoor
    Test-AccessibilityBackdoors
}
main
