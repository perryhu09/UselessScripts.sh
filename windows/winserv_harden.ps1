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
                    Get-ADUser -Filter * | Select-Object SamAccountName, Enabled | Format-Table
                } else {
                    Write-Host "`n--- Local Users ---"
                    Get-LocalUser | Format-Table Name, Enabled
                }
                
            }

            2 {
                $userName = Read-Host "Enter new username"
                $password = Read-Host "Enter password" -AsSecureString

                if ($domainJoined) {
                    New-ADUser -Name $userName -SamAccountName $userName -AccountPassword $password -Enabled $true
                    Write-Host "✅ Domain user '$userName' created."
                } else {
                    New-LocalUser -Name $userName -Password $password -FullName $userName -Description "Created by hardening script"
                    Write-Host "✅ Local user '$userName' created."
                }
                
            }

            3 {
                $userName = Read-Host "Enter username to remove"
                if ($domainJoined) {
                    Remove-ADUser -Identity $userName -Confirm:$false
                } else {
                    Remove-LocalUser -Name $userName
                }
                Write-Host "User '$userName' removed."
                
            }

            4 {
                if ($domainJoined) {
                    Write-Host "`n--- Domain Groups ---"
                    Get-ADGroup -Filter * | Select-Object Name, GroupScope | Format-Table
                } else {
                    Write-Host "`n--- Local Groups ---"
                    Get-LocalGroup | Format-Table Name
                }
                
            }

            5 {
                $groupName = Read-Host "Enter new group name"
                if ($domainJoined) {
                    $scopeChoice = Read-Host "Enter group scope (Global / Universal / DomainLocal, default = Global)"
                    if (-not $scopeChoice) { $scopeChoice = "Global" }
                    New-ADGroup -Name $groupName -GroupScope $scopeChoice -GroupCategory Security
                    Write-Host "Domain group '$groupName' ($scopeChoice) created."
                } else {
                    New-LocalGroup -Name $groupName -Description "Created by hardening script"
                    Write-Host "Local group '$groupName' created."
                }
                
            }

            6 {
                $groupName = Read-Host "Enter group name to remove"
                if ($domainJoined) {
                    Remove-ADGroup -Identity $groupName -Confirm:$false
                } else {
                    Remove-LocalGroup -Name $groupName
                }
                Write-Host "Group '$groupName' removed."
                
            }

            7 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                if ($domainJoined) {
                    Add-ADGroupMember -Identity $groupName -Members $userName
                } else {
                    Add-LocalGroupMember -Group $groupName -Member $userName
                }
                Write-Host "Added '$userName' to '$groupName'."
                
            }

            8 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                if ($domainJoined) {
                    Remove-ADGroupMember -Identity $groupName -Members $userName -Confirm:$false
                } else {
                    Remove-LocalGroupMember -Group $groupName -Member $userName
                }
                Write-Host "Removed '$userName' from '$groupName'."
                
            }

            10 {
                # Manage a single group: add/remove multiple users separated by commas
                $groupName = Read-Host "Enter the target group name"
                $action = Read-Host "Enter action ('add' or 'remove')"

                if ($action -notin @('add','remove')) {
                    Write-Host "Invalid action. Use 'add' or 'remove'."
                    
                    break
                }

                $usersInput = Read-Host "Enter usernames separated by commas"
                $users = $usersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

                if ($users.Count -eq 0) {
                    Write-Host "No valid usernames provided."
                    
                    break
                }

                try {
                    if ($domainJoined) {
                        if ($action -eq 'add') {
                            Add-ADGroupMember -Identity $groupName -Members $users
                            Write-Host "Added users to domain group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-ADGroupMember -Identity $groupName -Members $users -Confirm:$false
                            Write-Host "Removed users from domain group '$groupName': $($users -join ', ')"
                        }
                    } else {
                        if ($action -eq 'add') {
                            Add-LocalGroupMember -Group $groupName -Member $users
                            Write-Host "Added users to local group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-LocalGroupMember -Group $groupName -Member $users -Confirm:$false
                            Write-Host "Removed users from local group '$groupName': $($users -join ', ')"
                        }
                    }
                } catch {
                    Write-Host "Error processing group membership changes:`n$_"
                }
                
            }

            9 {
                Write-Host "Exiting user management..."
                break; 
            }

            Default {
                Write-Host "Invalid selection. Try again."
                
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

function remove_third_party_apps {

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

    foreach ($friendlyName in $apps.Keys) {
        $filter = "Name = '$friendlyName'"
        try {
            $products = Get-WmiObject -Class Win32_Product -Filter $filter -ErrorAction SilentlyContinue
            if (-not $products) { continue }

            foreach ($product in $products) {
                try {
                    $result = $product.Uninstall()
                    if ($result.ReturnValue -eq 0) {
                        Write-Host "Uninstalled: $($product.Name)"
                    } else {
                        Write-Host "Uninstall failed ($($result.ReturnValue)): $($product.Name)"
                    }
                } catch {
                    Write-Host "Uninstall error: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Host "Query error: $($_.Exception.Message)"
        }
    }
    
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
    remove_third_party_apps
}
main