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
        Write-Host "=========================================="
        Write-Host "  Windows Server 2022 User Management Tool"
        Write-Host "=========================================="
        Write-Host ""
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
                Pause
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
                Pause
            }

            3 {
                $userName = Read-Host "Enter username to remove"
                if ($domainJoined) {
                    Remove-ADUser -Identity $userName -Confirm:$false
                } else {
                    Remove-LocalUser -Name $userName
                }
                Write-Host "❌ User '$userName' removed."
                Pause
            }

            4 {
                if ($domainJoined) {
                    Write-Host "`n--- Domain Groups ---"
                    Get-ADGroup -Filter * | Select-Object Name, GroupScope | Format-Table
                } else {
                    Write-Host "`n--- Local Groups ---"
                    Get-LocalGroup | Format-Table Name
                }
                Pause
            }

            5 {
                $groupName = Read-Host "Enter new group name"
                if ($domainJoined) {
                    $scopeChoice = Read-Host "Enter group scope (Global / Universal / DomainLocal, default = Global)"
                    if (-not $scopeChoice) { $scopeChoice = "Global" }
                    New-ADGroup -Name $groupName -GroupScope $scopeChoice -GroupCategory Security
                    Write-Host "✅ Domain group '$groupName' ($scopeChoice) created."
                } else {
                    New-LocalGroup -Name $groupName -Description "Created by hardening script"
                    Write-Host "✅ Local group '$groupName' created."
                }
                Pause
            }

            6 {
                $groupName = Read-Host "Enter group name to remove"
                if ($domainJoined) {
                    Remove-ADGroup -Identity $groupName -Confirm:$false
                } else {
                    Remove-LocalGroup -Name $groupName
                }
                Write-Host "❌ Group '$groupName' removed."
                Pause
            }

            7 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                if ($domainJoined) {
                    Add-ADGroupMember -Identity $groupName -Members $userName
                } else {
                    Add-LocalGroupMember -Group $groupName -Member $userName
                }
                Write-Host "✅ Added '$userName' to '$groupName'."
                Pause
            }

            8 {
                $userName = Read-Host "Enter username"
                $groupName = Read-Host "Enter group name"

                if ($domainJoined) {
                    Remove-ADGroupMember -Identity $groupName -Members $userName -Confirm:$false
                } else {
                    Remove-LocalGroupMember -Group $groupName -Member $userName
                }
                Write-Host "❌ Removed '$userName' from '$groupName'."
                Pause
            }

            10 {
                # Manage a single group: add/remove multiple users separated by commas
                $groupName = Read-Host "Enter the target group name"
                $action = Read-Host "Enter action ('add' or 'remove')"

                if ($action -notin @('add','remove')) {
                    Write-Host "Invalid action. Use 'add' or 'remove'."
                    Pause
                    break
                }

                $usersInput = Read-Host "Enter usernames separated by commas"
                $users = $usersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

                if ($users.Count -eq 0) {
                    Write-Host "No valid usernames provided."
                    Pause
                    break
                }

                try {
                    if ($domainJoined) {
                        if ($action -eq 'add') {
                            Add-ADGroupMember -Identity $groupName -Members $users
                            Write-Host "✅ Added users to domain group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-ADGroupMember -Identity $groupName -Members $users -Confirm:$false
                            Write-Host "❌ Removed users from domain group '$groupName': $($users -join ', ')"
                        }
                    } else {
                        if ($action -eq 'add') {
                            Add-LocalGroupMember -Group $groupName -Member $users
                            Write-Host "✅ Added users to local group '$groupName': $($users -join ', ')"
                        } else {
                            Remove-LocalGroupMember -Group $groupName -Member $users -Confirm:$false
                            Write-Host "❌ Removed users from local group '$groupName': $($users -join ', ')"
                        }
                    }
                } catch {
                    Write-Host "Error processing group membership changes:`n$_"
                }
                Pause
            }

            9 {
                Write-Host "Exiting user management..."
                break; 
            }

            Default {
                Write-Host "Invalid selection. Try again."
                Pause
            }
        }
    } until ($choice -eq "9")
}
Manage-UsersAndGroups