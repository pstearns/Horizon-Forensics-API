<#
.SYNOPSIS
    A PowerShell script providing a GUI to manage Horizon Forensic Holds.

.DESCRIPTION
    This script includes event handlers and functions to:
    - Obtain an access token
    - Put a user on hold
    - Release a user from hold
    - Verify forensic admin roles and groups
    - Verify Archive Datastore
    The script uses Windows Presentation Foundation (WPF) for the graphical user interface.

.NOTES
    Author: Peter Stearns
    Created: 2/01/2025
    Version: 4.1
    Updated: 2/25/2025
#>

Add-Type -AssemblyName 'PresentationFramework'
Add-Type -AssemblyName 'WindowsBase'

# Define the path for the secure input file
$inputFilePath = "$env:APPDATA\HorizonForensicSecureInputs.xml"

# Define the function to get an access token
function Get-AccessToken {
    param (
        [string]$ServerUrl,
        [string]$Username,
        [System.Security.SecureString]$Password,
        [string]$Domain
    )

    try {
        $uri = [System.Uri]::new($ServerUrl)
    } catch {
        throw "Invalid server URL: $ServerUrl"
    }

    if ($Password) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } else {
        throw "Password cannot be null"
    }

    # Construct the API endpoint URL
    $loginUrl = "$ServerUrl/rest/login"

    # Create the request body
    $loginBody = @{
        "username" = $Username
        "password" = $PlainPassword
        "domain" = $Domain
    } | ConvertTo-Json

    # Invoke the login request
    try {
        $loginResponse = Invoke-WebRequest -Uri $loginUrl -Method Post -Body $loginBody -ContentType "application/json"
        # Clean up the plain string from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
        if ($loginResponse.StatusCode -eq 200) {
            # Return the access token
            $accessToken = $loginResponse.Content | ConvertFrom-Json | Select-Object -ExpandProperty access_token
            return $accessToken
        } else {
            Write-Host "Failed to obtain access token. Status code: $($loginResponse.StatusCode)"
            return "Failed to obtain access token. Status code: $($loginResponse.StatusCode)"
        }
    } catch {
        Write-Host "Error occurred during login: $_"
        return "Error occurred during login: $_"
    }
}

# Define the function to get user ID
function Get-UserID {
    param (
        [string]$ServerUrl,
        [String]$AccessToken,
        [string]$User_LoginName
    )

    # Construct the filter JSON object
    $filterObj = @{
        type = "And"
        filters = @(
            @{
                type  = "StartsWith"
                name  = "name"
                value = $User_LoginName
            }
        )
    }

    # Convert the filter object to a JSON string
    $filterJson = $filterObj | ConvertTo-Json -Compress

    # URL encode the JSON string
    $filterEncoded = [System.Net.WebUtility]::UrlEncode($filterJson)

    # Construct the API endpoint URL to get user ID with filter
    $userUrl = "$ServerUrl/rest/external/v1/ad-users-or-groups?filter=$filterEncoded"

    # Invoke the user request
    try {
        $userResponse = Invoke-WebRequest -Uri $userUrl -Method Get -Headers @{
            "Authorization" = "Bearer $AccessToken"
            "Accept" = "application/json"
        }

        if ($userResponse.StatusCode -eq 200) {
            # Parse the user response
            $users = $userResponse.Content | ConvertFrom-Json

            # Find user by login_name (case-insensitive comparison)
            $user = $users | Where-Object { $_.login_name -ieq $User_LoginName }

            if ($user) {
                return $user.id
            } else {
                return "User '$User_LoginName' not found."
            }
        } else {
            return "Failed to retrieve users. Status code: $($userResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during user request: $_"
    } 
}

# Define the function to create ForensicAdminRole
function Create-ForensicAdminRole {
    param (
        [string]$ServerUrl,
        [string]$AccessToken
    )

    # Construct the API endpoint URLs
    $rolesUrl = "$ServerUrl/rest/config/v1/roles"
    $roleName = "Forensic Admin"

    # Check if the role already exists
    try {
        $existingRolesResponse = Invoke-WebRequest -Uri $rolesUrl -Method Get -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }

        if ($existingRolesResponse.StatusCode -eq 200) {
            $existingRoles = $existingRolesResponse.Content | ConvertFrom-Json
            $existingRole = $existingRoles | Where-Object { $_.name -eq $roleName }

            if ($existingRole) {
                return "The role '$roleName' already exists."
            }
        } else {
            return "Failed to retrieve existing roles. Status code: $($existingRolesResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during existing roles request: $_"
    }

    # Create the request body
    $configBody = @{
        "name" = $roleName
        "description" = "Forensic Administrator role."
        "privileges" = @("FORENSICS", "MACHINE_MANAGEMENT")
    } | ConvertTo-Json

    # Invoke the config request to create the role
    try {
        $configResponse = Invoke-WebRequest -Uri $rolesUrl -Method Post -Body $configBody -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        
        if ($configResponse.StatusCode -eq 201) {
            return "Forensic Admin role created successfully."
        } else {
            return "Failed to create Forensic Admin role. Status code: $($configResponse.StatusCode)" + "`nResponse Content: $($configResponse.Content)"
        }
    } catch {
        return "Error occurred during request: $_"
    }
}

# Define the combined function to check AD group role assignment
function Get-ForensicAdminGroups {
    param (
        [string]$ServerUrl,
        [string]$AccessToken,
        [string]$RoleName = "Forensic Admin"
    )

    # Step 1: Get roles
    $rolesUrl = "$ServerUrl/rest/config/v1/roles"

    try {
        $rolesResponse = Invoke-WebRequest -Uri $rolesUrl -Method Get -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Accept" = "application/json"
        }

        if ($rolesResponse.StatusCode -eq 200) {
            # Parse the roles response
            $roles = $rolesResponse.Content | ConvertFrom-Json
            $role = $roles | Where-Object { $_.name -eq $RoleName }

            if ($role) {
                $RoleID = $role.id
            } else {
                return "Role '$RoleName' not found."
            }
        } else {
            return "Failed to retrieve roles. Status code: $($rolesResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during roles request: $_"
    }

    # Step 2: Get ad_user_or_group_id assigned to the role
    $permissionsUrl = "$ServerUrl/rest/config/v1/permissions"

    try {
        $permissionsResponse = Invoke-WebRequest -Uri $permissionsUrl -Method Get -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Accept" = "application/json"
        }

        if ($permissionsResponse.StatusCode -eq 200) {
            # Parse the permissions response
            $permissions = $permissionsResponse.Content | ConvertFrom-Json

            # Extract ad_user_or_group_id assigned to the role
            $assignedGroups = $permissions | Where-Object { $_.role_id -eq $RoleID } | Select-Object -ExpandProperty ad_user_or_group_id

            if (-not $assignedGroups) {
                return "No AD User or Group IDs assigned to the role."
            }
        } else {
            return "Failed to retrieve permissions. Status code: $($permissionsResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during permissions request: $_"
    }

    # Step 3: Get AD group names from the ad_user_or_group_id
    $adGroupsUrl = "$ServerUrl/rest/external/v1/ad-users-or-groups"
    $groupNames = @()

    foreach ($groupId in $assignedGroups) {
        try {
            $detailsUrl = "$adGroupsUrl/$groupId"
            $detailsResponse = Invoke-WebRequest -Uri $detailsUrl -Method Get -Headers @{
                "Authorization" = "Bearer $accessToken"
                "Content-Type" = "application/json"
            }

            if ($detailsResponse.StatusCode -eq 200) {
                $details = $detailsResponse.Content | ConvertFrom-Json
                if ($details.group) {
                    $groupNames += $details.display_name
                }
            } else {
                $groupNames += "Failed to retrieve name for ID: $groupId"
            }
        } catch {
            $groupNames += "Error occurred during group details request for ID: $groupId"
        }
    }

    if ($groupNames) {
        return $groupNames
    } else {
        return "No AD group names found for the assigned IDs."
    }
}

# Define the function to put a user on hold
function Put-UserOnHold {
    param (
        [string]$ServerUrl,
        [string]$AccessToken,
        [string]$UserName,
        [string]$UserSID
    )

    # Construct the API endpoint URL for putting user on hold
    $holdUrl = "$ServerUrl/rest/external/v2/ad-users-or-groups/action/hold"

    # Create the request body as a JSON array containing the user SID
    $holdBody = "[`"$UserSID`"]"

    # Invoke the request to put user on hold
    try {
        $holdResponse = Invoke-RestMethod -Uri $holdUrl -Method Post -Body $holdBody -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
            "Accept" = "*/*"
        }

        if ($holdResponse.status_code -eq 200) {
            return "User '$UserName' has been successfully put on hold."
        } elseif ($holdResponse.status_code -eq 409) {
            return "User '$UserName' is already on hold."
        } else {
            return "Failed to put '$UserName' on hold $UserSID. Response: $($holdResponse)"
        }
    } catch {
        return "Error occurred during hold request: $_"
    }
}

# Define the function to release a user on hold
function Release-UserFromHold {
    param (
        [string]$ServerUrl,
        [string]$AccessToken,
        [string]$UserName,
        [string]$UserSID
    )

    # Construct the API endpoint URL for releasing user from hold
    $releaseHoldUrl = "$ServerUrl/rest/external/v2/ad-users-or-groups/action/release-hold"

    # Create the request body as a JSON array containing the user SID
    $releaseBody = "[`"$UserSID`"]"

    # Invoke the request to release user from hold
    try {
        $releaseResponse = Invoke-RestMethod -Uri $releaseHoldUrl -Method Post -Body $releaseBody -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
            "Accept" = "*/*"
        }

        if ($releaseResponse.status_code -eq 200) {
            return "User '$UserName' has been successfully released from hold."
        } elseif ($releaseResponse.status_code -eq 400) {
            if ($releaseResponse.errors[0].error_key -eq "external.ad-user-or-group.not.held.error") {
                return "User '$UserName' is not on hold."
            }
            return "Failed to release user from hold. Error: $($releaseResponse.errors[0].error_message)"
        } elseif ($releaseResponse.status_code -eq 409) {
            return "User '$UserName' is not on hold."
        } else {
            return "Failed to release '$UserName' from hold. Response: $($releaseResponse)"
        }
    } catch {
        return "Error occurred during release hold request: $_"
    }
}

# Define the function to list held users and resolve names
function Get-HeldUsers {
    param (
        [string]$ServerUrl,
        [string]$AccessToken
    )

    # Construct the API endpoint URL for held users
    $heldUsersUrl = "$ServerUrl/rest/external/v1/ad-users-or-groups/held-users-or-groups"

    # Invoke the held users request
    try {
        $heldUsersResponse = Invoke-WebRequest -Uri $heldUsersUrl -Method Get -Headers @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        
        if ($heldUsersResponse.StatusCode -eq 200) {
            # Parse the held users response content
            $heldUsers = $heldUsersResponse.Content | ConvertFrom-Json

            # Initialize an array to hold the names
            $names = @()

            # For each held user, fetch the name based on ad_user_or_group_id
            foreach ($user in $heldUsers) {
                # Use ad_user_or_group_id to fetch the user or group details
                $detailsUrl = "$ServerUrl/rest/external/v1/ad-users-or-groups/$($user.ad_user_or_group_id)"
                $detailsResponse = Invoke-WebRequest -Uri $detailsUrl -Method Get -Headers @{
                    "Authorization" = "Bearer $accessToken"
                    "Content-Type" = "application/json"
                }

                if ($detailsResponse.StatusCode -eq 200) {
                    $details = $detailsResponse.Content | ConvertFrom-Json
                    $names += $details.display_name
                } else {
                    $names += "Failed to retrieve name for ID: $($user.ad_user_or_group_id)"
                }
            }

            # Return the list of names
            return $names
        } else {
            return "Failed to retrieve held users. Status code: $($heldUsersResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during held users request: $_"
    }
}

# Define the function to list held machines
function Get-HeldMachines {
    param (
        [string]$ServerUrl,
        [string]$AccessToken
    )

    # Construct the API endpoint URL for held machines
    $heldMachinesUrl = "$ServerUrl/rest/inventory/v3/machines"

    # Invoke the held machines request
    try {
        $heldMachinesResponse = Invoke-WebRequest -Uri $heldMachinesUrl -Method Get -Headers @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        if ($heldMachinesResponse.StatusCode -eq 200) {
            # Parse the response content
            $machines = $heldMachinesResponse.Content | ConvertFrom-Json
            
            # Ensure we're correctly identifying held machines
            $heldMachines = $machines | Where-Object { $_.held_machine -eq "true" }

            # Retrieve and translate user IDs to display names
            $heldMachinesInfo = @()
            foreach ($machine in $heldMachines) {
                $userId = $machine.user_ids
                $userName = ""
                
                if ($userId) {
                    # Construct the API endpoint URL for user info
                    $userInfoUrl = "$ServerUrl/rest/external/v1/ad-users-or-groups/$userId"
                    
                    # Invoke the user info request
                    $userInfoResponse = Invoke-WebRequest -Uri $userInfoUrl -Method Get -Headers @{
                        "Authorization" = "Bearer $AccessToken"
                        "Content-Type" = "application/json"
                    }

                    if ($userInfoResponse.StatusCode -eq 200) {
                        # Parse the user info content
                        $userInfo = $userInfoResponse.Content | ConvertFrom-Json
                        $userName = $userInfo.display_name
                    } else {
                        $userName = "Failed to retrieve display name. Status code: $($userInfoResponse.StatusCode)"
                    }
                }

                # Add the machine name and user display name to the output
                $heldMachinesInfo += [PSCustomObject]@{
                    MachineName = $machine.name
                    MachineID   = $machine.id
                    UserName    = $userName
                }
            }
            return $heldMachinesInfo
        } else {
            return "Failed to retrieve machines. Status code: $($heldMachinesResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during held machines request: $_"
    }
}

# Define the function to archive machines across multiple pods with existence and state check
function Set-MachinetoArchive {
    param (
        [string]$MachineID
    )

    $results = @()
    $machineFound = $false

    foreach ($pod in $global:accessTokens.Keys) {
        if ($machineFound) {
            break
        }
        $ServerUrl = $global:accessTokens[$pod].URL
        $AccessToken = $global:accessTokens[$pod].Token

        # Construct the API endpoint URLs
        $checkMachineUrl = "$ServerUrl/rest/inventory/v1/machines/$MachineID"
        $archiveMachineUrl = "$ServerUrl/rest/inventory/v1/machines/action/archive"

        # Check if the machine exists and its state
        try {
            $checkMachineResponse = Invoke-WebRequest -Uri $checkMachineUrl -Method Get -Headers @{
                "Authorization" = "Bearer $AccessToken"
                "Content-Type" = "application/json"
            }

            if ($checkMachineResponse.StatusCode -eq 200) {
                $machineInfo = $checkMachineResponse.Content | ConvertFrom-Json
                $machineFound = $true

                switch ($machineInfo.state) {
                    "AVAILABLE" {
                        # Construct the request body
                        $requestBody = "[`"$MachineID`"]"

                        # Invoke the archive machine request
                        try {
                            $archiveMachineResponse = Invoke-WebRequest -Uri $archiveMachineUrl -Method Post -Headers @{
                                "Authorization" = "Bearer $AccessToken"
                                "Content-Type" = "application/json"
                            } -Body $requestBody

                            if ($archiveMachineResponse.StatusCode -eq 200) {
                                $results += "${pod}: Machine ${MachineID} successfully archived."
                            } else {
                                $results += "${pod}: Failed to archive machine ${MachineID}. Status code: $($archiveMachineResponse.StatusCode)"
                            }
                        } catch {
                            $results += "${pod}: Error occurred during archive machine request for ${MachineID}: $_"
                        }
                    }
                    "DISCONNECTED" {
                        # Construct the request body
                        $requestBody = "[`"$MachineID`"]"

                        # Invoke the archive machine request
                        try {
                            $archiveMachineResponse = Invoke-WebRequest -Uri $archiveMachineUrl -Method Post -Headers @{
                                "Authorization" = "Bearer $AccessToken"
                                "Content-Type" = "application/json"
                            } -Body $requestBody

                            if ($archiveMachineResponse.StatusCode -eq 200) {
                                $results += "${pod}: Machine ${MachineID} successfully archived."
                            } else {
                                $results += "${pod}: Failed to archive machine ${MachineID}. Status code: $($archiveMachineResponse.StatusCode)"
                            }
                        } catch {
                            $results += "${pod}: Error occurred during archive machine request for ${MachineID}: $_"
                        }
                    }
                    "CONNECTED" {
                        $results += "${pod}: Machine ${MachineID} is currently connected. Archive will be scheduled when user logs off."
                    }
                    default {
                        $results += "${pod}: Machine ${MachineID} cannot be archived because its state is $($machineInfo.state)."
                    }
                }
            } elseif ($checkMachineResponse.StatusCode -eq 404) {
                continue
            } else {
                $results += "${pod}: Unexpected error. Status code: $($checkMachineResponse.StatusCode)"
            }
        } catch {
            if ($_.Exception.Response.StatusCode -ne 404) {
                $results += "${pod}: Error occurred during machine existence check for ${MachineID}: $_"
            }
        }
    }

    if (-not $machineFound) {
        $results += "Machine ${MachineID} was not found in any pod."
    }

    return $results -join "`n"
}

# Define the function to to set archive datastore for archival
function Set-ArchiveDatastore {
    param (
        [string]$ServerUrl,
        [string]$AccessToken
    )

    # Helper function to make API calls
    function Invoke-HorizonApi {
        param (
            [string]$Uri
        )
        return Invoke-RestMethod -Uri $Uri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Get
    }

    try {
        # Initialize the DatastoreID variable
        $DatastoreID = $null  

        # Get virtual centers
        $virtualCenters = Invoke-HorizonApi "$ServerUrl/rest/config/v1/virtual-centers"
        foreach ($vc in $virtualCenters) {
            # Get datacenters
            $datacenters = Invoke-HorizonApi "$ServerUrl/rest/external/v1/datacenters?vcenter_id=$($vc.id)"
            foreach ($dc in $datacenters) {
                # Get hosts or clusters
                $hostsOrClusters = Invoke-HorizonApi "$ServerUrl/rest/external/v1/hosts-or-clusters?vcenter_id=$($vc.id)&datacenter_id=$($dc.id)"
                foreach ($hc in $hostsOrClusters) {
                    # Get datastores
                    $datastores = Invoke-HorizonApi "$ServerUrl/rest/external/v1/datastores?vcenter_id=$($vc.id)&host_or_cluster_id=$($hc.id)"
                    foreach ($ds in $datastores) {
                        # Check if the datastore name is "archive"
                        if ($ds.name -eq "archive") {
                            $DatastoreID = $ds.id
                        }
                    }
                }
            }
        }

        if (-not $DatastoreID) {
            return "Datastore named 'archive' not found."
        }

        # Construct the API endpoint URL
        $archiveDatastoreUrl = "$ServerUrl/rest/config/v1/virtual-centers/$($vc.id)/action/mark-datastores-for-archival?host_or_cluster_id=$($hc.id)"

        # Construct the request body
        $requestBody = "[`"$DatastoreID`"]"

        # Invoke the archive datastore request
        $archiveDatastoreResponse = Invoke-WebRequest -Uri $archiveDatastoreUrl -Method Post -Headers @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        } -Body $requestBody

        if ($archiveDatastoreResponse.StatusCode -eq 200) {
            return "Archive Datastore successfully marked as archival."
        } else {
            return "Failed to archive the datastore. Status code: $($archiveDatastoreResponse.StatusCode)"
        }
    } catch {
        return "Error occurred during archive datastore request: $_"
    }
}

# Define the function GetvCenterInfo
function Get-HorizonvCenterInfo {
    param (
        [string]$ServerUrl,
        [string]$AccessToken
    )

    # Helper function to make API calls
    function Invoke-HorizonApi {
        param (
            [string]$Uri
        )
        return Invoke-RestMethod -Uri $Uri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Get
    }

    # Create a list to hold the information
    $result = @()

    # Get virtual centers
    $virtualCenters = Invoke-HorizonApi "$ServerUrl/rest/config/v1/virtual-centers"
    foreach ($vc in $virtualCenters) {
        $virtualCenterId = $vc.id
        $virtualCenterName = $vc.server_name

        # Get datacenters
        $datacenters = Invoke-HorizonApi "$ServerUrl/rest/external/v1/datacenters?vcenter_id=$virtualCenterId"
        foreach ($dc in $datacenters) {
            $datacenterId = $dc.id
            $datacenterName = $dc.name

            # Get hosts or clusters
            $hostsOrClusters = Invoke-HorizonApi "$ServerUrl/rest/external/v1/hosts-or-clusters?vcenter_id=$virtualCenterId&datacenter_id=$datacenterId"
            foreach ($hc in $hostsOrClusters) {
                $hostOrClusterId = $hc.id
                $hostOrClusterName = $hc.details.name

                # Get datastores
                $datastores = Invoke-HorizonApi "$ServerUrl/rest/external/v1/datastores?vcenter_id=$virtualCenterId&host_or_cluster_id=$hostOrClusterId"
                foreach ($ds in $datastores) {
                    $datastoreName = $ds.name
                    $datastoreId = $ds.id

                    # Collect the data in an object
                    $dataObject = [PSCustomObject]@{
                        DatastoreName     = $datastoreName
                        DatastoreID       = $datastoreId
                        HostOrClusterName = $hostOrClusterName
                        HostOrClusterID   = $hostOrClusterId
                        DatacenterName    = $datacenterName
                        DatacenterID      = $datacenterId
                        vCenterName       = $virtualCenterName
                        vCenterID         = $virtualCenterId
                    }
                    $result += $dataObject
                }
            }
        }
    }
    # Return the collected data
    return $result
}

# Define the function GetUsercurrentSessionInfo
function Get-HorizonUserSessionInfo {
    param (
        [string]$ServerUrl,
        [string]$AccessToken,
        [string]$targetUser
    )

    # Helper function to make API calls
    function Invoke-HorizonApi {
        param (
            [string]$Uri
        )
        try {
            return Invoke-RestMethod -Uri $Uri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Get
        } catch {
            Write-Host "Error in Invoke-HorizonApi: $_"
        }
    }

    # Function to retrieve session information
    function Get-SessionInfo {
        param (
            [string]$UserID
        )

        # Construct the filter JSON object
        $filterObj = @{
            type = "And"
            filters = @(
                @{
                    type  = "Equals"
                    name  = "user_id"
                    value = $UserID
                }
            )
        }

        # Convert the filter object to a JSON string
        $filterJson = $filterObj | ConvertTo-Json -Compress

        # URL encode the JSON string
        $filterEncoded = [System.Net.WebUtility]::UrlEncode($filterJson)

        # Construct the API endpoint URL to get session info with filter
        $sessionUrl = "$ServerUrl/rest/inventory/v1/sessions?filter=$filterEncoded"
        return Invoke-HorizonApi -Uri $sessionUrl
    }

    # Function to retrieve machine information
    function Get-MachineInfo {
        param (
            [string]$machineID
        )

        $machineUrl = "$ServerUrl/rest/inventory/v1/machines/$machineID"
        return Invoke-HorizonApi -Uri $machineUrl
    }

    try {
        # Get UserID
        $userID = Get-UserID -ServerUrl $ServerUrl -AccessToken $AccessToken -User_LoginName $targetUser
        if (-not $userID) {
            throw "User ID for '$targetUser' not found."
        }

        # Get session information
        $sessionInfo = Get-SessionInfo -UserID $userID
        if ($sessionInfo -isnot [System.Collections.IEnumerable]) {
            throw "No session information found for user '$targetUser'."
        }

        # Collect session details
        $sessions = @()
        foreach ($session in $sessionInfo) {
            $sessionId = $session.id
            $machineID = $session.machine_id

            # Convert start_time to human-readable format
            $start_datetime = [System.DateTimeOffset]::FromUnixTimeMilliseconds($session.start_time).ToLocalTime()

            # Convert last_session_duration_ms to human-readable format
            $timespan = [System.TimeSpan]::FromMilliseconds($session.last_session_duration_ms)

            # Get machine a
            $machineInfo = Get-MachineInfo -machineID $machineID

            $sessionDetails = [PSCustomObject]@{
                UserName      = $targetUser
                SessionID     = $sessionId
                LoginTime     = $start_datetime.DateTime
                SessionTime   = $timespan.ToString()
                VMName        = $machineInfo.name
                LocationID    = $session.client_data.name
                LocationMAC   = $session.client_data.location_id
                LocationIP    = $session.client_data.address
            }

            $sessions += $sessionDetails
        }

        return $sessions
    } catch {
        throw "Error retrieving user session information: $_"
    }
}

# Define the function Get-HistoricalSessionDetailsLogs
function Get-HistoricalSessionDetailsLogs {
    param (
        [string]$connectionServer,
        [string]$targetUser,
        [string]$outputCsvPath
    )

    # Retrieve user credentials from global variables
    $credentials = New-Object System.Management.Automation.PSCredential ($global:username, $global:password)

    # Initialize an array to hold the parsed session details
    $allSessions = @()

    # Script block to run on the remote server
    $scriptBlock = {
        param ($targetUser)
        
        $logDirectory = "C:\ProgramData\VMware\VDM\logs"
        $logFiles = Get-ChildItem -Path $logDirectory -Filter 'debug-*.txt'
        $sessions = @()

        foreach ($logFile in $logFiles) {
            $logContent = Get-Content -Path $logFile.FullName

            foreach ($line in $logContent) {
                if ($line -match "onEvent: CONNECTED - UserName:${targetUser}") {
                    if ($line -match '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[-+]\d{2}:\d{2})') {
                        $timestamp = $matches[1]
                        $dateTime = [DateTimeOffset]::Parse($timestamp).ToLocalTime()
                    }

                    if ($line -match 'ServerAddress:([^\.]+)\.') {
                        $vmName = $matches[1]
                    }

                    if ($line -match 'ClientName:([^;]+);') {
                        $locationID = $matches[1]
                    }

                    if ($locationID -like 'pcoip-portal-*' -and $locationID -match 'pcoip-portal-([0-9a-fA-F]{12})') {
                        $locationMAC = $matches[1]
                        $formattedMAC = ($locationMAC -split '(?<=\G.{2})(?!$)' -join '-')
                    } else {
                        $formattedMAC = "Horizon Client"
                    }

                    if ($line -match 'ClientAddress:([\d\.]+);') {
                        $IP = $matches[1]
                        $ipv4Pattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                        if ($IP -match $ipv4Pattern) {
                            $LocationIP = $IP
                        } else {
                            $LocationIP = "Invalid IP"
                        }
                    }

                    $sessionDetails = [PSCustomObject]@{
                        UserName      = ${targetUser}
                        LoginTime     = $dateTime.DateTime
                        VMName        = $vmName
                        LocationID    = $locationID
                        LocationMAC   = $formattedMAC
                        LocationIP    = $LocationIP
                    }

                    $sessions += $sessionDetails
                }
            }
        }

        return $sessions
    }

    # Execute the script block on the remote server with credentials
    $remoteSessions = Invoke-Command -ComputerName $connectionServer -Credential $credentials -ScriptBlock $scriptBlock -ArgumentList $targetUser

    # Add the results to the allSessions array
    $allSessions += $remoteSessions

    return $allSessions | Select-Object UserName, LoginTime, VMName, LocationID, LocationMAC, LocationIP

    # Output to CSV
    $allSessions | Select-Object UserName, LoginTime, VMName, LocationID, LocationMAC, LocationIP | Export-Csv -Path $outputCsvPath -NoTypeInformation
}

# Define the function to display GUI
function Show-HorizonAPIForensicsGUI {
    # XAML content for main window
    $xamlMain = @"
<Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
        xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
        Title='Horizon API: Forensics' Height='700' Width='900'>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height='Auto'/>
            <RowDefinition Height='Auto'/>
            <RowDefinition Height='*'/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width='200'/>
            <ColumnDefinition Width='*'/>
        </Grid.ColumnDefinitions>

        <!-- Menu on the left -->
        <StackPanel Grid.RowSpan='3' Grid.Column='0' Background='LightGray'>
            <TextBlock Text='Horizon API: Forensics' Margin='10' Foreground='Gray'/>
            <TextBlock Text='by Peter Stearns' Margin='0' Foreground='Gray' HorizontalAlignment='Right'/>
            <Button Name='GetAccessTokenBtn' Content='Get Access Token' Margin='10'/>
            <TextBlock Height='50'/>
            <Button Name='PutUserOnHoldReleaseBtn' Content='Put or Release Holds' Margin='10'/>
            <Button Name='GetHeldInfoBtn' Content='Get Hold Info' Margin='10'/>
            <Button Name='ArchiveMachineBtn' Content='Archive Machine' Margin='10'/>
            <Button Name='GetUserSessionInfoBtn' Content='Get User Current Session Info' Margin='10'/>
            <Button Name='GetUserHistoricalSessionInfoBtn' Content='Get Historical Session Info' Margin='10'/>
            <TextBlock Height='50'/>
            <Button Name='CreateForensicAdminRoleBtn' Content='Verify Forensic Admin Role' Margin='10'/>
            <Button Name='SetArchiveDatastoreBtn' Content='Set Archive Datastore' Margin='10'/>
            <TextBlock Height='70'/>
            <Button Name='ExitBtn' Content='Exit' Margin='10'/>
        </StackPanel>

        <!-- User input and output area on the right -->
        <StackPanel Grid.Row='0' Grid.Column='1' Name='InputOutputArea' Margin='10' Visibility='Visible'>
            <TextBlock Name='InitialMessage' TextWrapping='Wrap' Margin='0,0,0,10' Foreground='Gray' TextAlignment='Center'>
                <Bold>
                    <Run FontSize='16'>Welcome to the Horizon API Forensics tool!</Run>
                </Bold>
                <LineBreak/><LineBreak/>
                <TextBlock TextAlignment='Left'>
                    Follow these steps to get started:
                    <LineBreak/>
                    1. <Bold>Get Access Token</Bold>: Authenticate with the Horizon API (Server URL for each pod, Username, Password, Domain).
                    <LineBreak/>
                    2. <Bold>Put or Release Holds</Bold>: Manage hold status of users or groups.
                    <LineBreak/>
                    3. <Bold>Get Hold Info</Bold>: Retrieve info about held users and machines.
                    <LineBreak/>
                    4. <Bold>Archive Machine</Bold>: Archive Held Machine.
                    <LineBreak/>
                    5. <Bold>Get User Current Session Info</Bold>: Retrieve session information for a specified user.
                    <LineBreak/>
                    6. <Bold>Verify Forensic Admin Role</Bold>: Ensure Forensic Admin role is enabled and lists groups assigned.
                    <LineBreak/>
                    7. <Bold>Set Archive Datastore</Bold>: Set datastore for archival and archive specific machines.
                    <LineBreak/><LineBreak/>
                    For more details, refer to the 
                    <Hyperlink NavigateUri="https://docs.omnissa.com/bundle/Desktops-and-Applications-in-HorizonVmulti/page/ForensicsSelectHoldforWindowsInstantCloneDesktops.html">Horizon API Forensics Documentation</Hyperlink>.
                    <LineBreak/><LineBreak/>
                    Summary:
                    <LineBreak/>
                    - A hold can only be applied at an individual AD user level.
                    <LineBreak/>
                    - Hold applies to the user's current VM and any other VMs assigned to them.
                    <LineBreak/>
                    - The VM state changes from stateless to stateful but remains in its original pool.
                    <LineBreak/>
                    - A status indicator in the admin console shows that the VM is on hold.
                    <LineBreak/>
                    - VM is tagged as Forensic and protected in vCenter.
                    <LineBreak/><LineBreak/>
                    During the hold period:
                    <LineBreak/>
                    - Forensics team can access the stateful desktop for investigation.
                    <LineBreak/>
                    - Use the Archive API to archive VMs. Archive only when the user is logged out.
                    <LineBreak/><LineBreak/>
                    Archival operation:
                    <LineBreak/>
                    - VM is shut down, disks and snapshots consolidated, VMDK copied to the archival location, and VM re-synced.
                    <LineBreak/><LineBreak/>
                    Notes:
                    <LineBreak/>
                    - A held VM cannot be refreshed, recovered, removed, or put into maintenance mode.
                    <LineBreak/>
                    - Pool containing held VMs cannot be deleted.
                    <LineBreak/><LineBreak/>
                    Removing users from hold:
                    <LineBreak/>
                    - VM turns back into a stateless VM.
                    <LineBreak/>
                    - Forensic tag is removed and VM can be deleted from vCenter.
                    <LineBreak/>
                    - On user logoff, VM is deleted and recreated from the golden image.
                    <LineBreak/><LineBreak/>
                    Happy Forensics! 😊
                </TextBlock>
            </TextBlock>
        </StackPanel>

        <!-- Panel for Get Access Token input fields -->
        <StackPanel Grid.Row='0' Grid.Column='1' Name='GetAccessTokenPanel' Margin='10' Visibility='Collapsed'>
            <Label Content='Server URL' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <TextBox Name='ServerUrlInput' Margin='0,0,0,10'/>
            <Label Content='Username' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <TextBox Name='UsernameInput' Margin='0,0,0,10'/>
            <Label Content='Password' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <PasswordBox Name='PasswordInput' Margin='0,0,0,10'/>
            <Label Content='Domain' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <TextBox Name='DomainInput' Margin='0,0,0,10'/>
            <Button Name='SubmitAccessTokenBtn' Content='Submit' Margin='10'/>
            <Label Content='Output:' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <TextBox Name='AccessPanelOut' VerticalAlignment='Top' TextWrapping='Wrap' AcceptsReturn='True' VerticalScrollBarVisibility='Auto' Margin='0,0,0,10'/>
        </StackPanel>

        <!-- Output Label and TextBox for Held Users -->
        <StackPanel Grid.Row='1' Grid.Column='1' Name='HeldUsersPanel' Margin='10' Visibility='Collapsed'>
            <Label Content='Held Users' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <ScrollViewer VerticalScrollBarVisibility='Auto' Height='400'>
                <TextBox Name='HeldUsersOutput' Text='Held Users will be displayed here' VerticalAlignment='Top' TextWrapping='Wrap' AcceptsReturn='True'/>
            </ScrollViewer>
        </StackPanel>

        <!-- Output Label and TextBox for Held Machines -->
        <StackPanel Grid.Row='2' Grid.Column='1' Name='HeldMachinesPanel' Margin='10' Visibility='Collapsed'>
            <Label Content='Held Machines' VerticalAlignment='Top' Foreground='Gray' Padding='0' Margin='0,0,0,5'/>
            <ScrollViewer VerticalScrollBarVisibility='Auto' Height='400'>
                <TextBox Name='HeldMachinesOutput' Text='Held Machines will be displayed here' VerticalAlignment='Top' TextWrapping='Wrap' AcceptsReturn='True'/>
            </ScrollViewer>
        </StackPanel>
    </Grid>
</Window>
"@
    # Load main window XAML content
    $xamlStringReader = [System.IO.StringReader]::new($xamlMain)
    $reader = [System.Xml.XmlReader]::Create($xamlStringReader)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Get controls
    $initialMessage = $window.FindName('InitialMessage')
    $getAccessTokenBtn = $window.FindName('GetAccessTokenBtn')
    $createForensicAdminRoleBtn = $window.FindName('CreateForensicAdminRoleBtn')
    $putUserOnHoldReleaseBtn = $window.FindName('PutUserOnHoldReleaseBtn')
    $getHeldInfoBtn = $window.FindName('GetHeldInfoBtn')
    $exitBtn = $window.FindName('ExitBtn')
    $inputOutputArea = $window.FindName('InputOutputArea')
    $serverUrlInput = $window.FindName('ServerUrl')
    $usernameInput = $window.FindName('Username')
    $passwordInput = $window.FindName('Password')
    $domainInput = $window.FindName('Domain')
    $heldUsersPanel = $window.FindName('HeldUsersPanel')
    $heldUsersOutput = $window.FindName('HeldUsersOutput')
    $heldMachinesPanel = $window.FindName('HeldMachinesPanel')
    $heldMachinesOutput = $window.FindName('HeldMachinesOutput')
    $getAccessTokenPanel = $window.FindName('GetAccessTokenPanel')
    $setArchiveDatastoreBtn = $window.FindName('SetArchiveDatastoreBtn')
    $archiveMachineBtn = $window.FindName('ArchiveMachineBtn')
    $getUserSessionInfoBtn = $window.FindName('GetUserSessionInfoBtn')
    $historicalSessionDetailsLogsBtn = $window.FindName('GetUserHistoricalSessionInfoBtn')

    # Create new instances of the controls
    $serverUrlInput1 = [Windows.Controls.TextBox]::new()
    $serverUrlInput2 = [Windows.Controls.TextBox]::new()
    $usernameInput = [Windows.Controls.TextBox]::new()
    $passwordInput = [Windows.Controls.PasswordBox]::new()
    $domainInput = [Windows.Controls.TextBox]::new()
    $AccessPanelOut = [Windows.Controls.TextBox]::new()
    $outputBox = [Windows.Controls.TextBox]::new()

    # Global variable to store the access token
    $global:serverUrl = $null
    $global:username = $null
    $global:password = $null
    $global:domain = $null
    $global:accessTokens = $null

    # Define the event handler to clear the output boxes
    $clearOutput = {
        $heldUsersOutput.Text = ''
        $heldMachinesOutput.Text = ''
        $outputBox.Text = ''
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $initialMessage.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'
        $inputOutputArea.Visibility = 'Collapsed'
    }

    # Define the event handler for the Server URL text box to auto-fill the domain
    $serverUrlInput1.Add_LostFocus({
        $serverUrl = $serverUrlInput1.Text
        if ($serverUrl -match "https?://[^/]+?\.(.+)") {
            $domain = $matches[1]
            $domainInput.Text = $domain
        }
    })

    # Attach the same event handler to other buttons
    $createForensicAdminRoleBtn.Add_Click($clearOutput)
    $PutUserOnHoldReleaseBtn.Add_Click($clearOutput)
    $getHeldInfoBtn.Add_Click($clearOutput)
    $exitBtn.Add_Click($clearOutput)

    # Load inputs from the secure file
    try {
        $secureInputs = Import-Clixml -Path $inputFilePath
        $serverUrlInput1.Text = $secureInputs.ServerUrl1
        $serverUrlInput2.Text = $secureInputs.ServerUrl2
        $usernameInput.Text = $secureInputs.Username
        $domainInput.Text = $secureInputs.Domain
    } catch {
        # Clear the file if loading fails
        if (Test-Path -Path $inputFilePath) {
            Remove-Item -Path $inputFilePath
        }
    }

    # Define event handler for Get Access Token button
    $getAccessTokenBtn.Add_Click({
        & $clearOutput  # Clear previous outputs before making input/output area visible
        $getAccessTokenPanel.Visibility = 'Visible'

        # Clear existing children in the GetAccessTokenPanel
        $getAccessTokenPanel.Children.Clear()

        # Input fields for Server URLs
        $labelServerUrl1 = [Windows.Controls.Label]::new()
        $labelServerUrl1.Content = 'PodA - Server URL                          e.g.: https://servername.example.com'
        $labelServerUrl1.VerticalAlignment = 'Top'
        $labelServerUrl1.Foreground = 'Gray'
        $labelServerUrl1.Padding = [Windows.Thickness]::new(0)
        $getAccessTokenPanel.Children.Add($labelServerUrl1)
        $getAccessTokenPanel.Children.Add($serverUrlInput1)

        $labelServerUrl2 = [Windows.Controls.Label]::new()
        $labelServerUrl2.Content = 'PodB - Server URL                          e.g.: https://servername.example.com'
        $labelServerUrl2.VerticalAlignment = 'Top'
        $labelServerUrl2.Foreground = 'Gray'
        $labelServerUrl2.Padding = [Windows.Thickness]::new(0)
        $getAccessTokenPanel.Children.Add($labelServerUrl2)
        $getAccessTokenPanel.Children.Add($serverUrlInput2)

        # Input fields for common Username, Password, and Domain
        $labelUsername = [Windows.Controls.Label]::new()
        $labelUsername.Content = 'Username'
        $labelUsername.VerticalAlignment = 'Top'
        $labelUsername.Foreground = 'Gray'
        $labelUsername.Padding = [Windows.Thickness]::new(0)
        $getAccessTokenPanel.Children.Add($labelUsername)
        $getAccessTokenPanel.Children.Add($usernameInput)

        $labelPassword = [Windows.Controls.Label]::new()
        $labelPassword.Content = 'Password'
        $labelPassword.VerticalAlignment = 'Top'
        $labelPassword.Foreground = 'Gray'
        $labelPassword.Padding = [Windows.Thickness]::new(0)
        $getAccessTokenPanel.Children.Add($labelPassword)
        $getAccessTokenPanel.Children.Add($passwordInput)

        $labelDomain = [Windows.Controls.Label]::new()
        $labelDomain.Content = 'Domain'
        $labelDomain.VerticalAlignment = 'Top'
        $labelDomain.Foreground = 'Gray'
        $labelDomain.Padding = [Windows.Thickness]::new(0)
        $getAccessTokenPanel.Children.Add($labelDomain)
        $getAccessTokenPanel.Children.Add($domainInput)

        $submitBtn = [Windows.Controls.Button]::new()
        $submitBtn.Content = 'Submit'
        $submitBtn.Margin = [Windows.Thickness]::new(10)
        $getAccessTokenPanel.Children.Add($submitBtn)

        # Add output label and text box for the access token output
        $outputLabel = [Windows.Controls.Label]::new()
        $outputLabel.Content = 'Output:'
        $outputLabel.VerticalAlignment = 'Top'
        $outputLabel.Foreground = 'Gray'
        $outputLabel.Padding = [Windows.Thickness]::new(0)
        $outputLabel.Margin = [Windows.Thickness]::new(0)  # No spacing
        $getAccessTokenPanel.Children.Add($outputLabel)
        $AccessPanelOut.VerticalAlignment = 'Top'
        $AccessPanelOut.TextWrapping = 'Wrap'
        $AccessPanelOut.AcceptsReturn = $true
        $AccessPanelOut.VerticalScrollBarVisibility = 'Auto'
        $AccessPanelOut.Margin = [Windows.Thickness]::new(0, 0, 0, 10)  # No spacing between label and box
        $getAccessTokenPanel.Children.Add($AccessPanelOut)

        # Define event handler for Submit button
        $submitBtn.Add_Click({
            $serverUrl1 = $serverUrlInput1.Text
            $serverUrl2 = $serverUrlInput2.Text
            $username = $usernameInput.Text
            $password = $passwordInput.SecurePassword
            $domain = $domainInput.Text

            if ([string]::IsNullOrEmpty($serverUrl1) -or [string]::IsNullOrEmpty($serverUrl2) -or [string]::IsNullOrEmpty($username) -or $password.Length -eq 0 -or [string]::IsNullOrWhiteSpace($domain)) {
                $outputText = [Windows.Controls.TextBlock]::new()
                $getAccessTokenPanel.Children.Add($AccessPanelOut)
                $AccessPanelOut.Text = 'All fields must be filled out.'
            } else {
                $accessToken1 = Get-AccessToken -ServerUrl $serverUrl1 -Username $username -Password $password -Domain $domain
                $accessToken2 = Get-AccessToken -ServerUrl $serverUrl2 -Username $username -Password $password -Domain $domain

                if ($accessToken1 -and $accessToken2) {
                    # Store tokens and URLs in a dictionary
                    $global:accessTokens = @{
                        PodA = @{
                            URL = $serverUrl1
                            Token = $accessToken1
                        }
                        PodB = @{
                            URL = $serverUrl2
                            Token = $accessToken2
                        }
                    }

                    $AccessPanelOut.Text = "Access tokens obtained:`nPodA - $($global:accessTokens.PodA.URL): $($global:accessTokens.PodA.Token)`n`nPodB - $($global:accessTokens.PodA.URL): $($global:accessTokens.PodB.Token)"

                    # Save Global Variables for better recall
                    $global:username = $username
                    $global:password = $password
                    $global:domain = $domain

                    # Save inputs to a secure file (excluding password)
                    $secureInputs = @{
                        ServerUrl1 = $serverUrl1
                        ServerUrl2 = $serverUrl2
                        Username = $username
                        Domain = $domain
                    }
                    $secureInputs | Export-Clixml -Path $inputFilePath
                } else {
                    $AccessPanelOut.Text = 'Failed to obtain access tokens.'
                }
            }
        })
    })

    # Define event handler for combined button
    $getHeldInfoBtn.Add_Click({
        & $clearOutput

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Visible'
        $heldMachinesPanel.Visibility = 'Visible'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Validate input fields
        if (-not $global:accessTokens) {
            $heldUsersOutput.Text = 'Must Get an Access Token prior to using API Calls.'
            $heldMachinesOutput.Text = 'Must Get an Access Token prior to using API Calls.'
        } else {
            $allHeldUsers = @()
            $allHeldMachines = @()

            foreach ($key in $global:accessTokens.Keys) {
                $serverUrl = $global:accessTokens[$key].URL
                $accessToken = $global:accessTokens[$key].Token

                # Get held users with the access token
                $heldUsers = Get-HeldUsers -ServerUrl $serverUrl -AccessToken $accessToken
                if ($heldUsers -is [string]) {
                    $allHeldUsers += "${key}: $serverUrl`n$heldUsers"
                } else {
                    # Add held users to the collection
                    $allHeldUsers += "${key}: $serverUrl`n" + ($heldUsers | ConvertTo-Json -Depth 1)
                }

                # Get held machines with the access token
                $heldMachines = Get-HeldMachines -ServerUrl $serverUrl -AccessToken $accessToken
                if ($heldMachines -is [string]) {
                    $allHeldMachines += "${key}: $serverUrl`n$heldMachines"
                } else {
                    # Add held machines to the collection
                    $allHeldMachines += "${key}: $serverUrl`n" + ($heldMachines | ConvertTo-Json -Depth 1)
                }
            }

            # Display collected held users and machines
            $heldUsersOutput.Text = ($allHeldUsers -join "`n`n")
            $heldMachinesOutput.Text = ($allHeldMachines -join "`n`n")
        }
    })

    # Define the event handler for the Put User On Hold button and Release User from Hold button
    $putUserOnHoldReleaseBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Create input box for the User or Group
        $holdUserLabel = [Windows.Controls.Label]::new()
        $holdUserLabel.Content = 'Enter User(s) or Group Name(s):                           (sAMAccountName format, separated by commas)'
        $holdUserLabel.VerticalAlignment = 'Top'
        $holdUserLabel.Foreground = 'Gray'
        $holdUserLabel.Padding = [Windows.Thickness]::new(0)
        $holdUserLabel.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($holdUserLabel)

        $holdUserInputBox = [Windows.Controls.TextBox]::new()
        $holdUserInputBox.Name = 'HoldUserInputBox'
        $holdUserInputBox.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($holdUserInputBox)

        # Create the "Place User or Group on Hold" button
        $putUserOnHoldButton = [Windows.Controls.Button]::new()
        $putUserOnHoldButton.Content = 'Place User(s) or Group(s) on Hold'
        $putUserOnHoldButton.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($putUserOnHoldButton)

        # Create the "Release User or Group from Hold" button
        $releaseUserFromHoldButton = [Windows.Controls.Button]::new()
        $releaseUserFromHoldButton.Content = 'Release User(s) or Group(s) from Hold'
        $releaseUserFromHoldButton.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($releaseUserFromHoldButton)

        $outputBox.VerticalAlignment = 'Top'
        $outputBox.TextWrapping = 'Wrap'
        $outputBox.Margin = [Windows.Thickness]::new(10)
        $outputBox.IsReadOnly = $true
        $inputOutputArea.Children.Add($outputBox)

        # Define the event handler for the "Place User(s) or Group(s) on Hold" button
        $putUserOnHoldButton.Add_Click({
            # Retrieve the user or group names from the input box 
            $users2hold = $inputOutputArea.Children | Where-Object { $_.Name -eq 'HoldUserInputBox' } | Select-Object -ExpandProperty Text

            # Split the input by commas to get individual user or group names
            $users2holdArray = $users2hold -split ',\s*'

            # Check if any user or group name is blank after retrieving from the input box
            if ($users2holdArray -contains '') {
                $outputBox.Text = 'Please fill in all required fields.'
                $outputBox.Foreground = 'Red'
            } elseif (-not $global:accessTokens) {
                $outputBox.Text = 'Must get access tokens first.'
                $outputBox.Foreground = 'Red'
            } else {
                $results = @()
                foreach ($user2hold in $users2holdArray) {
                    foreach ($pod in $global:accessTokens.Keys) {
                        $ServerUrl = $global:accessTokens[$pod].URL
                        $AccessToken = $global:accessTokens[$pod].Token

                        # Convert to UserSID
                        $userSID = Get-UserID -ServerUrl $ServerUrl -AccessToken $AccessToken -User_LoginName $user2hold

                        # Call the function to put the user or group on hold
                        $result = Put-UserOnHold -ServerUrl $ServerUrl -AccessToken $AccessToken -UserSID $userSID -UserName $user2hold
                        $results += "${pod}: $result"
                    }
                }

                # Display the result in the output area
                $outputBox.Text = $results -join "`n"
                $outputBox.Foreground = 'Black'
            }
        })

        # Define the event handler for the "Release User(s) or Group(s) from Hold" button
        $releaseUserFromHoldButton.Add_Click({
            # Retrieve the user or group names from the input box 
            $users2hold = $inputOutputArea.Children | Where-Object { $_.Name -eq 'HoldUserInputBox' } | Select-Object -ExpandProperty Text

            # Split the input by commas to get individual user or group names
            $users2holdArray = $users2hold -split ',\s*'

            # Check if any user or group name is blank after retrieving from the input box
            if ($users2holdArray -contains '') {
                $outputBox.Text = 'Please fill in all required fields.'
                $outputBox.Foreground = 'Red'
            } elseif (-not $global:accessTokens) {
                $outputBox.Text = 'Must get access tokens first.'
                $outputBox.Foreground = 'Red'
            } else {
                $results = @()
                foreach ($user2hold in $users2holdArray) {
                    foreach ($pod in $global:accessTokens.Keys) {
                        $ServerUrl = $global:accessTokens[$pod].URL
                        $AccessToken = $global:accessTokens[$pod].Token

                        # Convert to UserSID
                        $userSID = Get-UserID -ServerUrl $ServerUrl -AccessToken $AccessToken -User_LoginName $user2hold

                        # Call the function to release the user or group from hold
                        $result = Release-UserFromHold -ServerUrl $ServerUrl -AccessToken $AccessToken -UserSID $userSID -UserName $user2hold
                        $results += "${pod}: $result"
                    }
                }

                # Display the result in the output area
                $outputBox.Text = $results -join "`n"
                $outputBox.Foreground = 'Black'
            }
        })
    })

    # Update the event handler for the Archive Machine button
    $archiveMachineBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Create new panel for displaying held machines
        $newHeldMachinesPanel = [Windows.Controls.StackPanel]::new()
        $newHeldMachinesPanel.Name = 'NewHeldMachinesPanel'
        $newHeldMachinesPanel.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($newHeldMachinesPanel)

        # Create label for held machines
        $heldMachinesLabel = [Windows.Controls.Label]::new()
        $heldMachinesLabel.Content = 'Held Machines:'
        $heldMachinesLabel.VerticalAlignment = 'Top'
        $heldMachinesLabel.Foreground = 'Gray'
        $heldMachinesLabel.Padding = [Windows.Thickness]::new(0)
        $heldMachinesLabel.Margin = [Windows.Thickness]::new(10, 0, 0, 10)
        $newHeldMachinesPanel.Children.Add($heldMachinesLabel)

        # Create text box for displaying held machines
        $newHeldMachinesOutput = [Windows.Controls.TextBox]::new()
        $newHeldMachinesOutput.Name = 'NewHeldMachinesOutput'
        $newHeldMachinesOutput.VerticalAlignment = 'Top'
        $newHeldMachinesOutput.TextWrapping = 'Wrap'
        $newHeldMachinesOutput.AcceptsReturn = $true
        $newHeldMachinesOutput.VerticalScrollBarVisibility = 'Auto'
        $newHeldMachinesOutput.Height = 400  # Set height to 400
        $newHeldMachinesOutput.Margin = [Windows.Thickness]::new(10, 0, 0, 10)
        $newHeldMachinesPanel.Children.Add($newHeldMachinesOutput)

        # Retrieve the input values from Global
        if (-not $global:accessTokens) {
            $newHeldMachinesOutput.Text = 'Must Get an Access Token prior to using API Calls.'
            $newHeldMachinesOutput.Foreground = 'Red'
        } else {
            # Get held machines with the access token for display
            $allHeldMachines = @()

            foreach ($key in $global:accessTokens.Keys) {
                $serverUrl = $global:accessTokens[$key].URL
                $accessToken = $global:accessTokens[$key].Token

                # Get held machines
                $heldMachines = Get-HeldMachines -ServerUrl $serverUrl -AccessToken $accessToken
                if ($heldMachines -is [string]) {
                    $allHeldMachines += "${key}: $serverUrl`n$heldMachines"
                } else {
                    $allHeldMachines += "${key}: $serverUrl`n" + ($heldMachines | ConvertTo-Json -Depth 1)
                }
            }

            # Display collected held machines
            $newHeldMachinesOutput.Text = ($allHeldMachines -join "`n`n")
        }

        # Create input box for the Machine ID
        $archiveMachineLabel = [Windows.Controls.Label]::new()
        $archiveMachineLabel.Content = 'Enter Machine ID to archive:'
        $archiveMachineLabel.VerticalAlignment = 'Top'
        $archiveMachineLabel.Foreground = 'Gray'
        $archiveMachineLabel.Padding = [Windows.Thickness]::new(0)
        $archiveMachineLabel.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($archiveMachineLabel)

        $archiveMachineInputBox = [Windows.Controls.TextBox]::new()
        $archiveMachineInputBox.Name = 'ArchiveMachineInputBox'
        $archiveMachineInputBox.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($archiveMachineInputBox)

        # Create the "Archive Machine" button
        $archiveMachineButton = [Windows.Controls.Button]::new()
        $archiveMachineButton.Content = 'Archive Machine'
        $archiveMachineButton.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($archiveMachineButton)

        # Create the output box
        $outputBox.Name = 'OutputBox'
        $outputBox.VerticalAlignment = 'Top'
        $outputBox.TextWrapping = 'Wrap'
        $outputBox.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($outputBox)

        # Define the event handler for the "Archive Machine" button
        $archiveMachineButton.Add_Click({
            # Retrieve the Machine ID from the input box 
            $machineID = $inputOutputArea.Children | Where-Object { $_.Name -eq 'ArchiveMachineInputBox' } | Select-Object -ExpandProperty Text

            # Check if machineID is blank after retrieving from the input box
            if ([string]::IsNullOrEmpty($machineID)) {
                $outputBox.Text = 'Please fill in the Machine ID.'
                $outputBox.Foreground = 'Red'
            } else {
                # Validate input fields
                if (-not $global:accessTokens -or [string]::IsNullOrEmpty($machineID)) {
                    $outputBox.Text = 'Please fill in all required fields.'
                    $outputBox.Foreground = 'Red'
                } else {
                    # Call the function to archive the machine
                    $result = Set-MachinetoArchive -MachineID $machineID

                    # Display the result in the output area
                    $outputBox.Text = $result
                    $outputBox.Foreground = 'Black'
                }
            }
        })
    })

    # Define event handler for the new button
    $getUserSessionInfoBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Create input box for the target user
        $targetUserLabel = [Windows.Controls.Label]::new()
        $targetUserLabel.Content = 'Enter target user:'
        $targetUserLabel.VerticalAlignment = 'Top'
        $targetUserLabel.Foreground = 'Gray'
        $targetUserLabel.Padding = [Windows.Thickness]::new(0)
        $targetUserLabel.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($targetUserLabel)

        $targetUserInputBox = [Windows.Controls.TextBox]::new()
        $targetUserInputBox.Name = 'TargetUserInputBox'
        $targetUserInputBox.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($targetUserInputBox)

        # Create the "Get Session Info" button
        $getSessionInfoButton = [Windows.Controls.Button]::new()
        $getSessionInfoButton.Content = 'Get Session Info'
        $getSessionInfoButton.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($getSessionInfoButton)

        # Create the output box
        $outputBox.Name = 'OutputBox'
        $outputBox.VerticalAlignment = 'Top'
        $outputBox.TextWrapping = 'Wrap'
        $outputBox.Margin = [Windows.Thickness]::new(10)
        $outputBox.VerticalScrollBarVisibility = 'Auto'
        $outputBox.Height = 500  # Set height to 500
        $inputOutputArea.Children.Add($outputBox)

        # Define the event handler for the "Get Session Info" button
        $getSessionInfoButton.Add_Click({
            # Retrieve the target user from the input box 
            $targetUser = $inputOutputArea.Children | Where-Object { $_.Name -eq 'TargetUserInputBox' } | Select-Object -ExpandProperty Text

            # Check if targetUser is blank after retrieving from the input box
            if ([string]::IsNullOrEmpty($targetUser)) {
                $outputBox.Text = 'Please fill in the target user.'
                $outputBox.Foreground = 'Red'
            } elseif (-not $global:accessTokens) {
                $outputBox.Text = 'Must Get an Access Token prior to using API Calls.'
                $outputBox.Foreground = 'Red'
            } else {
                $results = @()
                foreach ($pod in $global:accessTokens.Keys) {
                    $ServerUrl = $global:accessTokens[$pod].URL
                    $AccessToken = $global:accessTokens[$pod].Token

                    try {
                        $sessionInfo = Get-HorizonUserSessionInfo -ServerUrl $ServerUrl -AccessToken $AccessToken -targetUser $targetUser
                        $results += "${pod} - ${ServerUrl}: $($sessionInfo | Out-String)"
                    } catch {
                        $results += "${pod} - ${ServerUrl} Error retrieving session information for user '$targetUser'. $_"
                    }
                }

                # Display the result in the output area
                $outputBox.Text = $results -join "`n`n"
                $outputBox.Foreground = 'Black'
            }
        })
    })

    # Define event handler for the Get Historical Session Info from Logs button
    $historicalSessionDetailsLogsBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Create the red warning label
        $warningLabel = [Windows.Controls.Label]::new()
        $warningLabel.Content = '⚠️ Experimental: This feature requires OS admin access to retrieve info from Connection Server logs.'
        $warningLabel.VerticalAlignment = 'Top'
        $warningLabel.HorizontalAlignment = 'Center'
        $warningLabel.Foreground = 'Red'
        $warningLabel.Padding = [Windows.Thickness]::new(0)
        $warningLabel.Margin = [Windows.Thickness]::new(10, 0, 0, 10)
        $inputOutputArea.Children.Add($warningLabel)

        # Create input fields for target user and output CSV path
        $labelTargetUser = [Windows.Controls.Label]::new()
        $labelTargetUser.Content = 'Target User:'
        $labelTargetUser.VerticalAlignment = 'Top'
        $labelTargetUser.Foreground = 'Gray'
        $labelTargetUser.Padding = [Windows.Thickness]::new(0)
        $inputOutputArea.Children.Add($labelTargetUser)

        $targetUserInput = [Windows.Controls.TextBox]::new()
        $targetUserInput.Name = 'TargetUserInput'
        $targetUserInput.Margin = [Windows.Thickness]::new(0, 0, 0, 10)
        $inputOutputArea.Children.Add($targetUserInput)

        $labelOutputCsvPath = [Windows.Controls.Label]::new()
        $labelOutputCsvPath.Content = 'Output CSV Path:'
        $labelOutputCsvPath.VerticalAlignment = 'Top'
        $labelOutputCsvPath.Foreground = 'Gray'
        $labelOutputCsvPath.Padding = [Windows.Thickness]::new(0)
        $inputOutputArea.Children.Add($labelOutputCsvPath)

        $outputCsvPathInput = [Windows.Controls.TextBox]::new()
        $outputCsvPathInput.Name = 'OutputCsvPathInput'
        $outputCsvPathInput.Margin = [Windows.Thickness]::new(0, 0, 0, 10)
        $inputOutputArea.Children.Add($outputCsvPathInput)

        # Create the "Get Historical Session Info from Logs" button
        $getHistoricalSessionDetailsLogsButton = [Windows.Controls.Button]::new()
        $getHistoricalSessionDetailsLogsButton.Content = 'Get Historical Session Info from Connection Server Logs'
        $getHistoricalSessionDetailsLogsButton.Margin = [Windows.Thickness]::new(10)
        $inputOutputArea.Children.Add($getHistoricalSessionDetailsLogsButton)

        # Create the output box
        $outputBox.Name = 'OutputBox'
        $outputBox.VerticalAlignment = 'Top'
        $outputBox.TextWrapping = 'Wrap'
        $outputBox.Margin = [Windows.Thickness]::new(10)
        $outputBox.VerticalScrollBarVisibility = 'Auto'
        $outputBox.Height = 450
        $outputBox.IsReadOnly = $true
        $inputOutputArea.Children.Add($outputBox)

        $getHistoricalSessionDetailsLogsButton.Add_Click({
            # Retrieve the input values from the input boxes 
            $targetUser = $inputOutputArea.Children | Where-Object { $_.Name -eq 'TargetUserInput' } | Select-Object -ExpandProperty Text
            $outputCsvPath = $inputOutputArea.Children | Where-Object { $_.Name -eq 'OutputCsvPathInput' } | Select-Object -ExpandProperty Text

            # Validate input fields
            if ([string]::IsNullOrEmpty($targetUser) -or [string]::IsNullOrEmpty($outputCsvPath)) {
                $outputBox.Text = 'Please fill in all required fields.'
                $outputBox.Foreground = 'Red'
            } elseif (-not $global:accessTokens) {
                $outputBox.Text = 'Must get access tokens first.'
                $outputBox.Foreground = 'Red'
            } else {
                $outputBox.Text = 'Starting to gather session details logs...'  # Initial message

                # Loop through connection servers and gather logs
                $results = @()
                foreach ($serverUrl in $global:accessTokens.Keys) {
                    $connectionServer = $global:accessTokens[$serverUrl].URL -replace '^https?://', ''
                    $outputBox.Text += "`nConnecting to server: $connectionServer"  # Update output box

                    # Call the function to get historical session details logs for each server
                    $serverResults = Get-HistoricalSessionDetailsLogs -connectionServer $connectionServer -targetUser $targetUser -outputCsvPath $outputCsvPath

                    # Update output box with server results
                    $outputBox.Text += "`nResults from server: $connectionServer`n" + ($serverResults | Out-String)
                    $results += $serverResults
                }

                $outputBox.Text += "`nAll session details logs have been gathered."
                $outputBox.Foreground = 'Black'
            }
        })
    })

    # Define event handler for Verify Forensics Admin Role button
    $createForensicAdminRoleBtn.Content = 'Verify Forensics Admin Role'
    $createForensicAdminRoleBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Validate access tokens
        if (-not $global:accessTokens) {
            $outputText = [Windows.Controls.TextBlock]::new()
            $outputText.Text = 'Must Get an Access Token prior to using API Calls.'
            $outputText.Foreground = 'Red'
            $outputText.Margin = [Windows.Thickness]::new(10)
            $inputOutputArea.Children.Add($outputText)
        } else {
            $labelInfo = [Windows.Controls.TextBlock]::new()
            $labelInfo.Text = 'Verifying Forensic Admin Role...'
            $labelInfo.Foreground = 'Gray'
            $labelInfo.Margin = [Windows.Thickness]::new(10)
            $inputOutputArea.Children.Add($labelInfo)

            $outputText = [Windows.Controls.TextBox]::new()
            $outputText.VerticalAlignment = 'Top'
            $outputText.TextWrapping = 'Wrap'
            $outputText.Margin = [Windows.Thickness]::new(10)
            $outputText.IsReadOnly = $true
            $inputOutputArea.Children.Add($outputText)

            $results = @()
            foreach ($key in $global:accessTokens.Keys) {
                $serverUrl = $global:accessTokens[$key].URL
                $accessToken = $global:accessTokens[$key].Token

                # Call the function to create forensic admin role
                $createRoleResult = Create-ForensicAdminRole -ServerUrl $serverUrl -AccessToken $accessToken
                $results += "${key}: Create Forensic Admin Role Result:`n" + $createRoleResult + "`n`n"

                # Call the function to get forensic admin groups
                $getGroupsResult = Get-ForensicAdminGroups -ServerUrl $serverUrl -AccessToken $accessToken
                $results += "${key}: Forensic Admin Groups:`n" + ($getGroupsResult | ConvertTo-Json -Depth 1)
            }

            $outputText.AppendText($results -join "`n`n")
        }
    })

    # Define the event handler for Set Archive Datastore button
    $setArchiveDatastoreBtn.Add_Click({
        & $clearOutput  # Clear previous outputs

        # Clear existing children in the InputOutputArea
        $inputOutputArea.Children.Clear()

        $outputText = [Windows.Controls.TextBox]::new()

        $inputOutputArea.Visibility = 'Visible'
        $heldUsersPanel.Visibility = 'Collapsed'
        $heldMachinesPanel.Visibility = 'Collapsed'
        $getAccessTokenPanel.Visibility = 'Collapsed'

        # Validate access tokens
        if (-not $global:accessTokens) {
            $outputText.Text = 'Must Get an Access Token prior to using API Calls.'
            $outputText.Foreground = 'Red'
            $outputText.Margin = [Windows.Thickness]::new(10)
            $inputOutputArea.Children.Add($outputText)
        } else {
            $labelInfo = [Windows.Controls.TextBlock]::new()
            $labelInfo.Text = 'Setting Archive Datastore...'
            $labelInfo.Foreground = 'Gray'
            $labelInfo.Margin = [Windows.Thickness]::new(10)
            $inputOutputArea.Children.Add($labelInfo)

            $outputText = [Windows.Controls.TextBox]::new()
            $outputText.VerticalAlignment = 'Top'
            $outputText.TextWrapping = 'Wrap'
            $outputText.Margin = [Windows.Thickness]::new(10)
            $outputText.IsReadOnly = $true
            $inputOutputArea.Children.Add($outputText)

            $results = @()
            foreach ($key in $global:accessTokens.Keys) {
                $serverUrl = $global:accessTokens[$key].URL
                $accessToken = $global:accessTokens[$key].Token

                # Call the function to set the archive datastore
                $setArchiveDatastoreResult = Set-ArchiveDatastore -ServerUrl $serverUrl -AccessToken $accessToken
                $results += "${key}: $setArchiveDatastoreResult"
            }

            $outputText.AppendText("Set Archive Datastore Results:`n" + ($results -join "`n`n"))
        }
    })

    # Define event handler for Exit button
    $window.FindName('ExitBtn').Add_Click({
        $window.Close()
    })

    # Show the main window as a dialog and capture the result
    $null = $window.ShowDialog()
}

# Call the function to display the main GUI
Show-HorizonAPIForensicsGUI

<#
#Command Usage Without GUI

$serverUrl1 = Read-Host -Prompt "Connection server URL PodA"
$serverUrl2 = Read-Host -Prompt "Connection server URL PodB"
$username = Read-Host -Prompt "Username"
$password = Read-Host -Prompt "Password" -AsSecureString
$domain = Read-Host -Prompt "Domain"

$accessToken1 = Get-AccessToken -ServerUrl $serverUrl1 -Username $username -Password $password -Domain $domain
$accessToken2 = Get-AccessToken -ServerUrl $serverUrl2 -Username $username -Password $password -Domain $domain

if ($accessToken1 -and $accessToken2) {
    # Store tokens and URLs in a dictionary
    $global:accessTokens = @{
        PodA = @{
            URL = $serverUrl1
            Token = $accessToken1
        }
        PodB = @{
            URL = $serverUrl2
            Token = $accessToken2
        }
    }           

    # Save Global Variables for better recall
    $global:username = $username
    $global:password = $password
    $global:domain = $domain
}


$UserHold = Read-Host -Prompt "Enter UserName for Hold"
$UserSID = Get-UserID -ServerUrl $serverUrl -AccessToken $accessToken -User_LoginName $UserHold
Put-UserOnHold -ServerUrl $serverUrl -AccessToken $accessToken -UserName $UserHold -UserSID $UserSID
Release-UserFromHold -ServerUrl $serverUrl -AccessToken $accessToken -UserName $UserHold -UserSID $UserSID

Get-HeldUsers -ServerUrl $serverUrl -AccessToken $accessToken
Get-HeldMachines -ServerUrl $serverUrl -AccessToken $accessToken
Set-MachinetoArchive -MachineID $MachineID


Create-ForensicAdminRole -ServerUrl $serverUrl -AccessToken $accessToken
Get-ForensicAdminGroups -ServerUrl $serverUrl -AccessToken $accessToken
Set-ArchiveDatastore -ServerUrl $serverUrl -AccessToken $accessToken
Get-HorizonvCenterInfo -ServerUrl $serverUrl -AccessToken $accessToken

#>
