<# 
System_Details_Check.ps1
Enhanced version - checks ALL settings that Prepare-MSSQL-SourceForDMS.ps1 configures

Creates:
  1) $env:USERPROFILE\Documents\System_details.txt
  2) $env:USERPROFILE\Documents\System_details.json

Checks:
- System configuration (OS, RAM, etc.)
- MSSQL installed or not
- SQL versions and instance details
- TCP/IP Enabled (registry)
- TCP Port Configuration (static 1433 vs dynamic)
- Mixed Mode Authentication enabled
- SQL Browser service status
- SQL Server Agent service status
- Remote Access enabled
- Credential login test
- Database exists or not
- Recovery Model (FULL required for CDC)
- User permissions (VIEW SERVER STATE, VIEW ANY DEFINITION)
- User is db_owner in database
- User is sysadmin (optional)
- Table list
- CDC enabled on DB and tables
- TCP 1433 listening
- Firewall inbound rule for 1433
- VPN detection
#>

$ErrorActionPreference = "SilentlyContinue"

# ---------- Helper Functions ----------
function Write-ReportLine {
    param([string]$line = "")
    $script:Report += $line + "`r`n"
    Write-Host $line
}

function Section {
    param([string]$title)
    Write-ReportLine ""
    Write-ReportLine "============================================================"
    Write-ReportLine $title
    Write-ReportLine "============================================================"
}

function BoolText($b) { if ($b) { "YES" } else { "NO" } }

function Get-RegistryUninstallApps {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    return $apps
}

function Clean-SqlOutputLines {
    param([object]$raw)
    if ($null -eq $raw) { return @() }
    $lines = @()
    foreach ($item in @($raw)) {
        if ($null -eq $item) { continue }
        $s = $item.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        if ($s -match "^\(\d+\s+rows?\s+affected\)$") { continue }
        $lines += $s
    }
    return $lines
}

function Get-SqlYearFromVersion {
    param([string]$ver)
    if (-not $ver) { return "UNKNOWN" }
    $major = ($ver -split "\.")[0]
    switch ($major) {
        "16" { "SQL Server 2022" }
        "15" { "SQL Server 2019" }
        "14" { "SQL Server 2017" }
        "13" { "SQL Server 2016" }
        "12" { "SQL Server 2014" }
        "11" { "SQL Server 2012" }
        default { "UNKNOWN (major $major)" }
    }
}

function Get-SqlYearOnlyFromVersion {
    param([string]$ver)
    if (-not $ver) { return "UNKNOWN" }
    $major = ($ver -split "\.")[0]
    switch ($major) {
        "16" { "2022" }
        "15" { "2019" }
        "14" { "2017" }
        "13" { "2016" }
        "12" { "2014" }
        "11" { "2012" }
        default { "UNKNOWN" }
    }
}

function Find-VPNClients {
    $found = New-Object System.Collections.Generic.List[object]
    $apps = Get-RegistryUninstallApps

    $patterns = @(
        "Cisco AnyConnect", "Cisco Secure Client",
        "GlobalProtect", "Palo Alto Networks",
        "FortiClient", "Fortinet",
        "OpenVPN", "OpenVPN Connect",
        "WireGuard",
        "Pulse Secure", "Ivanti Secure Access",
        "Check Point VPN", "Check Point Endpoint Security",
        "SonicWall NetExtender",
        "NordVPN", "ExpressVPN", "Surfshark", "ProtonVPN"
    )

    foreach ($pat in $patterns) {
        $match = $apps | Where-Object { $_.DisplayName -like "*$pat*" }
        foreach ($m in $match) {
            $found.Add([PSCustomObject]@{
                source  = "installed_app"
                name    = $m.DisplayName
                version = $m.DisplayVersion
            })
        }
    }

    $svcPatterns = @(
        "OpenVPN*", "ovpn*", "TAP*", "Wintun*", "WireGuard*",
        "GlobalProtect*", "PanGPS*", "FortiClient*", "Cisco*AnyConnect*"
    )

    $services = Get-Service | Where-Object {
        foreach ($sp in $svcPatterns) {
            if ($_.Name -like $sp -or $_.DisplayName -like $sp) { return $true }
        }
        return $false
    }

    foreach ($s in $services) {
        $found.Add([PSCustomObject]@{
            source  = "service"
            name    = $s.DisplayName
            version = ""
        })
    }

    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceDescription -match "TAP|Wintun|OpenVPN|WireGuard|VPN"
    }

    foreach ($a in $adapters) {
        $found.Add([PSCustomObject]@{
            source  = "network_adapter"
            name    = $a.InterfaceDescription
            version = ""
        })
    }

    return $found | Sort-Object name -Unique
}

function Get-SqlInstances {
    $instKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (Test-Path $instKey) {
        $props = (Get-ItemProperty $instKey).PSObject.Properties |
        Where-Object { $_.Name -notlike "PS*" }
        return $props.Name
    }
    return @()
}

function Get-SqlInstanceId {
    param([string]$InstanceName)
    $instKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (Test-Path $instKey) {
        return (Get-ItemProperty $instKey).$InstanceName
    }
    return $null
}

function Get-SqlVersionInfo {
    param([string[]]$instances)
    $info = @()
    foreach ($inst in $instances) {
        $instId = Get-SqlInstanceId -InstanceName $inst
        $setupKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\Setup"
        if (Test-Path $setupKey) {
            $p = Get-ItemProperty $setupKey
            $info += [PSCustomObject]@{
                instance_name = $inst
                instance_id   = $instId
                edition       = $p.Edition
                version       = $p.Version
                patch_level   = $p.PatchLevel
                release_name  = Get-SqlYearFromVersion $p.Version
                release_year  = Get-SqlYearOnlyFromVersion $p.Version
            }
        }
    }
    return $info
}

function Use-SqlcmdAvailable {
    return [bool](Get-Command sqlcmd.exe -ErrorAction SilentlyContinue)
}

function Run-SqlQuery {
    param(
        [string]$ServerInstance,
        [string]$User,
        [string]$Password,
        [string]$Query,
        [string]$Database = "master"
    )

    if (Use-SqlcmdAvailable) {
        $tmpFile = Join-Path $env:TEMP ("kd_tmp_{0}.sql" -f ([guid]::NewGuid()))
        try {
            $Query | Out-File -FilePath $tmpFile -Encoding UTF8 -Force
            $cmd = "sqlcmd -S `"$ServerInstance`" -U `"$User`" -P `"$Password`" -d `"$Database`" -i `"$tmpFile`" -W -s `","" -h -1"
            $out = cmd.exe /c $cmd 2>&1
            return $out
        }
        finally { Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue }
    }
    else {
        Add-Type -AssemblyName System.Data
        $connStr = "Server=$ServerInstance;Database=$Database;User ID=$User;Password=$Password;TrustServerCertificate=True;Encrypt=False;"
        $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
        $conn.Open()
        $cmdObj = $conn.CreateCommand()
        $cmdObj.CommandText = $Query
        $reader = $cmdObj.ExecuteReader()

        $rows = @()
        while ($reader.Read()) {
            $vals = @()
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $vals += $reader.GetValue($i).ToString()
            }
            $rows += ($vals -join ",")
        }
        $reader.Close()
        $conn.Close()
        return $rows
    }
}

function Escape-TsqlLiteral {
    param([string]$s)
    if ($null -eq $s) { return "" }
    return ($s -replace "'", "''")
}

function Test-DbExists-WindowsAuth {
    param([string]$ServerInstance, [string]$DbName)
    $dbEsc = Escape-TsqlLiteral $DbName
    try {
        $out = sqlcmd -S $ServerInstance -E -Q "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE name=N'$dbEsc';" -h -1 -W 2>&1
        $clean = Clean-SqlOutputLines $out
        return ($clean -contains $DbName)
    }
    catch { return $false }
}

function Ensure-LoginAndGrants-WindowsAuth {
    param(
        [string]$ServerInstance,
        [string]$DbName,
        [string]$Login,
        [string]$Password,
        [switch]$MakeSysAdmin,
        [switch]$GrantDbOwner
    )

    if ($null -eq $GrantDbOwner) { $GrantDbOwner = $true }
    if ($null -eq $MakeSysAdmin) { $MakeSysAdmin = $false }

    $l = Escape-TsqlLiteral $Login
    $p = Escape-TsqlLiteral $Password
    $db = Escape-TsqlLiteral $DbName

    $srvBlocks = @()
    $srvBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = N'$l')"
    $srvBlocks += "BEGIN"
    if ([string]::IsNullOrEmpty($Password)) {
        $srvBlocks += "    -- No password supplied; skipping CREATE LOGIN"
    } else {
        $srvBlocks += "    CREATE LOGIN [$l] WITH PASSWORD = N'$p', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;"
    }
    $srvBlocks += "END"

    if ($MakeSysAdmin) {
        $srvBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id WHERE r.name='sysadmin' AND m.name=N'$l')"
        $srvBlocks += "BEGIN"
        $srvBlocks += "    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$l];"
        $srvBlocks += "END"
    }
    else {
        $srvBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE p.name = N'$l' AND sp.permission_name = 'VIEW SERVER STATE')"
        $srvBlocks += "BEGIN"
        $srvBlocks += "    GRANT VIEW SERVER STATE TO [$l];"
        $srvBlocks += "END"
        $srvBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE p.name = N'$l' AND sp.permission_name = 'VIEW ANY DEFINITION')"
        $srvBlocks += "BEGIN"
        $srvBlocks += "    GRANT VIEW ANY DEFINITION TO [$l];"
        $srvBlocks += "END"
    }

    $srvSql = ($srvBlocks -join "`r`n")

    $dbBlocks = @()
    $dbBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$l')"
    $dbBlocks += "BEGIN"
    $dbBlocks += "    CREATE USER [$l] FOR LOGIN [$l];"
    $dbBlocks += "END"
    if ($GrantDbOwner) {
        $dbBlocks += "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members drm JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE r.name = 'db_owner' AND m.name = N'$l')"
        $dbBlocks += "BEGIN"
        $dbBlocks += "    ALTER ROLE [db_owner] ADD MEMBER [$l];"
        $dbBlocks += "END"
    }
    $dbSql = ($dbBlocks -join "`r`n")

    $safeDb = $DbName -replace ']', ']]'
    $usePrefix = "USE [$safeDb];`r`n"
    $dbSqlFull = $usePrefix + $dbSql

    try {
        sqlcmd -S $ServerInstance -E -d master -Q $srvSql | Out-Null
        sqlcmd -S $ServerInstance -E -Q $dbSqlFull | Out-Null
        return $true
    }
    catch {
        Write-Host "Ensure-LoginAndGrants-WindowsAuth failed: $($_.Exception.Message)"
        return $false
    }
}

# ---------- NEW: TCP/IP and Network Configuration Checks ----------
function Get-InstanceNetworkConfig {
    param([string]$InstanceId)
    
    $result = [ordered]@{
        tcp_enabled       = $false
        tcp_port          = ""
        dynamic_ports     = ""
        port_type         = "UNKNOWN"
    }
    
    $tcpReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer\SuperSocketNetLib\Tcp"
    $ipAllReg = "$tcpReg\IPAll"
    
    if (Test-Path $tcpReg) {
        $tcpProps = Get-ItemProperty $tcpReg -ErrorAction SilentlyContinue
        $result.tcp_enabled = ($tcpProps.Enabled -eq 1)
    }
    
    if (Test-Path $ipAllReg) {
        $ipAllProps = Get-ItemProperty $ipAllReg -ErrorAction SilentlyContinue
        $result.tcp_port = $ipAllProps.TcpPort
        $result.dynamic_ports = $ipAllProps.TcpDynamicPorts
        
        if ($result.tcp_port -and $result.tcp_port.Trim() -ne "") {
            $result.port_type = "STATIC ($($result.tcp_port))"
        } elseif ($result.dynamic_ports -and $result.dynamic_ports.Trim() -ne "") {
            $result.port_type = "DYNAMIC"
        } else {
            $result.port_type = "NOT CONFIGURED"
        }
    }
    
    return $result
}

function Get-InstanceAuthMode {
    param([string]$InstanceId)
    
    $secReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer"
    if (Test-Path $secReg) {
        $props = Get-ItemProperty $secReg -ErrorAction SilentlyContinue
        $loginMode = $props.LoginMode
        switch ($loginMode) {
            1 { return @{ mode = "Windows Only"; mixed_mode = $false } }
            2 { return @{ mode = "Mixed Mode (SQL + Windows)"; mixed_mode = $true } }
            default { return @{ mode = "UNKNOWN ($loginMode)"; mixed_mode = $false } }
        }
    }
    return @{ mode = "UNKNOWN"; mixed_mode = $false }
}

function Get-ServiceStatus {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        return [ordered]@{
            exists       = $true
            status       = $svc.Status.ToString()
            start_type   = $svc.StartType.ToString()
            running      = ($svc.Status -eq "Running")
        }
    }
    return [ordered]@{
        exists       = $false
        status       = "NOT FOUND"
        start_type   = "N/A"
        running      = $false
    }
}

function Get-RecoveryModel {
    param([string]$ServerInstance, [string]$User, [string]$Password, [string]$DbName)
    try {
        $q = "SELECT recovery_model_desc FROM sys.databases WHERE name = N'$(Escape-TsqlLiteral $DbName)';"
        $result = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Query $q
        $clean = Clean-SqlOutputLines $result
        if ($clean.Count -gt 0) { return $clean[0] }
    } catch {}
    return "UNKNOWN"
}

function Get-UserServerPermissions {
    param([string]$ServerInstance, [string]$User, [string]$Password, [string]$LoginName)
    $perms = @{
        view_server_state   = $false
        view_any_definition = $false
        is_sysadmin         = $false
    }
    try {
        $loginEsc = Escape-TsqlLiteral $LoginName
        
        # Check sysadmin
        $sysadminQ = "SELECT COUNT(*) FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE r.name = 'sysadmin' AND p.name = N'$loginEsc';"
        $sysadminRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Query $sysadminQ
        $sysadminClean = Clean-SqlOutputLines $sysadminRes
        if ($sysadminClean.Count -gt 0 -and $sysadminClean[0] -gt 0) { $perms.is_sysadmin = $true }
        
        # Check VIEW SERVER STATE
        $vssQ = "SELECT COUNT(*) FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE p.name = N'$loginEsc' AND sp.permission_name = 'VIEW SERVER STATE';"
        $vssRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Query $vssQ
        $vssClean = Clean-SqlOutputLines $vssRes
        if ($vssClean.Count -gt 0 -and $vssClean[0] -gt 0) { $perms.view_server_state = $true }
        
        # Check VIEW ANY DEFINITION
        $vadQ = "SELECT COUNT(*) FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE p.name = N'$loginEsc' AND sp.permission_name = 'VIEW ANY DEFINITION';"
        $vadRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Query $vadQ
        $vadClean = Clean-SqlOutputLines $vadRes
        if ($vadClean.Count -gt 0 -and $vadClean[0] -gt 0) { $perms.view_any_definition = $true }
    } catch {}
    return $perms
}

function Get-UserDbRole {
    param([string]$ServerInstance, [string]$User, [string]$Password, [string]$DbName, [string]$LoginName)
    $roles = @{
        user_exists  = $false
        is_db_owner  = $false
        roles        = @()
    }
    try {
        $loginEsc = Escape-TsqlLiteral $LoginName
        
        # Check if user exists
        $userQ = "SELECT COUNT(*) FROM sys.database_principals WHERE name = N'$loginEsc';"
        $userRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Database $DbName -Query $userQ
        $userClean = Clean-SqlOutputLines $userRes
        if ($userClean.Count -gt 0 -and $userClean[0] -gt 0) { $roles.user_exists = $true }
        
        # Check db_owner
        $dboQ = "SELECT COUNT(*) FROM sys.database_role_members drm JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE r.name = 'db_owner' AND m.name = N'$loginEsc';"
        $dboRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Database $DbName -Query $dboQ
        $dboClean = Clean-SqlOutputLines $dboRes
        if ($dboClean.Count -gt 0 -and $dboClean[0] -gt 0) { $roles.is_db_owner = $true }
        
        # Get all roles
        $rolesQ = "SELECT r.name FROM sys.database_role_members drm JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id WHERE m.name = N'$loginEsc';"
        $rolesRes = Run-SqlQuery -ServerInstance $ServerInstance -User $User -Password $Password -Database $DbName -Query $rolesQ
        $rolesClean = Clean-SqlOutputLines $rolesRes
        $roles.roles = @($rolesClean)
    } catch {}
    return $roles
}

# ---------- Start ----------
$script:Report = ""
$JsonData = [ordered]@{}

# Ask server instance first
$server = Read-Host "Enter SQL Server Instance (default: localhost)"
if ([string]::IsNullOrWhiteSpace($server)) { $server = "localhost" }

# Show DB list using Windows auth
Write-Host ""
Write-Host "Existing databases (Windows Auth):"
try {
    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name;" 
} catch {
    Write-Host "Unable to list databases with Windows Authentication."
}

# Ask DB name until exists
do {
    $dbName = Read-Host "Enter Database Name"
    $dbExists = Test-DbExists-WindowsAuth -ServerInstance $server -DbName $dbName
    if (-not $dbExists) {
        Write-Host "Database not found. Please enter correct Database Name."
    }
} while (-not $dbExists)

# Ask if existing SQL login to use
$useExisting = Read-Host "Use existing SQL login? (y/n)"
$useExisting = $useExisting.Trim().ToLower()

$sqlUser = $null
$sqlPass = $null
$userCreated = $false
$loginOK = $false

if ($useExisting -match "^(y|yes)$") {
    $sqlUser = Read-Host "Enter existing SQL login name"
    $pwdSecure = Read-Host "Enter password" -AsSecureString
    $sqlPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwdSecure)
    )

    do {
        try {
            Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query "SELECT 1;" | Out-Null
            $loginOK = $true
        } catch {
            $loginOK = $false
            Write-Host "Login failed. Please re-enter credentials."
            $sqlUser = Read-Host "Enter existing SQL login name"
            $pwdSecure = Read-Host "Enter password" -AsSecureString
            $sqlPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwdSecure)
            )
        }
    } while (-not $loginOK)
} else {
    $sqlUser = Read-Host "Enter NEW login name to create"
    $pwdSecure = Read-Host "Enter NEW password" -AsSecureString
    $sqlPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwdSecure)
    )

    $userCreated = Ensure-LoginAndGrants-WindowsAuth -ServerInstance $server -DbName $dbName -Login $sqlUser -Password $sqlPass -GrantDbOwner

    try {
        Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query "SELECT 1;" | Out-Null
        $loginOK = $true
    } catch {
        $loginOK = $false
    }
}

# ---------- System Configuration ----------
Section "SYSTEM CONFIGURATION"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem

Write-ReportLine ("Computer Name   : {0}" -f $env:COMPUTERNAME)
Write-ReportLine ("OS              : {0} {1}" -f $os.Caption, $os.Version)
Write-ReportLine ("Build Number    : {0}" -f $os.BuildNumber)
Write-ReportLine ("Architecture    : {0}" -f $os.OSArchitecture)
Write-ReportLine ("Manufacturer    : {0}" -f $cs.Manufacturer)
Write-ReportLine ("Model           : {0}" -f $cs.Model)
Write-ReportLine ("RAM (GB)        : {0:N2}" -f ($cs.TotalPhysicalMemory / 1GB))
Write-ReportLine ("Last Boot Time  : {0}" -f $os.LastBootUpTime)

$JsonData.system_configuration = [ordered]@{
    computer_name  = $env:COMPUTERNAME
    os_caption     = $os.Caption
    os_version     = $os.Version
    build_number   = $os.BuildNumber
    architecture   = $os.OSArchitecture
    manufacturer   = $cs.Manufacturer
    model          = $cs.Model
    ram_gb         = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
    last_boot_time = $os.LastBootUpTime.ToString("o")
}

# ---------- SQL Server Installation ----------
Section "SQL SERVER INSTALLATION"

$instances = @(Get-SqlInstances)
$sqlInstalled = ($instances.Count -gt 0)
$verInfo = @()
$yearsOnly = @()

if ($sqlInstalled) {
    $verInfo = @(Get-SqlVersionInfo -instances $instances)
    $yearsOnly = @($verInfo.release_year | Sort-Object -Unique)
}

Write-ReportLine ("SQL Server Installed? : {0}" -f (BoolText $sqlInstalled))

if ($yearsOnly.Count -eq 0) {
    Write-ReportLine "SQL Server Version    : UNKNOWN"
} elseif ($yearsOnly.Count -eq 1) {
    Write-ReportLine ("SQL Server Version    : {0}" -f $yearsOnly[0])
} else {
    Write-ReportLine ("SQL Server Version    : {0}" -f ($yearsOnly -join ", "))
}

if ($sqlInstalled) {
    Write-ReportLine ""
    Write-ReportLine "Detected Instances:"
    foreach ($i in $instances) { Write-ReportLine "  - $i" }

    Write-ReportLine ""
    Write-ReportLine "Instance Version Details:"
    foreach ($v in $verInfo) {
        Write-ReportLine ("  Instance: {0} | Edition: {1} | Version: {2} | Patch: {3} | Release: {4}" -f $v.instance_name, $v.edition, $v.version, $v.patch_level, $v.release_name)
    }
}

$JsonData.sql_server_installation = [ordered]@{
    sql_server_installed = $sqlInstalled
    sql_server_version   = $(if ($yearsOnly.Count -eq 1) { $yearsOnly[0] } else { @($yearsOnly) })
    sql_server_instances = @($verInfo)
}

# ---------- SQL Server Network Configuration (TCP/IP, Mixed Mode) ----------
Section "SQL SERVER NETWORK CONFIGURATION"

$instanceNetworkConfigs = @()

foreach ($inst in $instances) {
    $instId = Get-SqlInstanceId -InstanceName $inst
    $netConfig = Get-InstanceNetworkConfig -InstanceId $instId
    $authMode = Get-InstanceAuthMode -InstanceId $instId
    
    Write-ReportLine ""
    Write-ReportLine "Instance: $inst"
    Write-ReportLine ("  TCP/IP Enabled?      : {0}" -f (BoolText $netConfig.tcp_enabled))
    Write-ReportLine ("  TCP Port             : {0}" -f $netConfig.tcp_port)
    Write-ReportLine ("  Dynamic Ports        : {0}" -f $netConfig.dynamic_ports)
    Write-ReportLine ("  Port Type            : {0}" -f $netConfig.port_type)
    Write-ReportLine ("  Authentication Mode  : {0}" -f $authMode.mode)
    Write-ReportLine ("  Mixed Mode Enabled?  : {0}" -f (BoolText $authMode.mixed_mode))
    
    $instanceNetworkConfigs += [ordered]@{
        instance_name       = $inst
        instance_id         = $instId
        tcp_enabled         = $netConfig.tcp_enabled
        tcp_port            = $netConfig.tcp_port
        dynamic_ports       = $netConfig.dynamic_ports
        port_type           = $netConfig.port_type
        authentication_mode = $authMode.mode
        mixed_mode_enabled  = $authMode.mixed_mode
    }
}

$JsonData.sql_network_configuration = @($instanceNetworkConfigs)

# ---------- SQL Services Status ----------
Section "SQL SERVICES STATUS"

# SQL Server service
$primaryInstance = if ($instances -contains "MSSQLSERVER") { "MSSQLSERVER" } else { $instances[0] }
$sqlSvcName = if ($primaryInstance -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$primaryInstance" }
$sqlSvcStatus = Get-ServiceStatus -ServiceName $sqlSvcName

Write-ReportLine ("SQL Server Service ({0}):" -f $sqlSvcName)
Write-ReportLine ("  Exists?    : {0}" -f (BoolText $sqlSvcStatus.exists))
Write-ReportLine ("  Status     : {0}" -f $sqlSvcStatus.status)
Write-ReportLine ("  Start Type : {0}" -f $sqlSvcStatus.start_type)
Write-ReportLine ("  Running?   : {0}" -f (BoolText $sqlSvcStatus.running))

# SQL Agent service
$agentSvcName = if ($primaryInstance -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$primaryInstance" }
$agentSvcStatus = Get-ServiceStatus -ServiceName $agentSvcName

Write-ReportLine ""
Write-ReportLine ("SQL Server Agent ({0}):" -f $agentSvcName)
Write-ReportLine ("  Exists?    : {0}" -f (BoolText $agentSvcStatus.exists))
Write-ReportLine ("  Status     : {0}" -f $agentSvcStatus.status)
Write-ReportLine ("  Start Type : {0}" -f $agentSvcStatus.start_type)
Write-ReportLine ("  Running?   : {0}" -f (BoolText $agentSvcStatus.running))

# SQL Browser service
$browserSvcStatus = Get-ServiceStatus -ServiceName "SQLBrowser"

Write-ReportLine ""
Write-ReportLine "SQL Browser Service:"
Write-ReportLine ("  Exists?    : {0}" -f (BoolText $browserSvcStatus.exists))
Write-ReportLine ("  Status     : {0}" -f $browserSvcStatus.status)
Write-ReportLine ("  Start Type : {0}" -f $browserSvcStatus.start_type)
Write-ReportLine ("  Running?   : {0}" -f (BoolText $browserSvcStatus.running))

$JsonData.sql_services = [ordered]@{
    sql_server_service = $sqlSvcStatus
    sql_agent_service  = $agentSvcStatus
    sql_browser_service = $browserSvcStatus
}

# ---------- SQL Remote Access ----------
Section "SQL REMOTE ACCESS"

$remoteEnabled = $null
if ($sqlInstalled -and $loginOK) {
    try {
        $remoteQ = "EXEC sp_configure 'remote access';"
        $remoteRes = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Query $remoteQ
        $remoteClean = Clean-SqlOutputLines $remoteRes
        $remoteEnabled = ($remoteClean -join "`n") -match ",1$"
        Write-ReportLine ("Remote Access Enabled? : {0}" -f (BoolText $remoteEnabled))
    } catch {
        Write-ReportLine "Remote Access Enabled? : UNKNOWN (query failed)"
    }
} else {
    Write-ReportLine "Remote Access Enabled? : UNKNOWN (not connected)"
}

$JsonData.sql_remote_access = [ordered]@{
    remote_access_enabled = $remoteEnabled
}

# ---------- SQL Login / Database Checks ----------
Section "SQL LOGIN / DATABASE CHECKS"

Write-ReportLine ("Login Successful?  : {0}" -f (BoolText $loginOK))
Write-ReportLine ("Database Exists?   : {0}" -f (BoolText $dbExists))
Write-ReportLine ("User Created Now?  : {0}" -f (BoolText $userCreated))

# Recovery Model
$recoveryModel = "UNKNOWN"
if ($loginOK -and $dbExists) {
    $recoveryModel = Get-RecoveryModel -ServerInstance $server -User $sqlUser -Password $sqlPass -DbName $dbName
    Write-ReportLine ("Recovery Model     : {0}" -f $recoveryModel)
    
    $recoveryOK = ($recoveryModel -eq "FULL")
    Write-ReportLine ("Recovery Model OK for CDC? : {0}" -f (BoolText $recoveryOK))
}

$JsonData.sql_login_database = [ordered]@{
    login_successful    = $loginOK
    database_exists     = $dbExists
    user_created        = $userCreated
    recovery_model      = $recoveryModel
    recovery_model_ok   = ($recoveryModel -eq "FULL")
}

# ---------- User Permissions ----------
Section "USER PERMISSIONS"

$serverPerms = @{ view_server_state = $false; view_any_definition = $false; is_sysadmin = $false }
$dbRoles = @{ user_exists = $false; is_db_owner = $false; roles = @() }

if ($loginOK) {
    $serverPerms = Get-UserServerPermissions -ServerInstance $server -User $sqlUser -Password $sqlPass -LoginName $sqlUser
    $dbRoles = Get-UserDbRole -ServerInstance $server -User $sqlUser -Password $sqlPass -DbName $dbName -LoginName $sqlUser
    
    Write-ReportLine "Server-Level Permissions for '$sqlUser':"
    Write-ReportLine ("  VIEW SERVER STATE    : {0}" -f (BoolText $serverPerms.view_server_state))
    Write-ReportLine ("  VIEW ANY DEFINITION  : {0}" -f (BoolText $serverPerms.view_any_definition))
    Write-ReportLine ("  Is Sysadmin?         : {0}" -f (BoolText $serverPerms.is_sysadmin))
    
    Write-ReportLine ""
    Write-ReportLine "Database-Level Roles for '$sqlUser' in '$dbName':"
    Write-ReportLine ("  User Exists in DB?   : {0}" -f (BoolText $dbRoles.user_exists))
    Write-ReportLine ("  Is db_owner?         : {0}" -f (BoolText $dbRoles.is_db_owner))
    if ($dbRoles.roles.Count -gt 0) {
        Write-ReportLine ("  All Roles            : {0}" -f ($dbRoles.roles -join ", "))
    }
}

$JsonData.user_permissions = [ordered]@{
    login_name           = $sqlUser
    view_server_state    = $serverPerms.view_server_state
    view_any_definition  = $serverPerms.view_any_definition
    is_sysadmin          = $serverPerms.is_sysadmin
    user_exists_in_db    = $dbRoles.user_exists
    is_db_owner          = $dbRoles.is_db_owner
    database_roles       = @($dbRoles.roles)
}

# ---------- Tables and CDC ----------
Section "TABLES AND CDC STATUS"

$tablesList = @()
$cdcDb = $false
$cdcTableDetails = @()

if ($loginOK -and $dbExists) {
    # Check CDC on database
    try {
        $cdcQ = "SELECT is_cdc_enabled FROM sys.databases WHERE name=N'$(Escape-TsqlLiteral $dbName)';"
        $cdcRes = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Query $cdcQ
        $cdcResClean = Clean-SqlOutputLines $cdcRes
        if ($cdcResClean -match "1") { $cdcDb = $true }
    } catch { $cdcDb = $false }

    Write-ReportLine ("CDC Enabled on Database? : {0}" -f (BoolText $cdcDb))
    Write-ReportLine ""
    
    # List tables
    Write-ReportLine "Tables:"
    try {
        $tq = "SELECT s.name + '.' + t.name FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id ORDER BY s.name, t.name;"
        $tablesRaw = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query $tq
        $tablesClean = Clean-SqlOutputLines $tablesRaw

        if ($tablesClean.Count -eq 0) {
            Write-ReportLine "  (No tables found)"
        } else {
            foreach ($t in $tablesClean) {
                Write-ReportLine ("  - {0}" -f $t)
                $tablesList += $t
            }
        }
    } catch {
        Write-ReportLine "  (Failed to list tables)"
    }

    # CDC per table
    Write-ReportLine ""
    Write-ReportLine "CDC Enabled per Table:"
    try {
        $cdcTQ = "SELECT s.name + '.' + t.name AS TableName, t.is_tracked_by_cdc FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id ORDER BY TableName;"
        $cdcRaw = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query $cdcTQ
        $cdcClean = Clean-SqlOutputLines $cdcRaw

        if ($cdcClean.Count -eq 0) {
            Write-ReportLine "  (No tables found)"
        } else {
            $cdcEnabledCount = 0
            $cdcDisabledCount = 0
            foreach ($row in $cdcClean) {
                $parts = $row -split ","
                if ($parts.Count -ge 2) {
                    $tname = $parts[0].Trim()
                    $enabled = ($parts[1].Trim() -eq "1")
                    Write-ReportLine ("  {0} : CDC = {1}" -f $tname, (BoolText $enabled))
                    if ($enabled) { $cdcEnabledCount++ } else { $cdcDisabledCount++ }
                    $cdcTableDetails += [ordered]@{
                        table_name  = $tname
                        cdc_enabled = $enabled
                    }
                }
            }
            Write-ReportLine ""
            Write-ReportLine ("  Summary: {0} tables with CDC enabled, {1} without" -f $cdcEnabledCount, $cdcDisabledCount)
        }
    } catch {
        Write-ReportLine "  (Failed to check CDC per table)"
    }
}

$JsonData.tables_and_cdc = [ordered]@{
    cdc_enabled_on_database = $cdcDb
    tables                  = @($tablesList)
    tables_count            = $tablesList.Count
    cdc_enabled_on_tables   = @($cdcTableDetails)
}

# ---------- Network / Firewall ----------
Section "NETWORK / FIREWALL"

$portListening = $false
try {
    $conns = @(Get-NetTCPConnection -LocalPort 1433 -State Listen -ErrorAction SilentlyContinue)
    if ($conns.Count -gt 0) { $portListening = $true }
} catch { $portListening = $false }

Write-ReportLine ("TCP Port 1433 Listening?     : {0}" -f (BoolText $portListening))

$fwRuleExists = $false
$fwRuleDetails = @()
try {
    $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue)
    foreach ($r in $rules) {
        $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        if ($pf -and $pf.Protocol -eq "TCP" -and $pf.LocalPort -contains "1433") {
            $fwRuleExists = $true
            $fwRuleDetails += [ordered]@{
                name        = $r.DisplayName
                enabled     = $r.Enabled
                direction   = $r.Direction.ToString()
                action      = $r.Action.ToString()
                local_port  = $pf.LocalPort
            }
        }
    }
} catch { $fwRuleExists = $false }

Write-ReportLine ("Firewall Inbound Rule 1433?  : {0}" -f (BoolText $fwRuleExists))

if ($fwRuleDetails.Count -gt 0) {
    Write-ReportLine ""
    Write-ReportLine "Firewall Rules for Port 1433:"
    foreach ($fr in $fwRuleDetails) {
        Write-ReportLine ("  - {0} (Action: {1})" -f $fr.name, $fr.action)
    }
}

$JsonData.network_firewall = [ordered]@{
    tcp_1433_listening         = $portListening
    firewall_inbound_rule_1433 = $fwRuleExists
    firewall_rules             = @($fwRuleDetails)
}

# ---------- VPN Checks ----------
Section "VPN INSTALLATION"
$vpnFound = @(Find-VPNClients)

if ($vpnFound.Count -gt 0) {
    Write-ReportLine "VPN Evidence Detected:"
    foreach ($v in $vpnFound) {
        if ($v.version) {
            Write-ReportLine ("  - [{0}] {1} (Version: {2})" -f $v.source, $v.name, $v.version)
        } else {
            Write-ReportLine ("  - [{0}] {1}" -f $v.source, $v.name)
        }
    }
} else {
    Write-ReportLine "VPN Evidence Detected: NONE"
}

$JsonData.vpn_installation = [ordered]@{
    vpn_detected = ($vpnFound.Count -gt 0)
    vpn_evidence = @($vpnFound)
}

# ---------- DMS Readiness Summary ----------
Section "DMS READINESS SUMMARY"

$dmsReady = $true
$dmsIssues = @()

# Check TCP/IP enabled
$primaryNetConfig = $instanceNetworkConfigs | Where-Object { $_.instance_name -eq $primaryInstance } | Select-Object -First 1
if (-not $primaryNetConfig.tcp_enabled) {
    $dmsReady = $false
    $dmsIssues += "TCP/IP is NOT enabled"
}

# Check port 1433
if ($primaryNetConfig.tcp_port -ne "1433") {
    $dmsReady = $false
    $dmsIssues += "TCP Port is NOT set to 1433 (current: $($primaryNetConfig.tcp_port))"
}

# Check Mixed Mode
if (-not $primaryNetConfig.mixed_mode_enabled) {
    $dmsReady = $false
    $dmsIssues += "Mixed Mode Authentication is NOT enabled"
}

# Check SQL Agent
if (-not $agentSvcStatus.running) {
    $dmsReady = $false
    $dmsIssues += "SQL Server Agent is NOT running"
}

# Check Recovery Model
if ($recoveryModel -ne "FULL") {
    $dmsReady = $false
    $dmsIssues += "Recovery Model is NOT FULL (current: $recoveryModel)"
}

# Check CDC on database
if (-not $cdcDb) {
    $dmsReady = $false
    $dmsIssues += "CDC is NOT enabled on database"
}

# Check firewall
if (-not $fwRuleExists) {
    $dmsReady = $false
    $dmsIssues += "No firewall inbound rule for port 1433"
}

# Check port listening
if (-not $portListening) {
    $dmsReady = $false
    $dmsIssues += "Port 1433 is NOT listening"
}

# Check user permissions
if (-not $serverPerms.is_sysadmin -and (-not $serverPerms.view_server_state -or -not $serverPerms.view_any_definition)) {
    $dmsReady = $false
    $dmsIssues += "User missing server permissions (VIEW SERVER STATE / VIEW ANY DEFINITION)"
}

if (-not $dbRoles.is_db_owner) {
    $dmsReady = $false
    $dmsIssues += "User is NOT db_owner in database"
}

Write-ReportLine ""
Write-ReportLine ("DMS Ready? : {0}" -f (BoolText $dmsReady))
Write-ReportLine ""

if ($dmsReady) {
    Write-ReportLine "All DMS prerequisites are met!"
} else {
    Write-ReportLine "Issues Found:"
    foreach ($issue in $dmsIssues) {
        Write-ReportLine ("  - {0}" -f $issue)
    }
    Write-ReportLine ""
    Write-ReportLine "Run Prepare-MSSQL-SourceForDMS.ps1 to fix these issues."
}

$JsonData.dms_readiness = [ordered]@{
    dms_ready  = $dmsReady
    issues     = @($dmsIssues)
}

# ---------- Inputs Summary ----------
Section "INPUTS SUMMARY"
Write-ReportLine "Server Instance : $server"
Write-ReportLine "Username        : $sqlUser"
Write-ReportLine "Database        : $dbName"
Write-ReportLine ("User Created?   : {0}" -f (BoolText $userCreated))
Write-ReportLine "(Password hidden in report)"

$JsonData.inputs = [ordered]@{
    server_instance     = $server
    username            = $sqlUser
    database_name       = $dbName
    password_provided   = $true
    used_existing_login = ($useExisting -match "^(y|yes)$")
    user_created        = $userCreated
}

# ---------- Save Report + JSON ----------
Section "REPORT OUTPUT"
$docPath = Join-Path $env:USERPROFILE "Documents"
$outTxt = Join-Path $docPath "System_details.txt"
$outJson = Join-Path $docPath "System_details.json"

try {
    $script:Report | Out-File -FilePath $outTxt -Encoding UTF8 -Force
    Write-ReportLine "Report saved to: $outTxt"
} catch {
    Write-ReportLine "Failed to write TXT report."
}

try {
    $JsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $outJson -Encoding UTF8 -Force
    Write-ReportLine "JSON saved to:   $outJson"
} catch {
    Write-ReportLine "Failed to write JSON report."
}

Write-ReportLine ""
Write-ReportLine "Done."
