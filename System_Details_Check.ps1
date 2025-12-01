<# 
System_Details_Check.ps1 (No-admin-prompt version)

Creates:
  1) $env:USERPROFILE\Documents\System_details.txt
  2) $env:USERPROFILE\Documents\System_details.json

Checks:
- System configuration
- MSSQL installed or not
- SQL versions and instance details
- Credential login test
- Database exists or not
- Table list (cleaned)
- CDC enabled on DB and tables (cleaned)
- Remote access enabled or not
- SQL Server Agent running or not
- TCP 1433 listening or not
- Firewall inbound rule for 1433
- VPN installed or not (apps + services + adapters)
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

function Get-SqlVersionInfo {
    param([string[]]$instances)
    $info = @()
    foreach ($inst in $instances) {
        $instId = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL").$inst
        $setupKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\Setup"
        if (Test-Path $setupKey) {
            $p = Get-ItemProperty $setupKey
            $info += [PSCustomObject]@{
                instance_name = $inst
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

# --- DB exists check using Windows auth ---
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

# --- Ensure login, user, sysadmin + db_owner using Windows auth ---
function Ensure-LoginAndGrants-WindowsAuth {
    param(
        [string]$ServerInstance,
        [string]$DbName,
        [string]$Login,
        [string]$Password
    )

    $l = Escape-TsqlLiteral $Login
    $p = Escape-TsqlLiteral $Password
    $db = Escape-TsqlLiteral $DbName

    $q = @"
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = N'$l')
BEGIN
    CREATE LOGIN [$l] WITH PASSWORD = N'$p', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
END

-- grant sysadmin (full server perms)
IF NOT EXISTS (
    SELECT 1
    FROM sys.server_role_members rm
    JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
    WHERE r.name='sysadmin' AND m.name=N'$l'
)
BEGIN
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$l];
END

USE [$db];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$l')
BEGIN
    CREATE USER [$l] FOR LOGIN [$l];
END
ALTER ROLE [db_owner] ADD MEMBER [$l];
"@

    try {
        sqlcmd -S $ServerInstance -E -Q $q | Out-Null
        return $true
    }
    catch { return $false }
}

# ---------- Start ----------
$Report = ""
$JsonData = [ordered]@{}

# Ask server instance first (needed to list DBs)
$server = Read-Host "Enter SQL Server Instance (default: localhost)"
if ([string]::IsNullOrWhiteSpace($server)) { $server = "localhost" }

# Show DB list using Windows auth
Write-Host ""
Write-Host "Existing databases (Windows Auth):"
try {
    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name;" 
} catch {
    Write-Host "Unable to list databases with Windows Authentication. You may not have admin rights."
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

    # Validate login (silent retry)
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

    # Create login + grants using Windows auth
    $userCreated = Ensure-LoginAndGrants-WindowsAuth -ServerInstance $server -DbName $dbName -Login $sqlUser -Password $sqlPass

    # Validate new login
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
    last_boot_time = $os.LastBootUpTime
}

# ---------- SQL SERVER Installation Checks ----------
Section "SQL SERVER INSTALLATION"

$instances = @(Get-SqlInstances)
$sqlInstalled = ($instances.Count -gt 0)

$verInfo = @()
$yearsOnly = @()

if ($sqlInstalled) {
    $verInfo = @(Get-SqlVersionInfo -instances $instances)
    $yearsOnly = @($verInfo.release_year | Sort-Object -Unique)
}

Write-ReportLine ("sql_server = {0}" -f (BoolText $sqlInstalled))

if ($yearsOnly.Count -eq 0) {
    Write-ReportLine "sql_server_version = UNKNOWN"
} elseif ($yearsOnly.Count -eq 1) {
    Write-ReportLine ("sql_server_version = {0}" -f $yearsOnly[0])
} else {
    Write-ReportLine ("sql_server_version = {0}" -f ($yearsOnly -join ", "))
}

if ($sqlInstalled) {
    Write-ReportLine ""
    Write-ReportLine "Detected Instances:"
    foreach ($i in $instances) { Write-ReportLine "  - $i" }

    Write-ReportLine ""
    Write-ReportLine "Instance Version Details:"
    foreach ($v in $verInfo) {
        Write-ReportLine ("  Instance: {0} | Edition: {1} | Version: {2} | Patch: {3} | Release: {4}" -f `
            $v.instance_name, $v.edition, $v.version, $v.patch_level, $v.release_name)
    }
}

$JsonData.sql_server_installation = [ordered]@{
    sql_server           = $(if ($sqlInstalled) { "yes" } else { "no" })
    sql_server_version   = $(if ($yearsOnly.Count -eq 1) { $yearsOnly[0] } else { @($yearsOnly) })
    sql_server_instances = @($verInfo)
}

# ---------- SQL LOGIN / DATABASE CHECKS ----------
Section "SQL LOGIN / DATABASE CHECKS"
Write-ReportLine ("Login Successful? : {0}" -f (BoolText $loginOK))
Write-ReportLine ("Database Exists?  : {0}" -f (BoolText $dbExists))
Write-ReportLine ("User Created?     : {0}" -f (BoolText $userCreated))

$tablesList = @()
$cdcDb = $false
$cdcTableDetails = @()

if ($loginOK -and $dbExists) {
    Write-ReportLine ""
    Write-ReportLine "Tables:"
    try {
        $tq = @"
SELECT s.name + '.' + t.name
FROM sys.tables t
JOIN sys.schemas s ON t.schema_id = s.schema_id
ORDER BY s.name, t.name;
"@
        $tablesRaw = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query $tq
        $tablesClean = Clean-SqlOutputLines $tablesRaw

        if ($tablesClean.Count -eq 0) {
            Write-ReportLine "  (No tables found)"
        } else {
            foreach ($t in $tablesClean) {
                Write-ReportLine ("  Table Name: {0}" -f $t)
                $tablesList += $t
            }
        }
    } catch {
        Write-ReportLine "  (Failed to list tables)"
    }

    try {
        $cdcQ = "SELECT is_cdc_enabled FROM sys.databases WHERE name='$dbName';"
        $cdcRes = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Query $cdcQ
        $cdcResClean = Clean-SqlOutputLines $cdcRes
        if ($cdcResClean -match "1") { $cdcDb = $true }
    } catch { $cdcDb = $false }

    Write-ReportLine ""
    Write-ReportLine ("CDC Enabled on Database? : {0}" -f (BoolText $cdcDb))

    Write-ReportLine ""
    Write-ReportLine "CDC Enabled per Table:"
    try {
        $cdcTQ = @"
SELECT s.name + '.' + t.name AS TableName,
       t.is_tracked_by_cdc
FROM sys.tables t
JOIN sys.schemas s ON t.schema_id = s.schema_id
ORDER BY TableName;
"@
        $cdcRaw = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Database $dbName -Query $cdcTQ
        $cdcClean = Clean-SqlOutputLines $cdcRaw

        if ($cdcClean.Count -eq 0) {
            Write-ReportLine "  (No tables found)"
        } else {
            foreach ($row in $cdcClean) {
                $parts = $row -split ","
                if ($parts.Count -ge 2) {
                    $tname = $parts[0].Trim()
                    $enabled = ($parts[1].Trim() -eq "1")
                    Write-ReportLine ("  Table Name: {0} | CDC Enabled: {1}" -f $tname, (BoolText $enabled))

                    $cdcTableDetails += [ordered]@{
                        table_name  = $tname
                        cdc_enabled = $enabled
                    }
                }
            }
        }
    } catch {
        Write-ReportLine "  (Failed to check CDC per table)"
    }
}

$JsonData.sql_login_database_checks = [ordered]@{
    login_successful        = $loginOK
    database_exists         = $dbExists
    tables                  = @($tablesList)
    cdc_enabled_on_database = $cdcDb
    cdc_enabled_on_tables   = @($cdcTableDetails)
}

# ---------- INPUTS (print once, final) ----------
Section "INPUTS"
Write-ReportLine "Server Instance : $server"
Write-ReportLine "Username        : $sqlUser"
Write-ReportLine "Database        : $dbName"
Write-ReportLine ("User Created?   : {0}" -f (BoolText $userCreated))
Write-ReportLine "(Password hidden in report)"

$JsonData.inputs = [ordered]@{
    server_instance          = $server
    username                 = $sqlUser
    database_name            = $dbName
    password_provided        = $true
    used_existing_login      = ($useExisting -match "^(y|yes)$")
    user_created             = $(if ($userCreated) { "yes" } else { "no" })
}

# ---------- Remote Access / Agent ----------
$remoteEnabled = $null
$agentRunning = $false

if ($sqlInstalled) {
    Section "SQL REMOTE ACCESS / AGENT"
    try {
        $remoteQ = "EXEC sp_configure 'remote access';"
        $remoteRes = Run-SqlQuery -ServerInstance $server -User $sqlUser -Password $sqlPass -Query $remoteQ
        $remoteClean = Clean-SqlOutputLines $remoteRes
        $remoteEnabled = ($remoteClean -join "`n") -match ",1$"
        Write-ReportLine ("Remote Access Enabled? : {0}" -f (BoolText $remoteEnabled))
    } catch {
        $remoteEnabled = $null
        Write-ReportLine "Remote Access Enabled? : UNKNOWN (login/query failed)"
    }

    try {
        $agent = Get-Service -Name "SQLSERVERAGENT" -ErrorAction SilentlyContinue
        if ($agent -and $agent.Status -eq "Running") { $agentRunning = $true }
    } catch { $agentRunning = $false }

    Write-ReportLine ("SQL Server Agent Running? : {0}" -f (BoolText $agentRunning))
}

$JsonData.sql_remote_access_agent = [ordered]@{
    remote_access_enabled    = $remoteEnabled
    sql_server_agent_running = $agentRunning
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
try {
    $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue)
    foreach ($r in $rules) {
        $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        if ($pf -and $pf.Protocol -eq "TCP" -and $pf.LocalPort -contains "1433") {
            $fwRuleExists = $true
            break
        }
    }
} catch { $fwRuleExists = $false }

Write-ReportLine ("Firewall Inbound Rule 1433?  : {0}" -f (BoolText $fwRuleExists))

$JsonData.network_firewall = [ordered]@{
    tcp_1433_listening         = $portListening
    firewall_inbound_rule_1433 = $fwRuleExists
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

# ---------- Save Report + JSON ----------
Section "REPORT OUTPUT"
$docPath = Join-Path $env:USERPROFILE "Documents"
$outTxt = Join-Path $docPath "System_details.txt"
$outJson = Join-Path $docPath "System_details.json"

try {
    $Report | Out-File -FilePath $outTxt -Encoding UTF8 -Force
    Write-ReportLine "Report saved to: $outTxt"
} catch {
    Write-ReportLine "Failed to write TXT report."
}

try {
    $JsonData | ConvertTo-Json -Depth 8 | Out-File -FilePath $outJson -Encoding UTF8 -Force
    Write-ReportLine "JSON saved to:   $outJson"
} catch {
    Write-ReportLine "Failed to write JSON report."
}

Write-ReportLine ""
Write-ReportLine "Done."
