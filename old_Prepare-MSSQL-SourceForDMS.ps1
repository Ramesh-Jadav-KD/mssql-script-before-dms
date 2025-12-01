<#
Prepare-MSSQL-SourceForDMS.ps1
All-in-one script to prepare SQL Server 2019 (or later) as AWS DMS source.

Features:
- Detect instances, enable TCP/IP (primary fixed to 1433)
- Enable remote access + Mixed Mode
- Configure firewall inbound TCP 1433
- Start SQL Browser + SQL Server Agent
- Create/validate SQL login and grant db_owner
- Enable CDC on DB + all user tables
- Restart services and print final status

Optional: restrict firewall to specific subnets
Example:
  .\Prepare-MSSQL-SourceForDMS.ps1 -AllowedSubnets "10.0.0.0/16","10.1.0.0/16"
#>

param(
    [string[]]$AllowedSubnets = @()   # empty => allow any source
)

$ErrorActionPreference = "Stop"
$PrimaryPort = 1433

function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red }

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail "Run this script as Administrator."
        exit 1
    }
    Write-Ok "Running as Administrator."
}

function Get-SqlInstances {
    Write-Info "Detecting SQL Server instances..."
    $instRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (-not (Test-Path $instRegPath)) {
        Write-Fail "No SQL Server instances found."
        exit 1
    }
    $props = Get-ItemProperty $instRegPath
    $names = $props.PSObject.Properties |
        Where-Object { $_.Name -notmatch "^PS" } |
        Select-Object -ExpandProperty Name

    Write-Ok ("Found instances: " + ($names -join ", "))
    return @{ Props=$props; Names=$names }
}

function Get-ServerName([string]$InstanceName) {
    if ($InstanceName -eq "MSSQLSERVER") { return "." }
    return ".\$InstanceName"
}

function Configure-Instance-Network {
    param([string]$InstanceName, [string]$InstanceId, [bool]$IsPrimary)

    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer\SuperSocketNetLib\Tcp"
    $ipAllReg = Join-Path $tcpReg "IPAll"
    if (-not (Test-Path $tcpReg)) {
        Write-Warn "TCP registry not found for $InstanceName"
        return
    }

    Set-ItemProperty -Path $tcpReg -Name "Enabled" -Value 1 -Type DWord
    if (-not (Test-Path $ipAllReg)) { New-Item -Path $ipAllReg -Force | Out-Null }

    if ($IsPrimary) {
        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "" -Type String
        Set-ItemProperty -Path $ipAllReg -Name "TcpPort"         -Value "$PrimaryPort" -Type String
        Write-Ok "[$InstanceName] TCP enabled + fixed port $PrimaryPort"
    } else {
        Set-ItemProperty -Path $ipAllReg -Name "TcpPort"         -Value ""  -Type String
        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "0" -Type String
        Write-Ok "[$InstanceName] TCP enabled + dynamic ports"
    }
}

function Restart-Instance-Service {
    param([string]$InstanceName)

    $svc = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }
    Write-Info "Restarting SQL service: $svc"
    try {
        Restart-Service -Name $svc -Force -ErrorAction Stop
        Write-Ok "Restarted $svc"
    } catch {
        Write-Warn "Restart failed for $svc. Trying stop/start..."
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Start-Service -Name $svc -ErrorAction Stop
        Write-Ok "Started $svc"
    }
}

function Enable-MixedModeAndRemoteAccess {
    param([string]$InstanceName, [string]$InstanceId)

    $server = Get-ServerName $InstanceName

    Write-Info "Enabling remote access + Mixed Mode for $InstanceName"

    $sql = @"
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'remote access', 1;
RECONFIGURE;
"@
    sqlcmd -S $server -E -Q $sql | Out-Null
    Write-Ok "[$InstanceName] Remote access enabled."

    # Mixed mode: LoginMode=2
    $secReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer"
    if (Test-Path $secReg) {
        Set-ItemProperty -Path $secReg -Name "LoginMode" -Value 2 -Type DWord
        Write-Ok "[$InstanceName] Mixed Mode enabled."
    }
}

function Ensure-Firewall1433 {
    Write-Info "Configuring Windows Firewall inbound TCP $PrimaryPort..."
    $ruleName = "SQL Server TCP $PrimaryPort (Auto)"

    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-Ok "Firewall rule already exists."
        return
    }

    if ($AllowedSubnets.Count -gt 0) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort `
            -RemoteAddress ($AllowedSubnets -join ",") `
            -Action Allow | Out-Null
        Write-Ok "Firewall rule created restricted to: $($AllowedSubnets -join ', ')"
    } else {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort `
            -Action Allow | Out-Null
        Write-Ok "Firewall rule created for all sources."
    }
}

function Ensure-SqlBrowser {
    Write-Info "Ensuring SQL Browser is running..."
    $browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
    if (-not $browser) { Write-Warn "SQL Browser service not found."; return }

    Set-Service -Name "SQLBrowser" -StartupType Automatic
    if ($browser.Status -ne "Running") {
        Start-Service -Name "SQLBrowser"
        Write-Ok "SQL Browser started."
    } else {
        Write-Ok "SQL Browser already running."
    }
}

function Ensure-SqlAgent {
    param([string]$InstanceName)

    $agentSvc = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }
    Write-Info "Ensuring SQL Server Agent is running: $agentSvc"
    $svc = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warn "Agent service not found for $InstanceName"; return }

    Set-Service -Name $agentSvc -StartupType Automatic
    if ($svc.Status -ne "Running") {
        Start-Service -Name $agentSvc
        Write-Ok "Agent started."
    } else {
        Write-Ok "Agent already running."
    }
}

function Prompt-ForDbAndLogin {
    param([string]$PrimaryInstance)

    $server = Get-ServerName $PrimaryInstance

    # Show DBs for user help
    Write-Info "Existing databases:"
    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name"

    $dbName = Read-Host "Enter target database name to prepare (example: tr8421)"
    $login = Read-Host "Enter existing SQL login name"
    $pwd   = Read-Host "Enter password" -AsSecureString
    $pwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd)
    )

    Write-Info "Validating login credentials..."
    try {
        sqlcmd -S $server -U $login -P $pwdPlain -d $dbName -Q "SELECT 1" | Out-Null
        Write-Ok "Login validated successfully."
    } catch {
        Write-Fail "Login validation failed. Check username/password."
        exit 1
    }

    return @{ Db=$dbName; Login=$login; Password=$pwdPlain }
}

function Ensure-LoginAndGrants {
    param(
        [string]$PrimaryInstance,
        [string]$DbName,
        [string]$Login,
        [string]$Password
    )

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Mapping existing SQL login to database user + granting db_owner on $DbName..."
    $sqlGrant = @"
USE [$DbName];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Login')
BEGIN
    CREATE USER [$Login] FOR LOGIN [$Login];
END
ALTER ROLE [db_owner] ADD MEMBER [$Login];
"@
    sqlcmd -S $server -E -Q $sqlGrant | Out-Null
    Write-Ok "User mapped and granted db_owner."
}

function Set-RecoveryModel-And-Backup {
    param([string]$PrimaryInstance, [string]$DbName, [string]$BackupPath = "NUL")

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Setting database recovery model to FULL for $DbName..."
    $sqlRecovery = @"
ALTER DATABASE [$DbName] SET RECOVERY FULL;
"@
    sqlcmd -S $server -E -Q $sqlRecovery | Out-Null
    Write-Ok "Recovery model set to FULL."

    Write-Info "Taking full database backup for $DbName..."
    $sqlBackup = @"
BACKUP DATABASE [$DbName] TO DISK = '$BackupPath';
"@
    sqlcmd -S $server -E -Q $sqlBackup | Out-Null
    Write-Ok "Full backup completed (log chain initialized)."
}

function Grant-DmsUserPermissions {
    param([string]$PrimaryInstance, [string]$Login)

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Granting VIEW SERVER STATE and VIEW ANY DEFINITION to $Login..."
    $sqlGrants = @"
USE master;
GO
GRANT VIEW SERVER STATE TO [$Login];
GO
GRANT VIEW ANY DEFINITION TO [$Login];
GO
"@
    sqlcmd -S $server -E -Q $sqlGrants | Out-Null
    Write-Ok "Permissions granted: VIEW SERVER STATE, VIEW ANY DEFINITION."
}

function Enable-CDC-Database-And-Tables {
    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Enabling CDC at database level for $DbName..."
    $sqlDbCdc = @"
USE [$DbName];
IF (SELECT is_cdc_enabled FROM sys.databases WHERE name = DB_NAME()) = 0
BEGIN
    EXEC sys.sp_cdc_enable_db;
END
"@
    sqlcmd -S $server -E -Q $sqlDbCdc | Out-Null
    Write-Ok "CDC enabled on database."

    Write-Info "Enabling CDC on all user tables..."
    $sqlTablesCdc = @"
USE [$DbName];
DECLARE @schema sysname, @table sysname, @sql nvarchar(max);

DECLARE cur CURSOR FAST_FORWARD FOR
SELECT s.name, t.name
FROM sys.tables t
JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE t.is_ms_shipped = 0;

OPEN cur;
FETCH NEXT FROM cur INTO @schema, @table;
WHILE @@FETCH_STATUS = 0
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM cdc.change_tables ct
        JOIN sys.tables t2 ON ct.source_object_id=t2.object_id
        JOIN sys.schemas s2 ON t2.schema_id=s2.schema_id
        WHERE s2.name=@schema AND t2.name=@table
    )
    BEGIN
        SET @sql = N'EXEC sys.sp_cdc_enable_table
            @source_schema = N''' + @schema + ''',
            @source_name   = N''' + @table + ''',
            @role_name     = NULL,
            @supports_net_changes = 0;';
        EXEC sp_executesql @sql;
    END
    FETCH NEXT FROM cur INTO @schema, @table;
END
CLOSE cur; DEALLOCATE cur;
"@
    sqlcmd -S $server -E -Q $sqlTablesCdc | Out-Null
    Write-Ok "CDC enabled on all user tables."
}

# ================= MAIN =================
Assert-Admin

$instData = Get-SqlInstances
$instancesProps = $instData.Props
$instanceNames  = $instData.Names

$PrimaryInstance = if ($instanceNames -contains "MSSQLSERVER") { "MSSQLSERVER" } else { $instanceNames[0] }
Write-Ok "Primary instance: $PrimaryInstance"

# Configure network for all instances
foreach ($inst in $instanceNames) {
    $instId = $instancesProps.$inst
    Configure-Instance-Network -InstanceName $inst -InstanceId $instId -IsPrimary ($inst -eq $PrimaryInstance)
}

# Restart SQL services so TCP settings take effect
foreach ($inst in $instanceNames) {
    Restart-Instance-Service -InstanceName $inst
}

# Enable remote access + mixed mode on each instance, restart primary at end
foreach ($inst in $instanceNames) {
    $instId = $instancesProps.$inst
    Enable-MixedModeAndRemoteAccess -InstanceName $inst -InstanceId $instId
}

Restart-Instance-Service -InstanceName $PrimaryInstance

# Firewall + browser + agent
Ensure-Firewall1433
Ensure-SqlBrowser
Ensure-SqlAgent -InstanceName $PrimaryInstance

# Prompt for DB/login and ensure it
$cred = Prompt-ForDbAndLogin -PrimaryInstance $PrimaryInstance
Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

# Grant DMS-specific permissions (VIEW SERVER STATE, VIEW ANY DEFINITION) required for CDC log reading
Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.Login

# Set recovery model to FULL and take a full backup (required for DMS CDC)
Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db

# Enable CDC
Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

# Final restart to make agent/cdc clean
Restart-Instance-Service -InstanceName $PrimaryInstance
Ensure-SqlAgent -InstanceName $PrimaryInstance

# ================= FINAL REPORT =================
Write-Host "`n========== FINAL STATUS =========="

foreach ($inst in $instanceNames) {
    $instId   = $instancesProps.$inst
    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp"
    $ipAllReg = Join-Path $tcpReg "IPAll"

    $enabled = (Get-ItemProperty $tcpReg).Enabled
    $tcpPort = (Get-ItemProperty $ipAllReg).TcpPort
    $dynPort = (Get-ItemProperty $ipAllReg).TcpDynamicPorts

    Write-Host "Instance: $inst"
    Write-Host "  TCP Enabled   : $enabled"
    Write-Host "  TCP Port      : '$tcpPort'"
    Write-Host "  Dynamic Ports : '$dynPort'"
}

Write-Host "`nListener check for Primary Port ($PrimaryPort):"
netstat -ano | findstr $PrimaryPort

Write-Ok "`nDONE."
Write-Host "DB Prepared : $($cred.Db)"
Write-Host "Login       : $($cred.Login)"
Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"
