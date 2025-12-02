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
    [string[]]$AllowedSubnets = @(),
    [string]$DmsUsername = '',
    [string]$DmsPassword = '',
    [switch]$GrantSysadmin = $false,
    [switch]$NonInteractive = $false
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

function Get-ScriptDir {
    if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
    if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) { return Split-Path -Parent $PSCommandPath }
    try { return (Get-Location).ProviderPath } catch { return '.' }
}

$script:logPath = Join-Path (Get-ScriptDir) "Prepare-MSSQL-SourceForDMS.log"

function Write-Log([string]$msg) {
    $entry = "$(Get-Date -Format o)`t$msg"
    try { Add-Content -Path $script:logPath -Value $entry -ErrorAction Stop } catch { Write-Warn "Failed to write log: $_" }
}

function Test-AlreadyConfigured {
    param([string]$DbName, [string]$Login)
    $scriptDir = Get-ScriptDir
    $marker = Join-Path $scriptDir ".prepare_marker_$DbName"
    return Test-Path $marker
}

function Invoke-SQL-Complete-Setup {
    param(
        [Parameter(Mandatory=$true)][string]$SqlScriptPath,
        [Parameter(Mandatory=$true)][string]$PrimaryInstance,
        [Parameter(Mandatory=$true)][string]$DbName,
        [string]$Login,
        [string]$Password
    )
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Executing SQL script: $SqlScriptPath against server: $server"
    try {
        $orig = Get-Content -Path $SqlScriptPath -Raw -ErrorAction Stop
        $safeDbName = $DbName -replace "'", "''"
        $safeDmsUser = $Login -replace "'", "''"
        $safeDmsPwd  = $Password -replace "'", "''"

        $patternDb = "DECLARE\s+@DatabaseName\s+NVARCHAR\(128\)\s*=.*?;"
        $patternUser = "DECLARE\s+@DMSUsername\s+NVARCHAR\(128\)\s*=.*?;"
        $patternPwd = "DECLARE\s+@DMSPassword\s+NVARCHAR\(256\)\s*=.*?;"
        $patternBackup = "DECLARE\s+@BackupPath\s+NVARCHAR\(500\)\s*=.*?;"

        $declDb = "DECLARE @DatabaseName NVARCHAR(128) = N'$safeDbName';"
        $declUser = "DECLARE @DMSUsername NVARCHAR(128) = N'$safeDmsUser';"
        $declPwd = "DECLARE @DMSPassword NVARCHAR(256) = N'$safeDmsPwd';"
        $declBackup = "DECLARE @BackupPath NVARCHAR(500) = N'NUL';"

        $new = $orig
        if ($orig -match $patternDb -or $orig -match $patternUser -or $orig -match $patternPwd) {
            $new = $new -replace $patternDb, ''
            $new = $new -replace $patternUser, ''
            $new = $new -replace $patternPwd, ''
            $new = $new -replace $patternBackup, ''
        }
        $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $new

        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))
        Set-Content -Path $tempPath -Value $new -Encoding UTF8 -Force

        if ($Login -and $Password) {
            sqlcmd -S $server -U $Login -P $Password -i $tempPath | Out-Null
        } else {
            sqlcmd -S $server -E -i $tempPath | Out-Null
        }

        Write-Log "Executed SQL verification script: $SqlScriptPath against $DbName"
    } catch {
        Write-Warn "Invoke-SQL-Complete-Setup failed: $_"
        throw
    } finally {
        if ($tempPath -and (Test-Path $tempPath)) { Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

function Get-SqlInstances {
    Write-Info "Detecting SQL Server instances..."
    $instRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    if (-not (Test-Path $instRegPath)) {
        Write-Fail "No SQL Server instances found."
        exit 1
    }
    $props = Get-ItemProperty $instRegPath
    $names = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name
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
    if (-not (Test-Path $tcpReg)) { Write-Warn "TCP registry not found for $InstanceName"; return }
    Set-ItemProperty -Path $tcpReg -Name "Enabled" -Value 1 -Type DWord
    if (-not (Test-Path $ipAllReg)) { New-Item -Path $ipAllReg -Force | Out-Null }
    if ($IsPrimary) {
        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "" -Type String
        Set-ItemProperty -Path $ipAllReg -Name "TcpPort" -Value "$PrimaryPort" -Type String
        Write-Ok "[$InstanceName] TCP enabled + fixed port $PrimaryPort"
    } else {
        Set-ItemProperty -Path $ipAllReg -Name "TcpPort" -Value "" -Type String
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
    $sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'remote access', 1; RECONFIGURE;"
    sqlcmd -S $server -E -Q $sql | Out-Null
    Write-Ok "[$InstanceName] Remote access enabled."
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
    if ($existingRule) { Write-Ok "Firewall rule already exists."; return }
    if ($AllowedSubnets.Count -gt 0) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort -RemoteAddress ($AllowedSubnets -join ",") -Action Allow | Out-Null
        Write-Ok "Firewall rule created restricted to: $($AllowedSubnets -join ', ')"
    } else {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort -Action Allow | Out-Null
        Write-Ok "Firewall rule created for all sources."
    }
}

function Ensure-SqlBrowser {
    Write-Info "Ensuring SQL Browser is running..."
    $browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
    if (-not $browser) { Write-Warn "SQL Browser service not found."; return }
    Set-Service -Name "SQLBrowser" -StartupType Automatic
    if ($browser.Status -ne "Running") { Start-Service -Name "SQLBrowser"; Write-Ok "SQL Browser started." }
    else { Write-Ok "SQL Browser already running." }
}

function Ensure-SqlAgent {
    param([string]$InstanceName)
    $agentSvc = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }
    Write-Info "Ensuring SQL Server Agent is running: $agentSvc"
    $svc = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Warn "Agent service not found for $InstanceName"; return }
    Set-Service -Name $agentSvc -StartupType Automatic
    if ($svc.Status -ne "Running") { Start-Service -Name $agentSvc; Write-Ok "Agent started." }
    else { Write-Ok "Agent already running." }
}

function Prompt-ForDbAndLogin {
    param([string]$PrimaryInstance)
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Existing databases:"
    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name"
    $dbName = Read-Host "Enter target database name to prepare (example: tr8421)"
    $login = Read-Host "Enter existing SQL login name"
    $pwd = Read-Host "Enter password" -AsSecureString
    $pwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
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
    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Mapping existing SQL login to database user + granting db_owner on $DbName..."
    $sqlGrant = "USE [$DbName]; IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Login') BEGIN CREATE USER [$Login] FOR LOGIN [$Login]; END; ALTER ROLE [db_owner] ADD MEMBER [$Login];"
    sqlcmd -S $server -E -Q $sqlGrant | Out-Null
    Write-Ok "User mapped and granted db_owner."
}

function Set-RecoveryModel-And-Backup {
    param([string]$PrimaryInstance, [string]$DbName, [string]$BackupPath = "NUL")
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Setting database recovery model to FULL for $DbName..."
    sqlcmd -S $server -E -Q "ALTER DATABASE [$DbName] SET RECOVERY FULL;" | Out-Null
    Write-Ok "Recovery model set to FULL."
    Write-Info "Taking full database backup for $DbName..."
    sqlcmd -S $server -E -Q "BACKUP DATABASE [$DbName] TO DISK = '$BackupPath';" | Out-Null
    Write-Ok "Full backup completed (log chain initialized)."
}

function Grant-DmsUserPermissions {
    param([string]$PrimaryInstance, [string]$Login)
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Granting VIEW SERVER STATE and VIEW ANY DEFINITION to $Login..."
    $sqlGrants = "GRANT VIEW SERVER STATE TO [$Login]; GRANT VIEW ANY DEFINITION TO [$Login];"
    $grantOut = sqlcmd -S $server -E -d master -Q $sqlGrants 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok "Permissions granted: VIEW SERVER STATE, VIEW ANY DEFINITION." }
    else { Write-Warn "Grant execution returned non-zero exit code: $LASTEXITCODE"; Write-Warn $grantOut }
    $verifySql = "SET NOCOUNT ON; SELECT p.name AS principal_name, perm.permission_name FROM sys.server_permissions perm JOIN sys.server_principals p ON perm.grantee_principal_id = p.principal_id WHERE p.name = N'$Login' AND perm.permission_name IN ('VIEW SERVER STATE','VIEW ANY DEFINITION');"
    $verifyOut = sqlcmd -S $server -E -d master -Q $verifySql 2>&1 | Out-String
    if ($verifyOut -match 'VIEW SERVER STATE' -and $verifyOut -match 'VIEW ANY DEFINITION') {
        Write-Ok "Verification: both VIEW SERVER STATE and VIEW ANY DEFINITION present for $Login."
    } else {
        Write-Warn "Verification: some permissions may be missing for $Login."
    }
}

function Ensure-DmsServerLogin {
    param([string]$PrimaryInstance, [string]$DmsUser, [string]$DmsPwd, [string]$DbName, [switch]$GrantSysadmin)
    if (-not $DmsUser -or -not $DmsPwd) { Write-Warn "DMS username/password not provided, skipping DMS login creation."; return }
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Ensuring DMS server login exists: $DmsUser (server: $server)"
    $safeUser = $DmsUser -replace "'", "''"
    $safePwd  = $DmsPwd -replace "'", "''"
    $safeDb   = $DbName -replace "'", "''"

    $sqlLines = @()
    $sqlLines += "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$safeUser' AND type_desc = 'SQL_LOGIN')"
    $sqlLines += "BEGIN"
    $sqlLines += "    CREATE LOGIN [$safeUser] WITH PASSWORD = N'$safePwd', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;"
    $sqlLines += "    PRINT 'Login created: $safeUser';"
    $sqlLines += "END"
    $sqlLines += "ELSE"
    $sqlLines += "BEGIN"
    $sqlLines += "    PRINT 'Login already exists: $safeUser';"
    $sqlLines += "END"
    $sqlLines += "GRANT VIEW SERVER STATE TO [$safeUser];"
    $sqlLines += "GRANT VIEW ANY DEFINITION TO [$safeUser];"
    $sqlLines += "IF (DB_ID(N'$safeDb') IS NOT NULL)"
    $sqlLines += "BEGIN"
    $sqlLines += "    USE [$safeDb];"
    $sqlLines += "    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$safeUser')"
    $sqlLines += "    BEGIN"
    $sqlLines += "        CREATE USER [$safeUser] FOR LOGIN [$safeUser];"
    $sqlLines += "    END"
    $sqlLines += "    ALTER ROLE [db_owner] ADD MEMBER [$safeUser];"
    $sqlLines += "    PRINT 'Mapped to DB and granted db_owner.';"
    $sqlLines += "END"

    if ($GrantSysadmin) {
        $sqlLines += "IF NOT EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id WHERE r.name='sysadmin' AND p.name=N'$safeUser')"
        $sqlLines += "BEGIN"
        $sqlLines += "    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$safeUser];"
        $sqlLines += "    PRINT 'Added to sysadmin role: $safeUser';"
        $sqlLines += "END"
    }

    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))
    Set-Content -Path $temp -Value $sqlLines -Encoding UTF8 -Force
    try {
        $out = sqlcmd -S $server -E -d master -i $temp 2>&1 | Out-String
        Write-Log "Ensure-DmsServerLogin output: $out"
        Write-Host $out
    } catch {
        Write-Warn "Failed to ensure DMS login: $_"
        throw
    } finally {
        if (Test-Path $temp) { Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue }
    }
}

function Enable-CDC-Database-And-Tables {
    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)
    $server = Get-ServerName $PrimaryInstance
    Write-Info "Enabling CDC at database level for $DbName..."
    $sqlDbCdc = "USE [$DbName]; IF (SELECT is_cdc_enabled FROM sys.databases WHERE name = DB_NAME()) = 0 BEGIN EXEC sys.sp_cdc_enable_db; END"
    sqlcmd -S $server -E -Q $sqlDbCdc | Out-Null
    Write-Ok "CDC enabled on database."

    Write-Info "Enabling CDC on all user tables..."
    $cdcLines = @()
    $cdcLines += "USE [$DbName];"
    $cdcLines += "DECLARE @schema sysname, @table sysname, @sql nvarchar(max);"
    $cdcLines += "DECLARE cur CURSOR FAST_FORWARD FOR SELECT s.name, t.name FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id WHERE t.is_ms_shipped = 0;"
    $cdcLines += "OPEN cur;"
    $cdcLines += "FETCH NEXT FROM cur INTO @schema, @table;"
    $cdcLines += "WHILE @@FETCH_STATUS = 0"
    $cdcLines += "BEGIN"
    $cdcLines += "    IF NOT EXISTS (SELECT 1 FROM cdc.change_tables ct JOIN sys.tables t2 ON ct.source_object_id=t2.object_id JOIN sys.schemas s2 ON t2.schema_id=s2.schema_id WHERE s2.name=@schema AND t2.name=@table)"
    $cdcLines += "    BEGIN"
    $cdcLines += "        SET @sql = N'EXEC sys.sp_cdc_enable_table @source_schema = N''' + @schema + ''', @source_name = N''' + @table + ''', @role_name = NULL, @supports_net_changes = 0;';"
    $cdcLines += "        EXEC sp_executesql @sql;"
    $cdcLines += "    END"
    $cdcLines += "    FETCH NEXT FROM cur INTO @schema, @table;"
    $cdcLines += "END"
    $cdcLines += "CLOSE cur; DEALLOCATE cur;"

    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))
    Set-Content -Path $temp -Value $cdcLines -Encoding UTF8 -Force
    try {
        sqlcmd -S $server -E -i $temp | Out-Null
    } finally {
        if (Test-Path $temp) { Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue }
    }
    Write-Ok "CDC enabled on all user tables."
}

# ================= MAIN =================
Assert-Admin

$instData = Get-SqlInstances
$instancesProps = $instData.Props
$instanceNames  = $instData.Names

$PrimaryInstance = if ($instanceNames -contains "MSSQLSERVER") { "MSSQLSERVER" } else { $instanceNames[0] }
Write-Ok "Primary instance: $PrimaryInstance"

foreach ($inst in $instanceNames) {
    $instId = $instancesProps.$inst
    Configure-Instance-Network -InstanceName $inst -InstanceId $instId -IsPrimary ($inst -eq $PrimaryInstance)
}

foreach ($inst in $instanceNames) { Restart-Instance-Service -InstanceName $inst }

foreach ($inst in $instanceNames) {
    $instId = $instancesProps.$inst
    Enable-MixedModeAndRemoteAccess -InstanceName $inst -InstanceId $instId
}

Restart-Instance-Service -InstanceName $PrimaryInstance

Ensure-Firewall1433
Ensure-SqlBrowser
Ensure-SqlAgent -InstanceName $PrimaryInstance

$cred = Prompt-ForDbAndLogin -PrimaryInstance $PrimaryInstance
Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password
Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.Login
Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db
Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

Restart-Instance-Service -InstanceName $PrimaryInstance
Ensure-SqlAgent -InstanceName $PrimaryInstance

# ================= FINAL REPORT =================
Write-Host ""
Write-Host "========== FINAL STATUS =========="

foreach ($inst in $instanceNames) {
    $instId   = $instancesProps.$inst
    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp"
    $ipAllReg = Join-Path $tcpReg "IPAll"
    $enabled = (Get-ItemProperty $tcpReg).Enabled
    $tcpPort = (Get-ItemProperty $ipAllReg).TcpPort
    $dynPort = (Get-ItemProperty $ipAllReg).TcpDynamicPorts
    Write-Host "Instance: $inst"
    Write-Host "  TCP Enabled   : $enabled"
    Write-Host "  TCP Port      : $tcpPort"
    Write-Host "  Dynamic Ports : $dynPort"
}

Write-Host ""
Write-Host "Listener check for Primary Port ($PrimaryPort):"
netstat -ano | findstr $PrimaryPort

Write-Host ""
Write-Ok "DONE."
Write-Host "DB Prepared : $($cred.Db)"
Write-Host "Login       : $($cred.Login)"
Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"
Write-Host "========================================" -ForegroundColor Cyan

$skipPhase1 = Test-AlreadyConfigured -DbName $cred.Db -Login $cred.Login

if (-not $skipPhase1) {
    Write-Log "Phase 1 complete: Network, Services, Firewall configured"
}

Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password
Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.Login
Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db
Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

if (-not $skipPhase1) { Restart-Instance-Service -InstanceName $PrimaryInstance }
Ensure-SqlAgent -InstanceName $PrimaryInstance

Write-Log "SUCCESS: Configuration complete for DB: $($cred.Db)"

$scriptDir = Get-ScriptDir
$marker = Join-Path $scriptDir ".prepare_marker_$($cred.Db)"
try { Set-Content -Path $marker -Value "Configured $($cred.Db) on $(Get-Date -Format o)" -Force } catch { Write-Warn "Unable to write marker file: $_" }

# ================= PHASE 2 =================
Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "PHASE 2: Comprehensive Database Setup (external SQL)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$scriptDir = Get-ScriptDir
$sqlScriptPath = Join-Path $scriptDir 'Setup-DMS-Complete.sql'

if (-not $DmsUsername) {
    $DmsUsername = $cred.Login
    Write-Info "No DMS username provided on CLI - using existing login from earlier prompt: $DmsUsername"
}
if (-not $DmsPassword) {
    $DmsPassword = $cred.Password
}

if ($DmsUsername -and $DmsPassword) {
    Ensure-DmsServerLogin -PrimaryInstance $PrimaryInstance -DmsUser $DmsUsername -DmsPwd $DmsPassword -DbName $cred.Db -GrantSysadmin:$GrantSysadmin
}

if (-not (Test-Path $sqlScriptPath)) {
    Write-Warn "External SQL file not found at: $sqlScriptPath"
    $templateContent = @'
-- Setup-DMS-Complete.sql
-- Template: override DECLARE variables at the top when running via the PowerShell script.
-- DO NOT store production passwords in this file.

-- Example DECLAREs (uncomment and modify):
-- DECLARE @DatabaseName NVARCHAR(128) = N'tr8421';
-- DECLARE @DMSUsername NVARCHAR(128) = N'dms_user';
-- DECLARE @DMSPassword NVARCHAR(256) = N'Password123';
-- DECLARE @BackupPath NVARCHAR(500) = N'NUL';

-- Add your Phase 2 SQL logic below.

PRINT 'Template file created. Edit this file to customize Phase 2 SQL.';
'@
    Set-Content -Path $sqlScriptPath -Value $templateContent -Encoding UTF8 -Force
    Write-Host "A template file was created: $sqlScriptPath" -ForegroundColor Yellow
    Write-Host "Edit the file and re-run the script." -ForegroundColor Yellow
} else {
    Write-Info "Found SQL setup script: $sqlScriptPath"
    Write-Host ""
    $autoRun = Read-Host "Run SQL setup verification from external file now? (Y/N)"
    if ($autoRun -ieq 'Y' -or $autoRun -ieq 'YES') {
        Invoke-SQL-Complete-Setup -SqlScriptPath $sqlScriptPath -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password
        Write-Log "Phase 2 complete: external SQL verification executed"
    } else {
        Write-Host "Manual SQL verification option available. Open in SSMS:" -ForegroundColor Yellow
        Write-Host "  File: $sqlScriptPath" -ForegroundColor Yellow
    }
}

# ================= FINAL STATUS =================
Write-Host ""
Write-Host "========== FINAL STATUS =========="

foreach ($inst in $instanceNames) {
    $instId   = $instancesProps.$inst
    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp"
    $ipAllReg = Join-Path $tcpReg "IPAll"
    $enabled = (Get-ItemProperty $tcpReg).Enabled
    $tcpPort = (Get-ItemProperty $ipAllReg).TcpPort
    $dynPort = (Get-ItemProperty $ipAllReg).TcpDynamicPorts
    Write-Host "Instance: $inst"
    Write-Host "  TCP Enabled   : $enabled"
    Write-Host "  TCP Port      : $tcpPort"
    Write-Host "  Dynamic Ports : $dynPort"
}

Write-Host ""
Write-Host "Listener check for Primary Port ($PrimaryPort):"
netstat -ano | findstr $PrimaryPort

Write-Host ""
Write-Ok "DONE."
Write-Host "DB Prepared : $($cred.Db)"
Write-Host "Login       : $($cred.Login)"
Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"
Write-Host ""
$theLogPath = $script:logPath
Write-Host "Execution log saved to: $theLogPath"
Write-Host "To review: Get-Content $theLogPath"
