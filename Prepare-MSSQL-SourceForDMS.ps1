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
    [string[]]$AllowedSubnets = @(),   # empty => allow any source
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

# Robust script directory resolver: prefer PSScriptRoot, then PSCommandPath, then current location
function Get-ScriptDir {
    if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }
    if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) { return Split-Path -Parent $PSCommandPath }
    try { return (Get-Location).ProviderPath } catch { return '.' }
}

# --- Small helper: simple logging to a file in the script directory
function Write-Log([string]$msg) {
    $scriptDir = Get-ScriptDir
    # Use script scope so other parts of the script can reference the path safely
    if (-not $script:logPath) { $script:logPath = Join-Path $scriptDir "Prepare-MSSQL-SourceForDMS.log" }
    $entry = "$(Get-Date -Format o) `t$msg"
    try { Add-Content -Path $script:logPath -Value $entry -ErrorAction Stop } catch { Write-Warn "Failed to write log: $_" }
}

# --- Test whether the database has already been prepared. Minimal, file-marker based.
function Test-AlreadyConfigured {
    param([string]$DbName, [string]$Login)
    $scriptDir = Get-ScriptDir
    $marker = Join-Path $scriptDir ".prepare_marker_$DbName"
    return Test-Path $marker
}

# --- Minimal invoker for the SQL verification script used in Phase 2
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
    # Create a temp script that injects the desired variables into the top of the SQL
    try {
        $orig = Get-Content -Path $SqlScriptPath -Raw -ErrorAction Stop

        # Escape single quotes in values
        $safeDbName = $DbName -replace "'", "''"
        # If the Login/Password provided are the admin credentials used to run the script,
        # they may also be the DMS username/password you want to set. We'll use the provided
        # $Login as DMS username and an optional separate DMS password if you passed one via DbName (not typical).
        # To be explicit: use $DbName (database), and re-use $Login as DMS username and $Password as DMS password.
        $safeDmsUser = $Login -replace "'", "''"
        $safeDmsPwd  = $Password -replace "'", "''"

        # Replace top-level DECLAREs if they exist; otherwise prepend custom DECLAREs
        $patternDb = "DECLARE\s+@DatabaseName\s+NVARCHAR\(128\)\s*=.*?;"
        $patternUser = "DECLARE\s+@DMSUsername\s+NVARCHAR\(128\)\s*=.*?;"
        $patternPwd = "DECLARE\s+@DMSPassword\s+NVARCHAR\(256\)\s*=.*?;"
        $patternBackup = "DECLARE\s+@BackupPath\s+NVARCHAR\(500\)\s*=.*?;"

        $declDb = "DECLARE @DatabaseName NVARCHAR(128) = N'$safeDbName';"
        $declUser = "DECLARE @DMSUsername NVARCHAR(128) = N'$safeDmsUser';"
        $declPwd = "DECLARE @DMSPassword NVARCHAR(256) = N'$safeDmsPwd';"
        $declBackup = "DECLARE @BackupPath NVARCHAR(500) = N'NUL';"

        $new = $orig
        $replaced = $false
        if ($orig -match $patternDb -or $orig -match $patternUser -or $orig -match $patternPwd) {
            # remove existing DECLARE lines
            $new = $new -replace $patternDb, ''
            $new = $new -replace $patternUser, ''
            $new = $new -replace $patternPwd, ''
            $new = $new -replace $patternBackup, ''
            # Prepend our DECLAREs
            $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $new
            $replaced = $true
        } else {
            # No declares found; just prepend
            $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $orig
        }

        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))
        Set-Content -Path $tempPath -Value $new -Encoding UTF8 -Force

        if ($Login -and $Password) {
            sqlcmd -S $server -U $Login -P $Password -i $tempPath | Out-Null
        } else {
            sqlcmd -S $server -E -i $tempPath | Out-Null
        }

        Write-Log "Executed SQL verification script: $SqlScriptPath (temp: $tempPath) against $DbName"
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
GRANT VIEW SERVER STATE TO [$Login];
GRANT VIEW ANY DEFINITION TO [$Login];
"@
    # Run the grants in the master database (server-scope permissions require master)
    $grantOut = sqlcmd -S $server -E -d master -Q $sqlGrants 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Permissions granted: VIEW SERVER STATE, VIEW ANY DEFINITION."
    } else {
        Write-Warn "Grant execution returned non-zero exit code: $LASTEXITCODE"
        Write-Warn $grantOut
    }

    # Verification: query server permissions for this principal to ensure grants exist
    $verifySql = "SET NOCOUNT ON; SELECT p.name AS principal_name, perm.permission_name FROM sys.server_permissions perm JOIN sys.server_principals p ON perm.grantee_principal_id = p.principal_id WHERE p.name = N'$Login' AND perm.permission_name IN ('VIEW SERVER STATE','VIEW ANY DEFINITION');"
    $verifyOut = sqlcmd -S $server -E -d master -Q $verifySql 2>&1 | Out-String
    if ($verifyOut -match 'VIEW SERVER STATE' -and $verifyOut -match 'VIEW ANY DEFINITION') {
        Write-Ok "Verification: both VIEW SERVER STATE and VIEW ANY DEFINITION present for $Login."
    } elseif ($verifyOut -match 'VIEW SERVER STATE') {
        Write-Warn "Verification: VIEW SERVER STATE present, VIEW ANY DEFINITION missing for $Login. Output:`n$verifyOut"
    } elseif ($verifyOut -match 'VIEW ANY DEFINITION') {
        Write-Warn "Verification: VIEW ANY DEFINITION present, VIEW SERVER STATE missing for $Login. Output:`n$verifyOut"
    } else {
        Write-Warn "Verification failed: no matching server-level permissions found for $Login. Output:`n$verifyOut"
    }
}

# Ensure a server-level DMS login exists, optionally grant sysadmin, and map to the database
function Ensure-DmsServerLogin {
    param(
        [string]$PrimaryInstance,
        [string]$DmsUser,
        [string]$DmsPwd,
        [string]$DbName,
        [switch]$GrantSysadmin
    )

    if (-not $DmsUser -or -not $DmsPwd) { Write-Warn "DMS username/password not provided, skipping DMS login creation."; return }

    $server = Get-ServerName $PrimaryInstance
    Write-Info "Ensuring DMS server login exists: $DmsUser (server: $server)"

    # Escape single quotes for SQL literal
    $safeUser = $DmsUser -replace "'", "''"
    $safePwd  = $DmsPwd -replace "'", "''"
    $safeDb   = $DbName -replace "'", "''"

    $sql = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$safeUser' AND type_desc = 'SQL_LOGIN')
BEGIN
    CREATE LOGIN [$safeUser] WITH PASSWORD = N'$safePwd', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;
    PRINT '  ✓ Login created: $safeUser';
END
ELSE
BEGIN
    PRINT '  ✓ Login already exists: $safeUser';
END

-- Grant server-level permissions (master context)
GRANT VIEW SERVER STATE TO [$safeUser];
GRANT VIEW ANY DEFINITION TO [$safeUser];

-- Map to target database and ensure db_owner
IF (DB_ID(N'$safeDb') IS NOT NULL)
BEGIN
    USE [$safeDb];
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$safeUser')
    BEGIN
        CREATE USER [$safeUser] FOR LOGIN [$safeUser];
    END
    ALTER ROLE [db_owner] ADD MEMBER [$safeUser];
    PRINT '  ✓ Mapped to DB and granted db_owner where DB exists.';
END
ELSE
BEGIN
    PRINT '  ⚠ Target database not found for mapping: $safeDb';
END
"@

    # Optionally append sysadmin block from PowerShell to avoid embedding PowerShell expressions in the here-string
    if ($GrantSysadmin) {
        $sysadminBlock = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id WHERE r.name='sysadmin' AND p.name=N'$safeUser')
BEGIN
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$safeUser];
    PRINT '  OK Added to sysadmin role: $safeUser';
END
ELSE
    PRINT '  OK Already member of sysadmin role: $safeUser';
"@
        $sql += "`r`n" + $sysadminBlock
    }

    # Write to temporary file and execute in master context
    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))
    Set-Content -Path $temp -Value $sql -Encoding UTF8 -Force
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
Write-Host "========================================" -ForegroundColor Cyan

# Check if already configured
$skipPhase1 = Test-AlreadyConfigured -DbName $cred.Db -Login $cred.Login

if ($skipPhase1) {
    Write-Ok "Skipping Phase 1 - Infrastructure Already Configured"
    Write-Log "Skipped Phase 1 for DB: $($cred.Db), Login: $($cred.Login)"
} else {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PHASE 1: Infrastructure & Services Setup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
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
    
    Write-Log "Phase 1 complete: Network, Services, Firewall configured"
}

# ================= PHASE 1B: DATABASE CONFIGURATION =================
Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

# Grant DMS-specific permissions (VIEW SERVER STATE, VIEW ANY DEFINITION) required for CDC log reading
Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.Login

# Set recovery model to FULL and take a full backup (required for DMS CDC)
Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db

# Enable CDC
Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password

# Final restart to make agent/cdc clean
if (-not $skipPhase1) {
    Restart-Instance-Service -InstanceName $PrimaryInstance
}
Ensure-SqlAgent -InstanceName $PrimaryInstance

Write-Log "SUCCESS: Configuration complete for DB: $($cred.Db)"
# create a small marker file so subsequent runs can quickly detect completion
$scriptDir = Get-ScriptDir
$marker = Join-Path $scriptDir ".prepare_marker_$($cred.Db)"
try { Set-Content -Path $marker -Value "Configured $($cred.Db) on $(Get-Date -Format o)" -Force } catch { Write-Warn "Unable to write marker file: $_" }

# ================= PHASE 2: RUN COMPREHENSIVE SQL SETUP (external SQL file)
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "PHASE 2: Comprehensive Database Setup (external SQL)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$scriptDir = Get-ScriptDir
$sqlScriptPath = Join-Path $scriptDir 'Setup-DMS-Complete.sql'

# If the DMS login was already created earlier (for example by System_Details_Check.ps1)
# re-use the existing login entered during the main prompt. This avoids asking twice.
if (-not $DmsUsername) {
    $DmsUsername = $cred.Login
    Write-Info "No DMS username provided on CLI — using existing login from earlier prompt: $DmsUsername"
}
# Default DMS password to the password entered earlier for the same login if not supplied
if (-not $DmsPassword) {
    $DmsPassword = $cred.Password
}

# If user requested, create the DMS server login now
if ($DmsUsername -and $DmsPassword) {
    Ensure-DmsServerLogin -PrimaryInstance $PrimaryInstance -DmsUser $DmsUsername -DmsPwd $DmsPassword -DbName $cred.Db -GrantSysadmin:$GrantSysadmin
}

# Ensure external SQL file exists; if not, create a template and ask user to edit/manage it
if (-not (Test-Path $sqlScriptPath)) {
    Write-Warn "External SQL file not found at: $sqlScriptPath"
    $template = @'
-- Setup-DMS-Complete.sql
-- Template: override DECLARE variables at the top when running via the PowerShell script.
-- DO NOT store production passwords in this file. Use the PowerShell prompt or a secure secrets store.

-- Example DECLAREs (these will be prepended by the PowerShell wrapper if you run it):
-- DECLARE @DatabaseName NVARCHAR(128) = N'tr8421';
-- DECLARE @DMSUsername NVARCHAR(128) = N'dms_final_user';
-- DECLARE @DMSPassword NVARCHAR(256) = N'YourPassword123!@#';
-- DECLARE @BackupPath NVARCHAR(500) = N'NUL';

-- Add your Phase 2 SQL logic below. Keep GO batch separators if needed.

PRINT 'Template file created. Edit this file to customize Phase 2 SQL.'
'@
    Set-Content -Path $sqlScriptPath -Value $template -Encoding UTF8 -Force
    Write-Host "A template file was created: $sqlScriptPath" -ForegroundColor Yellow
    Write-Host "Edit the file and re-run the script, or run the file manually in SSMS after customizing the DECLAREs." -ForegroundColor Yellow
} else {
    Write-Info "Found SQL setup script: $sqlScriptPath"
    Write-Host ""
    $autoRun = Read-Host "Run SQL setup verification from external file now? (Y/N)"
    if ($autoRun -ieq 'Y' -or $autoRun -ieq 'YES') {
        Invoke-SQL-Complete-Setup -SqlScriptPath $sqlScriptPath `
                                  -PrimaryInstance $PrimaryInstance `
                                  -DbName $cred.Db `
                                  -Login $cred.Login `
                                  -Password $cred.Password
        Write-Log "Phase 2 complete: external SQL verification executed"
    } else {
        Write-Host "Manual SQL verification option available. Open in SSMS:" -ForegroundColor Yellow
        Write-Host "  File: $sqlScriptPath"
        Write-Host "  1. Customize parameters at the top or let the PowerShell wrapper inject them" -ForegroundColor Yellow
        Write-Host "  2. Execute (F5)" -ForegroundColor Yellow
    }
}

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

Write-Host ""
Write-Ok "DONE."
Write-Host "DB Prepared : $($cred.Db)"
Write-Host "Login       : $($cred.Login)"
Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"
Write-Host ""
Write-Host "Execution log saved to: $script:logPath"
Write-Host "To review: Get-Content '$script:logPath'"
