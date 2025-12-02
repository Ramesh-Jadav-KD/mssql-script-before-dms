<#<#

Prepare-MSSQL-SourceForDMS.ps1Prepare-MSSQL-SourceForDMS.ps1

All-in-one script to prepare SQL Server 2019 (or later) as AWS DMS source.All-in-one script to prepare SQL Server 2019 (or later) as AWS DMS source.



Features:Features:

- Detect instances, enable TCP/IP (primary fixed to 1433)- Detect instances, enable TCP/IP (primary fixed to 1433)

- Enable remote access + Mixed Mode- Enable remote access + Mixed Mode

- Configure firewall inbound TCP 1433- Configure firewall inbound TCP 1433

- Start SQL Browser + SQL Server Agent- Start SQL Browser + SQL Server Agent

- Create/validate SQL login and grant db_owner- Create/validate SQL login and grant db_owner

- Enable CDC on DB + all user tables- Enable CDC on DB + all user tables

- Restart services and print final status- Restart services and print final status



Optional: restrict firewall to specific subnetsOptional: restrict firewall to specific subnets

Example:Example:

  .\Prepare-MSSQL-SourceForDMS.ps1 -AllowedSubnets "10.0.0.0/16","10.1.0.0/16"  .\Prepare-MSSQL-SourceForDMS.ps1 -AllowedSubnets "10.0.0.0/16","10.1.0.0/16"

#>#>



param(<#

    [string[]]$AllowedSubnets = @(),Prepare-MSSQL-SourceForDMS.ps1

    [string]$DmsUsername = '',All-in-one script to prepare SQL Server 2019 (or later) as AWS DMS source.

    [string]$DmsPassword = '',

    [switch]$GrantSysadmin = $false,Features:

    [switch]$NonInteractive = $false- Detect instances, enable TCP/IP (primary fixed to 1433)

)- Enable remote access + Mixed Mode

- Configure firewall inbound TCP 1433

$ErrorActionPreference = "Stop"- Start SQL Browser + SQL Server Agent

$PrimaryPort = 1433- Create/validate SQL login and grant db_owner

- Enable CDC on DB + all user tables

function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }- Restart services and print final status

function Write-Ok($msg)   { Write-Host "[OK]    $msg" -ForegroundColor Green }

function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }Optional: restrict firewall to specific subnets

function Write-Fail($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red }Example:

  .\Prepare-MSSQL-SourceForDMS.ps1 -AllowedSubnets "10.0.0.0/16","10.1.0.0/16"

function Assert-Admin {#>

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {param(

        Write-Fail "Run this script as Administrator."    [string[]]$AllowedSubnets = @(),   # empty => allow any source

        exit 1    [string]$DmsUsername = '',

    }    [string]$DmsPassword = '',

    Write-Ok "Running as Administrator."    [switch]$GrantSysadmin = $false,

}    [switch]$NonInteractive = $false

)

function Get-ScriptDir {

    if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }$ErrorActionPreference = "Stop"

    if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) { return Split-Path -Parent $PSCommandPath }$PrimaryPort = 1433

    try { return (Get-Location).ProviderPath } catch { return '.' }

}function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }

function Write-Ok($msg)   { Write-Host "[OK]    $msg" -ForegroundColor Green }

$script:logPath = Join-Path (Get-ScriptDir) "Prepare-MSSQL-SourceForDMS.log"function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }

function Write-Fail($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red }

function Write-Log([string]$msg) {

    $entry = "$(Get-Date -Format o)`t$msg"function Assert-Admin {

    try { Add-Content -Path $script:logPath -Value $entry -ErrorAction Stop } catch { Write-Warn "Failed to write log: $_" }    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

}    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        Write-Fail "Run this script as Administrator."

function Test-AlreadyConfigured {        exit 1

    param([string]$DbName, [string]$Login)    }

    $scriptDir = Get-ScriptDir    Write-Ok "Running as Administrator."

    $marker = Join-Path $scriptDir ".prepare_marker_$DbName"}

    return Test-Path $marker

}# Robust script directory resolver: prefer PSScriptRoot, then PSCommandPath, then current location

function Get-ScriptDir {

function Invoke-SQL-Complete-Setup {    if ($PSScriptRoot -and $PSScriptRoot.Trim().Length -gt 0) { return $PSScriptRoot }

    param(    if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) { return Split-Path -Parent $PSCommandPath }

        [Parameter(Mandatory=$true)][string]$SqlScriptPath,    try { return (Get-Location).ProviderPath } catch { return '.' }

        [Parameter(Mandatory=$true)][string]$PrimaryInstance,}

        [Parameter(Mandatory=$true)][string]$DbName,

        [string]$Login,# Initialize script-scoped log path (defined after Get-ScriptDir exists)

        [string]$Password$script:logPath = Join-Path (Get-ScriptDir) "Prepare-MSSQL-SourceForDMS.log"

    )

    $server = Get-ServerName $PrimaryInstance# --- Small helper: simple logging to a file in the script directory

    Write-Info "Executing SQL script: $SqlScriptPath against server: $server"function Write-Log([string]$msg) {

    try {    $scriptDir = Get-ScriptDir

        $orig = Get-Content -Path $SqlScriptPath -Raw -ErrorAction Stop    # Use script scope so other parts of the script can reference the path safely

        $safeDbName = $DbName -replace "'", "''"    if (-not $script:logPath) { $script:logPath = Join-Path $scriptDir "Prepare-MSSQL-SourceForDMS.log" }

        $safeDmsUser = $Login -replace "'", "''"    $entry = "$(Get-Date -Format o) `t$msg"

        $safeDmsPwd  = $Password -replace "'", "''"    try { Add-Content -Path $script:logPath -Value $entry -ErrorAction Stop } catch { Write-Warn "Failed to write log: $_" }

}

        $patternDb = "DECLARE\s+@DatabaseName\s+NVARCHAR\(128\)\s*=.*?;"

        $patternUser = "DECLARE\s+@DMSUsername\s+NVARCHAR\(128\)\s*=.*?;"# --- Test whether the database has already been prepared. Minimal, file-marker based.

        $patternPwd = "DECLARE\s+@DMSPassword\s+NVARCHAR\(256\)\s*=.*?;"function Test-AlreadyConfigured {

        $patternBackup = "DECLARE\s+@BackupPath\s+NVARCHAR\(500\)\s*=.*?;"    param([string]$DbName, [string]$Login)

    $scriptDir = Get-ScriptDir

        $declDb = "DECLARE @DatabaseName NVARCHAR(128) = N'$safeDbName';"    $marker = Join-Path $scriptDir ".prepare_marker_$DbName"

        $declUser = "DECLARE @DMSUsername NVARCHAR(128) = N'$safeDmsUser';"    return Test-Path $marker

        $declPwd = "DECLARE @DMSPassword NVARCHAR(256) = N'$safeDmsPwd';"}

        $declBackup = "DECLARE @BackupPath NVARCHAR(500) = N'NUL';"

# --- Minimal invoker for the SQL verification script used in Phase 2

        $new = $origfunction Invoke-SQL-Complete-Setup {

        if ($orig -match $patternDb -or $orig -match $patternUser -or $orig -match $patternPwd) {    param(

            $new = $new -replace $patternDb, ''        [Parameter(Mandatory=$true)][string]$SqlScriptPath,

            $new = $new -replace $patternUser, ''        [Parameter(Mandatory=$true)][string]$PrimaryInstance,

            $new = $new -replace $patternPwd, ''        [Parameter(Mandatory=$true)][string]$DbName,

            $new = $new -replace $patternBackup, ''        [string]$Login,

        }        [string]$Password

        $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $new    )

    $server = Get-ServerName $PrimaryInstance

        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))    Write-Info "Executing SQL script: $SqlScriptPath against server: $server"

        Set-Content -Path $tempPath -Value $new -Encoding UTF8 -Force    # Create a temp script that injects the desired variables into the top of the SQL

    try {

        if ($Login -and $Password) {        $orig = Get-Content -Path $SqlScriptPath -Raw -ErrorAction Stop

            sqlcmd -S $server -U $Login -P $Password -i $tempPath | Out-Null

        } else {        # Escape single quotes in values

            sqlcmd -S $server -E -i $tempPath | Out-Null        $safeDbName = $DbName -replace "'", "''"

        }        # If the Login/Password provided are the admin credentials used to run the script,

        # they may also be the DMS username/password you want to set. We'll use the provided

        Write-Log "Executed SQL verification script: $SqlScriptPath against $DbName"        # $Login as DMS username and an optional separate DMS password if you passed one via DbName (not typical).

    } catch {        # To be explicit: use $DbName (database), and re-use $Login as DMS username and $Password as DMS password.

        Write-Warn "Invoke-SQL-Complete-Setup failed: $_"        $safeDmsUser = $Login -replace "'", "''"

        throw        $safeDmsPwd  = $Password -replace "'", "''"

    } finally {

        if ($tempPath -and (Test-Path $tempPath)) { Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue }        # Replace top-level DECLAREs if they exist; otherwise prepend custom DECLAREs

    }        $patternDb = "DECLARE\s+@DatabaseName\s+NVARCHAR\(128\)\s*=.*?;"

}        $patternUser = "DECLARE\s+@DMSUsername\s+NVARCHAR\(128\)\s*=.*?;"

        $patternPwd = "DECLARE\s+@DMSPassword\s+NVARCHAR\(256\)\s*=.*?;"

function Get-SqlInstances {        $patternBackup = "DECLARE\s+@BackupPath\s+NVARCHAR\(500\)\s*=.*?;"

    Write-Info "Detecting SQL Server instances..."

    $instRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"        $declDb = "DECLARE @DatabaseName NVARCHAR(128) = N'$safeDbName';"

    if (-not (Test-Path $instRegPath)) {        $declUser = "DECLARE @DMSUsername NVARCHAR(128) = N'$safeDmsUser';"

        Write-Fail "No SQL Server instances found."        $declPwd = "DECLARE @DMSPassword NVARCHAR(256) = N'$safeDmsPwd';"

        exit 1        $declBackup = "DECLARE @BackupPath NVARCHAR(500) = N'NUL';"

    }

    $props = Get-ItemProperty $instRegPath        $new = $orig

    $names = $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object -ExpandProperty Name        $replaced = $false

    Write-Ok ("Found instances: " + ($names -join ", "))        if ($orig -match $patternDb -or $orig -match $patternUser -or $orig -match $patternPwd) {

    return @{ Props=$props; Names=$names }            # remove existing DECLARE lines

}            $new = $new -replace $patternDb, ''

            $new = $new -replace $patternUser, ''

function Get-ServerName([string]$InstanceName) {            $new = $new -replace $patternPwd, ''

    if ($InstanceName -eq "MSSQLSERVER") { return "." }            $new = $new -replace $patternBackup, ''

    return ".\$InstanceName"            # Prepend our DECLAREs

}            $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $new

            $replaced = $true

function Configure-Instance-Network {        } else {

    param([string]$InstanceName, [string]$InstanceId, [bool]$IsPrimary)            # No declares found; just prepend

    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer\SuperSocketNetLib\Tcp"            $new = $declDb + "`r`n" + $declUser + "`r`n" + $declPwd + "`r`n" + $declBackup + "`r`n`r`n" + $orig

    $ipAllReg = Join-Path $tcpReg "IPAll"        }

    if (-not (Test-Path $tcpReg)) { Write-Warn "TCP registry not found for $InstanceName"; return }

    Set-ItemProperty -Path $tcpReg -Name "Enabled" -Value 1 -Type DWord        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))

    if (-not (Test-Path $ipAllReg)) { New-Item -Path $ipAllReg -Force | Out-Null }        Set-Content -Path $tempPath -Value $new -Encoding UTF8 -Force

    if ($IsPrimary) {

        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "" -Type String        if ($Login -and $Password) {

        Set-ItemProperty -Path $ipAllReg -Name "TcpPort" -Value "$PrimaryPort" -Type String            sqlcmd -S $server -U $Login -P $Password -i $tempPath | Out-Null

        Write-Ok "[$InstanceName] TCP enabled + fixed port $PrimaryPort"        } else {

    } else {            sqlcmd -S $server -E -i $tempPath | Out-Null

        Set-ItemProperty -Path $ipAllReg -Name "TcpPort" -Value "" -Type String        }

        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "0" -Type String

        Write-Ok "[$InstanceName] TCP enabled + dynamic ports"        Write-Log "Executed SQL verification script: $SqlScriptPath (temp: $tempPath) against $DbName"

    }    } catch {

}        Write-Warn "Invoke-SQL-Complete-Setup failed: $_"

        throw

function Restart-Instance-Service {    } finally {

    param([string]$InstanceName)        if ($tempPath -and (Test-Path $tempPath)) { Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue }

    $svc = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }    }

    Write-Info "Restarting SQL service: $svc"}

    try {

        Restart-Service -Name $svc -Force -ErrorAction Stopfunction Get-SqlInstances {

        Write-Ok "Restarted $svc"    Write-Info "Detecting SQL Server instances..."

    } catch {    $instRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"

        Write-Warn "Restart failed for $svc. Trying stop/start..."    if (-not (Test-Path $instRegPath)) {

        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue        Write-Fail "No SQL Server instances found."

        Start-Service -Name $svc -ErrorAction Stop        exit 1

        Write-Ok "Started $svc"    }

    }    $props = Get-ItemProperty $instRegPath

}    $names = $props.PSObject.Properties |

        Where-Object { $_.Name -notmatch "^PS" } |

function Enable-MixedModeAndRemoteAccess {        Select-Object -ExpandProperty Name

    param([string]$InstanceName, [string]$InstanceId)

    $server = Get-ServerName $InstanceName    Write-Ok ("Found instances: " + ($names -join ", "))

    Write-Info "Enabling remote access + Mixed Mode for $InstanceName"    return @{ Props=$props; Names=$names }

    $sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'remote access', 1; RECONFIGURE;"}

    sqlcmd -S $server -E -Q $sql | Out-Null

    Write-Ok "[$InstanceName] Remote access enabled."function Get-ServerName([string]$InstanceName) {

    $secReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer"    if ($InstanceName -eq "MSSQLSERVER") { return "." }

    if (Test-Path $secReg) {    return ".\$InstanceName"

        Set-ItemProperty -Path $secReg -Name "LoginMode" -Value 2 -Type DWord}

        Write-Ok "[$InstanceName] Mixed Mode enabled."

    }function Configure-Instance-Network {

}    param([string]$InstanceName, [string]$InstanceId, [bool]$IsPrimary)



function Ensure-Firewall1433 {    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer\SuperSocketNetLib\Tcp"

    Write-Info "Configuring Windows Firewall inbound TCP $PrimaryPort..."    $ipAllReg = Join-Path $tcpReg "IPAll"

    $ruleName = "SQL Server TCP $PrimaryPort (Auto)"    if (-not (Test-Path $tcpReg)) {

    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue        Write-Warn "TCP registry not found for $InstanceName"

    if ($existingRule) { Write-Ok "Firewall rule already exists."; return }        return

    if ($AllowedSubnets.Count -gt 0) {    }

        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort -RemoteAddress ($AllowedSubnets -join ",") -Action Allow | Out-Null

        Write-Ok "Firewall rule created restricted to: $($AllowedSubnets -join ', ')"    Set-ItemProperty -Path $tcpReg -Name "Enabled" -Value 1 -Type DWord

    } else {    if (-not (Test-Path $ipAllReg)) { New-Item -Path $ipAllReg -Force | Out-Null }

        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort -Action Allow | Out-Null

        Write-Ok "Firewall rule created for all sources."    if ($IsPrimary) {

    }        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "" -Type String

}        Set-ItemProperty -Path $ipAllReg -Name "TcpPort"         -Value "$PrimaryPort" -Type String

        Write-Ok "[$InstanceName] TCP enabled + fixed port $PrimaryPort"

function Ensure-SqlBrowser {    } else {

    Write-Info "Ensuring SQL Browser is running..."        Set-ItemProperty -Path $ipAllReg -Name "TcpPort"         -Value ""  -Type String

    $browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue        Set-ItemProperty -Path $ipAllReg -Name "TcpDynamicPorts" -Value "0" -Type String

    if (-not $browser) { Write-Warn "SQL Browser service not found."; return }        Write-Ok "[$InstanceName] TCP enabled + dynamic ports"

    Set-Service -Name "SQLBrowser" -StartupType Automatic    }

    if ($browser.Status -ne "Running") { Start-Service -Name "SQLBrowser"; Write-Ok "SQL Browser started." }}

    else { Write-Ok "SQL Browser already running." }

}function Restart-Instance-Service {

    param([string]$InstanceName)

function Ensure-SqlAgent {

    param([string]$InstanceName)    $svc = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { "MSSQL`$$InstanceName" }

    $agentSvc = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }    Write-Info "Restarting SQL service: $svc"

    Write-Info "Ensuring SQL Server Agent is running: $agentSvc"    try {

    $svc = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue        Restart-Service -Name $svc -Force -ErrorAction Stop

    if (-not $svc) { Write-Warn "Agent service not found for $InstanceName"; return }        Write-Ok "Restarted $svc"

    Set-Service -Name $agentSvc -StartupType Automatic    } catch {

    if ($svc.Status -ne "Running") { Start-Service -Name $agentSvc; Write-Ok "Agent started." }        Write-Warn "Restart failed for $svc. Trying stop/start..."

    else { Write-Ok "Agent already running." }        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue

}        Start-Service -Name $svc -ErrorAction Stop

        Write-Ok "Started $svc"

function Prompt-ForDbAndLogin {    }

    param([string]$PrimaryInstance)}

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Existing databases:"function Enable-MixedModeAndRemoteAccess {

    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name"    param([string]$InstanceName, [string]$InstanceId)

    $dbName = Read-Host "Enter target database name to prepare (example: tr8421)"

    $login = Read-Host "Enter existing SQL login name"    $server = Get-ServerName $InstanceName

    $pwd = Read-Host "Enter password" -AsSecureString

    $pwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))    Write-Info "Enabling remote access + Mixed Mode for $InstanceName"

    Write-Info "Validating login credentials..."

    try {    $sql = @"

        sqlcmd -S $server -U $login -P $pwdPlain -d $dbName -Q "SELECT 1" | Out-NullEXEC sp_configure 'show advanced options', 1;

        Write-Ok "Login validated successfully."RECONFIGURE;

    } catch {EXEC sp_configure 'remote access', 1;

        Write-Fail "Login validation failed. Check username/password."RECONFIGURE;

        exit 1"@

    }    sqlcmd -S $server -E -Q $sql | Out-Null

    return @{ Db=$dbName; Login=$login; Password=$pwdPlain }    Write-Ok "[$InstanceName] Remote access enabled."

}

    # Mixed mode: LoginMode=2

function Ensure-LoginAndGrants {    $secReg = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer"

    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)    if (Test-Path $secReg) {

    $server = Get-ServerName $PrimaryInstance        Set-ItemProperty -Path $secReg -Name "LoginMode" -Value 2 -Type DWord

    Write-Info "Mapping existing SQL login to database user + granting db_owner on $DbName..."        Write-Ok "[$InstanceName] Mixed Mode enabled."

    $sqlGrant = "USE [$DbName]; IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Login') BEGIN CREATE USER [$Login] FOR LOGIN [$Login]; END; ALTER ROLE [db_owner] ADD MEMBER [$Login];"    }

    sqlcmd -S $server -E -Q $sqlGrant | Out-Null}

    Write-Ok "User mapped and granted db_owner."

}function Ensure-Firewall1433 {

    Write-Info "Configuring Windows Firewall inbound TCP $PrimaryPort..."

function Set-RecoveryModel-And-Backup {    $ruleName = "SQL Server TCP $PrimaryPort (Auto)"

    param([string]$PrimaryInstance, [string]$DbName, [string]$BackupPath = "NUL")

    $server = Get-ServerName $PrimaryInstance    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    Write-Info "Setting database recovery model to FULL for $DbName..."    if ($existingRule) {

    sqlcmd -S $server -E -Q "ALTER DATABASE [$DbName] SET RECOVERY FULL;" | Out-Null        Write-Ok "Firewall rule already exists."

    Write-Ok "Recovery model set to FULL."        return

    Write-Info "Taking full database backup for $DbName..."    }

    sqlcmd -S $server -E -Q "BACKUP DATABASE [$DbName] TO DISK = '$BackupPath';" | Out-Null

    Write-Ok "Full backup completed (log chain initialized)."    if ($AllowedSubnets.Count -gt 0) {

}        New-NetFirewallRule -DisplayName $ruleName `

            -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort `

function Grant-DmsUserPermissions {            -RemoteAddress ($AllowedSubnets -join ",") `

    param([string]$PrimaryInstance, [string]$Login)            -Action Allow | Out-Null

    $server = Get-ServerName $PrimaryInstance        Write-Ok "Firewall rule created restricted to: $($AllowedSubnets -join ', ')"

    Write-Info "Granting VIEW SERVER STATE and VIEW ANY DEFINITION to $Login..."    } else {

    $sqlGrants = "GRANT VIEW SERVER STATE TO [$Login]; GRANT VIEW ANY DEFINITION TO [$Login];"        New-NetFirewallRule -DisplayName $ruleName `

    $grantOut = sqlcmd -S $server -E -d master -Q $sqlGrants 2>&1            -Direction Inbound -Protocol TCP -LocalPort $PrimaryPort `

    if ($LASTEXITCODE -eq 0) { Write-Ok "Permissions granted: VIEW SERVER STATE, VIEW ANY DEFINITION." }            -Action Allow | Out-Null

    else { Write-Warn "Grant execution returned non-zero exit code: $LASTEXITCODE"; Write-Warn $grantOut }        Write-Ok "Firewall rule created for all sources."

    $verifySql = "SET NOCOUNT ON; SELECT p.name AS principal_name, perm.permission_name FROM sys.server_permissions perm JOIN sys.server_principals p ON perm.grantee_principal_id = p.principal_id WHERE p.name = N'$Login' AND perm.permission_name IN ('VIEW SERVER STATE','VIEW ANY DEFINITION');"    }

    $verifyOut = sqlcmd -S $server -E -d master -Q $verifySql 2>&1 | Out-String}

    if ($verifyOut -match 'VIEW SERVER STATE' -and $verifyOut -match 'VIEW ANY DEFINITION') {

        Write-Ok "Verification: both VIEW SERVER STATE and VIEW ANY DEFINITION present for $Login."function Ensure-SqlBrowser {

    } else {    Write-Info "Ensuring SQL Browser is running..."

        Write-Warn "Verification: some permissions may be missing for $Login."    $browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue

    }    if (-not $browser) { Write-Warn "SQL Browser service not found."; return }

}

    Set-Service -Name "SQLBrowser" -StartupType Automatic

function Ensure-DmsServerLogin {    if ($browser.Status -ne "Running") {

    param([string]$PrimaryInstance, [string]$DmsUser, [string]$DmsPwd, [string]$DbName, [switch]$GrantSysadmin)        Start-Service -Name "SQLBrowser"

    if (-not $DmsUser -or -not $DmsPwd) { Write-Warn "DMS username/password not provided, skipping DMS login creation."; return }        Write-Ok "SQL Browser started."

    $server = Get-ServerName $PrimaryInstance    } else {

    Write-Info "Ensuring DMS server login exists: $DmsUser (server: $server)"        Write-Ok "SQL Browser already running."

    $safeUser = $DmsUser -replace "'", "''"    }

    $safePwd  = $DmsPwd -replace "'", "''"}

    $safeDb   = $DbName -replace "'", "''"

function Ensure-SqlAgent {

    $sqlLines = @()    param([string]$InstanceName)

    $sqlLines += "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$safeUser' AND type_desc = 'SQL_LOGIN')"

    $sqlLines += "BEGIN"    $agentSvc = if ($InstanceName -eq "MSSQLSERVER") { "SQLSERVERAGENT" } else { "SQLAgent`$$InstanceName" }

    $sqlLines += "    CREATE LOGIN [$safeUser] WITH PASSWORD = N'$safePwd', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;"    Write-Info "Ensuring SQL Server Agent is running: $agentSvc"

    $sqlLines += "    PRINT 'Login created: $safeUser';"    $svc = Get-Service -Name $agentSvc -ErrorAction SilentlyContinue

    $sqlLines += "END"    if (-not $svc) { Write-Warn "Agent service not found for $InstanceName"; return }

    $sqlLines += "ELSE"

    $sqlLines += "BEGIN"    Set-Service -Name $agentSvc -StartupType Automatic

    $sqlLines += "    PRINT 'Login already exists: $safeUser';"    if ($svc.Status -ne "Running") {

    $sqlLines += "END"        Start-Service -Name $agentSvc

    $sqlLines += "GRANT VIEW SERVER STATE TO [$safeUser];"        Write-Ok "Agent started."

    $sqlLines += "GRANT VIEW ANY DEFINITION TO [$safeUser];"    } else {

    $sqlLines += "IF (DB_ID(N'$safeDb') IS NOT NULL)"        Write-Ok "Agent already running."

    $sqlLines += "BEGIN"    }

    $sqlLines += "    USE [$safeDb];"}

    $sqlLines += "    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$safeUser')"

    $sqlLines += "    BEGIN"function Prompt-ForDbAndLogin {

    $sqlLines += "        CREATE USER [$safeUser] FOR LOGIN [$safeUser];"    param([string]$PrimaryInstance)

    $sqlLines += "    END"

    $sqlLines += "    ALTER ROLE [db_owner] ADD MEMBER [$safeUser];"    $server = Get-ServerName $PrimaryInstance

    $sqlLines += "    PRINT 'Mapped to DB and granted db_owner.';"

    $sqlLines += "END"    # Show DBs for user help

    Write-Info "Existing databases:"

    if ($GrantSysadmin) {    sqlcmd -S $server -E -Q "SELECT name FROM sys.databases ORDER BY name"

        $sqlLines += "IF NOT EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id WHERE r.name='sysadmin' AND p.name=N'$safeUser')"

        $sqlLines += "BEGIN"    $dbName = Read-Host "Enter target database name to prepare (example: tr8421)"

        $sqlLines += "    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$safeUser];"    $login = Read-Host "Enter existing SQL login name"

        $sqlLines += "    PRINT 'Added to sysadmin role: $safeUser';"    $pwd   = Read-Host "Enter password" -AsSecureString

        $sqlLines += "END"    $pwdPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(

    }        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd)

    )

    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))

    Set-Content -Path $temp -Value $sqlLines -Encoding UTF8 -Force    Write-Info "Validating login credentials..."

    try {    try {

        $out = sqlcmd -S $server -E -d master -i $temp 2>&1 | Out-String        sqlcmd -S $server -U $login -P $pwdPlain -d $dbName -Q "SELECT 1" | Out-Null

        Write-Log "Ensure-DmsServerLogin output: $out"        Write-Ok "Login validated successfully."

        Write-Host $out    } catch {

    } catch {        Write-Fail "Login validation failed. Check username/password."

        Write-Warn "Failed to ensure DMS login: $_"        exit 1

        throw    }

    } finally {

        if (Test-Path $temp) { Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue }    return @{ Db=$dbName; Login=$login; Password=$pwdPlain }

    }}

}

function Ensure-LoginAndGrants {

function Enable-CDC-Database-And-Tables {    param(

    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)        [string]$PrimaryInstance,

    $server = Get-ServerName $PrimaryInstance        [string]$DbName,

    Write-Info "Enabling CDC at database level for $DbName..."        [string]$Login,

    $sqlDbCdc = "USE [$DbName]; IF (SELECT is_cdc_enabled FROM sys.databases WHERE name = DB_NAME()) = 0 BEGIN EXEC sys.sp_cdc_enable_db; END"        [string]$Password

    sqlcmd -S $server -E -Q $sqlDbCdc | Out-Null    )

    Write-Ok "CDC enabled on database."

    $server = Get-ServerName $PrimaryInstance

    Write-Info "Enabling CDC on all user tables..."

    $cdcLines = @()    Write-Info "Mapping existing SQL login to database user + granting db_owner on $DbName..."

    $cdcLines += "USE [$DbName];"    $sqlGrant = @"

    $cdcLines += "DECLARE @schema sysname, @table sysname, @sql nvarchar(max);"USE [$DbName];

    $cdcLines += "DECLARE cur CURSOR FAST_FORWARD FOR SELECT s.name, t.name FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id WHERE t.is_ms_shipped = 0;"IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$Login')

    $cdcLines += "OPEN cur;"BEGIN

    $cdcLines += "FETCH NEXT FROM cur INTO @schema, @table;"    CREATE USER [$Login] FOR LOGIN [$Login];

    $cdcLines += "WHILE @@FETCH_STATUS = 0"END

    $cdcLines += "BEGIN"ALTER ROLE [db_owner] ADD MEMBER [$Login];

    $cdcLines += "    IF NOT EXISTS (SELECT 1 FROM cdc.change_tables ct JOIN sys.tables t2 ON ct.source_object_id=t2.object_id JOIN sys.schemas s2 ON t2.schema_id=s2.schema_id WHERE s2.name=@schema AND t2.name=@table)""@

    $cdcLines += "    BEGIN"    sqlcmd -S $server -E -Q $sqlGrant | Out-Null

    $cdcLines += "        SET @sql = N'EXEC sys.sp_cdc_enable_table @source_schema = N''' + @schema + ''', @source_name = N''' + @table + ''', @role_name = NULL, @supports_net_changes = 0;';"    Write-Ok "User mapped and granted db_owner."

    $cdcLines += "        EXEC sp_executesql @sql;"}

    $cdcLines += "    END"

    $cdcLines += "    FETCH NEXT FROM cur INTO @schema, @table;"function Set-RecoveryModel-And-Backup {

    $cdcLines += "END"    param([string]$PrimaryInstance, [string]$DbName, [string]$BackupPath = "NUL")

    $cdcLines += "CLOSE cur; DEALLOCATE cur;"

    $server = Get-ServerName $PrimaryInstance

    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))

    Set-Content -Path $temp -Value $cdcLines -Encoding UTF8 -Force    Write-Info "Setting database recovery model to FULL for $DbName..."

    try {    $sqlRecovery = @"

        sqlcmd -S $server -E -i $temp | Out-NullALTER DATABASE [$DbName] SET RECOVERY FULL;

    } finally {"@

        if (Test-Path $temp) { Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue }    sqlcmd -S $server -E -Q $sqlRecovery | Out-Null

    }    Write-Ok "Recovery model set to FULL."

    Write-Ok "CDC enabled on all user tables."

}    Write-Info "Taking full database backup for $DbName..."

    $sqlBackup = @"

# ================= MAIN =================BACKUP DATABASE [$DbName] TO DISK = '$BackupPath';

Assert-Admin"@

    sqlcmd -S $server -E -Q $sqlBackup | Out-Null

$instData = Get-SqlInstances    Write-Ok "Full backup completed (log chain initialized)."

$instancesProps = $instData.Props}

$instanceNames  = $instData.Names

function Grant-DmsUserPermissions {

$PrimaryInstance = if ($instanceNames -contains "MSSQLSERVER") { "MSSQLSERVER" } else { $instanceNames[0] }    param([string]$PrimaryInstance, [string]$Login)

Write-Ok "Primary instance: $PrimaryInstance"

    $server = Get-ServerName $PrimaryInstance

foreach ($inst in $instanceNames) {

    $instId = $instancesProps.$inst    Write-Info "Granting VIEW SERVER STATE and VIEW ANY DEFINITION to $Login..."

    Configure-Instance-Network -InstanceName $inst -InstanceId $instId -IsPrimary ($inst -eq $PrimaryInstance)    $sqlGrants = @"

}GRANT VIEW SERVER STATE TO [$Login];

GRANT VIEW ANY DEFINITION TO [$Login];

foreach ($inst in $instanceNames) { Restart-Instance-Service -InstanceName $inst }"@

    # Run the grants in the master database (server-scope permissions require master)

foreach ($inst in $instanceNames) {    $grantOut = sqlcmd -S $server -E -d master -Q $sqlGrants 2>&1

    $instId = $instancesProps.$inst    if ($LASTEXITCODE -eq 0) {

    Enable-MixedModeAndRemoteAccess -InstanceName $inst -InstanceId $instId        Write-Ok "Permissions granted: VIEW SERVER STATE, VIEW ANY DEFINITION."

}    } else {

        Write-Warn "Grant execution returned non-zero exit code: $LASTEXITCODE"

Restart-Instance-Service -InstanceName $PrimaryInstance        Write-Warn $grantOut

    }

Ensure-Firewall1433

Ensure-SqlBrowser    # Verification: query server permissions for this principal to ensure grants exist

Ensure-SqlAgent -InstanceName $PrimaryInstance    $verifySql = "SET NOCOUNT ON; SELECT p.name AS principal_name, perm.permission_name FROM sys.server_permissions perm JOIN sys.server_principals p ON perm.grantee_principal_id = p.principal_id WHERE p.name = N'$Login' AND perm.permission_name IN ('VIEW SERVER STATE','VIEW ANY DEFINITION');"

    $verifyOut = sqlcmd -S $server -E -d master -Q $verifySql 2>&1 | Out-String

$cred = Prompt-ForDbAndLogin -PrimaryInstance $PrimaryInstance    if ($verifyOut -match 'VIEW SERVER STATE' -and $verifyOut -match 'VIEW ANY DEFINITION') {

Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password        Write-Ok "Verification: both VIEW SERVER STATE and VIEW ANY DEFINITION present for $Login."

Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.Login    } elseif ($verifyOut -match 'VIEW SERVER STATE') {

Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db        Write-Warn "Verification: VIEW SERVER STATE present, VIEW ANY DEFINITION missing for $Login. Output:`n$verifyOut"

Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password    } elseif ($verifyOut -match 'VIEW ANY DEFINITION') {

        Write-Warn "Verification: VIEW ANY DEFINITION present, VIEW SERVER STATE missing for $Login. Output:`n$verifyOut"

Restart-Instance-Service -InstanceName $PrimaryInstance    } else {

Ensure-SqlAgent -InstanceName $PrimaryInstance        Write-Warn "Verification failed: no matching server-level permissions found for $Login. Output:`n$verifyOut"

    }

# ================= FINAL REPORT =================}

Write-Host ""

Write-Host "========== FINAL STATUS =========="# Ensure a server-level DMS login exists, optionally grant sysadmin, and map to the database

function Ensure-DmsServerLogin {

foreach ($inst in $instanceNames) {    param(

    $instId   = $instancesProps.$inst        [string]$PrimaryInstance,

    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp"        [string]$DmsUser,

    $ipAllReg = Join-Path $tcpReg "IPAll"        [string]$DmsPwd,

    $enabled = (Get-ItemProperty $tcpReg).Enabled        [string]$DbName,

    $tcpPort = (Get-ItemProperty $ipAllReg).TcpPort        [switch]$GrantSysadmin

    $dynPort = (Get-ItemProperty $ipAllReg).TcpDynamicPorts    )

    Write-Host "Instance: $inst"

    Write-Host "  TCP Enabled   : $enabled"    if (-not $DmsUser -or -not $DmsPwd) { Write-Warn "DMS username/password not provided, skipping DMS login creation."; return }

    Write-Host "  TCP Port      : $tcpPort"

    Write-Host "  Dynamic Ports : $dynPort"    $server = Get-ServerName $PrimaryInstance

}    Write-Info "Ensuring DMS server login exists: $DmsUser (server: $server)"



Write-Host ""    # Escape single quotes for SQL literal

Write-Host "Listener check for Primary Port ($PrimaryPort):"    $safeUser = $DmsUser -replace "'", "''"

netstat -ano | findstr $PrimaryPort    $safePwd  = $DmsPwd -replace "'", "''"

    $safeDb   = $DbName -replace "'", "''"

Write-Host ""

Write-Ok "DONE."    $sql = @"

Write-Host "DB Prepared : $($cred.Db)"IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$safeUser' AND type_desc = 'SQL_LOGIN')

Write-Host "Login       : $($cred.Login)"BEGIN

Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"    CREATE LOGIN [$safeUser] WITH PASSWORD = N'$safePwd', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;

Write-Host "========================================" -ForegroundColor Cyan    PRINT '  ✓ Login created: $safeUser';

END

$skipPhase1 = Test-AlreadyConfigured -DbName $cred.Db -Login $cred.LoginELSE

BEGIN

if (-not $skipPhase1) {    PRINT '  ✓ Login already exists: $safeUser';

    Write-Log "Phase 1 complete: Network, Services, Firewall configured"END

}

-- Grant server-level permissions (master context)

Ensure-LoginAndGrants -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.PasswordGRANT VIEW SERVER STATE TO [$safeUser];

Grant-DmsUserPermissions -PrimaryInstance $PrimaryInstance -Login $cred.LoginGRANT VIEW ANY DEFINITION TO [$safeUser];

Set-RecoveryModel-And-Backup -PrimaryInstance $PrimaryInstance -DbName $cred.Db

Enable-CDC-Database-And-Tables -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password-- Map to target database and ensure db_owner

IF (DB_ID(N'$safeDb') IS NOT NULL)

if (-not $skipPhase1) { Restart-Instance-Service -InstanceName $PrimaryInstance }BEGIN

Ensure-SqlAgent -InstanceName $PrimaryInstance    USE [$safeDb];

    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$safeUser')

Write-Log "SUCCESS: Configuration complete for DB: $($cred.Db)"    BEGIN

        CREATE USER [$safeUser] FOR LOGIN [$safeUser];

$scriptDir = Get-ScriptDir    END

$marker = Join-Path $scriptDir ".prepare_marker_$($cred.Db)"    ALTER ROLE [db_owner] ADD MEMBER [$safeUser];

try { Set-Content -Path $marker -Value "Configured $($cred.Db) on $(Get-Date -Format o)" -Force } catch { Write-Warn "Unable to write marker file: $_" }    PRINT '  ✓ Mapped to DB and granted db_owner where DB exists.';

END

# ================= PHASE 2 =================ELSE

Write-Host ""BEGIN

Write-Host "========================================" -ForegroundColor Yellow    PRINT '  ⚠ Target database not found for mapping: $safeDb';

Write-Host "PHASE 2: Comprehensive Database Setup (external SQL)" -ForegroundColor YellowEND

Write-Host "========================================" -ForegroundColor Yellow"@



$scriptDir = Get-ScriptDir    # Optionally append sysadmin block from PowerShell to avoid embedding PowerShell expressions in the here-string

$sqlScriptPath = Join-Path $scriptDir 'Setup-DMS-Complete.sql'    if ($GrantSysadmin) {

        $sysadminBlock = @"

if (-not $DmsUsername) {IF NOT EXISTS (SELECT 1 FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id=r.principal_id JOIN sys.server_principals p ON rm.member_principal_id=p.principal_id WHERE r.name='sysadmin' AND p.name=N'$safeUser')

    $DmsUsername = $cred.LoginBEGIN

    Write-Info "No DMS username provided on CLI - using existing login from earlier prompt: $DmsUsername"    ALTER SERVER ROLE [sysadmin] ADD MEMBER [$safeUser];

}    PRINT '  OK Added to sysadmin role: $safeUser';

if (-not $DmsPassword) {END

    $DmsPassword = $cred.PasswordELSE

}    PRINT '  OK Already member of sysadmin role: $safeUser';

"@

if ($DmsUsername -and $DmsPassword) {        $sql += "`r`n" + $sysadminBlock

    Ensure-DmsServerLogin -PrimaryInstance $PrimaryInstance -DmsUser $DmsUsername -DmsPwd $DmsPassword -DbName $cred.Db -GrantSysadmin:$GrantSysadmin    }

}

    # Write to temporary file and execute in master context

if (-not (Test-Path $sqlScriptPath)) {    $temp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.sql'))

    Write-Warn "External SQL file not found at: $sqlScriptPath"    Set-Content -Path $temp -Value $sql -Encoding UTF8 -Force

    $templateContent = '-- Setup-DMS-Complete.sql    try {

-- Template: override DECLARE variables at the top when running via the PowerShell script.        $out = sqlcmd -S $server -E -d master -i $temp 2>&1 | Out-String

-- DO NOT store production passwords in this file.        Write-Log "Ensure-DmsServerLogin output: $out"

        Write-Host $out

-- Example DECLAREs (uncomment and modify):    } catch {

-- DECLARE @DatabaseName NVARCHAR(128) = N''tr8421'';        Write-Warn "Failed to ensure DMS login: $_"

-- DECLARE @DMSUsername NVARCHAR(128) = N''dms_user'';        throw

-- DECLARE @DMSPassword NVARCHAR(256) = N''Password123'';    } finally {

-- DECLARE @BackupPath NVARCHAR(500) = N''NUL'';        if (Test-Path $temp) { Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue }

    }

-- Add your Phase 2 SQL logic below.}



PRINT ''Template file created. Edit this file to customize Phase 2 SQL.'';function Enable-CDC-Database-And-Tables {

'    param([string]$PrimaryInstance, [string]$DbName, [string]$Login, [string]$Password)

    Set-Content -Path $sqlScriptPath -Value $templateContent -Encoding UTF8 -Force

    Write-Host "A template file was created: $sqlScriptPath" -ForegroundColor Yellow    $server = Get-ServerName $PrimaryInstance

    Write-Host "Edit the file and re-run the script." -ForegroundColor Yellow

} else {    Write-Info "Enabling CDC at database level for $DbName..."

    Write-Info "Found SQL setup script: $sqlScriptPath"    $sqlDbCdc = @"

    Write-Host ""USE [$DbName];

    $autoRun = Read-Host "Run SQL setup verification from external file now? (Y/N)"IF (SELECT is_cdc_enabled FROM sys.databases WHERE name = DB_NAME()) = 0

    if ($autoRun -ieq 'Y' -or $autoRun -ieq 'YES') {BEGIN

        Invoke-SQL-Complete-Setup -SqlScriptPath $sqlScriptPath -PrimaryInstance $PrimaryInstance -DbName $cred.Db -Login $cred.Login -Password $cred.Password    EXEC sys.sp_cdc_enable_db;

        Write-Log "Phase 2 complete: external SQL verification executed"END

    } else {"@

        Write-Host "Manual SQL verification option available. Open in SSMS:" -ForegroundColor Yellow    sqlcmd -S $server -E -Q $sqlDbCdc | Out-Null

        Write-Host "  File: $sqlScriptPath" -ForegroundColor Yellow    Write-Ok "CDC enabled on database."

    }

}    Write-Info "Enabling CDC on all user tables..."

    $sqlTablesCdc = @"

# ================= FINAL STATUS =================USE [$DbName];

Write-Host ""DECLARE @schema sysname, @table sysname, @sql nvarchar(max);

Write-Host "========== FINAL STATUS =========="

DECLARE cur CURSOR FAST_FORWARD FOR

foreach ($inst in $instanceNames) {SELECT s.name, t.name

    $instId   = $instancesProps.$instFROM sys.tables t

    $tcpReg   = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instId\MSSQLServer\SuperSocketNetLib\Tcp"JOIN sys.schemas s ON t.schema_id = s.schema_id

    $ipAllReg = Join-Path $tcpReg "IPAll"WHERE t.is_ms_shipped = 0;

    $enabled = (Get-ItemProperty $tcpReg).Enabled

    $tcpPort = (Get-ItemProperty $ipAllReg).TcpPortOPEN cur;

    $dynPort = (Get-ItemProperty $ipAllReg).TcpDynamicPortsFETCH NEXT FROM cur INTO @schema, @table;

    Write-Host "Instance: $inst"WHILE @@FETCH_STATUS = 0

    Write-Host "  TCP Enabled   : $enabled"BEGIN

    Write-Host "  TCP Port      : $tcpPort"    IF NOT EXISTS (

    Write-Host "  Dynamic Ports : $dynPort"        SELECT 1 FROM cdc.change_tables ct

}        JOIN sys.tables t2 ON ct.source_object_id=t2.object_id

        JOIN sys.schemas s2 ON t2.schema_id=s2.schema_id

Write-Host ""        WHERE s2.name=@schema AND t2.name=@table

Write-Host "Listener check for Primary Port ($PrimaryPort):"    )

netstat -ano | findstr $PrimaryPort    BEGIN

        SET @sql = N'EXEC sys.sp_cdc_enable_table

Write-Host ""            @source_schema = N''' + @schema + ''',

Write-Ok "DONE."            @source_name   = N''' + @table + ''',

Write-Host "DB Prepared : $($cred.Db)"            @role_name     = NULL,

Write-Host "Login       : $($cred.Login)"            @supports_net_changes = 0;';

Write-Host "Connect via : Server=<this_machine_ip>,$PrimaryPort;Database=$($cred.Db);User Id=$($cred.Login);Password=***;"        EXEC sp_executesql @sql;

Write-Host ""    END

$theLogPath = $script:logPath    FETCH NEXT FROM cur INTO @schema, @table;

Write-Host "Execution log saved to: $theLogPath"END

Write-Host "To review: Get-Content $theLogPath"CLOSE cur; DEALLOCATE cur;

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

    # Build template content without here-strings to avoid parser issues
    $templateLines = @(
        '-- Setup-DMS-Complete.sql',
        '-- Template: override DECLARE variables at the top when running via the PowerShell script.',
        '-- DO NOT store production passwords in this file. Use the PowerShell prompt or a secure secrets store.',
        '',
        '-- Example DECLAREs (these will be prepended by the PowerShell wrapper if you run it):',
        "-- DECLARE @DatabaseName NVARCHAR(128) = N'tr8421';",
        "-- DECLARE @DMSUsername NVARCHAR(128) = N'dms_final_user';",
        "-- DECLARE @DMSPassword NVARCHAR(256) = N'YourPassword123!@#';",
        "-- DECLARE @BackupPath NVARCHAR(500) = N'NUL';",
        '',
        '-- Add your Phase 2 SQL logic below. Keep GO batch separators if needed.',
        '',
        "PRINT 'Template file created. Edit this file to customize Phase 2 SQL.'"
    )

    Set-Content -Path $sqlScriptPath -Value $templateLines -Encoding UTF8 -Force
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
Write-Host "Execution log saved to:" $script:logPath
Write-Host "To review: Get-Content" $script:logPath
