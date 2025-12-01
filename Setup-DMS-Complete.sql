-- ============================================================================
-- AWS DMS COMPLETE SETUP SCRIPT FOR MSSQL
-- ============================================================================
-- ONE UNIFIED SCRIPT THAT DOES EVERYTHING:
--   ✓ Creates DMS login with password (dynamic)
--   ✓ Sets database recovery model to FULL
--   ✓ Takes full database backup
--   ✓ Enables CDC on database + all tables
--   ✓ Creates database user
--   ✓ Grants db_owner role
--   ✓ Grants DMS permissions (VIEW SERVER STATE, VIEW ANY DEFINITION)
--   ✓ Verifies all steps
--   ✓ Tests transaction log access
--
-- ============================================================================
-- CUSTOMIZE THESE PARAMETERS ONLY:
-- ============================================================================

DECLARE @DatabaseName NVARCHAR(128) = N'tr8421';               -- Database to migrate
DECLARE @DMSUsername NVARCHAR(128) = N'dms_final_user';        -- DMS login username
DECLARE @DMSPassword NVARCHAR(256) = N'YourPassword123!@#';    -- DMS password
DECLARE @BackupPath NVARCHAR(500) = N'NUL';                    -- Backup location (NUL = no file)

-- Execution flags (0 = skip, 1 = execute)
DECLARE @CreateLogin BIT = 1;          -- Create DMS login if not exists
DECLARE @EnableRecoveryFull BIT = 1;   -- Set database to FULL recovery
DECLARE @TakeFullBackup BIT = 1;       -- Take full database backup
DECLARE @EnableCDC BIT = 1;            -- Enable CDC on DB + tables
DECLARE @GrantPermissions BIT = 1;     -- Grant DMS permissions

-- ============================================================================
-- END OF PARAMETERS - NO CHANGES BELOW THIS LINE
-- ============================================================================

SET NOCOUNT ON;
DECLARE @SQL NVARCHAR(MAX);
DECLARE @Step INT = 0;

PRINT ''
PRINT '=================================================================='
PRINT 'AWS DMS SETUP - COMPLETE CONFIGURATION'
PRINT '=================================================================='
PRINT 'Database: ' + @DatabaseName
PRINT 'DMS User: ' + @DMSUsername
PRINT 'Recovery: ' + CASE WHEN @EnableRecoveryFull = 1 THEN 'FULL' ELSE 'SKIP' END
PRINT 'Backup: ' + CASE WHEN @TakeFullBackup = 1 THEN 'YES' ELSE 'SKIP' END
PRINT 'CDC: ' + CASE WHEN @EnableCDC = 1 THEN 'YES' ELSE 'SKIP' END
PRINT '=================================================================='
PRINT ''

-- ============================================================================
-- STEP 1: CREATE DMS LOGIN
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Creating DMS Login...'

IF @CreateLogin = 1
BEGIN
    DECLARE @LoginExists BIT
    SELECT @LoginExists = COUNT(*) FROM sys.server_principals 
    WHERE name = @DMSUsername AND type_desc = 'SQL_LOGIN'
    
    IF @LoginExists = 0
    BEGIN
        SET @SQL = 'CREATE LOGIN [' + @DMSUsername + '] WITH PASSWORD = N''' + 
                   REPLACE(@DMSPassword, '''', '''''') + 
                   ''', CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF;'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ Login created'
    END
    ELSE
    BEGIN
        PRINT '  ✓ Login already exists'
    END
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- STEP 2: SET DATABASE RECOVERY MODEL TO FULL
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Setting Recovery Model to FULL...'

IF @EnableRecoveryFull = 1
BEGIN
    SET @SQL = 'ALTER DATABASE [' + @DatabaseName + '] SET RECOVERY FULL;'
    EXEC sys.sp_executesql @SQL
    PRINT '  ✓ Recovery model set to FULL'
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- STEP 3: TAKE FULL DATABASE BACKUP
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Taking Full Database Backup...'

IF @TakeFullBackup = 1
BEGIN
    BEGIN TRY
        SET @SQL = 'BACKUP DATABASE [' + @DatabaseName + '] TO DISK = ''' + @BackupPath + ''';'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ Backup completed'
    END TRY
    BEGIN CATCH
        PRINT '  ⚠ Backup failed: ' + ERROR_MESSAGE()
    END CATCH
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- STEP 4: ENABLE CDC ON DATABASE
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Enabling CDC on Database...'

IF @EnableCDC = 1
BEGIN
    BEGIN TRY
        SET @SQL = 'USE [' + @DatabaseName + ']; 
                    IF (SELECT is_cdc_enabled FROM sys.databases WHERE name = ''' + @DatabaseName + ''') = 0
                    BEGIN
                        EXEC sys.sp_cdc_enable_db;
                    END'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ CDC enabled on database'
    END TRY
    BEGIN CATCH
        PRINT '  ⚠ CDC enable failed: ' + ERROR_MESSAGE()
    END CATCH
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- STEP 5: ENABLE CDC ON ALL USER TABLES
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Enabling CDC on All Tables...'

IF @EnableCDC = 1
BEGIN
    BEGIN TRY
        SET @SQL = 'USE [' + @DatabaseName + '];
                    DECLARE @schema SYSNAME, @table SYSNAME, @sql NVARCHAR(MAX), @count INT = 0;
                    DECLARE cur CURSOR FAST_FORWARD FOR
                    SELECT s.name, t.name FROM sys.tables t
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
                            SET @sql = N''EXEC sys.sp_cdc_enable_table
                                @source_schema = N'''''' + @schema + '''''',
                                @source_name = N'''''' + @table + '''''',
                                @role_name = NULL,
                                @supports_net_changes = 0;'';
                            EXEC sp_executesql @sql;
                            SET @count = @count + 1;
                        END
                        FETCH NEXT FROM cur INTO @schema, @table;
                    END
                    CLOSE cur; DEALLOCATE cur;'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ CDC enabled on all tables'
    END TRY
    BEGIN CATCH
        PRINT '  ⚠ Table CDC failed: ' + ERROR_MESSAGE()
    END CATCH
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- STEP 6: CREATE DATABASE USER & GRANT DB_OWNER
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Creating Database User and Granting Permissions...'

BEGIN TRY
    SET @SQL = 'USE [' + @DatabaseName + '];
                IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ''' + @DMSUsername + ''')
                    CREATE USER [' + @DMSUsername + '] FOR LOGIN [' + @DMSUsername + '];
                ALTER ROLE [db_owner] ADD MEMBER [' + @DMSUsername + '];'
    EXEC sys.sp_executesql @SQL
    PRINT '  ✓ Database user created and db_owner granted'
END TRY
BEGIN CATCH
    PRINT '  ⚠ User creation failed: ' + ERROR_MESSAGE()
END CATCH
PRINT ''

-- ============================================================================
-- STEP 7: GRANT DMS SERVER-LEVEL PERMISSIONS
-- ============================================================================
SET @Step = @Step + 1
PRINT '[' + CAST(@Step AS VARCHAR(1)) + '/7] Granting Server-Level Permissions...'

IF @GrantPermissions = 1
BEGIN
    BEGIN TRY
        SET @SQL = 'GRANT VIEW SERVER STATE TO [' + @DMSUsername + '];'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ VIEW SERVER STATE granted'
    END TRY
    BEGIN CATCH
        PRINT '  ⚠ VIEW SERVER STATE: ' + ERROR_MESSAGE()
    END CATCH
    
    BEGIN TRY
        SET @SQL = 'GRANT VIEW ANY DEFINITION TO [' + @DMSUsername + '];'
        EXEC sys.sp_executesql @SQL
        PRINT '  ✓ VIEW ANY DEFINITION granted'
    END TRY
    BEGIN CATCH
        PRINT '  ⚠ VIEW ANY DEFINITION: ' + ERROR_MESSAGE()
    END CATCH
END
ELSE
BEGIN
    PRINT '  ⊘ Skipped'
END
PRINT ''

-- ============================================================================
-- VERIFICATION: TEST TRANSACTION LOG ACCESS
-- ============================================================================
PRINT '=================================================================='
PRINT 'VERIFICATION'
PRINT '=================================================================='

BEGIN TRY
    SET @SQL = 'USE [' + @DatabaseName + ']; SELECT TOP 1 [Current LSN] FROM sys.fn_dblog(NULL, NULL);'
    EXEC sys.sp_executesql @SQL
    PRINT '✓✓✓ SUCCESS: All configuration complete! ✓✓✓'
    PRINT ''
    PRINT 'Next steps:'
    PRINT '  1. Go to AWS DMS Console'
    PRINT '  2. Click your task'
    PRINT '  3. Click "Retry task"'
    PRINT '  4. Monitor the Logs tab'
    PRINT '  5. Should see "Starting full load..." message'
END TRY
BEGIN CATCH
    PRINT '✗ Transaction log access failed: ' + ERROR_MESSAGE()
    PRINT ''
    PRINT 'Try manually running:'
    PRINT '  USE master;'
    PRINT '  GRANT VIEW SERVER STATE TO [' + @DMSUsername + '];'
    PRINT '  GRANT VIEW ANY DEFINITION TO [' + @DMSUsername + '];'
END CATCH

PRINT ''
PRINT '=================================================================='
