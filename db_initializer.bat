@echo off
REM This script runs an SQL file to create a database

REM Set PostgreSQL credentials and database connection details
set PGHOST=localhost
set PGPORT=5432
set PGUSER=your_username
set PGPASSWORD=your_password

REM Run the SQL file using psql
psql -h %PGHOST% -p %PGPORT% -U %PGUSER% -f "Initializer.sql"

REM Check for success or failure
if %ERRORLEVEL%==0 (
    echo Database creation completed successfully.
) else (
    echo Failed to create the database.
)

REM Pause to keep the command window open
pause