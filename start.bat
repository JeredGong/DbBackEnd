@echo off
setlocal enabledelayedexpansion

REM -----------����������ݿ��Ƿ���������
@echo off
echo -^>^>^> ������ݿ�����Ƿ�������...
sc query postgresql-x64-17 | findstr /i "RUNNING"
if %errorlevel%==0 (
    echo ^<^<^< PostgreSQL-x64-17 ������������.
) else (
    echo ^<^<^< PostgreSQL-x64-17 ����û������.
    echo ^<^<^< �������� PostgreSQL
    sc start postgresql-x64-17

    if %errorlevel%==0 (
        echo ^<^<^< PostgreSQL ����ɹ�����.
    ) else (
        echo ^<^<^< ���� PostgreSQL ����ʧ��.
        exit /b 1
    )
)

REM -------------��������������ݿ��Ƿ����
echo -^>^>^> ����������ݿ��Ƿ����...
REM Set the path to your .env file
set ENV_FILE=.env

REM Read the DATABASE_URL from the .env file
for /f "tokens=1,* delims==" %%a in (%ENV_FILE%) do (
    if "%%a"=="DATABASE_URL" set DATABASE_URL=%%b
)


rem Extract the part after 'postgres://'
for /f "tokens=2 delims=//" %%a in ("!DATABASE_URL!") do (
    set URL=%%a
)

rem Extract the user and password (before the first '@')
for /f "tokens=1 delims=@" %%a in ("!URL!") do (
    set USERPASS=%%a
)

rem Extract the user (before the first ':')
for /f "tokens=1 delims=:" %%a in ("!USERPASS!") do (
    set USER=%%a
)

rem Extract the password (after the first ':')

for /f "tokens=2 delims=:" %%a in ("!USERPASS!") do (
    set PASS=%%a
)

rem Extract the host and port (after '@' but before '/')
for /f "tokens=2 delims=@" %%a in ("!URL!") do (
    set HOSTPORT=%%a
)

rem Extract the host (before the first ':')
for /f "tokens=1 delims=:" %%a in ("!HOSTPORT!") do (
    set HOST=%%a
)

rem Extract the port (after the first ':')
for /f "tokens=2 delims=:" %%a in ("!HOSTPORT!") do (
    set PORTDB=%%a
)
for /f "tokens=1 delims=/" %%a in ("!PORTDB!") do (
    set PORT=%%a
)
rem Extract the database (after the '/')
for /f "tokens=3 delims=/" %%a in ("!DATABASE_URL!") do (
    set DB=%%a
)

REM Output the results
echo USER: !USER!
echo PASS: !PASS!
echo HOST: !HOST!
echo PORT: !PORT!
echo DB: !DB!
endlocal
:: Check if the database exists
echo Checking if database %DB% exists...

:: Use psql to check if the database exists
for /f "tokens=*" %%a in ('psql  -h %HOST% -d %DB% -U %USER% -p %PORT%  -tAc "SELECT 1 FROM pg_database WHERE datname='%DB%'"') do (
    set result=%%a
)

:: If the result is '1', database exists
if "%result%"=="1" (
    echo ^<^<^< Database %DB% ����.
) else (
    echo ^<^<^< Database %DB% ������,��psql·�����ڻ�������
    exit /b 1
)

REM -------------��������Ƿ�����Ŀ��Ŀ¼
@echo off
echo -^>^>^> ����Ƿ�����Ŀ��Ŀ¼...
set FILE_NAME=DBBackEnd.exe

REM ����ļ��Ƿ����
if exist "%FILE_NAME%" (
    echo ^<^<^< �ļ� %FILE_NAME% ����.
) else (
    echo ^<^<^< �ļ� %FILE_NAME% ������. ����Ƿ�����Ŀ��Ŀ¼
    exit /b 1
)

REM ---------�������� Rust ��˷���
start "" "file.exe"
endlocal