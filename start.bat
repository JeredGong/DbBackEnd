@echo off
setlocal enabledelayedexpansion

REM -----------》》检查数据库是否正在运行
@echo off
echo -^>^>^> 检查数据库服务是否运行中...
sc query postgresql-x64-17 | findstr /i "RUNNING"
if %errorlevel%==0 (
    echo ^<^<^< PostgreSQL-x64-17 服务正在运行.
) else (
    echo ^<^<^< PostgreSQL-x64-17 服务没有运行.
    echo ^<^<^< 尝试启动 PostgreSQL
    sc start postgresql-x64-17

    if %errorlevel%==0 (
        echo ^<^<^< PostgreSQL 服务成功启动.
    ) else (
        echo ^<^<^< 启动 PostgreSQL 服务失败.
        exit /b 1
    )
)

REM -------------》》检查所需数据库是否存在
echo -^>^>^> 检查所需数据库是否存在...
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
    echo ^<^<^< Database %DB% 存在.
) else (
    echo ^<^<^< Database %DB% 不存在,或psql路径不在环境变量
    exit /b 1
)

REM -------------》》检查是否在项目根目录
@echo off
echo -^>^>^> 检查是否在项目根目录...
set FILE_NAME=DBBackEnd.exe

REM 检查文件是否存在
if exist "%FILE_NAME%" (
    echo ^<^<^< 文件 %FILE_NAME% 存在.
) else (
    echo ^<^<^< 文件 %FILE_NAME% 不存在. 检查是否在项目根目录
    exit /b 1
)

REM ---------》》启动 Rust 后端服务
start "" "file.exe"
endlocal