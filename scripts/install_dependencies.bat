@echo off
REM Chrome CVE 框架依赖安装脚本 (CMD 版本)
REM 解决 agentlib 和 browser 的所有依赖问题

echo ======================================================================
echo Chrome CVE 框架依赖安装
echo ======================================================================

REM 1. 安装 langchain 核心组件
echo.
echo [1/4] 安装 langchain 核心组件...
pip install langchain-core langchain-text-splitters
if %errorlevel% neq 0 (
    echo 错误: langchain-core 安装失败
    pause
    exit /b 1
)

REM 2. 安装 agentlib
echo.
echo [2/4] 安装 agentlib...
cd /d "%~dp0..\src\agentlib"
pip install -e .
if %errorlevel% neq 0 (
    echo 错误: agentlib 安装失败
    pause
    exit /b 1
)

REM 3. 安装 browser 依赖
echo.
echo [3/4] 安装 browser 依赖...
cd /d "%~dp0..\src\browser"
if exist requirements.txt (
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo 警告: 部分 browser 依赖安装失败
    )
) else (
    echo 警告: requirements.txt 不存在，跳过
)

REM 4. 安装可选增强功能
echo.
echo [4/4] 安装可选增强功能...
pip install rich beautifulsoup4 lxml pefile
if %errorlevel% neq 0 (
    echo 警告: 部分可选功能安装失败
)

REM 验证安装
echo.
echo ======================================================================
echo 验证安装...
echo ======================================================================

python -c "from agentlib.lib.common.parsers import BaseParser; print('✓ agentlib 导入成功')"
if %errorlevel% neq 0 (
    echo ✗ agentlib 导入失败
    pause
    exit /b 1
)

python -c "from browser.agents import OrchestratorAgent; print('✓ browser 导入成功')"
if %errorlevel% neq 0 (
    echo ✗ browser 导入失败
    pause
    exit /b 1
)

python -c "import rich; print('✓ rich 导入成功')" 2>nul
python -c "import bs4; print('✓ beautifulsoup4 导入成功')" 2>nul

echo.
echo ======================================================================
echo 安装完成！
echo ======================================================================
echo.
echo 现在可以运行:
echo   cd D:\code\chrome_cve\src
echo   python -m browser.main --cve CVE-2021-21220
echo.
pause
