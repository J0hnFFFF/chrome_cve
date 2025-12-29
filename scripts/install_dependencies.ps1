# Chrome CVE 框架依赖安装脚本
# 解决 agentlib 和 browser 的所有依赖问题

Write-Host "Chrome CVE 框架依赖安装" -ForegroundColor Green
Write-Host "=" * 70

# 1. 安装 agentlib 核心依赖
Write-Host "`n[1/4] 安装 langchain 核心组件..." -ForegroundColor Yellow
pip install langchain-core langchain-text-splitters

# 2. 安装 agentlib
Write-Host "`n[2/4] 安装 agentlib..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\src\agentlib"
pip install -e .

# 3. 安装 browser 依赖
Write-Host "`n[3/4] 安装 browser 依赖..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\src\browser"
pip install -r requirements.txt

# 4. 安装可选增强功能
Write-Host "`n[4/4] 安装可选增强功能..." -ForegroundColor Yellow
pip install rich beautifulsoup4 lxml pefile

# 验证安装
Write-Host "`n验证安装..." -ForegroundColor Green
python -c "from agentlib.lib.common.parsers import BaseParser; print('✓ agentlib 导入成功')"
python -c "from browser.agents import OrchestratorAgent; print('✓ browser 导入成功')"
python -c "import rich; print('✓ rich 导入成功')"
python -c "import bs4; print('✓ beautifulsoup4 导入成功')"

Write-Host "`n安装完成！" -ForegroundColor Green
Write-Host "现在可以运行: python -m browser.main --cve CVE-2021-21220" -ForegroundColor Cyan
