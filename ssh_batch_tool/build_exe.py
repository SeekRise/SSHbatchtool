#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH批量运维工具打包脚本
用于将main_gui.py打包为Windows可执行文件
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).parent.absolute()

# 主程序文件
MAIN_SCRIPT = BASE_DIR / "main_gui.py"

# 图标文件
ICON_FILE = BASE_DIR / "favicon.ico"

# 输出目录
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"

# 配置文件列表（需要复制到dist目录的文件）
CONFIG_FILES = [
    BASE_DIR / "config.yaml",
    BASE_DIR / "hosts_data.json"
]

def run_command(cmd, cwd=None):
    """执行命令并返回结果"""
    print(f"执行命令: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        shell=True
    )
    print(f"返回码: {result.returncode}")
    if result.stdout:
        print(f"输出:\n{result.stdout}")
    if result.stderr:
        print(f"错误:\n{result.stderr}")
    return result

def check_pyinstaller():
    """检查PyInstaller是否已安装"""
    print("检查PyInstaller是否已安装...")
    result = run_command([sys.executable, "-m", "pip", "list"])
    if "pyinstaller" in result.stdout.lower():
        print("✓ PyInstaller已安装")
        return True
    else:
        print("✗ PyInstaller未安装，正在安装...")
        result = run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"])
        if result.returncode == 0:
            print("✓ PyInstaller安装成功")
            return True
        else:
            print("✗ PyInstaller安装失败")
            return False

def clean_old_builds():
    """清理旧的构建文件"""
    print("清理旧的构建文件...")
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
        print(f"✓ 删除目录: {DIST_DIR}")
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print(f"✓ 删除目录: {BUILD_DIR}")

def create_spec_file():
    """创建PyInstaller spec文件"""
    spec_content = """
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{}'],
    pathex=['{}'],
    binaries=[],
    datas=[
        ('{}/config.yaml', '.'),
        ('{}/hosts_data.json', '.'),
        ('{}/favicon.ico', '.'),
    ],
    hiddenimports=['paramiko', 'yaml', 'tkinter', 'logging', 'threading', 'queue', 'json', 'time', 're', 'datetime', 'sys', 'os', 'concurrent.futures'],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SSH批量运维工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='{}',
)
"""
    
    spec_file = BASE_DIR / "ssh_batch_tool.spec"
    with open(spec_file, "w", encoding="utf-8") as f:
        f.write(spec_content.format(
            MAIN_SCRIPT,
            BASE_DIR,
            BASE_DIR,
            BASE_DIR,
            BASE_DIR,
            ICON_FILE
        ))
    print(f"✓ 创建spec文件: {spec_file}")
    return spec_file

def build_exe():
    """使用PyInstaller打包程序"""
    print("使用PyInstaller打包程序...")
    
    # 构建命令，显式指定输出目录
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconsole",
        "--onefile",
        f"--name=SSH批量运维工具",
        f"--icon={ICON_FILE}",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        f"--specpath={BASE_DIR}",
        str(MAIN_SCRIPT)
    ]
    
    result = run_command(cmd)
    
    if result.returncode == 0:
        print("✓ 打包成功")
        return True
    else:
        print("✗ 打包失败")
        return False

def copy_config_files():
    """复制配置文件到dist目录"""
    print("复制配置文件到dist目录...")
    
    # 确保dist目录存在
    if not DIST_DIR.exists():
        print(f"⚠ 目标目录不存在，创建: {DIST_DIR}")
        DIST_DIR.mkdir(parents=True, exist_ok=True)
    
    for config_file in CONFIG_FILES:
        if config_file.exists():
            dest = DIST_DIR / config_file.name
            shutil.copy2(config_file, dest)
            print(f"✓ 复制文件: {config_file.name} -> {dest}")
        else:
            print(f"⚠ 配置文件不存在: {config_file}")

def main():
    """主函数"""
    print("=" * 50)
    print("SSH批量运维工具打包脚本")
    print("=" * 50)
    
    # 1. 检查PyInstaller
    if not check_pyinstaller():
        print("\n❌ 打包失败：PyInstaller安装失败")
        return 1
    
    # 2. 清理旧的构建文件
    clean_old_builds()
    
    # 3. 打包程序
    if not build_exe():
        print("\n❌ 打包失败：PyInstaller构建失败")
        return 1
    
    # 4. 复制配置文件
    copy_config_files()
    
    print("\n" + "=" * 50)
    print("✅ 打包完成！")
    print(f"可执行文件位置: {DIST_DIR}")
    print(f"执行命令: {DIST_DIR}/SSH批量运维工具.exe")
    print("=" * 50)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())