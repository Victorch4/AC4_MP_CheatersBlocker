"""
Build script for CheatersBlocker using PyInstaller
Run: python build.py
"""

import PyInstaller.__main__
import os
import shutil

# Clean previous builds
print("Cleaning previous builds...")
if os.path.exists('dist'):
    shutil.rmtree('dist')
if os.path.exists('build'):
    shutil.rmtree('build')

# Create build arguments
args = [
    'main.py',  # Main application file
    '--name=CheatersBlocker',
    '--onefile',  # Single executable
    '--windowed',  # No console window
    '--icon=data/logo.ico',
    '--add-data=data/logo.ico;data/',  # Include icon
    '--add-data=audio/*;audio/',  # Include audio files
    '--clean',
    '--noconfirm',
    '--hidden-import=PyQt6.QtWidgets',
    '--hidden-import=PyQt6.QtCore',
    '--hidden-import=PyQt6.QtGui',
    '--hidden-import=PyQt6.QtMultimedia',
    '--hidden-import=configparser',
    '--hidden-import=requests',
    '--hidden-import=ipaddress',
]

print("Starting PyInstaller build...")
PyInstaller.__main__.run(args)

print("\nBuild completed successfully!")
print("Executable file: dist/CheatersBlocker.exe")
print("\nNote: The executable requires the following in the same directory:")
print("1. audio/ folder with sound files (included in executable)")
print("2. data/ folder with icon (included in executable)")
print("3. block_status.ini (created automatically)")
print("4. settings.ini (created automatically)")
