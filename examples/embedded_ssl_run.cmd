@echo off
echo Reset the PATH so that no dependencies will be found
set backup_path=%path%
set path=
embedded_ssl.exe
set path=%backup_path%
set backup_path=
