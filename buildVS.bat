@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x64

mkdir %~dp0\build
pushd %~dp0\build

rc -fo dhdAlert.res ..\dhdAlert.rc
cl -Zi -FC ..\dhdAlert.cpp ..\build\dhdAlert.res user32.lib gdi32.lib gdiplus.lib ole32.lib shell32.lib Comctl32.lib

popd