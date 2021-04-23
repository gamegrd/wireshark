@ECHO OFF
echo https://blog.csdn.net/fjh1997/article/details/88686073
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64
Title Debug
:BEGIN
cd ..
mkdir build
cd build
mkdir msvc16
cd msvc16
set QT5_BASE_DIR=C:\Qt\5.15.2
set CMAKE_PREFIX_PATH=C:\Qt\5.15.2\msvc2019_64\lib\cmake
set WIRESHARK_TARGET_PLATFORM=win64
set WIRESHARK_BASE_DIR=C:\Development\wireshark
set WIRESHARK_VERSION_EXTRA=-xgDebug
cmake -G "Visual Studio 16 2019" -A x64 ..\..\wireshark
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
cd ..\..\
echo %cd%
echo ========================OK====================
pause
goto BEGIN