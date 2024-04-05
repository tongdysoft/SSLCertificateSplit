SET name=SSLCertificateSplittingTool
SET version=1.0.0
RD /S /Q bin
MKDIR bin
COPY README.md bin\
COPY ico\icon.png bin\
COPY %name%.desktop bin\
SET CGO_ENABLED=0

SET GOOS=windows

ECHO Compiling Windows x86
SET GOARCH=386
go generate
MKDIR bin\%name%_windows-x86
go build -o bin\%name%_windows-x86\%name%.exe
COPY README.md bin\%name%_windows-x86\
DEL /Q *.syso

ECHO Compiling Windows x64
SET GOARCH=amd64
go generate
MKDIR bin\%name%_windows-x64
go build -o bin\%name%_windows-x64\%name%.exe
COPY README.md bin\%name%_windows-x64\
DEL /Q *.syso

ECHO Compiling Windows ARM32
SET GOARCH=arm
go generate
MKDIR bin\%name%_windows-arm32
go build -o bin\%name%_windows-arm32\%name%.exe
COPY README.md bin\%name%_windows-arm32\
DEL /Q *.syso

ECHO Compiling Windows ARM64
SET GOARCH=arm64
go generate
MKDIR bin\%name%_windows-arm64
go build -o bin\%name%_windows-arm64\%name%.exe
COPY README.md bin\%name%_windows-arm64\
DEL /Q *.syso

SET GOOS=darwin

MKDIR bin\%name%.app
MKDIR bin\%name%.app\Contents
COPY Info.plist bin\%name%.app\Contents
MKDIR bin\%name%.app\Contents\Resources
COPY ico\icon.icns bin\%name%.app\Contents\Resources
MKDIR bin\%name%.app\Contents\MacOS
MKDIR bin\%name%_macos-x64
XCOPY bin\%name%.app bin\%name%_macos-x64\%name%.app /E /I
MKDIR bin\%name%_macos-arm64
XCOPY bin\%name%.app bin\%name%_macos-arm64\%name%.app /E /I
RD /S /Q bin\%name%.app

ECHO Compiling macOS x64
SET GOARCH=amd64
go build -o bin\%name%_macos-x64\%name%
COPY README.md bin\%name%_macos-x64\
COPY bin\%name%_macos-x64\%name% bin\%name%_macos-x64\%name%.app\Contents\MacOS\

ECHO Compiling macOS ARM64
SET GOARCH=arm64
go build -o bin\%name%_macos-arm64\%name%
COPY README.md bin\%name%_macos-arm64\
COPY bin\%name%_macos-arm64\%name% bin\%name%_macos-arm64\%name%.app\Contents\MacOS\

SET GOOS=linux

ECHO Compiling Linux x86
SET GOARCH=386
MKDIR bin\%name%_linux-x86
go build -o bin\%name%_linux-x86\%name%
COPY README.md bin\%name%_linux-x86\
COPY ico\icon.png bin\%name%_linux-x86\
COPY %name%.desktop bin\%name%_linux-x86\

ECHO Compiling Linux x64
SET GOARCH=amd64
MKDIR bin\%name%_linux-x64
go build -o bin\%name%_linux-x64\%name%
COPY README.md bin\%name%_linux-x64\
COPY ico\icon.png bin\%name%_linux-x64\
COPY %name%.desktop bin\%name%_linux-x64\

ECHO Compiling Linux ARM32
SET GOARCH=arm
MKDIR bin\%name%_linux-arm32
go build -o bin\%name%_linux-arm32\%name%
COPY README.md bin\%name%_linux-arm32\
COPY ico\icon.png bin\%name%_linux-arm32\
COPY %name%.desktop bin\%name%_linux-arm32\

ECHO Compiling Linux ARM64
SET GOARCH=arm64
MKDIR bin\%name%_linux-arm64
go build -o bin\%name%_linux-arm64\%name%
COPY README.md bin\%name%_linux-arm64\
COPY ico\icon.png bin\%name%_linux-arm64\
COPY %name%.desktop bin\%name%_linux-arm64\

CD bin
for /d %%D in (*) do (
    7z a -tzip -mx=9 "%%D.zip" "%%D"
    RD /S /Q "%%D"
)
DEL *.md
DEL *.png
DEL *.desktop
openssl sha256 %name%_*.zip >%name%_%version%.sha256.txt
CD ..

SET name=
SET version=
SET CGO_ENABLED=
SET GOOS=
SET GOARCH=
