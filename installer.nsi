; The name of the installer
Name "Pidgin-GPG"

; The file to write
OutFile "PidginGPG.exe"

; The default installation directory
InstallDir $PROGRAMFILES\Pidgin-GPG

; Request application privileges for Windows Vista
RequestExecutionLevel admin

;--------------------------------
; Pages
Page components
Page instfiles
;--------------------------------

; The stuff to install
Section "PidginGPG"
  SectionIn RO
  
  ReadRegStr $0 HKLM SOFTWARE\GNU\GnuPG "Install Directory"
  IfErrors onerror_nogpg
  DetailPrint "Found GnuPG at: $0"
  
  ReadRegStr $1 HKLM SOFTWARE\Pidgin ""
  IfErrors onerror_nopidgin
  DetailPrint "Found Pidgin at: $1"
  
  ReadRegStr $2 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$2;$0"
  DetailPrint "Added gnupg directory to path"
  
  ; Set output path to the installation directory.
  SetOutPath "$1\plugins"
  
  ; Put file there
  File "pidgin_gpg.dll"
  Goto finished

 onerror_nogpg:
  DetailPrint "GPG not found"
  Goto onerror
  
onerror_nopidgin:
  DetailPrint "Pidgin not found"
  Goto onerror

onerror:
  Abort "could not install, see details for more information"
 
finished:
SectionEnd


