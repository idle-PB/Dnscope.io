CompilerIf #PB_Compiler_OS = #PB_OS_Windows 

Procedure CreateShellLink(PATH$, LINK$, Argument$, DESCRIPTION$, WorkingDirectory$, ShowCommand.l, HotKey.l, IconFile$, IconIndexInFile.l)
  Protected psl.IShellLinkA,ppf.IPersistFile,*mem,len,hres,res.s
  
  CoInitialize_(0)
  If CoCreateInstance_(?CLSID_ShellLink,0,1,?IID_IShellLink,@psl.IShellLinkA) = 0
     
   Set_ShellLink_preferences:
   psl\SetPath(PATH$)
   psl\SetArguments(Argument$)
   psl\SetWorkingDirectory(WorkingDirectory$)
   psl\SetDescription(DESCRIPTION$)
   psl\SetShowCmd(ShowCommand)
   psl\SetHotkey(HotKey)
   psl\SetIconLocation(IconFile$, IconIndexInFile)
        
   ShellLink_SAVE:
      If psl\QueryInterface(?IID_IPersistFile,@ppf.IPersistFile) = 0
        hres = ppf\Save(link$,#True)
        ppf\Release()
      EndIf
      psl\Release()
   EndIf
   CoUninitialize_()
   ProcedureReturn hres ! 1
   
   DataSection
     CLSID_ShellLink:
       ; 00021401-0000-0000-C000-000000000046
       Data.l $00021401
       Data.w $0000,$0000
       Data.b $C0,$00,$00,$00,$00,$00,$00,$46
     IID_IShellLink:
       ; DEFINE_SHLGUID(IID_IShellLinkA,0x000214EEL, 0, 0);
       ; C000-000000000046
       Data.l $000214EE
       Data.w $0000,$0000
       Data.b $C0,$00,$00,$00,$00,$00,$00,$46
     IID_IPersistFile:
       ; 0000010b-0000-0000-C000-000000000046
       Data.l $0000010b
       Data.w $0000,$0000
       Data.b $C0,$00,$00,$00,$00,$00,$00,$46
   EndDataSection

EndProcedure

Procedure.s GetSpecialFolderLocation(Value.l)
  Protected Folder_ID,SpecialFolderLocation.s
 
  If SHGetSpecialFolderLocation_(0, Value, @Folder_ID) = 0
    SpecialFolderLocation = Space(#MAX_PATH*2)
    SHGetPathFromIDList_(Folder_ID, @SpecialFolderLocation)
    If SpecialFolderLocation
      If Right(SpecialFolderLocation, 1) <> "\"
        SpecialFolderLocation + "\"
      EndIf
    EndIf
    CoTaskMemFree_(Folder_ID)
  EndIf
   ProcedureReturn SpecialFolderLocation.s
EndProcedure

#CSIDL_STARTUP = $7
#CSIDL_APPDATA = $1A
#CSIDL_DESKTOP = 0  

Procedure DeleteDesktoplink(prog.s) 
  
  Protected path.s = GetSpecialFolderLocation(#CSIDL_DESKTOP) + prog + ".lnk"
  
  If FileSize(path) 
    DeleteFile(path,#PB_FileSystem_Force) 
  EndIf    
  
EndProcedure   

Procedure DeleteStartUplink(prog.s) 
  
  Protected path.s = GetSpecialFolderLocation(#CSIDL_STARTUP) + prog + ".lnk"
  
  If FileSize(path) 
    DeleteFile(path,#PB_FileSystem_Force) 
  EndIf
  
 EndProcedure  

Procedure ShellLinkAddtoDesktop(prog.s) 
  
  Protected tpath.s = GetSpecialFolderLocation(#CSIDL_DESKTOP) + prog + ".lnk"
  CreateShellLink(ProgramFilename(),tpath,"",prog,"",0,0,ProgramFilename(),0)
  Debug Tpath 
  
 EndProcedure  

Procedure ShellLinkAddtoStartMenu(prog.s)
  Protected tpath.s = GetSpecialFolderLocation(#CSIDL_STARTUP) + prog + ".lnk"
  CreateShellLink(ProgramFilename(),tpath,"",prog,"",0,0,ProgramFilename(),0)
  Debug Tpath 
EndProcedure 

CompilerEndIf  

; IDE Options = PureBasic 6.01 LTS beta 1 (Windows - x64)
; CursorPosition = 2
; Folding = --
; EnableXP
; DPIAware
; Executable = DNScope_0_6_2_a\DNScope.exe