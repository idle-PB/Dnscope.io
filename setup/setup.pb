; use this one of the below Ethernet Or wif fi To set the dns on the Default connection 
; If its adapter it might vary you can find which is what With 
;     
; netsh Interface ip show config
; 
; ;then either of 
; 
; netsh Interface ip add dns "Ethernet" 127.0.0.1
; netsh Interface ip add dns "Ethernet" 1.1.1.1 index=2
; 
; netsh Interface ip add dns "Wi-fi 2" 127.0.0.1  
; netsh Interface ip add dns "Wi-fi 2" 1.1.1.1 index=2
; 
;
; netsh Interface teredo set state disabled;
; netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
;
; netsh interface ipv4 show addresses "Ethernet"  

; It's only doing IPV4 at the moment that requires you to change the adapter to IPV4 only 

XIncludeFile "..\shelllink.pbi"
XIncludeFile "..\adapterinfo.pb"

XIncludeFile "euladnscope.pbi"  

#ProgramTitle = "DNScopeSetup "
#ProgramVersion = "v0.8.4.6b"
#MSGABOUT = #ProgramTitle + #ProgramVersion + " " + Chr($00A9) + " 2023 Andrew Ferguson"  

Global installpath.s  
Global gPortable 

Procedure SetPrefs() 
  Protected path.s,path1.s,ct,result 
  
  If dnsset\bPortable 
    path.s = GetPathPart(ProgramFilename()) + "DNScope\"
  Else 
    path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\"
  EndIf   
  
  If FileSize(path) < 0 
    CreateDirectory(path) 
  EndIf 
  path1 = path + "DNScope.ini"   
  
  If Not OpenPreferences(path1) 
    result = CreatePreferences(path1) 
  Else 
    result = 1  
  EndIf 
  
  If result 
    
    PreferenceGroup("Global")   
       
    WritePreferenceString("Installed",installpath) 
    
    If dnsset\bshortut  
      WritePreferenceLong("Shortcut",1)
    EndIf 
    
    If dnsset\bstartup 
      WritePreferenceLong("Startup",1)
    EndIf
    
    If dnsset\bPortable  = 1                   
      WritePreferenceLong("Portable",1)
    EndIf  
    
    If dnsset\bcache  = 1 
      WritePreferenceLong("Cache",1)
    EndIf 
    
    If dnsset\bAdapter = 1 
       WritePreferenceLong("SetAdapter",1)
    EndIf 
     
    ForEach IPAdapterInfoList() 
      If IPAdapterInfoList()\GateWayAdress <> "0.0.0.0" 
        ct+1  
        PreferenceGroup("OrigonalIP"+Str(ct)) 
        WritePreferenceLong("Adapter", IPAdapterInfoList()\Index) 
        WritePreferenceString("IPAddress" ,IPAdapterInfoList()\IPAdress)
        WritePreferenceLong("DHCP", IPAdapterInfoList()\Dhcp) 
        WritePreferenceString("Subnet", IPAdapterInfoList()\IPMask) 
        WritePreferenceString("Gateway", IPAdapterInfoList()\GateWayAdress) 
      EndIf   
    Next   
        
    WritePreferenceLong("Adapters",ct) 
        
    PreferenceGroup("DNS") 
    ct=1 
    ForEach DNSinfoList() 
      WritePreferenceString("DNSAddress"+Str(ct),DNSinfoList()\Name) 
      ct+1  
    Next  
      
    WritePreferenceLong("Dnscount",ct) 
    
    PreferenceGroup("WindowPosition") 
    WritePreferenceLong("x",0)
    WritePreferenceLong("y",0)
    WritePreferenceLong("w",800)
    WritePreferenceLong("h",600)
    ClosePreferences()   
  EndIf    
    
EndProcedure  

Procedure ReadPrefs() 
  Protected path.s ,count,a,ct,result    
      
  path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\DNScope.ini"
 
  If OpenPreferences(path) 
     result = 1  
  Else   
     path.s = GetPathPart(ProgramFilename()) + "DNScope\DNScope.ini"
     If OpenPreferences(path) 
      result = 1  
    EndIf 
  EndIf   
    
  ClearList(IPAdapterInfoList()) 
  
  If result 
    PreferenceGroup("Global") 
        
    count = ReadPreferenceLong("Adapters",1) 
    For a = 1 To count 
      AddElement(IPAdapterInfoList()) 
      PreferenceGroup("OrigonalIP"+Str(a))
      IPAdapterInfoList()\AdapterName = ReadPreferenceString("Adapter","")
      IPAdapterInfoList()\IPAdress = ReadPreferenceString("IPAddress","")
      IPAdapterInfoList()\Dhcp = ReadPreferenceLong("DHCP",0) 
      IPAdapterInfoList()\GateWayAdress = ReadPreferenceString("Gateway","")
      IPAdapterInfoList()\IPMask = ReadPreferenceString("Subnet","") 
    Next 
    
    ClearList(DNSinfoList())  
    PreferenceGroup("Global") 
    count = ReadPreferenceLong("Dnscount",1)
    For a = 1 To count 
       PreferenceGroup("DNS")
       AddElement(DNSinfoList())
       DNSinfoList()\Name = ReadPreferenceString("DNSAddress"+Str(ct),"")  
    Next 
       
    ClosePreferences()   
  EndIf    
    
EndProcedure   

Procedure _RunProgram(program.s, command.s) 
  Protected output$,prog,ok,input$ 
  
  Output$ = command + Chr(10) 
  
  prog = RunProgram(program,command,"",#PB_Program_Read |#PB_Program_Write | #PB_Program_Open | #PB_Program_Hide)   
  If prog 
   While ProgramRunning(prog)
      If AvailableProgramOutput(prog)
        input$ = ReadProgramString(prog)
        Output$ + input$ + Chr(13)
      EndIf
    Wend
    Output$ + Chr(13) 
    ok = ProgramExitCode(prog)
    CloseProgram(prog) 
 EndIf
 
 Debug output$
 ProcedureReturn ok   
  
EndProcedure  

Procedure DisableIPV6(state.s="disabled") 
  Protected output$ 
  
  If (state = "disabled" Or state = "enabled")  
    If state = "enabled"  
      _RunProgram("netsh","Interface teredo set state Default")
    Else 
      _RunProgram("netsh","Interface teredo set state disabled")
    EndIf 
    _RunProgram("netsh","Interface ipv6 6to4 set state state=" + state + " undoonstop=" + state)  
    _RunProgram("netsh","Interface ipv6 isatap set state state=" + state)
  EndIf 
  
EndProcedure 

Procedure DisableDNS(disable=1) 
  Protected cmd.s   
  If disable 
    cmd = "add " + Chr(34) + "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" + Chr(34) + " /v Start /t REG_DWORD /d 4 /f"
  Else   
    cmd = "add " + Chr(34) + "HKLM\SYSTEM\CurrentControlSet\services\Dnscache" + Chr(34) + " /v Start /t REG_DWORD /d 2 /f"
  EndIf 
  
  _RunProgram("REG",cmd) 
    
 EndProcedure   

Procedure SetAdapter() 
  Protected output$,pos,input$  

  GetIPAdaptersInfo()
  GetDNSInfo()   
  
  ForEach IPAdapterInfoList()  
  If IPAdapterInfoList()\GateWayAdress <> "0.0.0.0"  ;\ adapters() <> "" 
    _RunProgram("netsh","Interface ip set dnsservers name=" + Chr(34) +  Str(IPAdapterInfoList()\Index) + Chr(34) + " source=Static address=none")
    If IPAdapterInfoList()\DHCP = 1 
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.1")  
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.2 index=2")
    ElseIf IPAdapterInfoList()\DHCP = 0  
       ;need to reset gateway 
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " " + IPAdapterInfoList()\IPAdress)  
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.2 index=2")
    EndIf  
  EndIf 
  Next 
  
EndProcedure 

Procedure ResetAdapter() 
  
  Readprefs() 
  ForEach IPAdapterInfoList()   
     _RunProgram("netsh","Interface ip set dnsservers name=" + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " source=dhcp") 
  Next 
   
EndProcedure   

Procedure Install() 
     
  Protected Msg$,x
  Protected InitialPath$ = GetUserDirectory(#PB_Directory_Programs) 
  Protected Path$
  
  If dnsset\bPortable = 0
     Path$ = PathRequester("Please select the path to install", InitialPath$)
  Else 
     Path$ = GetPathPart(ProgramFilename())  
  EndIf 
    
  If Path$ <> ""
    
    If dnsset\bPortable = 0
    path$+"DNScope\"
    x = FileSize(Path$)
    If x = -1 
      If CreateDirectory(path$) = 0 
        msg$ = "failed to create directory " + path$
        Goto Error
      EndIf 
    EndIf 
    EndIf 
    
    installpath = path$
    
    If FileSize(path$+"DNScope.exe") 
      DeleteFile(path$+"DNScope.exe",#PB_FileSystem_Force)   
    EndIf 
    If CreateFile(0,path$+"DNScope.exe") 
      WriteData(0,?d1,?d2-?d1) 
      CloseFile(0) 
    Else 
      msg$ = "failed to create file DNScope.exe"
      Goto Error
    EndIf   
    
    If dnsset\bPortable = 0
      If FileSize(path$+"Uninstall.exe") 
        SetFileAttributes(path$+"Uninstall.exe", #PB_FileSystem_Normal)   
        DeleteFile(path$+"Uninstall.exe",#PB_FileSystem_Force)   
      EndIf   
      If CreateFile(1,path$+"Uninstall.exe")
        WriteData(1,?d2,?d3-?d2) 
        CloseFile(1) 
        SetFileAttributes(path$+"Uninstall.exe", #PB_FileSystem_Hidden | #PB_FileSystem_ReadOnly )
      Else 
        msg$ = "failed to create file Uninstall.exe"
        Goto Error
      EndIf
     EndIf  
    Goto Done   
  Else
    msg$ = "path doesn't exist exiting setup" 
    Goto Error    
  EndIf
    
  Error: 
  MessageRequester("DNScope setup","error " + msg$)
  End 
  
  Done:
    ;DisableIPV6() ;enabled 
  Protected outmsg.s
  If dnsset\bCache <> 0
    outmsg.s = "Note you will need to restart the computer before setups takes full effect " + #CRLF$  
    outmsg + " You can run Dnscope now though and restart later " + #CRLF$   
  EndIf   
  outmsg + " Do you want to start DNScope now ?"  
    
  SetPrefs() 
  
  If  MessageRequester("DNScope setup",outmsg ,#PB_MessageRequester_YesNo) = #PB_MessageRequester_Yes  
     RunProgram(path$+"DNScope.exe") 
  EndIf   
      
  End  
    
   DataSection
    d1:
    IncludeBinary "..\bin\DNScope.exe" 
    d2:
    IncludeBinary "..\bin\Uninstall.exe"
    d3: 
    
  EndDataSection   
      
EndProcedure 

If Open_LogonWindow()
   If dnsset\bPortable = 0 
     If dnsset\bstartup 
       ShellLinkAddtoStartMenu("DNScope")
     EndIf 
     If dnsset\bshortut 
       ShellLinkAddtoDesktop("DNScope")
     EndIf  
     If dnsset\bCache 
       DisableDNS() 
     EndIf 
   EndIf
   
   If dnsset\bAdapter 
      SetAdapter() 
   EndIf   
   
   Install() 
      
EndIf   

