
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

EnableExplicit

Structure setup 
  baccept.i 
  bPortable.i
  bstartup.i 
  bshortut.i 
  bCache.i
  bAdapter.i 
  path.s 
EndStructure   

Global dnsset.setup 

Procedure ReadPrefs() 
  Protected count,a,ct   
  Protected result
  
  dnsset\path = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\DNScope.ini"
   
  If OpenPreferences(dnsset\path) 
     result = 1  
  Else   
    dnsset\path = GetPathPart(ProgramFilename()) + "DNScope\DNScope.ini"
     If OpenPreferences(dnsset\path) 
      result = 1  
    EndIf 
  EndIf   
    
  ClearList(IPAdapterInfoList()) 
  
  If result 
    PreferenceGroup("Global") 
    
    dnsset\bstartup = ReadPreferenceLong("Startup",0) 
    dnsset\bshortut = ReadPreferenceLong("Shortcut",0)
    dnsset\bCache = ReadPreferenceLong("Cache",0) 
    dnsset\bPortable = ReadPreferenceLong("Portable",0) 
    dnsset\bAdapter = ReadPreferenceLong("SetAdapter",0)
    dnsset\path  =  ReadPreferenceString("Installed","") 
    
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
    CloseProgram(prog) ; Close the connection to the program
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
  
  If _RunProgram("REG",cmd) = 0 
    If disable 
       MessageRequester("DNScope setup","your computer will need to restart to complete the set up",#PB_MessageRequester_Info | #PB_MessageRequester_Info ) 
    EndIf   
  EndIf   
  
 EndProcedure   

Procedure ResetAdapter() 
  
  Readprefs() 
  ForEach IPAdapterInfoList()   
     _RunProgram("netsh","Interface ip set dnsservers name=" + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " source=dhcp") 
  Next 
   
EndProcedure   

Procedure Uninstall() 
   
      
  ReadPrefs()  
  
  If MessageRequester("DNScope Uninstall", "Click yes to Uninstall DNSCcope from " + dnsset\path,#PB_MessageRequester_YesNo) = #PB_MessageRequester_Yes
    
  If dnsset\bPortable = 0 
  
    If dnsset\bAdapter   
      ResetAdapter()
    EndIf   
  
    If dnsset\bCache 
      DisableDNS(0) 
    EndIf 
  
    If dnsset\bshortut   
      DeleteDesktoplink("DNScope") 
    EndIf 
    If dnsset\bstartup
       DeleteStartUplink("DNScope") 
    EndIf    
    
    Protected path.s = dnsset\path
         
    If FindString(path,"DNScope",1) 
      DeleteDirectory(path,"",#PB_FileSystem_Force) 
    EndIf   
        
    path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\"
    If FileSize(path) = -2 
       DeleteDirectory(path,"*.*",#PB_FileSystem_Force)  
    EndIf   
    
    MessageRequester("DNScope.io Scopes Up", "Uninstalled, please restart your computer to complete ")  
    
  EndIf 
    
  EndIf 
  
EndProcedure 

Uninstall() 



