EnableExplicit 

Enumeration 100
#Window_Eula  
#Buton_Accept 
#Button_Decline 
#Editor  
#Check_ShortCut  
#Check_Startup  
#Check_portable  
#Check_Cache 
#Check_Adapter 
EndEnumeration 

Structure setup 
  baccept.i 
  bPortable.i
  bstartup.i 
  bshortut.i 
  bCache.i
  bAdapter.i 
EndStructure   

Global dnsset.setup 
Global strEula.s = PeekS(?Eula,?EulaEnd-?Eula,#PB_UTF8) 

Procedure Open_LogonWindow()
  Protected Event
  
   
  If OpenWindow(#Window_Eula, 0,0,580, 480,"DNScope.io Scopes Up! Eula", #PB_Window_ScreenCentered)
    
    ButtonGadget(#Buton_Accept, 15, 365, 300, 25, "I accept the terms of the license agreement")
    ButtonGadget(#Button_Decline, 450, 365, 100, 25, "Decline")
    CheckBoxGadget(#Check_ShortCut,10,400,160,25,"Create Desktop Short cut") 
    GadgetToolTip(#Check_ShortCut,"create a desktop short cut")
    
    SetGadgetState(#Check_ShortCut, #PB_Checkbox_Checked)
    CheckBoxGadget(#Check_Startup,180,400,100,25,"Add to Start up") 
    SetGadgetState(#Check_Startup, #PB_Checkbox_Checked)
    GadgetToolTip(#Check_Startup, "Add Scopes up to startup")  
    
    CheckBoxGadget(#Check_portable,330,400,100,25,"Portable ") 
    SetGadgetState(#Check_portable, #PB_Checkbox_Unchecked)
    GadgetToolTip(#Check_portable, "Stores program data in a subfolder \DNScope where the program is extracted to")
    
    CheckBoxGadget(#Check_Cache,180,440,120,25,"Disable OS Cache ") 
    SetGadgetState(#Check_Cache, #PB_Checkbox_Checked)
    GadgetToolTip(#Check_Cache, "Disables the system dns service, this may have unwanted effects on work groups and networks") 
    
    CheckBoxGadget(#Check_Adapter,10,440,120,25,"Set Adapter") 
    SetGadgetState(#Check_Adapter, #PB_Checkbox_Checked)
    GadgetToolTip(#Check_Adapter,"Set the network adapter if dhcp dns is on localhost or if static dns is the satic IP so you can also forward dns from your router")    
    
    EditorGadget(#Editor, 5, 5, 570, 355, #PB_Editor_ReadOnly)
    SendMessage_(GadgetID(#Editor), #EM_SETTARGETDEVICE, #Null, 0) 
    SetGadgetText(#Editor,strEula)
    
    Repeat
      
      Event = WaitWindowEvent()
      
      If Event = #PB_Event_Gadget
        
        Select EventGadget()
            
          Case #Buton_Accept 
            
            dnsset\baccept = 1 
            
            If GetGadgetState(#Check_portable) = #PB_Checkbox_Checked  
              dnsset\bPortable = 1 
              dnsset\bshortut = 0 
              dnsset\bstartup = 0 
              dnsset\bcache = 0 
              
            EndIf 
            If GetGadgetState(#Check_ShortCut) = #PB_Checkbox_Checked  
              dnsset\bshortut = 1 
              dnsset\bPortable = 0
             
            EndIf 
            If GetGadgetState(#Check_Startup) = #PB_Checkbox_Checked  
              dnsset\bstartup = 1 
              dnsset\bPortable = 0
             
            EndIf
            If GetGadgetState(#Check_Cache) = #PB_Checkbox_Checked  
              dnsset\bcache  = 1 
              dnsset\bPortable = 0
              
            EndIf 
            If GetGadgetState(#Check_Adapter) = #PB_Checkbox_Checked  
              dnsset\bAdapter = 1 
                           
            EndIf 
                       
            Event = #PB_Event_CloseWindow         
          Case #Check_portable  
            If GetGadgetState(#Check_portable)
              SetGadgetState(#Check_ShortCut,0) 
              SetGadgetState(#Check_Startup,0) 
              SetGadgetState(#Check_Cache,0) 
             
            EndIf 
          Case #Check_ShortCut,#Check_Startup,#Check_Cache
             SetGadgetState(#Check_portable,0) 
          Case #Button_Decline
            End 
        EndSelect
        
      EndIf
      
    Until Event = #PB_Event_CloseWindow
    
  EndIf
  
  CloseWindow(#Window_Eula) 
  
  ProcedureReturn dnsset\baccept

EndProcedure

DataSection
    Eula:
    IncludeBinary "..\LICENSE"
    EulaEnd:
EndDataSection 

CompilerIf #PB_Compiler_IsMainFile 
  
  Open_LogonWindow()
  
CompilerEndIf   