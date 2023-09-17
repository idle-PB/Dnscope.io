; DNScope.io Scopes up local firewall cache 
; Copyright (C) 2023  Andrew Ferguson aka IDLE and contributers 
; 
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>

EnableExplicit 

UsePNGImageDecoder()

#ProgramTitle = "DNScope.io Scope's up! "

#ProgramVersion = "v0.8.4.6b"

#MSGABOUT = #ProgramTitle + #ProgramVersion + " " + Chr($00A9) + " 2023 Andrew Ferguson"  

XIncludeFile "shelllink.pbi"
XIncludeFile "bloom.pbi" 
XIncludeFile "squint3.pbi"              
XIncludeFile "httpstatus.pbi" 
XIncludeFile "adapterinfo.pb" 

UseModule SQUINT 

#DNS_MESSAGEFLAG_QR =$8000  ; QR query=0  1=answer 
#DNS_MESSAGEFLAG_AA =$400   ; AA 1 if authoritive 
#DNS_MESSAGEFLAG_TC =$200   ; TC 1 if trunc 
#DNS_MESSAGEFLAG_RD =$100   ; RD 1 if recureson desired  
#DNS_MESSAGEFLAG_RA =$80    ; Ra recursion avail 
#DNS_MESSAGEFLAG_AD =$20    ; 
#DNS_MESSAGEFLAG_CD =$10    ; Rcode 0 or 1 for error 

ImportC "" 
  htons(v.u) 
  ntohs(v.u)  
  htonl(v.l)  
  ntohl(v.l) 
  DateUTC(t.i=0) As "time"  
EndImport   

Structure DNS_Data 
  a.a[0]  
EndStructure 

Structure DNS_Message_Header   
  id.u
  flags.u  ; QR#DNS_MESSAGEFLAG bit field  
  qdCount.u; number of entries in question set to num queries   
  anCount.u; number of entries in answers    
  nscount.u;set 0 ignore
  arCount.u;set to 0 ignore 
EndStructure  

Structure DNS_QUESTION 
  mdata.DNS_Data   
EndStructure 

Structure DNS_QUESTION_DESC 
  qtype.u         ;1 for A recs 15 for mail mx and 2 for NS  
  qClass.u        ; 1 of IP address  
EndStructure   

Structure DNS_ANSWER 
  mdata.DNS_Data
EndStructure   

Structure DNS_ANSWER_DESC    
  Type.u
  Class.u
  TTL.l              ;cache time 
  rdLength.u         ;legnth of r data  
  *rdata.Ascii[128]  ;If Type $1 = A REC IP ADRESS 4 bytes , type $5 CNAME name field , $2 Name Server and if $f mail server  
EndStructure 

Structure DNS_ANSWER_MAIL_DESC
  Preference.u 
  *fxchange.DNS_Data[0]      
EndStructure   

Structure arA 
  a.a[0] 
EndStructure   

Structure DNS_Record 
  keylen.i
  key.s
  ipv4.i
  ipv6.i
  ttl.l 
  time.l
  block.w
  type.u
  stat.w
EndStructure 

Global wsaData.WSADATA 
Macro MAKEWORD(lb,hb) 
  (lb << 8 | hb)
EndMacro   

#WSAHOST_NOT_FOUND = 11001
#WSAEREFUSED = 10112
#WSANO_DATA  =11004
#WSATRY_AGAIN = 11002

Enumeration #PB_EventType_FirstCustomValue 
  #DNS_EVENT_ADD
  #DNS_EvENT_ADD_ACTIVE
  #DNS_EVENT_QUERY 
  #DNS_EVENT_ADD_LOG
EndEnumeration 

Enumeration Windows
  #Main
EndEnumeration

Enumeration MenuBar
  #MainMenu
EndEnumeration

Enumeration MenuItems
  #MainMenuAbout
  #MainMenuExit
  #MainMenuAddStartUP
  #MainMenuAddDesktop
  #MainMenuDonate
  #MainMenuUninstall 
  #OPTIONS  
  #OptionBloom  
  #Optionstatus 
EndEnumeration

Enumeration Gadgets
  #WhiteListGadget
  #BlackListGadget
  #SplitVertical
  #SplitHoritontal 
  #DataGadget
  
  #ActiveTimer
  #SaveTimer 
EndEnumeration

Enumeration StatusBar
  #MainStatusBar
EndEnumeration

Structure IPInfo 
  DHCP.s 
  IPAddress.s 
  Subnet.s 
  gateway.s 
EndStructure   

Structure DNScopeWindow 
  w.i
  h.i
  windowX.i
  windowY.i
  windowWidth.i
  windowHeight.i
  sx.f
  sy.f
  gww.i
  gwh.i
  gwx.i
  gwy.i
  
  lvcount.i
  AllowPos.i
  Blockpos.i
  WhiteText$
  BlackText$ 
  iconGo.i
  iconstop.i
  evt.i
EndStructure

Structure DNScope 
  *squint.isquint
  *bloom.ibloom 
  *rec.DNS_Record
  
  ServerThread.i 
  FifoThread.i 
  mutFifo.i
  
  quit.i
  IP.s
  text$
  
  UseBloom.i
  UseStatus.i
  blockcount.i
  AllowCount.i
  DenyCount.i
  TotalCount.i
  
  Save.i 
  Portable.i     
  
  win.DNScopeWindow
  
  IPINf.ipinfo 
  adapter.s 
   
  
  uninstall.i
EndStructure   

Global DNScope.DNScope 

DNScope\squint = SquintNew() 
DNScope\bloom = Bloom_Decompress(?F1) 

DNScope\UseBloom = 1 
DNScope\IP = "1.1.1.1"

Global NewList fifo.i() 
DNScope\mutFifo = CreateMutex() 

Macro ElapsedSeconds() 
  DateUTC()
EndMacro 

Procedure DNS_Write_Query(IP.s,*len.long) 
  Protected *sa.Ara,pos,ct,st,*out,pos1  
  Protected *header.DNS_Message_Header,*qe.DNS_QUESTION_DESC 
  Protected *q.DNS_QUESTION 
  Protected size = 18+Len(IP)
  Static DNS_MESSAGEID 
  
  DNS_MESSAGEID + 1  
  DNS_MESSAGEID & $FFFE 
  
  *sa = Ascii(IP) 
  *out = AllocateMemory(size) 
  *header = *out   
  *q = *out+SizeOf(DNS_Message_Header) 
  
  *header\id = htons(DNS_MESSAGEID)  
  *header\flags = htons(#DNS_MESSAGEFLAG_RD)    
  *header\qdCount = htons(1) 
  
  st=0
  pos=1
  While *sa\a[pos1] > 32  
    If *sa\a[pos1] <> '.' 
      *q\mdata\a[pos] = *sa\a[pos1]   
      pos+1
      pos1+1
      ct+1  
    Else     
      *q\mdata\a[st] = ct
      ct=0 
      st=pos 
      pos+1
      pos1+1
    EndIf   
  Wend 
  *q\mdata\a[st] = ct
  
  *qe.DNS_QUESTION_DESC = *q+pos+2 
  *qe\qtype = 1 
  *qe\qClass = 1 
  
  *len\l = size 
  ProcedureReturn *out 
EndProcedure   

Procedure DNS_Read_Query(*query,len.l) 
  Protected *header.DNS_Message_Header,*rec.DNS_Record    
  Protected *q.DNS_QUESTION,count,pos1
  Protected ID,flags.u  
  Protected NewList keys.s()  
  Protected out.s,a,ct   
  
  *header= *query 
  ID = *header\id 
  If ID  
    
    flags.u = ntohs(*header\flags)      
    
    If (flags & $8000) = 0  
      count = *header\qdCount 
      *q = *query + SizeOf(DNS_Message_Header) 
      
      pos1=1
      While *q\mdata\a[pos1] <> 0
        len = *q\mdata\a[pos1-1]
        If len 
          ResetList(keys()) 
          AddElement(keys())
          keys() = PeekS(@*q\mdata\a[pos1],len,#PB_UTF8)
          pos1+len 
          pos1+1
        Else 
          Break 
        EndIf   
      Wend  
      
      ct = ListSize(keys())
      FirstElement(keys()) 
      For a = 1 To ct  
        If a <> ct 
          out + keys() + "." 
        Else 
          out + keys()
        EndIf   
        NextElement(keys())   
      Next  
      
      *rec = DNScope\squint\get(0,@out) 
      
      DNScope\TotalCount+1
      
      If *rec = 0 
        If DNscope\UseBloom
          If DNScope\bloom\get(@out,StringByteLength(out))  
            *rec.DNS_Record = AllocateMemory(SizeOf(DNS_Record)) 
            *rec\key = out 
            *rec\ipv4 = -1
            *rec\ttl = DateUTC() + 86400 
            *rec\type = ntohs(1)          
            *rec\block = -1      ; -1 blocked 0 unset 1 allowed    
            *rec\time = ElapsedSeconds()+86400
            *rec\stat = -1
            DNScope\squint\Set(0,@out,*rec) 
            DNScope\DenyCount + 1 
            DNScope\blockcount + 1 
            ProcedureReturn *rec 
          EndIf 
        EndIf 
      EndIf    
      
      ProcedureReturn *rec   
      
    EndIf   
  EndIf 
  
EndProcedure  

Procedure DNS_Read_Answer(*msg,mlen) 
  Protected *header.DNS_Message_Header,adr.l,flags.u  
  Protected *q.DNS_ANSWER,count,pos1,len,a,ct
  Protected *ad.DNS_ANSWER_DESC, *rec.DNS_Record
  Protected ID,HttpRequest,status,type   
  Protected NewList keys.s()  
  Protected out.s,fout.s   
  
  *header = *msg 
  flags.u = ntohs(*header\flags)  
  
  If (flags & #DNS_MESSAGEFLAG_QR) 
    
    ID = ntohs(*header\id)  
    
    count = ntohs(*header\arCount) 
    
    *q = *msg + SizeOf(DNS_Message_Header) 
    
    pos1=1
    While *q\mdata\a[pos1] <> 0
      len = *q\mdata\a[pos1-1]
      If len 
        ResetList(keys()) 
        AddElement(keys())
        keys() = PeekS(@*q\mdata\a[pos1],len,#PB_Ascii)
        fout + keys() + "." 
        pos1+len 
        pos1+1
        ct+1
      Else 
        Break 
      EndIf   
    Wend  
    fout = Trim(fout,".") 
    
    ct = ListSize(keys())
    FirstElement(keys()) 
    For a = 1 To ct  
      If a <> ct 
        out + keys() + "." 
      Else 
        out + keys()
      EndIf   
      NextElement(keys())   
    Next  
    
    *ad = *msg + SizeOf(DNS_Message_Header) + pos1 + 6 
    
    type = ntohs(*ad\Type)
    len = PeekB(*msg+(mlen-5)) 
    
    If (type = 1 Or type = 5)   
      
      If len = 4 
        adr = PeekI(*msg+(mlen-4))     
        
        *rec = DNScope\squint\Get(0,@out)
        
        If *rec = 0 
          
          *rec.DNS_Record = AllocateMemory(SizeOf(DNS_Record)) 
          
          *rec\key = out 
          *rec\ipv4 = adr 
          *rec\ttl =  DateUTC() + ntohl(*ad\TTL) 
          *rec\type = ntohs(1)          
          *rec\block = 1      ; -1 blocked 0 unset 1 allowed    
          *rec\time = ElapsedMilliseconds()+30000
          
          DNScope\squint\Set(0,@out,*rec) 
          ; status isn't very useful there are to many sites that don't use status properly and it blocks to many sites  
          ;          If DNScope\UseStatus  
          ;             HttpRequest = HTTPRequestMemory(#PB_HTTP_Get,"http://"+IPString(adr,#PB_Network_IPv4),0,0,#PB_HTTP_HeadersOnly) 
          ;             If HttpRequest
          ;               status = Val(HTTPInfo(HTTPRequest, #PB_HTTP_StatusCode)) 
          ;               *rec\stat = status 
          ;               Select status
          ;                 Case 100 To 500; , 404;'. 101,102,103,200,201,204,205,206,300,302,307,400,404
          ;                   
          ;                   If DNScope\bloom\Get(@out,StringByteLength(out)) 
          ;                     *rec\block = -1 
          ;                     DNScope\blockcount + 1
          ;                     DNScope\DenyCount + 1 
          ;                     ;Debug "bloom Block"
          ;                   Else 
          ;                     DNScope\AllowCount + 1 
          ;                     *rec\block=1 
          ;                   EndIf 
          ;                   ;Debug "status ok " + Str(status)  +  " " + out + IPString(adr,#PB_Network_IPv4) 
          ;                   ;EndIf   
          ;                 Default  
          ;                   
          ;                   If status = 0 
          ;                     
          ;                     If DNScope\UseStatus 
          ;                       
          ;                       *rec\stat = -1 
          ;                       *rec\block=-1 
          ;                       DNScope\blockcount + 1
          ;                       DNScope\DenyCount + 1 
          ;                       
          ;                     EndIf 
          ;                     
          ;                   ElseIf DNScope\bloom\Get(@out,StringByteLength(out)) 
          ;                     *rec\block = -1 
          ;                     DNScope\blockcount + 1
          ;                     DNScope\DenyCount + 1   
          ;                     ;Debug "bloom Block"
          ;                   EndIf   
          ;                   ;Debug "status blocked " +Str(status)  +  " " + out + IPString(adr,#PB_Network_IPv4) 
          ;                   
          ;               EndSelect   
          ;               FinishHTTP(HTTPRequest)
          ;             Else
          ;               ;Debug "failed"  
          ;             EndIf
          ;           EndIf      
          
          PostEvent(#DNS_EVENT_ADD_LOG,0,0,0,*rec)         
          ProcedureReturn *rec 
        ElseIf *rec\block = -1  
          *rec\ttl = 86400 + ElapsedSeconds() 
          *rec\ipv4 = adr
          *rec\time = ElapsedMilliseconds()+30000        
          PostEvent(#DNS_EVENT_ADD_LOG,0,0,0,*rec)     
          
          ProcedureReturn *rec   
        ElseIf *rec\block = 1     
          *rec\ttl = DateUTC() + ntohl(*ad\TTL) 
          *rec\ipv4 = adr
          *rec\time = ElapsedMilliseconds() + 30000  
          PostEvent(#DNS_EVENT_ADD_LOG,0,0,0,*rec) 
          
          ProcedureReturn *rec    
        EndIf        
        
      EndIf   
      
    EndIf  
  EndIf    
  
EndProcedure 

Procedure DNS_Write_Reject_Answer(con,*msg,len) 
  Protected l1,*out,res 
  l1 = (?endpack1-?endpack) 
  *out = AllocateMemory(l1+len)
  
  CopyMemory(*msg,*out,len) 
  CopyMemory(?endpack,*out+len,l1)   
  l1 + len 
  
  DataSection : endpack: 
    Data.a $c0, $1c, $00, $06, $00, $01, $00, $00, $03, $84, $00, $3d, $01, $61, $0c, $67
    Data.a $74, $6c, $64, $2d, $73, $65, $72, $76, $65, $72, $73, $03, $6e, $65, $74, $00
    Data.a $05, $6e, $73, $74, $6c, $64, $0c, $76, $65, $72, $69, $73, $69, $67, $6e, $2d
    Data.a $67, $72, $73, $c0, $1c, $62, $d3, $8c, $94, $00, $00, $07, $08, $00, $00, $03
    Data.a $84, $00, $09, $3a, $80, $00, $01, $51, $80
    endpack1: 
  EndDataSection   
  
  PokeU(*out+2,$8381)
  res =  SendNetworkData(con,*out,l1)  
  
  FreeMemory(*out)
  
EndProcedure   

Procedure Bitset(*buf,index) 
  Protected *ta.Ascii  
  *ta = *buf + ((index)>>3) 
  *ta\a | (1 << (7-(index & $07))) 
EndProcedure   

Procedure DNS_Write_Cache_Answer(con,*msg,len,*rec.DNS_Record) 
  Protected pos,*out,res,ttl 
  
  *out = AllocateMemory(len+16)
  
  CopyMemory(*msg,*out,len) 
  Bitset(*out,16)         ;set bit 16 is answer  
  PokeU(*out+6,htons(1))  ;set Ancount 
  pos=len 
  PokeU(*out+pos,$0cc0)  ; name offset type A
  pos+2
  PokeU(*out+pos,htons(1))  ;Type A 
  pos+2 
  PokeU(*out+pos,htons(1))  ;class 1 
  pos+2 
  PokeL(*out+pos,htonl(ttl))  
  pos+4 
  PokeL(*out+pos,htons(4))  ;len  
  pos+2 
  PokeL(*out+pos,*rec\ipv4) ;ip 
  pos+4
  
  res =  SendNetworkData(con,*out,pos)  
  FreeMemory(*out)
  
  If res 
    If DateUTC() > (*rec\ttl - 60000)  
      ProcedureReturn 2 
    Else   
      ProcedureReturn 1
    EndIf   
  EndIf  
  
EndProcedure   

Procedure WaitforReply(con) 
  
  Protected *buff,timeout,len,res,st   
  st = ElapsedMilliseconds() 
  timeout = st+3000 
  *buff = AllocateMemory(512)
  
  Repeat 
    Select NetworkClientEvent(con) 
      Case #PB_NetworkEvent_Data       
        len = ReceiveNetworkData(con,*buff,512)
        If len > 16 
          res =  DNS_Read_Answer(*buff,len) 
        EndIf 
        Break   
      Case #PB_NetworkEvent_Disconnect
        Break  
    EndSelect 
    Delay(1) 
    
  Until ElapsedMilliseconds() > timeout  
  
  FreeMemory(*buff) 
  CloseNetworkConnection(con)
  ProcedureReturn res 
  
EndProcedure   

CompilerIf #PB_Compiler_OS = #PB_OS_Windows 
  ImportC "dnsapi.lib"
    DnsFlushResolverCache(); 
  EndImport   
CompilerEndIf 

Procedure FlushDNS() 
    
  CompilerIf #PB_Compiler_OS = #PB_OS_Windows 
  Protected prog,res   
    
  ;   prog = RunProgram("ipconfig.exe", "/flushdns","", #PB_Program_Wait |  #PB_Program_Open )   
  ;   If Prog 
  ;     res = ProgramExitCode(prog)
  ;   EndIf 
  
  res = DnsFlushResolverCache();
  If res
    Debug "DnsFlushResolverCache succeeded"
  Else 
    Debug "DnsFlushResolverCache failed "+ Str(GetLastError_())
  EndIf   
  
  CompilerEndIf 
  
EndProcedure  

Procedure CBSquintFree(*key,*rec.DNS_Record,*userData)
  
  If *rec 
    If MemorySize(*rec) = SizeOf(DNS_Record) 
      FreeMemory(*rec) 
    EndIf 
  EndIf   
  
EndProcedure  

; Procedure CBAddBlackList(*key,*rec.DNS_Record,stringtype=#PB_UTF8)   
;   Protected key.s 
;   If *rec 
;     If *rec\block = -1 
;       key = PeekS(*key,-1,stringtype) 
;       AddGadgetItem(#BlackListGadget,-1,key) 
;     EndIf      
;   EndIf 
; EndProcedure  

; Procedure CBAddWhiteList(*key,*rec.DNS_Record,stringtype=#PB_UTF8)   
;   Protected key.s 
;   
;   If *rec 
;     If *rec\block = 1 
;       key = PeekS(*key,-1,stringtype) 
;       AddGadgetItem(#WhiteListGadget,-1,key) 
;     EndIf      
;   EndIf 
;   
; EndProcedure  

Procedure CBAddActiveList(*key,*rec.DNS_Record,stringtype=#PB_UTF8)   
  Protected key.s,out.s  
  If *rec   
    key = PeekS(*key,-1,stringtype) 
    If *rec\time > ElapsedMilliseconds() 
      If *rec\block = 1 
        SetGadgetItemText(#WhiteListGadget,DNScope\win\AllowPos,key) 
        If key = DNScope\win\WhiteText$  
          SetGadgetItemState(#WhiteListGadget,DNScope\win\AllowPos,1)
        EndIf   
        DNScope\win\AllowPos + 1 
        DNScope\win\AllowPos & (DNScope\win\lvcount-1) 
        ChangeSysTrayIcon(0,ImageID(DNScope\win\iconGo)) 
      ElseIf *rec\block = -1 
        SetGadgetItemText(#BlackListGadget,DNScope\win\Blockpos,key) 
        If key = DNScope\win\BlackText$  
          
          SetGadgetItemState(#BlackListGadget,DNScope\win\BlockPos,1)
        EndIf   
        
        DNScope\win\Blockpos + 1 
        DNScope\win\Blockpos & (DNScope\win\lvcount-1)  
                
        ChangeSysTrayIcon(0,ImageID(DNScope\win\iconGo)) 
      EndIf 
    EndIf 
    
  EndIf 
EndProcedure  

Procedure ClearActive() 
  Protected a 
  DNScope\win\Blockpos=0 
  DNScope\win\AllowPos=0 
  
  If DNScope\Save = 0 
    
    DNScope\squint\Walk(0,@CBAddActiveList(),#PB_UTF8)
    
    For a = DNScope\win\blockpos To DNScope\win\lvcount   
      SetGadgetItemText(#BlackListGadget,a,"") 
    Next 
    For a = DNScope\win\AllowPos To DNScope\win\lvcount   
      SetGadgetItemText(#WhiteListGadget,a,"") 
    Next  
  EndIf 
  
EndProcedure  

Procedure CBSave(*key,*rec.DNS_Record,file)
  Protected out.s,keylen.i    
  Static count 
  out = PeekS(*key,-1,#PB_UTF8) 
  count+1
  
  keylen = Len(out) 
  WriteLong(file,keylen) 
  WriteString(file,out,#PB_Unicode)
  WriteCharacter(file,0) 
  WriteData(file,*rec,SizeOf(DNS_Record)) 
  
  ;If *rec\block = -1              ;add to bloom 
  ;  DNScope\bloom\Set(@out,StringByteLength(out)) 
  ;EndIf  
  
  If DNScope\save = 0 
    If *rec 
      If MemorySize(*rec) = SizeOf(DNS_Record) 
        FreeMemory(*rec) 
      EndIf 
    EndIf   
  EndIf    
EndProcedure   

Procedure Save() 
  Protected path.s
  
  If DNScope\Portable 
    path.s = GetPathPart(ProgramFilename()) + "DNScope\" 
  Else 
    path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\" 
  EndIf   
  
  Protected fn,*buf 
  If FileSize(path) = - 1  
    If CreateDirectory(path)  
      path + "dnsdata.bin" 
    EndIf  
  Else    
    path + "dnsdata.bin"
  EndIf     
  
  fn = CreateFile(-1,path) 
  If fn 
    
    DNScope\squint\Walk(0,@CBSave(),fn) 
    
    CloseFile(fn) 
  EndIf   
  
  If DNScope\Portable 
    path.s = GetPathPart(ProgramFilename()) + "DNScope\DNScope.ini"
  Else 
    path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\DNScope.ini"
  EndIf   
  
  Protected result 
  If Not OpenPreferences(path) 
    result = CreatePreferences(path) 
  Else 
    result = 1  
  EndIf 
  If result 
    PreferenceGroup("WindowPosition") 
    
    WritePreferenceLong("x",DNScope\win\gwx)
    WritePreferenceLong("y",DNScope\win\gwy)
    WritePreferenceLong("w",DNScope\win\gww)
    WritePreferenceLong("h",DNScope\win\gwh)
    
    
    PreferenceGroup("Options") 
    WritePreferenceLong("UseBloom",dnscope\UseBloom) 
    WritePreferenceLong("UseStatus",dnscope\UseStatus) 
    
    ClosePreferences() 
    
  EndIf    
  
  ;path.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\DNScope.dat"
  ;Bloom_Save(DNScope\bloom,path) 
  
  
EndProcedure  

Procedure Load() 
  Protected keylen.l ,count,*mem,ct 
  Protected key.s,*rec.DNS_Record,*rec1.DNS_Record  
  Protected p1.s,p2.s,path.s
  
  p1.s = GetPathPart(ProgramFilename()) + "DNScope\DNScope.ini"
  If FileSize(p1) > 0  
    DNScope\Portable = 1
    path = p1 
  Else     
    p2.s = GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\DNScope.ini"
    If FileSize(p2) > 0  
      DNScope\Portable = 0 
      path = p2   
    Else 
      DNScope\Portable = 1 
      path = p1 
    EndIf 
  EndIf   
  
  Protected result 
  If Not OpenPreferences(path) 
    If CreateDirectory(GetPathPart(path))
      result = CreatePreferences(path) 
     If result = 0
      MessageRequester("error", "Please run dnscope from a writable directory") 
      End 
    EndIf 
    EndIf 
  Else 
    result = 1  
  EndIf 
  If result 
    PreferenceGroup("WindowPosition") 
    DNScope\win\windowx = ReadPreferenceLong("x",0)
    DNScope\win\windowy = ReadPreferenceLong("y",0)
    DNScope\win\windowWidth = ReadPreferenceLong("w",800)
    DNScope\win\windowHeight = ReadPreferenceLong("h",600)
    
    Protected bshort,startup 
    PreferenceGroup("Global")
    bshort = ReadPreferenceLong("Shortcut",0) 
    startup = ReadPreferenceLong("Startup",0) 
        
    If bshort 
      ShellLinkAddtoDesktop("DNScope")
      WritePreferenceLong("Shortcut",0) 
    EndIf 
    If startup 
      ShellLinkAddtoStartMenu("DNScope")
      WritePreferenceLong("Startup",0)
    EndIf    
    
    PreferenceGroup("OrigonalIP1")
    If ReadPreferenceLong("DHCP",1) = 0   
      DNScope\IPINf\IPAddress = ReadPreferenceString("IPAddress","127.0.0.1") 
    Else 
       DNScope\IPINf\IPAddress = "127.0.0.1"
    EndIf   
    
    PreferenceGroup("Options") 
    dnscope\UseBloom = ReadPreferenceLong("UseBloom",1)
    dnscope\UseStatus = ReadPreferenceLong("UseStatus",0) 
    
    ClosePreferences()   
  EndIf    
  
  If  DNScope\Portable   
    path.s = GetPathPart(ProgramFilename()) + "DNScope\dnsdata.bin" 
  Else 
    path.s =  GetUserDirectory(#PB_Directory_ProgramData) + "DNScope\dnsdata.bin" 
  EndIf   
  
  
  If FileSize(path) > 0
    If OpenFile(0,path) 
      Repeat 
        keylen = ReadLong(0)+2
        If keylen 
          *rec = AllocateMemory(SizeOf(DNS_Record)) 
          *rec1 = AllocateMemory(SizeOf(DNS_Record)) 
          key = ReadString(0,#PB_Unicode,keylen)  
          *rec\keylen = keylen
          *rec\key = key  
          
          ReadData(0,*rec1,SizeOf(DNS_Record))
          *rec\block = *rec1\block 
          *rec\ipv4 = *rec1\ipv4 
          *rec\ttl =  *rec1\ttl 
          *rec\stat = *rec1\stat 
          
          count+1
          
          
          DNScope\squint\set(0,@key,*rec)
          
          If *rec\block = 1 
            DNScope\AllowCount + 1 
          ElseIf *rec\block = - 1 
            *rec\ttl = DateUTC() + 86400  
            DNScope\DenyCount + 1 
          EndIf 
          
;           If *rec\time < 60    
;             If *rec\block = 1 
;               LockMutex(mutFifo) 
;               Debug "enqueue fifo" 
;               LastElement(fifo())
;               AddElement(fifo()) 
;               fifo() = *rec
;               UnlockMutex(mutfifo)
;             EndIf   
;           Else 
;             Debug Str(ct) + " " + Str(DateUTC()) + " " + Str(*rec\time)     
;             ct+1   
;           EndIf   
          
          *rec\time = ElapsedMilliseconds() 
          
          FreeMemory(*rec1) 
        EndIf 
      Until Eof(0)   
      CloseFile(0)
    EndIf  
  EndIf  
  
EndProcedure   

Procedure.s GetMS(date) 
  Protected st.SYSTEMTIME 
  GetSystemTime_(@st.SYSTEMTIME) 
  ProcedureReturn Str(st\wMilliseconds) 
EndProcedure 

Procedure AddToDataGrid(*rec.DNS_Record) 
  Protected out.s,date,date$,stat$,ttl$     
  
  date = DateUTC()
  date$ = FormatDate("%dd:%hh:%ii:%ss", date) + ":" + GetMS(date) 
  
  ttl$ = FormatDate("%dd:%hh:%ii:%ss",*rec\ttl)
  stat$ = GetHttPStatus(*rec\stat) 
  
  If *rec     
    If *rec\ipv4 <> 0
      If *rec\ipv4 <> -1
        out = *rec\key + Chr(10) + IPString(*rec\ipv4,#PB_Network_IPv4) + Chr(10) + date$  + Chr(10) + TTL$  + Chr(10) + stat$ 
      Else 
        out = *rec\key + Chr(10) + "0.0.0.0"  + Chr(10) + date$  + Chr(10) + TTL$  + Chr(10) + stat$ 
      EndIf   
    ElseIf *rec\ipv6     
      out = *rec\key + Chr(10) + IPString(*rec\ipv6,#PB_Network_IPv4) + Chr(10) + date$   + Chr(10) + TTL$ + Chr(10) + stat$ 
    EndIf   
    
    If out <> "" 
      
      If CountGadgetItems(#DataGadget) = 65534
        RemoveGadgetItem(#DataGadget,65534) 
      EndIf 
      
      AddGadgetItem(#DataGadget,0,out) 
      If *rec\block = 1 
        SetGadgetItemState(#DataGadget,0,#PB_ListIcon_Checked)  
      ElseIf *rec\block = -1    
        SetGadgetItemState(#DataGadget,0,#PB_ListIcon_Inbetween) 
      EndIf 
    EndIf           
  EndIf 
  
  StatusBarText(#MainStatusBar,0, "Blocked " + Str(DNScope\blockcount) + " Total " + Str(DNScope\TotalCount))
  StatusBarText(#MainStatusBar,1, "DNS on " + DNScope\IPINf\IPAddress + " : " + DNScope\IP)
  StatusBarText(#MainStatusBar,2, "Allowed " + Str(DNScope\AllowCount)) 
  StatusBarText(#MainStatusBar,3, "Denied " + Str(DNScope\DenyCount)) ;
  
EndProcedure   

Procedure Resize() 
  Protected cw,bh,hh,pad 
  pad = 5
  
  DNScope\win\gwx = WindowX(0) 
  DNScope\win\gwy = WindowY(0)
  DNScope\win\gww = WindowWidth(0)
  DNScope\win\gwh = WindowHeight(0) 
  
  cw=DNScope\win\gww/2 - pad 
  bh=DNScope\win\gwh/2 
  hh =(DNScope\win\gwh-bh)- StatusBarHeight(#MainStatusBar) - MenuHeight() 
  
  ResizeGadget(#SplitHoritontal,5,5,DNScope\win\gwW-10,DNScope\win\gwh-50) 
  
  SetGadgetItemAttribute(#DataGadget,0,#PB_Explorer_ColumnWidth,DNScope\win\gww/4-2,0) 
  SetGadgetItemAttribute(#DataGadget,1,#PB_Explorer_ColumnWidth,DNScope\win\gww/4-2,1) 
  SetGadgetItemAttribute(#DataGadget,2,#PB_Explorer_ColumnWidth,DNScope\win\gww/4-2,2) 
  SetGadgetItemAttribute(#DataGadget,3,#PB_Explorer_ColumnWidth,DNScope\win\gww/4-2,3) 
  SetGadgetItemAttribute(#DataGadget,4,#PB_Explorer_ColumnWidth,DNScope\win\gww/4-6,4)
  
EndProcedure  

Procedure SetSystemTray(window) 
  
  DNScope\win\icongo = CatchImage(-1,?ico)
  DNScope\win\iconstop = CatchImage(-1,?Ico1) 
  AddSysTrayIcon(0,WindowID(window),ImageID(DNScope\win\icongo))
  SysTrayIconToolTip(0,"Left click to Show, Right click to hide")
  
EndProcedure 

Procedure _ListViewGadget(Gadget,x,y,w,h)
  Protected a 
  ListViewGadget(gadget,x,y,w,h);
  For a = 0 To DNScope\win\lvcount 
    AddGadgetItem(gadget,-1,"") 
  Next  
  
EndProcedure   

Procedure UninstallAndDelete() 
  Protected path.s,program.s,tmp.s  
  Protected rand.s = Str(Random($ffff)) 
  path = GetPathPart(ProgramFilename()) 
  tmp = GetTemporaryDirectory() 
  tmp + "DnscopeUnInstall_" + rand + ".exe"
  CopyFile(path+"Uninstall.exe",tmp) 
  If DNScope\Portable = 0 
    RunProgram(tmp,"",path)
  EndIf 
    
  End 
  
EndProcedure   

Procedure Process(client) 
  Protected *rec.DNS_Record 
  Protected len,*buff ,res, con 
  
  *buff = AllocateMemory(512) 
  
  len = ReceiveNetworkData(client,*buff,512)
  If len > 16 
    *rec = DNS_Read_Query(*buff,len) 
    If (*rec = 0 Or *rec\ttl < DateUTC()) 
      con = OpenNetworkConnection(DNScope\IP,53,#PB_Network_UDP,2000)  
      If con 
        res =  SendNetworkData(con,*buff,len) 
       
        CreateThread(@WaitforReply(),con) 
      EndIf 
    ElseIf *rec\block = -1      
      DNS_Write_Reject_Answer(client,*buff,len) 
      *rec\time = ElapsedMilliseconds() + 30000 
      PostEvent(#DNS_EVENT_ADD_LOG,0,0,0,*rec) 
      DNScope\blockcount + 1 
      
      ChangeSysTrayIcon(0,ImageID(DNScope\win\iconstop)) 
    Else 
      DNS_Write_Cache_Answer(client,*buff,len,*rec) 
      *rec\time = ElapsedMilliseconds() + 30000 
      PostEvent(#DNS_EVENT_ADD_LOG,0,0,0,*rec)
      ChangeSysTrayIcon(0,ImageID(DNScope\win\iconGo)) 
    EndIf 
  EndIf
  
  FreeMemory(*buff)     
  
EndProcedure   

Procedure NetworkThread(void) 
  
  Protected v4,v6,client 
    
  V4 = CreateNetworkServer(-1,53,#PB_Network_UDP|#PB_Network_IPv4,DNScope\IPINf\IPAddress)
 ;v6 = CreateNetworkServer(-1,53,#PB_Network_UDP|#PB_Network_IPv6,DNSinfoList()\Name) 
  
  If v4 
    
    Repeat
      
      Select NetworkServerEvent()
          
        Case #PB_NetworkEvent_Data
          client = EventClient()
          CreateThread(@Process(),client) 
          
      EndSelect 
      
      Delay(1)
    Until DNScope\Quit 
    
    CloseNetworkServer(v4)
    
  EndIf  
  
EndProcedure 

Global wsaData.WSADATA 
WSAStartup_(MAKEWORD(2, 2), @wsaData);

Procedure GetIPAddress(host.s)
  Protected *rs.HOSTENT
  Protected *ahost = Ascii(host) 
  Protected adr,err 
  
  *rs = gethostbyname_(*ahost);
   
  FreeMemory(*ahost) 
  If *rs <> 0   
    err = WSAGetLastError_()
    If err = #WSAHOST_NOT_FOUND
      ProcedureReturn 0 
    ElseIf err =  #WSAEREFUSED
      ProcedureReturn 0 
    Else 
      ProcedureReturn 1 
    EndIf   
  Else 
    err = WSAGetLastError_()
  EndIf     
  
EndProcedure 

Procedure Dequeue(void) 
  
  Protected *rec.DNS_Record 
  Protected tcon,len,*buff,res 
  Protected a,ct,out.s
  
  Repeat 
    LockMutex(DNScope\mutFifo) 
    If ListSize(fifo()) 
      FirstElement(fifo()) 
      *rec = Fifo() 
      out=""
      ct = CountString(*rec\key,".")+1 
      For a = ct To 1 Step-1
        If a > 1 
          out + StringField(*rec\key,a,".") + "."   
        Else 
          out + StringField(*rec\key,a,".")
        EndIf  
      Next   
      GetIPAddress(out)
      DeleteElement(fifo()) 
    EndIf 
    UnlockMutex(DNScope\mutfifo)    
    Delay(1)   
  Until DNScope\quit    
  
EndProcedure   
 
FlushDNS() 
load() 

ExamineDesktops() 
DNScope\win\sx = DesktopResolutionX() 
DNScope\win\sy = DesktopResolutionY() 

DNScope\win\w = DNScope\win\windowWidth * DNScope\win\sx 
DNScope\win\h = DNScope\win\windowHeight * DNScope\win\sy

If DNScope\win\w = 0 : DNScope\win\w = 800 * DNScope\win\sx : EndIf  
If DNScope\win\h = 0 : DNScope\win\h = 600 * DNScope\win\sy : EndIf 

DNScope\win\lvcount = 128  ;power of 2 so listview is anded instread of mod 

#MainStyle = #PB_Window_SystemMenu | #PB_Window_SizeGadget | #PB_Window_MinimizeGadget | #PB_Window_MaximizeGadget ;| #PB_Window_ScreenCentered

If OpenWindow(0, DNScope\win\windowX, DNScope\win\windowY, DNScope\win\w, DNScope\win\h, #ProgramTitle + #ProgramVersion, #MainStyle)
  
  CreateMenu(#MainMenu, WindowID(#Main))
  MenuTitle("&File")
  MenuItem(#MainMenuAddStartUP,"Add to &Start up") 
  MenuItem(#MainMenuAddDesktop,"Add to &Desktop") 
  MenuBar()
  MenuItem(#MainMenuUninstall,"&Uninstall")
  MenuBar()
  MenuItem(#MainMenuExit, "E&xit")
  MenuTitle("&Options") 
  MenuItem(#OptionBloom,"&Bloom")
  SetMenuItemState(0,#OptionBloom, DNScope\UseBloom)   
  MenuItem(#optionstatus,"&Status") 
  SetMenuItemState(0,#Optionstatus, DNScope\UseStatus) 
  
  MenuTitle("&About")
  MenuItem(#MainMenuAbout, "&About")
  MenuItem(#MainMenuDonate,"&Donate")
  
  CreateStatusBar(#MainStatusBar, WindowID(0))
  AddStatusBarField(#PB_Ignore)
  AddStatusBarField(#PB_Ignore)
  AddStatusBarField(#PB_Ignore)
  AddStatusBarField(#PB_Ignore)
  
  _ListViewGadget(#BlackListGadget,5,5,DNScope\win\w/2-5,DNScope\win\h/2-10)
  _ListViewGadget(#WhiteListGadget,DNScope\win\w/2+5,5,DNScope\win\w/2-10,DNScope\win\h/2-10)
  SetGadgetColor(#WhiteListGadget, #PB_Gadget_FrontColor ,RGB(0,192,0))
  SetGadgetColor(#BlackListGadget,#PB_Gadget_FrontColor ,RGB(192,0,0))
  EnableGadgetDrop(#WhiteListGadget,#PB_Drop_Text, #PB_Drag_Copy)
  EnableGadgetDrop(#BlackListGadget,#PB_Drop_Text, #PB_Drag_Copy)
  ListIconGadget(#DataGadget,5,DNScope\win\h/2,DNScope\win\w,DNScope\win\h/2,"URL",DNScope\win\w/2-8,#PB_ListIcon_FullRowSelect | #PB_ListIcon_CheckBoxes) 
  
  AddGadgetColumn(#DataGadget,1,"IP address",DNScope\win\w/4) 
  AddGadgetColumn(#DataGadget,2,"Time",DNScope\win\w/4) 
  AddGadgetColumn(#DataGadget,3,"Renew",DNScope\win\w/4)
  AddGadgetColumn(#DataGadget,4,"Status",DNScope\win\w/4) 
  
  AddWindowTimer(0,#Activetimer,1000)
  AddWindowTimer(0,#SaveTimer,600000); 10 mins auto save  
  StatusBarText(#MainStatusBar,1, "DNS on " + dnscope\IPINf\IPAddress)
  
  SplitterGadget(#SplitVertical,0,0,DNScope\win\w,DNScope\win\h/2,#BlackListGadget,#WhiteListGadget,#PB_Splitter_Vertical)
  SplitterGadget(#SplitHoritontal,0,0,DNScope\win\w,DNScope\win\h-60,#SplitVertical,#DataGadget)
  
  Resize()
  
  BindEvent(#PB_Event_SizeWindow, @Resize(),0)
  
  SetSystemTray(0) 
  
  
  dnscope\ServerThread = CreateThread(@NetworkThread(),0) 
  ;Dnscope\FifoThread = CreateThread(@Dequeue(),0) 
  
  Repeat    
    
    Select WaitWindowEvent()   
      Case #PB_Event_Menu
        Select EventMenu() 
          Case  #MainMenuAbout 
            MessageRequester(#ProgramTitle + #ProgramVersion,#MSGABOUT,#PB_MessageRequester_Info) 
          Case #MainMenuExit
            Resize()
            DNScope\quit = 1 
          Case #MainMenuAddStartUP 
            ShellLinkAddtoStartMenu("DNScope")
          Case #MainMenuAddDesktop 
            ShellLinkAddtoDesktop("DNScope")
          Case #MainMenuUninstall 
            DNScope\quit = 1 
            DNScope\uninstall=1 
          Case #MainMenuDonate 
            RunProgram("https://dnscope.io/","","") 
          Case #OptionBloom 
            If GetMenuItemState(#MainMenu,#OptionBloom) = 1
              SetMenuItemState(#MainMenu,#OptionBloom,0) 
              DNScope\UseBloom = 0 
            Else 
              SetMenuItemState(#MainMenu,#OptionBloom,1) 
              DNScope\UseBloom = 1 
            EndIf   
            
          Case #Optionstatus   
            If GetMenuItemState(#MainMenu,#Optionstatus) = 1 
              SetMenuItemState(#MainMenu,#Optionstatus,0)
              DNScope\UseStatus = 0
            Else   
              SetMenuItemState(#MainMenu,#Optionstatus,1) 
              DNScope\UseStatus = 1
            EndIf 
        EndSelect 
      Case #PB_Event_Timer 
        If EventTimer() = #ActiveTimer
          ClearActive() 
          StatusBarText(#MainStatusBar,0, "Blocked " + Str(DNScope\blockcount) + " Total " + Str(DNScope\TotalCount))
        ElseIf EventTimer() = #SaveTimer   
          DNScope\save = 1
          save() 
          DNScope\save= 0
        EndIf  
      Case #PB_Event_CloseWindow
        Resize()
        DNScope\quit = 1 
      Case #DNS_EVENT_ADD_ACTIVE 
        StatusBarText(#MainStatusBar,0, "Blocked " + Str(DNScope\blockcount))
        StatusBarText(#MainStatusBar,1, "DNS on " + DNSinfoList()\Name + " : " + DNScope\IP)
        StatusBarText(#MainStatusBar,2, "Allowed " + Str(DNScope\AllowCount)) 
        StatusBarText(#MainStatusBar,3, "Denied " + Str(DNScope\DenyCount)) 
        ChangeSysTrayIcon(0,ImageID(DNScope\win\iconstop)) 
        AddToDataGrid(DNScope\rec) 
        
      Case #DNS_EVENT_ADD_LOG 
        AddToDataGrid(EventData()) 
      Case  #PB_Event_Gadget
        DNScope\win\EVT = EventType()
        
        If (DNScope\win\EVT = #PB_EventType_DragStart Or DNScope\win\EVT = #PB_EventType_LeftClick Or #PB_EventType_StatusChange)
          Select EventGadget() 
            Case  #WhiteListGadget
              DNScope\win\WhiteText$ = GetGadgetItemText(#WhiteListGadget, GetGadgetState(#WhiteListGadget))
              
              If DNScope\win\WhiteText$ <> ""
                If DNScope\win\EVT = #PB_EventType_DragStart                 
                  RemoveGadgetItem(#WhiteListGadget,GetGadgetState(#WhiteListGadget)) 
                  DragText(DNScope\win\WhiteText$) 
                Else 
                  
                  DNScope\rec = DNScope\squint\Get(0,@DNScope\win\WhiteText$) 
                  
                EndIf   
              EndIf             
            Case #BlackListGadget  
              DNScope\win\BlackText$ = GetGadgetItemText(#BlackListGadget, GetGadgetState(#BlackListGadget))
              If DNScope\win\BlackText$ <> ""
                If DNScope\win\EVT = #PB_EventType_DragStart  
                  RemoveGadgetItem(#BlackListGadget,GetGadgetState(#BlackListGadget)) 
                  DragText(DNScope\win\BlackText$)
                Else
                  DNScope\rec = DNScope\squint\Get(0,@DNScope\win\BlackText$) 
                  
                EndIf 
              EndIf   
            Case #DataGadget 
              DNScope\Text$ = GetGadgetItemText(#DataGadget, GetGadgetState(#DataGadget))
              
              DNScope\rec = DNScope\squint\Get(0,@DNScope\text$) 
              
              If DNScope\rec 
                If GetGadgetItemState(#DataGadget,GetGadgetState(#DataGadget)) & #PB_ListIcon_Checked   
                  DNScope\rec\block = 1 
                  DNScope\rec\ttl = DateUTC() - 60
                  
                Else 
                  DNScope\rec\block = -1 
                  DNScope\rec\ttl = DateUTC()+ 86400  
                  
                EndIf  
              EndIf 
          EndSelect 
        EndIf   
      Case #PB_Event_GadgetDrop
        Select EventGadget()  
          Case #WhiteListGadget
            DNScope\text$ = EventDropText()
            If DNScope\text$ <> "" 
              
              DNScope\rec = DNScope\squint\Get(0,@DNScope\text$) 
              
              If DNScope\rec 
                DNScope\rec\block = 1 
                DNScope\rec\ttl = DateUTC() - 60  
                FlushDNS() 
                
              EndIf
            EndIf  
          Case #BlackListGadget
            DNScope\text$ = EventDropText()
            If DNScope\text$ <> "" 
              
              DNScope\rec = DNScope\squint\Get(0,@DNScope\text$) 
              
              If DNScope\rec 
                DNScope\rec\block = -1 
                DNScope\rec\ttl = DateUTC() + 86400  
                DNScope\rec\ipv4 = 0
              EndIf    
              DNScope\blockcount + 1
              FlushDNS() 
            EndIf 
        EndSelect 
      Case #PB_Event_SysTray
        
        If EventType() = #PB_EventType_RightClick  
          HideWindow(0,1)               
        ElseIf EventType()  = #PB_EventType_LeftClick
          HideWindow(0,0)
        EndIf     
        
    EndSelect       
    
  Until DNScope\Quit 
  
  WaitThread(Dnscope\ServerThread) 
  ; WaitThread(Dnscope\FifoThread) 
  
EndIf 

save()


DNScope\Squint\Free()
DNScope\bloom\Free() 

FreeHttpStatus() 

If DNScope\uninstall 
  UninstallAndDelete() 
  End 
EndIf 

DataSection
  Ico:
  IncludeBinary "icon0.png"
  Ico1: 
  IncludeBinary "icon1.png" 
  F1: 
  IncludeBinary "allbloom.dat"
  F2:
EndDataSection     
