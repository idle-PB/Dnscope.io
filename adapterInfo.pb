 CompilerIf  #PB_Compiler_OS = #PB_OS_Windows   

; ABBKlaus Mon May 17, 2004 20:16
; http://msdn2.microsoft.com/en-us/library/aa365917.aspx
; with the help of IPHlpAPI.inc from the Powerbasic include-file for the structures
; Microsoft isn´t quite a help here :-)
; modified by PSW Wed Sep 06, 2006 07:49
; PB4.02 compatible since 29.05.2007 19:48
; PB4.10 compatible on 23.12.2007 21:03
; added more commands 31.12.2007 17:09
; updated to PB6.0 x86 and x64 idle  
; Added DNSlist  3/10/22
; Two global lists named as the functions AdapterInfoList() and DNSInfoList()   
; they are cleared on calls to the function  
 
EnableExplicit 

ImportC "msvcrt.lib"
   asctime.l(a.l)
   localtime.l(a.l)
   strftime.l(a.l,b.l,c.p-ascii,d.l)
EndImport

Structure TM
  tm_sec.l
  tm_min.l
  tm_hour.l
  tm_mday.l
  tm_mon.l
  tm_year.l
  tm_wday.l
  tm_yday.l
  tm_isdst.l
EndStructure

#MAX_ADAPTER_NAME=128
#MAX_ADAPTER_NAME_LENGTH=256
#MAX_ADAPTER_DESCRIPTION_LENGTH=128
#MAX_ADAPTER_ADDRESS_LENGTH=8
#MAX_HOSTNAME_LEN=128
#MAX_DOMAIN_NAME_LEN=128
#MAX_SCOPE_ID_LEN = 256 

#MIB_IF_TYPE_OTHER     = 1
#MIB_IF_TYPE_ETHERNET  = 6
#MIB_IF_TYPE_TOKENRING = 9
#MIB_IF_TYPE_PPP       = 23
#MIB_IF_TYPE_LOOPBACK  = 24
#MIB_IF_TYPE_SLIP      = 28 
#IF_TYPE_IEEE80211     = 71 

Structure _IP_ADDR_STRING Align #PB_Structure_AlignC 
  *pnext._IP_ADDR_STRING ;
  IPAddress.IP_ADDRESS_STRING;
  Ipmask.IP_MASK_STRING;
  Context.l            ;
EndStructure   

Structure IP_ADAPTER_INFO Align #PB_Structure_AlignC 
  *pNext
  ComboIndex.l
  AdapterName.a[#MAX_ADAPTER_NAME_LENGTH+4]
  Description.a[#MAX_ADAPTER_DESCRIPTION_LENGTH+4]
  AddressLength.l
  Address.b[#MAX_ADAPTER_ADDRESS_LENGTH]
  Index.l
  Type.l
  DhcpEnabled.l
  *CurrentIpAddressPTR._IP_ADDR_STRING
  IpAddressList._IP_ADDR_STRING
  GatewayList._IP_ADDR_STRING
  DhcpServer._IP_ADDR_STRING
  HaveWins.l
  PrimaryWinsServer._IP_ADDR_STRING
  SecondaryWinsServer._IP_ADDR_STRING
  CompilerIf #PB_Compiler_Processor = #PB_Processor_x86
    LeaseObtained.l
    LeaseExpires.l
  CompilerElse
    LeaseObtained.q
    LeaseExpires.q
  CompilerEndIf
EndStructure

Structure IP_ADAPTER_INDEX_MAP
  Index.l
  Name.w[#MAX_ADAPTER_NAME]
EndStructure

Structure IP_INTERFACE_INFO
  NumAdapters.l
  Adapter.IP_ADAPTER_INDEX_MAP[1]
EndStructure

Structure MyIP_ADAPTER_INFO
  Index.l
  Dhcp.l
  AdapterName.s
  Description.s
  MACAddress.s
  IPAdress.s
  GateWayAdress.s
  IPMask.s
  ;
  LeaseObtained.s
  LeaseExpires.s
EndStructure

Structure MyIP_INTERFACE_INFO
  Index.l
  Name.s
EndStructure

Structure FIXED_INFO
  HostName.a[#MAX_HOSTNAME_LEN + 4];
  DomainName.a[#MAX_DOMAIN_NAME_LEN + 4];
  *CurrentDnsServer;
  DnsServerList.IP_ADDR_STRING;
  NodeType.l;
  ScopeId.a[#MAX_SCOPE_ID_LEN + 4];
  EnableRouting.l;
  EnableProxy.l;
  EnableDns.l  ;
EndStructure 

Global NewList DNSinfoList.MyIP_INTERFACE_INFO() 
Global NewList IPAdapterInfoList.MyIP_ADAPTER_INFO() 

Procedure GetDNSInfo() 
  
  Protected res,*mem,*info.FIXED_INFO,len=1024,index=1,ct  
  Protected *pIPAddr._IP_ADDR_STRING
  
  ClearList(DNSinfoList()) 
  
  *mem = AllocateMemory(len)
  
  res = GetNetworkParams_(*mem,@len) 
  If res = 111 
    *mem = ReAllocateMemory(*mem,len) 
    res = GetNetworkParams_(*mem,@len)  
  EndIf 
  
  If res = 0 
    *info = *mem  
    
    AddElement(DNSinfoList()) 
    DNSinfoList()\Name = PeekS(@*info\DnsServerList\IpAddress\String,-1,#PB_Ascii) 
    
    *pIPAddr = *Info\DnsServerList\pNext;
    While *pIPAddr
      index+1 
      AddElement(DNSinfoList())  
      DNSinfoList()\Name = PeekS(@*pIPAddr\IpAddress\String,-1,#PB_Ascii) 
      DNSinfoList()\Index = index 
      *pIPAddr = *pIPAddr\pnext;
    Wend   
    
  EndIf 
  
  FreeMemory(*mem)
  
  ProcedureReturn index 
  
  
EndProcedure   

Procedure GetIPAdaptersInfo()
  Protected length.l=0,Result.l,*Buffer,*Buffer2,*ipinfo.IP_ADAPTER_INFO,*iplist._IP_ADDR_STRING
  Protected mac$,i.l,byte.b
  
  ClearList(IPAdapterInfoList())
  
  Result=GetAdaptersInfo_(0,@length) ; Get the length for Buffer
  If Result=#ERROR_BUFFER_OVERFLOW And length
    *Buffer=AllocateMemory(length)
    If *Buffer And GetAdaptersInfo_(*Buffer,@length)=#ERROR_SUCCESS
      *ipinfo.IP_ADAPTER_INFO=*Buffer
      
      While *ipinfo
        AddElement(IPAdapterInfoList()) ; add one element
        
        IPAdapterInfoList()\Index=*ipinfo\Index
        IPAdapterInfoList()\AdapterName=PeekS(@*ipinfo\AdapterName,-1,#PB_Ascii)
        IPAdapterInfoList()\Description=PeekS(@*ipinfo\Description,-1,#PB_Ascii)
        IPAdapterInfoList()\Dhcp=*ipinfo\DhcpEnabled 
                    
        ;IP-Adress
        *iplist._IP_ADDR_STRING=*ipinfo\IpAddressList
        While *iplist
          IPAdapterInfoList()\IPAdress+PeekS(@*iplist\IpAddress,-1,#PB_Ascii) 
          IPAdapterInfoList()\IPMask+PeekS(@*iplist\Ipmask,-1,#PB_Ascii) 
          *iplist._IP_ADDR_STRING= *iplist\pNext
        Wend
              
        ;Gateway
        *iplist._IP_ADDR_STRING=*ipinfo\GatewayList
        While *iplist
          IPAdapterInfoList()\GateWayAdress+PeekS(@*iplist\IpAddress,-1,#PB_Ascii)  
          *iplist._IP_ADDR_STRING=*iplist\pNext
        Wend
        ;Wins
        If *ipinfo\HaveWins
          ;PrimaryWinsServer
          *iplist._IP_ADDR_STRING=*ipinfo\PrimaryWinsServer
          While *iplist
            *iplist._IP_ADDR_STRING=*iplist\pNext
          Wend
          ;SecondaryWinsServer
          *iplist._IP_ADDR_STRING=*ipinfo\SecondaryWinsServer
          While *iplist
            *iplist._IP_ADDR_STRING=*iplist\pNext
          Wend
        EndIf
        ;DHCP
        If *ipinfo\DhcpEnabled
          ;DhcpServer
          *iplist._IP_ADDR_STRING=*ipinfo\DhcpServer
          While *iplist
             *iplist._IP_ADDR_STRING=*iplist\pNext
          Wend
          ;LeaseObtained
          *Buffer2=AllocateMemory(#MAXCHAR)
          If *Buffer2
            strftime(*Buffer2,#MAXCHAR,"%d.%m.%Y %H:%M:%S",localtime(@*ipinfo\LeaseObtained))
            IPAdapterInfoList()\LeaseObtained = PeekS(*Buffer2, -1, #PB_Ascii) 
            FreeMemory(*Buffer2)
            *Buffer2=0
          EndIf
          ;LeaseExpires
          *Buffer2=AllocateMemory(#MAXCHAR)
          If *Buffer2
            strftime(*Buffer2,#MAXCHAR,"%d.%m.%Y %H:%M:%S",localtime(@*ipinfo\LeaseExpires))
            IPAdapterInfoList()\LeaseExpires = PeekS(*Buffer2, -1, #PB_Ascii) 
            FreeMemory(*Buffer2)
            *Buffer2=0
          EndIf
        Else
           
        EndIf
         
        If *ipinfo\AddressLength
          mac$=""
          For i=0 To *ipinfo\AddressLength-1
            If i
              mac$+":"
            EndIf
            byte.b=PeekB(@*ipinfo\Address+i)
            If byte>=0
              mac$+RSet(Hex(byte),2,"0")
            Else
              mac$+RSet(Hex(byte+256),2,"0")
            EndIf
          Next
           
          IPAdapterInfoList()\MACAddress=mac$
        EndIf
        *ipinfo.IP_ADAPTER_INFO=*ipinfo\pNext
      Wend
    EndIf
    If *Buffer
      FreeMemory(*Buffer)
      *Buffer=0
    EndIf
  EndIf
EndProcedure

CompilerIf #PB_Compiler_IsMainFile
  
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
    
  GetIPAdaptersInfo()
  
  ForEach IPAdapterInfoList.MyIP_ADAPTER_INFO() 
    If IPAdapterInfoList()\GateWayAdress <> "0.0.0.0"  
      
      Debug "Name " +  IPAdapterInfoList()\AdapterName 
      Debug "Description " + IPAdapterInfoList()\Description
      Debug "DHCP " + Str(IPAdapterInfoList()\Dhcp) 
      Debug "Address " + IPAdapterInfoList()\IPAdress 
      Debug "Mask " + IPAdapterInfoList()\IPMask 
      Debug "Gateway " + IPAdapterInfoList()\GateWayAdress 
      Debug "Index " +  IPAdapterInfoList()\Index  
      Debug "mac address " + IPAdapterInfoList()\MACAddress
      If IPAdapterInfoList()\Dhcp 
        Debug "DHCP: LeaseObtained " + IPAdapterInfoList()\LeaseObtained
        Debug "DHCP: LeaseExpires " + IPAdapterInfoList()\LeaseExpires
      EndIf 
      Debug ""
    EndIf      
  Next 
  
  GetDNSInfo() 
  Debug "DNS servers list" 
  Debug ""
  
  ForEach DNSinfoList() 
    Debug DNSinfoList()\Name 
  Next 
  
  FirstElement(DNSinfoList()) 
  Debug DNSinfoList()\Name  
  
  Procedure SetAdapter() 
  Protected output$,pos,input$  

  GetIPAdaptersInfo()
  GetDNSInfo()   
  
  ForEach IPAdapterInfoList()  
  If IPAdapterInfoList()\GateWayAdress <> "0.0.0.0"  
    _RunProgram("netsh","Interface ip set dnsservers name=" + Chr(34) +  Str(IPAdapterInfoList()\Index) + Chr(34) + " source=Static address=none")
    If IPAdapterInfoList()\DHCP = 1 
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.1")  
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.2 index=2")
    ElseIf IPAdapterInfoList()\DHCP = 0  
       ;need to reset gateway 
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " " + IPAdapterInfoList()\GateWayAdress)  
      _RunProgram("netsh","Interface ip add dns " + Chr(34) + Str(IPAdapterInfoList()\Index) + Chr(34) + " 127.0.0.2 index=2")
    EndIf  
  EndIf 
  Next 
  
EndProcedure 
  
  
CompilerEndIf 
CompilerEndIf