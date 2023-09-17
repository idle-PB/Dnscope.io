XIncludeFile "squint3.pbi"              
UseModule SQUINT 

Global *httpstatus.isquint

Procedure.s GetHttPStatus(err) 
  Protected ierr = err  
  Protected *result   
  *result = *httpstatus\GetNumeric(@ierr,2)    
  If *result 
     ProcedureReturn Str(ierr) + " : " + PeekS(*result) 
  EndIf    
EndProcedure 

Procedure set(key,*str) 
  Protected ikey 
  ikey=key 
  *httpstatus\SetNumeric(@ikey,*str,2) 
EndProcedure 

Procedure InitHttpStatus() 
    
  *httpstatus.isquint = SquintNew() 
  
  set(0,   @"Connection refused") 
  
  set(100, @"Continue") 
  set(101, @"Switching Protocols")
  set(200, @"OK")
  set(201, @"Created")
  set(202, @"Accepted")
  set(203, @"Non-Authoritative Information")
  set(204, @"No Content")
  set(205, @"Reset Content")
  set(206, @"Partial Content")
  set(300, @"Multiple Choices")
  set(301, @"Moved Permanently")
  set(302, @"Found")
  set(303, @"See Other")
  set(304, @"Not Modified")
  set(305, @"Use Proxy")
  set(306, @"(unused)")
  set(307, @"Temporary Redirect")
  set(400, @"Bad Request")
  set(401, @"Unauthorized")
  set(402, @"Payment Required")
  set(403, @"Forbidden")
  set(404, @"Not Found")
  set(405, @"Method Not Allowed")
  set(406, @"Not Acceptable")
  set(407, @"Proxy Authentication Required")
  set(408, @"Request Timeout")
  set(409, @"Conflict")
  set(410, @"Gone")
  set(411, @"Length Required")
  set(412, @"Precondition Failed")
  set(413, @"Request Entity Too Large")
  set(414, @"Request-URI Too Long")
  set(415, @"Unsupported Media Type")
  set(416, @"Requested Range Not Satisfiable")
  set(417, @"Expectation Failed")
  set(500, @"Internal Server Error")
  set(501, @"Not Implemented")
  set(502, @"Bad Gateway")
  set(503, @"Service Unavailable")
  set(504, @"Gateway Timeout")
  set(505, @"HTTP Version Not Supported")
  
  ProcedureReturn *httpstatus 
  
EndProcedure 

Procedure FreeHttpStatus() 
  If *httpstatus 
    *httpstatus\Free() 
  EndIf 
EndProcedure 

InitHttpStatus() 

CompilerIf #PB_Compiler_IsMainFile  
  
  Debug GetHttPStatus(101) 
  FreeHttpStatus()  
  
CompilerEndIf   
    


