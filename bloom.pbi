;High speed 64 bit Bloomfilter 
;Author Idle Andrew Ferguson
;licence MIT   
;v1.1 X64 ASM & C Backends, ARM64 PI4 and M1 C backends  

Structure bloom 
  *vt
  *filter 
  size.q
  elements.q
  hashes.q[2]
EndStructure 

Interface Ibloom 
  Set(*key,len)
  Get(*key,len) 
  GetSize()
  Or(*other.bloom)
  Compress(*len.long=0)
  Save(file.s)
  Free() 
EndInterface

Declare Bloom_Set(*this.bloom,*key,len) 
Declare Bloom_Get(*this.bloom,*key,len) 
Declare Bloom_Free(*this.bloom) 
Declare Bloom_GetSize(*this.bloom)
Declare Bloom_OR(*this.Bloom,*other.bloom) 
Declare Bloom_Compress(*this.bloom,*len.long=0) 
Declare Bloom_Save(*this.bloom,file.s) 

Declare Bloom_Decompress(*buf) 
Declare Bloom_Load(file.s) 
Declare Bloom_New(Items.i,MaxErrors.d=0.001)

DataSection : vt_bloom: 
  Data.i @Bloom_Set() 
  Data.i @Bloom_Get()
  Data.i @Bloom_GetSize()
  Data.i @Bloom_OR()
  Data.i @Bloom_Compress()
  Data.i @Bloom_Save()
  Data.i @Bloom_Free() 
EndDataSection 

CompilerIf #PB_Compiler_Backend = #PB_Backend_C  
    
  Procedure.q FastHash64(*buf,len,Seed.q=0)
    Protected result.q  
    ;FastHash64 algorithm by Zilong Tan
    !typedef unsigned long long uint64_t; 
    
    !#define mix(h) ({				      	  \
    !			(h) ^= (h) >> 23;		          \
    !			(h) *= 0x2127599bf4325c37ULL;	\
    !			(h) ^= (h) >> 47; })
    !
    
    !	const uint64_t m = 0x880355f21e6d1965ULL;
    !	const uint64_t *pos = (const uint64_t *)p_buf;
    !	const uint64_t *end = pos + (v_len / 8);
    !	const unsigned char *pos2;
    !	uint64_t h = v_seed ^ (v_len * m);
    !	uint64_t v;
    ! uint64_t result; 
    
    !	while (pos != end) {
    !		v  = *pos++;
    !		h ^= mix(v);
    !		h *= m;
    !	}
    
    !	pos2 = (const unsigned char*)pos;
    !	v = 0;
    
    !	switch (v_len & 7) {
    !	case 7: v ^= (uint64_t)pos2[6] << 48;
    !	case 6: v ^= (uint64_t)pos2[5] << 40;
    !	case 5: v ^= (uint64_t)pos2[4] << 32;
    !	case 4: v ^= (uint64_t)pos2[3] << 24;
    !	case 3: v ^= (uint64_t)pos2[2] << 16;
    !	case 2: v ^= (uint64_t)pos2[1] << 8;
    !	case 1: v ^= (uint64_t)pos2[0];
    !		h ^= mix(v);
    !		h *= m;
    !	}
    !
    !	v_result = mix(h);
    
    ProcedureReturn result 
  EndProcedure  
  
  Procedure.q pengyhash(*buf,len,seed.q=0)
    Protected result    
    !typedef unsigned long long uint64_t; 
    ! {
    ! 	uint64_t b[4] = { 0 };
    ! 	uint64_t s[4] = { 0, 0, 0, v_len};
    ! 	int i;
    ! 
    ! 	for(; v_len >= 32; v_len -= 32, p_buf = (const char*)p_buf + 32) {
    ! 		memcpy(b, p_buf, 32);
    ! 		
    ! 		s[1] = (s[0] += s[1] + b[3]) + (s[1] << 14 | s[1] >> 50);
    ! 		s[3] = (s[2] += s[3] + b[2]) + (s[3] << 23 | s[3] >> 41);
    ! 		s[3] = (s[0] += s[3] + b[1]) ^ (s[3] << 16 | s[3] >> 48);
    ! 		s[1] = (s[2] += s[1] + b[0]) ^ (s[1] << 40 | s[1] >> 24);
    ! 	}
    ! 
    ! 	memcpy(b, p_buf, v_len);
    ! 
    ! 	for(i = 0; i < 6; i++) {
    ! 		s[1] = (s[0] += s[1] + b[3]) + (s[1] << 14 | s[1] >> 50) + v_seed;
    ! 		s[3] = (s[2] += s[3] + b[2]) + (s[3] << 23 | s[3] >> 41);
    ! 		s[3] = (s[0] += s[3] + b[1]) ^ (s[3] << 16 | s[3] >> 48);
    ! 		s[1] = (s[2] += s[1] + b[0]) ^ (s[1] << 40 | s[1] >> 24);
    ! 	}
    ! 
    ! 	v_result = s[0] + s[1] + s[2] + s[3];
    ! }
    ProcedureReturn result   
  EndProcedure   
  
  Procedure fletcher4(*buf,len,seed.q=0)  
  Protected result   
!   typedef unsigned long long uint64_t; 
!   typedef unsigned long uint32_t; 
!   typedef unsigned char uint8_t; 
!   uint32_t *dataw = (uint32_t *)p_buf;
!   const uint32_t *const endw = &((const uint32_t*)p_buf)[v_len/4];
!   uint64_t A = v_seed, B = 0, C = 0, D = 0;
!   while (dataw < endw) {
!     A += *dataw++;
!     B += A;
!     C += B;
!     D += C;
!   }
!   if (v_len & 3) {
!     uint8_t *datac = (uint8_t*)dataw; //byte stepper
!     const uint8_t *const endc = &((const uint8_t*)p_buf)[v_len];
!     while (datac < endc) {
!       A += *datac++;
!       B += A;
!       C += B;
!       D += C;
!     }
!   }
!   v_result = D;

    ProcedureReturn result   
EndProcedure   

CompilerElse 
  
  Procedure.q FastHash64(*Buffer, Len, Seed.q=0)
    ; FastHash64 algorithm by Zilong Tan ported by wilbert
    !mov r10, 0x2127599bf4325c37
    !mov r11, 0x880355f21e6d1965
    !mov rdx, [p.p_Buffer]
    !mov rcx, [p.v_Len]
    !mov rax, rcx         ; h = seed ^ (len * m);
    !imul rax, r11
    !xor rax, [p.v_Seed]
    !sub rcx, 8
    !jc .l1
    ; 8 byte loop  
    !.l0:
    !mov r8, [rdx]        ; v = *pos++;
    !add rdx, 8
    ; -- mix(v) start --
    !mov r9, r8
    !shr r9, 23
    !xor r8, r9
    !imul r8, r10
    !mov r9, r8
    !shr r9, 47
    !xor r8, r9
    ; -- mix end --
    !xor rax, r8          ; h ^= mix(v);
    !imul rax, r11        ; h *= m;
    !sub rcx, 8
    !jnc .l0
    ; remaining bytes
    !.l1:
    !add rcx, 8
    !jz .l5
    !xor r8, r8
    !test rcx, 4
    !jz .l2
    ; get 4 bytes
    !mov r8d, [rdx]
    !add rdx, 4
    !ror r8, 32
    !.l2:
    !test rcx, 2
    !jz .l3
    ; get 2 bytes
    !movzx r9d, word [rdx]
    !add rdx, 2
    !xor r8, r9
    !ror r8, 16
    !.l3:
    !test rcx, 1
    !jz .l4
    ; get 1 byte
    !movzx r9d, byte [rdx]
    !xor r8, r9
    !ror r8, 8
    !.l4:
    !and rcx, 7
    !shl rcx, 3
    !rol r8, cl
    ; -- mix(v) start --
    !mov r9, r8
    !shr r9, 23
    !xor r8, r9
    !imul r8, r10
    !mov r9, r8
    !shr r9, 47
    !xor r8, r9
    ; -- mix end --
    !xor rax, r8          ; h ^= mix(v);
    !imul rax, r11        ; h *= m;
    ; -- mix(h) start --
    !.l5:
    !mov r9, rax
    !shr r9, 23
    !xor rax, r9
    !imul rax, r10
    !mov r9, rax
    !shr r9, 47
    !xor rax, r9
    ; -- mix end --
    ProcedureReturn       ; return mix(h);
  EndProcedure
  
CompilerEndIf 

Procedure Bloom_New(Items.i,MaxErrors.d=0.001)
  Protected *this.bloom,MaxError.d,size.i,pow.i  
  
  *this = AllocateMemory(SizeOf(bloom))
  
  If *this
    *this\vt = ?vt_bloom
    *this\elements = (-(2.0 * (items))) / (Log(1.0 - Pow(MaxErrors,0.5))) 
    *this\size = *this\elements / 8 
    *this\filter = AllocateMemory(*this\size) 
    *this\hashes[0] = 11400714819323198485
    *this\hashes[1] = 11400714819323198485 << 1
    
    ProcedureReturn *this 
  EndIf 
  
EndProcedure 

Procedure Bloom_Free(*this.bloom) 
  If *this 
    FreeMemory(*this\filter) 
    FreeMemory(*this)
    *this = 0 
  EndIf 
EndProcedure  

Procedure Bloom_GetSize(*this.bloom) 
  ProcedureReturn *this\size 
EndProcedure     

Procedure  Bloom_Set(*this.Bloom,*key,len)
  Protected hash.q,thash.q,a.i,*ta.Ascii
  Protected thash1.q
  thash1 = FastHash64(*key,len) 
  hash =  (thash1 ! *this\hashes[0]) & $fffffffffffffff 
  thash = (thash1 ! *this\hashes[1]) & $fffffffffffffff
  hash % *this\elements
  thash % *this\elements
  *ta = *this\filter+(hash>>3)
  *ta\a | (1 << (hash & $07))
  *ta = *this\filter+(thash>>3)
  *ta\a | (1 << (thash & $07))
  ProcedureReturn thash1 
EndProcedure

Procedure Bloom_Get(*this.Bloom,*Key,len)
  Protected hash.q,thash.q,tret,retrn,a,*ta.Ascii
  Protected thash1.q,t1,t2
  thash1 =  FastHash64(*key,len) 
  hash =  (thash1 ! *this\hashes[0]) & $fffffffffffffff 
  thash = (thash1 ! *this\hashes[1]) & $fffffffffffffff 
  hash % *this\elements
  thash % *this\elements
  *ta = *this\filter+(hash>>3)
  t1 = (*ta\a & (1 << (hash & $07))) 
  *ta = *this\filter+(thash>>3)
  t2 = (*ta\a & (1 << (thash & $07)))
  If (t1 <> 0 And t2 <> 0) 
    ProcedureReturn #True
  Else
    ProcedureReturn #False
  EndIf
EndProcedure

UseLZMAPacker() 

#BLOOM_COMPPRESS = #PB_PackerPlugin_Lzma

Procedure Bloom_OR(*a.Bloom,*b.bloom)
  Protected *pa.Ascii,*pb.Ascii,a 
  
  If (*a And *b)
    
    If *a\Size <= *b\Size 
      *a\filter = ReAllocateMemory(*a\filter,*b\size)
      *a\size = *b\size  
    EndIf    
    
    *pa = *a\filter 
    *pb = *b\filter 
    
    For a = 0 To *b\size-1 
      *pa\a | *pb\a 
      *pa+1
      *pb+1
    Next 
  EndIf 
  
EndProcedure   

Procedure Bloom_Decompress(*buf) 
  Protected *this.bloom,size,size1,len  
  *this = AllocateMemory(SizeOf(bloom))
  
  size = PeekI(*buf) 
  size1 = PeekI(*buf+8)
  len = PeekI(*buf+16) 
  
  If *this
    *this\vt = ?vt_bloom
    *this\elements = len   
    *this\size = size1  
    *this\filter = AllocateMemory(*this\size) 
    *this\hashes[0] = 11400714819323198485
    *this\hashes[1] = 11400714819323198485 << 1
    
    len = UncompressMemory(*buf+24,size,*this\filter,size1,#BLOOM_COMPPRESS) 
    
    Debug *this\elements
    Debug *this\size 
    
    If len = size1 
      ProcedureReturn *this 
    EndIf 
  EndIf    
EndProcedure 

Procedure Bloom_Compress(*this.bloom,*len.long=0) 
  
  ;Debug *this\size 
  Debug "mem size filter " + Str(MemorySize(*this\filter)) 
  Debug "num elements " + Str(*this\elements) 
  Debug "size " +Str(*this\size) 
  
  Protected outsize ,*buf,len  
  outsize = *this\size + 24
  *buf = AllocateMemory(outsize) 
  len = CompressMemory(*this\filter,*this\size,*buf+24,outsize,#BLOOM_COMPPRESS,9) 
  
  Debug "Compressed Len : " + Str(len) 
  
  If len  
    PokeL(*buf,len) 
    PokeL(*buf+8,*this\size)
    PokeL(*buf+16,*this\elements) 
    If *len 
      *len\l = len+24 
    EndIf   
    ProcedureReturn *buf   
  EndIf   
  
EndProcedure 

Procedure Bloom_load(file.s) 
  
  Protected fn,bloom,*mem,len  
  fn = OpenFile(-1,file) 
  If fn 
    len = Lof(fn)
    If len 
      *mem = AllocateMemory(len) 
      ReadData(fn,*mem,len) 
      bloom = Bloom_Decompress(*mem) 
      FreeMemory(*mem) 
      CloseFile(fn) 
      ProcedureReturn bloom 
      
    EndIf 
  EndIf   
  
EndProcedure   

Procedure Bloom_Save(*this.bloom,file.s)
  Protected *buf,fn,res,len.l 
  fn = CreateFile(-1,file) 
  If fn 
    
    *buf = Bloom_Compress(*this,@len) 
    If (*buf And len > 0)  
      res = WriteData(fn,*buf,len)
    EndIf 
    FreeMemory(*buf) 
    CloseFile(fn) 
    ProcedureReturn res  
  EndIf 
  
EndProcedure    

CompilerIf #PB_Compiler_IsMainFile
  
  EnableExplicit
  DisableDebugger 
  
  Procedure MakeRandom(*buf.Ascii,seed=0) 
    Protected a, len,c  
    If seed <> 0 
      RandomSeed(seed)
    EndIf 
    len = (MemorySize(*buf)-1) 
    For a = 0 To Len 
      c = Random(74)+47 
      Select c 
        Case 0 
          *buf\a = 'A' 
        Case 1 
          *buf\a = 'C' 
        Case 2 
          *buf\a = 'G' 
        Case 3 
          *buf\a = 'T' 
      EndSelect 
      *buf\a = c 
      
      *buf+1 
    Next   
    
  EndProcedure  
  
  
  Global bloom.ibloom,bloom2,bloom3  
  Global k=16
  Global ers.d = 1.0 / 1024    ;max errors   
  Global size = 1024*1024
  Global size2 = 2 * size 
  Global size3
  Global out.s 
  Global *buf,*pc
  Global st,et,et1,stm,etm,etm1,a,ct,ct1,ct2,ct3,x
  
  *buf = AllocateMemory(size2)
  MakeRandom(*buf) 
  
  bloom = Bloom_new(size,ers) 
  
  Global NewMap mp(size) 
  
  st= ElapsedMilliseconds() 
  For a = 1 To size
    bloom_Set(bloom,*buf+a,k)
  Next 
  et = ElapsedMilliseconds()  
  For a = 1 To size
    ct + bloom_get(bloom,*buf+a,k)
  Next 
  et1 = ElapsedMilliseconds()  
  
  stm= ElapsedMilliseconds() 
  For a = 1 To size
    mp(PeekS(*buf+a,k,#PB_Ascii))=1
  Next 
  etm = ElapsedMilliseconds()  
  For a = 1 To size
    x=mp(PeekS(*buf+a,k,#PB_Ascii))
  Next 
  etm1 = ElapsedMilliseconds()  
  
  ;test for false positives, items that haven't been added to the set. 
  For a = size To size2
    ct1 + bloom_get(bloom,*buf+a,k) 
  Next 
  
  *pc = bloom\Compress()  ;compress bloom to buffer 
  If *pc 
    size3 = PeekL(*pc) 
  EndIf   
  
  bloom2 = Bloom_Decompress(*pc) ;returns a new bloom 
  FreeMemory(*pc) 
  
  For a = 1 To size
    ct2 + bloom_get(bloom2,*buf+a,k)
  Next 
  
  bloom3 = Bloom_new(size,ers) 
  Bloom_OR(bloom3,bloom2) 
  
  If  Bloom_Save(bloom3,"testbloom.blm") 
    Bloom_Free(bloom3)
    bloom3 = Bloom_load("testbloom.blm")
  EndIf    
  
  For a = 1 To size
    ct3 + bloom_get(bloom3,*buf+a,k)
  Next 
  
  
  out = "bloom items = " + FormatNumber(size,0,".",",") + " memory = " + StrF(bloom_GetSize(bloom) / 1024 / 1024,2) + " mb" + #CRLF$
  out + "Compressed size " + Str(size3) + " b" +  Str(size3 / 1024) + " kb  " + StrF(size3 / 1024 / 1024,2) + " mb" + #CRLF$
  out + "Bloom get = " + Str(ct) +#CRLF$
  out + "Bloom2 get = " + Str(ct2) +#CRLF$
  out + "Bloom3 get = " + Str(ct3) +#CRLF$
  
  out + "max false positives expected = " + Str(size*ers) + " actual " + Str(ct1) + #CRLF$ 
  out + "Bloom set " + Str(et-st) + " ms" + #CRLF$  
  out + "Bloom get " + Str(et1-et) + " ms" + #CRLF$  
  out + "map set " + Str(etm-stm) + " ms" + #CRLF$  
  out + "map get " + Str(etm1-etm) + " ms" + #CRLF$  
  
  
  SetClipboardText(out) 
  
  MessageRequester("bloom",out) 
  
  bloom_Free(bloom) 
  
CompilerEndIf   




