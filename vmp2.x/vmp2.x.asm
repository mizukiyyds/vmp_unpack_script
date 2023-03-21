VAR OEP                                  ;原始入口点
VAR text_base                            ;.text段起始地址 
VAR text_size                            ;.text段在内存中的大小
VAR vmp0_base                            ;.vmp0段起始地址 
VAR vmp0_size                            ;.vmp0段在内存中的大小
VAR vmp1_base                            ;.vmp1段在内存中的大小
VAR cnt_retn                             ;根据IAT加密的特征，搜索出来的可能转到真正地址的retn
VAR cnt_call                             ;被加密的call的数量
VAR cnt_jmp                              ;被加密的jmp的数量
VAR call_base                            ;被加密的call的地址
VAR call_dst                             ;被加密call的目标地址
VAR call_retn_addr                       ;被加密call的返回地址
VAR jmp_base                             ;被加密的jmp的地址
VAR jmp_dst                              ;被加密jmp的目标地址
VAR before_esp                           ;加密call，jmp执行前的esp，通过比较esp判断原始是call还是jmp
VAR status                               ;正在修复call还是jmp，0代表call，1代表jmp
VAR exception_address                    ;KiUserExceptionDispatcher函数地址
VAR i                                    ;循环变量
                                  

;----------------------------脚本主逻辑-----------------------------------------
MOV text_base, 00401000                  ;[需要修改]初始化，这里的数据需要根据实际情况修改
MOV text_size, 00002000
MOV vmp0_base, 00406000
MOV vmp0_size, 00006000
MOV vmp1_base, 0040C000

CALL FindOEP
CALL HookException
CALL FixIAT
MOV eip, OEP
BC
RET
;-------------------------------------------------------------------------------



FindOEP:                                 ;通过一次内存访问断点断在OEP
BPRM text_base, text_size
RUN
MOV OEP, eip
CMT eip, "这里是OEP"
BPMC
RET

--------------------------------------------------------------------------------
HookException:                                   ;（少见情况）当搜索到的指令在两条指令中间时，直接转过去调用很大概率出异常
GPA "KiUserExceptionDispatcher","ntdll.dll"      ;通过hook的方式跳过异常继续搜索
MOV exception_address, $RESULT
BP exception_address
BPGOTO exception_address, HookCallback
RET

HookCallback:
CMP status,0
JNE JmpException
  EVAL "修复call时发生异常，address = {call_base}"
  LOG $RESULT
  JMP Loop_FixCall
JmpException:
  EVAL "修复jmp时发生异常，address = {jmp_base}"
  LOG $RESULT
  JMP Loop_FixJmp
--------------------------------------------------------------------------------


FixIAT:
FINDCMD vmp0_base, "push dword ptr ss:[esp+const];retn const"
GREF
MOV cnt_retn, $RESULT
MOV i, 0
Loop_SetBreakPoint:
  INC i
  GREF i
  BP $RESULT+4
  CMP i,cnt_retn
JB Loop_SetBreakPoint
LOG cnt_retn, "设置断点完毕，数量 = "

FINDCMD text_base, "call const"                ;搜索可能是被加密的call，记录数量
GREF
MOV cnt_call, $RESULT
MOV i, 0
MOV status, 0
Loop_FixCall:
  INC i  
  CMP i, cnt_call  
  JA Loop_FixCallEnd
  GREF i
  MOV call_base, $RESULT                       ;获取当前call的地址和目标地址
  GCI call_base, DESTINATION
  MOV call_dst, $RESULT
  CMP call_dst, vmp0_base                      ;判断是否是call到vmp0这个节，如果不是，跳过
  JB Loop_FixCall
  CMP call_dst, vmp1_base
  JAE Loop_FixCall
    
  MOV eip, call_base                            
  MOV before_esp, esp        
  Loop_FindLastRetn1:                            ;开始获取真正api的地址
    RUN
    STI
    GN eip
    CMP $RESULT, 0
  JE Loop_FindLastRetn1
                                      
  MOV call_retn_addr, [esp]                      ;获取返回地址
  SUB call_retn_addr, call_base                  
  CMP call_retn_addr, 5                          ;类型为call，且废字节为第一字节
  JNE FixCall_2
    EVAL "call {eip}"                              
    ASM call_base-1, $RESULT
    JMP Loop_FixCall
  FixCall_2:    
  CMP call_retn_addr, 6                          ;类型为call，且废字节为最后的字节
  JNE FixCall_3
    EVAL "call {eip}"                              
    ASM call_base, $RESULT                         
    JMP Loop_FixCall      
  FixCall_3:
  CMP before_esp, esp                            ;原始esp小于到达api时的esp，(相差为4或8)且加密后调用方式为jmp，说明压入了无用数据。
  JAE FixCall_4                                   ;类型为jmp，废字节为第一字节
    EVAL "jmp {eip}"                              
    ASM call_base-1, $RESULT
    JMP Loop_FixCall                                             
  FixCall_4:                                     ;类型为jmp，废字节为最后的字节
    EVAL "jmp {eip}"                              
    ASM call_base, $RESULT
    JMP Loop_FixCall                                           
  FixCall_Unknown:                               ;未知情况
  LOG call_base, "修复call出现未知情况，addr = "
  PAUSE
  Loop_FixCallEnd:
  LOG cnt_call, "修复call完毕，数量 = "


FINDCMD text_base, "jmp const"                   ;搜索可能是被加密的jmp，记录数量
GREF
MOV cnt_jmp, $RESULT
MOV i, 0
MOV status, 1
Loop_FixJmp:
  INC i  
  CMP i, cnt_jmp  
  JA Loop_FixJmpEnd
  GREF i
  MOV jmp_base, $RESULT                       ;获取当前jmp的地址和目标地址
  GCI jmp_base, DESTINATION
  MOV jmp_dst, $RESULT
  CMP jmp_dst, vmp0_base                      ;判断是否是jmp到vmp0这个节，如果不是，跳过
  JB Loop_FixJmp
  CMP jmp_dst, vmp1_base
  JAE Loop_FixJmp

  MOV eip, jmp_base                            
  MOV before_esp, esp        
  Loop_FindLastRetn2:                            ;开始获取真正api的地址
    RUN
    STI
    GN eip
    CMP $RESULT, 0
  JE Loop_FindLastRetn2
                                      
  MOV call_retn_addr, [esp]                      ;获取返回地址
  SUB call_retn_addr, jmp_base                  
  CMP call_retn_addr, 5                          ;类型为call，且废字节为第一字节
  JNE FixJmp_2
    EVAL "call {eip}"                              
    ASM jmp_base-1, $RESULT
    JMP Loop_FixJmp
  FixJmp_2:    
  CMP call_retn_addr, 6                         ;类型为call，且废字节为最后的字节
  JNE FixJmp_3
    EVAL "call {eip}"                              
    ASM jmp_base, $RESULT                         
    JMP Loop_FixJmp      
  FixJmp_3:
  CMP before_esp, esp                           ;原始esp小于到达api时的esp，(相差为4或8)且加密后调用方式为jmp，说明压入了无用数据。
  JAE FixJmp_4                                  ;类型为jmp，废字节为第一个字节
    EVAL "jmp {eip}"                              
    ASM jmp_base-1, $RESULT
    JMP Loop_FixJmp                                             
  FixJmp_4:                                     ;类型为jmp，废字节为最后的字节
    EVAL "jmp {eip}"                              
    ASM jmp_base, $RESULT
    JMP Loop_FixJmp                                           
  FixJmp_Unknown:                               ;未知情况
  LOG jmp_base, "修复jmp出现未知情况，addr = "
  PAUSE
  Loop_FixJmpEnd:
  LOG cnt_jmp, "修复jmp完毕，数量 = "
RET

;-------------------------------------------------------------------------------
