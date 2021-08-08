import idc 
import idaapi
import ida_frame 
import ida_struct


def get_lvar_data(lvar_name: str) -> tuple(int, int):
    ea = idc.here()
    func = idaapi.get_func(ea)
    frame = ida_frame.get_frame(func.start_ea)
    lvar = ida_struct.get_member_by_name(frame, lvar_name)
    
    acrh_info = idaapi.get_inf_structure()
    
    if info.is_32bit():
        lvar_ea = lvar.soff + idc.get_reg_value("esp")
        lvar_value = idc.read_dbg_dword(lvar_ea) 
    elif info.is_64bit():
        lvar_ea = lvar.soff + idc.get_reg_value("rsp")
        lvar_value = idc.read_dbg_qword(lvar_ea)
    else:
        return None, None
    
    return lv_ea, lv_value


def get_lv_ea(lvar_name: str) -> int:
    ea, _ = get_lvar_data(lvar_name)
    
    return ea
    
    
def get_lv_name(lvar_name: str) -> int:
    _, value = get_lvar_data(lvar_name)
    
    return value
    
    