import idaapi
import idautils
import string

from pprint import pprint

def go_make_any(addr, name, make_func, comment=""):
    MakeUnkn(addr, 0)
    make_func(addr)
    if name != "":
        MakeName(addr, name)
    if comment != "":
        MakeComm(addr, comment)
def go_make_dword(addr, name, comment=""):
    go_make_any(addr, name, MakeDword, comment)
    return Dword(addr)

def go_make_qword(addr, name, comment=""):
    go_make_any(addr, name, MakeQword, comment)
    return Qword(addr)

def go_make_offset(addr, name, comment="", base=0):
    v = go_make_qword(addr, name, comment)
    OpOff(addr, 0, base)
    return v

def go_make_array(addr, name):
    go_make_offset(addr, name)
    go_make_qword(addr+8, "", name+".len")
    go_make_qword(addr+0x10, "", name+".cap")

def go_make_string(addr, name, comment=""):
    strptr = Qword(addr)
    strlen = Qword(addr+8)
    if strptr != 0 and strlen != 0:
        MakeUnkn(strptr, 0)
        MakeStr(strptr, strptr + strlen)
    go_make_offset(addr, name, comment)
    go_make_qword(addr+8, "", name+".len")
    return GetString(strptr, strlen)

def go_buildid():
    # TODO: work only for windows
    textstart = idaapi.get_segm_by_name(".text").startEA
    buildid = GetManyBytes(textstart, 0x3c)
    if buildid.startswith("\xff Go build ID: \""):
        MakeStr(textstart, textstart + 0x3c)
        return buildid[1:-1]
    else:
        return None

def go_find_pclntab():
    # search using buildid entry in pclntab
    pos = idaapi.get_segm_by_name(".text").endEA
    textstart = idaapi.get_segm_by_name(".text").startEA
    idaapi.get_segm_by_name(".text").startEA
    while True:
        # WARN: TODO: 0x1234567 planned to remove, need find another way
        gobuilddefpos = FindBinary(
            pos, SEARCH_UP,
            "67 45 23 01 " + "00 "*20 +
            "67 6f 2e 62 75 69 6c 64 69 64")
        if gobuilddefpos < 100 or gobuilddefpos > pos:
            break
        
        # TODO: pointersize matching
        if Dword(gobuilddefpos-0x10) == textstart:
            # at this point we must have valid buildid entry in pclntab
            # some pointers in this struct relative to pclntab base
            # use entry name relative^ pointer to detect pclntab base
            return gobuilddefpos + 24 - Dword(gobuilddefpos-0x8)
        
        pos = gobuilddefpos
    return None

def go_name_filter(name):
    name = filter(lambda x: x in string.printable, name)
    if len(name.split("{")) > 1:
        # deal with struct
        name = name.split("{")[0] + "____"
    replacements = {
        "/": "_",
        ".": "_",
        "*": "p_",
        "(": "_",
        ")": "_",
        ";": "",
        ":": "",
        "[": "_",
        "]": "_",
        "{": "_",
        "}": "_",
        "-": "",
        " ": "",
        "<": "_",
        ">": "_",
    }
    return "".join([replacements.get(c, c) for c in name])

def go_pclntab_handle_function(funcaddr, funcname, pclnentry):
    name_filtered = go_name_filter(funcname)
    if GetFunctionName(funcaddr) not in [name_filtered, name_filtered + hex(funcaddr)]:
        MakeUnkn(funcaddr, 0)
        MakeCode(funcaddr)
        MakeFunction(funcaddr)
        if MakeName(funcaddr, name_filtered) == 0:
            MakeName(funcaddr, name_filtered + hex(funcaddr))
        MakeComm(funcaddr, funcname)
    
    if funcname == "runtime.dopanic_m":
        flags = GetFunctionFlags(funcaddr)
        if flags != -1:
            SetFunctionFlags(funcaddr, flags | FUNC_NORET_PENDING)

def go_pclntab_travel(pclntab):
    # TODO: pointersize
    nfunc = Dword(pclntab+8)
    for i in xrange(nfunc):
        entry = pclntab + 0x10 + i * 0x10
        MakeQword(entry)
        MakeQword(entry+8)
        sym = Qword(entry)
        info = Qword(entry + 8) + pclntab
        symnameoff = Dword(info + 8) + pclntab
        symname = GetString(symnameoff)
        MakeStr(symnameoff, symnameoff + len(symname))
        go_pclntab_handle_function(sym, symname, info)
    return nfunc

def go_pclntab_find(pclntab, name):
    # TODO: pointersize
    nfunc = Dword(pclntab+8)
    for i in xrange(nfunc):
        entry = pclntab + 0x10 + i * 0x10
        sym = Qword(entry)
        info = Qword(entry + 8) + pclntab
        symnameoff = Dword(info + 8) + pclntab
        if GetString(symnameoff) == name:
            return sym
    return None

def go_get_first_moduledata(resolvenameoff):
    pos = resolvenameoff
    for i in xrange(0, 25):
        if GetMnem(pos) == "lea" and GetOpnd(pos, 0) != "rbp":
            return GetOperandValue(pos, 1)
        pos = NextHead(pos)
    return None

def go_moduledatas_parse(moduledata):
    mdname = go_make_string(moduledata + 0x160, "", "module name")
    if mdname == None or mdname == "":
        mdname = "md"
    go_make_array(moduledata, mdname + "_pclntable")
    go_make_array(moduledata + 0x18, mdname + "_ftab")
    go_make_array(moduledata + 0x30, mdname + "_filetab")
    def make_datawithend(off, name):
        go_make_offset(moduledata + off + 8, mdname + "_e" + name)
        return go_make_offset(moduledata + off, mdname + "_" + name)
    go_make_offset(moduledata + 0x48, mdname + "_findfunctab")
    go_make_offset(moduledata + 0x50, mdname + "_minpc")
    go_make_offset(moduledata + 0x58, mdname + "_maxpc")
    make_datawithend(0x60, "text")
    make_datawithend(0x80, "data")
    make_datawithend(0x90, "bss")
    make_datawithend(0xa0, "noptrbss")
    types = make_datawithend(0xc8, "types")
    MakeName(types, mdname + "_types__")

def go_moduledatas_travel(firstmodule):
    module = firstmodule
    modules = []
    while module != 0:
        go_moduledatas_parse(module)
        modules.append(module)
        module = Qword(module + 0x1b0)
    return modules

def go_parse_typestr(addr):
    MakeUnkn(addr, 0)
    MakeUnkn(addr, 3)
    strsize = (Byte(addr+1)<<8) | Byte(addr+2)
    MakeStr(addr+3, addr+3+strsize)
    MakeName(addr, "type_string__" + (hex(addr)[2:]))
    return GetString(addr+3,strsize)

def go_handle_type(typebase, t):
    typename = go_parse_typestr(typebase + Dword(t + 0x28))
    go_make_dword(t + 0x28, "")
    OpOff(t+ 0x28, 0, typebase)
    MakeName(t, "_type_" + go_name_filter(typename) + "_" + (hex(t)[2:-1]))
    MakeRptCmt(t, typename)
    go_make_qword(t + 8, "", "type.ptrdata")
    go_make_dword(t + 0x10, "", "type.hash")
    go_make_offset(t + 0x18, "", "type.alg")
    go_make_offset(t + 0x20, "", "type.gcdata")
    
def go_newobject_types_xfer_travel(module, newobjectfunc):
    typebase = Dword(module + 0xc8)
    already = []
    for xfer in idautils.XrefsTo(newobjectfunc):
        exmov = PrevHead(xfer.frm)
        exlea = PrevHead(exmov)
        if GetMnem(exmov) == "mov" and GetMnem(exlea) == "lea" and \
            GetOpnd(exmov, 1) == GetOpnd(exlea, 0):
            newtype = GetOperandValue(exlea, 1)
            if newtype not in already:
                go_handle_type(typebase, newtype)
                already.append(newtype)
    return len(already)

def log(str):
    print "[GO] {}".format(str)

def main():
    buildid = go_buildid()
    if buildid is None:
        log("Cannot find build id in binary")
    else:
        print buildid

    pclntab = go_find_pclntab()
    if pclntab is None:
        log("Cannot find pclntab table :(")
        return
    
    log("Naming functions...")
    log("Named {} functions".\
        format(go_pclntab_travel(pclntab)))

    resolveNameOff = go_pclntab_find(pclntab, "runtime.resolveNameOff")
    if resolveNameOff is None:
        log("Cannot find runtime.resolveNameOff function :(")
        return
    
    firstModuleData = go_get_first_moduledata(resolveNameOff)
    if firstModuleData is None:
        log("Cannot find first moduledata :(")
        return

    log("Finded first moduledata at {}".format(hex(firstModuleData)))
    modules = go_moduledatas_travel(firstModuleData)
    if len(modules) == 0:
        log("Cannot find module information")
        return
    
    newObjectFunc = go_pclntab_find(pclntab, "runtime.newobject")
    if newObjectFunc is None:
        log("Cannot find runtime.newobject")
        return
    
    # TODO: support many modules, need some code changes in other places
    log("Naming types structs...")
    log("Named {} type structs".\
        format(go_newobject_types_xfer_travel(modules[0], newObjectFunc)))

if __name__ == "__main__":
    main()
