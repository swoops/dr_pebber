#!/usr/bin/python3
import struct
import pefile
from os.path import join as path_join

import sys
def hexdump(binary, start):
    buf = ""
    print("=========================== HexDump ========================================")
    size = len(binary)
    for i,x in enumerate( binary ):
        if i % 16 == 0:
            if len( buf ) > 0: 
                sys.stdout.write("%s\n" % buf)
            buf = ""
            if i != size-1:
                sys.stdout.write("0x%08x: " % (i+start))

        if x >= 0x20 and x <= 0x7e:
            buf += chr(x)
        else:
            buf += "."
        sys.stdout.write("%02x " % x)

    written = i % 16
    if written > 0:
        sys.stdout.write("%s%s\n" % (" "*((15-written )*3), buf))
    else:
        print("")
    print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")


class dllbuild():
    def __init__(self, name, dll_dir=None, base=0):
        if dll_dir: 
            self.fname = path_join(dll_dir, name)
        else: 
            self.fname = name

        self.name = name
        self.size = None
        self.base = base
        self.pe = pefile.PE(self.fname)
        self.pe.close()
        self.r2_suffix = "dr_"

        if not self.pe.is_dll: 
            raise Exception("Must be a DLL")

        self._keys = [
            self.pe.DOS_HEADER, 
            self.pe.NT_HEADERS, 
            self.pe.FILE_HEADER, 
            self.pe.OPTIONAL_HEADER,
            self.pe.DIRECTORY_ENTRY_EXPORT.struct
        ]
        self._fix_offsets()
        self._build_export_data()

    def _fix_offsets(self):
        # much of the DLL is being removed, most of the offsets can be fixed up
        # front
        pe  = self.pe
        opt = pe.OPTIONAL_HEADER
        ex  = pe.DIRECTORY_ENTRY_EXPORT.struct

        # change offsets in the pefile headers so we can just use those
        # this makes printing come out correct as well
        offset = 0
        for i in self._keys:
            i.set_file_offset(offset)
            offset += i.sizeof()

        # bytes between DOS_HEADER and NT_HEADERS removed, adjusted
        pe.DOS_HEADER.e_lfanew = pe.DOS_HEADER.sizeof()

        # options should point to export directory
        opt.SizeOfHeapCommit = ex.get_file_offset()

        name_count = ex.NumberOfNames
        func_count = ex.NumberOfFunctions
        ex.AddressOfFunctions    = ex.get_file_offset() + ex.sizeof()
        ex.AddressOfNames        = ex.AddressOfFunctions + (func_count+1)*4 #+1 for 0th elemnt
        ex.AddressOfNameOrdinals = ex.AddressOfNames + name_count*4
        self.string_buff_offset  = ex.AddressOfNameOrdinals + func_count*2


    def print_r2flags(self):
        """
        Print all the Radare2 flags for this object
        """
        print(" == Radare2 Flags ==")
        for i in self.r2_flags(): print(i)

    def r2_flags(self):
        suffix = self.r2_suffix
        for sec in self._keys:
            for d in self._gen_dicts_from_sec(sec):
                params = ( suffix, self.name, sec.name, d["name"],
                    d["FileOffset"] + self.base
                )
                yield 'f ptr.%s%s:%s.%s 4 @0x%x' % params
        ex  = self.pe.DIRECTORY_ENTRY_EXPORT
        exs = ex.struct
        yield 'f ptr.%s%s.AddressOfFunctions 4 @0x%x' % (suffix, self.name, exs.AddressOfFunctions+self.base)
        yield 'f ptr.%s%s.AddressOfNames 4 @0x%x' % (suffix, self.name, exs.AddressOfNames+self.base)
        yield 'f ptr.%s%s.AddressOfNameOrdinals 4 @0x%x' % (suffix, self.name, exs.AddressOfNameOrdinals+self.base)

        # strings
        for i,name in enumerate( self.name_buf ):
            yield 'f str.%s %d @0x%x' % (name.decode("utf-8"), len(name), self.name_pointers_arr[i] + self.base)

        for i in ex.symbols:
            if not i.name: continue 
            values = ( suffix,  i.name.decode("utf-8"), self.func_pointer_arr[i.ordinal]+self.base)
            ret = 'f sym.%s%s 1 @0x%x' % values
            yield ret

    def _gen_dicts_from_sec(self, sect):
        if type(sect) != pefile.Structure:
            raise Exception("section must be a pefile.Structure")
        obj_dict = sect.dump_dict()
        for key in sect.__keys__:
            name = key[0]
            d = dict(obj_dict[name])
            d["name"] = name
            yield d

    def print_all(self):
        """
        pretty print the entire Nearly the entire DLL strcutre produced.
        """
        print(" == DLL: %s ==" % self.name)
        print("from_file: %s" % self.fname)
        if self.base:
            print("Offsets are all relative to the base adddress (0x%x)" % self.base)
            print("Unless otherwise stated")
        offset = 0

        for i in self._keys:
            if self.base > 0:
                print("[0x%08x] real offset" % ( i.get_file_offset()+self.base ))
            for line in i.dump():
                print(line)
            hexdump(i.__pack__(), offset+self.base)
            offset += i.sizeof()

        ex = self.pe.DIRECTORY_ENTRY_EXPORT.struct

        ##
        # functions
        ##
        # TODO: make this less bad
        print("Listing all functions")
        print("    RADDR       RVA      ordinal      name")
        for i in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not i.name: continue 
            values = (
                self.func_pointer_arr[i.ordinal] + self.base,
                self.func_pointer_arr[i.ordinal],
                i.ordinal,
                i.name.decode("utf-8")
            )
            print("  0x%08x 0x%08x   0x%04x      %s" % values)

        #TODO: text section
        return

    def _pack_name_buf(self):
        return b'\x00'.join(self.name_buf) + b'\x00'

    def pack(self):
        """
        Return the entire DLL as bytes
        """
        buf = bytes()
        ## headers that pefile can take care of for us ##
        ex = self.pe.DIRECTORY_ENTRY_EXPORT.struct
        for i in self._keys:
            buf += i.__pack__()

        ## add function,name and ordinal arrays ##
        if len(buf) != ex.AddressOfFunctions:
            raise Exception("offset to AddressOfFunctions is wrong")
        st = struct.Struct("<I")
        for i in self.func_pointer_arr:
            buf += st.pack(i)

        if len(buf) != ex.AddressOfNames:
            raise Exception("offset to AddressOfNames is wrong")
        for i in self.name_pointers_arr:
            buf += st.pack(i)

        st = struct.Struct("<H")
        if len(buf) != ex.AddressOfNameOrdinals:
            raise Exception("offset to AddressOfNameOrdinals is wrong")
        for i in self.ordinals_arr:
            buf += st.pack(i)

        ## handle data: strings buff, function bytecode ##
        if len(buf) != self.name_pointers_arr[0]:
            raise Exception("Offset to Name buffer wrong (buflen: 0x%x, offset: 0x%x)" % (len(buf), self.name_pointers_arr[0]))
        buf += self._pack_name_buf()

        if len(buf) != self.func_text_offset:
            raise Exception("Offset to function text section wrong")
        buf += self.func_text

        return buf

    def _build_export_data(self):
        ex = self.pe.DIRECTORY_ENTRY_EXPORT
        self.name_buf = []
        self.name_pointers_arr = []
        self.ordinals_arr = []

        if self.string_buff_offset == None:
            raise Exception("Need to of fixed export table")

        offset = self.string_buff_offset
        for i in ex.symbols:
            self.ordinals_arr.append(i.ordinal)
            if i.name:
                self.name_pointers_arr.append(offset)
                self.name_buf.append(i.name)
                # +1 for null termination, to be added
                offset += len(i.name)+1 

        self.func_text_offset = offset 
        self.name_buf_size = offset - self.string_buff_offset

        # sanity: make sure things are init properly
        if len(self.ordinals_arr) != ex.struct.NumberOfFunctions:
            raise Exception("Number of Ordinals not correct")
        elif len(self.name_pointers_arr) != ex.struct.NumberOfNames:
            raise Exception("Number of Function Names not correct")

        # each function is just a `ret`, at it's own location to distinguish
        # them
        ret = b'\xc3'
        self.func_text = ret * ex.struct.NumberOfFunctions
        self.size = offset + len(self.func_text) 
        self.func_pointer_arr = []

        self.func_pointer_arr.append(0) # ordinals start at 1, but offset at 0, so extra unused pointer?
        l = list(ex.symbols)
        l.sort(key=lambda x: x.ordinal)
        for i,func in enumerate(l):
            if i+1 != func.ordinal: raise Exception("Sanity failed")
            self.func_pointer_arr.append(offset)
            offset += 1 # ponit to next null byte

    def name_from_ord(self, ordinal):
        """
        From a ordinal, get a function name
        """
        ex = self.pe.DIRECTORY_ENTRY_EXPORT
        for i in ex.symbols:
            if i.ordinal == ordinal:
                print(i.name)
                return
        return None

class dr_pebber():
    pvoid_fmt = "I"
    types = {
        "BOOLEAN"                      : {"fmt": "B"}, # should be ? but put a B so we can make unique values
        "BBOOLEAN"                     : {"fmt": "I"}, # fake, to fix offset problems
        "BYTE"                         : {"fmt": "B"},
        "HANDLE"                       : {"fmt": pvoid_fmt},
        "LARGE_INTEGER"                : {"fmt": None},
        "PPEB_FREE_BLOCK"              : {"fmt": None},
        "PPEB_LDR_DATA"                : {"fmt": pvoid_fmt},
        "PPEBLOCKROUTINE"              : {"fmt": None},
        "PPVOID"                       : {"fmt": None},
        "PRTL_USER_PROCESS_PARAMETERS" : {"fmt": None},
        "PVOID"                        : {"fmt": pvoid_fmt},
        "ULONG"                        : {"fmt": "I"},
        "SHORT"                        : {"fmt": "H"},
        "PSHORT"                       : {"fmt": "h"}, # invinted to take care of DOS 16 bit pointers
        "USHORT"                       : {"fmt": "h"},
        "PWSTR"                        : {"fmt": pvoid_fmt}
    }

    def __init__(self, offset=0x30, dll_dir=None):
        self.teb = None
        self.peb = None
        self.loaderdata = None
        self.strings = None
        self.dll_dir = dll_dir
        self.dlls = []
        self.modules = []
        self.unique = 0x10
        self.r2_suffix = "dr_"

        self.offset = offset
        new_offset = offset
        new_offset += self._build_teb(new_offset)
        new_offset += self._build_peb(new_offset)
        new_offset += self._build_loaderdata(new_offset)

        for i in ["ntdll.dll", "kernel32.dll", ]:
            new_offset += self._add_module(i, new_offset)

        for mod in self.modules: 
            dll = dllbuild(mod["name"], dll_dir=self.dll_dir, base=new_offset)
            self._struct_set(mod, "BaseAddress", "value", new_offset)
            self.dlls.append(dll)
            new_offset += dll.size

        new_offset += self._add_mod_strings(new_offset)
        self.size = new_offset
        self.link_modules()

    def get_unique_value(self, t):
        if t not in self.types: 
            raise Exception("Unknown type")
        ty = self.types[t]
        ret = 0
        for i in range(struct.calcsize(ty["fmt"])):
            ret <<= 8
            ret += self.unique
        self.unique += 1
        return ret

    def print_r2flags(self):
        """
        Print all the Radare2 flags for this object
        """
        print(" == Radare2 Flags ==")
        for i in self.r2_flags():
            print(i)

    def r2_flags(self):
        """
        Generate each command to add a flag in Radare2
        """
        ptr_size = struct.calcsize(self.pvoid_fmt)

        for obj in [self.teb, self.peb, self.loaderdata]:
            for i in self._r2flags_frm_obj(obj):
                yield i
        for obj in self.modules:
            for i in self._r2flags_frm_obj(obj):
                yield i

        for obj in self.dlls:
            for i in obj.r2_flags():
                yield i

        for obj in self.strings["info"]:
            yield "f str.%s_DP %d @0x%x" % (obj["name"], obj["size"], obj["offset"])

    def _r2flags_frm_obj(self, obj):
        name = obj["name"]
        for i in obj["info"]:
            size = struct.calcsize(self.types[i["type"]]["fmt"])
            yield "f ptr.%s%s.%s %d @0x%x" % (self.r2_suffix, name, i["name"], size, i["offset"] )

    def print_all(self):
        """
        Print an annotated version of the entire structure
        """
        print("== PRETTY PRINT STRUCTURE==\n")
        self._print_obj(self.teb, "TEB")
        self._print_obj(self.peb, "PEB")
        self._print_obj(self.loaderdata, "LoaderData")
        for i,m in enumerate(self.modules):
            self._print_obj(m, "MODULE[%d] %s" % (i,m["name"]))
        self.print_dlls()
        self.print_strings()
        self.print_r2flags

        print("-- Everything --")
        data = b''
        data = dp.get_whole_binary()
        hexdump(data, self.offset)

    def print_dlls(self):
        """
        Print the information in each DLL added.
        """
        for i in self.dlls:
            i.print_all()

    def print_strings(self):
        """
        Print the strings section of this object. This won't include the
        strings inside any of the DLLS.
        """
        obj = self.strings
        print("Strings (size: 0x%x)" % obj["size"])
        for i in obj["info"]:
            print("  0x%08x: %s length: %d" % (i["offset"], i["name"], i["size"]))
        hexdump(self.serialize_all_strings(), self.strings["offset"])

    def _print_obj(self, obj, name):
        print("%s (size: 0x%x)" % ( name, obj["st"].size))
        for i in obj["info"]:
            val  = "0x%x" % i["value"]
            print("  0x%08x: %-40s %s" % (i["offset"], i["name"], val))
        hexdump(self.serialize_obj(obj), obj["offset"])
        

    def _build_py_struct(self, obj, offset=None):
        fmt = "<" # little endian
        for i in obj:
            if offset != None:
                i["offset"] = offset+struct.calcsize(fmt)
            t = self.types[i["type"]]
            fmt += "%c" % t["fmt"]
        st = struct.Struct(fmt)
        return st

    def struct_get(self, obj, name, member):
        for i in obj["info"]:
            if i["name"] == name:
                return i[member]
        raise Exception("Could not find %s" % name)

    def _struct_set(self, obj, name, member, val):
        for i in obj["info"]:
            if i["name"] == name:
                i[member] = val
                return
        raise Exception("Could not find %s" % name)
        
    
    def _build_teb(self, offset):
        if self.teb: 
            raise Exception("Peb already exists")
        # missing everything except PEB pointer
        teb_struct = [
            {"name" : "Peb", "type":"PVOID", "value":None }
        ]
        st = self._build_py_struct(teb_struct, offset)
        teb_struct[0]["value"] = offset + st.size

        teb = {"name" : "TEB"}
        teb["st"] = st
        teb["info"] = teb_struct
        teb["offset"] = offset
        self.teb = teb
        return st.size
        
    def _build_peb(self, offset, loader=None, debugged=False):
        if self.peb: 
            raise Exception("Peb already exists")
        peb_struct = [
            {"name" : "InheritedAddressSpace", "type":"BOOLEAN", "value":None },
            {"name" : "ReadImageFileExecOptions", "type":"BOOLEAN", "value":None },
            {"name" : "BeingDebugged", "type":"BOOLEAN", "value":None },
            {"name" : "Spare", "type":"BOOLEAN", "value":None },
            {"name" : "Mutant", "type":"HANDLE", "value":None },
            {"name" : "ImageBaseAddress", "type":"PVOID", "value":None },
            {"name" : "LoaderData", "type":"PPEB_LDR_DATA", "value":None },
            # more follow... but don't need them
        ]
        st = self._build_py_struct(peb_struct, offset)

        ## set values
        for i in peb_struct:
            if i["name"] == "LoaderData":
                i["value"] = offset + st.size
            elif i["name"] == "BeingDebugged":
                i["value"] = debugged
            else:
                i["value"] = self.get_unique_value(i["type"])

        peb = {"name": "PEB"}
        peb["st"] = st
        peb["info"] = peb_struct
        peb["offset"] = offset

        self.peb = peb
        return st.size
        # raw_peb = st.pack(*[i["value"] for i in peb_struct])

    def _build_loaderdata(self, offset):
        ldr_struct = [ # this struct is complete, flattened for convenience
            {"name" : "Length","type":"ULONG", "value":None },
            {"name" : "Initialized","type":"BBOOLEAN", "value":None }, ## for the sake of alignment
            {"name" : "SsHandle","type":"PVOID", "value":None },
            # all LIST_ENTRY's will point to NULL, must be updated later
            # {"name" : "InLoadOrderModuleList","type":"LIST_ENTRY", "value":None },
            {"name" : "InLoadOrderModuleList.Flink","type":"PVOID", "value":0 },
            {"name" : "InLoadOrderModuleList.Blink","type":"PVOID", "value":0 },
            # {"name" : "InMemoryOrderModuleList","type":"LIST_ENTRY", "value":None },
            {"name" : "InMemoryOrderModuleList.Flink","type":"PVOID", "value":0 },
            {"name" : "InMemoryOrderModuleList.Blink","type":"PVOID", "value":0 },
            # {"name" : "InInitializationOrderModuleList","type":"LIST_ENTRY", "value":None },
            {"name" : "InInitializationOrderModuleList.Flink","type":"PVOID", "value":0 },
            {"name" : "InInitializationOrderModuleList.Blink","type":"PVOID", "value":0 }
        ]
        st = self._build_py_struct(ldr_struct, offset)
        end = offset+st.size

        ## set values
        for i in ldr_struct:
            if i["value"] == None:
                i["value"] = self.get_unique_value(i["type"])

        loaderdata = {"name" : "LoaderData"}
        loaderdata["st"] = st
        loaderdata["info"] = ldr_struct
        loaderdata["offset"] = offset
        self.loaderdata = loaderdata
        return st.size

    def _add_module(self, fname, offset):
        mod_struct = [
            # {"name" : "InLoadOrderModuleList","type":"LIST_ENTRY", "value" : None},
            {"name" : "InLoadOrderModuleList.Flink","type":"PVOID", "value" : None},
            {"name" : "InLoadOrderModuleList.Blink","type":"PVOID", "value" : None},
            # {"name" : "InMemoryOrderModuleList","type":"LIST_ENTRY", "value" : None},
            {"name" : "InMemoryOrderModuleList.Flink","type":"PVOID", "value" : None},
            {"name" : "InMemoryOrderModuleList.Blink","type":"PVOID", "value" : None},
            # {"name" : "InInitializationOrderModuleList","type":"LIST_ENTRY", "value" : None},
            {"name" : "InInitializationOrderModuleList.Flink","type":"PVOID", "value" : None},
            {"name" : "InInitializationOrderModuleList.Blink","type":"PVOID", "value" : None},
            {"name" : "BaseAddress","type":"PVOID", "value" : 0},
            {"name" : "EntryPoint","type":"PVOID", "value" : None},
            {"name" : "SizeOfImage","type":"ULONG", "value" : None},
            # {"name" : "FullDllName","type":"UNICODE_STRING", "value" : None},
            {"name" : "FullDllName.Length","type":"USHORT", "value" : None},
            {"name" : "FullDllName.MaximumLength","type":"USHORT", "value" : None},
            {"name" : "FullDllName.Buffer","type":"PWSTR", "value" : None},
            # {"name" : "BaseDllName","type":"UNICODE_STRING", "value" : None},
            {"name" : "BaseDllName.Length","type":"USHORT", "value" : 0},
            {"name" : "BaseDllName.MaximumLength","type":"USHORT", "value" : 0},
            {"name" : "BaseDllName.Buffer","type":"PWSTR", "value" : 0},
            # Does not appear to be needed at this time... may as well save space :)
            # {"name" : "Flags","type":"ULONG", "value" : None},
            # {"name" : "LoadCount","type":"SHORT", "value" : None},
            # {"name" : "TlsIndex","type":"SHORT", "value" : None},
            # # {"name" : "HashTableEntry","type":"LIST_ENTRY", "value" : None},
            # {"name" : "HashTableEntry.Flink","type":"PVOID", "value" : None},
            # {"name" : "HashTableEntry.Blink","type":"PVOID", "value" : None},
            # {"name" : "TimeDateStamp","type":"ULONG", "value" : None},
        ]
        st = self._build_py_struct(mod_struct, offset)
        end = offset+st.size

        ## set values
        for i in mod_struct:
            if i["value"] == None:
                i["value"] = self.get_unique_value(i["type"])

        mod = {}
        mod["st"] = st
        mod["info"] = mod_struct
        mod["offset"] = offset
        mod["name"] = "%s" % fname
        self.modules.append(mod)
        return st.size

    def link_modules(self):
        """
        Walk through array of modules and link them all together. Every module
        will be linked in a circular double linked list. Currently, ordering is
        disregarded.
        """
        ####
        # Ordering is not really checked, sorry.
        # from reverinsg a sampe of Emotete:
        # InLoadOrderModuleList: 
        #  Emotete (prg name itself), ntdll.dll, kernel32.dll, KERNELBASE.dll
        size = len(self.modules)
        if size <= 0:
            raise Exception("Modules list is empty")

        links = [ "InLoadOrderModuleList", "InMemoryOrderModuleList", "InInitializationOrderModuleList" ]

        # link each module to next and back
        for i in range(size):
            # iterate over order piars of modules
            m0 = self.modules[i]
            m1 = self.modules[(i+1)%size]
            
            # InLoadOrderModuleList 
            for name in links:
                self._struct_set(
                    m0, name+".Flink", "value", # modules[i].InLoadOrderModuleList.Flink = 
                    self.struct_get(m1, name+".Flink", "offset") # &modules[i+1]InLoadOrderModuleList.Blink
                )
                self._struct_set(
                    m1, name+".Blink", "value", # modules[i+1].InLoadOrderModuleList.Blink = 
                    self.struct_get(m0, name+".Flink", "offset") # &modules[i]InLoadOrderModuleList.Flink
                )

        # loaderdata.Flink
        m0 = self.modules[0] 
        m1 = self.modules[-1] 
        for name in links:
            self._struct_set( # link loaderdata->Flink to m0
                self.loaderdata, name+".Flink", "value",
                self.struct_get(m0, name+".Flink", "offset")
            )
            self._struct_set( # link loaderdata->Blink to m1
                self.loaderdata, name+".Blink", "value",
                self.struct_get(m1, name+".Flink", "offset")
            )
            self._struct_set( # link m1.Flink to loaderdata
                m1, name+".Flink", "value", 
                self.struct_get(self.loaderdata, name+".Flink", "offset") 
            )
            self._struct_set( # link m0.Blink to loaderdata
                m0, name+".Blink", "value", 
                self.struct_get(self.loaderdata, name+".Flink", "offset") 
            )


    def wide_encode(self, string):
        """
        Encode a string as Windows wide character array.
        """
        ret = b''
        st = struct.Struct("<H")
        for i in string:
            ret += st.pack(ord(i))
        ret += st.pack(0)
        return ret

    def _add_mod_strings(self, offset):
        if len(self.modules) <= 0:
            raise Exception("No modules")

        if self.strings != None:
            raise Exception("Strings already exist")

        strings = {}
        strings["offset"] = offset
        info = []

        for mod in self.modules:
            # TODO: If it is already in list of strings, just use it instead of adding a second one
            size = len(self.wide_encode( mod["name"] ))
            self._struct_set(mod, "BaseDllName.Length", "value", size)
            self._struct_set(mod, "BaseDllName.MaximumLength", "value", size)
            self._struct_set(mod, "BaseDllName.Buffer", "value", offset)
            info.append( {"name": mod["name"], "size":size, "offset":offset } ) 
            offset+=size

        strings["info"] = info
        strings["size"] = offset-strings["offset"]
        self.strings = strings
        return strings["size"]

    def generate_raw_bytes(self):
        """
        Generates raw bytes, yielding one byte at a time
        """
        for obj in [self.teb, self.peb, self.loaderdata]:
            for byte in self.serialize_obj(obj):
                yield byte

        for mod in self.modules:
            for byte in self.serialize_obj(mod):
                yield byte
        for b in self.pack_dlls():
            yield b
        for b in self.serialize_all_strings():
            yield b

    def get_whole_binary(self):
        """
        Returns the entire binary in one big blob
        """
        data = b''
        for obj in [self.teb, self.peb, self.loaderdata]:
            data += self.serialize_obj(obj)

        for mod in self.modules:
            data += self.serialize_obj(mod)
        data += self.pack_dlls()
        data += self.serialize_all_strings()
        return data

    def serialize_obj(self, obj):
        return obj["st"].pack(*[i["value"] for i in obj["info"]] )

    def pack_dlls(self):
        ret = b''
        for blob in self.dlls:
            ret += blob.pack()
        return ret

    def serialize_all_strings(self):
        ret = b''
        for s in self.strings["info"]:
            ret += self.wide_encode( s["name"] )
        return ret

if __name__ == "__main__":
    dp = dr_pebber(dll_dir="./dlls/")
    dp.print_all()
    # dp.print_r2flags()

    # some sanity # TODO: add more tests
    data = dp.get_whole_binary()
    for i,b in enumerate(dp.generate_raw_bytes()):
        if data[i] != b:
            print("Offsets DIFFER:")
            print("byte %x vs %x" % ( int( data[i] ), int( b ) ))
            print("offset: 0x%x" % dp.offset+i)
            raise Exception("Sanity")
    if i+1 != len(data):
        raise Exception("Sanity data: %d vs %d" % (len(data), i))
