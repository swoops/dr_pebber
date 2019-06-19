#/usr/bin/python3
import r2pipe
import json
from dr_pebber import dr_pebber
import tempfile
import struct

####################
# notes
#
# e io.cache = true
# wow 00 @0x4000!0x20
#   write 0x20 bytes of null, initializing it in mem that ESIL can use
#
class r2_peb:
    def __init__(self):
        r2p=r2pipe.open() 
        self.r2p = r2p
        self.esil_init()

    def get_iocahce(self):
        j = json.loads( self.r2p.cmd("ej") )
        return j["io.cache"]

    def set_iocache(self, val):
        if type(val) != bool:
            raise Exception("Invalid value")
        self.r2p.cmd("e io.cache = %s" % val)

    def esil_init(self):
        # notes:
        # | aei                        initialize ESIL VM state (aei- to deinitialize)
        # | aeim [addr] [size] [name]  initialize ESIL VM stack (aeim- remove)
        # | aeip                       initialize ESIL program counter to curseek
       r2p = self.r2p 
       r2p.cmd("ara+") # push new register arena
       r2p.cmd("aei")
       r2p.cmd("aeim 0x4000 0x1000 global_area")
       r2p.cmd("aeip")


    def esil_fin(self):
       r2p = self.r2p 
       r2p.cmd("aei-")
       r2p.cmd("aeim-")
       r2p.cmd("ara-") # pop new register arena
       r2p.cmd(".ar-")

    def putpeb(self, loc=0x30, peb=None):
        r2p = self.r2p
        if not self.get_iocahce():
            raise Exception("Need ioCache")
        if type(loc) != int:
            raise Exception("Need a valid location")
        # wff <<fname>> @0x4000
        #  wite the contents of fnamme to the 0x4000 location
        #  make sure io.cache is on :)
        r2p.cmd("wff %s @0x%x" % (self.fname,loc))
        print("[*] Fake PEB loaded at 0x%x" % (loc))

    def peb_exist(self):
        # TODO: don't use 0x30, find it
        where = 0x30
        addr = 0
        st = struct.Struct("<I")
        jl = self.r2p.cmd("pxj %d @0x%x" % (st.size, where ) )
        jl = json.loads(jl)
        addr = st.unpack(bytearray(jl))[0]

        if addr == where+4: # TODO: better check here too...
            return True
        return False

    def put_dr_pebber(self, dp):
        r2p = self.r2p
        if not self.get_iocahce():
            raise Exception("Need ioCache")
        loc = dp.offset
        with tempfile.NamedTemporaryFile() as fp:
            for i in dp.generate_raw_bytes():
                fp.write(i)
            fp.flush()
            r2p.cmd("wff %s @0x%x" % (fp.name,loc))

        if not self.peb_exist():
            raise Exception("Peb write failed")
        print("[*] Fake PEB loaded 0x%x to 0x%x" % (loc,dp.size))
        for i in dp.r2_flags():
            r2p.cmd(i)

    def prep(self):
        self.r2p.cmd("s 0x00401300")
        self.r2p.cmd("af")

if __name__ == "__main__":
    dp = dr_pebber(dll_dir="./dlls/")
    r2 = r2_peb()
    if not r2.get_iocahce():
        r2.set_iocache(True)
        print("[*] Setting IO Cache")
    r2.put_dr_pebber(dp)
