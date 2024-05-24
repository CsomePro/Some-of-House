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

### class _IO_jumps_t(addr, name)

**Parameters**
- addr(int) - IO虚表的地址
- name(str) - 当前IO虚表的名字

#### from_bytes(addr, data, name="\<unknown\>") -> _IO_jumps_t

_@classmethod_

从原始字节序列中构建_IO_jumps_对象

**Parameters**

- addr(int) - IO虚表的地址
- data(bytes) - IO虚表原始bytes
- name(str) - 当前IO虚表的名字，默认为未知

**return**

返回构建虚表对象

#### print()

打印输出当前虚表

### class HouseLibc(libc)

**Parameters**

- libc([ELF](https://docs.pwntools.com/en/latest/elf/elf.html#pwnlib.elf.elf.ELF) | str) - libc文件ELF对象或者libc文件路径字符串


#### find__IO_wfile_jumps_maybe_mmap() -> _IO_jump_t

适用于无符号libc搜索_IO_wfile_jumps_maybe_mmap地址