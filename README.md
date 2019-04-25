---
title: SymbolicExecution
date: 2019-04-09 14:34:09
categories: 笔记
description: 符号执行笔记
tags: [bin,angr]
---
<!--more-->

> Angr是一个利用python开发的二进制程序分析框架它能够进行动态的符号执行分析,真实执行程序时我们只能选择一条路径,而由于符号是可变的可以利用这一特性来进行遍历每一条路径,同时存在路径爆炸的问题,这里介绍一下angr的基础方法和介绍一下官方使用的简单例子

angr的安装
官方有安装方法非常方便
[官方安装方法](https://docs.angr.io/introductory-errata/install)
## angr的基础方法
### Project
通过Project 返回 <class 'angr.project.Project'>类的对象 用于之后的使用
用法: `proj = angr.Project('/bin/true')`
二进制的预加载选项
`main_ops和lib_opts` 通过字典实现
`angr.Project(main_opts={'backend': 'ida', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})`
base_addr—要使用的基本地址
entry_point—要使用的入口点
arch -要使用的架构的名称
backend——使用哪个后端，作为类或名称
CLE目前有用于静态加载ELF、PE、CGC、Mach-O和ELF核心转储文件的后端，以及用IDA加载二进制文件和将文件加载到平面地址空间的后端。
backend :elf(Static loader for ELF files based on PyELFTools),pe(基于PEFile的PE文件的静态加载程序),mach-o(用于Mach-O文件的静态加载程序。不支持动态链接或重设基础。),cgc,backedcgc,elfcore(用于ELF内核转储的静态加载程序),ida(启动一个IDA实例来解析文件),blob(以平面映像的形式将文件加载到内存中)

`auto_load_libs` 为真加载真的库函数
如果`auto_load_libs`为False，那么外部函数将无法解析，每次调用它时，它都返回一个惟一的无约束符号值。

#### hook
`stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']` 获取一个用于hook的函数
`proj.hook(0x10000, stub_func()) ` 在0x10000 hook掉
`proj.is_hooked(0x10000)` 判断此位置是否hook了
`proj.hooked_by(0x10000)` 返回此位置替换的函数
`proj.hook(0x20000, length=5) `定义一个函数并且hook到地址
`proj.hook_symbol(name, hook)` 对函数进行hook name是函数名 ,用于扩展angr的内置库simprocedure


#### arch
proj.arch 架构 
proj.arch.bits 位数（32,64）
arch.ip_offset寄存器文件中指令指针的偏移量
arch.sp_offset 栈顶指针的偏移量
arch.bp_offset 栈基指针的偏移量
arch.lr_offset  进入函数时的返回地址 的偏移量 R14
arch.ret_offset 返回地址的偏移量

proj.entry 返回程序入口点地址
proj.filename 文件名称(带路径)

#### loader 
proj.loader 查看加载地址空间
proj.loader.shared_objects  动态连接库及加载地址
proj.loader.min_addr 最低地址
proj.loader.max_addr 最高地址
proj.loader.main_object 主要的二进制文件对象（我们一开始传的那个）
proj.loader.main_object.execstack  
proj.loader.main_object.pic  
proj.loader.all_objects 完整的对象表更细的分类,以及内存里的加载地址
proj.loader.shared_objects 加载的动态函数库,也就是libc.so.XXX 这种的
proj.loader.all\_elf \_objects ELF文件加载对象  
windwos下使用这个  proj.loader.all\_pe\_objects
proj.loader.extern_object 用来给angr 内部提供地址
proj.loader.kernel_object  用来提供模拟的系统调用地址
proj.loader.find\_object\_containing(0x400000) 获得指定的地址对象引用 这里是最初传入的程序加载地址 
![/img/SymbolicExecution_2](/img/SymbolicExecution_2.png)
`malloc = proj.loader.find_symbol('malloc')`  获取对应名称的函数地址
  malloc.name 函数名
  malloc.owner_obj 属主对象
  malloc.rebased_addr 是它在全局地址空间中的地址。
  malloc.linked_addr 是它相对于二进制预链接基的地址
  malloc.relative_addr 是它相对于对象基的地址 RVA(相对虚拟基址）
在Loader上，方法是find_symbol，因为它执行搜索操作来查找符号。
对于单个对象，方法是get_symbol，因为给定名称只能有一个符号
`main_malloc = proj.loader.main_object.get_symbol("malloc")`
`proj.loader.shared_objects['libc.so.6'].imports`

##### object
obj = proj.loader.main_object 获取主要二进制文件的对象
obj.entry 对象入口点地址
obj.min\_addr, obj.max\_addr 内存中最低地址和最高地址
obj.plt['函数名'] 返回对应函数plt地址
obj.reverse_plt[addr] 返回对应plt地址所存的函数的函数名
obj.segments 
obj.sections 
obj.find\_segment\_containing(obj.entry) 
obj.find\_section\_containing(obj.entry)

#### factory
block = proj.factory.block(proj.entry)  从程序入口点取出代码块
block.pp() 打印出汇编代码和地址
block.instructions   输出这块的指令数目
block.instruction_addrs  打印出每条地址的指令

#### States
项目对象只表示程序的“初始化镜像”。当用angr执行时，使用的是表示模拟程序状态的特定对象—SimState
SimState包含程序的内存、寄存器、文件系统数据,任何可以通过执行来更改的“活动数据”都在状态中有一个地方.
state = proj.factory.entry_state() 获取入口states
state.regs.rip 获取当前指令指针(也就是程序运行到哪,指令地址)
state.regs.rax rax寄存器的值
state.mem[proj.entry].int.resolved 入口内存解释为C整型 实际上就是指令的字节码
`state.regs.rbp = state.regs.rsp rsp`值赋给rbp
`state.mem[0x1000].uint64_t = state.regs.rdx` 把rdx的值储存在地址0x1000
`state.regs.rax += state.mem[state.regs.rsp +  8].uint64_t.resolved` rax的值加上rsp+8地址处的值 
`state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved` rbp存入rbp中地址处的值


####  bitvectors 
bitvectors 位向量不是python int
`bv = state.solver.BVV(0x1234,  32)` 创建一个三十二位值位0x1234的 位向量
state.solver.eval(bv) 转换为python int
可以用 位向量给寄存器内存赋值
`state.regs.rsi = state.solver.BVV(3, 64)`  给rsi赋值0x3
state.regs.rsi =`<BV64 0x3>`
state.mem[0x1000].long  =  4
state.mem[0x1000].long.resolved 获得位向量
通过数组下标找到指定地址 
.type 指定数据解释类型
.resolved  获得位向量
.concrete 获得python int
 state.regs.rdi=`<BV64 reg_rdi_4_64{UNINITIALIZED}>`这仍然是一个64位位向量，但它不包含数值。相反，它有一个名字!这被称为符号变量，它是符号执行的基础
位向量运算
one = state.solver.BVV(1,  64) 64位值0x1的位向量
`one_hundred = state.solver.BVV(100,  64)`
`one + one_hundred=<BV64 0x65>`
`one_hundred +  0x100=<BV64 0x164>`
`one_hundred - one*200 = <BV64 0xffffffffffffff9c>`
weird_nine = state.solver.BVV(9,  27)
`weird_nine.zero_extend(64  -  27)=<BV64 0x9>` 位向量拓展
`one + weird_nine.zero_extend(64  -  27) = <BV64 0xa>`
x = state.solver.BVS("x",  64)  类似z3解方程里的变量 x 六十四位的位向量这里的x 为一个类似数学变量的东西, 返回的是AST对象
y = state.solver.BVS("y",  64) 同上
`x + one = <BV64 x_9_64 +  0x1>`
`(x + one)  /  2 = <BV64 (x_9_64 +  0x1)  /  0x2>`
`x - y =<BV64 x_9_64 - y_10_64>`
AST :语法树
每个AST都有一个.op和一个.args。op是命名正在执行的操作的字符串，args是该操作作为输入的值。
tree =  (x +  1)  /  (y +  2)
tree.op 运算符
tree.args 操作数
tree.args[0].op 第一个操作数的运算符
tree.args[0].args[1].op 第一个操作数的 第一个操作数的运算符
符号的约束
`x ==  1  <Bool x_9_64 ==  0x1>`
`x == one <Bool x_9_64 ==  0x1>`
`x >  2  <Bool x_9_64 >  0x2>`
`x + y == one_hundred +  5 <Bool (x_9_64 + y_10_64)  ==  0x69>`
`one_hundred >  5 <Bool True>`
`one_hundred >  -5  <Bool False> 负五为<BV64 0xfffffffffffffffb>` 所以判断是false 此时应该用 one_hundred.SGT(-5)
返回的是布尔值
yes = one ==  1
no = one ==  2
maybe = x == y
state.solver.is_true(yes) 结果是否为真
state.solver.is_false(yes)  结果是否为假。
state.solver.is_true(maybe) 对于不确定的结果非真非假
state.solver.is_false(maybe)  
state.solver.add(x > y) 添加约束
state.solver.add(y >  2)
state.solver.add(10  > x)
state.solver.eval(x) 提供可能的解决方案 ,这里表现为获取X的值
solver.eval(expression)  提供可能的解决方案
solver.eval_one(expression) 提供可能的解决方案如果有多个抛出错误
solver.eval_upto(expression, n) 为表达式提供最多n个解,如果可能返回值小于n
solver.eval_atleast(expression, n) 为给定表达式提供n个解 如过可能抛出错误
solver.eval_exact(expression, n) 为表达式提供n个解 可能的数目大于或者小于n抛出错误
solver.min(expression) 给出最小数目可能的解
solver.max(expression)给出最大数目可能的解
可用cast_to 传递转换的结果类型
`state.solver.eval(state.solver.BVV(0x41424344, 32), cast_to=str) `返回值为“ABCD”

input  = state.solver.BVS('input',  64)
operation =  (((input  +  4)  *  3)  >>  1)  +  input
output =  200
state.solver.add(operation == output)
state.solver.eval(input)
如果我们添加冲突或矛盾的约束，这样就没有可以分配给变量的值
state.solver.add(input  <  2**32)
state.satisfiable()  检查状态是否可满足

浮点数 可通过FPV and FPS 创建
`a = state.solver.FPV(3.2, state.solver.fp.FSORT_DOUBLE)`
`a=<FP64 FPV(3.2, DOUBLE)>`
`b = state.solver.FPS('b', state.solver.fp.FSORT_DOUBLE)`
`b=<FP64 FPS('FP_b_0_64', DOUBLE)>`
`a+b=<FP64 fpAdd(RNE, FPV(3.2, DOUBLE), FPS(FP_b_4_64, DOUBLE))>`
`a +  4.4 =<FP64 FPV(7.6000000000000005, DOUBLE)> `
`b +  2  <  0  = <Bool fpLT(fpAdd(RNE, FPS(FP_b_4_64, DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>`
用eval返回一个浮点数
浮点数表示位向量:
`a.raw_to_bv() = <BV64 0x400999999999999a>`
`b.raw_to_bv() = <BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>`
val\_to\_bv方法用来转换成int类型   val\_to\_fp 用来转回float
`a.val_to_bv(12)=<BV12 0x3> `
`a.val_to_bv(12).val_to_fp(state.solver.fp.FSORT_FLOAT) = <FP32 FPV(3.0, FLOAT)>`



#### Simulation Managers 
simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active> 输出活动数量
simgr.active
Simulation Managers 可以包含多个状态通过 simgr.active[0]来观看,默认活动是我们传入的状态

simgr.step() 执行一个基本块的符号执行,并没有修改原始状态也就是说我们可以使用单个状态作为多轮执行的基础
![/img/SymbolicExecution_1](/img/SymbolicExecution_1.PNG)
可以看到初始的state状态没变
 proj = angr.Project('/root/Desktop/angr-doc/examples/fauxware/fauxware', auto\_load\_libs=False)  这里使用官方文档的演示程序
 state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.active `[<SimState @ 0x400580>]` 入口点地址
simgr.step()
simgr.active`[<SimState @ 0x400540>]` ___libc\_start\_main plt表地址
while  len(simgr.active)  ==  1:
        simgr.step()   
上面的代码意思是 一直执行到分支不为一
simgr.active = `[<SimState @ 0x400692>, <SimState @ 0x400699>]`
simgr.run() 逐步执行直到没有其他步骤执行
simgr 最后获得三个结束状态 所谓结束状态就是一个程序因为调用了exit syscall 无法继续。
用move 在stashe之间移动状态 filter是移动条件
`simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome'  in s.posix.dumps(1))`
 `simgr=<SimulationManager with  2 authenticated,  1 deadended>`
例子的意思是 移动含有welcome的输出到 新创建的 authenticated 存储
每个stash都是一列可通过索引迭代来访问
simgr.one_deadended 用来获得第一个状态
simgr.mp\_authenticated mp\_ 获取输入状态
simgr.mp_authenticated.posix.dumps(0) dump输入数据 0输入流 1输出流
simgr.explore() 找到到达某个地址的状态丢弃经过另一个地址的所有状态

#### Breakpoint
这里使用例子examples/fauxware/fauxware
b = angr.Project('examples/fauxware/fauxware')
s = b.factory.entry_state() 获取入口点状态
s.inspect.b('mem_write') 下断 在内存写入前插入ipdb
`s.inspect.b('mem_write', mem_write_address=0x1000)` 对0x1000写入时下断
def  debug_func(state):
  print("State %s is about to do a memory write!")
定义一个断点处理函数
因为会使用ipdb 需要提前安装sudo pip install ipdb 
除了内存写入还有很多其他需要下断的地方 具体请查看 
https://docs.angr.io/core-concepts/simulation
#### Analyses
proj.analyses. + “TAB” 可查自带的方法
具体使用可以查看官方API文档
http://angr.io/api-doc/angr.html?highlight=cfg#module-angr.analysis（emmm）



这里不多赘述了

## 使用 (这里使用了官方的例子进行简单解释)
### fauxware
第一个是官方给的例子 
找出含SOSNEAKY的input
第二个是我自己写的
找出输出流含有 welcome的 然后打印出输入输出

```
#!/usr/bin/env python

import angr
import sys
def basic_symbolic_execution():
    proj = angr.Project('fauxware')
    simgr = proj.factory.simgr()
    simgr.explore(find=lambda s: b"Welcome"  in s.posix.dumps(1)) #找出输出流含有welcome的路径
    s = simgr.found[0]
    print(s.posix.dumps(1)) 输出流
    print(s.posix.dumps(0)) 输入流
    return 0

if __name__ == '__main__':
    print(basic_symbolic_execution())
```

###  CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a
proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Congrats"  in s.posix.dumps(1)) 找出输出含有Congrats 的结果
s = simgr.found[0] s为找到的第一个结果 
print(s.posix.dumps(1)) 输出这个结果的输出流
print(s.posix.dumps(0)) 输出这个结果的输入流
### strcpy_find
看一下反编译结果程序整体流程先判断argv 数目不足进入func3
然后把字符串 

```
"Unu`mmx!onu!uid!q`rrvnse///"
```

每位与1异或放入s中最后比较argv[1]和s是否不同
以下是官方代码 以及我自己对其的理解

```python
#!/usr/bin/env python
'''
@author Kyle Ossinger (k0ss_sec)
@desc   Tutorial solver for an example program.  I noticed most of the angr
        examples were for solving for a password/flag rather than for finding
        exploitable memory corruptions.  I hope this will lead you on the path
        to finding your own memory corruptions.  Enjoy!

'''

import angr
import claripy  # It is optimal to use claripy.BVV/BVS over state.solver.BVV/BVS
                # EDITOR'S NOTE: this is somewhat true but it super super does
                # not matter if you're just creating a few variables for
                # initialization. do what's convenient. state.solver.BVS will
                # trigger some instrumentation if people have asked to be
                # notified whenever new variables are created, which doesn't
                # usually happen.

def main():
    def getFuncAddress( funcName, plt=None ):  #找出对应函数的地址
        found = [
            addr for addr,func in cfg.kb.functions.items()  #返回函数字典
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
        if len( found ) > 0:
            print("Found "+funcName+"'s address at "+hex(found[0])+"!")
            return found[0]
        else:
            raise Exception("No address found for function : "+funcName)


    def get_byte(s, i):
        pos = s.size() // 8 - 1 - i
        return s[pos * 8 + 7 : pos * 8]
    project = angr.Project("strcpy_test", load_options={'auto_load_libs':False})
    cfg = project.analyses.CFG(fail_fast=True)
    addrStrcpy = getFuncAddress('strcpy', plt=True) 
    addrBadFunc = getFuncAddress('func3')
    argv = [project.filename]   #argv[0]
    sym_arg_size = 40   #max number of bytes we'll try to solve for
    sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
    argv.append(sym_arg)    #argv[1]
    argv.append("HAHAHAHA") # argv[2]
    state = project.factory.entry_state(args=argv)
    sm = project.factory.simulation_manager(state)
    def check(state):
        if (state.ip.args[0] == addrStrcpy):    # 判断执行到此的地址是strcpy
            BV_strCpySrc = state.memory.load( state.regs.rsi, len(argv[2]) ) #把rsi中的地址存放的值取出len(argv[2])长度 返回类型为位向量
            strCpySrc = state.solver.eval( BV_strCpySrc , cast_to=bytes )  #转换成python int
            return True if argv[2].encode() in strCpySrc else False  #判断 内存是否有argv[2]也就是message
        else:
            return False
    sm = sm.explore(find=check, avoid=(addrBadFunc,)) #寻找满足check 避开 addrBadFunc 的结果

    found = sm.found   #提取found的结果
    if len(found) > 0:    #  确定找到的结果数量大于0
        found = sm.found[0]
        result = found.solver.eval(argv[1], cast_to=bytes)
        try:
            result = result[:result.index(b'\0')]
        except ValueError:
            pass
    else:   # Aww somehow we didn't find a path.  Time to work on that check() function!
        result = "Couldn't find any paths which satisfied our conditions."
    return result

def test():
    output = main()
    target = b"Totally not the password..."
    assert output[:len(target)] == target

if __name__ == "__main__":
    print('The password is "%s"' % main())

```

以上就是angr的基本用法，本人对于angr的理解也还是很浅显，有些地方也不是特别清楚，如果有错的地方，希望大家指点。
参考 
https://docs.angr.io/



