#!/usr/bin/env python2
## -*- coding: utf-8 -*-

import sys
import triton
import pintool

post_call_to_check_license = 0x4007bf # the instruction after check_license() returns I.E. mov DWORD PTR [rbp-0x1c],eax
target                     = 0x4007cd # main's call to printf(License check passed\n")

Triton = pintool.getTritonContext()

def symbolize_inputs(tid):
    rsi = pintool.getCurrentRegisterValue(Triton.registers.rsi) # argv
    addr = pintool.getCurrentMemoryValue(rsi + (triton.CPUSIZE.QWORD), triton.CPUSIZE.QWORD) # argv[1]

    # symbolize each character in argv[1], i.e the serial (including the terminating NULL)
    c = None
    s = ''
    while c != 0:
        c = pintool.getCurrentMemoryValue(addr)
        s += chr(c)
        Triton.setConcreteMemoryValue(addr, c)
        Triton.convertMemoryToSymbolicVariable(triton.MemoryAccess(addr, triton.CPUSIZE.BYTE)).setComment('argv[1][%d]' % (len(s)-1))
        addr += 1
    print 'Symbolized argv[1]: %s' % (s)

def find_input(insn, op):
    regId   = Triton.getSymbolicRegisterId(op)
    regExpr = Triton.unrollAst(Triton.getAstFromId(regId))
    ast = Triton.getAstContext()

    exploitExpr = ast.bvugt(regExpr, ast.bv(0, triton.CPUSIZE.QWORD_BIT))
    for k, v in Triton.getSymbolicVariables().iteritems():
        if 'argv[1]' in v.getComment():
            # Argument characters must be alphanumeric
            argExpr = Triton.getAstFromId(k)
            argExpr1 = ast.land([
                          ast.bvuge(argExpr, ast.bv(0x30,  triton.CPUSIZE.BYTE_BIT)),
                          ast.bvule(argExpr, ast.bv(0x39, triton.CPUSIZE.BYTE_BIT))
                      ])
            
            argExpr2 = ast.land([
                          ast.bvuge(argExpr, ast.bv(0x41,  triton.CPUSIZE.BYTE_BIT)),
                          ast.bvule(argExpr, ast.bv(0x5a, triton.CPUSIZE.BYTE_BIT))
                      ])

            argExpr3 = ast.land([
                          ast.bvuge(argExpr, ast.bv(0x61,  triton.CPUSIZE.BYTE_BIT)),
                          ast.bvule(argExpr, ast.bv(0x7a, triton.CPUSIZE.BYTE_BIT))
                      ])

            argExpr = ast.lor([argExpr1, argExpr2, argExpr3])
            
            exploitExpr = ast.land([exploitExpr, argExpr])

    print 'Getting model for %s -> 0x%x' % (insn, target)
    model = Triton.getModel(exploitExpr)
    for k, v in model.iteritems():
        print '%s (%s)' % (v, Triton.getSymbolicVariableFromId(k).getComment())

def hook_call(insn):
    if insn.getAddress() == post_call_to_check_license:
        for op in insn.getOperands():
            if op.getType() == triton.OPERAND.REG and (op.getName() == "eax" or op.getName() == "rax"):
                print 'Found instruction after check_license() returns: \'%s\'' % (insn)
                find_input(insn, op)

def main():
    Triton.setArchitecture(triton.ARCH.X86_64)
    Triton.enableMode(triton.MODE.ALIGNED_MEMORY, True)

    pintool.startAnalysisFromSymbol('main')

    pintool.insertCall(symbolize_inputs, pintool.INSERT_POINT.ROUTINE_ENTRY, 'main')
    pintool.insertCall(hook_call, pintool.INSERT_POINT.BEFORE)

    pintool.runProgram()

if __name__ == '__main__':
    main()


