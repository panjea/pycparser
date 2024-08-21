#!/usr/bin/env python3
# HolyGuacamole : Brent Hartshorn - Aug 20, 2024

import os, sys, subprocess, json
import holypycparser as hpp
import pycparser

tests = [
'''
`0`register a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`register a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',


'''
`0
`register a0,a1,a2,a3,a4,a5,a6,a8
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
// thread
`0
// registers
`a0,a1,a2,a3,a4,a5,a6,a8
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`0`a0,a1,a2,a3,a4,a5,a6,a8`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

## threads
'''
`0`a0,a1,a2,a3,a4,a5,a6,a8`U0 ThreadA(I32 x, I32 y) {
	if (x < y) return -1;
	return x + y;
}


`1`s0,s1,s2,s3,s4,s5,s6,s8`U0 ThreadB(I32 x, I32 y) {
	if (x < y) return -1;
	return x + y;
}
''',


]

def parse_holyg(ln):
	ln = ln[ : ln.rindex('`') ].strip()
	regs = {}
	for i, a in enumerate(ln.split('`')):
		if ',' in a:
			for reg in a.split(','):
				reg = reg.strip()
				if reg.startswith('register'):
					reg = reg.split()[-1]
				if reg.startswith('a'):
					regs[ reg ] = reg.replace('a', 's')
				elif reg.startswith('s'):
					regs[ reg ] = reg.replace('s', 'a')
			break
	return regs

def c2asm( c, reg_replace_map, opt=0, strip_backticks=True ):
	if type(c) is list: c = '\n'.join(c)

	

	if strip_backticks:
		a = []
		prev = None
		for ln in c.splitlines():
			if ln.startswith('`'):
				assert prev.startswith('//JSON//')
				finfo = json.loads( prev[ len('//JSON//') : ] )
				print(finfo)
				reg_replace_map[finfo['name']] = parse_holyg(ln)
				ln = ln.split('`')[-1]

			a.append(ln)
			prev = ln
		c = '\n'.join(a)

	tmp = '/tmp/c2asm.c'
	open(tmp, 'wb').write(c.encode('utf-8'))
	if not opt: opt = '-O0'
	else: opt = '-O%s' % opt
	asm = '/tmp/c2asm.S'
	cmd = [
		'riscv64-unknown-elf-gcc', '-mcmodel=medany', '-fomit-frame-pointer', '-ffunction-sections',
		'-ffreestanding', '-nostdlib', '-nostartfiles', '-nodefaultlibs', '-fno-tree-loop-distribute-patterns', 
		'-fno-optimize-register-move', '-fno-sched-pressure', '-fno-sched-interblock',
		'-ffixed-t0', '-ffixed-t1', '-ffixed-t2', '-ffixed-t3', '-ffixed-t4', '-ffixed-t5', '-ffixed-t6',
		opt, 
		#'-g', 
		'-S', '-o', asm, tmp
	]
	print(cmd)
	subprocess.check_call(cmd)
	return open('/tmp/c2asm.S', 'rb').read().decode('utf-8')

def asm2asm(data, func_reg_replace={}, reg_replace={}, debug=False, skip_calls=False):
	#data = open(path,'rb').read().decode('utf-8')
	if debug: print_asm(data)
	sects = {}
	sect = {}
	label = None
	out = []
	funcs = {}
	func = None
	for ln in data.splitlines():
		if ln.strip().startswith('.'):
			out.append(ln)
			continue
		if ln.strip().startswith('#'): continue
		a = parse_asm(ln)
		if 'label' in a:
			label = a['label']
			sect = {}
			sects[label] = sect
			func = {'lines':[],'ast':[], 'reps':[]}
			funcs[label] = func
			out.append(ln)
			continue

		if 'inst' in a and a['inst']=='call' and skip_calls:
			continue

		if func:
			func['lines'].append(ln)
			func['ast'].append(a)

		if 'regs' in a:
			for b in a['regs']:
				if b not in sect: sect[b] = {'count':0,'asm':[]}

				sect[b]['count'] += 1
				sect[b]['asm'].append('%s :: %s' % (a['inst'],a['ops']))

				if label in func_reg_replace and b in func_reg_replace[label]:
					c = func_reg_replace[label][b]
					ln = ln.replace(b, c)
					reps = func['reps']
					if c not in reps: reps.append(c)
				elif b in reg_replace:
					ln = ln.replace(b, reg_replace[b])

		out.append(ln)

	for fname in funcs:
		for a in funcs[fname]['ast']:
			if 'regs' in a:
				for b in a['regs']:
					if b in funcs[fname]['reps']:
						print(fname)
						print('\n'.join(funcs[fname]['lines']))
						print(func_reg_replace[fname])
						raise SyntaxError('reg replace error: %s %s' % (a,b))

	if debug:
		for ln in out:
			if not ln.strip().startswith('.'):
				print(ln)

	return '\n'.join(out)

def parse_asm(ln, debug=False):
	r = {}
	if ln.strip().startswith('.'):
		r['data'] = ln
		return r
	elif ln.strip().startswith('#'):
		r['comment'] = ln.strip()
		return r
	if debug: print(ln)
	a = ln.strip().split()
	ops = None
	if len(a)==1:
		if a[0].endswith(':'):
			label = a[0][:-1]
			r['label'] = label
		else:
			r['inst']  = a[0]
		return r
	elif len(a)==2:
		inst, ops = a
	else:
		raise RuntimeError(ln)
	if not ops:
		return r

	r['inst'] = inst
	r['ops']  = ops
	r['regs'] = []
	vis = []
	for b in ops.split(','):
		index = None
		if '(' in b:
			index = b.split('(')[0]
			b = b.split('(')[-1][:-1]

		if b in REGS:
			if b not in r['regs']:
				r['regs'].append(b)

			if b in reg_colors:
				b = '\033[%sm%s\033[0m' % (reg_colors[b], b)
			elif b.startswith('s'):
				if b in S_COLORS:
					COLOR_S = '48;5;%s' % S_COLORS[b]
				else:
					COLOR_S = '30;43'
				b = '\033[%sm %s \033[0m' % (COLOR_S, b)
			elif b.startswith('a'):
				if b in A_COLORS:
					COLOR_A = '48;5;%s' % A_COLORS[b]
				else:
					COLOR_A = '30;44'
				b = '\033[%sm %s \033[0m' % (COLOR_A, b)
			elif b.startswith('t'):
				#b = '\033[38;5;%sm %s \033[0m' % (T_COLORS[b], b)  #fg color
				b = '\033[38;5;0;48;5;%sm %s \033[0m' % (T_COLORS[b], b)

		if index is not None:
			vis.append('%s[%s]' %(b,index))
		else:
			vis.append(b)

	vis = tuple(vis)
	if inst in ('sret', 'sbreak'):
		r['vis'] = 'system< %s >' % inst
	elif inst in ('call', 'tail'):
		r['vis'] = '%s(...)' % ops
	elif inst == 'ble':
		r['vis'] = 'if %s <= %s: goto %s' % vis
	elif inst.startswith('sext.'):  ## sign extend
		if inst.endswith('.w'):  ## 32bit word to 64bit
			r['vis'] = '%s =(i64*)%s' % vis
	else:
		map = {'add':'+', 'div':'/',  'sll' : '<<', 'slr' : '>>', 
			'l':'<-', 's':'->', 'neg':'-', 'rem':'%', 'mul':'*',
			'mv':'◀═┅┅',  ## atomic copy from reg to reg
			'j':'goto',
		}
		for tag in map:
			if inst.startswith(tag):
				if len(vis)==1:
					x = vis[0]
					r['vis'] = '%s %s' % (map[tag], x)
				elif len(vis)==2:
					x,y = vis
					if inst.startswith('neg'):
						r['vis'] = '%s = %s%s' % (x, map[tag], y)
					else:
						r['vis'] = '%s %s %s' % (x, map[tag], y)
				else:
					x,y,z = vis
					r['vis'] = '%s = %s %s %s' % (x, y, map[tag], z)
				break

	if 'vis' in r:
		r['vis'] += '\t\t\t %s : %s' %(inst, ops)
		if inst in asm_help:
			r['vis'] += '\t\t\t : %s' % asm_help[inst] 

	return r


def print_asm(asm, *labels):
	if asm.startswith('/') and len(asm) < 128:
		if os.path.isfile(asm): asm = open(asm,'rb').read().decode('utf-8')
	lab = None
	for idx, ln in enumerate(asm.splitlines()):
		#print(ln)
		a = parse_asm(ln)
		if 'label' in a:
			lab = a['label']
		if 'data' in a: continue
		if labels:
			if lab in labels:
				if 'vis' in a: print(a['vis'])
				else: print(a)
		else:
			if 'vis' in a: print(a['vis'])
			else: print(a)

REGS = ['x%s' % i for i in range(32)]
REGS += [
	'zero',
	'ra',  ## return addr
	'sp',  ## stack pointer
	'gp',  ## global pointer
	'tp',  ## thread pointer
	't0', 't1', 't2',
	's0', 'fp',  ## s0 is sometimes fp
	's1'   ## saved reg1
] + ['a%s' % i for i in range(8)] + ['s%s' % i for i in range(2,12)] + ['t%s' % i for i in range(3,7)]
print('RISC-V registers:',REGS)

S_COLORS = { 's0': 22, 's1': 28, 's2': 64, 's3': 34, 's4': 70, 's5': 40, 's6': 76, 's7': 46, 's8': 47, 's9': 48}
A_COLORS = {'a0': 19,'a1': 20, 'a2': 21, 'a3': 57, 'a4': 56, 'a5': 92, 'a6': 93, 'a7': 129, 'a8': 165, 'a9': 201}
T_COLORS = {'t0' : 226,'t1' : 190,'t2' : 227,'t3' : 191,'t4' : 228,'t5' : 192,'t6' : 229}
reg_colors = { 'tp' : '31', 'sp' : '31', 'gp' : '31', 'ra' : '31', 'zero' : '31' }


asm_help = {
	'lw' : 'load word',
	'sw' : 'store word',
	'li' : 'load value',
	'sext.w' : 'convert i32 to i64',
	'mulw' : 'multiply word',
	'subw' : 'subtract word',
	'addw' : 'add word',
}


for t in tests:
	print(t)
	print('-'*80)
	c = hpp.holyc_to_c( t )
	print(c)
	print('_'*80)
	func_reg_replace = {}
	a = c2asm(c, func_reg_replace)
	print('c2asm output:', a)
	print('reg_replace_map:', func_reg_replace)
	a = asm2asm(a, func_reg_replace)
	print('asm2asm output:')
	print_asm(a)
