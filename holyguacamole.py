#!/usr/bin/env python3
# HolyGuacamole : Brent Hartshorn - Aug 20, 2024

import os, sys, subprocess
import holypycparser as hpp
import pycparser

tests = [
'''
`0`register a0,a1`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`register a0,a1`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',


'''
`0
`register a0,a1
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
// cpu core
`0
// registers
`a0,a1
`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

'''
`0`a0,a1`U0 A(I32 x, I32 y)
{
	if (x < y) return -1;
	return x + y;
}
''',

]

for t in tests:
	print(t)
	print('-'*80)
	c = hpp.holyc_to_c( t )
	print(c)
	print('_'*80)